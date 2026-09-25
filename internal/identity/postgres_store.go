package identity

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStoreConfig collects everything NewPostgresStore needs. Kept as
// its own type (rather than reusing config.PostgresConfig directly) so
// internal/identity has no import-time dependency on internal/config.
type PostgresStoreConfig struct {
	DSN              string
	DataDir          string
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
	ConnectTimeout   time.Duration
	StatementTimeout time.Duration
	SSLMode          string
}

type PostgresStore struct {
	pool             *pgxpool.Pool
	secrets          *FileStore
	statementTimeout time.Duration
}

// serializationFailure / deadlockDetected are the two SQLSTATE codes worth
// retrying a whole Write callback for: both mean no work was lost, the
// transaction simply lost a race and must be replayed from scratch.
const (
	sqlStateSerializationFailure = "40001"
	sqlStateDeadlockDetected     = "40P01"
)

const maxWriteRetries = 3

func NewPostgresStore(ctx context.Context, cfg PostgresStoreConfig) (*PostgresStore, error) {
	dsn := postgresDSNWithSSLMode(cfg.DSN, cfg.SSLMode)
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	poolCfg.MaxConns = int32(cfg.MaxOpenConns)
	poolCfg.MinConns = int32(cfg.MaxIdleConns)
	if cfg.ConnMaxLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime
	}

	connectCtx := ctx
	if cfg.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		connectCtx, cancel = context.WithTimeout(ctx, cfg.ConnectTimeout)
		defer cancel()
	}

	pool, err := pgxpool.NewWithConfig(connectCtx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connect PostgreSQL %s: %w", redactDSN(dsn), err)
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL %s: %w", redactDSN(dsn), err)
	}

	if err := runPostgresMigrations(dsn); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate PostgreSQL %s: %w", redactDSN(dsn), err)
	}

	secrets, err := databaseSecretStore(cfg.DataDir, "postgres")
	if err != nil {
		pool.Close()
		return nil, err
	}

	statementTimeout := cfg.StatementTimeout
	if statementTimeout <= 0 {
		statementTimeout = 10 * time.Second
	}

	return &PostgresStore{pool: pool, secrets: secrets, statementTimeout: statementTimeout}, nil
}

// postgresDSNWithSSLMode makes storage.postgres.sslMode authoritative for
// both the application pool and the short-lived migration connection. pgx
// accepts URL and keyword/value DSNs; appending a final keyword overrides an
// earlier sslmode in the latter form.
func postgresDSNWithSSLMode(dsn, sslMode string) string {
	if strings.TrimSpace(sslMode) == "" {
		return dsn
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err == nil {
			query := u.Query()
			query.Set("sslmode", sslMode)
			u.RawQuery = query.Encode()
			return u.String()
		}
	}
	return dsn + " sslmode=" + sslMode
}

func (s *PostgresStore) Close() { s.pool.Close() }

func (s *PostgresStore) Read(ctx context.Context, fn func(ReadTx) error) error {
	return s.runOnce(ctx, pgx.ReadOnly, func(tx *postgresTx) error { return fn(tx) })
}

// Write retries the entire callback on Postgres serialization/deadlock
// failures, since those mean the transaction committed nothing and
// re-running it from scratch (with fresh reads) is safe and correct. Any
// other error - including one returned deliberately by a Tx mutator that
// failed, per postgresTx's error-poisoning below - is not retried.
func (s *PostgresStore) Write(ctx context.Context, fn func(Tx) error) error {
	var lastErr error
	for attempt := 0; attempt < maxWriteRetries; attempt++ {
		err := s.runOnce(ctx, pgx.ReadWrite, func(tx *postgresTx) error { return fn(tx) })
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableSerializationError(err) {
			return err
		}
		time.Sleep(retryBackoff(attempt))
	}
	return lastErr
}

func retryBackoff(attempt int) time.Duration {
	base := time.Duration(1<<attempt) * 5 * time.Millisecond
	jitter := time.Duration(rand.Int63n(int64(base) + 1))
	return base + jitter
}

func isRetryableSerializationError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == sqlStateSerializationFailure || pgErr.Code == sqlStateDeadlockDetected
}

// runOnce executes fn inside exactly one SERIALIZABLE transaction. The
// transaction commits if and only if fn returns nil, matching the Store
// contract (store.go: "Write must roll back all changes when the callback
// returns an error") and the "return nil to commit a replay revocation"
// idiom the OIDC layer depends on for authorization-code and refresh-token
// replay handling - since the whole revoke-then-return-nil sequence
// happens inside this one fn call, it is either entirely committed or
// (on any other error) entirely rolled back.
func (s *PostgresStore) runOnce(ctx context.Context, mode pgx.TxAccessMode, fn func(*postgresTx) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: mode})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", s.statementTimeout.Milliseconds())); err != nil {
		return err
	}

	ptx := &postgresTx{postgresOperations: bindPostgresOperations(ctx, tx), secrets: s.secrets, now: time.Now}
	if err := fn(ptx); err != nil {
		return err
	}
	if ptx.err != nil {
		return ptx.err
	}
	return tx.Commit(ctx)
}
