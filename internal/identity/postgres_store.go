package identity

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool    *pgxpool.Pool
	secrets *FileStore
}

func NewPostgresStore(ctx context.Context, dsn, dataDir string, maxOpen, maxIdle int) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL DSN: %w", err)
	}
	cfg.MaxConns = int32(maxOpen)
	cfg.MinConns = int32(maxIdle)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect PostgreSQL: %w", err)
	}
	if _, err = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS opened_connect_state (id boolean PRIMARY KEY DEFAULT true CHECK (id), state jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		pool.Close()
		return nil, fmt.Errorf("initialize PostgreSQL store: %w", err)
	}
	secrets, err := databaseSecretStore(dataDir, "postgres")
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &PostgresStore{pool: pool, secrets: secrets}, nil
}
func (s *PostgresStore) Close() { s.pool.Close() }
func (s *PostgresStore) Read(ctx context.Context, fn func(ReadTx) error) error {
	return s.withState(ctx, false, func(tx *fileState) error { return fn(tx) })
}
func (s *PostgresStore) Write(ctx context.Context, fn func(Tx) error) error {
	return s.withState(ctx, true, func(tx *fileState) error { return fn(tx) })
}
func (s *PostgresStore) withState(ctx context.Context, write bool, fn func(*fileState) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT state FROM opened_connect_state WHERE id = true`+map[bool]string{true: " FOR UPDATE", false: ""}[write]).Scan(&raw)
	if err == pgx.ErrNoRows {
		raw = nil
	} else if err != nil {
		return err
	}
	next, err := executeSerializedState(ctx, raw, write, s.secrets, fn)
	if err != nil {
		return err
	}
	if write {
		_, err = tx.Exec(ctx, `INSERT INTO opened_connect_state (id, state) VALUES (true, $1::jsonb) ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`, string(next))
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
