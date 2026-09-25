package identity

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// postgresOperations binds I/O to the context of a single Store callback.
// The domain Tx interface has no per-method context; these closures keep its
// operations within the owning transaction's cancellation scope.
type postgresOperations struct {
	exec     func(string, ...any) (pgconn.CommandTag, error)
	query    func(string, ...any) (pgx.Rows, error)
	queryRow func(string, ...any) pgx.Row
}

func bindPostgresOperations(ctx context.Context, tx pgx.Tx) postgresOperations {
	return postgresOperations{
		exec:     func(sql string, args ...any) (pgconn.CommandTag, error) { return tx.Exec(ctx, sql, args...) },
		query:    func(sql string, args ...any) (pgx.Rows, error) { return tx.Query(ctx, sql, args...) },
		queryRow: func(sql string, args ...any) pgx.Row { return tx.QueryRow(ctx, sql, args...) },
	}
}
