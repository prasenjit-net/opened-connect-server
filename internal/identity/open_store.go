package identity

import (
	"context"
	"fmt"
	"time"
)

type StoreOptions struct {
	Backend, DataDir, PostgresDSN, MongoURI, MongoDatabase string
	PostgresMaxOpen, PostgresMaxIdle                       int
	PostgresConnMaxLifetime                                time.Duration
	PostgresConnectTimeout                                 time.Duration
	PostgresStatementTimeout                               time.Duration
	PostgresSSLMode                                        string
}

func OpenStore(ctx context.Context, o StoreOptions) (Store, error) {
	switch o.Backend {
	case "", "json":
		return NewFileStore(o.DataDir)
	case "postgres":
		return NewPostgresStore(ctx, PostgresStoreConfig{
			DSN:              o.PostgresDSN,
			DataDir:          o.DataDir,
			MaxOpenConns:     o.PostgresMaxOpen,
			MaxIdleConns:     o.PostgresMaxIdle,
			ConnMaxLifetime:  o.PostgresConnMaxLifetime,
			ConnectTimeout:   o.PostgresConnectTimeout,
			StatementTimeout: o.PostgresStatementTimeout,
			SSLMode:          o.PostgresSSLMode,
		})
	case "mongodb":
		return NewMongoStore(ctx, o.MongoURI, o.MongoDatabase, o.DataDir)
	default:
		return nil, fmt.Errorf("unknown storage backend %q", o.Backend)
	}
}
