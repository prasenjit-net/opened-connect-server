package identity

import "context"

type StoreOptions struct {
	Backend, DataDir, PostgresDSN, MongoURI, MongoDatabase string
	PostgresMaxOpen, PostgresMaxIdle                       int
}

func OpenStore(ctx context.Context, o StoreOptions) (Store, error) {
	switch o.Backend {
	case "", "json":
		return NewFileStore(o.DataDir)
	case "postgres":
		return NewPostgresStore(ctx, o.PostgresDSN, o.DataDir, o.PostgresMaxOpen, o.PostgresMaxIdle)
	case "mongodb":
		return NewMongoStore(ctx, o.MongoURI, o.MongoDatabase, o.DataDir)
	default:
		return nil, ErrNotFound
	}
}
