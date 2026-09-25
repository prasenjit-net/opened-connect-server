package identity

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// mongoOperations binds database I/O to one WithTransaction attempt. Binding
// happens inside the driver callback so retries use the current session context.
// Cursors share that same context for iteration and cleanup.
type mongoOperations struct {
	findOne        func(coll *mongo.Collection, filter any, opts ...options.Lister[options.FindOneOptions]) *mongo.SingleResult
	find           func(coll *mongo.Collection, filter any, opts ...options.Lister[options.FindOptions]) (*mongoCursor, error)
	replaceOne     func(coll *mongo.Collection, filter, replacement any, opts ...options.Lister[options.ReplaceOptions]) (*mongo.UpdateResult, error)
	updateOne      func(coll *mongo.Collection, filter, update any, opts ...options.Lister[options.UpdateOneOptions]) (*mongo.UpdateResult, error)
	updateMany     func(coll *mongo.Collection, filter, update any, opts ...options.Lister[options.UpdateManyOptions]) (*mongo.UpdateResult, error)
	deleteOne      func(coll *mongo.Collection, filter any, opts ...options.Lister[options.DeleteOneOptions]) (*mongo.DeleteResult, error)
	deleteMany     func(coll *mongo.Collection, filter any, opts ...options.Lister[options.DeleteManyOptions]) (*mongo.DeleteResult, error)
	countDocuments func(coll *mongo.Collection, filter any, opts ...options.Lister[options.CountOptions]) (int64, error)
}

type mongoCursor struct {
	*mongo.Cursor
	next  func() bool
	close func() error
}

func bindMongoOperations(ctx context.Context) mongoOperations {
	return mongoOperations{
		findOne: func(coll *mongo.Collection, filter any, opts ...options.Lister[options.FindOneOptions]) *mongo.SingleResult {
			return coll.FindOne(ctx, filter, opts...)
		},
		find: func(coll *mongo.Collection, filter any, opts ...options.Lister[options.FindOptions]) (*mongoCursor, error) {
			cur, err := coll.Find(ctx, filter, opts...)
			if err != nil {
				return nil, err
			}
			return &mongoCursor{Cursor: cur, next: func() bool { return cur.Next(ctx) }, close: func() error { return cur.Close(ctx) }}, nil
		},
		replaceOne: func(coll *mongo.Collection, filter, replacement any, opts ...options.Lister[options.ReplaceOptions]) (*mongo.UpdateResult, error) {
			return coll.ReplaceOne(ctx, filter, replacement, opts...)
		},
		updateOne: func(coll *mongo.Collection, filter, update any, opts ...options.Lister[options.UpdateOneOptions]) (*mongo.UpdateResult, error) {
			return coll.UpdateOne(ctx, filter, update, opts...)
		},
		updateMany: func(coll *mongo.Collection, filter, update any, opts ...options.Lister[options.UpdateManyOptions]) (*mongo.UpdateResult, error) {
			return coll.UpdateMany(ctx, filter, update, opts...)
		},
		deleteOne: func(coll *mongo.Collection, filter any, opts ...options.Lister[options.DeleteOneOptions]) (*mongo.DeleteResult, error) {
			return coll.DeleteOne(ctx, filter, opts...)
		},
		deleteMany: func(coll *mongo.Collection, filter any, opts ...options.Lister[options.DeleteManyOptions]) (*mongo.DeleteResult, error) {
			return coll.DeleteMany(ctx, filter, opts...)
		},
		countDocuments: func(coll *mongo.Collection, filter any, opts ...options.Lister[options.CountOptions]) (int64, error) {
			return coll.CountDocuments(ctx, filter, opts...)
		},
	}
}
