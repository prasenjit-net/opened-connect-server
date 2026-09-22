package identity

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoStore struct {
	client     *mongo.Client
	collection *mongo.Collection
	secrets    *FileStore
}
type mongoState struct {
	ID    string `bson:"_id"`
	State []byte `bson:"state"`
}

func NewMongoStore(ctx context.Context, uri, database, dataDir string) (*MongoStore, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("connect MongoDB: %w", err)
	}
	if err = client.Ping(ctx, nil); err != nil {
		client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping MongoDB: %w", err)
	}
	secrets, err := databaseSecretStore(dataDir, "mongodb")
	if err != nil {
		client.Disconnect(context.Background())
		return nil, err
	}
	return &MongoStore{client: client, collection: client.Database(database).Collection("opened_connect_state"), secrets: secrets}, nil
}
func (s *MongoStore) Close(ctx context.Context) error { return s.client.Disconnect(ctx) }
func (s *MongoStore) Read(ctx context.Context, fn func(ReadTx) error) error {
	return s.withState(ctx, false, func(tx *fileState) error { return fn(tx) })
}
func (s *MongoStore) Write(ctx context.Context, fn func(Tx) error) error {
	return s.withState(ctx, true, func(tx *fileState) error { return fn(tx) })
}
func (s *MongoStore) withState(ctx context.Context, write bool, fn func(*fileState) error) error {
	session, err := s.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(ctx, func(ctx context.Context) (any, error) {
		var record mongoState
		err := s.collection.FindOne(ctx, bson.D{{Key: "_id", Value: "state"}}).Decode(&record)
		if err == mongo.ErrNoDocuments {
			record.ID = "state"
		} else if err != nil {
			return nil, err
		}
		next, err := executeSerializedState(ctx, record.State, write, s.secrets, fn)
		if err != nil {
			return nil, err
		}
		if write {
			_, err = s.collection.ReplaceOne(ctx, bson.D{{Key: "_id", Value: "state"}}, mongoState{ID: "state", State: next}, options.Replace().SetUpsert(true))
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}
