package identity

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

// MongoStore is a document-oriented mapping of the identity domain onto 14
// collections (fewer than PostgresStore's 17 tables: OAuth policy is
// embedded in its client document, a refresh family's tokens are embedded
// in the family document, and a logout operation's targets are a plain
// array field) rather than a full relational normalization - see
// DESIGN.md-equivalent reasoning in the delivery plan: this backend
// intentionally accepts denormalization where Mongo's document model fits
// the domain's real access patterns (always-read-together data embeds;
// independently-and-frequently-looked-up data stays its own collection).
type MongoStore struct {
	client  *mongo.Client
	db      *mongo.Database
	secrets *FileStore

	users                    *mongo.Collection
	sessions                 *mongo.Collection
	appSessions              *mongo.Collection
	clients                  *mongo.Collection
	oauthAccess              *mongo.Collection
	refreshFamilies          *mongo.Collection
	authzTransactions        *mongo.Collection
	authorizationCodes       *mongo.Collection
	accessTokens             *mongo.Collection
	consents                 *mongo.Collection
	initialAccessTokens      *mongo.Collection
	registrationAccessTokens *mongo.Collection
	logoutOperations         *mongo.Collection
	logoutDeliveries         *mongo.Collection
	logoutInteractions       *mongo.Collection
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

	db := client.Database(database)
	s := &MongoStore{
		client:  client,
		db:      db,
		secrets: secrets,

		users:                    db.Collection("users"),
		sessions:                 db.Collection("sessions"),
		appSessions:              db.Collection("app_sessions"),
		clients:                  db.Collection("clients"),
		oauthAccess:              db.Collection("oauth_access"),
		refreshFamilies:          db.Collection("refresh_families"),
		authzTransactions:        db.Collection("authz_transactions"),
		authorizationCodes:       db.Collection("authorization_codes"),
		accessTokens:             db.Collection("access_tokens"),
		consents:                 db.Collection("consents"),
		initialAccessTokens:      db.Collection("initial_access_tokens"),
		registrationAccessTokens: db.Collection("registration_access_tokens"),
		logoutOperations:         db.Collection("logout_operations"),
		logoutDeliveries:         db.Collection("logout_deliveries"),
		logoutInteractions:       db.Collection("logout_interactions"),
	}

	if err := s.ensureIndexes(ctx); err != nil {
		client.Disconnect(context.Background())
		return nil, fmt.Errorf("create MongoDB indexes: %w", err)
	}
	return s, nil
}

// ensureIndexes creates every index the schema relies on. createIndexes is
// idempotent (an existing identical index is a no-op), so this runs
// unconditionally on every connect - the same "fail closed before serving
// traffic" role runPostgresMigrations plays for the Postgres backend, just
// without a separate migration-versioning tool since index creation needs
// none.
func (s *MongoStore) ensureIndexes(ctx context.Context) error {
	type target struct {
		coll  *mongo.Collection
		model mongo.IndexModel
	}
	targets := []target{
		{s.users, mongo.IndexModel{Keys: bson.D{{Key: "emailLower", Value: 1}}, Options: options.Index().SetUnique(true)}},
		{s.users, mongo.IndexModel{Keys: bson.D{{Key: "role", Value: 1}, {Key: "active", Value: 1}}}},

		{s.sessions, mongo.IndexModel{Keys: bson.D{{Key: "id", Value: 1}}, Options: options.Index().SetUnique(true)}},
		{s.sessions, mongo.IndexModel{Keys: bson.D{{Key: "userId", Value: 1}}}},

		{s.appSessions, mongo.IndexModel{
			Keys: bson.D{{Key: "opSessionId", Value: 1}, {Key: "clientId", Value: 1}},
			// Partial indexes only support a documented operator subset
			// that excludes $exists: false ($not is rejected outright).
			// {$eq: null} matches both an absent field and an explicit
			// null, which is exactly "endedAt was never set" here since
			// this store never writes endedAt: null.
			Options: options.Index().SetUnique(true).SetPartialFilterExpression(
				bson.D{{Key: "endedAt", Value: bson.D{{Key: "$eq", Value: nil}}}}),
		}},
		{s.appSessions, mongo.IndexModel{Keys: bson.D{{Key: "opSessionId", Value: 1}}}},
		{s.appSessions, mongo.IndexModel{Keys: bson.D{{Key: "clientId", Value: 1}}}},
		{s.appSessions, mongo.IndexModel{Keys: bson.D{{Key: "userId", Value: 1}}}},

		{s.oauthAccess, mongo.IndexModel{Keys: bson.D{{Key: "userId", Value: 1}}}},

		{s.refreshFamilies, mongo.IndexModel{Keys: bson.D{{Key: "clientId", Value: 1}}}},
		{s.refreshFamilies, mongo.IndexModel{Keys: bson.D{{Key: "userId", Value: 1}}}},
		{s.refreshFamilies, mongo.IndexModel{Keys: bson.D{{Key: "codeHash", Value: 1}}}},
		{s.refreshFamilies, mongo.IndexModel{Keys: bson.D{{Key: "tokens.hash", Value: 1}}}},
		{s.refreshFamilies, mongo.IndexModel{Keys: bson.D{{Key: "retainUntil", Value: 1}}}},

		{s.authzTransactions, mongo.IndexModel{Keys: bson.D{{Key: "clientId", Value: 1}}}},
		{s.authzTransactions, mongo.IndexModel{Keys: bson.D{{Key: "userId", Value: 1}}}},
		{s.authzTransactions, mongo.IndexModel{Keys: bson.D{{Key: "opSessionId", Value: 1}}}},
		{s.authzTransactions, mongo.IndexModel{Keys: bson.D{{Key: "expiresAt", Value: 1}}}},

		{s.authorizationCodes, mongo.IndexModel{Keys: bson.D{{Key: "clientId", Value: 1}}}},
		{s.authorizationCodes, mongo.IndexModel{Keys: bson.D{{Key: "userId", Value: 1}}}},
		{s.authorizationCodes, mongo.IndexModel{Keys: bson.D{{Key: "opSessionId", Value: 1}, {Key: "clientId", Value: 1}}}},
		{s.authorizationCodes, mongo.IndexModel{Keys: bson.D{{Key: "expiresAt", Value: 1}, {Key: "retainUntil", Value: 1}}}},

		{s.accessTokens, mongo.IndexModel{Keys: bson.D{{Key: "clientId", Value: 1}}}},
		{s.accessTokens, mongo.IndexModel{Keys: bson.D{{Key: "userId", Value: 1}}}},
		{s.accessTokens, mongo.IndexModel{Keys: bson.D{{Key: "familyId", Value: 1}}}},
		{s.accessTokens, mongo.IndexModel{Keys: bson.D{{Key: "codeHash", Value: 1}}}},
		{s.accessTokens, mongo.IndexModel{Keys: bson.D{{Key: "appSessionId", Value: 1}}}},
		{s.accessTokens, mongo.IndexModel{Keys: bson.D{{Key: "expiresAt", Value: 1}}}},

		{s.consents, mongo.IndexModel{Keys: bson.D{{Key: "clientId", Value: 1}}}},

		{s.initialAccessTokens, mongo.IndexModel{Keys: bson.D{{Key: "id", Value: 1}}, Options: options.Index().SetUnique(true)}},

		{s.registrationAccessTokens, mongo.IndexModel{Keys: bson.D{{Key: "hash", Value: 1}}, Options: options.Index().SetUnique(true)}},

		{s.logoutOperations, mongo.IndexModel{Keys: bson.D{{Key: "createdAt", Value: 1}}}},
		{s.logoutOperations, mongo.IndexModel{Keys: bson.D{{Key: "targets", Value: 1}}}},

		{s.logoutDeliveries, mongo.IndexModel{Keys: bson.D{{Key: "opSessionId", Value: 1}}}},
		{s.logoutDeliveries, mongo.IndexModel{Keys: bson.D{{Key: "appSessionId", Value: 1}}}},
		{s.logoutDeliveries, mongo.IndexModel{Keys: bson.D{{Key: "createdAt", Value: 1}}}},
		{s.logoutDeliveries, mongo.IndexModel{Keys: bson.D{{Key: "channel", Value: 1}, {Key: "status", Value: 1}, {Key: "nextAttempt", Value: 1}}}},

		{s.logoutInteractions, mongo.IndexModel{Keys: bson.D{{Key: "expiresAt", Value: 1}}}},
	}
	for _, t := range targets {
		if _, err := t.coll.Indexes().CreateOne(ctx, t.model); err != nil {
			return err
		}
	}
	return nil
}

func (s *MongoStore) Close(ctx context.Context) error { return s.client.Disconnect(ctx) }

func (s *MongoStore) Read(ctx context.Context, fn func(ReadTx) error) error {
	return s.withTransaction(ctx, func(tx *mongoTx) error { return fn(tx) })
}

func (s *MongoStore) Write(ctx context.Context, fn func(Tx) error) error {
	return s.withTransaction(ctx, func(tx *mongoTx) error { return fn(tx) })
}

// withTransaction runs fn inside one Mongo transaction using the driver's
// retry-aware WithTransaction helper (not the manual StartTransaction/
// CommitTransaction pattern the previous single-document design used),
// with snapshot read concern and majority write concern so a replica-set
// failover cannot roll back an acknowledged token-consumption write - the
// gap the original backend audit flagged. WithTransaction automatically
// retries the whole callback on TransientTransactionError/
// UnknownTransactionCommitResult, which is exactly the "a failed
// transaction committed nothing, so replaying the callback from scratch is
// safe" property Store.Write needs, mirroring the Postgres backend's
// retry-on-serialization-failure.
func (s *MongoStore) withTransaction(ctx context.Context, fn func(*mongoTx) error) error {
	session, err := s.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)

	txnOpts := options.Transaction().
		SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority())

	_, err = session.WithTransaction(ctx, func(sc context.Context) (any, error) {
		tx := &mongoTx{mongoOperations: bindMongoOperations(sc), store: s}
		if err := fn(tx); err != nil {
			return nil, err
		}
		return nil, tx.err
	}, txnOpts)
	return err
}
