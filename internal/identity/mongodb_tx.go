package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// mongoTx implements both ReadTx and Tx against one Mongo transaction
// (via the session-bound ctx). Mirrors postgresTx's error-poisoning
// pattern: Tx-only Save*/Delete*/Revoke* methods cannot return an error
// per the Store interface, so a failure "poisons" the transaction and the
// Store.Write caller (mongodb_store.go's withTransaction) still observes
// it via tx.err, causing the transaction to abort.
type mongoTx struct {
	ctx   context.Context
	store *MongoStore
	now   func() time.Time
	err   error
}

func (m *mongoTx) currentTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *mongoTx) fail(err error) {
	if m.err == nil && err != nil {
		m.err = err
	}
}

func (m *mongoTx) poisoned() bool { return m.err != nil }

func isDuplicateKey(err error) bool {
	var we mongo.WriteException
	if errors.As(err, &we) {
		for _, e := range we.WriteErrors {
			if e.Code == 11000 {
				return true
			}
		}
		return false
	}
	var ce mongo.CommandError
	return errors.As(err, &ce) && ce.Code == 11000
}

func notFoundOrErr(err error) error {
	if errors.Is(err, mongo.ErrNoDocuments) {
		return ErrNotFound
	}
	return err
}

// ---- Users ----

type userDoc struct {
	ID                  string                     `bson:"_id"`
	Email               string                     `bson:"email"`
	EmailLower          string                     `bson:"emailLower"`
	EmailVerified       bool                       `bson:"emailVerified"`
	PhoneNumberVerified bool                       `bson:"phoneNumberVerified"`
	Name                string                     `bson:"name"`
	Role                Role                       `bson:"role"`
	Active              bool                       `bson:"active"`
	PasswordHash        string                     `bson:"passwordHash"`
	GivenName           string                     `bson:"givenName,omitempty"`
	FamilyName          string                     `bson:"familyName,omitempty"`
	MiddleName          string                     `bson:"middleName,omitempty"`
	Nickname            string                     `bson:"nickname,omitempty"`
	PreferredUsername   string                     `bson:"preferredUsername,omitempty"`
	ProfileURL          string                     `bson:"profileUrl,omitempty"`
	Picture             string                     `bson:"picture,omitempty"`
	Website             string                     `bson:"website,omitempty"`
	Gender              string                     `bson:"gender,omitempty"`
	Birthdate           string                     `bson:"birthdate,omitempty"`
	Zoneinfo            string                     `bson:"zoneinfo,omitempty"`
	Locale              string                     `bson:"locale,omitempty"`
	PhoneNumber         string                     `bson:"phoneNumber,omitempty"`
	Address             Address                    `bson:"address"`
	CustomAttributes    map[string]json.RawMessage `bson:"customAttributes,omitempty"`
	CreatedAt           time.Time                  `bson:"createdAt"`
	UpdatedAt           time.Time                  `bson:"updatedAt"`
}

func userToDoc(u User) userDoc {
	return userDoc{
		ID: u.ID, Email: u.Email, EmailLower: strings.ToLower(u.Email), EmailVerified: u.EmailVerified,
		PhoneNumberVerified: u.PhoneNumberVerified, Name: u.Name, Role: u.Role, Active: u.Active, PasswordHash: u.PasswordHash,
		GivenName: u.GivenName, FamilyName: u.FamilyName, MiddleName: u.MiddleName, Nickname: u.Nickname,
		PreferredUsername: u.PreferredUsername, ProfileURL: u.ProfileURL, Picture: u.Picture, Website: u.Website,
		Gender: u.Gender, Birthdate: u.Birthdate, Zoneinfo: u.Zoneinfo, Locale: u.Locale, PhoneNumber: u.PhoneNumber,
		Address: u.Address, CustomAttributes: u.CustomAttributes, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

func docToUser(d userDoc) User {
	u := User{Profile: Profile{
		ID: d.ID, Email: d.Email, EmailVerified: d.EmailVerified, PhoneNumberVerified: d.PhoneNumberVerified,
		Name: d.Name, Role: d.Role, Active: d.Active, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}, PasswordHash: d.PasswordHash}
	u.GivenName, u.FamilyName, u.MiddleName = d.GivenName, d.FamilyName, d.MiddleName
	u.Nickname, u.PreferredUsername, u.ProfileURL = d.Nickname, d.PreferredUsername, d.ProfileURL
	u.Picture, u.Website, u.Gender, u.Birthdate = d.Picture, d.Website, d.Gender, d.Birthdate
	u.Zoneinfo, u.Locale, u.PhoneNumber = d.Zoneinfo, d.Locale, d.PhoneNumber
	u.Address, u.CustomAttributes = d.Address, d.CustomAttributes
	u.Sub = u.ID
	u.ClaimUpdatedAt = u.UpdatedAt.Unix()
	return u
}

func (m *mongoTx) User(id string) (User, error) {
	var d userDoc
	err := m.store.users.FindOne(m.ctx, bson.D{{Key: "_id", Value: id}}).Decode(&d)
	if err != nil {
		return User{}, notFoundOrErr(err)
	}
	return docToUser(d), nil
}

func (m *mongoTx) UserByEmail(email string) (User, error) {
	var d userDoc
	err := m.store.users.FindOne(m.ctx, bson.D{{Key: "emailLower", Value: strings.ToLower(email)}}).Decode(&d)
	if err != nil {
		return User{}, notFoundOrErr(err)
	}
	return docToUser(d), nil
}

func (m *mongoTx) Users() []User {
	cur, err := m.store.users.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []User
	for cur.Next(m.ctx) {
		var d userDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToUser(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

// SaveUser is the only fallible Tx mutator. Case-insensitive email
// uniqueness is enforced by the unique index on emailLower; a duplicate
// key error is translated to ErrConflict. A change to
// passwordHash/email/role/active cascades into DeleteUserSessions,
// matching fileState.SaveUser.
func (m *mongoTx) SaveUser(user User) error {
	if m.poisoned() {
		return m.err
	}
	existing, err := m.User(user.ID)
	hadOld := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	doc := userToDoc(user)
	_, err = m.store.users.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: user.ID}}, doc, options.Replace().SetUpsert(true))
	if err != nil {
		if isDuplicateKey(err) {
			return ErrConflict
		}
		return err
	}
	if hadOld && (existing.PasswordHash != user.PasswordHash || existing.Email != user.Email ||
		existing.Role != user.Role || existing.Active != user.Active) {
		m.DeleteUserSessions(user.ID)
	}
	return m.err
}

func (m *mongoTx) DeleteUser(id string) {
	if m.poisoned() {
		return
	}
	if _, err := m.store.oauthAccess.DeleteOne(m.ctx, bson.D{{Key: "_id", Value: id}}); err != nil {
		m.fail(err)
		return
	}
	m.DeleteUserSessions(id)
	if m.poisoned() {
		return
	}
	if _, err := m.store.users.DeleteOne(m.ctx, bson.D{{Key: "_id", Value: id}}); err != nil {
		m.fail(err)
	}
}

// DeleteUserSessions is the security cascade: revoke all access grants,
// hard-delete codes/transactions/consents, and end (not delete) every
// live session - order matches fileState.DeleteUserSessions.
func (m *mongoTx) DeleteUserSessions(userID string) {
	if m.poisoned() {
		return
	}
	m.RevokeAccessTokensForUser(userID)
	if m.poisoned() {
		return
	}
	if _, err := m.store.authorizationCodes.DeleteMany(m.ctx, bson.D{{Key: "userId", Value: userID}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.authzTransactions.DeleteMany(m.ctx, bson.D{{Key: "userId", Value: userID}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.consents.DeleteMany(m.ctx, bson.D{{Key: "userId", Value: userID}}); err != nil {
		m.fail(err)
		return
	}
	ids, err := m.distinctSessionIDs(bson.D{{Key: "userId", Value: userID}, {Key: "endedAt", Value: bson.D{{Key: "$exists", Value: false}}}})
	if err != nil {
		m.fail(err)
		return
	}
	now := m.currentTime()
	for _, id := range ids {
		m.EndSession(id, "security", "account_security_change", now)
	}
}

func (m *mongoTx) distinctSessionIDs(filter bson.D) ([]string, error) {
	cur, err := m.store.sessions.Find(m.ctx, filter, options.Find().SetProjection(bson.D{{Key: "id", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(m.ctx)
	var ids []string
	for cur.Next(m.ctx) {
		var doc struct {
			ID string `bson:"id"`
		}
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		ids = append(ids, doc.ID)
	}
	return ids, cur.Err()
}

// ---- Sessions ----

type sessionDoc struct {
	Hash       string     `bson:"_id"`
	ID         string     `bson:"id"`
	UserID     string     `bson:"userId"`
	Device     string     `bson:"device,omitempty"`
	CSRF       string     `bson:"csrf,omitempty"`
	CreatedAt  time.Time  `bson:"createdAt"`
	LastSeenAt time.Time  `bson:"lastSeenAt"`
	AuthTime   *time.Time `bson:"authTime,omitempty"`
	ExpiresAt  time.Time  `bson:"expiresAt"`
	EndedAt    *time.Time `bson:"endedAt,omitempty"`
	EndReason  string     `bson:"endReason,omitempty"`
}

func sessionToDoc(s Session) sessionDoc {
	d := sessionDoc{Hash: s.Hash, ID: s.ID, UserID: s.UserID, Device: s.Device, CSRF: s.CSRF, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt, EndReason: s.EndReason}
	if !s.AuthTime.IsZero() {
		d.AuthTime = &s.AuthTime
	}
	if !s.EndedAt.IsZero() {
		d.EndedAt = &s.EndedAt
	}
	return d
}

func docToSession(d sessionDoc) Session {
	s := Session{Hash: d.Hash, ID: d.ID, UserID: d.UserID, Device: d.Device, CSRF: d.CSRF, CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt, ExpiresAt: d.ExpiresAt, EndReason: d.EndReason}
	if d.AuthTime != nil {
		s.AuthTime = *d.AuthTime
	}
	if d.EndedAt != nil {
		s.EndedAt = *d.EndedAt
	}
	return s
}

// Session returns ErrNotFound for an ended session, matching
// fileState.Session - callers separately check ExpiresAt themselves.
func (m *mongoTx) Session(hash string) (Session, error) {
	var d sessionDoc
	err := m.store.sessions.FindOne(m.ctx, bson.D{{Key: "_id", Value: hash}, {Key: "endedAt", Value: bson.D{{Key: "$exists", Value: false}}}}).Decode(&d)
	if err != nil {
		return Session{}, notFoundOrErr(err)
	}
	return docToSession(d), nil
}

func (m *mongoTx) ListSessions() []Session {
	cur, err := m.store.sessions.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []Session
	for cur.Next(m.ctx) {
		var d sessionDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToSession(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

func (m *mongoTx) SaveSession(session Session) {
	if m.poisoned() {
		return
	}
	doc := sessionToDoc(session)
	_, err := m.store.sessions.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: session.Hash}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

// RemoveSessionCredential hard-deletes a session row without ending it -
// used only for credential rotation at login.
func (m *mongoTx) RemoveSessionCredential(hash string) {
	if m.poisoned() {
		return
	}
	_, err := m.store.sessions.DeleteOne(m.ctx, bson.D{{Key: "_id", Value: hash}})
	m.fail(err)
}

// DeleteSession is not a delete: it ends the session with reason
// "sign_out", matching fileState.DeleteSession.
func (m *mongoTx) DeleteSession(hash string) {
	if m.poisoned() {
		return
	}
	sess, err := m.Session(hash)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			m.fail(err)
		}
		return
	}
	m.EndSession(sess.ID, "user", "sign_out", m.currentTime())
}

func (m *mongoTx) CheckSessionCapacity(kind string) error {
	var coll *mongo.Collection
	var limit int64
	switch kind {
	case "op":
		coll, limit = m.store.sessions, 10000
	case "app":
		coll, limit = m.store.appSessions, 50000
	case "interaction":
		coll, limit = m.store.logoutInteractions, 10000
	default:
		return nil
	}
	// EstimatedDocumentCount uses the count command, which MongoDB
	// rejects inside a multi-document transaction
	// (OperationNotSupportedInTransaction) - CountDocuments (aggregation
	// based) is the transaction-safe alternative.
	count, err := coll.CountDocuments(m.ctx, bson.D{})
	if err != nil {
		return err
	}
	if count >= limit {
		return errors.New(kind + " capacity exceeded")
	}
	return nil
}

// EndSession ends every live session row with the given logical ID,
// cascading exactly as fileState.EndSession: emit a local logout
// delivery, end every app session tied to it, and revoke (not delete)
// transactions/codes tied to it.
func (m *mongoTx) EndSession(id, actor, reason string, now time.Time) {
	if m.poisoned() {
		return
	}
	cur, err := m.store.sessions.Find(m.ctx, bson.D{{Key: "id", Value: id}, {Key: "endedAt", Value: bson.D{{Key: "$exists", Value: false}}}})
	if err != nil {
		m.fail(err)
		return
	}
	type liveSession struct {
		Hash   string `bson:"_id"`
		UserID string `bson:"userId"`
	}
	var live []liveSession
	for cur.Next(m.ctx) {
		var l liveSession
		if err := cur.Decode(&l); err != nil {
			cur.Close(m.ctx)
			m.fail(err)
			return
		}
		live = append(live, l)
	}
	cur.Close(m.ctx)
	if err := cur.Err(); err != nil {
		m.fail(err)
		return
	}
	for _, l := range live {
		_, err := m.store.sessions.UpdateOne(m.ctx,
			bson.D{{Key: "_id", Value: l.Hash}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "endedAt", Value: now}, {Key: "endReason", Value: reason}, {Key: "csrf", Value: ""}}}},
		)
		if err != nil {
			m.fail(err)
			return
		}
		m.SaveLogoutDelivery(LogoutDelivery{ID: "op-" + id, OPSessionID: id, UserID: l.UserID, Actor: actor, Reason: reason, Channel: "local", Status: "ended", CreatedAt: now, UpdatedAt: now})

		appCur, err := m.store.appSessions.Find(m.ctx, bson.D{{Key: "opSessionId", Value: id}, {Key: "endedAt", Value: bson.D{{Key: "$exists", Value: false}}}}, options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}))
		if err != nil {
			m.fail(err)
			return
		}
		var appIDs []string
		for appCur.Next(m.ctx) {
			var doc struct {
				ID string `bson:"_id"`
			}
			if err := appCur.Decode(&doc); err != nil {
				appCur.Close(m.ctx)
				m.fail(err)
				return
			}
			appIDs = append(appIDs, doc.ID)
		}
		appCur.Close(m.ctx)
		if err := appCur.Err(); err != nil {
			m.fail(err)
			return
		}
		for _, appID := range appIDs {
			m.EndAppSession(appID, actor, reason, now)
		}

		if _, err := m.store.authzTransactions.UpdateMany(m.ctx, bson.D{{Key: "opSessionId", Value: id}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
			m.fail(err)
			return
		}
		if _, err := m.store.authorizationCodes.UpdateMany(m.ctx, bson.D{{Key: "opSessionId", Value: id}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
			m.fail(err)
			return
		}
	}
}

// ---- AppSessions ----

type appSessionDoc struct {
	ID          string     `bson:"_id"`
	OPSessionID string     `bson:"opSessionId"`
	ClientID    string     `bson:"clientId"`
	UserID      string     `bson:"userId"`
	Subject     string     `bson:"subject,omitempty"`
	CreatedAt   time.Time  `bson:"createdAt"`
	LastSeenAt  time.Time  `bson:"lastSeenAt"`
	EndedAt     *time.Time `bson:"endedAt,omitempty"`
	EndReason   string     `bson:"endReason,omitempty"`
}

func appSessionToDoc(a AppSession) appSessionDoc {
	d := appSessionDoc{ID: a.ID, OPSessionID: a.OPSessionID, ClientID: a.ClientID, UserID: a.UserID, Subject: a.Subject, CreatedAt: a.CreatedAt, LastSeenAt: a.LastSeenAt, EndReason: a.EndReason}
	if !a.EndedAt.IsZero() {
		d.EndedAt = &a.EndedAt
	}
	return d
}

func docToAppSession(d appSessionDoc) AppSession {
	a := AppSession{ID: d.ID, OPSessionID: d.OPSessionID, ClientID: d.ClientID, UserID: d.UserID, Subject: d.Subject, CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt, EndReason: d.EndReason}
	if d.EndedAt != nil {
		a.EndedAt = *d.EndedAt
	}
	return a
}

func (m *mongoTx) AppSession(id string) (AppSession, error) {
	var d appSessionDoc
	err := m.store.appSessions.FindOne(m.ctx, bson.D{{Key: "_id", Value: id}}).Decode(&d)
	if err != nil {
		return AppSession{}, notFoundOrErr(err)
	}
	return docToAppSession(d), nil
}

func (m *mongoTx) ListAppSessions() []AppSession {
	cur, err := m.store.appSessions.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []AppSession
	for cur.Next(m.ctx) {
		var d appSessionDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToAppSession(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

func (m *mongoTx) SaveAppSession(a AppSession) {
	if m.poisoned() {
		return
	}
	doc := appSessionToDoc(a)
	_, err := m.store.appSessions.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: a.ID}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

// EndAppSession cascades exactly as fileState.EndAppSession: revoke
// non-family-backed access tokens, revoke (not delete) transactions/codes
// matched by the (op_session_id, client_id) pair, and emit logout
// deliveries derived from the client's current front/back-channel logout
// URIs.
func (m *mongoTx) EndAppSession(id, actor, reason string, now time.Time) {
	if m.poisoned() {
		return
	}
	a, err := m.AppSession(id)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			m.fail(err)
		}
		return
	}
	if !a.EndedAt.IsZero() {
		return
	}
	if _, err := m.store.appSessions.UpdateOne(m.ctx, bson.D{{Key: "_id", Value: id}}, bson.D{{Key: "$set", Value: bson.D{{Key: "endedAt", Value: now}, {Key: "endReason", Value: reason}}}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.accessTokens.UpdateMany(m.ctx, bson.D{{Key: "appSessionId", Value: id}, {Key: "familyId", Value: ""}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.authorizationCodes.UpdateMany(m.ctx, bson.D{{Key: "opSessionId", Value: a.OPSessionID}, {Key: "clientId", Value: a.ClientID}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.authzTransactions.UpdateMany(m.ctx, bson.D{{Key: "opSessionId", Value: a.OPSessionID}, {Key: "clientId", Value: a.ClientID}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
		m.fail(err)
		return
	}

	var clientDoc struct {
		Metadata ClientMetadata `bson:"metadata"`
	}
	err = m.store.clients.FindOne(m.ctx, bson.D{{Key: "_id", Value: a.ClientID}}, options.FindOne().SetProjection(bson.D{{Key: "metadata", Value: 1}})).Decode(&clientDoc)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		m.fail(err)
		return
	}

	backchannel := clientDoc.Metadata.text("backchannel_logout_uri")
	frontchannel := clientDoc.Metadata.text("frontchannel_logout_uri")
	supported := false
	if backchannel != "" {
		supported = true
		m.SaveLogoutDelivery(LogoutDelivery{ID: id + "-backchannel", OPSessionID: a.OPSessionID, AppSessionID: id, ClientID: a.ClientID, UserID: a.UserID, Subject: a.Subject, Actor: actor, Reason: reason, Channel: "backchannel", Status: "pending", Endpoint: backchannel, CreatedAt: now, UpdatedAt: now, NextAttempt: now})
	}
	if frontchannel != "" {
		supported = true
		m.SaveLogoutDelivery(LogoutDelivery{ID: id + "-frontchannel", OPSessionID: a.OPSessionID, AppSessionID: id, ClientID: a.ClientID, UserID: a.UserID, Subject: a.Subject, Actor: actor, Reason: reason, Channel: "frontchannel", Status: "browser_unavailable", Endpoint: frontchannel, CreatedAt: now, UpdatedAt: now, NextAttempt: now})
	}
	if !supported {
		m.SaveLogoutDelivery(LogoutDelivery{ID: id + "-unsupported", OPSessionID: a.OPSessionID, AppSessionID: id, ClientID: a.ClientID, UserID: a.UserID, Actor: actor, Reason: reason, Channel: "none", Status: "unsupported", CreatedAt: now, UpdatedAt: now})
	}
}

// ---- LogoutOperations ----

type logoutOperationDoc struct {
	ID        string    `bson:"_id"`
	Actor     string    `bson:"actor,omitempty"`
	Kind      string    `bson:"kind"`
	CreatedAt time.Time `bson:"createdAt"`
	Targets   []string  `bson:"targets,omitempty"`
}

func (m *mongoTx) LogoutOperation(id string) (LogoutOperation, error) {
	var d logoutOperationDoc
	err := m.store.logoutOperations.FindOne(m.ctx, bson.D{{Key: "_id", Value: id}}).Decode(&d)
	if err != nil {
		return LogoutOperation{}, notFoundOrErr(err)
	}
	return LogoutOperation{ID: d.ID, Actor: d.Actor, Kind: d.Kind, CreatedAt: d.CreatedAt, Targets: d.Targets}, nil
}

// SaveLogoutOperation bounds operational history at 10000 documents,
// evicting the oldest by created_at before inserting - matching
// fileState's O(n) eviction, expressed as a count-then-delete-oldest pair.
func (m *mongoTx) SaveLogoutOperation(op LogoutOperation) {
	if m.poisoned() {
		return
	}
	count, err := m.store.logoutOperations.CountDocuments(m.ctx, bson.D{})
	if err != nil {
		m.fail(err)
		return
	}
	if count >= 10000 {
		var oldest struct {
			ID string `bson:"_id"`
		}
		err := m.store.logoutOperations.FindOne(m.ctx, bson.D{}, options.FindOne().SetSort(bson.D{{Key: "createdAt", Value: 1}}).SetProjection(bson.D{{Key: "_id", Value: 1}})).Decode(&oldest)
		if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			m.fail(err)
			return
		}
		if oldest.ID != "" {
			if _, err := m.store.logoutOperations.DeleteOne(m.ctx, bson.D{{Key: "_id", Value: oldest.ID}}); err != nil {
				m.fail(err)
				return
			}
		}
	}
	doc := logoutOperationDoc{ID: op.ID, Actor: op.Actor, Kind: op.Kind, CreatedAt: op.CreatedAt, Targets: op.Targets}
	_, err = m.store.logoutOperations.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: op.ID}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

// ---- LogoutDeliveries ----

type logoutDeliveryDoc struct {
	ID           string          `bson:"_id"`
	OPSessionID  string          `bson:"opSessionId,omitempty"`
	AppSessionID string          `bson:"appSessionId,omitempty"`
	ClientID     string          `bson:"clientId,omitempty"`
	UserID       string          `bson:"userId,omitempty"`
	Subject      string          `bson:"subject,omitempty"`
	Actor        string          `bson:"actor,omitempty"`
	Reason       string          `bson:"reason,omitempty"`
	Channel      string          `bson:"channel"`
	Status       string          `bson:"status"`
	Endpoint     string          `bson:"endpoint,omitempty"`
	History      []LogoutAttempt `bson:"history,omitempty"`
	CreatedAt    time.Time       `bson:"createdAt"`
	UpdatedAt    time.Time       `bson:"updatedAt"`
	NextAttempt  time.Time       `bson:"nextAttempt"`
	LeaseUntil   *time.Time      `bson:"leaseUntil,omitempty"`
	LeaseID      string          `bson:"leaseId,omitempty"`
	Attempts     int             `bson:"attempts"`
	HTTPStatus   int             `bson:"httpStatus,omitempty"`
	ErrorCode    string          `bson:"errorCode,omitempty"`
}

func logoutDeliveryToDoc(d LogoutDelivery) logoutDeliveryDoc {
	doc := logoutDeliveryDoc{
		ID: d.ID, OPSessionID: d.OPSessionID, AppSessionID: d.AppSessionID, ClientID: d.ClientID, UserID: d.UserID,
		Subject: d.Subject, Actor: d.Actor, Reason: d.Reason, Channel: d.Channel, Status: d.Status, Endpoint: d.Endpoint,
		History: d.History, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt, NextAttempt: d.NextAttempt,
		LeaseID: d.LeaseID, Attempts: d.Attempts, HTTPStatus: d.HTTPStatus, ErrorCode: d.ErrorCode,
	}
	if !d.LeaseUntil.IsZero() {
		doc.LeaseUntil = &d.LeaseUntil
	}
	return doc
}

func docToLogoutDelivery(d logoutDeliveryDoc) LogoutDelivery {
	out := LogoutDelivery{
		ID: d.ID, OPSessionID: d.OPSessionID, AppSessionID: d.AppSessionID, ClientID: d.ClientID, UserID: d.UserID,
		Subject: d.Subject, Actor: d.Actor, Reason: d.Reason, Channel: d.Channel, Status: d.Status, Endpoint: d.Endpoint,
		History: d.History, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt, NextAttempt: d.NextAttempt,
		LeaseID: d.LeaseID, Attempts: d.Attempts, HTTPStatus: d.HTTPStatus, ErrorCode: d.ErrorCode,
	}
	if d.LeaseUntil != nil {
		out.LeaseUntil = *d.LeaseUntil
	}
	return out
}

func (m *mongoTx) ListLogoutDeliveries() []LogoutDelivery {
	cur, err := m.store.logoutDeliveries.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []LogoutDelivery
	for cur.Next(m.ctx) {
		var d logoutDeliveryDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToLogoutDelivery(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

// SaveLogoutDelivery relies on the caller (EndSession/EndAppSession) to
// have built a deterministic id, so ReplaceOne+upsert reproduces the
// idempotent-overwrite semantics fileState gets for free from map[id]=v.
func (m *mongoTx) SaveLogoutDelivery(d LogoutDelivery) {
	if m.poisoned() {
		return
	}
	doc := logoutDeliveryToDoc(d)
	_, err := m.store.logoutDeliveries.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: d.ID}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

// ---- LogoutInteractions ----

type logoutInteractionDoc struct {
	ID           string    `bson:"_id"`
	ClientID     string    `bson:"clientId,omitempty"`
	AppSessionID string    `bson:"appSessionId,omitempty"`
	BindingHash  string    `bson:"bindingHash,omitempty"`
	CSRF         string    `bson:"csrf,omitempty"`
	OPSessionID  string    `bson:"opSessionId,omitempty"`
	UserID       string    `bson:"userId,omitempty"`
	RedirectURI  string    `bson:"redirectUri,omitempty"`
	State        string    `bson:"state,omitempty"`
	ExpiresAt    time.Time `bson:"expiresAt"`
	Completed    bool      `bson:"completed"`
}

func (m *mongoTx) LogoutInteraction(id string) (LogoutInteraction, error) {
	var d logoutInteractionDoc
	err := m.store.logoutInteractions.FindOne(m.ctx, bson.D{{Key: "_id", Value: id}}).Decode(&d)
	if err != nil {
		return LogoutInteraction{}, notFoundOrErr(err)
	}
	return LogoutInteraction{
		ID: d.ID, ClientID: d.ClientID, AppSessionID: d.AppSessionID, BindingHash: d.BindingHash, CSRF: d.CSRF,
		OPSessionID: d.OPSessionID, UserID: d.UserID, RedirectURI: d.RedirectURI, State: d.State, ExpiresAt: d.ExpiresAt, Completed: d.Completed,
	}, nil
}

func (m *mongoTx) SaveLogoutInteraction(v LogoutInteraction) {
	if m.poisoned() {
		return
	}
	doc := logoutInteractionDoc{
		ID: v.ID, ClientID: v.ClientID, AppSessionID: v.AppSessionID, BindingHash: v.BindingHash, CSRF: v.CSRF,
		OPSessionID: v.OPSessionID, UserID: v.UserID, RedirectURI: v.RedirectURI, State: v.State, ExpiresAt: v.ExpiresAt, Completed: v.Completed,
	}
	_, err := m.store.logoutInteractions.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: v.ID}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

func (m *mongoTx) LogoutMaintenanceDue(now time.Time) bool {
	// No persisted "last swept at" marker exists in fileState either;
	// maintenance is always considered due, and the prune queries below
	// are cheap no-ops when there is nothing to do.
	return true
}

// ---- Pruning ----

func (m *mongoTx) PruneSessions(now time.Time) {
	if m.poisoned() {
		return
	}
	ids, err := m.distinctSessionIDs(bson.D{{Key: "endedAt", Value: bson.D{{Key: "$exists", Value: false}}}, {Key: "expiresAt", Value: bson.D{{Key: "$lte", Value: now}}}})
	if err != nil {
		m.fail(err)
		return
	}
	for _, id := range ids {
		m.EndSession(id, "system", "expired", now)
	}
}

// PruneLogoutState ends expired sessions, then hard-deletes 30-day-old
// logout operations/deliveries, expired logout interactions, and 30-day-
// ended app sessions/sessions - matching fileState.PruneLogoutState.
func (m *mongoTx) PruneLogoutState(now time.Time) {
	if m.poisoned() {
		return
	}
	m.PruneSessions(now)
	if m.poisoned() {
		return
	}
	cutoff := now.Add(-30 * 24 * time.Hour)
	ops := []struct {
		coll   *mongo.Collection
		filter bson.D
	}{
		{m.store.logoutOperations, bson.D{{Key: "createdAt", Value: bson.D{{Key: "$lt", Value: cutoff}}}}},
		{m.store.logoutInteractions, bson.D{{Key: "expiresAt", Value: bson.D{{Key: "$lte", Value: now}}}}},
		{m.store.logoutDeliveries, bson.D{{Key: "createdAt", Value: bson.D{{Key: "$lt", Value: cutoff}}}}},
		{m.store.appSessions, bson.D{{Key: "endedAt", Value: bson.D{{Key: "$exists", Value: true}, {Key: "$lt", Value: cutoff}}}}},
		{m.store.sessions, bson.D{{Key: "endedAt", Value: bson.D{{Key: "$exists", Value: true}, {Key: "$lt", Value: cutoff}}}}},
	}
	for _, op := range ops {
		if _, err := op.coll.DeleteMany(m.ctx, op.filter); err != nil {
			m.fail(err)
			return
		}
	}
}

// PruneOIDCState deletes expired transactions, expired-and-retention-
// lapsed codes, expired access tokens, and refresh families past their
// retain_until - matching fileState.PruneOIDCState exactly, including the
// dual-condition authorization_codes predicate that protects
// replay-detection evidence.
func (m *mongoTx) PruneOIDCState(now time.Time) {
	if m.poisoned() {
		return
	}
	if _, err := m.store.refreshFamilies.DeleteMany(m.ctx, bson.D{{Key: "retainUntil", Value: bson.D{{Key: "$lte", Value: now}}}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.authzTransactions.DeleteMany(m.ctx, bson.D{{Key: "expiresAt", Value: bson.D{{Key: "$lte", Value: now}}}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.authorizationCodes.DeleteMany(m.ctx, bson.D{
		{Key: "expiresAt", Value: bson.D{{Key: "$lte", Value: now}}},
		{Key: "$or", Value: bson.A{
			bson.D{{Key: "retainUntil", Value: bson.D{{Key: "$exists", Value: false}}}},
			bson.D{{Key: "retainUntil", Value: bson.D{{Key: "$lte", Value: now}}}},
		}},
	}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.accessTokens.DeleteMany(m.ctx, bson.D{{Key: "expiresAt", Value: bson.D{{Key: "$lte", Value: now}}}}); err != nil {
		m.fail(err)
	}
}

// ---- Access tokens / revocation ----

type accessTokenDoc struct {
	Hash             string     `bson:"_id"`
	ClientID         string     `bson:"clientId"`
	UserID           string     `bson:"userId,omitempty"`
	Audience         string     `bson:"audience,omitempty"`
	Scopes           []string   `bson:"scopes,omitempty"`
	GrantType        string     `bson:"grantType,omitempty"`
	SubjectKind      string     `bson:"subjectKind,omitempty"`
	FamilyID         string     `bson:"familyId,omitempty"`
	OriginalGrant    string     `bson:"originalGrant,omitempty"`
	CodeHash         string     `bson:"codeHash,omitempty"`
	OPSessionID      string     `bson:"opSessionId,omitempty"`
	AppSessionID     string     `bson:"appSessionId,omitempty"`
	IDTokenExpiresAt *time.Time `bson:"idTokenExpiresAt,omitempty"`
	IssuedAt         time.Time  `bson:"issuedAt"`
	ExpiresAt        time.Time  `bson:"expiresAt"`
	Revoked          bool       `bson:"revoked"`
}

func accessTokenToDoc(a AccessToken) accessTokenDoc {
	d := accessTokenDoc{
		Hash: a.Hash, ClientID: a.ClientID, UserID: a.UserID, Audience: a.Audience, Scopes: a.Scopes,
		GrantType: a.GrantType, SubjectKind: a.SubjectKind, FamilyID: a.FamilyID, OriginalGrant: a.OriginalGrant,
		CodeHash: a.CodeHash, OPSessionID: a.OPSessionID, AppSessionID: a.AppSessionID, IssuedAt: a.IssuedAt, ExpiresAt: a.ExpiresAt, Revoked: a.Revoked,
	}
	if !a.IDTokenExpiresAt.IsZero() {
		d.IDTokenExpiresAt = &a.IDTokenExpiresAt
	}
	return d
}

func docToAccessToken(d accessTokenDoc) AccessToken {
	a := AccessToken{
		Hash: d.Hash, ClientID: d.ClientID, UserID: d.UserID, Audience: d.Audience, Scopes: d.Scopes,
		GrantType: d.GrantType, SubjectKind: d.SubjectKind, FamilyID: d.FamilyID, OriginalGrant: d.OriginalGrant,
		CodeHash: d.CodeHash, OPSessionID: d.OPSessionID, AppSessionID: d.AppSessionID, IssuedAt: d.IssuedAt, ExpiresAt: d.ExpiresAt, Revoked: d.Revoked,
	}
	if d.IDTokenExpiresAt != nil {
		a.IDTokenExpiresAt = *d.IDTokenExpiresAt
	}
	return a
}

func (m *mongoTx) AccessToken(hash string) (AccessToken, error) {
	var d accessTokenDoc
	err := m.store.accessTokens.FindOne(m.ctx, bson.D{{Key: "_id", Value: hash}}).Decode(&d)
	if err != nil {
		return AccessToken{}, notFoundOrErr(err)
	}
	return docToAccessToken(d), nil
}

func (m *mongoTx) ListAccessTokens() []AccessToken {
	cur, err := m.store.accessTokens.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "issuedAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []AccessToken
	for cur.Next(m.ctx) {
		var d accessTokenDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToAccessToken(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

func (m *mongoTx) SaveAccessToken(a AccessToken) {
	if m.poisoned() {
		return
	}
	doc := accessTokenToDoc(a)
	_, err := m.store.accessTokens.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: a.Hash}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

func (m *mongoTx) RevokeAccessToken(hash string) {
	if m.poisoned() {
		return
	}
	_, err := m.store.accessTokens.UpdateOne(m.ctx, bson.D{{Key: "_id", Value: hash}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}})
	m.fail(err)
}

func (m *mongoTx) RevokeAccessTokensForUser(userID string) {
	if m.poisoned() {
		return
	}
	m.revokeFamiliesMatching(bson.D{{Key: "userId", Value: userID}})
	if m.poisoned() {
		return
	}
	if _, err := m.store.accessTokens.UpdateMany(m.ctx, bson.D{{Key: "userId", Value: userID}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
		m.fail(err)
	}
}

func (m *mongoTx) RevokeAccessTokensForClient(clientID string) {
	if m.poisoned() {
		return
	}
	m.revokeFamiliesMatching(bson.D{{Key: "clientId", Value: clientID}})
	if m.poisoned() {
		return
	}
	if _, err := m.store.accessTokens.UpdateMany(m.ctx, bson.D{{Key: "clientId", Value: clientID}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
		m.fail(err)
	}
}

func (m *mongoTx) RevokeAccessTokensForCode(codeHash string) {
	if m.poisoned() {
		return
	}
	m.revokeFamiliesMatching(bson.D{{Key: "codeHash", Value: codeHash}})
	if m.poisoned() {
		return
	}
	if _, err := m.store.accessTokens.UpdateMany(m.ctx, bson.D{{Key: "codeHash", Value: codeHash}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
		m.fail(err)
	}
}

// revokeFamiliesMatching revokes every refresh family matching the given
// filter, one at a time via RevokeRefreshFamily so each family's own
// access-token cascade also runs.
func (m *mongoTx) revokeFamiliesMatching(filter bson.D) {
	filter = append(bson.D{{Key: "revoked", Value: bson.D{{Key: "$ne", Value: true}}}}, filter...)
	cur, err := m.store.refreshFamilies.Find(m.ctx, filter, options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		m.fail(err)
		return
	}
	var ids []string
	for cur.Next(m.ctx) {
		var doc struct {
			ID string `bson:"_id"`
		}
		if err := cur.Decode(&doc); err != nil {
			cur.Close(m.ctx)
			m.fail(err)
			return
		}
		ids = append(ids, doc.ID)
	}
	cur.Close(m.ctx)
	if err := cur.Err(); err != nil {
		m.fail(err)
		return
	}
	for _, id := range ids {
		m.RevokeRefreshFamily(id)
	}
}

// ---- Clients (embeds OAuthPolicy) ----

type oauthPolicyDoc struct {
	Grants                 []string                  `bson:"grants,omitempty"`
	Resources              map[string]ResourceScopes `bson:"resources,omitempty"`
	DefaultResource        string                    `bson:"defaultResource,omitempty"`
	IntrospectionEnabled   bool                      `bson:"introspectionEnabled"`
	IntrospectionAudiences []string                  `bson:"introspectionAudiences,omitempty"`
	RefreshInspection      bool                      `bson:"refreshInspection"`
	RefreshEnabled         bool                      `bson:"refreshEnabled"`
	PasswordEnabled        bool                      `bson:"passwordEnabled"`
}

type clientDoc struct {
	ID             string          `bson:"_id"`
	Origin         string          `bson:"origin,omitempty"`
	InitialTokenID string          `bson:"initialTokenId,omitempty"`
	Metadata       ClientMetadata  `bson:"metadata"`
	Secret         string          `bson:"secret,omitempty"`
	IssuedAt       int64           `bson:"issuedAt"`
	UpdatedAt      time.Time       `bson:"updatedAt"`
	UpdatedAtNS    int64           `bson:"updatedAtNs"`
	OAuthPolicy    *oauthPolicyDoc `bson:"oauthPolicy,omitempty"`
}

// docToClient reconstructs UpdatedAt from the separate updatedAtNs int64
// field, not the updatedAt BSON Date field: BSON Date has only
// millisecond precision, but UpdatedAt.UnixNano() is compared for exact
// equality against RefreshFamily.ClientRevision, Consent.PolicyRevision,
// and AuthzTransaction/AuthorizationCode.ClientUpdatedAt elsewhere in the
// domain - returning the truncated Date value here would silently break
// every one of those revision-pin comparisons.
func docToClient(d clientDoc) ClientRecord {
	return ClientRecord{ID: d.ID, Origin: d.Origin, InitialTokenID: d.InitialTokenID, Metadata: d.Metadata, Secret: d.Secret, IssuedAt: d.IssuedAt, UpdatedAt: time.Unix(0, d.UpdatedAtNS).UTC()}
}

func (m *mongoTx) Client(id string) (ClientRecord, error) {
	var d clientDoc
	err := m.store.clients.FindOne(m.ctx, bson.D{{Key: "_id", Value: id}}).Decode(&d)
	if err != nil {
		return ClientRecord{}, notFoundOrErr(err)
	}
	return docToClient(d), nil
}

func (m *mongoTx) Clients() []ClientRecord {
	cur, err := m.store.clients.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "issuedAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []ClientRecord
	for cur.Next(m.ctx) {
		var d clientDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToClient(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

// SaveClient enforces the strict monotonic UpdatedAt bump (store.go:
// "SaveClient must advance UpdatedAt monotonically, even with an unchanged
// clock") and, on any update to an existing client, invalidates its
// grants - matching fileState.SaveClient. The embedded oauthPolicy
// subdocument is preserved across the replace (it is only ever written by
// SaveOAuthPolicy, never by SaveClient), by reading it back first.
func (m *mongoTx) SaveClient(c ClientRecord) {
	if m.poisoned() {
		return
	}
	var existing clientDoc
	err := m.store.clients.FindOne(m.ctx, bson.D{{Key: "_id", Value: c.ID}}).Decode(&existing)
	hadOld := err == nil
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		m.fail(err)
		return
	}
	existingUpdatedAt := time.Unix(0, existing.UpdatedAtNS).UTC()
	if hadOld && !c.UpdatedAt.After(existingUpdatedAt) {
		c.UpdatedAt = existingUpdatedAt.Add(time.Nanosecond)
	}
	doc := clientDoc{ID: c.ID, Origin: c.Origin, InitialTokenID: c.InitialTokenID, Metadata: c.Metadata, Secret: c.Secret, IssuedAt: c.IssuedAt, UpdatedAt: c.UpdatedAt, UpdatedAtNS: c.UpdatedAt.UnixNano()}
	if hadOld {
		doc.OAuthPolicy = existing.OAuthPolicy
	}
	_, err = m.store.clients.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: c.ID}}, doc, options.Replace().SetUpsert(true))
	if err != nil {
		m.fail(err)
		return
	}
	if hadOld {
		m.invalidateClientGrants(c.ID)
	}
}

func (m *mongoTx) DeleteClient(id string) {
	if m.poisoned() {
		return
	}
	m.DeleteRegistrationToken(id)
	m.invalidateClientGrants(id)
	if m.poisoned() {
		return
	}
	if _, err := m.store.clients.DeleteOne(m.ctx, bson.D{{Key: "_id", Value: id}}); err != nil {
		m.fail(err)
	}
}

// invalidateClientGrants: end every app session for the client, revoke its
// access tokens/refresh families, and hard-delete its authorization
// codes, authz transactions, and consents - matching
// fileState.invalidateClientGrants exactly. The client's oauthPolicy
// subdocument itself is never touched here (deleting the client document
// removes it along with everything else, matching
// fileState.DeleteClient's delete(OAuthPolicies, id)).
func (m *mongoTx) invalidateClientGrants(clientID string) {
	if m.poisoned() {
		return
	}
	cur, err := m.store.appSessions.Find(m.ctx, bson.D{{Key: "clientId", Value: clientID}, {Key: "endedAt", Value: bson.D{{Key: "$exists", Value: false}}}}, options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		m.fail(err)
		return
	}
	var appIDs []string
	for cur.Next(m.ctx) {
		var doc struct {
			ID string `bson:"_id"`
		}
		if err := cur.Decode(&doc); err != nil {
			cur.Close(m.ctx)
			m.fail(err)
			return
		}
		appIDs = append(appIDs, doc.ID)
	}
	cur.Close(m.ctx)
	if err := cur.Err(); err != nil {
		m.fail(err)
		return
	}
	now := m.currentTime()
	for _, id := range appIDs {
		m.EndAppSession(id, "security", "client_changed", now)
	}
	m.RevokeAccessTokensForClient(clientID)
	if m.poisoned() {
		return
	}
	if _, err := m.store.authorizationCodes.DeleteMany(m.ctx, bson.D{{Key: "clientId", Value: clientID}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.authzTransactions.DeleteMany(m.ctx, bson.D{{Key: "clientId", Value: clientID}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.consents.DeleteMany(m.ctx, bson.D{{Key: "clientId", Value: clientID}}); err != nil {
		m.fail(err)
	}
}

// ---- OAuthPolicy (embedded in clients) / OAuthAccess ----
//
// Both read paths return the Go zero value for a missing row, never
// ErrNotFound - AccessTokenActive and RefreshFamilyActive call them
// unconditionally and depend on this.

func (m *mongoTx) OAuthPolicy(id string) OAuthPolicy {
	var d struct {
		OAuthPolicy *oauthPolicyDoc `bson:"oauthPolicy"`
	}
	err := m.store.clients.FindOne(m.ctx, bson.D{{Key: "_id", Value: id}}, options.FindOne().SetProjection(bson.D{{Key: "oauthPolicy", Value: 1}})).Decode(&d)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) {
			m.fail(err)
		}
		return OAuthPolicy{}
	}
	if d.OAuthPolicy == nil {
		return OAuthPolicy{}
	}
	p := d.OAuthPolicy
	return OAuthPolicy{
		Grants: p.Grants, Resources: p.Resources, DefaultResource: p.DefaultResource,
		IntrospectionEnabled: p.IntrospectionEnabled, IntrospectionAudiences: p.IntrospectionAudiences,
		RefreshInspection: p.RefreshInspection, RefreshEnabled: p.RefreshEnabled, PasswordEnabled: p.PasswordEnabled,
	}
}

// SaveOAuthPolicy invalidates the client's grants exactly like SaveClient -
// any policy change can widen or narrow what existing tokens/families are
// entitled to, so they must be re-evaluated from a clean slate. Requires
// the client document to already exist (matching the Postgres backend's
// FK-equivalent contract - fileState.SaveOAuthPolicy has no such
// requirement since it's keyed independently, but every caller in
// internal/api only calls this for an existing client).
func (m *mongoTx) SaveOAuthPolicy(id string, policy OAuthPolicy) {
	if m.poisoned() {
		return
	}
	doc := oauthPolicyDoc{
		Grants: policy.Grants, Resources: policy.Resources, DefaultResource: policy.DefaultResource,
		IntrospectionEnabled: policy.IntrospectionEnabled, IntrospectionAudiences: policy.IntrospectionAudiences,
		RefreshInspection: policy.RefreshInspection, RefreshEnabled: policy.RefreshEnabled, PasswordEnabled: policy.PasswordEnabled,
	}
	res, err := m.store.clients.UpdateOne(m.ctx, bson.D{{Key: "_id", Value: id}}, bson.D{{Key: "$set", Value: bson.D{{Key: "oauthPolicy", Value: doc}}}})
	if err != nil {
		m.fail(err)
		return
	}
	if res.MatchedCount == 0 {
		m.fail(ErrNotFound)
		return
	}
	m.invalidateClientGrants(id)
}

func (m *mongoTx) OAuthAccess(id string) OAuthAccess {
	var d struct {
		Access map[string][]string `bson:"access"`
	}
	err := m.store.oauthAccess.FindOne(m.ctx, bson.D{{Key: "_id", Value: id}}).Decode(&d)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) {
			m.fail(err)
		}
		return OAuthAccess{}
	}
	out := OAuthAccess{}
	for k, v := range d.Access {
		out[k] = v
	}
	return out
}

// SaveOAuthAccess replaces the user's entire access map (matching
// fileState's whole-map replace semantics), then cascades: end their app
// sessions and revoke their tokens/families.
func (m *mongoTx) SaveOAuthAccess(id string, access OAuthAccess) {
	if m.poisoned() {
		return
	}
	doc := bson.D{{Key: "_id", Value: id}, {Key: "userId", Value: id}, {Key: "access", Value: map[string][]string(access)}}
	_, err := m.store.oauthAccess.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: id}}, doc, options.Replace().SetUpsert(true))
	if err != nil {
		m.fail(err)
		return
	}
	cur, err := m.store.appSessions.Find(m.ctx, bson.D{{Key: "userId", Value: id}, {Key: "endedAt", Value: bson.D{{Key: "$exists", Value: false}}}}, options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		m.fail(err)
		return
	}
	var appIDs []string
	for cur.Next(m.ctx) {
		var d struct {
			ID string `bson:"_id"`
		}
		if err := cur.Decode(&d); err != nil {
			cur.Close(m.ctx)
			m.fail(err)
			return
		}
		appIDs = append(appIDs, d.ID)
	}
	cur.Close(m.ctx)
	if err := cur.Err(); err != nil {
		m.fail(err)
		return
	}
	now := m.currentTime()
	for _, appID := range appIDs {
		m.EndAppSession(appID, "security", "access_policy_changed", now)
	}
	m.RevokeAccessTokensForUser(id)
}

// ---- RefreshFamily (embeds RefreshToken as an array) ----
//
// A family's tokens are always read and rotated together (refresh.go
// reads the token then immediately reads its family), and array growth
// is bounded by rotation count over the family's TTL-limited lifetime, so
// this embeds cleanly rather than needing its own collection.

type refreshTokenElem struct {
	Hash     string    `bson:"hash"`
	Scopes   []string  `bson:"scopes,omitempty"`
	IssuedAt time.Time `bson:"issuedAt"`
	Consumed bool      `bson:"consumed"`
}

type refreshFamilyDoc struct {
	ID             string             `bson:"_id"`
	AppSessionID   string             `bson:"appSessionId,omitempty"`
	OPSessionID    string             `bson:"opSessionId,omitempty"`
	ClientID       string             `bson:"clientId"`
	UserID         string             `bson:"userId"`
	CodeHash       string             `bson:"codeHash,omitempty"`
	Audience       string             `bson:"audience,omitempty"`
	Scopes         []string           `bson:"scopes,omitempty"`
	AuthTime       int64              `bson:"authTime,omitempty"`
	ClientRevision int64              `bson:"clientRevision"`
	CreatedAt      time.Time          `bson:"createdAt"`
	AbsoluteExpiry time.Time          `bson:"absoluteExpiry"`
	IdleExpiry     time.Time          `bson:"idleExpiry"`
	RetainUntil    time.Time          `bson:"retainUntil"`
	Revoked        bool               `bson:"revoked"`
	Tokens         []refreshTokenElem `bson:"tokens,omitempty"`
}

func docToRefreshFamily(d refreshFamilyDoc) RefreshFamily {
	return RefreshFamily{
		ID: d.ID, AppSessionID: d.AppSessionID, OPSessionID: d.OPSessionID, ClientID: d.ClientID, UserID: d.UserID,
		CodeHash: d.CodeHash, Audience: d.Audience, Scopes: d.Scopes, AuthTime: d.AuthTime, ClientRevision: d.ClientRevision,
		CreatedAt: d.CreatedAt, AbsoluteExpiry: d.AbsoluteExpiry, IdleExpiry: d.IdleExpiry, RetainUntil: d.RetainUntil, Revoked: d.Revoked,
	}
}

func (m *mongoTx) RefreshFamily(id string) (RefreshFamily, error) {
	var d refreshFamilyDoc
	err := m.store.refreshFamilies.FindOne(m.ctx, bson.D{{Key: "_id", Value: id}}).Decode(&d)
	if err != nil {
		return RefreshFamily{}, notFoundOrErr(err)
	}
	return docToRefreshFamily(d), nil
}

func (m *mongoTx) ListRefreshFamilies() []RefreshFamily {
	cur, err := m.store.refreshFamilies.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []RefreshFamily
	for cur.Next(m.ctx) {
		var d refreshFamilyDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToRefreshFamily(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

// SaveRefreshFamily upserts the family's own fields, preserving its
// embedded tokens array (only SaveRefreshToken/RevokeRefreshFamily touch
// that array) by reading it back first.
func (m *mongoTx) SaveRefreshFamily(f RefreshFamily) {
	if m.poisoned() {
		return
	}
	var existing refreshFamilyDoc
	err := m.store.refreshFamilies.FindOne(m.ctx, bson.D{{Key: "_id", Value: f.ID}}).Decode(&existing)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		m.fail(err)
		return
	}
	doc := refreshFamilyDoc{
		ID: f.ID, AppSessionID: f.AppSessionID, OPSessionID: f.OPSessionID, ClientID: f.ClientID, UserID: f.UserID,
		CodeHash: f.CodeHash, Audience: f.Audience, Scopes: f.Scopes, AuthTime: f.AuthTime, ClientRevision: f.ClientRevision,
		CreatedAt: f.CreatedAt, AbsoluteExpiry: f.AbsoluteExpiry, IdleExpiry: f.IdleExpiry, RetainUntil: f.RetainUntil, Revoked: f.Revoked,
		Tokens: existing.Tokens,
	}
	_, err = m.store.refreshFamilies.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: f.ID}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

// RevokeRefreshFamily atomically revokes the family and every access
// token minted from it. A no-op if the family doesn't exist.
func (m *mongoTx) RevokeRefreshFamily(id string) {
	if m.poisoned() {
		return
	}
	if _, err := m.store.refreshFamilies.UpdateOne(m.ctx, bson.D{{Key: "_id", Value: id}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
		m.fail(err)
		return
	}
	if _, err := m.store.accessTokens.UpdateMany(m.ctx, bson.D{{Key: "familyId", Value: id}}, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}}}}); err != nil {
		m.fail(err)
	}
}

// RefreshToken looks up a single embedded array element by hash across
// all families, backed by the tokens.hash index.
func (m *mongoTx) RefreshToken(hash string) (RefreshToken, error) {
	var d refreshFamilyDoc
	err := m.store.refreshFamilies.FindOne(m.ctx,
		bson.D{{Key: "tokens.hash", Value: hash}},
		options.FindOne().SetProjection(bson.D{{Key: "tokens.$", Value: 1}}),
	).Decode(&d)
	if err != nil {
		return RefreshToken{}, notFoundOrErr(err)
	}
	if len(d.Tokens) == 0 {
		return RefreshToken{}, ErrNotFound
	}
	t := d.Tokens[0]
	return RefreshToken{Hash: t.Hash, FamilyID: d.ID, Scopes: t.Scopes, IssuedAt: t.IssuedAt, Consumed: t.Consumed}, nil
}

func (m *mongoTx) ListRefreshTokens() []RefreshToken {
	cur, err := m.store.refreshFamilies.Find(m.ctx, bson.D{{Key: "tokens", Value: bson.D{{Key: "$exists", Value: true}, {Key: "$ne", Value: bson.A{}}}}})
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []RefreshToken
	for cur.Next(m.ctx) {
		var d refreshFamilyDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		for _, t := range d.Tokens {
			out = append(out, RefreshToken{Hash: t.Hash, FamilyID: d.ID, Scopes: t.Scopes, IssuedAt: t.IssuedAt, Consumed: t.Consumed})
		}
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

// SaveRefreshToken upserts one element of the family's embedded tokens
// array by hash (pushing a new element if the hash isn't already
// present), preserving fileState's per-token map[hash]=v semantics
// without needing a separate collection. The single-use/replay check
// (refresh.go: read old via RefreshToken above, branch on Consumed, then
// save) runs in application code within the same Mongo transaction;
// snapshot read concern plus WithTransaction's retry-on-conflict is what
// makes two concurrent redemptions resolve to exactly one winner.
func (m *mongoTx) SaveRefreshToken(t RefreshToken) {
	if m.poisoned() {
		return
	}
	elem := refreshTokenElem{Hash: t.Hash, Scopes: t.Scopes, IssuedAt: t.IssuedAt, Consumed: t.Consumed}
	res, err := m.store.refreshFamilies.UpdateOne(m.ctx,
		bson.D{{Key: "_id", Value: t.FamilyID}, {Key: "tokens.hash", Value: t.Hash}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "tokens.$", Value: elem}}}},
	)
	if err != nil {
		m.fail(err)
		return
	}
	if res.MatchedCount == 0 {
		_, err := m.store.refreshFamilies.UpdateOne(m.ctx,
			bson.D{{Key: "_id", Value: t.FamilyID}},
			bson.D{{Key: "$push", Value: bson.D{{Key: "tokens", Value: elem}}}},
		)
		m.fail(err)
	}
}

// ---- InitialAccessToken / RegistrationAccessToken ----

type initialAccessTokenDoc struct {
	Hash      string    `bson:"_id"`
	ID        string    `bson:"id"`
	Label     string    `bson:"label,omitempty"`
	IssuedBy  string    `bson:"issuedBy,omitempty"`
	IssuedAt  time.Time `bson:"issuedAt"`
	ExpiresAt time.Time `bson:"expiresAt"`
	MaxUses   int       `bson:"maxUses"`
	Uses      int       `bson:"uses"`
	Revoked   bool      `bson:"revoked"`
}

func docToInitialToken(d initialAccessTokenDoc) InitialAccessToken {
	return InitialAccessToken{Hash: d.Hash, ID: d.ID, Label: d.Label, IssuedBy: d.IssuedBy, IssuedAt: d.IssuedAt, ExpiresAt: d.ExpiresAt, MaxUses: d.MaxUses, Uses: d.Uses, Revoked: d.Revoked}
}

func (m *mongoTx) InitialToken(hash string) (InitialAccessToken, error) {
	var d initialAccessTokenDoc
	err := m.store.initialAccessTokens.FindOne(m.ctx, bson.D{{Key: "_id", Value: hash}}).Decode(&d)
	if err != nil {
		return InitialAccessToken{}, notFoundOrErr(err)
	}
	return docToInitialToken(d), nil
}

func (m *mongoTx) InitialTokens() []InitialAccessToken {
	cur, err := m.store.initialAccessTokens.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "issuedAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []InitialAccessToken
	for cur.Next(m.ctx) {
		var d initialAccessTokenDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToInitialToken(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

// SaveInitialToken is a plain upsert. The atomic use-counting invariant
// (registration.go: Uses++ under a re-validated "active" check) is
// implemented in application code as read-then-save within the same
// transaction, relying on snapshot isolation plus WithTransaction's
// retry-on-conflict for exactly one winner under concurrent registration
// attempts against the same token.
func (m *mongoTx) SaveInitialToken(t InitialAccessToken) {
	if m.poisoned() {
		return
	}
	doc := initialAccessTokenDoc{Hash: t.Hash, ID: t.ID, Label: t.Label, IssuedBy: t.IssuedBy, IssuedAt: t.IssuedAt, ExpiresAt: t.ExpiresAt, MaxUses: t.MaxUses, Uses: t.Uses, Revoked: t.Revoked}
	_, err := m.store.initialAccessTokens.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: t.Hash}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

func (m *mongoTx) RegistrationToken(clientID string) (RegistrationAccessToken, error) {
	var d struct {
		ClientID string    `bson:"_id"`
		Hash     string    `bson:"hash"`
		IssuedAt time.Time `bson:"issuedAt"`
	}
	err := m.store.registrationAccessTokens.FindOne(m.ctx, bson.D{{Key: "_id", Value: clientID}}).Decode(&d)
	if err != nil {
		return RegistrationAccessToken{}, notFoundOrErr(err)
	}
	return RegistrationAccessToken{Hash: d.Hash, ClientID: d.ClientID, IssuedAt: d.IssuedAt}, nil
}

// SaveRegistrationToken silently replaces any existing token for the
// client (at most one per client). Per store.go's documented contract,
// this must NOT touch clients.updatedAt or invalidate grants, and it
// does not.
func (m *mongoTx) SaveRegistrationToken(t RegistrationAccessToken) {
	if m.poisoned() {
		return
	}
	doc := bson.D{{Key: "_id", Value: t.ClientID}, {Key: "hash", Value: t.Hash}, {Key: "issuedAt", Value: t.IssuedAt}}
	_, err := m.store.registrationAccessTokens.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: t.ClientID}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

func (m *mongoTx) DeleteRegistrationToken(clientID string) {
	if m.poisoned() {
		return
	}
	_, err := m.store.registrationAccessTokens.DeleteOne(m.ctx, bson.D{{Key: "_id", Value: clientID}})
	m.fail(err)
}

// ---- AuthzTransaction ----

type authzTransactionDoc struct {
	ID                  string     `bson:"_id"`
	ClientID            string     `bson:"clientId"`
	RedirectURI         string     `bson:"redirectUri,omitempty"`
	Scopes              []string   `bson:"scopes,omitempty"`
	State               string     `bson:"state,omitempty"`
	ResponseMode        string     `bson:"responseMode,omitempty"`
	Nonce               string     `bson:"nonce,omitempty"`
	CodeChallenge       string     `bson:"codeChallenge,omitempty"`
	CodeChallengeMethod string     `bson:"codeChallengeMethod,omitempty"`
	Prompt              []string   `bson:"prompt,omitempty"`
	MaxAge              *int64     `bson:"maxAge,omitempty"`
	LoginHint           string     `bson:"loginHint,omitempty"`
	BrowserBindingHash  string     `bson:"browserBindingHash,omitempty"`
	OPSessionID         string     `bson:"opSessionId,omitempty"`
	AppSessionID        string     `bson:"appSessionId,omitempty"`
	UserID              string     `bson:"userId,omitempty"`
	AuthTime            int64      `bson:"authTime,omitempty"`
	ClientUpdatedAtNS   int64      `bson:"clientUpdatedAtNs"`
	ReauthenticateAfter *time.Time `bson:"reauthenticateAfter,omitempty"`
	ConsentGranted      bool       `bson:"consentGranted"`
	Revoked             bool       `bson:"revoked"`
	Consumed            bool       `bson:"consumed"`
	ExpiresAt           time.Time  `bson:"expiresAt"`
	CreatedAt           time.Time  `bson:"createdAt"`
}

func docToAuthzTransaction(d authzTransactionDoc) AuthzTransaction {
	t := AuthzTransaction{
		ID: d.ID, ClientID: d.ClientID, RedirectURI: d.RedirectURI, Scopes: d.Scopes, State: d.State, ResponseMode: d.ResponseMode,
		Nonce: d.Nonce, CodeChallenge: d.CodeChallenge, CodeChallengeMethod: d.CodeChallengeMethod, Prompt: d.Prompt, MaxAge: d.MaxAge,
		LoginHint: d.LoginHint, BrowserBindingHash: d.BrowserBindingHash, OPSessionID: d.OPSessionID, AppSessionID: d.AppSessionID,
		UserID: d.UserID, AuthTime: d.AuthTime, ClientUpdatedAt: time.Unix(0, d.ClientUpdatedAtNS).UTC(),
		ConsentGranted: d.ConsentGranted, Revoked: d.Revoked, Consumed: d.Consumed, ExpiresAt: d.ExpiresAt, CreatedAt: d.CreatedAt,
	}
	if d.ReauthenticateAfter != nil {
		t.ReauthenticateAfter = *d.ReauthenticateAfter
	}
	return t
}

func (m *mongoTx) AuthzTransaction(id string) (AuthzTransaction, error) {
	var d authzTransactionDoc
	err := m.store.authzTransactions.FindOne(m.ctx, bson.D{{Key: "_id", Value: id}}).Decode(&d)
	if err != nil {
		return AuthzTransaction{}, notFoundOrErr(err)
	}
	return docToAuthzTransaction(d), nil
}

func (m *mongoTx) ListAuthzTransactions() []AuthzTransaction {
	cur, err := m.store.authzTransactions.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []AuthzTransaction
	for cur.Next(m.ctx) {
		var d authzTransactionDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToAuthzTransaction(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

func (m *mongoTx) SaveAuthzTransaction(t AuthzTransaction) {
	if m.poisoned() {
		return
	}
	doc := authzTransactionDoc{
		ID: t.ID, ClientID: t.ClientID, RedirectURI: t.RedirectURI, Scopes: t.Scopes, State: t.State, ResponseMode: t.ResponseMode,
		Nonce: t.Nonce, CodeChallenge: t.CodeChallenge, CodeChallengeMethod: t.CodeChallengeMethod, Prompt: t.Prompt, MaxAge: t.MaxAge,
		LoginHint: t.LoginHint, BrowserBindingHash: t.BrowserBindingHash, OPSessionID: t.OPSessionID, AppSessionID: t.AppSessionID,
		UserID: t.UserID, AuthTime: t.AuthTime, ClientUpdatedAtNS: t.ClientUpdatedAt.UnixNano(),
		ConsentGranted: t.ConsentGranted, Revoked: t.Revoked, Consumed: t.Consumed, ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt,
	}
	if !t.ReauthenticateAfter.IsZero() {
		doc.ReauthenticateAfter = &t.ReauthenticateAfter
	}
	_, err := m.store.authzTransactions.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: t.ID}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

func (m *mongoTx) DeleteAuthzTransaction(id string) {
	if m.poisoned() {
		return
	}
	_, err := m.store.authzTransactions.DeleteOne(m.ctx, bson.D{{Key: "_id", Value: id}})
	m.fail(err)
}

// ---- AuthorizationCode ----

type authorizationCodeDoc struct {
	Hash                string     `bson:"_id"`
	TransactionID       string     `bson:"transactionId,omitempty"`
	ClientID            string     `bson:"clientId"`
	UserID              string     `bson:"userId"`
	RedirectURI         string     `bson:"redirectUri,omitempty"`
	Scopes              []string   `bson:"scopes,omitempty"`
	Nonce               string     `bson:"nonce,omitempty"`
	AuthTime            int64      `bson:"authTime,omitempty"`
	CodeChallenge       string     `bson:"codeChallenge,omitempty"`
	CodeChallengeMethod string     `bson:"codeChallengeMethod,omitempty"`
	ClientUpdatedAtNS   int64      `bson:"clientUpdatedAtNs"`
	OPSessionID         string     `bson:"opSessionId,omitempty"`
	AppSessionID        string     `bson:"appSessionId,omitempty"`
	Revoked             bool       `bson:"revoked,omitempty"`
	Consumed            bool       `bson:"consumed"`
	CreatedAt           *time.Time `bson:"createdAt,omitempty"`
	ExpiresAt           time.Time  `bson:"expiresAt"`
	RetainUntil         *time.Time `bson:"retainUntil,omitempty"`
}

func docToAuthorizationCode(d authorizationCodeDoc) AuthorizationCode {
	c := AuthorizationCode{
		Hash: d.Hash, TransactionID: d.TransactionID, ClientID: d.ClientID, UserID: d.UserID, RedirectURI: d.RedirectURI,
		Scopes: d.Scopes, Nonce: d.Nonce, AuthTime: d.AuthTime, CodeChallenge: d.CodeChallenge, CodeChallengeMethod: d.CodeChallengeMethod,
		ClientUpdatedAt: time.Unix(0, d.ClientUpdatedAtNS).UTC(), OPSessionID: d.OPSessionID, AppSessionID: d.AppSessionID,
		Revoked: d.Revoked, Consumed: d.Consumed, ExpiresAt: d.ExpiresAt,
	}
	if d.CreatedAt != nil {
		c.CreatedAt = *d.CreatedAt
	}
	if d.RetainUntil != nil {
		c.RetainUntil = *d.RetainUntil
	}
	return c
}

func (m *mongoTx) AuthorizationCode(hash string) (AuthorizationCode, error) {
	var d authorizationCodeDoc
	err := m.store.authorizationCodes.FindOne(m.ctx, bson.D{{Key: "_id", Value: hash}}).Decode(&d)
	if err != nil {
		return AuthorizationCode{}, notFoundOrErr(err)
	}
	return docToAuthorizationCode(d), nil
}

func (m *mongoTx) ListAuthorizationCodes() []AuthorizationCode {
	cur, err := m.store.authorizationCodes.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []AuthorizationCode
	for cur.Next(m.ctx) {
		var d authorizationCodeDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, docToAuthorizationCode(d))
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

func (m *mongoTx) SaveAuthorizationCode(c AuthorizationCode) {
	if m.poisoned() {
		return
	}
	doc := authorizationCodeDoc{
		Hash: c.Hash, TransactionID: c.TransactionID, ClientID: c.ClientID, UserID: c.UserID, RedirectURI: c.RedirectURI,
		Scopes: c.Scopes, Nonce: c.Nonce, AuthTime: c.AuthTime, CodeChallenge: c.CodeChallenge, CodeChallengeMethod: c.CodeChallengeMethod,
		ClientUpdatedAtNS: c.ClientUpdatedAt.UnixNano(), OPSessionID: c.OPSessionID, AppSessionID: c.AppSessionID,
		Revoked: c.Revoked, Consumed: c.Consumed, ExpiresAt: c.ExpiresAt,
	}
	if !c.CreatedAt.IsZero() {
		doc.CreatedAt = &c.CreatedAt
	}
	if !c.RetainUntil.IsZero() {
		doc.RetainUntil = &c.RetainUntil
	}
	_, err := m.store.authorizationCodes.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: c.Hash}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}

// ---- Consent ----

type consentDoc struct {
	ID             string    `bson:"_id"`
	UserID         string    `bson:"userId"`
	ClientID       string    `bson:"clientId"`
	Scopes         []string  `bson:"scopes,omitempty"`
	PolicyRevision int64     `bson:"policyRevision"`
	GrantedAt      time.Time `bson:"grantedAt"`
	Revoked        bool      `bson:"revoked"`
}

func (m *mongoTx) Consent(userID, clientID string) (Consent, error) {
	var d consentDoc
	err := m.store.consents.FindOne(m.ctx, bson.D{{Key: "_id", Value: consentID(userID, clientID)}}).Decode(&d)
	if err != nil {
		return Consent{}, notFoundOrErr(err)
	}
	return Consent{ID: d.ID, UserID: d.UserID, ClientID: d.ClientID, Scopes: d.Scopes, PolicyRevision: d.PolicyRevision, GrantedAt: d.GrantedAt, Revoked: d.Revoked}, nil
}

func (m *mongoTx) ListConsents() []Consent {
	cur, err := m.store.consents.Find(m.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "grantedAt", Value: 1}}))
	if err != nil {
		m.fail(err)
		return nil
	}
	defer cur.Close(m.ctx)
	var out []Consent
	for cur.Next(m.ctx) {
		var d consentDoc
		if err := cur.Decode(&d); err != nil {
			m.fail(err)
			return nil
		}
		out = append(out, Consent{ID: d.ID, UserID: d.UserID, ClientID: d.ClientID, Scopes: d.Scopes, PolicyRevision: d.PolicyRevision, GrantedAt: d.GrantedAt, Revoked: d.Revoked})
	}
	if err := cur.Err(); err != nil {
		m.fail(err)
	}
	return out
}

// SaveConsent cascades exactly as fileState.SaveConsent: when the saved
// consent is revoked, first end the user's app sessions for this client
// and revoke their refresh families for this client, then persist.
func (m *mongoTx) SaveConsent(c Consent) {
	if m.poisoned() {
		return
	}
	id := consentID(c.UserID, c.ClientID)
	if c.Revoked {
		cur, err := m.store.appSessions.Find(m.ctx, bson.D{{Key: "userId", Value: c.UserID}, {Key: "clientId", Value: c.ClientID}, {Key: "endedAt", Value: bson.D{{Key: "$exists", Value: false}}}}, options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}))
		if err != nil {
			m.fail(err)
			return
		}
		var appIDs []string
		for cur.Next(m.ctx) {
			var d struct {
				ID string `bson:"_id"`
			}
			if err := cur.Decode(&d); err != nil {
				cur.Close(m.ctx)
				m.fail(err)
				return
			}
			appIDs = append(appIDs, d.ID)
		}
		cur.Close(m.ctx)
		if err := cur.Err(); err != nil {
			m.fail(err)
			return
		}
		now := m.currentTime()
		for _, appID := range appIDs {
			// Matches fileState.SaveConsent's exact (surprising) actor
			// argument: the user's own ID, not a fixed system label.
			m.EndAppSession(appID, c.UserID, "access_revoked", now)
		}
		if m.poisoned() {
			return
		}
		m.revokeFamiliesMatching(bson.D{{Key: "userId", Value: c.UserID}, {Key: "clientId", Value: c.ClientID}})
		if m.poisoned() {
			return
		}
	}
	doc := consentDoc{ID: id, UserID: c.UserID, ClientID: c.ClientID, Scopes: c.Scopes, PolicyRevision: c.PolicyRevision, GrantedAt: c.GrantedAt, Revoked: c.Revoked}
	_, err := m.store.consents.ReplaceOne(m.ctx, bson.D{{Key: "_id", Value: id}}, doc, options.Replace().SetUpsert(true))
	m.fail(err)
}
