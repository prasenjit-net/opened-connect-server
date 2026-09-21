package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Event is one entry in the inspectable protocol log: every request sent to
// the OP and every response/callback received, kept verbatim so the log
// doubles as a debugger.
type Event struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"` // e.g. "authorize.redirect", "token.request", "token.response", "userinfo.response", "backchannel-logout"
	Detail string    `json:"detail"`
	Data   any       `json:"data,omitempty"`
	Raw    string    `json:"raw,omitempty"` // raw HTTP body / JWT / query string, when useful to show verbatim
}

// PendingAuth tracks an in-flight authorization_code request between the
// redirect to /authorize and the callback landing on /callback. It carries
// the client credentials the user typed into the start-flow form, since
// nothing is persisted in a saved config - the callback needs them again to
// perform the token exchange.
type PendingAuth struct {
	State        string
	Nonce        string
	CodeVerifier string
	ClientID     string
	ClientSecret string
	AuthMethod   string
	Created      time.Time
}

// Client is an OIDC client this RP knows about, either because it was
// registered dynamically through /register (in which case OP-issued
// credentials for editing it are also kept) or entered by hand on the
// config page (e.g. a client created via the OP's admin API). Saved here so
// every flow form can offer it instead of requiring the id/secret to be
// retyped each time.
type Client struct {
	ClientID     string
	ClientSecret string
	AuthMethod   string
	Label        string
	Source       string // "dynamic" | "manual"

	// Only set for dynamically registered clients: lets the config page
	// re-fetch and display the client's current metadata via
	// GET /register/{clientID}.
	RegistrationAccessToken string
	RegistrationClientURI   string
	Metadata                map[string]any // last-fetched/received raw metadata, for display

	Created time.Time
}

// MetadataJSON renders the client's last-fetched metadata for display;
// empty if none has been fetched yet.
func (c *Client) MetadataJSON() string {
	if c.Metadata == nil {
		return ""
	}
	return prettyJSON(c.Metadata)
}

// AppSession is this RP's own login session, created after a successful
// token exchange. Keyed by an opaque cookie value. It remembers which
// client credentials produced it so refresh/introspect/revoke/logout can
// reuse them without asking the user to retype anything.
type AppSession struct {
	Cookie       string
	ClientID     string
	ClientSecret string
	AuthMethod   string
	Flow         string // "authorization_code" | "password", for display

	Subject      string
	IDToken      string
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	Claims       map[string]any // decoded ID token claims
	UserInfo     map[string]any // last successful /userinfo response
	SID          string         // "sid" claim - correlates with logout notifications
	Created      time.Time
}

// Store is the whole app's in-memory, thread-safe state. Nothing here ever
// touches disk; restarting the process wipes everything, which is the point
// for a disposable test client.
type Store struct {
	mu sync.Mutex

	pending  map[string]*PendingAuth // keyed by state
	sessions map[string]*AppSession  // keyed by cookie
	sidIndex map[string]string       // sid -> cookie, for logout notifications
	clients  map[string]*Client      // keyed by client_id

	events   []Event
	eventSeq int64

	// discovery/JWKS cache, refreshed lazily
	discovery *Discovery
	jwks      any // *jose.JSONWebKeySet, kept as any to avoid an import cycle in this file
}

func newStore() *Store {
	return &Store{
		pending:  map[string]*PendingAuth{},
		sessions: map[string]*AppSession{},
		sidIndex: map[string]string{},
		clients:  map[string]*Client{},
	}
}

func randomToken(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (s *Store) addPending(p *PendingAuth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[p.State] = p
}

func (s *Store) takePending(state string) (*PendingAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[state]
	if ok {
		delete(s.pending, state)
	}
	return p, ok
}

func (s *Store) putSession(sess *AppSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.Cookie] = sess
	if sess.SID != "" {
		s.sidIndex[sess.SID] = sess.Cookie
	}
}

func (s *Store) getSession(cookie string) (*AppSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[cookie]
	return sess, ok
}

func (s *Store) deleteSession(cookie string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[cookie]; ok {
		delete(s.sidIndex, sess.SID)
		delete(s.sessions, cookie)
	}
}

// deleteBySID ends whichever local session matches an OP-issued sid claim,
// used by both front-channel and back-channel logout handlers. Returns
// whether a matching local session was found.
func (s *Store) deleteBySID(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cookie, ok := s.sidIndex[sid]
	if !ok {
		return false
	}
	delete(s.sessions, cookie)
	delete(s.sidIndex, sid)
	return true
}

func (s *Store) putClient(c *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = c
}

func (s *Store) getClient(clientID string) (*Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	return c, ok
}

func (s *Store) deleteClient(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, clientID)
}

// allClients returns known clients ordered newest-first, for the config
// page and for the quick-pick lists on each flow's form.
func (s *Store) allClients() []*Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

func (s *Store) allSessions() []*AppSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*AppSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

func (s *Store) log(kind, detail string, data any, raw string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventSeq++
	s.events = append(s.events, Event{
		ID:     s.eventSeq,
		Time:   time.Now(),
		Kind:   kind,
		Detail: detail,
		Data:   data,
		Raw:    raw,
	})
	// Keep the log bounded; this is a debugging aid, not an audit trail.
	if len(s.events) > 500 {
		s.events = s.events[len(s.events)-500:]
	}
}

func (s *Store) recentEvents() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	// newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) clearEvents() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
