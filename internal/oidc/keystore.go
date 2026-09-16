// Package oidc implements the OpenID Connect protocol surface: signing
// keys, discovery/JWKS, the authorization/token/userinfo endpoints, PKCE,
// client authentication, and claims projection. It is hand-rolled against
// internal/identity.Store's existing atomic-transaction pattern rather than
// built on a third-party OAuth provider framework; see
// OIDC_IMPLEMENTATION_PLAN.md section 4 for the recorded decision.
package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gofrs/flock"
)

const (
	keyBits        = 3072
	certValidity   = 365 * 24 * time.Hour
	clockSkewGrace = 5 * time.Minute
)

// ErrNoActiveKey is returned by Sign/ActiveKID before Load or Provision has
// established an active signing key.
var ErrNoActiveKey = errors.New("no active signing key loaded")

// KeyRecord describes one RSA signing key's public identity and lifecycle.
// It never carries private material.
type KeyRecord struct {
	KID       string    `json:"kid"`
	CreatedAt time.Time `json:"createdAt"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Retired   bool      `json:"retired"`
}

type keyManifest struct {
	Active string      `json:"active"`
	Keys   []KeyRecord `json:"keys"`
}

// signingKey holds one key pair's in-memory material.
type signingKey struct {
	record  KeyRecord
	private *rsa.PrivateKey
	public  jose.JSONWebKey
	cert    *x509.Certificate
}

// Loaded reports the outcome of a successful Load.
type Loaded struct {
	ActiveKID string
	NotAfter  time.Time
}

// KeyStore manages the provider's RSA signing keys on disk, under
// <dir>/manifest.json and <dir>/<kid>/{private.pem,certificate.pem}. Its
// lifecycle (provision/load/rotate) is independent of identity.json's lock
// and schema version, per OIDC_IMPLEMENTATION_PLAN.md section 9: signing
// material has a different lifecycle than grant/session state.
type KeyStore struct {
	dir string

	mu      sync.RWMutex
	active  *signingKey
	retired []*signingKey
}

// NewFileKeyStore prepares (but does not populate) a key store rooted at
// dir. Call Provision (typically from `init`) or Load (from `serve`) next.
func NewFileKeyStore(dir string) (*KeyStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("signing key directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return nil, fmt.Errorf("create signing key directory: %w", err)
	}
	if err := os.Chmod(abs, 0700); err != nil {
		return nil, err
	}
	return &KeyStore{dir: abs}, nil
}

func (k *KeyStore) manifestPath() string     { return filepath.Join(k.dir, "manifest.json") }
func (k *KeyStore) lockPath() string         { return filepath.Join(k.dir, "manifest.json.lock") }
func (k *KeyStore) keyDir(kid string) string { return filepath.Join(k.dir, kid) }

func (k *KeyStore) withLock(ctx context.Context, fn func() error) error {
	lock := flock.New(k.lockPath())
	defer lock.Close()
	ok, err := lock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil {
		return err
	}
	if !ok {
		return ctx.Err()
	}
	defer lock.Unlock()
	return fn()
}

// Provision idempotently ensures an active signing key exists, generating
// one only if none is present. Rerunning it (including from `init --force`,
// which must never reach this call with force semantics) preserves any
// valid existing key. It also resumes an interrupted prior run: a key
// directory that already exists and is internally consistent (its own
// computed thumbprint matches its directory name) but isn't yet referenced
// by the manifest is activated in place rather than duplicated.
func (k *KeyStore) Provision(ctx context.Context) (KeyRecord, error) {
	var result KeyRecord
	err := k.withLock(ctx, func() error {
		m, err := k.readManifest()
		if err != nil {
			return err
		}
		if m.Active != "" {
			key, err := k.loadKey(m.Active, m)
			if err != nil {
				return fmt.Errorf("existing signing key %q is invalid: %w", m.Active, err)
			}
			result = key.record
			return nil
		}
		if kid, key, err := k.findOrphanedKey(); err != nil {
			return err
		} else if kid != "" {
			m.Active = kid
			m.Keys = append(m.Keys, key.record)
			if err := k.writeManifest(m); err != nil {
				return err
			}
			result = key.record
			return nil
		}
		key, err := generateSigningKey(time.Now())
		if err != nil {
			return err
		}
		if err := k.stageAndCommitKey(key); err != nil {
			return err
		}
		m.Active = key.record.KID
		m.Keys = append(m.Keys, key.record)
		if err := k.writeManifest(m); err != nil {
			return err
		}
		result = key.record
		return nil
	})
	return result, err
}

// Load validates and activates the on-disk signing material for runtime
// use. Unlike Provision, it never generates a key: with OIDC enabled,
// `serve` must fail startup on missing/invalid/expired material rather than
// run with an ephemeral key.
func (k *KeyStore) Load(ctx context.Context) (Loaded, error) {
	var result Loaded
	err := k.withLock(ctx, func() error {
		m, err := k.readManifest()
		if err != nil {
			return err
		}
		if m.Active == "" {
			return errors.New("no active signing key; run `init` or `keys rotate` first")
		}
		active, err := k.loadKey(m.Active, m)
		if err != nil {
			return fmt.Errorf("active signing key %q is invalid: %w", m.Active, err)
		}
		if !time.Now().Before(active.record.NotAfter) {
			return fmt.Errorf("active signing key %q expired at %s; rotate it", m.Active, active.record.NotAfter)
		}
		var retired []*signingKey
		for _, r := range m.Keys {
			if r.KID == m.Active {
				continue
			}
			rk, err := k.loadKey(r.KID, m)
			if err != nil {
				return fmt.Errorf("retired signing key %q is invalid: %w", r.KID, err)
			}
			retired = append(retired, rk)
		}
		k.mu.Lock()
		k.active = active
		k.retired = retired
		k.mu.Unlock()
		result = Loaded{ActiveKID: active.record.KID, NotAfter: active.record.NotAfter}
		return nil
	})
	return result, err
}

// Rotate always generates and activates a new signing key, retiring (never
// deleting) the previous one so unexpired artifacts remain verifiable.
func (k *KeyStore) Rotate(ctx context.Context) (KeyRecord, error) {
	var result KeyRecord
	err := k.withLock(ctx, func() error {
		m, err := k.readManifest()
		if err != nil {
			return err
		}
		key, err := generateSigningKey(time.Now())
		if err != nil {
			return err
		}
		if err := k.stageAndCommitKey(key); err != nil {
			return err
		}
		for i, r := range m.Keys {
			if r.KID == m.Active {
				m.Keys[i].Retired = true
			}
		}
		m.Active = key.record.KID
		m.Keys = append(m.Keys, key.record)
		if err := k.writeManifest(m); err != nil {
			return err
		}
		result = key.record
		return nil
	})
	if err != nil {
		return KeyRecord{}, err
	}
	if _, err := k.Load(ctx); err != nil {
		return KeyRecord{}, err
	}
	return result, nil
}

// Status reports the manifest's recorded keys without requiring a prior
// Load, for the `keys status` CLI command. It never returns private
// material.
func (k *KeyStore) Status(ctx context.Context) (active string, keys []KeyRecord, err error) {
	err = k.withLock(ctx, func() error {
		m, e := k.readManifest()
		if e != nil {
			return e
		}
		active, keys = m.Active, m.Keys
		return nil
	})
	return active, keys, err
}

func (k *KeyStore) ActiveKID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == nil {
		return ""
	}
	return k.active.record.KID
}

// PublicJWKS returns the provider's public signing keys only; private
// material is never included, per OIDC_IMPLEMENTATION_PLAN.md section 5.
func (k *KeyStore) PublicJWKS() jose.JSONWebKeySet {
	k.mu.RLock()
	defer k.mu.RUnlock()
	set := jose.JSONWebKeySet{}
	if k.active != nil {
		set.Keys = append(set.Keys, k.active.public)
	}
	for _, r := range k.retired {
		set.Keys = append(set.Keys, r.public)
	}
	return set
}

// Sign builds and signs a JWT from the given claims values (merged in
// order, per jwt.Builder.Claims) using the active RSA key and its kid.
func (k *KeyStore) Sign(claims ...interface{}) (string, error) {
	k.mu.RLock()
	active := k.active
	k.mu.RUnlock()
	if active == nil {
		return "", ErrNoActiveKey
	}
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", active.record.KID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: active.private}, opts)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}
	builder := jwt.Signed(signer)
	for _, c := range claims {
		builder = builder.Claims(c)
	}
	return builder.Serialize()
}

func generateSigningKey(now time.Time) (*signingKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	pub := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.RS256), Use: "sig"}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("compute key thumbprint: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(thumb)
	pub.KeyID = kid

	notBefore := now.Add(-clockSkewGrace)
	notAfter := now.Add(certValidity)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: kid},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create self-signed certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated certificate: %w", err)
	}
	return &signingKey{
		record:  KeyRecord{KID: kid, CreatedAt: now, NotBefore: notBefore, NotAfter: notAfter},
		private: priv,
		public:  pub,
		cert:    cert,
	}, nil
}

func (k *KeyStore) parseKeyFiles(kid string) (*rsa.PrivateKey, *x509.Certificate, error) {
	dir := k.keyDir(kid)
	privPEM, err := os.ReadFile(filepath.Join(dir, "private.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("invalid private key PEM")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := privAny.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("signing key is not RSA")
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "certificate.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("read certificate: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	certKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || certKey.N.Cmp(priv.PublicKey.N) != 0 || certKey.E != priv.PublicKey.E {
		return nil, nil, fmt.Errorf("certificate does not match private key")
	}
	return priv, cert, nil
}

func toSigningKey(kid string, priv *rsa.PrivateKey, cert *x509.Certificate, record KeyRecord) (*signingKey, error) {
	pub := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(thumb) != kid {
		return nil, fmt.Errorf("key thumbprint does not match kid %q", kid)
	}
	return &signingKey{record: record, private: priv, public: pub, cert: cert}, nil
}

func recordForKID(m keyManifest, kid string) KeyRecord {
	for _, r := range m.Keys {
		if r.KID == kid {
			return r
		}
	}
	return KeyRecord{}
}

func (k *KeyStore) loadKey(kid string, m keyManifest) (*signingKey, error) {
	priv, cert, err := k.parseKeyFiles(kid)
	if err != nil {
		return nil, err
	}
	record := recordForKID(m, kid)
	if record.KID == "" {
		record = KeyRecord{KID: kid, CreatedAt: cert.NotBefore.Add(clockSkewGrace), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}
	}
	return toSigningKey(kid, priv, cert, record)
}

// findOrphanedKey looks for a key directory left behind by an interrupted
// Provision: its own computed thumbprint matches its directory name, but it
// isn't yet referenced by the manifest. A directory that fails to parse or
// whose thumbprint doesn't match its name is reported as an error rather
// than silently skipped, since it may represent corrupted material.
func (k *KeyStore) findOrphanedKey() (string, *signingKey, error) {
	entries, err := os.ReadDir(k.dir)
	if err != nil {
		return "", nil, fmt.Errorf("read signing key directory: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		kid := e.Name()
		priv, cert, err := k.parseKeyFiles(kid)
		if err != nil {
			return "", nil, fmt.Errorf("existing key directory %q is invalid: %w", kid, err)
		}
		key, err := toSigningKey(kid, priv, cert, KeyRecord{KID: kid, CreatedAt: cert.NotBefore.Add(clockSkewGrace), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter})
		if err != nil {
			return "", nil, fmt.Errorf("existing key directory %q does not match its name: %w", kid, err)
		}
		return kid, key, nil
	}
	return "", nil, nil
}

// stageAndCommitKey writes the key pair to a staging directory, fsyncs it,
// then atomically renames it into place as <dir>/<kid>/ so a crash never
// leaves a partially written key directory visible under its final name.
func (k *KeyStore) stageAndCommitKey(key *signingKey) error {
	staging, err := os.MkdirTemp(k.dir, ".staging-*")
	if err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0700); err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key.private)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := writeFileSynced(filepath.Join(staging, "private.pem"), privPEM, 0600); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: key.cert.Raw})
	if err := writeFileSynced(filepath.Join(staging, "certificate.pem"), certPEM, 0600); err != nil {
		return err
	}
	if err := syncDir(staging); err != nil {
		return err
	}
	target := k.keyDir(key.record.KID)
	if err := os.Rename(staging, target); err != nil {
		return fmt.Errorf("activate signing key directory: %w", err)
	}
	return syncDir(k.dir)
}

func (k *KeyStore) readManifest() (keyManifest, error) {
	data, err := os.ReadFile(k.manifestPath())
	if os.IsNotExist(err) {
		return keyManifest{}, nil
	}
	if err != nil {
		return keyManifest{}, fmt.Errorf("read signing key manifest: %w", err)
	}
	var m keyManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return keyManifest{}, fmt.Errorf("invalid signing key manifest: %w", err)
	}
	return m, nil
}

func (k *KeyStore) writeManifest(m keyManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(k.dir, ".manifest-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0600); err != nil {
		return err
	}
	return os.Rename(name, k.manifestPath())
}

func writeFileSynced(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
