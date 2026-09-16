package oidc

import (
	"context"
	"crypto/rsa"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestProvisionGeneratesAndSignsAndVerifies(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	record, err := ks.Provision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if record.KID == "" {
		t.Fatal("expected a kid")
	}
	if _, err := ks.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if ks.ActiveKID() != record.KID {
		t.Fatalf("active kid mismatch: %s vs %s", ks.ActiveKID(), record.KID)
	}

	token, err := ks.Sign(jwt.Claims{Issuer: "https://issuer.example.com", Subject: "user-1", Audience: jwt.Audience{"client-1"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now())}, map[string]any{"nonce": "abc123"})
	if err != nil {
		t.Fatal(err)
	}

	jwks := ks.PublicJWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 published key, got %d", len(jwks.Keys))
	}
	for _, key := range jwks.Keys {
		if _, ok := key.Key.(*rsa.PublicKey); !ok {
			t.Fatalf("expected an RSA public key in JWKS, got %T", key.Key)
		}
	}
	matching := jwks.Key(record.KID)
	if len(matching) != 1 {
		t.Fatalf("expected exactly one JWK matching kid %s", record.KID)
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	var extra map[string]any
	if err := parsed.Claims(matching[0].Key, &claims, &extra); err != nil {
		t.Fatalf("signature did not verify against published JWK: %v", err)
	}
	if claims.Subject != "user-1" || extra["nonce"] != "abc123" {
		t.Fatalf("unexpected claims: %+v %+v", claims, extra)
	}
}

func TestProvisionIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := ks.Provision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ks.Provision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.KID != second.KID {
		t.Fatalf("provisioning again generated a new key: %s vs %s", first.KID, second.KID)
	}
}

func TestProvisionResumesInterruptedInit(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between committing the key directory and writing the
	// manifest: generate and stage a key directly, without recording it.
	key, err := generateSigningKey(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.stageAndCommitKey(key); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one orphaned key directory, got %v (err=%v)", entries, err)
	}

	record, err := ks.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if record.KID != key.record.KID {
		t.Fatalf("expected orphaned key %s to be activated, got %s", key.record.KID, record.KID)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	dirCount := 0
	for _, e := range entries {
		if e.IsDir() {
			dirCount++
		}
	}
	if dirCount != 1 {
		t.Fatalf("expected recovery to reuse the orphaned key, not generate a second one; found %d directories", dirCount)
	}
}

func TestLoadFailsClosedWithoutProvision(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Load(context.Background()); err == nil {
		t.Fatal("expected Load to fail closed with no signing material")
	}
}

func TestLoadFailsClosedOnCorruptMaterial(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	record, err := ks.Provision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, record.KID, "private.pem"), []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Load(ctx); err == nil {
		t.Fatal("expected Load to fail closed on corrupted private key material")
	}
}

func TestLoadFailsClosedOnExpiredKey(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Generate a key that's already expired and commit it directly.
	key, err := generateSigningKey(time.Now().Add(-400 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.stageAndCommitKey(key); err != nil {
		t.Fatal(err)
	}
	if err := ks.writeManifest(keyManifest{Active: key.record.KID, Keys: []KeyRecord{key.record}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Load(ctx); err == nil {
		t.Fatal("expected Load to fail closed on an expired active key")
	}
}

func TestRotatePreservesVerificationOfPriorKey(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := ks.Provision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Load(ctx); err != nil {
		t.Fatal(err)
	}
	tokenFromFirst, err := ks.Sign(jwt.Claims{Subject: "user-1"})
	if err != nil {
		t.Fatal(err)
	}

	second, err := ks.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.KID == first.KID {
		t.Fatal("rotate did not generate a new key")
	}
	if ks.ActiveKID() != second.KID {
		t.Fatalf("expected new key to be active, got %s", ks.ActiveKID())
	}

	jwks := ks.PublicJWKS()
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected both keys published for verification, got %d", len(jwks.Keys))
	}
	matching := jwks.Key(first.KID)
	if len(matching) != 1 {
		t.Fatal("expected the retired key to remain in the published JWKS")
	}
	parsed, err := jwt.ParseSigned(tokenFromFirst, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	if err := parsed.Claims(matching[0].Key, &claims); err != nil {
		t.Fatalf("token signed with retired key no longer verifies: %v", err)
	}
}

func TestConcurrentProvisionFromTwoProcesses(t *testing.T) {
	dir := t.TempDir()
	a, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan KeyRecord, 2)
	errs := make(chan error, 2)
	for _, ks := range []*KeyStore{a, b} {
		wg.Add(1)
		go func(ks *KeyStore) {
			defer wg.Done()
			r, err := ks.Provision(context.Background())
			if err != nil {
				errs <- err
				return
			}
			results <- r
		}(ks)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var kids []string
	for r := range results {
		kids = append(kids, r.KID)
	}
	if len(kids) != 2 || kids[0] != kids[1] {
		t.Fatalf("expected both concurrent provisions to agree on one active key, got %v", kids)
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	record, err := ks.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("expected signing key directory to be 0700, got %v", info.Mode().Perm())
	}
	for _, name := range []string{"private.pem", "certificate.pem"} {
		info, err := os.Stat(filepath.Join(dir, record.KID, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected %s to be 0600, got %v", name, info.Mode().Perm())
		}
	}
	info, err = os.Stat(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected manifest.json to be 0600, got %v", info.Mode().Perm())
	}
}
