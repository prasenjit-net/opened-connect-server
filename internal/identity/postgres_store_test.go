package identity

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresDSNWithSSLMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		dsn  string
		mode string
		want string
	}{
		{"URL replaces existing mode", "postgres://user:secret@db.example/opened?sslmode=disable", "verify-full", "postgres://user:secret@db.example/opened?sslmode=verify-full"},
		{"URL adds mode", "postgresql://db.example/opened", "require", "postgresql://db.example/opened?sslmode=require"},
		{"keyword replaces mode", "host=db.example dbname=opened sslmode=disable", "verify-ca", "host=db.example dbname=opened sslmode=disable sslmode=verify-ca"},
		{"empty mode preserves DSN", "host=db.example dbname=opened", "", "host=db.example dbname=opened"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := postgresDSNWithSSLMode(tc.dsn, tc.mode)
			if got != tc.want {
				t.Fatalf("postgresDSNWithSSLMode() = %q, want %q", got, tc.want)
			}
			if tc.mode == "" {
				return
			}
			poolCfg, err := pgxpool.ParseConfig(got)
			if err != nil {
				t.Fatalf("parse configured DSN: %v", err)
			}
			if poolCfg.ConnConfig.TLSConfig == nil {
				t.Fatal("configured TLS mode left TLS disabled")
			}
		})
	}
}
