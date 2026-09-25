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
		{"URL replaces existing mode", "postgres://user:secret@db.example/openid?sslmode=disable", "verify-full", "postgres://user:secret@db.example/openid?sslmode=verify-full"},
		{"URL adds mode", "postgresql://db.example/openid", "require", "postgresql://db.example/openid?sslmode=require"},
		{"keyword replaces mode", "host=db.example dbname=openid sslmode=disable", "verify-ca", "host=db.example dbname=openid sslmode=disable sslmode=verify-ca"},
		{"empty mode preserves DSN", "host=db.example dbname=openid", "", "host=db.example dbname=openid"},
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
