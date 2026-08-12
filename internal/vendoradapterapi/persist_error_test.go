package vendoradapterapi

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
)

func testServer(t *testing.T, psqlPath string, postgresRequired bool) *Server {
	t.Helper()
	root := filepath.Clean(filepath.Join("..", ".."))
	cfg := Config{
		ListenAddress:     "127.0.0.1:0",
		ProfilesDirectory: filepath.Join(root, "configs", "vendor-adapters"),
		StateDirectory:    t.TempDir(),
		StreamID:          "test",
		MaxBodyBytes:      4 << 20,
		PostgresDSN:       "postgres://fixture",
		PSQLPath:          psqlPath,
		PostgresRequired:  postgresRequired,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func genericAlertBody(t *testing.T) []byte {
	t.Helper()
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, "test", "fixtures", "vendor-adapters", "generic-alert.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestIngestSurfacesTenantMismatchRegardlessOfPostgresRequired is the
// regression test for the silent-201 swallow: server.go's ingest handler
// only inspected s.Postgres.Persist's error when Config.PostgresRequired
// was true, so an integrity failure -- here, a body tenant_id disagreeing
// with a ctx-bound tenant -- was discarded and the handler still returned
// 201 with PostgresRequired's shipped default (false). This binds a
// tenant on the request context directly (bypassing the fact that no auth
// middleware exists yet on this surface -- SEC-1e) so the assertion is
// exercised deterministically regardless of the SEC-1e interim fallback:
// a bound ctx always takes tenantctx.Assert's real mismatch check.
func TestIngestSurfacesTenantMismatchRegardlessOfPostgresRequired(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	s := testServer(t, filepath.Join(root, "test", "fixtures", "alert-case", "fake-psql.sh"), false)

	bound, err := tenantctx.Resolve(reviewauth.Claims{TenantID: "tenant-other"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/vendor-alerts/generic-json-v1", bytes.NewReader(genericAlertBody(t)))
	req = req.WithContext(tenantctx.NewContext(req.Context(), bound))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code == 200 || rec.Code == 201 {
		t.Fatalf("ingest() with a tenant-mismatched write returned %d (body swallowed the integrity failure), want it surfaced regardless of PostgresRequired=false", rec.Code)
	}
	if rec.Code != 403 {
		t.Fatalf("ingest() with a tenant-mismatched write returned %d, want 403", rec.Code)
	}
}

// TestIngestDegradesOnGenericPostgresFailureWhenNotRequired guards the
// behavior PostgresRequired=false is actually meant to tolerate: a
// Postgres-side outage (here, simulated by pointing PSQLPath at a
// nonexistent binary) is not a tenant-integrity failure, and the fix for
// the silent-201 bug must not turn this into a hard failure. The local
// filesystem write already succeeded; the Postgres mirror is best-effort
// under this config.
func TestIngestDegradesOnGenericPostgresFailureWhenNotRequired(t *testing.T) {
	s := testServer(t, filepath.Join(t.TempDir(), "no-such-psql-binary"), false)

	req := httptest.NewRequest("POST", "/v1/vendor-alerts/generic-json-v1", bytes.NewReader(genericAlertBody(t)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Fatalf("ingest() with an unreachable Postgres and PostgresRequired=false returned %d, want 201 (degrade gracefully)", rec.Code)
	}
}
