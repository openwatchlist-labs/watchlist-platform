package vendoradapterapi

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
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
// used to inspect s.Postgres.Persist's error only when Config.PostgresRequired
// was true, so an integrity failure -- here, an authenticated caller's bound
// tenant disagreeing with the adapter profile's declared tenant -- was
// discarded and the handler still returned 201 with PostgresRequired's
// shipped default (false). Now that internal/httpauth middleware exists
// (ADR-0006 D1), this mints a real token (mallory, bound to tenant-b) rather
// than binding a tenant on the request context directly, per ADR-0006 §6's
// point against stubbing the verification path out of the tests that exist
// to protect it.
func TestIngestSurfacesTenantMismatchRegardlessOfPostgresRequired(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("mallory", "tenant-b", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	s := testServer(t, filepath.Join(root, "test", "fixtures", "alert-case", "fake-psql.sh"), false)
	handler, err := s.AuthenticatedHandler(tokens, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/v1/vendor-alerts/generic-json-v1", bytes.NewReader(genericAlertBody(t)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == 200 || rec.Code == 201 {
		t.Fatalf("ingest() with a tenant-mismatched write returned %d (body swallowed the integrity failure), want it surfaced regardless of PostgresRequired=false", rec.Code)
	}
	if rec.Code != 403 {
		t.Fatalf("ingest() with a tenant-mismatched write returned %d, want 403", rec.Code)
	}
	status, err := s.Store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if status.RecordCount != 0 {
		t.Fatalf("record count = %d, want 0: a mismatched write must leave nothing on disk (ADR-0006 D3)", status.RecordCount)
	}
}

// TestIngestDegradesOnGenericPostgresFailureWhenNotRequired guards the
// behavior PostgresRequired=false is actually meant to tolerate: a
// Postgres-side outage (here, simulated by pointing PSQLPath at a
// nonexistent binary) is not a tenant-integrity failure, and the fix for the
// silent-201 bug must not turn this into a hard failure. The local
// filesystem write already succeeded; the Postgres mirror is best-effort
// under this config. A real token (alice, bound to tenant-a, matching
// generic-json-v1's declared constant) is required so the request clears
// the D3 tenant assertion before reaching Store.Process.
func TestIngestDegradesOnGenericPostgresFailureWhenNotRequired(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	s := testServer(t, filepath.Join(t.TempDir(), "no-such-psql-binary"), false)
	handler, err := s.AuthenticatedHandler(tokens, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/v1/vendor-alerts/generic-json-v1", bytes.NewReader(genericAlertBody(t)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Fatalf("ingest() with an unreachable Postgres and PostgresRequired=false returned %d, want 201 (degrade gracefully)", rec.Code)
	}
}
