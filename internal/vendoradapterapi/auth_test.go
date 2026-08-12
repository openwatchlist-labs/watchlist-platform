package vendoradapterapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/httpauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
)

const authTestRepoRoot = "../.."

// loadFixtureTokenService builds a TokenService from the same registry and
// signing key ADR-0003 §6 names as the worked reference: alice is bound to
// tenant-a, platform-admin to the wildcard tenant (ADR-0006 §3, §8).
func loadFixtureTokenService(t *testing.T) *reviewauth.TokenService {
	t.Helper()
	registry, err := reviewauth.LoadRegistry(filepath.Join(authTestRepoRoot, "configs", "review-console", "identity-registry-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := reviewauth.LoadSigningKey(filepath.Join(authTestRepoRoot, "test", "fixtures", "review-console", "signing-key.hex"))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := reviewauth.NewTokenService(registry, key, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

// newAuthenticatedServer builds a Server wrapped by AuthenticatedHandler
// (ADR-0006 §3), so requests in these tests exercise the full guard ->
// handler -> sink chain rather than the raw, unauthenticated s.Handler().
func newAuthenticatedServer(t *testing.T, tokens *reviewauth.TokenService, psqlPath string, postgresRequired bool) (*Server, http.Handler) {
	t.Helper()
	s := testServer(t, psqlPath, postgresRequired)
	handler, err := s.AuthenticatedHandler(tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, handler
}

func postVendorAlert(handler http.Handler, adapter, bearer string, body []byte) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vendor-alerts/"+adapter, bytes.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	return rr
}

func corruptSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape: %q", token)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

// forgeTamperedClaims signs a claims payload reviewauth.TokenService.Issue
// would never produce -- an extra role the registry does not grant this
// subject for this tenant -- using the same HMAC key the fixture
// TokenService holds, to prove Parse rejects a token whose signature is
// valid but whose claims disagree with the registry.
func forgeTamperedClaims(t *testing.T, tokens *reviewauth.TokenService, claims reviewauth.Claims) string {
	t.Helper()
	tampered := claims
	tampered.Roles = append(append([]string(nil), claims.Roles...), "platform_admin")
	sort.Strings(tampered.Roles)
	payload, err := reviewauth.CanonicalJSON(tampered)
	if err != nil {
		t.Fatal(err)
	}
	signed := "owat1." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, tokens.Key)
	mac.Write([]byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TestVendorAdapterAuthUnauthenticatedRejected is ADR-0006 §8 case 3: no
// Authorization header, a header without the Bearer prefix, a well-formed
// token with an invalid signature, and a token with a valid signature over
// tampered claims all reject with 401, and none of them reaches the handler
// (proven by RecordCount staying zero).
func TestVendorAdapterAuthUnauthenticatedRejected(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	validToken, validClaims, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		header string
	}{
		{"no authorization header", ""},
		{"header without bearer prefix", validToken},
		{"invalid signature", "Bearer " + corruptSignature(t, validToken)},
		{"valid signature over tampered claims", "Bearer " + forgeTamperedClaims(t, tokens, validClaims)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Clean(filepath.Join("..", ".."))
			s, handler := newAuthenticatedServer(t, tokens, filepath.Join(root, "test", "fixtures", "alert-case", "fake-psql.sh"), false)
			rr := postVendorAlert(handler, "generic-json-v1", tc.header, genericAlertBody(t))
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401, body=%s", rr.Code, rr.Body.String())
			}
			status, err := s.Store.Verify()
			if err != nil {
				t.Fatal(err)
			}
			if status.RecordCount != 0 {
				t.Fatalf("record count = %d, want 0: an unauthenticated request reached the handler", status.RecordCount)
			}
		})
	}
}

// TestVendorAdapterAuthWildcardRejected is ADR-0006 §8 case 4: a valid
// platform-admin token bound to tenant '*' is rejected.
func TestVendorAdapterAuthWildcardRejected(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("platform-admin", "*", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	s, handler := newAuthenticatedServer(t, tokens, filepath.Join(root, "test", "fixtures", "alert-case", "fake-psql.sh"), false)
	rr := postVendorAlert(handler, "generic-json-v1", "Bearer "+token, genericAlertBody(t))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rr.Code, rr.Body.String())
	}
	status, err := s.Store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if status.RecordCount != 0 {
		t.Fatalf("record count = %d, want 0", status.RecordCount)
	}
}

// mismatchedProfilesDir writes a copy of the real generic-json-v1 profile
// into a fresh directory with constants.tenant_id overridden to tenant-b, so
// a token bound to tenant-a can be posted against an adapter whose profile
// declares a different tenant. profile_sha256 is cleared so LoadProfile
// recomputes it for the mutated content instead of failing a stale-checksum
// check unrelated to what this test is proving.
func mismatchedProfilesDir(t *testing.T, root string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "configs", "vendor-adapters", "generic-json-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["constants"].(map[string]any)["tenant_id"] = "tenant-b"
	doc["profile_sha256"] = ""
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "generic-json-v1.json"), out, 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestVendorAdapterIngestConstantsBoundTenantEnforced is ADR-0006 §8 case 1:
// a token issued for tenant-a posting to an adapter whose profile declares
// constants.tenant_id = "tenant-a" reaches the handler, the write proceeds,
// and the persisted tenant is tenant-a.
func TestVendorAdapterIngestConstantsBoundTenantEnforced(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	s, handler := newAuthenticatedServer(t, tokens, filepath.Join(root, "test", "fixtures", "alert-case", "fake-psql.sh"), false)
	rr := postVendorAlert(handler, "generic-json-v1", "Bearer "+token, genericAlertBody(t))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Envelope struct {
			CreateAlertRequest struct {
				TenantID string `json:"tenant_id"`
			} `json:"create_alert_request"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Envelope.CreateAlertRequest.TenantID != "tenant-a" {
		t.Fatalf("persisted tenant = %q, want tenant-a", body.Envelope.CreateAlertRequest.TenantID)
	}
	status, err := s.Store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if status.RecordCount != 1 {
		t.Fatalf("record count = %d, want 1", status.RecordCount)
	}
}

// TestVendorAdapterIngestMismatchRejectedNothingWritten is ADR-0006 §8 case
// 2, and the test that proves D3 rather than restating D4: a token for
// tenant-a posting to an adapter whose profile declares tenant-b is
// rejected with 403 and leaves no record, receipt or audit entry in the
// state directory. Before the ordering fix, the mismatch is only caught
// downstream in Postgres.Persist, after Store.Process has already written
// the record to disk -- the filesystem is the authoritative read source
// (ADR-0006 §5), not a mirror, so a 403 that fires after that write is too
// late.
func TestVendorAdapterIngestMismatchRejectedNothingWritten(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	cfg := Config{
		ListenAddress:     "127.0.0.1:0",
		ProfilesDirectory: mismatchedProfilesDir(t, root),
		StateDirectory:    t.TempDir(),
		StreamID:          "auth-test",
		MaxBodyBytes:      4 << 20,
		PostgresDSN:       "postgres://fixture",
		PSQLPath:          filepath.Join(root, "test", "fixtures", "alert-case", "fake-psql.sh"),
		PostgresRequired:  false,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := s.AuthenticatedHandler(tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := postVendorAlert(handler, "generic-json-v1", "Bearer "+token, genericAlertBody(t))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rr.Code, rr.Body.String())
	}
	status, err := s.Store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if status.RecordCount != 0 || status.ReceiptCount != 0 || status.AuditCount != 0 {
		t.Fatalf("status = %+v, want all zero: a rejected write must leave nothing on disk (ADR-0006 D3)", status)
	}
}

// TestVendorAdapterRouteTableCompleteness asserts every route
// vendoradapterapi registers has a policy entry, and that constructing a
// Guard with an incomplete table fails, per ADR-0006 §3 (ADR-0003 §4's
// structural guarantee, transposed).
func TestVendorAdapterRouteTableCompleteness(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	root := filepath.Clean(filepath.Join("..", ".."))
	s := testServer(t, filepath.Join(root, "test", "fixtures", "alert-case", "fake-psql.sh"), false)
	mux := s.Handler()
	if _, err := httpauth.New(Routes, RoutePolicy, tokens, httpauth.MuxMatcher(mux), nil); err != nil {
		t.Fatalf("route table should be complete: %v", err)
	}
	incomplete := map[httpauth.Route]httpauth.Policy{}
	for route, policy := range RoutePolicy {
		if route == "POST /v1/vendor-alerts/{adapter}" {
			continue
		}
		incomplete[route] = policy
	}
	if _, err := httpauth.New(Routes, incomplete, tokens, httpauth.MuxMatcher(mux), nil); err == nil {
		t.Fatal("expected construction failure for an incomplete route table")
	}
}
