package alertcaseapi

import (
	"bytes"
	"context"
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

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/httpauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
)

const repoRoot = "../.."

// loadFixtureTokenService builds a TokenService from the same registry and
// signing key ADR-0003 §6 names as the worked reference
// (cmd/review-console/main.go issue-token): alice is bound to tenant-a,
// mallory to tenant-b, platform-admin to the wildcard tenant.
func loadFixtureTokenService(t *testing.T) *reviewauth.TokenService {
	t.Helper()
	registry, err := reviewauth.LoadRegistry(filepath.Join(repoRoot, "configs", "review-console", "identity-registry-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := reviewauth.LoadSigningKey(filepath.Join(repoRoot, "test", "fixtures", "review-console", "signing-key.hex"))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := reviewauth.NewTokenService(registry, key, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

// syntheticTokenService builds a small, self-contained, valid registry
// distinct from the fixture one, for cases that need a *different*
// RegistrySHA256 (stale lineage) or that mutate registry state in place
// after minting (revoked epoch, a binding removed before parse) without
// disturbing the shared fixture registry.
func syntheticTokenService(t *testing.T, version, userTenant string) *reviewauth.TokenService {
	t.Helper()
	registry := reviewauth.Registry{
		SchemaVersion: reviewauth.RegistrySchemaV1,
		RegistryID:    "alertcaseapi-auth-test",
		Version:       version,
		Roles:         []reviewauth.Role{{RoleID: "analyst", Permissions: []string{"case.read"}}},
		Users: []reviewauth.User{{
			UserID: "alice", DisplayName: "Alice", Active: true, SessionEpoch: 1,
			Bindings: []reviewauth.RoleBinding{{TenantID: userTenant, Roles: []string{"analyst"}}},
		}},
	}
	sha, err := reviewauth.HashObject(registry)
	if err != nil {
		t.Fatal(err)
	}
	registry.RegistrySHA256 = sha
	tokens, err := reviewauth.NewTokenService(registry, []byte("0123456789abcdef0123456789abcdef"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func testPolicy(t *testing.T) alertcase.Policy {
	t.Helper()
	policy, err := alertcase.LoadPolicy(filepath.Join(repoRoot, "test", "fixtures", "alert-case", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// recordingRunner is a fake alertcase.CommandRunner that records the SQL
// body each call would have sent instead of shelling out to psql. ADR-0003
// §9 requires this test bar run with no database dependency; this is what
// makes "no row written through the Postgres sink" observable without one.
type recordingRunner struct {
	calls [][]byte
}

func (r *recordingRunner) Run(_ context.Context, _ string, _ []string, stdin []byte) ([]byte, error) {
	r.calls = append(r.calls, append([]byte(nil), stdin...))
	return nil, nil
}

// newGuardedServer builds a Server with a real filesystem Store and a fake
// Postgres sink (so PersistAlert/PersistCase are actually reachable, per
// ADR-0003 §6's observation that no existing test enters a sink), wrapped
// by AuthenticatedHandler so every request in these tests exercises the
// full guard -> handler -> sink chain.
func newGuardedServer(t *testing.T, tokens *reviewauth.TokenService) (*Server, http.Handler, *recordingRunner) {
	t.Helper()
	cfg := Config{StateDirectory: t.TempDir(), StreamID: "auth-test", MaxBodyBytes: 1 << 20, TimeoutSeconds: 5}
	server, err := New(cfg, testPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	server.Postgres, err = alertcase.NewPostgresSink("postgres://unused", "psql", runner, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.AuthenticatedHandler(tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server, handler, runner
}

func createAlertRequestBody(t *testing.T, tenant, idempotencyKey string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "test", "fixtures", "alert-case", "create-alert.request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var req alertcase.CreateAlertRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	req.TenantID = tenant
	req.IdempotencyKey = idempotencyKey
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func postAlert(handler http.Handler, token string, body []byte) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", token)
	}
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
// TokenService holds. reviewauth exposes no way to do this (by design);
// it is reimplemented here with stdlib crypto/hmac purely to prove that
// Parse rejects a token whose signature is valid but whose claims disagree
// with the registry, rather than trusting the signature alone.
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

// TestAlertCaseAuthUnauthenticatedRejected is ADR-0003 §9 case 1 for
// alertcaseapi: no Authorization header, a header without the Bearer
// prefix, a well-formed token with an invalid signature, and a token with
// a valid signature over tampered claims all reject with 401, and none of
// them reaches the handler (proven by AlertCount staying zero) or a sink
// (proven by no recorded SQL).
func TestAlertCaseAuthUnauthenticatedRejected(t *testing.T) {
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
			server, handler, runner := newGuardedServer(t, tokens)
			body := createAlertRequestBody(t, "tenant-a", "idem-"+tc.name)
			rr := postAlert(handler, tc.header, body)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401, body=%s", rr.Code, rr.Body.String())
			}
			if len(runner.calls) != 0 {
				t.Fatalf("expected no sink writes, got %d", len(runner.calls))
			}
			status, err := server.Store.Status()
			if err != nil {
				t.Fatal(err)
			}
			if status.AlertCount != 0 {
				t.Fatalf("alert count = %d, want 0: an unauthenticated request reached the handler", status.AlertCount)
			}
		})
	}
}

// TestAlertCaseAuthValidTokenBindsTenant is ADR-0003 §9 case 2: a token
// issued for tenant-a reaches the handler with the bound tenant, and the
// write proceeds all the way through to the sink.
func TestAlertCaseAuthValidTokenBindsTenant(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	server, handler, runner := newGuardedServer(t, tokens)
	body := createAlertRequestBody(t, "tenant-a", "idem-valid-bind")
	rr := postAlert(handler, "Bearer "+token, body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rr.Code, rr.Body.String())
	}
	if len(runner.calls) == 0 {
		t.Fatal("expected the write to reach the Postgres sink")
	}
	status, err := server.Store.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.AlertCount != 1 {
		t.Fatalf("alert count = %d, want 1", status.AlertCount)
	}
}

// TestAlertCaseAuthMismatchedBodyTenantRejected is ADR-0003 §9 case 3: a
// token for tenant-a with a body asserting tenant-b is rejected with 403
// and writes no row through the sink. This is the case that requires the
// server.go tenantctx.ErrTenantMismatch -> 403 mapping: before that
// mapping existed, this exact request returned 201 (PostgresRequired is
// false by default, so the sink's rejection was silently swallowed).
func TestAlertCaseAuthMismatchedBodyTenantRejected(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, handler, runner := newGuardedServer(t, tokens)
	body := createAlertRequestBody(t, "tenant-b", "idem-mismatch")
	rr := postAlert(handler, "Bearer "+token, body)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rr.Code, rr.Body.String())
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no row written through the sink, got %d calls", len(runner.calls))
	}
}

// TestAlertCaseAuthMismatchedBodyTenantRejectedOnCreateCase repeats case 3
// against createCase, the other body-tenant_id write route, proving the
// fix is not specific to a single call site.
func TestAlertCaseAuthMismatchedBodyTenantRejectedOnCreateCase(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	server, handler, runner := newGuardedServer(t, tokens)
	// CreateCase's filesystem validation requires each alert_id to exist
	// and belong to the case's own tenant_id, so seed a real tenant-b
	// alert directly through the Store (bypassing HTTP, and therefore
	// the guard and the sink) before exercising the mismatch through the
	// guarded /v1/cases route.
	var alertReq alertcase.CreateAlertRequest
	if err := json.Unmarshal(createAlertRequestBody(t, "tenant-b", "idem-seed-alert"), &alertReq); err != nil {
		t.Fatal(err)
	}
	alert, _, err := server.Store.CreateAlert(alertReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("seeding the alert through the Store directly should not touch the sink, got %d calls", len(runner.calls))
	}
	caseReq := alertcase.CreateCaseRequest{TenantID: "tenant-b", AlertIDs: []string{alert.AlertID}, CreatedBy: "alice", Reason: "review", OccurredAt: "2026-07-15T13:00:00Z", IdempotencyKey: "idem-case-mismatch"}
	body, err := json.Marshal(caseReq)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cases", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rr.Code, rr.Body.String())
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no row written through the sink, got %d calls", len(runner.calls))
	}
}

// TestAlertCaseAuthWildcardRejected is ADR-0003 §9 case 4: a valid
// platform-admin token bound to tenant '*' is rejected.
func TestAlertCaseAuthWildcardRejected(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("platform-admin", "*", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	server, handler, runner := newGuardedServer(t, tokens)
	body := createAlertRequestBody(t, "tenant-a", "idem-wildcard")
	rr := postAlert(handler, "Bearer "+token, body)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rr.Code, rr.Body.String())
	}
	if len(runner.calls) != 0 {
		t.Fatal("expected no sink writes")
	}
	status, err := server.Store.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.AlertCount != 0 {
		t.Fatalf("alert count = %d, want 0", status.AlertCount)
	}
}

func assertAlertCaseAuthRejected(t *testing.T, tokens *reviewauth.TokenService, token string) {
	t.Helper()
	server, handler, runner := newGuardedServer(t, tokens)
	body := createAlertRequestBody(t, "tenant-a", "idem-lifecycle")
	rr := postAlert(handler, "Bearer "+token, body)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rr.Code, rr.Body.String())
	}
	if len(runner.calls) != 0 {
		t.Fatal("expected no sink writes")
	}
	status, err := server.Store.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.AlertCount != 0 {
		t.Fatalf("alert count = %d, want 0", status.AlertCount)
	}
}

// TestAlertCaseAuthTokenLifecycleRejections is ADR-0003 §9 cases 5 and 6:
// expired, stale-registry-lineage, and revoked-session-epoch tokens are
// rejected (token.go:123-125, :108-110, :133-135), and a token naming a
// tenant its subject has no binding for fails even when that binding is
// removed only at parse time rather than at issue time.
func TestAlertCaseAuthTokenLifecycleRejections(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		tokens := syntheticTokenService(t, "v1", "tenant-a")
		// iat truncates to the second and exp = iat + ttl, so a 1ns ttl
		// makes exp == iat: already in the past by the time Parse runs,
		// deterministically, with no sleep required.
		token, _, err := tokens.Issue("alice", "tenant-a", time.Nanosecond, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		assertAlertCaseAuthRejected(t, tokens, token)
	})
	t.Run("stale registry lineage", func(t *testing.T) {
		mintTokens := syntheticTokenService(t, "v1", "tenant-a")
		token, _, err := mintTokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		guardTokens := syntheticTokenService(t, "v2", "tenant-a")
		assertAlertCaseAuthRejected(t, guardTokens, token)
	})
	t.Run("revoked session epoch", func(t *testing.T) {
		tokens := syntheticTokenService(t, "v1", "tenant-a")
		token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		// Mutated in place, deliberately without recomputing
		// RegistrySHA256, to isolate the epoch check from the lineage
		// check tested above.
		tokens.Registry.Users[0].SessionEpoch = 2
		assertAlertCaseAuthRejected(t, tokens, token)
	})
	t.Run("cross-tenant binding removed before parse", func(t *testing.T) {
		tokens := syntheticTokenService(t, "v1", "tenant-a")
		token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		tokens.Registry.Users[0].Bindings[0].TenantID = "tenant-z"
		assertAlertCaseAuthRejected(t, tokens, token)
	})
}

// TestAlertCaseRouteTableCompleteness asserts every route alertcaseapi
// registers has a policy entry, and that constructing a Guard with an
// incomplete table fails, per ADR-0003 §4.
func TestAlertCaseRouteTableCompleteness(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	cfg := Config{StateDirectory: t.TempDir(), StreamID: "route-test", MaxBodyBytes: 1 << 20, TimeoutSeconds: 5}
	server, err := New(cfg, testPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	mux := server.Handler()
	if _, err := httpauth.New(Routes, RoutePolicy, tokens, httpauth.MuxMatcher(mux), nil); err != nil {
		t.Fatalf("route table should be complete: %v", err)
	}
	incomplete := map[httpauth.Route]httpauth.Policy{}
	for route, policy := range RoutePolicy {
		if route == "POST /v1/alerts" {
			continue
		}
		incomplete[route] = policy
	}
	if _, err := httpauth.New(Routes, incomplete, tokens, httpauth.MuxMatcher(mux), nil); err == nil {
		t.Fatal("expected construction failure for an incomplete route table")
	}
}
