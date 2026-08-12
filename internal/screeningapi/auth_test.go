package screeningapi

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
	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimemmapclient"
)

// loadFixtureTokenService builds a TokenService from the same registry and
// signing key ADR-0003 §6 names as the worked reference
// (cmd/review-console/main.go issue-token): alice is bound to tenant-a,
// mallory to tenant-b, platform-admin to the wildcard tenant.
func loadFixtureTokenService(t *testing.T) *reviewauth.TokenService {
	t.Helper()
	root := filepath.Join("..", "..")
	registry, err := reviewauth.LoadRegistry(filepath.Join(root, "configs", "review-console", "identity-registry-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := reviewauth.LoadSigningKey(filepath.Join(root, "test", "fixtures", "review-console", "signing-key.hex"))
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
		RegistryID:    "screeningapi-auth-test",
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

// newAuthTestHandler builds a guarded screeningapi Handler backed by a
// real (temp-dir) IdempotencyStore, wired through NewAuthenticatedHandler
// so every request in these tests exercises the full guard -> handler ->
// idempotency-store chain, exactly the path §7's tenant-scoped key change
// and §2's tenant binding both need to prove out together.
func newAuthTestHandler(t *testing.T, tokens *reviewauth.TokenService) (http.Handler, IdempotencyStore) {
	t.Helper()
	state := loadGoldenState(t)
	runtime := &fakeRuntime{info: runtimemmapclient.PackageInfo{ProtocolVersion: "1", PackageSHA256: strings.Repeat("a", 64), RecordCount: 3}}
	service := &Service{Loader: staticLoader{state}, Runtime: runtime, MaxCandidates: 20, Clock: func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") }, Scoring: testScoringBinding(t)}
	config := Config{MaxBodyBytes: 1 << 20, MaxBatchItems: 100, MaxCandidates: 20, RequestTimeoutMS: 2000}
	store := IdempotencyStore{Root: t.TempDir()}
	handler := &Handler{Config: config, Service: service, Store: store}
	guarded, err := NewAuthenticatedHandler(handler, tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	return guarded, store
}

func screeningRequestBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(fixtureRequest("screen-auth", "unknown", "UNKNOWN", "2026-07-20T12:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func postScreening(handler http.Handler, authorization string, body []byte, idempotencyKey string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	handler.ServeHTTP(rr, req)
	return rr
}

func idempotencyRecordCount(t *testing.T, root string) int {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
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

// TestScreeningAuthUnauthenticatedRejected is ADR-0003 §9 case 1 for
// screeningapi: no Authorization header, a header without the Bearer
// prefix, a well-formed token with an invalid signature, and a token with
// a valid signature over tampered claims all reject with 401, and none of
// them reaches the handler (proven by no idempotency record written).
func TestScreeningAuthUnauthenticatedRejected(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	validToken, validClaims, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name          string
		authorization string
	}{
		{"no authorization header", ""},
		{"header without bearer prefix", validToken},
		{"invalid signature", "Bearer " + corruptSignature(t, validToken)},
		{"valid signature over tampered claims", "Bearer " + forgeTamperedClaims(t, tokens, validClaims)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, store := newAuthTestHandler(t, tokens)
			rr := postScreening(handler, tc.authorization, screeningRequestBody(t), "idem-"+tc.name)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401, body=%s", rr.Code, rr.Body.String())
			}
			if n := idempotencyRecordCount(t, store.Root); n != 0 {
				t.Fatalf("idempotency records = %d, want 0: an unauthenticated request reached the handler", n)
			}
		})
	}
}

// TestScreeningAuthValidTokenBindsTenant is ADR-0003 §9 case 2: a token
// issued for tenant-a reaches the handler with the bound tenant, the write
// proceeds, and the tenant that reached the handler is exactly the one the
// token named -- proven by reading it back out of the on-disk idempotency
// record (ADR-0003 §7's Tenant field).
func TestScreeningAuthValidTokenBindsTenant(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	handler, store := newAuthTestHandler(t, tokens)
	rr := postScreening(handler, "Bearer "+token, screeningRequestBody(t), "idem-valid-bind")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rr.Code, rr.Body.String())
	}
	entries, err := os.ReadDir(store.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("idempotency records = %d, want 1", len(entries))
	}
	raw, err := os.ReadFile(filepath.Join(store.Root, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Tenant string `json:"tenant"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Tenant != "tenant-a" {
		t.Fatalf("idempotency record tenant = %q, want %q", record.Tenant, "tenant-a")
	}
}

// TestScreeningIdempotencyKeyScopedPerTenant is ADR-0003 §7's regression
// case: two tenants presenting the same idempotency key (and the same
// body) to /v1/screenings receive independent records, and neither
// inherits the other's response -- the screeningapi half of
// GHSA-vhj8-986g-vjf4, testable over HTTP for the first time now that a
// bound tenant reaches the idempotency key derivation.
func TestScreeningIdempotencyKeyScopedPerTenant(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	tokenA, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	tokenB, _, err := tokens.Issue("mallory", "tenant-b", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	handler, store := newAuthTestHandler(t, tokens)
	body := screeningRequestBody(t)
	const sharedKey = "idem-shared-across-tenants"

	respA := postScreening(handler, "Bearer "+tokenA, body, sharedKey)
	if respA.Code != http.StatusOK {
		t.Fatalf("tenant-a status = %d, want 200, body=%s", respA.Code, respA.Body.String())
	}
	if respA.Header().Get("X-Idempotent-Replay") == "true" {
		t.Fatal("tenant-a's first request should not be a replay")
	}

	respB := postScreening(handler, "Bearer "+tokenB, body, sharedKey)
	if respB.Code != http.StatusOK {
		t.Fatalf("tenant-b status = %d, want 200, body=%s", respB.Code, respB.Body.String())
	}
	if respB.Header().Get("X-Idempotent-Replay") == "true" {
		t.Fatal("tenant-b's request replayed tenant-a's response -- the idempotency key collided across tenants")
	}

	if n := idempotencyRecordCount(t, store.Root); n != 2 {
		t.Fatalf("idempotency records = %d, want 2 independent records", n)
	}

	// A same-tenant replay of the same key must still short-circuit --
	// the fix scopes the key by tenant, it does not disable replay.
	replayA := postScreening(handler, "Bearer "+tokenA, body, sharedKey)
	if replayA.Code != http.StatusOK || replayA.Header().Get("X-Idempotent-Replay") != "true" {
		t.Fatalf("expected tenant-a's second identical request to replay, got status=%d header=%q", replayA.Code, replayA.Header().Get("X-Idempotent-Replay"))
	}
	if n := idempotencyRecordCount(t, store.Root); n != 2 {
		t.Fatalf("idempotency records after same-tenant replay = %d, want still 2", n)
	}
}

// TestScreeningAuthWildcardRejected is ADR-0003 §9 case 4: a valid
// platform-admin token bound to tenant '*' is rejected.
func TestScreeningAuthWildcardRejected(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("platform-admin", "*", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	handler, store := newAuthTestHandler(t, tokens)
	rr := postScreening(handler, "Bearer "+token, screeningRequestBody(t), "idem-wildcard")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rr.Code, rr.Body.String())
	}
	if n := idempotencyRecordCount(t, store.Root); n != 0 {
		t.Fatalf("idempotency records = %d, want 0", n)
	}
}

func assertScreeningAuthRejected(t *testing.T, tokens *reviewauth.TokenService, token string) {
	t.Helper()
	handler, store := newAuthTestHandler(t, tokens)
	rr := postScreening(handler, "Bearer "+token, screeningRequestBody(t), "idem-lifecycle")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rr.Code, rr.Body.String())
	}
	if n := idempotencyRecordCount(t, store.Root); n != 0 {
		t.Fatalf("idempotency records = %d, want 0", n)
	}
}

// TestScreeningAuthTokenLifecycleRejections is ADR-0003 §9 cases 5 and 6:
// expired, stale-registry-lineage, and revoked-session-epoch tokens are
// rejected (token.go:123-125, :108-110, :133-135), and a token naming a
// tenant its subject has no binding for fails even when that binding is
// removed only at parse time rather than at issue time.
func TestScreeningAuthTokenLifecycleRejections(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		tokens := syntheticTokenService(t, "v1", "tenant-a")
		// iat truncates to the second and exp = iat + ttl, so a 1ns ttl
		// makes exp == iat: already in the past by the time Parse runs,
		// deterministically, with no sleep required.
		token, _, err := tokens.Issue("alice", "tenant-a", time.Nanosecond, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		assertScreeningAuthRejected(t, tokens, token)
	})
	t.Run("stale registry lineage", func(t *testing.T) {
		mintTokens := syntheticTokenService(t, "v1", "tenant-a")
		token, _, err := mintTokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		guardTokens := syntheticTokenService(t, "v2", "tenant-a")
		assertScreeningAuthRejected(t, guardTokens, token)
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
		assertScreeningAuthRejected(t, tokens, token)
	})
	t.Run("cross-tenant binding removed before parse", func(t *testing.T) {
		tokens := syntheticTokenService(t, "v1", "tenant-a")
		token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		tokens.Registry.Users[0].Bindings[0].TenantID = "tenant-z"
		assertScreeningAuthRejected(t, tokens, token)
	})
}

// TestScreeningRouteTableCompleteness asserts every route screeningapi
// registers has a policy entry, and that constructing a Guard with an
// incomplete table fails, per ADR-0003 §4.
func TestScreeningRouteTableCompleteness(t *testing.T) {
	tokens := loadFixtureTokenService(t)
	if _, err := httpauth.New(Routes, RoutePolicy, tokens, httpauth.ExactMatcher(), nil); err != nil {
		t.Fatalf("route table should be complete: %v", err)
	}
	incomplete := map[httpauth.Route]httpauth.Policy{}
	for route, policy := range RoutePolicy {
		if route == "POST /v1/screenings" {
			continue
		}
		incomplete[route] = policy
	}
	if _, err := httpauth.New(Routes, incomplete, tokens, httpauth.ExactMatcher(), nil); err == nil {
		t.Fatal("expected construction failure for an incomplete route table")
	}
}
