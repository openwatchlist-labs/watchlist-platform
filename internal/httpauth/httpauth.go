// Package httpauth is the HTTP edge adapter for internal/alertcaseapi and
// internal/screeningapi (ADR-0003 SEC-1b, D2). It authenticates a bearer
// token via reviewauth.TokenService.Parse (unchanged) and binds the
// resulting tenant onto the request context via tenantctx before any
// handler runs, so "authenticated but forgot to bind" cannot compile.
//
// A Guard is constructed from an explicit, exhaustive route-to-policy table
// (ADR-0003 §4). Every route a surface registers must be named in that
// table; a route the surface registers but the table omits fails at
// construction, not at request time.
package httpauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
)

// Policy is the authorization requirement declared for a route (ADR-0003
// §4, D3). AuthenticatedTenant is the only non-Public value today; the
// route-level authorization follow-up (ADR-0003 §11) adds more.
type Policy int

const (
	// Public routes require no authentication (health/readiness probes).
	Public Policy = iota
	// AuthenticatedTenant routes require a valid bearer token that binds a
	// concrete tenant onto the request context before the handler runs.
	AuthenticatedTenant
)

// Route identifies one registered endpoint as "METHOD pattern" -- exactly
// as registered with the underlying router (http.ServeMux pattern syntax
// for a surface using ServeMux, or "METHOD literal-path" for a hand-rolled
// switch with no path parameters). It is the key of the route-to-policy
// table.
type Route string

// Matcher derives the Route a request resolves to, using whatever routing
// mechanism the wrapped surface already has (ADR-0003 §2: neither surface's
// routing changes). It must return the same Route value construction-time
// validation was given for that endpoint; requests that match no known
// route (a 404/405 the underlying handler will produce) may return "".
type Matcher func(r *http.Request) Route

// AuditFunc records a security-relevant authentication outcome. It is an
// optional dependency (ADR-0003 §3): screeningapi has no audit store
// configured today, and requiring one would make audit-store provisioning
// a blocker for authentication. A nil AuditFunc disables recording.
type AuditFunc func(event reviewauth.SecurityAuditEvent)

// Guard authenticates and tenant-binds inbound requests per its
// route-to-policy table.
type Guard struct {
	tokens *reviewauth.TokenService
	table  map[Route]Policy
	match  Matcher
	audit  AuditFunc
}

// New builds a Guard. routes is the exhaustive list of endpoints the
// surface registers with its router; table declares the policy for each.
// Construction fails if any route in routes has no entry in table -- the
// structural guarantee ADR-0003 §4 requires: a route present in the mux but
// absent from the table is a startup error, not a 500 on the first request
// that happens to hit it.
func New(routes []Route, table map[Route]Policy, tokens *reviewauth.TokenService, match Matcher, audit AuditFunc) (*Guard, error) {
	if tokens == nil {
		return nil, fmt.Errorf("httpauth: token service is required")
	}
	if match == nil {
		return nil, fmt.Errorf("httpauth: route matcher is required")
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("httpauth: at least one route is required")
	}
	policies := make(map[Route]Policy, len(table))
	for route, policy := range table {
		policies[route] = policy
	}
	seen := make(map[Route]struct{}, len(routes))
	for _, route := range routes {
		if _, ok := policies[route]; !ok {
			return nil, fmt.Errorf("httpauth: route %q has no policy entry in the route table", route)
		}
		seen[route] = struct{}{}
	}
	return &Guard{tokens: tokens, table: policies, match: match, audit: audit}, nil
}

// Wrap returns next guarded by g: Public routes and routes Wrap does not
// recognize (the underlying handler's own 404/405) pass through unchanged;
// AuthenticatedTenant routes require a valid bearer token, and a request
// that clears authentication proceeds with a tenant bound on its context
// (tenantctx.FromContext).
func (g *Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := g.match(r)
		policy, ok := g.table[route]
		if !ok || policy == Public {
			next.ServeHTTP(w, r)
			return
		}

		bearer := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if !strings.HasPrefix(bearer, prefix) {
			g.deny(w, r, "", "authentication required")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(bearer, prefix))
		claims, err := g.tokens.Parse(token, time.Now().UTC())
		if err != nil {
			g.deny(w, r, "", "invalid access token: "+err.Error())
			return
		}
		tenant, err := tenantctx.Resolve(claims)
		if err != nil {
			g.deny(w, r, claims.TokenID, "invalid tenant claim: "+err.Error())
			return
		}

		ctx := tenantctx.NewContext(r.Context(), tenant)
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r.WithContext(ctx))
		g.record(r, claims, tenant.String(), recorder.status)
	})
}

func (g *Guard) deny(w http.ResponseWriter, r *http.Request, tokenID, detail string) {
	if g.audit != nil {
		g.audit(reviewauth.SecurityAuditEvent{
			OccurredAt:  time.Now().UTC().Format(time.RFC3339Nano),
			TokenIDHash: hashOrEmpty(tokenID),
			Method:      r.Method,
			Path:        r.URL.Path,
			Outcome:     "denied",
			StatusCode:  http.StatusUnauthorized,
			Detail:      detailJSON(detail),
		})
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized", "detail": detail})
}

func (g *Guard) record(r *http.Request, claims reviewauth.Claims, tenant string, status int) {
	if g.audit == nil {
		return
	}
	outcome := "allowed"
	if status >= 400 {
		outcome = "denied"
	}
	g.audit(reviewauth.SecurityAuditEvent{
		OccurredAt:  time.Now().UTC().Format(time.RFC3339Nano),
		TokenIDHash: hashOrEmpty(claims.TokenID),
		Subject:     claims.Subject,
		TenantID:    tenant,
		Method:      r.Method,
		Path:        r.URL.Path,
		Outcome:     outcome,
		StatusCode:  status,
	})
}

func hashOrEmpty(tokenID string) string {
	if tokenID == "" {
		return ""
	}
	return reviewauth.HashString(tokenID)
}

func detailJSON(detail string) json.RawMessage {
	encoded, err := json.Marshal(map[string]string{"detail": detail})
	if err != nil {
		return json.RawMessage(`{"detail":"unencodable"}`)
	}
	return encoded
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(w, `{"error":"encoding failure"}`)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// MuxMatcher builds a Matcher from an *http.ServeMux, reusing the mux's own
// pattern match (mux.Handler) so the Route it returns is exactly the
// "METHOD pattern" string the mux was registered with -- no second routing
// implementation to keep in sync with the first. A request matching no
// registered pattern (a 404/405 the mux will itself produce) yields "".
func MuxMatcher(mux *http.ServeMux) Matcher {
	return func(r *http.Request) Route {
		_, pattern := mux.Handler(r)
		return Route(pattern)
	}
}

// ExactMatcher builds a Matcher for a hand-rolled router with no path
// parameters, where every route is an exact "METHOD path" pair (as in
// internal/screeningapi/http.go's switch on request.URL.Path).
func ExactMatcher() Matcher {
	return func(r *http.Request) Route {
		return Route(r.Method + " " + r.URL.Path)
	}
}
