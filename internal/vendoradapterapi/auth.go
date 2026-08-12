package vendoradapterapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/httpauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
)

// Routes lists every endpoint Handler's mux registers (server.go:54-57),
// exactly as httpauth.MuxMatcher observes it (the http.ServeMux pattern
// string, method included). ADR-0006 §3's construction-time completeness
// guarantee depends on this list staying exhaustive: NewAuthenticatedHandler
// fails to construct if a route named here has no entry in RoutePolicy.
var Routes = []httpauth.Route{
	"GET /healthz",
	"GET /readyz",
	"GET /v1/vendor-adapters",
	"POST /v1/vendor-alerts/{adapter}",
}

// RoutePolicy is the route-to-policy table ADR-0006 §3 declares for
// internal/vendoradapterapi. AuthenticatedTenant is the only policy in use
// until the route-level authorization follow-up (ADR-0003 §11, ADR-0006 §9)
// lands -- including on /v1/vendor-adapters, which does not yet filter by
// tenant (ADR-0006 §9).
var RoutePolicy = map[httpauth.Route]httpauth.Policy{
	"GET /healthz":                     httpauth.Public,
	"GET /readyz":                      httpauth.Public,
	"GET /v1/vendor-adapters":          httpauth.AuthenticatedTenant,
	"POST /v1/vendor-alerts/{adapter}": httpauth.AuthenticatedTenant,
}

// AuthenticatedHandler wraps s.Handler() with an httpauth.Guard built from
// Routes and RoutePolicy (ADR-0006 §3). This is the hard cutover (D5): every
// caller of this surface, cmd/vendor-adapter-api/main.go included, must
// serve through the returned http.Handler rather than s.Handler() directly.
func (s *Server) AuthenticatedHandler(tokens *reviewauth.TokenService, audit httpauth.AuditFunc) (http.Handler, error) {
	mux := s.Handler()
	guard, err := httpauth.New(Routes, RoutePolicy, tokens, httpauth.MuxMatcher(mux), audit)
	if err != nil {
		return nil, err
	}
	return guard.Wrap(mux), nil
}

// LoadTokenService constructs the reviewauth.TokenService config.serve
// authenticates with, from config.AuthRegistryPath and config.SigningKeyPath.
// Unlike LoadConfig, this treats both as required -- they are optional at
// LoadConfig time (so "check" needs no auth wiring), but "serve" cannot
// start without them under D5's hard cutover.
func LoadTokenService(config Config) (*reviewauth.TokenService, error) {
	if strings.TrimSpace(config.AuthRegistryPath) == "" || strings.TrimSpace(config.SigningKeyPath) == "" {
		return nil, fmt.Errorf("auth_registry_path and signing_key_path are required to serve")
	}
	registry, err := reviewauth.LoadRegistry(config.AuthRegistryPath)
	if err != nil {
		return nil, fmt.Errorf("auth registry: %w", err)
	}
	signingKey, err := reviewauth.LoadSigningKey(config.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	maxTTL := time.Duration(config.MaxTokenTTLMinutes) * time.Minute
	tokens, err := reviewauth.NewTokenService(registry, signingKey, maxTTL)
	if err != nil {
		return nil, fmt.Errorf("token service: %w", err)
	}
	return tokens, nil
}
