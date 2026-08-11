package screeningapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/httpauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
)

// Routes lists every endpoint the ServeHTTP switch (http.go:23-54)
// dispatches, exactly as httpauth.ExactMatcher observes it (method plus
// literal path -- this surface has no path parameters). ADR-0003 §4's
// construction-time completeness guarantee depends on this list staying
// exhaustive: NewAuthenticatedHandler fails to construct if a route named
// here has no entry in RoutePolicy.
var Routes = []httpauth.Route{
	"GET /healthz",
	"GET /readyz",
	"POST /v1/screenings",
	"POST /v1/screenings/batch",
}

// RoutePolicy is the route-to-policy table ADR-0003 §4 declares for
// internal/screeningapi. AuthenticatedTenant is the only policy in use
// until the route-level authorization follow-up (ADR-0003 §11) lands.
var RoutePolicy = map[httpauth.Route]httpauth.Policy{
	"GET /healthz":              httpauth.Public,
	"GET /readyz":               httpauth.Public,
	"POST /v1/screenings":       httpauth.AuthenticatedTenant,
	"POST /v1/screenings/batch": httpauth.AuthenticatedTenant,
}

// NewAuthenticatedHandler wraps handler with an httpauth.Guard built from
// Routes and RoutePolicy (ADR-0003 §2, §4). This is the hard cutover (D4):
// every caller of this surface, cmd/screening-api/main.go included, must
// serve through the returned http.Handler rather than handler directly.
func NewAuthenticatedHandler(handler *Handler, tokens *reviewauth.TokenService, audit httpauth.AuditFunc) (http.Handler, error) {
	guard, err := httpauth.New(Routes, RoutePolicy, tokens, httpauth.ExactMatcher(), audit)
	if err != nil {
		return nil, err
	}
	return guard.Wrap(handler), nil
}

// LoadTokenService constructs the reviewauth.TokenService config.serve
// authenticates with, from config.AuthRegistryPath and
// config.SigningKeyPath. Unlike ValidateConfig, this treats both as
// required -- they are optional at LoadConfig time (so "check" needs no
// auth wiring), but "serve" cannot start without them under D4's hard
// cutover.
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
