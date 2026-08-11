// Package tenantctx is the single authority for constructing a bound
// tenant value (ADR-0001 SEC-1, §2). It derives a tenant from verified
// reviewauth.Claims and refuses to bind the '*' wildcard: a caller holding
// a wildcard claim must resolve a concrete tenant upstream (the pattern
// already in internal/reviewconsoleapi/server.go:210-216) or be rejected.
// No other package may construct a Tenant.
package tenantctx

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
)

// Tenant is an opaque, resolved tenant binding. The zero value is not a
// valid binding; Resolve is the only constructor.
type Tenant struct{ id string }

// String returns the underlying tenant identifier.
func (t Tenant) String() string { return t.id }

var (
	ErrNoTenantClaim  = errors.New("tenantctx: claims carry no tenant_id")
	ErrWildcardTenant = errors.New("tenantctx: wildcard tenant claim cannot be bound; a concrete tenant is required")
)

// Resolve derives a bound Tenant from verified claims
// (reviewauth.Claims.TenantID). It refuses an empty tenant and refuses the
// '*' wildcard outright -- a wildcard-claim caller must already have
// substituted a concrete tenant into claims.TenantID before calling
// Resolve, or this call is rejected.
func Resolve(claims reviewauth.Claims) (Tenant, error) {
	id := strings.TrimSpace(claims.TenantID)
	switch id {
	case "":
		return Tenant{}, ErrNoTenantClaim
	case "*":
		return Tenant{}, ErrWildcardTenant
	default:
		return Tenant{id: id}, nil
	}
}

type ctxKey struct{}

// NewContext returns a copy of ctx carrying the bound tenant.
func NewContext(ctx context.Context, t Tenant) context.Context {
	return context.WithValue(ctx, ctxKey{}, t)
}

// FromContext returns the bound tenant carried by ctx, if any.
func FromContext(ctx context.Context) (Tenant, bool) {
	t, ok := ctx.Value(ctxKey{}).(Tenant)
	return t, ok
}

// ErrTenantMismatch is returned by Assert when a body-supplied tenant_id
// disagrees with a tenant already bound on ctx.
var ErrTenantMismatch = errors.New("tenantctx: body tenant_id does not match bound tenant")

// ErrNoBoundTenant is returned by Assert when ctx carries no tenant bound
// by a verified caller. Every sink must be reached through a request path
// that authenticates and binds first (internal/httpauth, ADR-0003 SEC-1b
// §2); there is no fallback that trusts a body-supplied tenant_id absent
// that binding.
var ErrNoBoundTenant = errors.New("tenantctx: no tenant bound on context")

// Assert resolves the tenant a write is scoped to, implementing the
// demotion of a body-supplied tenant_id to an assertion (ADR-0001 SEC-1
// §2). ctx must already carry a tenant bound by a verified caller -- id
// must equal it exactly or the write is rejected with ErrTenantMismatch,
// so the body's claim is checked, never silently overwritten and never
// silently trusted. Absent a ctx-bound tenant, Assert fails closed with
// ErrNoBoundTenant rather than resolving id directly: SEC-1b
// (internal/httpauth) closed the gap this interim covered, so a caller
// reaching a sink with no bound tenant is a bug in that caller, not a
// caller this package should still accommodate.
func Assert(ctx context.Context, id string) (Tenant, error) {
	bound, ok := FromContext(ctx)
	if !ok {
		return Tenant{}, ErrNoBoundTenant
	}
	if bound.id != strings.TrimSpace(id) {
		return Tenant{}, fmt.Errorf("%w: body=%q bound=%q", ErrTenantMismatch, id, bound.id)
	}
	return bound, nil
}
