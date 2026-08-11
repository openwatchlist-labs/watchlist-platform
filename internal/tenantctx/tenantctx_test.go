package tenantctx

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
)

func TestResolveRejectsWildcard(t *testing.T) {
	_, err := Resolve(reviewauth.Claims{TenantID: "*"})
	if !errors.Is(err, ErrWildcardTenant) {
		t.Fatalf("Resolve(wildcard) = %v, want ErrWildcardTenant", err)
	}
}

func TestResolveRejectsEmpty(t *testing.T) {
	for _, id := range []string{"", "   "} {
		_, err := Resolve(reviewauth.Claims{TenantID: id})
		if !errors.Is(err, ErrNoTenantClaim) {
			t.Fatalf("Resolve(%q) = %v, want ErrNoTenantClaim", id, err)
		}
	}
}

func TestResolveAcceptsConcreteTenant(t *testing.T) {
	tenant, err := Resolve(reviewauth.Claims{TenantID: "tenant-acme"})
	if err != nil {
		t.Fatalf("Resolve() unexpected error: %v", err)
	}
	if tenant.String() != "tenant-acme" {
		t.Fatalf("tenant.String() = %q, want %q", tenant.String(), "tenant-acme")
	}
}

func TestContextRoundTrip(t *testing.T) {
	tenant, err := Resolve(reviewauth.Claims{TenantID: "tenant-acme"})
	if err != nil {
		t.Fatalf("Resolve() unexpected error: %v", err)
	}
	ctx := NewContext(context.Background(), tenant)
	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext() ok = false, want true")
	}
	if got.String() != tenant.String() {
		t.Fatalf("FromContext() = %q, want %q", got.String(), tenant.String())
	}
}

func TestFromContextMissing(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("FromContext(background) ok = true, want false")
	}
}

func TestAssertResolvesFromBodyWhenNoBoundTenant(t *testing.T) {
	tenant, err := Assert(context.Background(), "tenant-acme")
	if err != nil {
		t.Fatalf("Assert() unexpected error: %v", err)
	}
	if tenant.String() != "tenant-acme" {
		t.Fatalf("Assert() = %q, want %q", tenant.String(), "tenant-acme")
	}
}

func TestAssertRejectsWildcardOrEmptyBodyWhenNoBoundTenant(t *testing.T) {
	for _, id := range []string{"", "*"} {
		if _, err := Assert(context.Background(), id); err == nil {
			t.Fatalf("Assert(%q) = nil error, want rejection", id)
		}
	}
}

func TestAssertAcceptsBodyMatchingBoundTenant(t *testing.T) {
	bound, err := Resolve(reviewauth.Claims{TenantID: "tenant-acme"})
	if err != nil {
		t.Fatalf("Resolve() unexpected error: %v", err)
	}
	ctx := NewContext(context.Background(), bound)
	tenant, err := Assert(ctx, "tenant-acme")
	if err != nil {
		t.Fatalf("Assert() unexpected error: %v", err)
	}
	if tenant.String() != "tenant-acme" {
		t.Fatalf("Assert() = %q, want %q", tenant.String(), "tenant-acme")
	}
}

func TestAssertRejectsBodyMismatchingBoundTenant(t *testing.T) {
	bound, err := Resolve(reviewauth.Claims{TenantID: "tenant-acme"})
	if err != nil {
		t.Fatalf("Resolve() unexpected error: %v", err)
	}
	ctx := NewContext(context.Background(), bound)
	if _, err := Assert(ctx, "tenant-other"); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("Assert() = %v, want ErrTenantMismatch", err)
	}
}

// TestResolveConcurrentSafe exercises Resolve under -race: independent
// resolutions from concurrent goroutines must not share mutable state.
func TestResolveConcurrentSafe(t *testing.T) {
	var wg sync.WaitGroup
	tenants := []string{"tenant-a", "tenant-b", "tenant-c"}
	for i := 0; i < 50; i++ {
		want := tenants[i%len(tenants)]
		wg.Add(1)
		go func(want string) {
			defer wg.Done()
			tenant, err := Resolve(reviewauth.Claims{TenantID: want})
			if err != nil {
				t.Errorf("Resolve(%q) unexpected error: %v", want, err)
				return
			}
			if tenant.String() != want {
				t.Errorf("Resolve(%q).String() = %q", want, tenant.String())
			}
		}(want)
	}
	wg.Wait()
}
