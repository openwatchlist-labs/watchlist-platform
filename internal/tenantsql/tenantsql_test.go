package tenantsql_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantsql"
)

// This test file lives in the external tenantsql_test package precisely
// because internal/tenantsql.Bound (ADR-0001 SEC-1 §3.3) is only
// constructible from inside internal/tenantsql: the concrete type
// implementing it is unexported. There is no expression an external
// package (including this test) can write that produces a tenantsql.Bound
// except by receiving one through a tenantsql.WithTenant callback -- that
// is the property this file exercises, since it cannot be exercised any
// other way (writing `tenantsql.bound{}` here does not compile).

func TestWithTenantWrapsBeginSetConfigCommit(t *testing.T) {
	tenant, err := tenantctx.Resolve(reviewauth.Claims{TenantID: "tenant-acme"})
	if err != nil {
		t.Fatalf("Resolve() unexpected error: %v", err)
	}
	body := "INSERT INTO alert_record(alert_id) VALUES (1);\n"
	var got string
	var gotProof tenantsql.Bound
	exec := func(ctx context.Context, proof tenantsql.Bound, sql string) error {
		got = sql
		gotProof = proof
		return nil
	}
	if err := tenantsql.WithTenant(context.Background(), tenant, body, exec); err != nil {
		t.Fatalf("WithTenant() unexpected error: %v", err)
	}
	if gotProof == nil {
		t.Fatal("exec was not handed a Bound proof")
	}
	if !strings.HasPrefix(got, "BEGIN;\n") {
		t.Fatalf("wrapped SQL does not start with BEGIN;\\n: %q", got)
	}
	if !strings.Contains(got, "SELECT set_config('openwatchlist.tenant_id',") {
		t.Fatalf("wrapped SQL does not set the tenant GUC: %q", got)
	}
	if !strings.Contains(got, body) {
		t.Fatalf("wrapped SQL does not contain the caller's body: %q", got)
	}
	if !strings.HasSuffix(got, "COMMIT;\n") {
		t.Fatalf("wrapped SQL does not end with COMMIT;\\n: %q", got)
	}
	// SELECT set_config must precede the body, and the body must precede COMMIT.
	setIdx := strings.Index(got, "SELECT set_config")
	bodyIdx := strings.Index(got, body)
	commitIdx := strings.LastIndex(got, "COMMIT;")
	if !(setIdx < bodyIdx && bodyIdx < commitIdx) {
		t.Fatalf("wrapped SQL out of order: set_config=%d body=%d commit=%d\n%s", setIdx, bodyIdx, commitIdx, got)
	}
}

func TestWithTenantHexEncodesTenant(t *testing.T) {
	tenant, err := tenantctx.Resolve(reviewauth.Claims{TenantID: "tenant-o'brien"})
	if err != nil {
		t.Fatalf("Resolve() unexpected error: %v", err)
	}
	var got string
	exec := func(ctx context.Context, proof tenantsql.Bound, sql string) error {
		got = sql
		return nil
	}
	if err := tenantsql.WithTenant(context.Background(), tenant, "", exec); err != nil {
		t.Fatalf("WithTenant() unexpected error: %v", err)
	}
	// The tenant value must never appear as a raw quoted literal -- it is
	// hex-decoded server-side via convert_from(decode(...)), the same
	// idiom as internal/screeningledger/postgres.go:90-92.
	if strings.Contains(got, "'tenant-o'brien'") {
		t.Fatalf("tenant literal was interpolated unescaped: %q", got)
	}
	if !strings.Contains(got, "convert_from(decode('") {
		t.Fatalf("tenant was not hex-encoded via the sqlText idiom: %q", got)
	}
}

func TestWithTenantPropagatesExecError(t *testing.T) {
	tenant, err := tenantctx.Resolve(reviewauth.Claims{TenantID: "tenant-acme"})
	if err != nil {
		t.Fatalf("Resolve() unexpected error: %v", err)
	}
	sentinel := context.Canceled
	exec := func(ctx context.Context, proof tenantsql.Bound, sql string) error { return sentinel }
	if err := tenantsql.WithTenant(context.Background(), tenant, "", exec); err != sentinel {
		t.Fatalf("WithTenant() error = %v, want %v", err, sentinel)
	}
}

func TestInsertAssemblesStatement(t *testing.T) {
	sql := tenantsql.Insert("alert_record", []tenantsql.Col{
		{Name: "alert_id", SQL: "'a1'"},
		{Name: "tenant_id", SQL: "'t1'"},
	}, "ON CONFLICT(alert_id) DO NOTHING")
	want := "INSERT INTO alert_record(alert_id,tenant_id) VALUES ('a1','t1') ON CONFLICT(alert_id) DO NOTHING;\n"
	if sql != want {
		t.Fatalf("Insert() = %q, want %q", sql, want)
	}
}

func TestInsertNoConflictClause(t *testing.T) {
	sql := tenantsql.Insert("alert_record", []tenantsql.Col{{Name: "alert_id", SQL: "'a1'"}}, "")
	want := "INSERT INTO alert_record(alert_id) VALUES ('a1');\n"
	if sql != want {
		t.Fatalf("Insert() = %q, want %q", sql, want)
	}
}

func TestInsertCatchConflictAssemblesStatement(t *testing.T) {
	sql := tenantsql.InsertCatchConflict("alert_case_idempotency", []tenantsql.Col{
		{Name: "tenant_id", SQL: "'t1'"},
		{Name: "scope", SQL: "'s1'"},
	})
	want := "DO $$ BEGIN\n" +
		"INSERT INTO alert_case_idempotency(tenant_id,scope) VALUES ('t1','s1');\n" +
		"EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'idempotency key conflict on alert_case_idempotency: %', SQLERRM;\n" +
		"END $$;\n"
	if sql != want {
		t.Fatalf("InsertCatchConflict() = %q, want %q", sql, want)
	}
}

func TestInsertCatchConflictHasNoConflictClause(t *testing.T) {
	sql := tenantsql.InsertCatchConflict("alert_case_idempotency", []tenantsql.Col{{Name: "scope", SQL: "'s1'"}})
	if strings.Contains(sql, "ON CONFLICT") {
		t.Fatalf("InsertCatchConflict() must never contain ON CONFLICT, got %q", sql)
	}
	if !strings.Contains(sql, "EXCEPTION WHEN unique_violation") {
		t.Fatalf("InsertCatchConflict() does not catch unique_violation: %q", sql)
	}
}

// TestWithTenantConcurrentSafe exercises the seam under -race: concurrent
// bindings for different tenants must not observe each other's state,
// since there is none shared -- each call builds an independent string.
func TestWithTenantConcurrentSafe(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		id := "tenant-" + string(rune('a'+i%5))
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			tenant, err := tenantctx.Resolve(reviewauth.Claims{TenantID: id})
			if err != nil {
				t.Errorf("Resolve(%q) unexpected error: %v", id, err)
				return
			}
			exec := func(ctx context.Context, proof tenantsql.Bound, sql string) error { return nil }
			if err := tenantsql.WithTenant(context.Background(), tenant, "", exec); err != nil {
				t.Errorf("WithTenant(%q) unexpected error: %v", id, err)
			}
		}(id)
	}
	wg.Wait()
}
