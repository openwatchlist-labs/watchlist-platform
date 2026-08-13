// NewReadinessPool/NewReadinessConn exercised against a live PostgreSQL
// connection (ADR-0005 §11.2), the same OWL_TEST_DATABASE_URL-gated shape
// internal/screeningledger/postgres_pgx_test.go uses for its own pgx
// suite -- skips cleanly when unset. This is the owl_app identity, not
// the migrator: the readiness probe only ever issues Ping, so it needs
// no DDL rights.
package productionops

import (
	"context"
	"os"
	"testing"
)

func requireReadinessDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_TEST_DATABASE_URL not set; readiness pgx suite requires a live Postgres (see scripts/ci/run-ci.sh)")
	}
	return dsn
}

func TestNewReadinessPoolPingsRealPostgres(t *testing.T) {
	t.Setenv("REL2_STAGE2_TEST_DSN", requireReadinessDSN(t))
	ctx := context.Background()
	c := RuntimeConfig{Readiness: ReadinessConfig{PostgreSQLRequired: true, PostgreSQLDSNEnv: "REL2_STAGE2_TEST_DSN"}}

	pool, err := NewReadinessPool(ctx, c)
	if err != nil {
		t.Fatalf("NewReadinessPool: %v", err)
	}
	if pool == nil {
		t.Fatal("NewReadinessPool returned a nil pool when PostgreSQL readiness is configured")
	}
	defer pool.Close()

	r := CheckRuntime(ctx, c, QuotaRegistry{}, pool)
	for _, chk := range r.Checks {
		if chk.Name == "postgresql" && chk.Status != "ok" {
			t.Fatalf("postgresql check failed against a real pooled connection: %s", chk.Detail)
		}
	}
}

func TestNewReadinessConnPingsRealPostgres(t *testing.T) {
	t.Setenv("REL2_STAGE2_TEST_DSN", requireReadinessDSN(t))
	ctx := context.Background()
	c := RuntimeConfig{Readiness: ReadinessConfig{PostgreSQLRequired: true, PostgreSQLDSNEnv: "REL2_STAGE2_TEST_DSN"}}

	conn, err := NewReadinessConn(ctx, c)
	if err != nil {
		t.Fatalf("NewReadinessConn: %v", err)
	}
	if conn == nil {
		t.Fatal("NewReadinessConn returned a nil connection when PostgreSQL readiness is configured")
	}
	defer conn.Close(ctx)

	r := CheckRuntime(ctx, c, QuotaRegistry{}, conn)
	for _, chk := range r.Checks {
		if chk.Name == "postgresql" && chk.Status != "ok" {
			t.Fatalf("postgresql check failed against a real single connection: %s", chk.Detail)
		}
	}
}

func TestNewReadinessPoolNotRequiredReturnsNil(t *testing.T) {
	c := RuntimeConfig{Readiness: ReadinessConfig{PostgreSQLRequired: false}}
	pool, err := NewReadinessPool(context.Background(), c)
	if err != nil || pool != nil {
		t.Fatalf("NewReadinessPool = %v, %v; want nil, nil when PostgreSQL readiness is not required", pool, err)
	}
}

func TestNewReadinessConnNotRequiredReturnsNil(t *testing.T) {
	c := RuntimeConfig{Readiness: ReadinessConfig{PostgreSQLRequired: false}}
	conn, err := NewReadinessConn(context.Background(), c)
	if err != nil || conn != nil {
		t.Fatalf("NewReadinessConn = %v, %v; want nil, nil when PostgreSQL readiness is not required", conn, err)
	}
}

func TestNewReadinessPoolEmptyDSNErrors(t *testing.T) {
	t.Setenv("REL2_STAGE2_EMPTY_DSN", "")
	c := RuntimeConfig{Readiness: ReadinessConfig{PostgreSQLRequired: true, PostgreSQLDSNEnv: "REL2_STAGE2_EMPTY_DSN"}}
	if _, err := NewReadinessPool(context.Background(), c); err == nil {
		t.Fatal("expected an error when the named DSN environment variable is empty")
	}
}
