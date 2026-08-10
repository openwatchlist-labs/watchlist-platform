// Package tenantsql is the single seam through which SQL touching a
// tenant-scoped relation reaches a command runner (ADR-0001 SEC-1, §3). It
// owns the transaction envelope -- BEGIN, the tenant GUC, COMMIT -- and is
// the only place allowed to spell an INSERT against a tenant-scoped
// relation: sinks describe what to write as data (table name, columns),
// this package writes the SQL text. That split is what lets
// scripts/ci/check_tenant_binding.py reduce to a lexical scan: after this
// package exists, the literal "INSERT INTO <tenant-table>" text cannot
// appear anywhere else in the tree.
package tenantsql

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
)

// Bound is proof that a SQL statement is about to run inside a transaction
// with the tenant GUC already set. The concrete type implementing it is
// unexported, so no package outside tenantsql can construct one -- a
// sink's run()/Run() helper that requires a Bound cannot be called except
// through WithTenant.
type Bound interface{ boundToTenant() }

type bound struct{}

func (bound) boundToTenant() {}

// Runner is the shape every sink's psql-invocation helper implements:
// execute a batch of SQL statements, given proof that they are bound.
type Runner func(ctx context.Context, proof Bound, sql string) error

// WithTenant wraps body in
//
//	BEGIN;
//	SELECT set_config('openwatchlist.tenant_id', <hex-encoded tenant literal>, true);
//	<body>
//	COMMIT;
//
// and hands the wrapped statement to exec along with proof that binding
// happened. set_config(..., true) is used rather than SET LOCAL so the
// tenant reuses the existing sqlText() hex-encoding idiom
// (internal/screeningledger/postgres.go:90-92) instead of being
// interpolated as a literal/identifier.
func WithTenant(ctx context.Context, tenant tenantctx.Tenant, body string, exec Runner) error {
	wrapped := "BEGIN;\n" +
		"SELECT set_config('openwatchlist.tenant_id'," + sqlText(tenant.String()) + ",true);\n" +
		body +
		"COMMIT;\n"
	return exec(ctx, bound{}, wrapped)
}

// Col is a single column/value pair for an INSERT built against a
// tenant-scoped relation. SQL is a pre-encoded expression -- from
// sqlText()/sqlJSON() or a bare literal like a cast expression -- never
// raw caller-controlled text.
type Col struct {
	Name string
	SQL  string
}

// Insert assembles "INSERT INTO <table>(<cols>) VALUES (<vals>) <conflict>;\n".
// table is a runtime value, not a literal baked in alongside the verb, so
// callers pass table names as data.
func Insert(table string, cols []Col, conflict string) string {
	names := make([]string, len(cols))
	vals := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name
		vals[i] = c.SQL
	}
	sql := "INSERT INTO " + table + "(" + strings.Join(names, ",") + ") VALUES (" + strings.Join(vals, ",") + ")"
	if conflict != "" {
		sql += " " + conflict
	}
	return sql + ";\n"
}

func sqlText(v string) string {
	return "convert_from(decode('" + hex.EncodeToString([]byte(v)) + "','hex'),'UTF8')"
}
