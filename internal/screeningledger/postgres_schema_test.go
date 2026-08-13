package screeningledger

import (
	"strings"
	"testing"
)

// TestSchemaSQLCarriesTruncateGuards is REL-9-adjacent, found while
// implementing SEC-7 Stage 2 (ADR-0007 D3): SchemaSQL independently
// bootstraps screening_ledger_event, screening_ledger_snapshot,
// screening_ledger_replication, screening_idempotency_receipt,
// screening_ledger_retention_tombstone, watchlist_operational_audit, and
// screening_ledger_audit via Migrate(), called from every CLI invocation
// (cmd/screening-ledger/main.go) and from this package's own pgx test
// suite (postgres_pgx_test.go) -- with zero dependency on db/migrations/
// ever having run. db/migrations/012_truncate_guards.sql already added a
// BEFORE TRUNCATE guard to all seven of those tables, but SchemaSQL never
// did, so any bootstrap that reaches Migrate() without db/migrations/
// having run first ends up with a TRUNCATE guard silently absent -- the
// same silent-absence bug class CLAUDE.md exists to catch. This asserts
// SchemaSQL carries the same owl_reject_truncate() trigger migration 012
// established, so the two sources cannot diverge on this control again
// without this test catching it.
func TestSchemaSQLCarriesTruncateGuards(t *testing.T) {
	protectedTables := []string{
		"screening_ledger_event",
		"screening_ledger_snapshot",
		"screening_ledger_replication",
		"screening_idempotency_receipt",
		"screening_ledger_retention_tombstone",
		"watchlist_operational_audit",
		"screening_ledger_audit",
	}
	if !strings.Contains(SchemaSQL, "owl_reject_truncate") {
		t.Fatal("SchemaSQL does not define or use owl_reject_truncate()")
	}
	for _, table := range protectedTables {
		marker := "BEFORE TRUNCATE ON " + table + " FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate()"
		if !strings.Contains(SchemaSQL, marker) {
			t.Fatalf("SchemaSQL is missing a BEFORE TRUNCATE guard on %s", table)
		}
	}
}
