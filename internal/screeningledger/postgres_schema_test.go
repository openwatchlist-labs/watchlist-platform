package screeningledger

import (
	"strings"
	"testing"
)

// TestSchemaSQLCarriesTruncateGuards is REL-9-adjacent, found while
// implementing SEC-7 Stage 2 (ADR-0007 D3): SchemaSQL independently
// bootstraps screening_ledger_event, screening_ledger_snapshot,
// screening_ledger_replication, screening_idempotency_receipt,
// screening_ledger_retention_tombstone, watchlist_operational_audit,
// screening_ledger_audit, and (Addendum 1 D15) screening_ledger_anchor
// via Migrate(), called from every CLI invocation
// (cmd/screening-ledger/main.go) and from this package's own pgx test
// suite (postgres_pgx_test.go) -- with zero dependency on db/migrations/
// ever having run. db/migrations/012_truncate_guards.sql (and, for the
// anchor table, 015/017) already added a BEFORE TRUNCATE guard to all
// eight of those tables, but SchemaSQL used to lag behind (F3: it never
// created the anchor table at all), so any bootstrap that reaches
// Migrate() without db/migrations/ having run first could end up with a
// control silently absent -- the same silent-absence bug class
// CLAUDE.md exists to catch. This asserts SchemaSQL carries the same
// owl_reject_truncate() trigger migration 012/015 established, so the
// two sources cannot diverge on this control again without this test
// catching it.
func TestSchemaSQLCarriesTruncateGuards(t *testing.T) {
	protectedTables := []string{
		"screening_ledger_event",
		"screening_ledger_snapshot",
		"screening_ledger_replication",
		"screening_idempotency_receipt",
		"screening_ledger_retention_tombstone",
		"watchlist_operational_audit",
		"screening_ledger_audit",
		"screening_ledger_anchor",
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

// TestSchemaSQLAnchorTableHasImmutabilityTrigger is ADR-0007 Addendum 1
// D15/D16/F7: the anchor table historically had only the TRUNCATE guard
// (015:48-49) while every other protected table had both a TRUNCATE
// guard and a row-immutability trigger since 012. Asserting only the
// TRUNCATE marker (as TestSchemaSQLCarriesTruncateGuards does, for all
// eight tables including this one) would not have caught F7 -- this
// checks the row-immutability trigger specifically, per D15's own text
// ("the same test asserts the row-immutability trigger, not only the
// TRUNCATE guard").
func TestSchemaSQLAnchorTableHasImmutabilityTrigger(t *testing.T) {
	marker := "BEFORE UPDATE OR DELETE ON screening_ledger_anchor FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation()"
	if !strings.Contains(SchemaSQL, marker) {
		t.Fatal("SchemaSQL is missing a row-immutability (BEFORE UPDATE OR DELETE) trigger on screening_ledger_anchor (ADR-0007 D16/F7)")
	}
}

// TestRequiredSchemaObjectsMatchProtectedTables is ADR-0007 Addendum 2
// D21: postgres.go's requiredSchemaObjects (Migrate()'s live-database
// postcondition check) and this file's protectedTables (SchemaSQL's own
// text) are two separately hand-written enumerations of the same
// eight-table set, per CLAUDE.md's "never enumerate targets by
// inference." This is the guard that keeps them from silently
// drifting apart -- a table present in one list and not the other is
// exactly the kind of gap that class of bug hides in.
func TestRequiredSchemaObjectsMatchProtectedTables(t *testing.T) {
	protectedTables := []string{
		"screening_ledger_event",
		"screening_ledger_snapshot",
		"screening_ledger_replication",
		"screening_idempotency_receipt",
		"screening_ledger_retention_tombstone",
		"watchlist_operational_audit",
		"screening_ledger_audit",
		"screening_ledger_anchor",
	}
	if len(requiredSchemaObjects) != len(protectedTables) {
		t.Fatalf("requiredSchemaObjects has %d entries, protectedTables has %d -- they must name the same tables", len(requiredSchemaObjects), len(protectedTables))
	}
	for i, table := range protectedTables {
		if requiredSchemaObjects[i].table != table {
			t.Fatalf("requiredSchemaObjects[%d] = %q, protectedTables[%d] = %q -- the two enumerations have drifted apart", i, requiredSchemaObjects[i].table, i, table)
		}
	}
}
