package assistancerag

import (
	"strings"
	"testing"
)

// TestSchemaSQLCarriesTruncateGuards is the SEC-2 followup found during
// the Sprint 0 register reconciliation: SchemaSQL independently
// bootstraps these five tables via Migrate(), with no dependency on
// db/migrations/ ever having run (the same REL-9-adjacent shape
// ADR-0007 D3/D15 already found and fixed in screeningledger's own
// SchemaSQL -- see internal/screeningledger/postgres_schema_test.go).
// db/migrations/012_truncate_guards.sql already guards these same five
// relations, but SchemaSQL used to carry zero BEFORE TRUNCATE guards, so
// any bootstrap that reached Migrate() without db/migrations/ having run
// first left every one of them silently truncatable. This is the fast,
// no-database regression guard for that gap; internal/schemasqlgate's
// pgx suite is the live-Postgres empirical proof.
func TestSchemaSQLCarriesTruncateGuards(t *testing.T) {
	protectedTables := []string{
		"rag_corpus_snapshot",
		"case_assistance_record",
		"case_assistance_review",
		"case_assistance_idempotency",
		"case_assistance_audit",
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
