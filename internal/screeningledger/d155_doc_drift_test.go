package screeningledger

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestSEC7DatabaseCopiesDocNamesCurrentPurgeMigrationFiles is ADR-0007
// Addendum 20 D155's drift-proofing half: docs/operations/sec7-database-copies.md
// names the two migration files that currently define each
// screening_ledger_purge_snapshots overload's body. Those filenames have
// already moved three times (020->021->022->023/024) as the function's
// body changed, and a document that names a superseded file installs a
// body grant-ddl-ownership's own D34 guard refuses -- leaving
// sec7_protect_ddl_objects_on_alter DISABLED, per the corrected procedure
// this test guards.
//
// This is DSN-free (D99's own directory-scan population pattern): it
// derives the CURRENT per-overload defining file straight from
// db/migrations/*.sql, never from a hand-maintained list, so the next
// time either overload's body moves to a new file this test fails rather
// than the document silently going stale.
func TestSEC7DatabaseCopiesDocNamesCurrentPurgeMigrationFiles(t *testing.T) {
	migrationsDir := "../../db/migrations"
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // migration order: numeric-prefixed filenames sort correctly as strings.

	// Matches `CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(<params>)`.
	// (?s) so the parameter list can span lines.
	funcRe := regexp.MustCompile(`(?is)CREATE\s+OR\s+REPLACE\s+FUNCTION\s+screening_ledger_purge_snapshots\s*\(([^)]*)\)`)
	arrayOverloadRe := regexp.MustCompile(`p_snapshot_sha256\s+text\s*\[\s*\]`)

	currentArrayFile := ""
	currentScalarFile := ""
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range funcRe.FindAllStringSubmatch(string(raw), -1) {
			params := match[1]
			if arrayOverloadRe.MatchString(params) {
				currentArrayFile = name
			} else {
				currentScalarFile = name
			}
		}
	}
	if currentArrayFile == "" || currentScalarFile == "" {
		t.Fatalf("test construction bug: expected to find both screening_ledger_purge_snapshots overloads across db/migrations/*.sql, got array=%q scalar=%q", currentArrayFile, currentScalarFile)
	}
	if currentArrayFile == currentScalarFile {
		t.Fatalf("test construction bug: array and scalar overloads resolved to the same file %q -- the classification regex is not distinguishing them", currentArrayFile)
	}

	docPath := "../../docs/operations/sec7-database-copies.md"
	docRaw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(docRaw)
	for _, want := range []string{currentArrayFile, currentScalarFile} {
		if !strings.Contains(doc, want) {
			t.Fatalf("ADR-0007 Addendum 20 D155: %s names %q as one of the two current screening_ledger_purge_snapshots migration files, but that filename does not appear in %s at all -- the document has drifted from db/migrations/*.sql and must be corrected, not the other way around", docPath, want, docPath)
		}
	}
	// The document must NOT still instruct an operator to run the previous
	// single-file pointer this addendum's own reproduction showed installs
	// a superseded body for at least one overload. A bare mention of the
	// filename in explanatory prose (recounting that it used to be the
	// pointer, and why that was wrong) is not itself the defect; an
	// executable `-f db/migrations/022...` line is.
	if regexp.MustCompile(`-f\s+db/migrations/022_screening_ledger_purge_chain_corroboration\.sql`).MatchString(doc) {
		t.Fatalf("ADR-0007 Addendum 20 D155: %s still instructs applying the superseded single-file pointer 022_screening_ledger_purge_chain_corroboration.sql, which installs a stale body for at least one overload", docPath)
	}
}
