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
// names the migration files that currently define each declared
// function's body. Those filenames have already moved three times
// (020->021->022->023/024) as screening_ledger_purge_snapshots's own body
// changed, and a document that names a superseded file installs a body
// grant-ddl-ownership's own D34 guard refuses -- leaving
// sec7_protect_ddl_objects_on_alter DISABLED, per the corrected procedure
// this test guards.
//
// This is DSN-free (D99's own directory-scan population pattern): it
// derives the CURRENT per-function defining file straight from
// db/migrations/*.sql, never from a hand-maintained list, so the next
// time any declared function's body moves to a new file this test fails
// rather than the document silently going stale.
//
// ADR-0007 Addendum 21 D172(2): the checked population widened from one
// hard-coded function name (screening_ledger_purge_snapshots) to the
// full declared function set (declaredFunctions(), after D170 adds
// screening_ledger_snapshot_guard) -- D99's own directory-scan
// discipline, applied to the function axis rather than the file axis, so
// this file needed no edit when D170 grew that set. A function is
// checked only if the document already names it by identifier (the
// document's own choice of what to discuss, not a second hard-coded
// list here); a declared function the document never mentions by name
// carries no filename claim for this test to go stale on.
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

	docPath := "../../docs/operations/sec7-database-copies.md"
	docRaw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(docRaw)

	arrayOverloadRe := regexp.MustCompile(`p_snapshot_sha256\s+text\s*\[\s*\]`)

	// funcNames is declaredFunctions()'s own distinct function-name
	// population (D170's own dispatch), deduplicated -- not a second,
	// separately maintained list. owl_reject_truncate is skipped: it is
	// not a screening-ledger-specific function this document discusses by
	// name (it protects eight unrelated tables too), and it has no
	// per-overload file-splitting history the way screening_ledger_purge_
	// snapshots does.
	seen := map[string]bool{}
	var funcNames []string
	for _, d := range declaredFunctions() {
		if d.funcName == "" || d.funcName == "owl_reject_truncate" || seen[d.funcName] {
			continue
		}
		seen[d.funcName] = true
		funcNames = append(funcNames, d.funcName)
	}
	sort.Strings(funcNames)

	checkedAny := false
	for _, funcName := range funcNames {
		if !strings.Contains(doc, funcName) {
			// This document never names this function by identifier, so
			// it makes no filename claim about it -- nothing to check.
			continue
		}
		funcRe := regexp.MustCompile(`(?is)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+` + regexp.QuoteMeta(funcName) + `\s*\(([^)]*)\)`)

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

		var currentFiles []string
		if currentArrayFile != "" {
			currentFiles = append(currentFiles, currentArrayFile)
		}
		if currentScalarFile != "" && currentScalarFile != currentArrayFile {
			currentFiles = append(currentFiles, currentScalarFile)
		}
		if len(currentFiles) == 0 {
			t.Fatalf("test construction bug: %s is named in %s but was not found defined in any db/migrations/*.sql file", funcName, docPath)
		}

		for _, want := range currentFiles {
			checkedAny = true
			if !strings.Contains(doc, want) {
				t.Fatalf("ADR-0007 Addendum 20 D155 / Addendum 21 D172(2): %s names %q as a function this document discusses, but its current defining file %q does not appear in %s at all -- the document has drifted from db/migrations/*.sql and must be corrected, not the other way around", docPath, funcName, want, docPath)
			}
		}
	}
	if !checkedAny {
		t.Fatalf("test construction bug: none of declaredFunctions()'s names (%v) were found mentioned in %s -- the document's own naming convention changed and this test's discovery step needs updating", funcNames, docPath)
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
