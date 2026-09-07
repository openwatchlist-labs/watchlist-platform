// ADR-0007 Addendum 10 D92/D95 test 6 (N-D, MEDIUM), rewritten by
// Addendum 11 D99 (O-B): the gate that is supposed to keep D77/D87's
// declared digests honest computed a digest, but derived its population
// from a HAND-LISTED set of three files (012, 008g, 020) rather than
// R35's own named mitigation ("extracts both bootstrap paths' literal
// function bodies from db/migrations/*.sql ... and asserts the declared
// set is exactly that set"). Measured at the tree D99 was written
// against: the committed literal set for screening_ledger_purge_snapshots
// is five (008g:1, 019:2, 020:2), the hand list covered two (020's), and
// CLAUDE.md's own named trap -- a hand-maintained enumeration silently
// drifting out of sync with the directory it describes -- is exactly
// what fired. Addendum 11 adds a sixth and seventh literal (021's two
// ALL-expired bodies, D98), which is what makes the population a moving
// target this gate must track by scan, not by list.
//
// This file derives its population from db/migrations/*.sql by directory
// glob -- the same one .github/workflows/ci.yml and run-ci.sh apply --
// plus SchemaSQL, for every declared function. Files are walked in the
// glob's own sorted order (the same lexical order the migration runner
// applies them in), and for a function with more than one CREATE [OR
// REPLACE] FUNCTION statement across that ordered population, the LAST
// one is the live body a fully-migrated database actually has -- exactly
// Postgres's own CREATE OR REPLACE semantics. The gate asserts that live
// literal's digest EQUALS the declared accepted digest for that
// bootstrap path (not merely that the accepted digest appears somewhere
// in history), which is what makes a new migration file that changes a
// declared function's body without updating the declared constant a gate
// failure -- with no edit to this file, since the file list is never
// named here.
//
// D99(b): every OTHER (non-live, historical) committed literal for a
// declared function must digest to something outside every declared
// accepted set for that function, so a superseded body (008g's original
// ON CONFLICT DO NOTHING form, or 020's now-superseded ANY-expired
// predicate) can never be silently readopted by a future edit that
// happens to reproduce it.
package screeningledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// extractedBody is one CREATE [OR REPLACE] FUNCTION statement's
// dollar-quoted body, found by scanning a source text (a migration
// file's full contents, or SchemaSQL) for a declared function name.
type extractedBody struct {
	source string // file path, or "SchemaSQL"
	args   string // the raw parameter-list text, for overload disambiguation
	body   string
}

var dollarTagRe = regexp.MustCompile(`^\s*(\$[A-Za-z0-9_]*\$)`)

// extractFunctionBodies scans source for every occurrence of "CREATE [OR
// REPLACE] FUNCTION <funcName>(...) ... AS <tag> <body> <tag>", in the
// order they appear, and returns each body found, tagged with
// sourceLabel and its raw parameter list (so a caller can disambiguate
// overloads sharing one name). None of the parameter lists or return
// types this repository ships contain a literal ")" before the argument
// list's own close, so the first ")" after the opening "(" is that
// close; none contain the literal substring "AS" before their own
// dollar-quote tag either.
func extractFunctionBodies(t *testing.T, source, sourceLabel, funcName string) []extractedBody {
	t.Helper()
	var results []extractedBody
	nameRe := regexp.MustCompile(`CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+` + regexp.QuoteMeta(funcName) + `\s*\(`)
	rest := source
	for {
		loc := nameRe.FindStringIndex(rest)
		if loc == nil {
			break
		}
		argsStart := loc[1]
		closeRel := strings.Index(rest[argsStart:], ")")
		if closeRel < 0 {
			t.Fatalf("%s: found %q with no closing ')' for its argument list", sourceLabel, funcName)
		}
		argsText := rest[argsStart : argsStart+closeRel]
		afterArgs := rest[argsStart+closeRel+1:]
		asIdx := strings.Index(afterArgs, "AS")
		if asIdx < 0 {
			t.Fatalf("%s: found %q with no 'AS' after its argument list", sourceLabel, funcName)
		}
		afterAS := afterArgs[asIdx+2:]
		tagMatch := dollarTagRe.FindStringSubmatch(afterAS)
		if tagMatch == nil {
			t.Fatalf("%s: found %q with no dollar-quote tag immediately after AS", sourceLabel, funcName)
		}
		tag := tagMatch[1]
		bodyStart := strings.Index(afterAS, tag) + len(tag)
		closeIdx := strings.Index(afterAS[bodyStart:], tag)
		if closeIdx < 0 {
			t.Fatalf("%s: found %q whose dollar-quote tag %s is never closed", sourceLabel, funcName, tag)
		}
		body := afterAS[bodyStart : bodyStart+closeIdx]
		results = append(results, extractedBody{source: sourceLabel, args: strings.TrimSpace(argsText), body: body})
		advance := argsStart + closeRel + 1 + asIdx + 2 + bodyStart + closeIdx + len(tag)
		rest = rest[advance:]
	}
	return results
}

func digestHexString(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// declaredFunction is one function (or one overload of a function that
// has more than one) this gate holds a declared, accepted digest for,
// per bootstrap path -- exactly one accepted digest per path, since that
// is the live body a fully-migrated or SchemaSQL-bootstrapped database
// actually has.
type declaredFunction struct {
	label             string // for failure messages
	funcName          string
	signatureContains string // "" if the function has only one overload; otherwise disambiguates which CREATE FUNCTION match is this overload
	acceptedMigration string
	acceptedSchemaSQL string
}

func declaredFunctions() []declaredFunction {
	return []declaredFunction{
		{
			label:    "owl_reject_truncate",
			funcName: "owl_reject_truncate",
			// ADR-0007 Addendum 9: owl_reject_truncate() has two
			// legitimate digests that differ by bootstrap PATH, not by
			// migration history -- a single declared value false-fails
			// whichever path it wasn't measured on. Both accepted values
			// are checked against BOTH derived populations below via
			// acceptEither.
		},
		{
			label:             "screening_ledger_reject_mutation",
			funcName:          "screening_ledger_reject_mutation",
			acceptedMigration: screeningLedgerRejectMutationBodySHA256,
			acceptedSchemaSQL: screeningLedgerRejectMutationBodySHA256,
		},
		{
			label:             "screening_ledger_purge_snapshots(timestamptz,...)",
			funcName:          "screening_ledger_purge_snapshots",
			signatureContains: "p_before timestamptz",
			acceptedMigration: purgeSnapshotsTimeFloorBodySHA256Migration,
			acceptedSchemaSQL: purgeSnapshotsTimeFloorBodySHA256SchemaSQLBoot,
		},
		{
			label:             "screening_ledger_purge_snapshots(text[],...)",
			funcName:          "screening_ledger_purge_snapshots",
			signatureContains: "p_snapshot_sha256 text[]",
			acceptedMigration: purgeSnapshotsArrayFormBodySHA256Migration,
			acceptedSchemaSQL: purgeSnapshotsArrayFormBodySHA256SchemaSQLBoot,
		},
	}
}

// migrationFilePaths glob-scans dir (the same glob shape
// .github/workflows/ci.yml's "Apply database migrations" step and
// run-ci.sh apply), sorted -- filepath.Glob already returns lexical
// order, which is migration application order for this repository's
// NNN_name.sql convention.
func migrationFilePaths(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no *.sql files found under %s -- glob is broken", dir)
	}
	return paths
}

// derivedPopulation returns every body extracted for this
// declaredFunction across migrationDir's *.sql files (in apply order)
// and SchemaSQL, each tagged with its source.
func (d declaredFunction) derivedPopulation(t *testing.T, migrationDir string) (migration []extractedBody, schemaSQL []extractedBody) {
	t.Helper()
	for _, path := range migrationFilePaths(t, migrationDir) {
		content := mustReadFile(t, path)
		for _, found := range extractFunctionBodies(t, content, path, d.funcName) {
			if d.signatureContains != "" && !strings.HasPrefix(found.args, d.signatureContains) {
				continue
			}
			migration = append(migration, found)
		}
	}
	for _, found := range extractFunctionBodies(t, SchemaSQL, "SchemaSQL", d.funcName) {
		if d.signatureContains != "" && !strings.HasPrefix(found.args, d.signatureContains) {
			continue
		}
		schemaSQL = append(schemaSQL, found)
	}
	return migration, schemaSQL
}

// checkLiveDigestMatchesAccepted asserts the LAST literal in migration
// (apply order) -- the one CREATE OR REPLACE FUNCTION actually leaves
// live -- digests to the declared accepted value, and does the same for
// the (necessarily singular) SchemaSQL literal. Returns a descriptive
// error rather than failing a *testing.T directly, so it can be run
// against a constructed directory in the required negative test without
// aborting that test's own goroutine.
func checkLiveDigestMatchesAccepted(t *testing.T, d declaredFunction, migrationDir string) error {
	t.Helper()
	migration, schemaSQL := d.derivedPopulation(t, migrationDir)
	if len(migration) == 0 {
		return fmt.Errorf("no committed literal found for %s across %s/*.sql", d.label, migrationDir)
	}
	if len(schemaSQL) == 0 {
		return fmt.Errorf("no committed literal found for %s in SchemaSQL", d.label)
	}
	liveMigration := migration[len(migration)-1]
	liveDigest := digestHexString(liveMigration.body)
	if d.acceptedMigration != "" && liveDigest != d.acceptedMigration {
		return fmt.Errorf("ADR-0007 Addendum 11 D99: %s's LIVE migration-path literal (last applied, in %s) digests to %s, which is not the declared accepted digest %s -- either the body changed without updating the declared constant, or an unaccounted-for migration file now runs last", d.label, liveMigration.source, liveDigest, d.acceptedMigration)
	}
	if len(schemaSQL) != 1 {
		return fmt.Errorf("expected exactly 1 SchemaSQL literal for %s, found %d", d.label, len(schemaSQL))
	}
	schemaDigest := digestHexString(schemaSQL[0].body)
	if d.acceptedSchemaSQL != "" && schemaDigest != d.acceptedSchemaSQL {
		return fmt.Errorf("ADR-0007 Addendum 11 D99: %s's SchemaSQL literal digests to %s, which is not the declared accepted digest %s", d.label, schemaDigest, d.acceptedSchemaSQL)
	}
	// owl_reject_truncate (D77/D79): both bootstrap paths may legitimately
	// carry EITHER of the two accepted digests (they diverge by which
	// path built them, not by which is "migration" vs "SchemaSQL"), so
	// for that one function the two acceptedMigration/acceptedSchemaSQL
	// fields above are left blank and this fallback checks membership in
	// owlRejectTruncateAcceptedBodySHA256 instead.
	if d.acceptedMigration == "" && d.acceptedSchemaSQL == "" {
		accepted := map[string]bool{}
		for _, a := range owlRejectTruncateAcceptedBodySHA256 {
			accepted[a] = true
		}
		if !accepted[liveDigest] {
			return fmt.Errorf("ADR-0007 Addendum 9: %s's LIVE migration-path literal digests to %s, not in the declared two-member accepted set %v", d.label, liveDigest, owlRejectTruncateAcceptedBodySHA256)
		}
		if !accepted[schemaDigest] {
			return fmt.Errorf("ADR-0007 Addendum 9: %s's SchemaSQL literal digests to %s, not in the declared two-member accepted set %v", d.label, schemaDigest, owlRejectTruncateAcceptedBodySHA256)
		}
	}
	return nil
}

// TestGuardAndDefinerBodyDigestsAreDerivedFromCommittedLiterals is D92's
// gate, D99's population: the LIVE literal on each bootstrap path -- the
// one a fully-migrated or SchemaSQL-bootstrapped database actually has --
// must digest to the declared accepted value, derived by scanning
// db/migrations/*.sql and SchemaSQL rather than a hand-picked file list.
// Runs with no DSN.
func TestGuardAndDefinerBodyDigestsAreDerivedFromCommittedLiterals(t *testing.T) {
	for _, d := range declaredFunctions() {
		t.Run(d.label, func(t *testing.T) {
			if err := checkLiveDigestMatchesAccepted(t, d, "../../db/migrations"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestSupersededPurgeSnapshotsLiteralsAreNotAccepted is D99(b)'s stronger
// property: every committed literal for a declared function which is NOT
// the live one must digest to something outside EVERY declared accepted
// digest for that function (both bootstrap paths) -- so a superseded
// body (008g's original ON CONFLICT DO NOTHING form, or 020's
// now-superseded ANY-expired predicate) can never be silently readopted,
// and a literal that drifts into agreement with an accepted digest fails
// the gate. 008g's own surviving ON CONFLICT ... DO NOTHING body
// (D99(c): left as committed history, not edited) is the case that
// exists today and is asserted here by derivation, not by naming the
// file.
func TestSupersededPurgeSnapshotsLiteralsAreNotAccepted(t *testing.T) {
	// D87/D86 row 8's own two constants, renamed rather than deleted:
	// 020's now-superseded ANY-expired bodies are pinned to their exact
	// measured digests, not merely asserted absent from the accepted
	// set -- the same "measured, not guessed" standard this file's other
	// constants already meet.
	knownSuperseded020 := map[string]string{
		"screening_ledger_purge_snapshots(timestamptz,...)": purgeSnapshotsTimeFloorBodySHA256Superseded020,
		"screening_ledger_purge_snapshots(text[],...)":      purgeSnapshotsArrayFormBodySHA256Superseded020,
	}
	for _, d := range declaredFunctions() {
		t.Run(d.label, func(t *testing.T) {
			if want, ok := knownSuperseded020[d.label]; ok {
				migration, _ := d.derivedPopulation(t, "../../db/migrations")
				found := false
				for _, got := range migration {
					if got.source == "../../db/migrations/020_screening_ledger_purge_server_side_floor.sql" && digestHexString(got.body) == want {
						found = true
					}
				}
				if !found {
					t.Fatalf("ADR-0007 Addendum 10 D87/D86 row 8: expected 020's own literal for %s to digest to the known superseded value %s", d.label, want)
				}
			}
			migration, schemaSQL := d.derivedPopulation(t, "../../db/migrations")
			accepted := map[string]bool{}
			if d.acceptedMigration != "" {
				accepted[d.acceptedMigration] = true
			}
			if d.acceptedSchemaSQL != "" {
				accepted[d.acceptedSchemaSQL] = true
			}
			for _, a := range owlRejectTruncateAcceptedBodySHA256 {
				accepted[a] = true // covers the owl_reject_truncate two-member case
			}
			liveMigrationIdx := len(migration) - 1
			for i, got := range migration {
				if i == liveMigrationIdx {
					continue // the live body -- expected to be accepted
				}
				digest := digestHexString(got.body)
				if accepted[digest] {
					t.Fatalf("ADR-0007 Addendum 11 D99: a superseded literal for %s in %s digests to %s, which IS a declared accepted digest -- a superseded body must not silently agree with the live one", d.label, got.source, digest)
				}
			}
			for _, got := range schemaSQL[:len(schemaSQL)-1] {
				digest := digestHexString(got.body)
				if accepted[digest] {
					t.Fatalf("ADR-0007 Addendum 11 D99: a superseded SchemaSQL literal for %s in %s digests to %s, which IS a declared accepted digest", d.label, got.source, digest)
				}
			}
		})
	}
}

// TestDigestGateCatchesWhitespaceAlteredCopy is D92/D95's own required
// negative: the gate must FAIL against a deliberately whitespace-altered
// copy of the live literal for each declared function, while the
// extraction marker still matches -- the exact two variants R35/D92's
// own measurement used (extra leading/trailing space inside the
// delimiters, a trailing newline added). A gate that cannot fail here is
// the shape D92 replaced.
func TestDigestGateCatchesWhitespaceAlteredCopy(t *testing.T) {
	for _, d := range declaredFunctions() {
		t.Run(d.label, func(t *testing.T) {
			migration, _ := d.derivedPopulation(t, "../../db/migrations")
			body := migration[len(migration)-1].body
			original := digestHexString(body)
			accepted := map[string]bool{}
			if d.acceptedMigration != "" {
				accepted[d.acceptedMigration] = true
			}
			for _, a := range owlRejectTruncateAcceptedBodySHA256 {
				accepted[a] = true
			}
			variants := map[string]string{
				"leading_and_trailing_space_doubled": "  " + body + "  ",
				"trailing_newline_added":             body + "\n",
			}
			for name, altered := range variants {
				if digestHexString(altered) == original {
					t.Fatalf("test bug: %s variant %q did not actually change the digest", d.label, name)
				}
				if accepted[digestHexString(altered)] {
					t.Fatalf("ADR-0007 Addendum 10 D92: %s variant %q unexpectedly matched a declared accepted digest -- the gate is not sensitive to whitespace", d.label, name)
				}
			}
		})
	}
}

// TestDigestGateCoversANewMigrationFileWithNoEdit is ADR-0007 Addendum 11
// D99/D103 test 7: the gate must FAIL if a new db/migrations/*.sql file
// introduces a literal for a declared function that no declared digest
// covers -- WITHOUT that file being named anywhere in this test. Built
// by copying the real db/migrations/ directory into a temp directory
// (never named beyond that copy) and appending one rogue file whose name
// sorts after every real migration, so it becomes the LIVE body under
// this gate's own "last in apply order wins" rule; the SAME
// checkLiveDigestMatchesAccepted the real gate above uses is run against
// that temp directory, not a hand-simulated shortcut.
func TestDigestGateCoversANewMigrationFileWithNoEdit(t *testing.T) {
	tempDir := t.TempDir()
	for _, path := range migrationFilePaths(t, "../../db/migrations") {
		content := mustReadFile(t, path)
		dest := filepath.Join(tempDir, filepath.Base(path))
		if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rogueBody := "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz, p_operator text, p_reason text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN 0; END; $$;\n"
	if err := os.WriteFile(filepath.Join(tempDir, "999_rogue_purge_snapshots.sql"), []byte(rogueBody), 0o644); err != nil {
		t.Fatal(err)
	}

	d := declaredFunctions()[2] // screening_ledger_purge_snapshots(timestamptz,...)
	if d.label != "screening_ledger_purge_snapshots(timestamptz,...)" {
		t.Fatalf("test construction error: wrong declaredFunctions() index")
	}
	err := checkLiveDigestMatchesAccepted(t, d, tempDir)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 11 D99/D103 test 7: expected the gate to FAIL once a new migration file changes the live body without updating the declared digest -- it passed instead")
	}
	if !strings.Contains(err.Error(), "999_rogue_purge_snapshots.sql") {
		t.Fatalf("expected the failure to name the rogue file as the new LIVE literal's source, got: %v", err)
	}

	// Positive control: the SAME temp-directory check, without the rogue
	// file, must still pass -- proving the failure above came from the
	// rogue file and not from copying the real tree into a temp dir.
	tempDirClean := t.TempDir()
	for _, path := range migrationFilePaths(t, "../../db/migrations") {
		content := mustReadFile(t, path)
		dest := filepath.Join(tempDirClean, filepath.Base(path))
		if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkLiveDigestMatchesAccepted(t, d, tempDirClean); err != nil {
		t.Fatalf("positive control: an unmodified copy of the real migrations directory must still pass the gate, got: %v", err)
	}
}
