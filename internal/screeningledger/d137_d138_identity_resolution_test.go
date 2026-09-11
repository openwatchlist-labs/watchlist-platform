// ADR-0007 Addendum 16 D138: the required tests for D137's fix, in the
// order D138 lists them. Every test here fails against the shipped
// (pre-D137) extractFunctionBodies -- either because it returns the
// wrong count (tests 1-2), or because its signature was
// `[]extractedBody` with no error return at all, so the exotic-form
// rows of test 2 and the surfaced-failure assertions of test 3 could
// not even compile against it. DSN-free throughout (test 6 pins this
// explicitly), matching every other extractFunctionBodies-based test in
// this package.
package screeningledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// a16BuildDeclaration wraps a name production (bare, schema-qualified,
// quoted, commented, or an exotic form) in an otherwise-ordinary CREATE
// FUNCTION statement, so extractFunctionBodies is exercised against a
// realistic declaration and not just a bare name fragment.
func a16BuildDeclaration(qualifiedName string) string {
	return "CREATE OR REPLACE FUNCTION " + qualifiedName + "(p_x text) RETURNS text LANGUAGE plpgsql AS $$ BEGIN RETURN p_x; END; $$;\n"
}

// TestExtractFunctionBodiesResolvesSchemaQualifiedIdentity is D138 item
// 1: the H-A reproduction and the property the finding is about. Against
// the shipped (pre-D137) extractor this returns 1 for the bare control
// and 0 for the public.-qualified declaration (CAP #15's own measured
// transcript, independently reproduced in this addendum's design pass).
// After D137, both return 1 -- so this test distinguishes a working fix
// from one that still keys on a textual name.
func TestExtractFunctionBodiesResolvesSchemaQualifiedIdentity(t *testing.T) {
	bare := a16BuildDeclaration("screening_ledger_purge_snapshots")
	qualified := a16BuildDeclaration("public.screening_ledger_purge_snapshots")

	gotBare, err := extractFunctionBodies(t, bare, "probe-bare", "screening_ledger_purge_snapshots")
	if err != nil {
		t.Fatalf("unexpected error on the bare control: %v", err)
	}
	if len(gotBare) != 1 {
		t.Fatalf("ADR-0007 Addendum 16 D137/D138 test 1: expected 1 body for the bare control, got %d", len(gotBare))
	}

	gotQualified, err := extractFunctionBodies(t, qualified, "probe-qualified", "screening_ledger_purge_snapshots")
	if err != nil {
		t.Fatalf("unexpected error on the public.-qualified declaration: %v", err)
	}
	if len(gotQualified) != 1 {
		t.Fatalf("ADR-0007 Addendum 16 D137/D138 test 1 (CAP #15's H-A): expected the fixed extractor to resolve a public.-qualified declaration to 1 body (the shipped, pre-fix extractor returned 0 -- CAP #15's own measured transcript) -- got %d", len(gotQualified))
	}
}

// TestExtractFunctionBodiesSpellingMatrix is D138 item 2: the exhaustive
// spelling matrix, table-driven over every row ADR-0007 Addendum 16
// names -- eleven same-function spellings each finding exactly one
// body; the two genuinely-different functions (a different schema, a
// mixed-case quoted name) finding zero (correct exclusion, not a gap);
// and the two exotic U&-escaped forms (name, schema) producing a
// surfaced failure, never an invisible pass.
func TestExtractFunctionBodiesSpellingMatrix(t *testing.T) {
	const funcName = "screening_ledger_purge_snapshots"
	type row struct {
		name          string
		qualifiedName string
		wantFound     int
		wantErr       bool
	}
	rows := []row{
		// Eleven same-function spellings -- must each find exactly 1.
		{"bare", "screening_ledger_purge_snapshots", 1, false},
		{"public_dot_qualified", "public.screening_ledger_purge_snapshots", 1, false},
		{"PUBLIC_dot_qualified_folds", "PUBLIC.screening_ledger_purge_snapshots", 1, false},
		{"Public_dot_qualified_folds", "Public.screening_ledger_purge_snapshots", 1, false},
		{"quoted_schema_public_dot", `"public".screening_ledger_purge_snapshots`, 1, false},
		{"quoted_bare_name", `"screening_ledger_purge_snapshots"`, 1, false},
		{"quoted_schema_plus_quoted_name", `"public"."screening_ledger_purge_snapshots"`, 1, false},
		{"uppercase_bare_folds", "SCREENING_LEDGER_PURGE_SNAPSHOTS", 1, false},
		{"whitespace_around_dot", "public . screening_ledger_purge_snapshots", 1, false},
		{"block_comment_between_tokens", "public/* schema-qualifier */.screening_ledger_purge_snapshots", 1, false},
		{"line_comment_before_name", "public.-- the target function\n\tscreening_ledger_purge_snapshots", 1, false},
		// Two genuinely-different functions -- must each find 0, and
		// must NOT error (a resolved identity that simply is not this
		// declaration).
		{"other_schema_excluded", "myschema.screening_ledger_purge_snapshots", 0, false},
		{"quoted_mixed_case_excluded", `"Screening_Ledger_Purge_Snapshots"`, 0, false},
		// Two exotic forms -- must surface a failure, never an
		// invisible pass.
		{"unicode_escape_name_fails_closed", `public.U&"screening_ledger_purge_snapshots"`, 0, true},
		{"unicode_escape_schema_fails_closed", `U&"public".screening_ledger_purge_snapshots`, 0, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			source := a16BuildDeclaration(r.qualifiedName)
			bodies, err := extractFunctionBodies(t, source, r.name, funcName)
			if r.wantErr {
				if err == nil {
					t.Fatalf("ADR-0007 Addendum 16 D137/D138 test 2: expected a surfaced failure for %q, got %d body(ies) and no error", r.qualifiedName, len(bodies))
				}
				return
			}
			if err != nil {
				t.Fatalf("ADR-0007 Addendum 16 D137/D138 test 2: unexpected error for %q: %v", r.qualifiedName, err)
			}
			if len(bodies) != r.wantFound {
				t.Fatalf("ADR-0007 Addendum 16 D137/D138 test 2: %q: want %d body(ies), got %d", r.qualifiedName, r.wantFound, len(bodies))
			}
		})
	}
}

// a16RogueQualifiedArrayFormBody is a public.-qualified declaration of
// the LIVE array-form overload's own signature, carrying a body this
// repository never shipped -- the same shape as CAP #15's H-A and this
// addendum's own independently-reproduced live destructive demonstration.
const a16RogueQualifiedArrayFormBody = "CREATE OR REPLACE FUNCTION public.screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER AS $$ DECLARE recorded text[]; BEGIN WITH inserted AS (INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT snapshot_sha256, clock_timestamp(), p_operator, p_reason FROM screening_ledger_snapshot WHERE purged_at IS NULL RETURNING snapshot_sha256) SELECT array_agg(snapshot_sha256) INTO recorded FROM inserted; RETURN COALESCE(recorded, ARRAY[]::text[]); END; $$;\n"

// TestD137EndToEndGateBothBootstrapPathsBothPlacements is D138 item 3:
// a public.-qualified rogue placed in the real db/migrations/ (a file
// that sorts between two migrations, and one that sorts last) and in
// SchemaSQL via the schemaSQLOverride test hook, asserting the composed
// gate fails closed and names the rogue in every placement -- the
// property CAP #15 measured (the shipped extractor's blindness let this
// pass in full) and this fix inverts.
func TestD137EndToEndGateBothBootstrapPathsBothPlacements(t *testing.T) {
	placements := []string{"023a_a16_rogue.sql", "zzz999_a16_rogue.sql"}
	messages := map[string]string{}
	for _, filename := range placements {
		t.Run("migration_file/"+filename, func(t *testing.T) {
			tempDir := t.TempDir()
			a15CopyMigrationsInto(t, tempDir)
			roguePath := filepath.Join(tempDir, filename)
			if err := os.WriteFile(roguePath, []byte(a16RogueQualifiedArrayFormBody), 0o644); err != nil {
				t.Fatal(err)
			}

			// D132's own membership rule, widened by D133 to the full
			// bootstrap-path population: every committed literal must
			// digest to a declared member. The qualified rogue's body
			// is not one, in EITHER placement.
			err := assertEveryCommittedLiteralIsADeclaredBody(t, tempDir)
			if err == nil {
				t.Fatalf("ADR-0007 Addendum 16 D137/D138 test 3: expected the gate to FAIL closed against a public.-qualified rogue placed as %s -- it passed instead (CAP #15's H-A, now fixed)", filename)
			}
			if !strings.Contains(err.Error(), filename) {
				t.Fatalf("expected the failure to name %s, got: %v", filename, err)
			}
			messages[filename] = strings.Replace(err.Error(), roguePath, "<FILE>", 1)

			if filename == "zzz999_a16_rogue.sql" {
				// This placement sorts LAST, so it is also the LIVE
				// body under checkLiveDigestMatchesAccepted's own
				// "last applied wins" rule -- a second, independent
				// mechanism that must also refuse it.
				d := declaredFunctions()[3] // screening_ledger_purge_snapshots(p_snapshot_sha256 text[],...)
				if d.label != "screening_ledger_purge_snapshots(p_snapshot_sha256 text[],...)" {
					t.Fatalf("test construction error: wrong declaredFunctions() index")
				}
				if err := checkLiveDigestMatchesAccepted(t, d, tempDir); err == nil {
					t.Fatal("ADR-0007 Addendum 16 D137/D138 test 3: expected checkLiveDigestMatchesAccepted to ALSO fail once the qualified rogue is the last-sorting, live migration-path body")
				}
			}
		})
	}
	if messages[placements[0]] != messages[placements[1]] {
		t.Fatalf("D42: the two failure messages must differ ONLY in the filename each names (sort order must not appear in the rule) -- got:\n  %s: %s\n  %s: %s", placements[0], messages[placements[0]], placements[1], messages[placements[1]])
	}

	t.Run("schemaSQL_override_hook", func(t *testing.T) {
		// assertNoBodyDropped places the qualified rogue correctly (its
		// type list matches the live array-form overload exactly, so
		// it is neither a retired signature nor an unmapped synonym --
		// D133's own scope). What D137 changes is that the body is now
		// FOUND at all inside SchemaSQL -- confirmed by
		// assertEveryCommittedLiteralIsADeclaredBody's digest
		// comparison over the SAME, D133-widened population, which must
		// refuse it.
		if err := assertNoBodyDropped(t, "../../db/migrations", a16RogueQualifiedArrayFormBody); err != nil {
			t.Fatalf("unexpected: assertNoBodyDropped should place (not refuse) a live-signature body: %v", err)
		}
		err := assertEveryCommittedLiteralIsADeclaredBody(t, "../../db/migrations", a16RogueQualifiedArrayFormBody)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 16 D137/D138 test 3: expected the gate to FAIL closed against a public.-qualified rogue placed inside SchemaSQL via the schemaSQLOverride hook -- it passed instead")
		}
		if !strings.Contains(err.Error(), "SchemaSQL") {
			t.Fatalf("expected the failure to name SchemaSQL, got: %v", err)
		}
	})
}

// TestD137PositiveControlRealTreeAllDeclarationsFound is D138 item 4,
// D37's own shipping requirement (0007:2643-2645) restated: the
// unmodified db/migrations/ and SchemaSQL tree must pass ALL of this
// package's gate functions with the fixed extractor, for every
// declaredFunctions() entry, including every SchemaSQL declaration
// inside its EXECUTE $exec$...$exec$ block. A fix that finds the rogue
// but drops a real body passes its own suite and must not be accepted
// as done -- this is the test that would catch that.
func TestD137PositiveControlRealTreeAllDeclarationsFound(t *testing.T) {
	for _, d := range declaredFunctions() {
		t.Run(d.label, func(t *testing.T) {
			if err := checkLiveDigestMatchesAccepted(t, d, "../../db/migrations"); err != nil {
				t.Fatalf("D137/D138 item 4: %v", err)
			}
		})
	}
	if err := assertNoBodyDropped(t, "../../db/migrations"); err != nil {
		t.Fatalf("D137/D138 item 4: %v", err)
	}
	if err := assertEveryCommittedLiteralIsADeclaredBody(t, "../../db/migrations"); err != nil {
		t.Fatalf("D137/D138 item 4: %v", err)
	}

	// Every SchemaSQL declaration lives inside EXECUTE
	// $exec$...$exec$ (postgres.go:2010/2047/2121/2122) -- confirm the
	// fixed extractor's kept flat scan still finds every one of them.
	for _, name := range []string{"screening_ledger_reject_mutation", "owl_reject_truncate", "screening_ledger_purge_snapshots"} {
		bodies, err := extractFunctionBodies(t, SchemaSQL, "SchemaSQL", name)
		if err != nil {
			t.Fatalf("D137/D138 item 4: %s: %v", name, err)
		}
		if len(bodies) == 0 {
			t.Fatalf("D137/D138 item 4: expected at least 1 SchemaSQL body for %s (inside EXECUTE $exec$...$exec$), found 0", name)
		}
	}
}

// TestExtractFunctionBodiesSkipsCommentProseMentionRatherThanFailing is
// D138 item 5: the comment discriminator, pinned. db/migrations/020:165
// contains "-- point and CREATE OR REPLACE FUNCTION succeeds without a
// preceding" -- the resolved name "succeeds" is a legitimate identifier
// not followed by "(", so it must be SKIPPED, not failed. Also pins the
// narrower case D137(b) actually decides: a resolved name that DOES
// match funcName but is not immediately followed by "(" is likewise a
// skip, not a failure -- proving name-then-"(" (not name alone) is the
// discriminator.
func TestExtractFunctionBodiesSkipsCommentProseMentionRatherThanFailing(t *testing.T) {
	content := mustReadFile(t, "../../db/migrations/020_screening_ledger_purge_server_side_floor.sql")
	if !strings.Contains(content, "CREATE OR REPLACE FUNCTION succeeds without a preceding") {
		t.Fatal("test construction error: the 020:165 comment shape this test pins is no longer present verbatim -- update the fixture or this test")
	}
	if _, err := extractFunctionBodies(t, content, "020", "screening_ledger_purge_snapshots"); err != nil {
		t.Fatalf("D137(b): expected the fixed extractor to SKIP the 020:165 prose mention rather than fail on it, got: %v", err)
	}

	prose := "-- see CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots succeeds without a preceding call\n"
	bodies, err := extractFunctionBodies(t, prose, "prose-probe", "screening_ledger_purge_snapshots")
	if err != nil {
		t.Fatalf("D137(b): expected a resolved name-then-not-'(' prose mention (matching funcName itself) to be SKIPPED, not a surfaced failure, got: %v", err)
	}
	if len(bodies) != 0 {
		t.Fatalf("expected 0 bodies from a prose mention, got %d", len(bodies))
	}
}

// TestExtractFunctionBodiesRunsWithNoDSN is D138 item 6, D92's own
// property (0007:9484-9486): this gate runs with no database connection.
// Confirmed directly -- every OWL_*_DATABASE_URL and every libpq PG*
// variable this repository's gates read is unset for the duration of
// this test, and the fixed extractor and the gate functions built on it
// still find every real declaration and pass.
func TestExtractFunctionBodiesRunsWithNoDSN(t *testing.T) {
	for _, ev := range []string{
		"OWL_TEST_DATABASE_URL", "OWL_MIGRATOR_DATABASE_URL", "OWL_LEDGER_ANCHOR_DATABASE_URL",
		"OWL_LEDGER_DDL_DATABASE_URL", "OWL_BOOTSTRAP_SUPERUSER_DATABASE_URL",
		"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD",
	} {
		old, had := os.LookupEnv(ev)
		os.Unsetenv(ev)
		if had {
			ev, old := ev, old
			t.Cleanup(func() { os.Setenv(ev, old) })
		}
	}
	if err := assertEveryCommittedLiteralIsADeclaredBody(t, "../../db/migrations"); err != nil {
		t.Fatalf("D138 item 6: expected the gate to run with zero DSN and pass against the real tree, got: %v", err)
	}
	if _, err := extractFunctionBodies(t, SchemaSQL, "SchemaSQL", "owl_reject_truncate"); err != nil {
		t.Fatalf("D138 item 6: %v", err)
	}
}
