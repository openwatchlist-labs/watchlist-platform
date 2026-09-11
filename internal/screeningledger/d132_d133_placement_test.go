// ADR-0007 Addendum 15 D132/D133/D136 test file (CAP #14 remediation,
// second pass). CAP #14's G-A found that a superseded literal of a LIVE
// signature is never digest-compared, only placed -- D99(b)'s own
// assertion is negative (a non-live literal must digest to something
// OUTSIDE the accepted set) and is satisfied for free by a body this
// repository never shipped. This addendum's own sweep found the same
// defect one source over: SchemaSQL is a live bootstrap path
// assertNoBodyDropped never scanned at all. D132 supplies the missing
// digest comparison on a placed body; D133 supplies the missing
// placement on a whole source. Neither closes the other -- see
// TestD132MembershipRuleAloneDoesNotCatchTheSchemaSQLRogue below, which
// pins that fact so a later round cannot collapse the two mechanisms.
// DSN-free throughout, like every other assertNoBodyDropped/
// checkLiveDigestMatchesAccepted test in this package.
//
// Every SchemaSQL-rogue reproduction below uses derivedPopulation's and
// assertNoBodyDropped's schemaSQLOverride test hook rather than mutating
// the real, package-level SchemaSQL constant: the same extraction,
// classification and (for D132) digest-comparison code runs against
// SchemaSQL-shaped content carrying the rogue, labeled "SchemaSQL" in
// every failure message, without ever touching the live constant other
// tests and production code depend on.
package screeningledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// a15RogueArrayFormBody is ADR-0007 Addendum 15 G-A's own construction:
// a SECURITY DEFINER body carrying the CURRENT, live array-form type
// list that ignores every argument except p_operator/p_reason, tombstones
// every unpurged snapshot and strips its ciphertext -- no = ANY, no
// expiry test, no corroboration.
const a15RogueArrayFormBody = "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER AS $$ DECLARE recorded text[]; BEGIN WITH inserted AS (INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT snapshot_sha256, clock_timestamp(), p_operator, p_reason FROM screening_ledger_snapshot WHERE purged_at IS NULL RETURNING snapshot_sha256) SELECT array_agg(snapshot_sha256) INTO recorded FROM inserted; RETURN COALESCE(recorded, ARRAY[]::text[]); END; $$;\n"

// a15RogueRetiredTimeFloorBody is D133's first SchemaSQL rogue class: a
// resurrected retired signature (type list "timestamptz,text,text")
// carrying a body this repository never shipped under it.
const a15RogueRetiredTimeFloorBody = "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz, p_operator text, p_reason text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $$ DECLARE affected bigint; BEGIN INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT snapshot_sha256, clock_timestamp(), p_operator, p_reason FROM screening_ledger_snapshot WHERE purged_at IS NULL; GET DIAGNOSTICS affected = ROW_COUNT; RETURN affected; END; $$;\n"

// a15RogueUnmappedSynonymBody is D133's second SchemaSQL rogue class: a
// schema-qualified spelling (pg_catalog.text[]) typeSpellingAliases does
// not map -- the same synonym TestAssertNoBodyDroppedCatchesUnmappedSynonym
// itself uses for the migration-file case.
const a15RogueUnmappedSynonymBody = "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 pg_catalog.text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN ARRAY[]::text[]; END; $$;\n"

func a15CopyMigrationsInto(t *testing.T, dir string) {
	t.Helper()
	for _, path := range migrationFilePaths(t, "../../db/migrations") {
		content := mustReadFile(t, path)
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(path)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestEveryCommittedLiteralIsADeclaredBody is D136 item 1: D132's own
// required reproduction, table-driven over BOTH rogue placements CAP
// #14's G-A measured -- a file sorting between 023 and 024 (which the
// shipped gate passes in full: the finding), and one sorting last (which
// the shipped gate partially, and misleadingly, catches via two
// collateral failures naming the wrong file, per drift note 2). Both
// must FAIL under assertEveryCommittedLiteralIsADeclaredBody, and their
// two failure messages must differ ONLY in the filename each names --
// proving detection is a property of what is declared and what is live,
// not of sort order.
func TestEveryCommittedLiteralIsADeclaredBody(t *testing.T) {
	t.Run("positive_control_clean_tree", func(t *testing.T) {
		if err := assertEveryCommittedLiteralIsADeclaredBody(t, "../../db/migrations"); err != nil {
			t.Fatalf("D37: the unmodified tree must pass -- a gate that only refuses has not been shown safe to install: %v", err)
		}
	})

	placements := []string{"023a_rogue.sql", "zzz999_rogue.sql"}
	messages := map[string]string{}
	for _, filename := range placements {
		t.Run(filename, func(t *testing.T) {
			tempDir := t.TempDir()
			a15CopyMigrationsInto(t, tempDir)
			rogueFile := filepath.Join(tempDir, filename)
			if err := os.WriteFile(rogueFile, []byte(a15RogueArrayFormBody), 0o644); err != nil {
				t.Fatal(err)
			}
			err := assertEveryCommittedLiteralIsADeclaredBody(t, tempDir)
			if err == nil {
				t.Fatalf("ADR-0007 Addendum 15 D132: expected the gate to FAIL against a superseded literal of a LIVE signature placed as %s -- it passed instead (CAP #14 G-A)", filename)
			}
			if !strings.Contains(err.Error(), filename) {
				t.Fatalf("expected the failure to name %s, got: %v", filename, err)
			}
			// Normalize away the temp directory's own path (which differs
			// per subtest -- t.TempDir() embeds the subtest name) so only
			// the ROGUE FILENAME itself is masked, isolating whether the
			// two messages differ in anything beyond that.
			messages[filename] = strings.Replace(err.Error(), rogueFile, "<FILE>", 1)
		})
	}
	if messages[placements[0]] != messages[placements[1]] {
		t.Fatalf("D42: the two failure messages must differ ONLY in the filename each names (sort order must not appear in the rule) -- got:\n  %s: %s\n  %s: %s", placements[0], messages[placements[0]], placements[1], messages[placements[1]])
	}
}

// TestEveryCommittedLiteralIsADeclaredBodyAppliesToEveryEntry is D136
// item 2 (D132(b)'s own whole-round half, a separate assertion and not a
// corollary of the array-form reproduction above): the SAME rogue
// construction against the TIME-FLOOR overload (whose own superseded
// 022 literal drift note 1 found, unenumerated by any CAP) and against
// owl_reject_truncate (placed unconditionally, typeList == "", at
// declaredFunctions()'s own dispatch). Both must fail after -- proving
// D132 is not applied to only the one overload CAP #14 demonstrated.
func TestEveryCommittedLiteralIsADeclaredBodyAppliesToEveryEntry(t *testing.T) {
	t.Run("time_floor_overload", func(t *testing.T) {
		tempDir := t.TempDir()
		a15CopyMigrationsInto(t, tempDir)
		rogue := "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_ledger_id text, p_expected_count bigint, p_expected_max timestamptz, p_operator text, p_reason text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN 0; END; $$;\n"
		if err := os.WriteFile(filepath.Join(tempDir, "023a_rogue_timefloor.sql"), []byte(rogue), 0o644); err != nil {
			t.Fatal(err)
		}
		err := assertEveryCommittedLiteralIsADeclaredBody(t, tempDir)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 15 D132(b): expected the gate to FAIL against a superseded literal of the TIME-FLOOR overload -- it passed instead (drift note 1: this overload's own history was unenumerated by every CAP)")
		}
		if !strings.Contains(err.Error(), "023a_rogue_timefloor.sql") {
			t.Fatalf("expected the failure to name the file, got: %v", err)
		}
	})

	t.Run("owl_reject_truncate_unconditionally_placed", func(t *testing.T) {
		tempDir := t.TempDir()
		a15CopyMigrationsInto(t, tempDir)
		rogue := "CREATE OR REPLACE FUNCTION owl_reject_truncate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$;\n"
		if err := os.WriteFile(filepath.Join(tempDir, "023a_rogue_owlreject.sql"), []byte(rogue), 0o644); err != nil {
			t.Fatal(err)
		}
		err := assertEveryCommittedLiteralIsADeclaredBody(t, tempDir)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 15 D132(b): expected the gate to FAIL against a superseded literal of owl_reject_truncate() -- it passed instead (typeList==\"\" places any body under this name unconditionally, and this addendum's own membership rule must still range over that population)")
		}
		if !strings.Contains(err.Error(), "023a_rogue_owlreject.sql") {
			t.Fatalf("expected the failure to name the file, got: %v", err)
		}
	})

	// D132(b)'s own text names BOTH unconditionally-placed functions
	// ("owl_reject_truncate and screening_ledger_reject_mutation are
	// placed at :471-475 by d.typeList == "" matching unconditionally")
	// -- this is the second, not a corollary of the first.
	t.Run("screening_ledger_reject_mutation_unconditionally_placed", func(t *testing.T) {
		tempDir := t.TempDir()
		a15CopyMigrationsInto(t, tempDir)
		rogue := "CREATE OR REPLACE FUNCTION screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$;\n"
		if err := os.WriteFile(filepath.Join(tempDir, "023a_rogue_rejectmutation.sql"), []byte(rogue), 0o644); err != nil {
			t.Fatal(err)
		}
		err := assertEveryCommittedLiteralIsADeclaredBody(t, tempDir)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 15 D132(b): expected the gate to FAIL against a superseded literal of screening_ledger_reject_mutation() -- it passed instead")
		}
		if !strings.Contains(err.Error(), "023a_rogue_rejectmutation.sql") {
			t.Fatalf("expected the failure to name the file, got: %v", err)
		}
	})
}

// TestAssertNoBodyDroppedCatchesRogueInsideSchemaSQL is D136 item 4:
// D133's own required reproduction, BOTH rogue classes, "inside
// SchemaSQL" via the schemaSQLOverride test hook (documented at this
// file's top) -- PLUS the positive control, run against the REAL,
// unmodified SchemaSQL (no override), proving assertNoBodyDropped's own
// default behaviour places every body in the live constant.
func TestAssertNoBodyDroppedCatchesRogueInsideSchemaSQL(t *testing.T) {
	t.Run("positive_control_clean_SchemaSQL", func(t *testing.T) {
		if err := assertNoBodyDropped(t, "../../db/migrations"); err != nil {
			t.Fatalf("D37: the unmodified SchemaSQL (scanned alongside the real db/migrations tree, no override) must pass: %v", err)
		}
	})

	t.Run("resurrected_retired_time_floor_signature", func(t *testing.T) {
		err := assertNoBodyDropped(t, "../../db/migrations", a15RogueRetiredTimeFloorBody)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 15 D133: expected the gate to FAIL against a resurrected retired signature inside SchemaSQL -- it passed instead")
		}
		if !strings.Contains(err.Error(), "SchemaSQL") || !strings.Contains(err.Error(), "timestamptz,text,text") {
			t.Fatalf("expected the failure to name SchemaSQL and the retired type list, got: %v", err)
		}
	})

	t.Run("unmapped_synonym", func(t *testing.T) {
		err := assertNoBodyDropped(t, "../../db/migrations", a15RogueUnmappedSynonymBody)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 15 D133: expected the gate to FAIL against an unplaceable synonym inside SchemaSQL -- it passed instead")
		}
		if !strings.Contains(err.Error(), "SchemaSQL") {
			t.Fatalf("expected the failure to name SchemaSQL, got: %v", err)
		}
	})
}

// TestD132MembershipRuleAloneDoesNotCatchTheSchemaSQLRogue is D136 item
// 5, and D133's own withdrawal condition made a pinned fact rather than
// only a design-document assertion: D132's membership rule
// (assertEveryCommittedLiteralIsADeclaredBody), run ALONE against
// SchemaSQL-shaped content carrying the SAME resurrected-retired-
// signature rogue TestAssertNoBodyDroppedCatchesRogueInsideSchemaSQL
// above proves assertNoBodyDropped catches, PASSES -- because
// derivedPopulation filters SchemaSQL bodies by type list BEFORE any
// digest is compared, so a body whose type list matches no declared
// overload (the retired time-floor signature matches neither current
// overload) is never a member of any overload's population to begin
// with. D132 and D133 are two mechanisms; this pins that neither
// discharges the other, per D122 item 7's precedent (a fact that decides
// a design is pinned by a test, not only by this document's prose).
func TestD132MembershipRuleAloneDoesNotCatchTheSchemaSQLRogue(t *testing.T) {
	if err := assertEveryCommittedLiteralIsADeclaredBody(t, "../../db/migrations", a15RogueRetiredTimeFloorBody); err != nil {
		t.Fatalf("ADR-0007 Addendum 15 D133 withdrawal condition: D132's membership rule alone was expected to PASS on a SchemaSQL carrying the retired-signature rogue (proving it does NOT close D133 -- that is the whole point of this test), but it failed: %v", err)
	}
}

// TestCheckSupersededLiteralsNotAcceptedNamesAbsentFunctionRatherThanPanicking
// is D136 item 6 (row 3 of the sweep): a declaredFunction absent from a
// bootstrap path -- schemaSQL has zero members -- must produce a named
// error identifying the function and the path, not the
// "slice bounds out of range [:-1]" panic measured before this fix at
// what was d92_digest_gate_derivation_test.go:626.
func TestCheckSupersededLiteralsNotAcceptedNamesAbsentFunctionRatherThanPanicking(t *testing.T) {
	phantom := declaredFunction{
		label:    "A15D133-phantom-absent-from-every-bootstrap-path",
		funcName: "screening_ledger_purge_snapshots_a15_absent_probe",
	}
	err := checkSupersededLiteralsNotAccepted(t, phantom, "../../db/migrations")
	if err == nil {
		t.Fatal("expected a named failure for a declared function absent from SchemaSQL -- got nil (test construction error: the phantom function name must not exist anywhere)")
	}
	if !strings.Contains(err.Error(), phantom.label) || !strings.Contains(err.Error(), "SchemaSQL") {
		t.Fatalf("expected the failure to name the function and SchemaSQL, got: %v", err)
	}
}
