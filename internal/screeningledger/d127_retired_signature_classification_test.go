// ADR-0007 Addendum 14 D127 (F-C, MEDIUM) test file (D131 item 5).
// isRetiredSignature's unconditional `continue` in assertNoBodyDropped
// made a body whose type list matches a retired signature invisible to
// the gate no matter what it contains -- two resurrected-retired-
// signature rogues, and a third that reaches the same invisibility by a
// different mechanism (argTypeList counting an OUT parameter PostgreSQL
// itself excludes from a function's identity arguments). DSN-free, like
// every other assertNoBodyDropped test in this file.
package screeningledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// d127BuildRogueTempDir copies the real db/migrations/ tree into a temp
// directory and appends one rogue file that sorts last (so it becomes
// the LIVE body under the gate's own "last in apply order wins" rule).
func d127BuildRogueTempDir(t *testing.T, rogueSQL string) string {
	t.Helper()
	tempDir := t.TempDir()
	for _, path := range migrationFilePaths(t, "../../db/migrations") {
		content := mustReadFile(t, path)
		if err := os.WriteFile(filepath.Join(tempDir, filepath.Base(path)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tempDir, "zzz999_d127_rogue.sql"), []byte(rogueSQL), 0o644); err != nil {
		t.Fatal(err)
	}
	return tempDir
}

// TestAssertNoBodyDroppedCatchesResurrectedRetiredTimeFloorSignature is
// D127(a): a SECURITY DEFINER body redeclaring the retired time-floor
// signature ("timestamptz,text,text") -- one that inserts a tombstone
// for every unpurged snapshot -- must be caught, not silently classified
// retired and skipped.
func TestAssertNoBodyDroppedCatchesResurrectedRetiredTimeFloorSignature(t *testing.T) {
	tempDir := d127BuildRogueTempDir(t, "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz, p_operator text, p_reason text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $$ DECLARE affected bigint; BEGIN INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT snapshot_sha256, clock_timestamp(), p_operator, p_reason FROM screening_ledger_snapshot WHERE purged_at IS NULL; GET DIAGNOSTICS affected = ROW_COUNT; RETURN affected; END; $$;\n")
	err := assertNoBodyDropped(t, tempDir)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 14 D127: expected the gate to FAIL against a resurrected retired time-floor signature carrying a body this repository never shipped -- it passed instead")
	}
	if !containsAll(err.Error(), "zzz999_d127_rogue.sql", "timestamptz,text,text") {
		t.Fatalf("expected the failure to name the file and the retired type list, got: %v", err)
	}
}

// TestAssertNoBodyDroppedCatchesResurrectedRetiredArraySignature is
// D127(a)'s array-form sibling ("text[],timestamptz,text,text").
func TestAssertNoBodyDroppedCatchesResurrectedRetiredArraySignature(t *testing.T) {
	tempDir := d127BuildRogueTempDir(t, "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_before timestamptz, p_operator text, p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER AS $$ DECLARE recorded text[]; BEGIN WITH inserted AS (INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT snapshot_sha256, clock_timestamp(), p_operator, p_reason FROM screening_ledger_snapshot WHERE purged_at IS NULL RETURNING snapshot_sha256) SELECT array_agg(snapshot_sha256) INTO recorded FROM inserted; RETURN COALESCE(recorded, ARRAY[]::text[]); END; $$;\n")
	err := assertNoBodyDropped(t, tempDir)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 14 D127: expected the gate to FAIL against a resurrected retired array-form signature carrying a body this repository never shipped -- it passed instead")
	}
	if !containsAll(err.Error(), "zzz999_d127_rogue.sql", "text[],timestamptz,text,text") {
		t.Fatalf("expected the failure to name the file and the retired type list, got: %v", err)
	}
}

// TestAssertNoBodyDroppedCatchesOutParameterIdentityShift is D127(b):
// PostgreSQL excludes OUT parameters from a function's identity
// arguments. The pre-fix argTypeList counted this rogue's OUT p_reason,
// producing "timestamptz,text,text" -- which EQUALS the retired
// time-floor signature, so the rogue was classified retired and
// skipped. The fixed argTypeList excludes it, producing
// "timestamptz,text" -- which matches no declared or retired signature
// at all, so the rogue is now caught as unplaceable.
func TestAssertNoBodyDroppedCatchesOutParameterIdentityShift(t *testing.T) {
	tempDir := d127BuildRogueTempDir(t, "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz, p_operator text, OUT p_reason text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN p_reason := 'd127-forged'; END; $$;\n")
	err := assertNoBodyDropped(t, tempDir)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 14 D127(b): expected the gate to FAIL against a rogue whose OUT parameter shifts its true identity away from anything declared -- it passed instead")
	}
	if !containsAll(err.Error(), "zzz999_d127_rogue.sql") {
		t.Fatalf("expected the failure to name the file, got: %v", err)
	}
}

// TestAssertNoBodyDroppedVariadicControlUnregressed is D127(b)'s own
// required control: VARIADIC is not OUT, and PostgreSQL DOES include a
// VARIADIC parameter's own array type in a function's identity
// arguments -- this must still be correctly extracted and still fail to
// place (its true identity, "timestamptz,text,text[]", matches no
// declared or retired signature either), the same outcome as before this
// fix, confirming the fix touches OUT handling only.
func TestAssertNoBodyDroppedVariadicControlUnregressed(t *testing.T) {
	tempDir := d127BuildRogueTempDir(t, "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz, p_operator text, VARIADIC p_extra text[]) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN 0; END; $$;\n")
	err := assertNoBodyDropped(t, tempDir)
	if err == nil {
		t.Fatal("test construction error: expected the VARIADIC control to still be caught as unplaceable (unchanged from before this fix)")
	}
	if !containsAll(err.Error(), "zzz999_d127_rogue.sql") {
		t.Fatalf("expected the failure to name the file, got: %v", err)
	}
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
