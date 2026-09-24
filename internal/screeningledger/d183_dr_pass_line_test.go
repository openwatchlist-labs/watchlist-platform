// ADR-0007 Addendum 23 D183 (C23-B, Stage X2): verify_cross_cluster_dr.sh
// had no test harness binding its own closing PASS line's claim to what
// the script actually runs -- CAP #23 found the claim wrong by reading
// the script, not by any test failing. This is that harness, DSN-free
// and read-and-regex in d155_doc_drift_test.go's own idiom, applied to a
// bash script's prose instead of a Markdown document's.
//
// D183's decision: the PASS line's direct-assertion clause names the
// REINDEX INDEX CONCURRENTLY owner-role probe (which observes MAINTAIN
// held by the owner or by PUBLIC -- drift note 1, executed and measured
// in the design pass: the owner is itself a member of PUBLIC) and names
// the subsequent `screening-ledger migrate` assertion as the mechanism
// covering MAINTAIN held by a role that is neither -- not a claim that
// the probe is blind to PUBLIC, and not a second enumeration mechanism
// (D183 rejected that as redundant with the existing migrate check).
package screeningledger

import (
	"os"
	"regexp"
	"testing"
)

// d183ReadDRScriptPassLine returns verify_cross_cluster_dr.sh's final
// echo "PASS: ..." line -- the one exact instance, not a match among
// several, since a script with zero or two matches is itself the test
// construction bug this function surfaces.
func d183ReadDRScriptPassLine(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../scripts/ci/verify_cross_cluster_dr.sh")
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`(?m)^echo "PASS: (.*)"$`).FindAllStringSubmatch(string(raw), -1)
	if len(matches) != 1 {
		t.Fatalf("test construction bug: expected exactly one closing PASS line in verify_cross_cluster_dr.sh, found %d", len(matches))
	}
	return matches[0][1]
}

// TestD183DRScriptPassLineNamesWhatItDirectlyAsserts is ADR-0007
// Addendum 23 D188 item 4: "The PASS line names the owner-role probe
// and the L-D backstop." Both mechanisms it names must still be present
// in the script -- this binds the PROSE claim to the CODE, not merely
// to itself, so a later edit that removes the REINDEX probe or the
// migrate assertion while leaving the PASS line's wording untouched
// still fails here.
func TestD183DRScriptPassLineNamesWhatItDirectlyAsserts(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/ci/verify_cross_cluster_dr.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	passLine := d183ReadDRScriptPassLine(t)

	// The pre-Addendum-23 claim, refuted by CAP #23: the PASS line must
	// not say the enumeration this script runs is the SAME one D174
	// installs (it is a per-relation owner-role REINDEX probe, a
	// narrower mechanism, plus the migrate backstop -- D183's own
	// "D178's decision text is corrected forward here").
	if regexp.MustCompile(`directly asserted on all four`).MatchString(passLine) {
		t.Fatalf("ADR-0007 Addendum 23 D183: the PASS line still claims MAINTAIN's survival is \"directly asserted on all four\" relations by a single enumeration -- CAP #23's C23-B found this overstated (what runs is a per-relation owner-role probe plus the migrate backstop), got %q", passLine)
	}

	// The PASS line must name the mechanism that is actually directly
	// asserted: the REINDEX INDEX CONCURRENTLY owner-role probe.
	if !regexp.MustCompile(`REINDEX INDEX CONCURRENTLY`).MatchString(passLine) {
		t.Fatalf("expected the PASS line to name the REINDEX INDEX CONCURRENTLY probe as what is directly asserted, got %q", passLine)
	}
	if !regexp.MustCompile(`\bPUBLIC\b`).MatchString(passLine) {
		t.Fatalf("expected the PASS line to say the probe observes MAINTAIN held by PUBLIC (the owner is itself a PUBLIC member -- drift note 1, measured), got %q", passLine)
	}
	// And the PASS line must name migrate as the backstop covering a
	// non-owner role -- the case the probe cannot see.
	if !regexp.MustCompile(`\bmigrate\b`).MatchString(passLine) {
		t.Fatalf("expected the PASS line to name the migrate assertion as the backstop for a non-owner-role grant, got %q", passLine)
	}

	// Bind the claim to the code: both mechanisms the PASS line now
	// names must actually be present in the script, not merely
	// asserted in prose.
	if !regexp.MustCompile(`REINDEX INDEX CONCURRENTLY \$\{dr_rel_index\}`).MatchString(script) {
		t.Fatal("test construction bug (or a real regression): the PASS line names a REINDEX INDEX CONCURRENTLY probe, but the script no longer runs one per declared relation")
	}
	if !regexp.MustCompile(`"\$DR_BINARY" migrate --postgres-dsn-env DR_MIGRATOR_DSN`).MatchString(script) {
		t.Fatal("test construction bug (or a real regression): the PASS line names the migrate assertion as its backstop, but the script no longer runs screening-ledger migrate against the recovered copy")
	}

	// The PASS line must not claim a SECOND enumeration mechanism was
	// added -- D183 rejected wiring D73's own two-limb SQL into this
	// script as redundant with the existing migrate backstop (option
	// (b), explicitly not adopted). "grantee-side" or "aclexplode" in
	// the PASS line, or a second privilegeHolders-style query in the
	// script beside the REINDEX loop, would mean that rejected
	// alternative was implemented instead of the wording fix.
	if regexp.MustCompile(`(?i)aclexplode|grantee-side`).MatchString(script) {
		t.Fatal("ADR-0007 Addendum 23 D183: verify_cross_cluster_dr.sh appears to wire in a second MAINTAIN-enumeration mechanism -- D183 rejected this (option (b)) as redundant with the existing migrate backstop; the fix is the PASS line's wording, not a new mechanism")
	}
}
