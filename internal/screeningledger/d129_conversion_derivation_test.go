// ADR-0007 Addendum 14 D129 (F-E, LOW): D113's derivation-audit table
// (docs/adr/0007-audit-chain-integrity.md) disposes of anchor.go's
// int64(...)/uint64(...) sequence conversions by listing line numbers --
// row 6 lists six, row 5 one. Re-derived directly against this file, it
// actually contains NINE such conversions; the two omitted are D32's
// forward attestation-ordering comparison and D70's reverse one
// (anchor.go:737, :786 at this commit). Both are confirmed benign by
// execution (their operand, entry.Sequence, is bounded by the number of
// audit entries this ledger's own chain contains -- identically to row
// 6's six original members), but the METHOD that missed them -- a
// hand-enumerated population -- is the finding CLAUDE.md's own "never
// enumerate targets by inference" trap names, applied to this addendum's
// own audit table by a later reader of it.
//
// This file derives the population instead of listing it: every
// int64(...)/uint64(...) conversion in anchor.go, found by pattern, must
// appear in the declared table below with a disposition (D99(a)'s own
// move, applied to a derivation table instead of a digest gate). A
// conversion added later that this table does not account for fails the
// gate -- DSN-free, so it runs on every PR regardless of database
// availability, the same standing D92 established for the digest gate.
package screeningledger

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// d129DeclaredConversion is one row of the derivation table: an exact
// source snippet (e.g. "int64(entry.Sequence)"), how many times it is
// expected to appear in anchor.go, and why that is safe -- D113's own
// disposition, carried forward rather than re-argued.
type d129DeclaredConversion struct {
	snippet     string
	count       int
	disposition string
}

// d129AnchorGoConversions is D113's table (0007:12545-12559), rows 5 and
// 6, re-derived in full against anchor.go: row 5 is D114(c)'s own single
// conversion; row 6 is now EIGHT sites (the six D113 originally listed
// plus the two D129 adds), all sharing row 6's own disposition --
// "checked, unreachable", because every one of them compares this
// ledger's own monotonically increasing sequence counter, bounded by how
// many events or audit entries this ledger's own chain actually
// contains.
var d129AnchorGoConversions = []d129DeclaredConversion{
	{
		snippet:     "int64(opts.Policy.MinAnchorSequence)",
		count:       1,
		disposition: "D113 row 5 (D114(c)): uint64->int64 from an Ed25519-signed field, compared against latest.Sequence -- bounded by D114(c)'s own analysis",
	},
	{
		snippet:     "int64(entry.Sequence)",
		count:       2,
		disposition: "D129 (D113 row 6's own shape, omitted by the hand list): anchor.go's forward (D32) and reverse (D70) attestation-ordering comparisons -- entry.Sequence is an AuditEvent's own sequence, drawn from this ledger's own audit chain, bounded by the number of audit entries the chain contains, identically to this row's other members",
	},
	{
		snippet:     "int64(report.Head.Sequence)",
		count:       2,
		disposition: "D113 row 6: this ledger's own monotonic event-chain counter -- checked, unreachable",
	},
	{
		snippet:     "uint64(latest.Sequence)",
		count:       1,
		disposition: "D113 row 6: this ledger's own monotonic event-chain counter -- checked, unreachable",
	},
	{
		snippet:     "int64(report.AuditHead.Sequence)",
		count:       2,
		disposition: "D113 row 6: this ledger's own monotonic audit-chain counter -- checked, unreachable",
	},
	{
		snippet:     "uint64(latest.AuditSequence)",
		count:       1,
		disposition: "D113 row 6: this ledger's own monotonic audit-chain counter -- checked, unreachable",
	},
}

// conversionPattern matches a bare int64(...)/uint64(...) conversion
// call. None of anchor.go's actual conversions nest a parenthesized
// expression inside the conversion's own argument (each is a single
// field-access expression), so a non-greedy match to the first ")" is
// exact for this file -- the same posture d92's own extractFunctionBodies
// already takes on similarly simple, non-nested source shapes.
var conversionPattern = regexp.MustCompile(`\b(?:u?int64)\([^()]*\)`)

// checkAnchorGoIntegerConversionsAccountedFor derives the population of
// int64(...)/uint64(...) conversions in content by pattern, and asserts
// every one -- and its exact multiplicity -- is a member of
// d129AnchorGoConversions. Returns a descriptive error rather than
// failing a *testing.T directly, so a negative test can assert on it
// without aborting its own goroutine (checkLiveDigestMatchesAccepted's
// own convention).
func checkAnchorGoIntegerConversionsAccountedFor(content string) error {
	found := map[string]int{}
	for _, m := range conversionPattern.FindAllString(content, -1) {
		found[m]++
	}
	declared := map[string]int{}
	for _, d := range d129AnchorGoConversions {
		declared[d.snippet] = d.count
	}
	var unaccounted []string
	for snippet, n := range found {
		want, ok := declared[snippet]
		if !ok {
			unaccounted = append(unaccounted, fmt.Sprintf("%s (found %d time(s), not in the declared table at all)", snippet, n))
			continue
		}
		if n != want {
			unaccounted = append(unaccounted, fmt.Sprintf("%s (found %d time(s), the declared table expects %d)", snippet, n, want))
		}
	}
	for snippet, want := range declared {
		if _, ok := found[snippet]; !ok && want > 0 {
			unaccounted = append(unaccounted, fmt.Sprintf("%s (declared %d time(s), found 0 -- the table is now stale)", snippet, want))
		}
	}
	if len(unaccounted) > 0 {
		sort.Strings(unaccounted)
		return fmt.Errorf("ADR-0007 Addendum 14 D129: anchor.go's int64(...)/uint64(...) conversion population does not match d129AnchorGoConversions: %v", unaccounted)
	}
	return nil
}

// TestAnchorGoIntegerConversionsAreDerivedNotHandListed is D131 item 7:
// runs with no DSN, and confirms the real, unmodified anchor.go is fully
// accounted for.
func TestAnchorGoIntegerConversionsAreDerivedNotHandListed(t *testing.T) {
	content, err := os.ReadFile("anchor.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAnchorGoIntegerConversionsAccountedFor(string(content)); err != nil {
		t.Fatal(err)
	}
}

// TestAnchorGoIntegerConversionsCatchesAnUnaccountedAddition is D131
// item 7's own required negative: a deliberately added int64(...)
// conversion the declared table does not know about must fail the gate.
func TestAnchorGoIntegerConversionsCatchesAnUnaccountedAddition(t *testing.T) {
	content, err := os.ReadFile("anchor.go")
	if err != nil {
		t.Fatal(err)
	}
	rogue := string(content) + "\nvar a14RogueConversion = int64(someNewUnaccountedField)\n"
	err = checkAnchorGoIntegerConversionsAccountedFor(rogue)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 14 D129: expected the gate to FAIL against a deliberately added, unaccounted-for int64(...) conversion -- it passed instead")
	}
	if !strings.Contains(err.Error(), "someNewUnaccountedField") {
		t.Fatalf("expected the failure to name the new conversion, got: %v", err)
	}

	// Positive control: the unmodified content, run through the exact
	// same check, must still pass -- proving the failure above came from
	// the injected line and not from some other difference.
	if err := checkAnchorGoIntegerConversionsAccountedFor(string(content)); err != nil {
		t.Fatalf("positive control: unmodified anchor.go must still pass, got: %v", err)
	}
}
