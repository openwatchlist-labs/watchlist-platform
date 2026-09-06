// ADR-0007 Addendum 10 D92/D95 test 6 (N-D, MEDIUM): the gate that is
// supposed to keep D77's declared digests honest computes a digest.
// R35's own named mitigation ("a check that extracts both bootstrap
// paths' literal function bodies from db/migrations/*.sql and
// internal/screeningledger/postgres.go, digests them, and asserts the
// declared set is exactly that set") was, before this addendum, three
// strings.Contains marker checks plus one inequality -- it never
// extracted a body, never digested one, and never compared a digest to
// a declared constant, so a reformat that preserves the marker (extra
// whitespace inside the delimiters, a trailing newline) passed silently
// while producing a genuinely different digest. This file replaces that
// shape with the derivation R35 actually named, over all eight literals
// (D87 adds screening_ledger_purge_snapshots's two overloads beside
// D77's original two guard functions) -- DSN-free, so it runs on every
// `go test ./...` with no database, which is what makes it a gate rather
// than something that self-skips.
package screeningledger

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// digestLiteral is one (function, bootstrap path) pair this gate derives
// and checks against a declared accepted-digest set.
type digestLiteral struct {
	label    string   // for failure messages
	source   string   // the full committed text to search (a file's contents, or SchemaSQL)
	marker   string   // text immediately preceding the opening dollar-quote tag
	tag      string   // the dollar-quote tag itself, e.g. "$$" or "$func$"
	declared []string // the accepted digest set this literal must belong to
}

// extractDollarQuotedBody locates marker in source, then the first
// occurrence of tag after it, and returns everything up to the NEXT
// occurrence of tag -- the same shape pg_proc.prosrc holds for a
// dollar-quoted plpgsql body (see anchor.go/postgres.go's own comments
// on this: prosrc is the text between the delimiters, not the full
// CREATE FUNCTION statement).
func extractDollarQuotedBody(t *testing.T, source, marker, tag string) string {
	t.Helper()
	idx := strings.Index(source, marker)
	if idx < 0 {
		t.Fatalf("marker %q not found in source (len=%d)", marker, len(source))
	}
	rest := source[idx+len(marker):]
	openIdx := strings.Index(rest, tag)
	if openIdx < 0 {
		t.Fatalf("opening tag %q not found immediately after marker %q", tag, marker)
	}
	bodyStart := openIdx + len(tag)
	closeIdx := strings.Index(rest[bodyStart:], tag)
	if closeIdx < 0 {
		t.Fatalf("closing tag %q not found after marker %q", tag, marker)
	}
	return rest[bodyStart : bodyStart+closeIdx]
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

// digestGateLiterals is the eight (function, bootstrap path) pairs D92
// derives -- D77's original four (owl_reject_truncate,
// screening_ledger_reject_mutation, each on both paths) plus D87's new
// four (both screening_ledger_purge_snapshots overloads, each on both
// paths).
func digestGateLiterals(t *testing.T) []digestLiteral {
	t.Helper()
	migration012 := mustReadFile(t, "../../db/migrations/012_truncate_guards.sql")
	migration008g := mustReadFile(t, "../../db/migrations/008g_screening_ledger.sql")
	migration020 := mustReadFile(t, "../../db/migrations/020_screening_ledger_purge_server_side_floor.sql")

	return []digestLiteral{
		{
			label:    "owl_reject_truncate (migration 012)",
			source:   migration012,
			marker:   "CREATE OR REPLACE FUNCTION owl_reject_truncate() RETURNS trigger\nLANGUAGE plpgsql AS ",
			tag:      "$$",
			declared: owlRejectTruncateAcceptedBodySHA256,
		},
		{
			label:    "owl_reject_truncate (SchemaSQL)",
			source:   SchemaSQL,
			marker:   "CREATE FUNCTION owl_reject_truncate()RETURNS trigger LANGUAGE plpgsql AS ",
			tag:      "$func$",
			declared: owlRejectTruncateAcceptedBodySHA256,
		},
		{
			label:    "screening_ledger_reject_mutation (migration 008g)",
			source:   migration008g,
			marker:   "CREATE OR REPLACE FUNCTION screening_ledger_reject_mutation()RETURNS trigger LANGUAGE plpgsql AS ",
			tag:      "$$",
			declared: []string{screeningLedgerRejectMutationBodySHA256},
		},
		{
			label:    "screening_ledger_reject_mutation (SchemaSQL)",
			source:   SchemaSQL,
			marker:   "CREATE FUNCTION screening_ledger_reject_mutation()RETURNS trigger LANGUAGE plpgsql AS ",
			tag:      "$func$",
			declared: []string{screeningLedgerRejectMutationBodySHA256},
		},
		{
			label:    "screening_ledger_purge_snapshots(timestamptz,...) (migration 020)",
			source:   migration020,
			marker:   "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz, p_operator text, p_reason text)\nRETURNS bigint\nLANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = pg_catalog, public\nAS ",
			tag:      "$$",
			declared: []string{purgeSnapshotsTimeFloorBodySHA256Migration},
		},
		{
			label:    "screening_ledger_purge_snapshots(text[],...) (migration 020)",
			source:   migration020,
			marker:   "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_before timestamptz, p_operator text, p_reason text)\nRETURNS text[]\nLANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = pg_catalog, public\nAS ",
			tag:      "$$",
			declared: []string{purgeSnapshotsArrayFormBodySHA256Migration},
		},
		{
			label:    "screening_ledger_purge_snapshots(timestamptz,...) (SchemaSQL)",
			source:   SchemaSQL,
			marker:   "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz,p_operator text,p_reason text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS ",
			tag:      "$func$",
			declared: []string{purgeSnapshotsTimeFloorBodySHA256SchemaSQLBoot},
		},
		{
			label:    "screening_ledger_purge_snapshots(text[],...) (SchemaSQL)",
			source:   SchemaSQL,
			marker:   "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[],p_before timestamptz,p_operator text,p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS ",
			tag:      "$func$",
			declared: []string{purgeSnapshotsArrayFormBodySHA256SchemaSQLBoot},
		},
	}
}

// TestGuardAndDefinerBodyDigestsAreDerivedFromCommittedLiterals is D92's
// own gate: extract, digest, compare for EQUALITY against the declared
// set -- marker presence is only the extraction anchor now, not the
// assertion. Runs with no DSN.
func TestGuardAndDefinerBodyDigestsAreDerivedFromCommittedLiterals(t *testing.T) {
	for _, lit := range digestGateLiterals(t) {
		t.Run(lit.label, func(t *testing.T) {
			body := extractDollarQuotedBody(t, lit.source, lit.marker, lit.tag)
			digest := digestHexString(body)
			found := false
			for _, accepted := range lit.declared {
				if digest == accepted {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("ADR-0007 Addendum 10 D92: %s's committed body digests to %s, which is not in its declared accepted set %v -- re-derive the declared constant from the new text", lit.label, digest, lit.declared)
			}
		})
	}
}

// TestDigestGateCatchesWhitespaceAlteredCopy is D92/D95's own required
// negative: the gate must FAIL against a deliberately whitespace-altered
// copy of each literal while the marker still matches -- the exact three
// variants R35/D92's own measurement used (extra leading/trailing space
// inside the delimiters, a trailing newline added). A gate that cannot
// fail here is the shape this addendum replaces.
func TestDigestGateCatchesWhitespaceAlteredCopy(t *testing.T) {
	for _, lit := range digestGateLiterals(t) {
		t.Run(lit.label, func(t *testing.T) {
			body := extractDollarQuotedBody(t, lit.source, lit.marker, lit.tag)
			original := digestHexString(body)

			variants := map[string]string{
				"leading_and_trailing_space_doubled": "  " + body + "  ",
				"trailing_newline_added":             body + "\n",
			}
			for name, altered := range variants {
				if digestHexString(altered) == original {
					t.Fatalf("test bug: %s variant %q did not actually change the digest", lit.label, name)
				}
				altered := altered
				found := false
				for _, accepted := range lit.declared {
					if digestHexString(altered) == accepted {
						found = true
					}
				}
				if found {
					t.Fatalf("ADR-0007 Addendum 10 D92: %s variant %q unexpectedly matched a declared accepted digest -- the gate is not sensitive to whitespace", lit.label, name)
				}
			}
		})
	}
}

// TestDigestGateSetEqualityBothDirections is D61's own direction, applied
// here (D92): the declared set must be EXACTLY the set of digests derived
// from the committed literals for each function -- a declared member with
// no literal behind it fails, and (implicitly, since digestGateLiterals
// enumerates every literal this repository ships) a literal with no
// declared member fails via TestGuardAndDefinerBodyDigestsAreDerivedFromCommittedLiterals
// above. This test covers the direction that test cannot: a declared
// digest that no committed literal on either path actually produces.
func TestDigestGateSetEqualityBothDirections(t *testing.T) {
	literals := digestGateLiterals(t)
	// Group by the declared slice's own identity (two literals that
	// share a declared set, e.g. owl_reject_truncate's migration and
	// SchemaSQL paths, are meant to jointly produce exactly that set).
	type group struct {
		declared []string
		derived  map[string]bool
	}
	var groups []*group
	findGroup := func(declared []string) *group {
		for _, g := range groups {
			if len(g.declared) == len(declared) {
				same := true
				for i := range declared {
					if g.declared[i] != declared[i] {
						same = false
						break
					}
				}
				if same {
					return g
				}
			}
		}
		g := &group{declared: declared, derived: map[string]bool{}}
		groups = append(groups, g)
		return g
	}
	for _, lit := range literals {
		g := findGroup(lit.declared)
		body := extractDollarQuotedBody(t, lit.source, lit.marker, lit.tag)
		g.derived[digestHexString(body)] = true
	}
	for _, g := range groups {
		for _, declared := range g.declared {
			if !g.derived[declared] {
				t.Fatalf("ADR-0007 Addendum 10 D92: declared digest %s has no committed literal producing it on either bootstrap path -- a stale declaration", declared)
			}
		}
		if len(g.derived) != len(g.declared) {
			t.Fatalf("ADR-0007 Addendum 10 D92: declared set %v (size %d) does not match the set of digests actually derived (size %d) -- set equality required, not membership", g.declared, len(g.declared), len(g.derived))
		}
	}
}
