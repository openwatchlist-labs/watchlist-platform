// ADR-0007 Addendum 17 D139/D140 (CAP #16's K-A, MEDIUM): the required
// tests for D139's fix, in the order D140 lists them. Every test here
// fails against the shipped (pre-D139) createFunctionKeywordRe: its `\s+`
// between the CREATE/OR/REPLACE/FUNCTION keyword tokens matches whitespace
// but NOT a SQL comment, so a comment-mid-keyword rogue (which PostgreSQL
// accepts as the identical function -- measured on PG 17) is invisible to
// the flat scan -> extractFunctionBodies returns 0 bodies, nil error, a
// silent fail-open one token earlier than D137's H-A. D139 replaces the
// regexp with scanCreateFunctionKeyword, a lexer over the WHOLE header that
// applies the same skipWSAndComments D137 wrote for the name production
// between every keyword token too, so comment tolerance is one uniform
// mechanism across the header. DSN-free throughout (D140 item 6), matching
// every other extractFunctionBodies-based test in this package.
package screeningledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// d139Decl wraps a caller-supplied CREATE FUNCTION header (the part through
// FUNCTION, e.g. "CREATE OR/**/REPLACE FUNCTION") plus a name production in
// an otherwise-ordinary declaration, so the WHOLE header -- keyword
// sequence and name -- is exercised, not just a name fragment.
func d139Decl(header, qualifiedName string) string {
	return header + " " + qualifiedName + "(p_x text) RETURNS text LANGUAGE plpgsql AS $$ BEGIN RETURN p_x; END; $$;\n"
}

// d139CommentKeywordArrayRogue is K-A's own live shape: the array-form
// overload's signature under a CREATE OR/**/REPLACE keyword header, carrying
// a SECURITY DEFINER body this repository never shipped. Independently
// reproduced live in this addendum's design pass (has_ct t->f under a
// 2100 obligation via an empty-array call).
const d139CommentKeywordArrayRogue = "CREATE OR/**/REPLACE FUNCTION public.screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER AS $$ DECLARE recorded text[]; BEGIN WITH inserted AS (INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT snapshot_sha256, clock_timestamp(), p_operator, p_reason FROM screening_ledger_snapshot WHERE purged_at IS NULL RETURNING snapshot_sha256) SELECT array_agg(snapshot_sha256) INTO recorded FROM inserted; RETURN COALESCE(recorded, ARRAY[]::text[]); END; $$;\n"

// TestD139CommentKeywordRogueIsFound is D140 item 1: the K-A reproduction
// and the property the finding is about. Against the shipped (pre-D139)
// extractor the comment-keyword declaration returns 0 bodies (measured in
// this addendum's design pass); the plain-keyword control returns 1. After
// D139 both return 1 -- so this test distinguishes a working fix from one
// that still matches the keyword sequence with `\s+`.
func TestD139CommentKeywordRogueIsFound(t *testing.T) {
	const fn = "screening_ledger_purge_snapshots"
	plain := d139Decl("CREATE OR REPLACE FUNCTION", "public.screening_ledger_purge_snapshots")
	commented := d139Decl("CREATE OR/**/REPLACE FUNCTION", "public.screening_ledger_purge_snapshots")

	gotPlain, err := extractFunctionBodies(t, plain, "probe-plain", fn)
	if err != nil {
		t.Fatalf("unexpected error on the plain-keyword control: %v", err)
	}
	if len(gotPlain) != 1 {
		t.Fatalf("D140 item 1: expected 1 body for the plain-keyword control, got %d", len(gotPlain))
	}

	gotCommented, err := extractFunctionBodies(t, commented, "probe-commented", fn)
	if err != nil {
		t.Fatalf("unexpected error on the comment-keyword declaration: %v", err)
	}
	if len(gotCommented) != 1 {
		t.Fatalf("D140 item 1 (CAP #16's K-A): expected the fixed extractor to find the comment-keyword declaration (the shipped, pre-D139 extractor returned 0 -- a SQL comment between OR and REPLACE defeats the `\\s+` keyword regex) -- got %d", len(gotCommented))
	}
}

// TestD139KeywordCommentInterspersalMatrix is D140 item 2: the exhaustive
// matrix over EVERY way PostgreSQL allows whitespace/comments to be
// interspersed in "CREATE OR REPLACE FUNCTION" -- between every adjacent
// keyword pair, multiple comments in sequence, both comment styles, nested
// block comments (PG nests: measured), and a comment immediately before the
// name where D137's resolver takes over. Every row PG accepts as the
// declaration finds exactly one body; the word-boundary and prose rows find
// zero; an unterminated nested comment (which PG itself rejects, creating
// nothing) finds zero and is not an error. Exhaustiveness is by construction
// (one uniform skipWSAndComments between every token), not by this list.
func TestD139KeywordCommentInterspersalMatrix(t *testing.T) {
	const fn = "screening_ledger_purge_snapshots"
	const qn = "public.screening_ledger_purge_snapshots"
	rows := []struct {
		name    string
		header  string // through FUNCTION
		wantN   int
		wantErr bool
	}{
		{"plain_control", "CREATE OR REPLACE FUNCTION", 1, false},
		{"block_between_or_replace_KA", "CREATE OR/**/REPLACE FUNCTION", 1, false},
		{"block_between_create_function_no_or_replace", "CREATE/**/FUNCTION", 1, false},
		{"block_between_create_or", "CREATE/**/OR REPLACE FUNCTION", 1, false},
		{"block_between_replace_function", "CREATE OR REPLACE/**/FUNCTION", 1, false},
		{"line_comment_before_function", "CREATE OR REPLACE--x\nFUNCTION", 1, false},
		{"multiple_comments_in_sequence", "CREATE/*a*/ /*b*/OR/**/REPLACE/**/FUNCTION", 1, false},
		{"mixed_line_and_block", "CREATE --a\n/**/OR --b\nREPLACE/*c*/FUNCTION", 1, false},
		{"nested_block_between_create_function", "CREATE /* a /* b */ c */ FUNCTION", 1, false},
		{"nested_3level_between_or_replace", "CREATE OR/* 1 /* 2 /* 3 */ 2 */ 1 */REPLACE FUNCTION", 1, false},
		// name-region comments (stage-2 handoff, D137) with the header intact
		{"comment_before_name", "CREATE OR REPLACE FUNCTION/* c */", 1, false},
		// word boundary by construction (maximal-run lexer): must NOT match
		{"procreate_not_create", "proCREATE OR REPLACE FUNCTION", 0, false},
		{"functional_not_function", "CREATE OR REPLACE FUNCTIONAL", 0, false},
		// an unterminated nested comment: PG rejects (creates nothing), so
		// found=0 is correct and safe -- NOT a surfaced error.
		{"unterminated_nested_comment", "CREATE /* a /* b */ FUNCTION", 0, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			src := d139Decl(r.header, qn)
			bodies, err := extractFunctionBodies(t, src, r.name, fn)
			if r.wantErr {
				if err == nil {
					t.Fatalf("expected a surfaced failure for header %q, got %d body(ies) and no error", r.header, len(bodies))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for header %q: %v", r.header, err)
			}
			if len(bodies) != r.wantN {
				t.Fatalf("header %q: want %d body(ies), got %d", r.header, r.wantN, len(bodies))
			}
		})
	}
}

// TestD139CommentAroundSchemaDot pins the name-region comments D137 already
// handles, now reached through the D139 keyword scanner: a comment around
// the schema dot and before the name resolve to the same identity.
func TestD139CommentAroundSchemaDot(t *testing.T) {
	const fn = "screening_ledger_purge_snapshots"
	for _, qn := range []string{
		"public/* s */./* n */screening_ledger_purge_snapshots",
		"public.-- line\n\tscreening_ledger_purge_snapshots",
	} {
		src := d139Decl("CREATE OR/**/REPLACE FUNCTION", qn)
		bodies, err := extractFunctionBodies(t, src, qn, fn)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", qn, err)
		}
		if len(bodies) != 1 {
			t.Fatalf("%q: want 1 body, got %d", qn, len(bodies))
		}
	}
}

// TestD139EndToEndGateBothBootstrapPathsBothPlacements is D140 item 3: a
// comment-keyword rogue placed in the real db/migrations/ (a file that sorts
// between two migrations, and one that sorts last) and in SchemaSQL via the
// schemaSQLOverride hook, asserting the composed gate fails closed and names
// the rogue in every placement -- the property CAP #16 measured (the shipped
// extractor's blindness let this pass in full) and this fix inverts. The
// plain-keyword control (already caught pre-D139) confirms the comment is the
// only thing the fix changes.
func TestD139EndToEndGateBothBootstrapPathsBothPlacements(t *testing.T) {
	placements := []string{"023a_d139_rogue.sql", "zzz999_d139_rogue.sql"}
	messages := map[string]string{}
	for _, filename := range placements {
		t.Run("migration_file/"+filename, func(t *testing.T) {
			tempDir := t.TempDir()
			a15CopyMigrationsInto(t, tempDir)
			roguePath := filepath.Join(tempDir, filename)
			if err := os.WriteFile(roguePath, []byte(d139CommentKeywordArrayRogue), 0o644); err != nil {
				t.Fatal(err)
			}
			err := assertEveryCommittedLiteralIsADeclaredBody(t, tempDir)
			if err == nil {
				t.Fatalf("D140 item 3: expected the gate to FAIL closed against a comment-keyword rogue placed as %s -- it passed instead (CAP #16's K-A, now fixed)", filename)
			}
			if !strings.Contains(err.Error(), filename) {
				t.Fatalf("expected the failure to name %s, got: %v", filename, err)
			}
			messages[filename] = strings.Replace(err.Error(), roguePath, "<FILE>", 1)

			if filename == "zzz999_d139_rogue.sql" {
				d := declaredFunctions()[3] // screening_ledger_purge_snapshots(p_snapshot_sha256 text[],...)
				if d.label != "screening_ledger_purge_snapshots(p_snapshot_sha256 text[],...)" {
					t.Fatalf("test construction error: wrong declaredFunctions() index")
				}
				if err := checkLiveDigestMatchesAccepted(t, d, tempDir); err == nil {
					t.Fatal("D140 item 3: expected checkLiveDigestMatchesAccepted to ALSO fail once the comment-keyword rogue is the last-sorting, live migration-path body")
				}
			}
		})
	}
	if messages[placements[0]] != messages[placements[1]] {
		t.Fatalf("the two failure messages must differ ONLY in the filename each names (sort order must not appear in the rule) -- got:\n  %s: %s\n  %s: %s", placements[0], messages[placements[0]], placements[1], messages[placements[1]])
	}

	t.Run("schemaSQL_override_hook", func(t *testing.T) {
		if err := assertNoBodyDropped(t, "../../db/migrations", d139CommentKeywordArrayRogue); err != nil {
			t.Fatalf("unexpected: assertNoBodyDropped should place (not refuse) a live-signature body: %v", err)
		}
		err := assertEveryCommittedLiteralIsADeclaredBody(t, "../../db/migrations", d139CommentKeywordArrayRogue)
		if err == nil {
			t.Fatal("D140 item 3: expected the gate to FAIL closed against a comment-keyword rogue placed inside SchemaSQL via the schemaSQLOverride hook -- it passed instead")
		}
		if !strings.Contains(err.Error(), "SchemaSQL") {
			t.Fatalf("expected the failure to name SchemaSQL, got: %v", err)
		}
	})

	// The decisive control: the SAME body with a PLAIN keyword was already
	// caught pre-D139 (H-A's fix). Only the comment made it invisible.
	t.Run("plain_keyword_control_still_caught", func(t *testing.T) {
		plain := strings.Replace(d139CommentKeywordArrayRogue, "CREATE OR/**/REPLACE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
		tempDir := t.TempDir()
		a15CopyMigrationsInto(t, tempDir)
		if err := os.WriteFile(filepath.Join(tempDir, "023a_d139_plain.sql"), []byte(plain), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := assertEveryCommittedLiteralIsADeclaredBody(t, tempDir); err == nil {
			t.Fatal("the plain-keyword control must also fail closed")
		}
	})
}

// TestD139PositiveControlRealTreeAllDeclarationsFound is D140 item 4, D37's
// shipping requirement: the unmodified db/migrations/ and SchemaSQL tree must
// pass ALL of this package's gate functions with the D139 scanner, for every
// declaredFunctions() entry, including every SchemaSQL declaration inside its
// EXECUTE $exec$...$exec$ block ($exec$CREATE -- the boundary case the `\b`
// start-check preserves). A fix that finds the rogue but drops a real body
// passes its own suite; this is the test that would catch that.
func TestD139PositiveControlRealTreeAllDeclarationsFound(t *testing.T) {
	for _, d := range declaredFunctions() {
		t.Run(d.label, func(t *testing.T) {
			if err := checkLiveDigestMatchesAccepted(t, d, "../../db/migrations"); err != nil {
				t.Fatalf("D140 item 4: %v", err)
			}
		})
	}
	if err := assertNoBodyDropped(t, "../../db/migrations"); err != nil {
		t.Fatalf("D140 item 4: %v", err)
	}
	if err := assertEveryCommittedLiteralIsADeclaredBody(t, "../../db/migrations"); err != nil {
		t.Fatalf("D140 item 4: %v", err)
	}
	for _, name := range []string{"screening_ledger_reject_mutation", "owl_reject_truncate", "screening_ledger_purge_snapshots"} {
		bodies, err := extractFunctionBodies(t, SchemaSQL, "SchemaSQL", name)
		if err != nil {
			t.Fatalf("D140 item 4: %s: %v", name, err)
		}
		if len(bodies) == 0 {
			t.Fatalf("D140 item 4: expected at least 1 SchemaSQL body for %s (inside EXECUTE $exec$...$exec$), found 0", name)
		}
	}
}

// TestD139SkipWSAndCommentsNesting pins the mechanism the whole fix depends
// on: skipWSAndComments consumes a balanced nested block comment as one
// separator (PG nests -- measured), and returns the comment's start on an
// unterminated one (PG rejects such input, so the caller fails closed). A
// first-"*/" scan (the pre-D139 code) would stop after the inner close.
func TestD139SkipWSAndCommentsNesting(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int // index skipWSAndComments should reach
	}{
		{"balanced_nested_2level", "/* a /* b */ c */X", len("/* a /* b */ c */")},
		{"balanced_nested_3level", "/* 1 /* 2 /* 3 */ 2 */ 1 */X", len("/* 1 /* 2 /* 3 */ 2 */ 1 */")},
		{"comment_then_ws_then_token", "/* a */  \n X", len("/* a */  \n ")},
		{"unterminated_returns_start", "/* a /* b */ still open", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := skipWSAndComments(c.src, 0)
			if got != c.want {
				t.Fatalf("skipWSAndComments(%q,0)=%d, want %d (reached %q)", c.src, got, c.want, c.src[got:])
			}
		})
	}
}

// TestD139WordBoundaryAndDollarQuote pins the two start-boundary properties
// D139's scanner must hold together: a maximal-run lexer excludes procreate/
// FUNCTIONAL (the `\b` end/ start property), AND a CREATE immediately after a
// dollar-quote '$' (SchemaSQL's $exec$CREATE) is still found -- which forces
// the start boundary to be `\b` (ASCII word chars), NOT the full PG identifier
// rule that counts '$' as continuation.
func TestD139WordBoundaryAndDollarQuote(t *testing.T) {
	const fn = "screening_ledger_reject_mutation"
	// $exec$CREATE FUNCTION ... must be found (SchemaSQL's own shape).
	dollar := "DO $$ BEGIN EXECUTE $exec$CREATE FUNCTION screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $func$ BEGIN RETURN NEW; END $func$ $exec$; END $$;"
	bodies, err := extractFunctionBodies(t, dollar, "dollar", fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("$exec$CREATE must be found (start boundary must exclude '$'): got %d bodies", len(bodies))
	}
	// procreate / a_create must NOT be treated as a CREATE candidate.
	for _, neg := range []string{
		"proCREATE OR REPLACE FUNCTION public.screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;",
		"x_create OR REPLACE FUNCTION public.screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;",
	} {
		b, err := extractFunctionBodies(t, neg, "neg", fn)
		if err != nil {
			t.Fatalf("unexpected error on %q: %v", neg, err)
		}
		if len(b) != 0 {
			t.Fatalf("a CREATE inside a larger word must not match: got %d bodies for %q", len(b), neg)
		}
	}
}
