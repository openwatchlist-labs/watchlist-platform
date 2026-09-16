// ADR-0007 Addendum 18 D146: test ownership for D142/D143/D144's fix.
// Every test below fails against the pre-Addendum-18 extractor (confirmed
// during this addendum's implementation: the L-B rogue returned bodies=1
// with a declared historical digest, the token-kind matrix returned the
// decoy in ten placements, the CR matrix returned bodies=0, and the
// end-to-end gate passed in the mid-tree placement -- CLAUDE.md rule 5).
package screeningledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// a18LBHistoricalAndEvilBodies returns 023's own declared-historical
// array-form body (measured, not retyped, straight from the real
// migration file) and a short, distinct "evil" replacement body, for
// building the L-B construction below.
func a18LBHistoricalAndEvilBodies(t *testing.T) (historical, evil string) {
	t.Helper()
	found, err := extractFunctionBodies(t, mustReadFile(t, "../../db/migrations/023_screening_ledger_purge_global_corroboration.sql"), "023", "screening_ledger_purge_snapshots")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range found {
		if strings.Contains(b.args, "text[]") {
			historical = b.body
		}
	}
	if historical == "" {
		t.Fatal("test construction error: could not find 023's array-form historical body")
	}
	evil = "\nBEGIN\n  UPDATE screening_ledger_snapshot SET has_ciphertext = false, purged_at = clock_timestamp() WHERE snapshot_sha256 = ANY(p_snapshot_sha256);\n  RETURN p_snapshot_sha256;\nEND;\n"
	return historical, evil
}

func a18LBRogueSource(t *testing.T) string {
	t.Helper()
	historical, evil := a18LBHistoricalAndEvilBodies(t)
	return "CREATE OR REPLACE FUNCTION public.screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text)\n" +
		"RETURNS text[]\n" +
		"LANGUAGE plpgsql\n" +
		"SECURITY DEFINER\n" +
		"SET search_path = pg_catalog, public\n" +
		"/* AS $$" + historical + "$$ */\n" +
		"as $$" + evil + "$$;\n"
}

// TestD142LBReproduction is ADR-0007 Addendum 18 D146 item 1: the exact
// construction this addendum measured -- a lowercase `as` introducing the
// real (evil) body, with 023's own declared-historical body parked in a
// block comment above it, introduced by an uppercase `AS`. Asserts THREE
// things, not one: the fixed extractor returns the REAL body; that body's
// digest is NOT a member of the declared set; and D132 (membership)
// refuses and names the rogue's own file, in BOTH migration-file
// placements and on BOTH bootstrap paths (migration file, SchemaSQL via
// the schemaSQLOverride hook). D133 (placement) does NOT refuse this
// specific construction and that is correct, not a gap: the rogue's
// argument list is byte-identical to a genuinely declared overload's, so
// its TYPE LIST places into exactly one bucket -- D133's own population
// (Addendum 18's own end-to-end transcript: "D132=true D133=false
// CAUGHT"). The wrong DIGEST under a correctly-PLACED signature is
// exactly D132's territory, not D133's; composition (Addendum 9/10) only
// requires that at least one member catches it.
func TestD142LBReproduction(t *testing.T) {
	rogue := a18LBRogueSource(t)
	historical, evil := a18LBHistoricalAndEvilBodies(t)

	got, err := extractFunctionBodies(t, rogue, "A18-LB", "screening_ledger_purge_snapshots")
	if err != nil {
		t.Fatalf("the fixed extractor must not surface an error on this construction: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 body, got %d", len(got))
	}
	if got[0].body != evil {
		t.Fatalf("assertion 1 FAILED: the fixed extractor must return the REAL (evil) body -- got a body of length %d, want %d", len(got[0].body), len(evil))
	}

	dg := digestHexString(got[0].body)
	histDigest := digestHexString(historical)
	if dg == histDigest {
		t.Fatalf("test construction error: the evil body's digest collides with the historical body's -- pick a different evil body")
	}
	d := declaredFunctions()[3] // screening_ledger_purge_snapshots(p_snapshot_sha256 text[],...)
	if d.label != "screening_ledger_purge_snapshots(p_snapshot_sha256 text[],...)" {
		t.Fatalf("test construction error: wrong declaredFunctions() index")
	}
	if d.declaredAcceptedSet()[dg] {
		t.Fatalf("assertion 2 FAILED: the evil body's digest %s must NOT be a member of the declared accepted set -- got a false negative on the exact defect this addendum fixes", dg)
	}

	placements := []string{"023a_a18_lb.sql", "zzz999_a18_lb.sql"}
	for _, filename := range placements {
		t.Run("migration_file/"+filename, func(t *testing.T) {
			tempDir := t.TempDir()
			a15CopyMigrationsInto(t, tempDir)
			if err := os.WriteFile(filepath.Join(tempDir, filename), []byte(rogue), 0o644); err != nil {
				t.Fatal(err)
			}
			errD132 := assertEveryCommittedLiteralIsADeclaredBody(t, tempDir)
			if errD132 == nil {
				t.Fatalf("assertion 3 FAILED (D132): expected the gate to refuse the L-B rogue at %s -- it passed instead", filename)
			}
			if !strings.Contains(errD132.Error(), filename) {
				t.Fatalf("D132's failure must name %s, got: %v", filename, errD132)
			}
			if err := assertNoBodyDropped(t, tempDir); err != nil {
				t.Fatalf("D133 must NOT refuse this construction (its signature is correctly placed; D132 alone is the composed gate's catch) -- got: %v", err)
			}
		})
	}

	t.Run("schemaSQL_bootstrap_path", func(t *testing.T) {
		errD132 := assertEveryCommittedLiteralIsADeclaredBody(t, "../../db/migrations", rogue)
		if errD132 == nil {
			t.Fatal("assertion 3 FAILED (D132): expected the gate to refuse the L-B rogue via the SchemaSQL bootstrap path -- it passed instead")
		}
		if !strings.Contains(errD132.Error(), "SchemaSQL") {
			t.Fatalf("D132's failure must name SchemaSQL, got: %v", errD132)
		}
		if err := assertNoBodyDropped(t, "../../db/migrations", rogue); err != nil {
			t.Fatalf("D133 must NOT refuse this construction via the SchemaSQL path either -- got: %v", err)
		}
	})
}

// TestD142TokenKindMatrixFindsRealBodyInEveryPlacement is ADR-0007
// Addendum 18 D146 item 2: a decoy `AS <tag> ... <tag>` planted inside
// each of the ten lexical forms that can carry it without PostgreSQL ever
// lexing a keyword there, plus two safe-direction robustness rows (a
// quoted identifier spelled "as", and "AS" inside a longer identifier) --
// each must find the REAL body, never the decoy.
func TestD142TokenKindMatrixFindsRealBodyInEveryPlacement(t *testing.T) {
	real := "\nBEGIN RETURN p_snapshot_sha256; END;\n"
	decoy := "DECOY_CONTENT_POSTGRESQL_NEVER_LEXES_$$decoytag$$"
	header := "CREATE OR REPLACE FUNCTION public.screening_ledger_purge_snapshots(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text)\nRETURNS text[]\nLANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = pg_catalog, public\n"

	cases := []struct {
		name string
		frag string
	}{
		{"block_comment", "/* AS $x$" + decoy + "$x$ */\nas $$" + real + "$$;"},
		{"nested_block_comment", "/* AS $x$ /* nested */ " + decoy + "$x$ */\nas $$" + real + "$$;"},
		{"line_comment_LF", "-- AS $x$" + decoy + "$x$\nas $$" + real + "$$;"},
		{"line_comment_bare_CR", "-- AS $x$" + decoy + "$x$\ras $$" + real + "$$;"},
		{"plain_string", "SET a.b = 'AS $x$" + decoy + "$x$'\nas $$" + real + "$$;"},
		{"plain_string_doubled", "SET a.b = 'AS $x$" + decoy + "$x$ don''t'\nas $$" + real + "$$;"},
		{"E_string_backslash", "SET a.b = E'AS $x$" + decoy + "$x$ \\\\'\nas $$" + real + "$$;"},
		{"U_ampersand_string", "SET a.b = U&'AS $x$" + decoy + "$x$'\nas $$" + real + "$$;"},
		{"dollar_quoted_SET_value", "SET a.b = $decoy$AS $x$" + decoy + "$x$$decoy$\nas $$" + real + "$$;"},
		{"quoted_identifier", "SET \"AS $x$" + decoy + "$x$\" = 1\nas $$" + real + "$$;"},
		{"quoted_identifier_spelled_as", "SET \"as\" = 1\nAS $$" + real + "$$;"},
		{"AS_inside_longer_identifier", "SET a.b = ASX\nas $$" + real + "$$;"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := header + c.frag + "\n"
			got, err := extractFunctionBodies(t, src, "A18-TK-"+c.name, "screening_ledger_purge_snapshots")
			if err != nil {
				t.Fatalf("unexpected surfaced error: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("expected exactly 1 body, got %d", len(got))
			}
			if got[0].body != real {
				t.Fatalf("expected the REAL body, got a different one (len=%d, want len=%d) -- the decoy was found instead", len(got[0].body), len(real))
			}
		})
	}
}

// TestD144LAReproduction is ADR-0007 Addendum 18 D146 item 5: the bare-CR
// construction at all four CREATE FUNCTION keyword boundaries and both
// stage-2 name-production positions, with LF/CRLF controls, plus a real
// db/migrations/*.sql rogue carrying exactly one bare CR (byte-count
// asserted, since a CRLF passes today and proves nothing).
func TestD144LAReproduction(t *testing.T) {
	args := "(p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text)"
	body := "\nBEGIN RETURN p_snapshot_sha256; END;\n"
	tail := args + "\nRETURNS text[]\nLANGUAGE plpgsql\nSECURITY DEFINER\nAS $$" + body + "$$;\n"

	cases := []struct {
		name       string
		header     string
		wantBodies int
	}{
		{"control_plain", "CREATE OR REPLACE FUNCTION public.screening_ledger_purge_snapshots", 1},
		{"CR_CREATE_FUNCTION", "CREATE --x\rFUNCTION public.screening_ledger_purge_snapshots", 1},
		{"CR_CREATE_OR", "CREATE --x\rOR REPLACE FUNCTION public.screening_ledger_purge_snapshots", 1},
		{"CR_OR_REPLACE", "CREATE OR --x\rREPLACE FUNCTION public.screening_ledger_purge_snapshots", 1},
		{"CR_REPLACE_FUNCTION", "CREATE OR REPLACE --x\rFUNCTION public.screening_ledger_purge_snapshots", 1},
		{"CR_before_NAME_stage2", "CREATE OR REPLACE FUNCTION --x\rpublic.screening_ledger_purge_snapshots", 1},
		{"CR_around_schema_DOT_stage2", "CREATE OR REPLACE FUNCTION public --x\r. --x\rscreening_ledger_purge_snapshots", 1},
		{"LF_control", "CREATE --x\nFUNCTION public.screening_ledger_purge_snapshots", 1},
		{"CRLF_control", "CREATE --x\r\nFUNCTION public.screening_ledger_purge_snapshots", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := c.header + tail
			got, err := extractFunctionBodies(t, src, "A18-LA-"+c.name, "screening_ledger_purge_snapshots")
			if err != nil {
				t.Fatalf("unexpected surfaced error: %v", err)
			}
			if len(got) != c.wantBodies {
				t.Fatalf("expected %d bodies, got %d (D144(a)'s fix must make the CR-boundary rogue visible at every one of these positions)", c.wantBodies, len(got))
			}
		})
	}

	// A real db/migrations/*.sql rogue carrying exactly one bare CR (not
	// CRLF), placed both before and after the real array-form migrations,
	// caught by D132 in both placements.
	rogueTemplate := "CREATE OR --x\rREPLACE FUNCTION screening_ledger_purge_snapshots" + tail
	crCount := strings.Count(rogueTemplate, "\r")
	bareCRCount := strings.Count(rogueTemplate, "\r") - strings.Count(rogueTemplate, "\r\n")
	if crCount != 1 || bareCRCount != 1 {
		t.Fatalf("test construction error: expected exactly 1 bare CR (not CRLF) in the rogue, got %d CR / %d bare", crCount, bareCRCount)
	}
	for _, filename := range []string{"023a_a18_cr.sql", "zzz999_a18_cr.sql"} {
		t.Run("real_tree/"+filename, func(t *testing.T) {
			tempDir := t.TempDir()
			a15CopyMigrationsInto(t, tempDir)
			if err := os.WriteFile(filepath.Join(tempDir, filename), []byte(rogueTemplate), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := assertEveryCommittedLiteralIsADeclaredBody(t, tempDir); err == nil {
				t.Fatalf("expected D132 to refuse the bare-CR rogue at %s -- it passed instead", filename)
			}
		})
	}
}

// TestD142D143SurfacedFailuresAreNamedNeverSilentlyAbsent is ADR-0007
// Addendum 18 D146 item 8: a BEGIN ATOMIC body, a RETURN expr body, a
// plain single-quoted string containing a backslash in the option
// region, an unterminated dollar-quote tag, and a tag that is not a tag
// by PostgreSQL's own rule must each return a NAMED error, never
// `bodies=0, err=nil`.
func TestD142D143SurfacedFailuresAreNamedNeverSilentlyAbsent(t *testing.T) {
	header := "CREATE OR REPLACE FUNCTION public.a18_surf(x text)\nRETURNS text\nLANGUAGE sql\n"
	cases := []struct {
		name string
		src  string
	}{
		{"begin_atomic_no_AS", header + "BEGIN ATOMIC SELECT x; END;"},
		{"return_expr_no_AS", header + "RETURN x;"},
		{"ambiguous_backslash_string", "CREATE OR REPLACE FUNCTION public.a18_surf(x text)\nRETURNS text\nLANGUAGE plpgsql\nSET a.b = 'contains \\\\ a backslash'\nAS $$BEGIN RETURN x; END;$$;"},
		{"unterminated_dollar_tag", "CREATE OR REPLACE FUNCTION public.a18_surf(x text)\nRETURNS text\nLANGUAGE plpgsql\nAS $tag$BEGIN RETURN x; END;"},
		{"tag_not_a_tag_by_pg_rule", "CREATE OR REPLACE FUNCTION public.a18_surf(x text)\nRETURNS text\nLANGUAGE plpgsql\nAS $1$BEGIN RETURN x; END;$1$;"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := extractFunctionBodies(t, c.src, "A18-SURF-"+c.name, "a18_surf")
			if err == nil {
				t.Fatalf("expected a NAMED, surfaced error -- got bodies=%d err=nil", len(got))
			}
			if len(got) != 0 {
				t.Fatalf("expected no bodies on a surfaced failure, got %d", len(got))
			}
		})
	}
}
