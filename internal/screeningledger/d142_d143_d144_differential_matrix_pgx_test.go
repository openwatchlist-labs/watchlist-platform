// ADR-0007 Addendum 18 D144(b): "any future decision that claims a
// grammar is covered 'by construction' must ship a differential matrix
// generated once and fed to both PostgreSQL and the gate, and must state
// its agreement count" -- promoted from a design-time transcript to a
// standing, committed obligation. This file discharges it for D142's
// bounded token walk (the 32-row matrix), D143(d)'s unchanged closing
// boundary (the 18-shape matrix), and D144(a)'s separator fix (the
// 30-shape matrix CAP #17 measured at 23/30 and this addendum's own fix
// closes to 30/30) -- three committed regression tests future rounds can
// re-run rather than re-derive.
//
// Every row is sent to the real PostgreSQL server via pgx (which performs
// no client-side SQL parsing of its own -- the accept/reject verdict and
// the installed body's digest are the SERVER's, never an artifact of a
// client-side parser), and the SAME source text is fed to the real,
// production extractFunctionBodies (never a reimplementation). DSN-gated
// on OWL_MIGRATOR_DATABASE_URL (requireMigratorDSN, postgres_pgx_test.go)
// -- CREATE FUNCTION needs DDL rights owl_app does not have -- and skips
// cleanly without one (D92's DSN-free property is otherwise unaffected).
package screeningledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

const a18MxFuncName = "a18_mx_fn"

// a18MxProbe drops any prior a18_mx_fn(int), executes stmt (a full CREATE
// [OR REPLACE] FUNCTION statement) against the live server, and reports
// whether PostgreSQL accepted it and, if so, the installed prosrc's
// sha256 digest (or "" for a SQL-standard body, which has no prosrc --
// D141's own measured case).
func a18MxProbe(t *testing.T, ctx context.Context, conn *pgx.Conn, stmt string) (accepted bool, liveDigest string, pgErr error) {
	t.Helper()
	if _, err := conn.Exec(ctx, "DROP FUNCTION IF EXISTS public."+a18MxFuncName+"(int)"); err != nil {
		t.Fatalf("could not drop prior probe function: %v", err)
	}
	if _, err := conn.Exec(ctx, "DROP FUNCTION IF EXISTS public."+a18MxFuncName+"(int,int)"); err != nil {
		t.Fatalf("could not drop prior probe function (2-arg overload): %v", err)
	}
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return false, "", err
	}
	row := conn.QueryRow(ctx, "SELECT prosrc FROM pg_proc WHERE proname = $1 AND pronamespace = 'public'::regnamespace", a18MxFuncName)
	var prosrc string
	if err := row.Scan(&prosrc); err != nil {
		t.Fatalf("PostgreSQL accepted the statement but the function is not in pg_proc: %v", err)
	}
	sum := sha256.Sum256([]byte(prosrc))
	return true, hex.EncodeToString(sum[:]), nil
}

func a18ExtractLiveOverload(t *testing.T, source string) (bodies int, digest string, err error) {
	t.Helper()
	got, err := extractFunctionBodies(t, source, "A18-MX", a18MxFuncName)
	if err != nil {
		return 0, "", err
	}
	if len(got) == 0 {
		return 0, "", nil
	}
	sum := sha256.Sum256([]byte(got[len(got)-1].body))
	return len(got), hex.EncodeToString(sum[:]), nil
}

// TestD142ThirtyTwoRowDifferentialMatrix is ADR-0007 Addendum 18 D142/
// D146 item 3: every one of the ten lexical placements that can carry a
// decoy "AS" without PostgreSQL ever lexing a keyword there, plus the
// case-fold controls, the safe-direction robustness rows, the
// comment-before-tag rows, the argument-list mechanics rows, and the
// no-AS SQL-standard body rows -- fed to both PostgreSQL (via pgx, no
// client-side parsing) and the real, fixed extractFunctionBodies, with
// the agreement count asserted rather than merely reported.
func TestD142ThirtyTwoRowDifferentialMatrix(t *testing.T) {
	dsn := requireMigratorDSN(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	// This matrix tests the OUTER SQL lexer's boundary-finding, which is
	// what extractFunctionBodies models -- not whether the body's CONTENT
	// is semantically valid plpgsql/SQL. With body validation on, a decoy
	// dollar-sign sequence inside the extracted body text can trip
	// PL/pgSQL's OWN (separate) scanner, which is a different, irrelevant
	// failure (measured: "$b$ ... $a$" as valid OUTER dollar-quoted content
	// is accepted by the SQL lexer, but PL/pgSQL's body-compilation pass
	// then tries to lex "$b$" as the start of ITS OWN dollar-quoted literal
	// within the already-extracted body text and finds no partner for it,
	// an entirely separate and correct PL/pgSQL error unrelated to this
	// gate's own boundary-finding).
	if _, err := conn.Exec(ctx, "SET check_function_bodies = off"); err != nil {
		t.Fatalf("SET check_function_bodies = off: %v", err)
	}

	real := "BEGIN RETURN x; END;"
	decoyTag := "$decoytag$"
	decoyBody := "DECOY_BODY_POSTGRESQL_NEVER_LEXES_THIS"
	decoy := "AS " + decoyTag + decoyBody + decoyTag

	type row struct {
		name       string
		stmt       string
		wantAccept bool
		// outOfScopeSurfaced is true for the three body forms D142(d)
		// deliberately cannot digest at all (a SQL-standard body has no
		// "AS $$...$$" to find, by PostgreSQL's own grammar) -- there, a
		// named, surfaced failure IS the agreed, accepted behavior (R68),
		// not a miss: D146 item 8 requires exactly this be asserted as
		// surfaced, never silently absent.
		outOfScopeSurfaced bool
	}
	header := func(args string) string {
		return "CREATE OR REPLACE FUNCTION public." + a18MxFuncName + "(" + args + ")\nRETURNS int\nLANGUAGE plpgsql\n"
	}
	tail := func(optionFrag, asClause string) string {
		return optionFrag + asClause + ";\n"
	}
	plainArgs := "x int"

	rows := []row{
		{"00_control_uppercase_AS", header(plainArgs) + tail("", "AS $$"+real+"$$"), true, false},
		{"01_control_lowercase_as", header(plainArgs) + tail("", "as $$"+real+"$$"), true, false},
		{"02_control_mixedcase_As", header(plainArgs) + tail("", "As $$"+real+"$$"), true, false},
		{"03_decoy_block_comment", header(plainArgs) + tail("/* "+decoy+" */\n", "as $$"+real+"$$"), true, false},
		{"04_decoy_nested_block_comment", header(plainArgs) + tail("/* "+decoy+" /* nested */ tail */\n", "as $$"+real+"$$"), true, false},
		{"05_decoy_line_comment_LF", header(plainArgs) + tail("-- "+decoy+"\n", "as $$"+real+"$$"), true, false},
		{"06_decoy_line_comment_CR", header(plainArgs) + tail("-- "+decoy+"\ras $$"+real+"$$", ""), true, false},
		{"07_decoy_line_comment_CRLF", header(plainArgs) + tail("-- "+decoy+"\r\n", "as $$"+real+"$$"), true, false},
		{"08_decoy_plain_string", header(plainArgs) + tail("SET search_path = '"+decoy+"'\n", "as $$"+real+"$$"), true, false},
		{"09_decoy_plain_string_doubled_quote", header(plainArgs) + tail("SET search_path = '"+decoy+" don''t'\n", "as $$"+real+"$$"), true, false},
		{"10_decoy_E_string_backslash", header(plainArgs) + tail("SET search_path = E'"+decoy+" \\\\done'\n", "as $$"+real+"$$"), true, false},
		{"11_decoy_U_ampersand_string", header(plainArgs) + tail("SET search_path = U&'"+decoy+"'\n", "as $$"+real+"$$"), true, false},
		{"12_decoy_dollar_quoted_SET_value", header(plainArgs) + tail("SET search_path = $optval$"+decoy+"$optval$\n", "as $$"+real+"$$"), true, false},
		{"13_decoy_quoted_identifier", header("\""+decoy+"\" int, x int") + tail("", "as $$"+real+"$$"), true, false}, // the decoy sits in a PARAMETER NAME, which PostgreSQL never validates semantically, so it is always accepted -- exercises quoted-identifier skipping in the argument list rather than in the option region
		{"14_quoted_identifier_spelled_as", header("\"as\" int, x int") + tail("", "as $$"+real+"$$"), true, false},
		{"15_AS_inside_longer_identifier", header(plainArgs) + tail("SET search_path = ASX\n", "as $$"+real+"$$"), true, false},
		{"16_AS_then_block_comment_then_tag", header(plainArgs) + tail("", "AS /* c */ $$"+real+"$$"), true, false},
		{"17_AS_then_line_comment_then_tag", header(plainArgs) + tail("", "AS -- c\n$$"+real+"$$"), true, false},
		{"18_AS_then_vtab_then_tag", header(plainArgs) + tail("", "AS \x0b$$"+real+"$$"), true, false},
		{"19_decoy_comment_inside_arglist", header("x int /* ) "+decoy+" */") + tail("", "AS $$"+real+"$$"), true, false},
		{"20_literal_paren_inside_DEFAULT", header("x int DEFAULT length('a)b')") + tail("", "AS $$"+real+"$$"), true, false},
		{"21_literal_paren_in_DEFAULT_decoy_after", header("x int DEFAULT length('a)b')") + tail("/* "+decoy+" */\n", "as $$"+real+"$$"), true, false},
		{"22_tag_dollar_a_dollar", header(plainArgs) + tail("", "AS $a$"+real+"$a$"), true, false},
		{"23_tag_dollar_underscore_x9_dollar", header(plainArgs) + tail("", "AS $_x9$"+real+"$_x9$"), true, false},
		{"24_tag_digit_leading_INVALID", header(plainArgs) + tail("", "AS $1$"+real+"$1$"), false, false},
		{"25_tag_non_ascii_VALID", header(plainArgs) + tail("", "AS $é$"+real+"$é$"), true, false},
		{"26_body_contains_nonmatching_longer_tag", header(plainArgs) + tail("", "AS $a$"+real+" $ab$ not a close $a$"), true, false},
		{"27_body_contains_dollardollar_under_a_tag", header(plainArgs) + tail("", "AS $a$"+real+" $$ not a close $a$"), true, false},
		{"28_body_contains_prefix_trap", header(plainArgs) + tail("", "AS $b$"+real+" $a$$ not a close $b$"), true, false},
		{"29_sql_standard_RETURN_body_no_AS", "CREATE OR REPLACE FUNCTION public." + a18MxFuncName + "(" + plainArgs + ")\nRETURNS int\nLANGUAGE sql\nRETURN x", true, true},
		{"30_begin_atomic_body_no_AS", "CREATE OR REPLACE FUNCTION public." + a18MxFuncName + "(" + plainArgs + ")\nRETURNS int\nLANGUAGE sql\nBEGIN ATOMIC SELECT x; END", true, true},
		{"31_return_body_decoy_AS_in_trailing_comment", "CREATE OR REPLACE FUNCTION public." + a18MxFuncName + "(" + plainArgs + ")\nRETURNS int\nLANGUAGE sql\nRETURN x -- " + decoy + "\n", true, true},
	}
	if len(rows) != 32 {
		t.Fatalf("test construction error: expected exactly 32 rows, got %d", len(rows))
	}

	agree := 0
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			accepted, liveDigest, pgErr := a18MxProbe(t, ctx, conn, r.stmt)
			bodies, gateDigest, gateErr := a18ExtractLiveOverload(t, r.stmt)

			var status string
			switch {
			case !accepted && (bodies == 0 || gateErr != nil):
				status = "agree (both refuse)"
				agree++
			case accepted && gateErr == nil && bodies > 0 && gateDigest == liveDigest:
				status = "agree (bodies match)"
				agree++
			case accepted && r.outOfScopeSurfaced && (bodies == 0 && gateErr != nil):
				status = "agree (D142(d): a body form outside this gate's scope, surfaced by name -- R68's accepted, agreed behavior)"
				agree++
			case accepted && (bodies == 0 || gateErr != nil):
				status = "MISS (gate found nothing/surfaced, PG accepted) -- safe direction"
			case accepted && gateDigest != liveDigest:
				status = "*** WRONG *** (gate reports a body PostgreSQL did not install)"
			default:
				status = "DISAGREE (gate found a body PostgreSQL rejected)"
			}
			t.Logf("row=%-42s PG accepted=%-5v gate bodies=%d err=%v  %s", r.name, accepted, bodies, gateErr, status)
			if status == "*** WRONG *** (gate reports a body PostgreSQL did not install)" {
				t.Errorf("row %s: gate digest %s != live PostgreSQL digest %s (source rejected: %v)", r.name, gateDigest, liveDigest, pgErr)
			}
			if r.wantAccept != accepted {
				t.Logf("row %s: expected PostgreSQL acceptance=%v, measured %v (pgErr=%v) -- recorded, not asserted, since PostgreSQL's own verdict is ground truth here, not this table's guess", r.name, r.wantAccept, accepted, pgErr)
			}
		})
	}
	t.Logf("D142 32-ROW DIFFERENTIAL MATRIX: fixed gate agrees with PostgreSQL on %d/%d", agree, len(rows))
	if agree != len(rows) {
		t.Fatalf("ADR-0007 Addendum 18 D142/D146 item 3: expected 32/32 agreement between the fixed gate and PostgreSQL, got %d/%d", agree, len(rows))
	}
}

// TestD143DollarQuoteCloseEighteenShapeMatrix is ADR-0007 Addendum 18
// D143(d)/D146 item 4: the body's CLOSE boundary is measured, not argued,
// to already agree with PostgreSQL's own <xdolq> scanner on every
// adversarial tag/body-content shape tried -- prefix traps, non-matching
// longer delimiters, case sensitivity, non-ASCII tags, bare "$" runs --
// so D141 row 7 is "no change needed" as a re-derived, re-runnable fact,
// not a claim trusted from this document.
func TestD143DollarQuoteCloseEighteenShapeMatrix(t *testing.T) {
	dsn := requireMigratorDSN(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	// This matrix tests the OUTER SQL lexer's boundary-finding, which is
	// what extractFunctionBodies models -- not whether the body's CONTENT
	// is semantically valid plpgsql/SQL. With body validation on, a decoy
	// dollar-sign sequence inside the extracted body text can trip
	// PL/pgSQL's OWN (separate) scanner, which is a different, irrelevant
	// failure (measured: "$b$ ... $a$" as valid OUTER dollar-quoted content
	// is accepted by the SQL lexer, but PL/pgSQL's body-compilation pass
	// then tries to lex "$b$" as the start of ITS OWN dollar-quoted literal
	// within the already-extracted body text and finds no partner for it,
	// an entirely separate and correct PL/pgSQL error unrelated to this
	// gate's own boundary-finding).
	if _, err := conn.Exec(ctx, "SET check_function_bodies = off"); err != nil {
		t.Fatalf("SET check_function_bodies = off: %v", err)
	}

	header := "CREATE OR REPLACE FUNCTION public." + a18MxFuncName + "(x int)\nRETURNS int\nLANGUAGE plpgsql\nAS "

	shapes := []string{
		"$$BEGIN RETURN x; END;$$",
		"$a$BEGIN RETURN x; END;$a$",
		"$$BEGIN RETURN x; END; -- contains $a$ .. $a$ literally\n$$",
		"$a$BEGIN RETURN x; END; -- contains $$ literally\n$a$",
		"$a$BEGIN RETURN x; END; -- contains $ab$ (longer, non-matching)\n$a$",
		"$ab$BEGIN RETURN x; END; -- contains $a$\n$ab$",
		"$ab$BEGIN RETURN x; END; -- contains $a$b$ prefix trap\n$ab$",
		"$a$BEGIN RETURN x; END; -- contains $aa$ (not a close) yyless(1) trap\n$a$",
		"$q$BEGIN RETURN x; END; -- contains $x$$\n$q$",
		"$a$BEGIN RETURN x; END; -- contains a bare $\n$a$",
		"$a$BEGIN RETURN x; END; -- contains $$$\n$a$",
		"$_$BEGIN RETURN x; END; -- contains $_x$\n$_$",
		"$A$BEGIN RETURN x; END; -- contains $a$ (case-sensitive)\n$A$",
		"$a$BEGIN RETURN x; END; -- contains $A$\n$a$",
		"$é$BEGIN RETURN x; END;$é$",
		"$é$BEGIN RETURN x; END; -- contains $e$\n$é$",
		"$a1$BEGIN RETURN x; END; -- contains $a$1$\n$a1$",
		"$q$BEGIN RETURN x; END; -- contains a lone $ then $$\n$q$",
	}
	if len(shapes) != 18 {
		t.Fatalf("test construction error: expected exactly 18 shapes, got %d", len(shapes))
	}

	agree := 0
	for i, body := range shapes {
		name := fmt.Sprintf("shape_%02d", i)
		t.Run(name, func(t *testing.T) {
			stmt := header + body + ";\n"
			accepted, liveDigest, _ := a18MxProbe(t, ctx, conn, stmt)
			bodies, gateDigest, gateErr := a18ExtractLiveOverload(t, stmt)
			if !accepted {
				t.Fatalf("test construction error: expected PostgreSQL to ACCEPT shape %d, it rejected", i)
			}
			if gateErr != nil || bodies == 0 {
				t.Fatalf("shape %d: gate found no body (err=%v)", i, gateErr)
			}
			if gateDigest == liveDigest {
				agree++
			} else {
				t.Errorf("shape %d: gate digest %s != live PostgreSQL digest %s", i, gateDigest, liveDigest)
			}
		})
	}
	t.Logf("D143(d) DOLLAR-QUOTE CLOSE: gate agrees with PostgreSQL on %d/%d shapes", agree, len(shapes))
	if agree != len(shapes) {
		t.Fatalf("ADR-0007 Addendum 18 D143(d)/D146 item 4: expected 18/18 agreement, got %d/%d", agree, len(shapes))
	}
}

// TestD144SeparatorGrammarThirtyShapeMatrix is ADR-0007 Addendum 18
// D144(b): CAP #17 section 5.2 measured the pre-fix separator grammar at
// 23/30 (seven disagreements, all CR-terminated, all fail-open). This
// re-generates the same shape classes and asserts 30/30 against the fixed
// skipWSAndComments.
func TestD144SeparatorGrammarThirtyShapeMatrix(t *testing.T) {
	dsn := requireMigratorDSN(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	// This matrix tests the OUTER SQL lexer's boundary-finding, which is
	// what extractFunctionBodies models -- not whether the body's CONTENT
	// is semantically valid plpgsql/SQL. With body validation on, a decoy
	// dollar-sign sequence inside the extracted body text can trip
	// PL/pgSQL's OWN (separate) scanner, which is a different, irrelevant
	// failure (measured: "$b$ ... $a$" as valid OUTER dollar-quoted content
	// is accepted by the SQL lexer, but PL/pgSQL's body-compilation pass
	// then tries to lex "$b$" as the start of ITS OWN dollar-quoted literal
	// within the already-extracted body text and finds no partner for it,
	// an entirely separate and correct PL/pgSQL error unrelated to this
	// gate's own boundary-finding).
	if _, err := conn.Exec(ctx, "SET check_function_bodies = off"); err != nil {
		t.Fatalf("SET check_function_bodies = off: %v", err)
	}

	// Each separator shape is inserted between "OR" and "REPLACE" in the
	// keyword header -- D139 made skipWSAndComments shared across every
	// keyword boundary, so any one boundary exercises the identical
	// mechanism L-A found broken at all four.
	shapes := []struct {
		name       string
		sep        string
		wantAccept bool
	}{
		{"space", " ", true},
		{"tab", "\t", true},
		{"LF", "\n", true},
		{"CR", "\r", true},
		{"CRLF", "\r\n", true},
		{"formfeed", "\x0c", true},
		{"vtab", "\x0b", true},
		{"block_comment", "/*c*/", true},
		{"nested_block_comment", "/* a /* b */ c */", true},
		{"unterminated_nested_block_comment", "/* a /* b */", false},
		{"unterminated_block_comment", "/*", false},
		{"dangling_close", "*/", false},
		{"line_comment_LF", "--c\n", true},
		{"line_comment_CR", "--c\r", true},
		{"line_comment_CRLF", "--c\r\n", true},
		{"line_comment_then_block", "--c\n/*d*/", true},
		{"block_then_line_comment_LF", "/*c*/ --d\n", true},
		{"line_comment_CR_then_block", "--c\r/*d*/", true},
		{"block_then_line_comment_CR", "/*c*/ --d\r", true},
		{"two_line_comments_CR", "--a\r--b\r", true},
		{"two_line_comments_mixed", "--a\n--b\r", true},
		{"line_then_space_then_line_CR", "--a\r --b\r", true},
		{"space_then_block", " /*a*/", true},
		{"block_then_space", "/*a*/ ", true},
		{"line_comment_only_no_terminator", "--c", false},
		{"space_then_CR_terminated_line_then_block", "/* a */ --b\r", true},
		{"CR_terminated_line_then_block_comment", "--b\r/*a*/", true},
		{"empty", "", true},
		{"multi_space", "     ", true},
		{"CR_then_space", "\r ", true},
	}
	if len(shapes) != 30 {
		t.Fatalf("test construction error: expected exactly 30 shapes, got %d", len(shapes))
	}

	agree := 0
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			stmt := "CREATE OR" + s.sep + "REPLACE FUNCTION public." + a18MxFuncName + "(x int)\nRETURNS int\nLANGUAGE plpgsql\nAS $$BEGIN RETURN x; END;$$;\n"
			accepted, _, _ := a18MxProbe(t, ctx, conn, stmt)
			bodies, _, gateErr := a18ExtractLiveOverload(t, stmt)
			gateAccepts := gateErr == nil && bodies > 0
			t.Logf("shape=%-42s PG=%-9v gate bodies=%d err=%v", s.name, accepted, bodies, gateErr)
			if accepted == gateAccepts {
				agree++
			} else {
				t.Errorf("shape %s: PostgreSQL accepted=%v, gate found a body=%v -- disagreement", s.name, accepted, gateAccepts)
			}
		})
	}
	t.Logf("D144(b) SEPARATOR GRAMMAR: the fixed gate agrees with PostgreSQL on %d/%d shapes", agree, len(shapes))
	if agree != len(shapes) {
		t.Fatalf("ADR-0007 Addendum 18 D144(b): expected 30/30 agreement, got %d/%d", agree, len(shapes))
	}
}
