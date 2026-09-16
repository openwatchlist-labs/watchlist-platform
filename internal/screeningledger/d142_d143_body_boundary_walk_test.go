// ADR-0007 Addendum 18 D142/D143 (CAP #17's L-B, HIGH): extractFunctionBodies
// (d92_digest_gate_derivation_test.go) located the argument list's close,
// the body-introducing `AS`, and the body's open dollar-quote tag with
// flat, literal-byte searches -- `strings.Index(source[argsStart:], ")")`,
// `strings.Index(source[afterArgs:], "AS")` (case-sensitive, unanchored
// over the WHOLE remainder of the file), and a regexp (`dollarTagRe`)
// anchored only by `^\s*`. Ten distinct PostgreSQL lexical forms that
// legitimately appear in the routine-option clause list -- a block
// comment, a nested block comment, a `--` line comment (LF/CR/CRLF
// terminated), a plain string (with `”` doubling), an `E'...'` string, a
// `U&'...'` string, a dollar-quoted `SET` value, and a quoted identifier
// -- can carry the letters "AS" where PostgreSQL never lexes a keyword,
// and each one defeats the flat search: the gate reports a body, and
// (measured, d92_digest_gate_derivation_test.go's own construction) it is
// not the one PostgreSQL compiles.
//
// D142's decision: the argument list's close and the body-introducing `as`
// are BOTH located by walking TOKENS forward from the `(` D137's
// resolveCreateFunctionName already found, reusing the SAME skipWSAndComments
// (d137_create_function_name_resolver_test.go) and lexPgIdentifier D137 and
// D139 already use -- no second, parallel mechanism, and no literal-byte
// search survives on this path. D143's decision: the body's own OPEN
// dollar-quote tag is lexed by PostgreSQL's own grammar
// ($([A-Za-z\200-\377_][A-Za-z\200-\377_0-9]*)?$, byte-level so every byte
// of a multi-byte UTF-8 rune -- always >= 0x80 -- satisfies PostgreSQL's own
// \200-\377 class), found at the position the walk's own skip already
// computed -- the redundant tag RE-SEARCH the shipped code performed
// (`strings.Index(source[afterAS:], tag)`) is DELETED, not adjusted,
// because admitting a comment between AS and the tag (D143(a)) makes that
// re-search able to find the tag's text inside the comment and mis-place
// bodyStart -- a fresh instance of L-B inside L-B's own fix. The body's
// CLOSE boundary is unchanged: measured (D143(d), the 18-shape matrix in
// this package) to already agree with PostgreSQL's own <xdolq> scanner on
// every adversarial shape tried, so `strings.Index(source[bodyStart:], tag)`
// stays exactly as it was.
//
// No SQL-parser dependency is used or introduced (CLAUDE.md rule 1): this
// file adds four small, closed-grammar helpers over the source text, none
// of which perform general SQL parsing, and no live-connection resolve
// (D92's DSN-free property is unaffected -- everything in this file runs
// with no DSN; only this package's *_pgx_test.go differential-matrix tests
// require one, and skip cleanly without it).
package screeningledger

import (
	"fmt"
	"strings"
)

// skipArgumentList is ADR-0007 Addendum 18 D142, D141 row 3: walks tokens
// forward from openParenIdx (source[openParenIdx] must be '(', the `(`
// resolveCreateFunctionName's caller already found immediately after the
// function name) to the byte offset of the MATCHING ')' -- paren depth
// counted only over bytes that are not inside a comment, a string literal
// of any PostgreSQL form, a dollar-quoted string, or a quoted identifier,
// so a literal ')' inside a parameter DEFAULT expression (a function call,
// e.g. `DEFAULT length('x')`) or inside a comment/string INSIDE the
// argument list is never mistaken for the list's own close. Returns a
// named, surfaced error (never a silent truncation) if the list never
// closes or if a comment or quoted region inside it is unterminated.
func skipArgumentList(source string, openParenIdx int) (closeParenIdx int, err error) {
	at := openParenIdx + 1
	depth := 1
	for at < len(source) {
		skipped := skipWSAndComments(source, at)
		if isStuckAtUnterminatedComment(source, skipped) {
			return 0, fmt.Errorf("an unterminated block comment inside its argument list")
		}
		at = skipped
		if at >= len(source) {
			break
		}
		next, consumed, terr := skipLexicalToken(source, at)
		if terr != nil {
			return 0, terr
		}
		if consumed {
			at = next
			continue
		}
		switch source[at] {
		case '(':
			depth++
			at++
		case ')':
			depth--
			at++
			if depth == 0 {
				return at - 1, nil
			}
		default:
			at++
		}
	}
	return 0, fmt.Errorf("no closing ')' for its argument list")
}

// findBodyIntroducingAS is ADR-0007 Addendum 18 D142, D141 row 4: walks
// tokens forward from `at` (the byte offset immediately after the argument
// list's own matching ')', i.e. skipArgumentList's own result + 1) to the
// byte offset immediately after the body-introducing `as` keyword token --
// the ONLY mechanism that locates it, replacing the flat, case-sensitive,
// unanchored `strings.Index(source[afterArgs:], "AS")`.
//
// (a) Case is handled because lexPgIdentifier folds every unquoted
// identifier to lower case (d137:239) -- AS, as, As and aS are one token.
// No case-insensitive substring search, EqualFold, or spelling alternation
// is introduced anywhere (D146's withdrawal condition).
//
// (b) The token must be unquoted. A quoted `"as"` is consumed whole by
// skipLexicalToken (never reaches lexPgIdentifier's equality test at all
// in this walk), and a comment-embedded `AS` is not a token start the walk
// ever arrives at, because skipWSAndComments consumes the whole comment as
// one separator.
//
// (c) Every PostgreSQL lexical form whose interior is not tokenized --
// comments (skipWSAndComments), string literals of every form, dollar-
// quoted strings, and quoted identifiers (skipLexicalToken) -- is modeled
// and skipped whole, so a decoy "AS" inside any of them is never a
// candidate token. This list is closed by PostgreSQL's own grammar, not by
// enumerating the CAP's one reported construction.
//
// (d) The walk is BOUNDED at the statement terminator ';'. Reaching it
// (or an unterminated comment/quoted region) is a NAMED, SURFACED failure
// -- never a silent run-on into the next statement -- covering the body
// forms this gate cannot digest (`BEGIN ATOMIC ... END`, `RETURN expr`,
// `LANGUAGE c AS '<file>','<symbol>'`) and any decoy header the flat outer
// scan reached where PostgreSQL never lexed one.
func findBodyIntroducingAS(source string, at int) (afterAS int, err error) {
	for at < len(source) {
		skipped := skipWSAndComments(source, at)
		if isStuckAtUnterminatedComment(source, skipped) {
			return 0, fmt.Errorf("an unterminated block comment before finding an 'AS' keyword")
		}
		at = skipped
		if at >= len(source) {
			break
		}
		if source[at] == ';' {
			return 0, fmt.Errorf("reached the statement terminator ';' before finding an 'AS' keyword -- a body form this gate cannot digest (BEGIN ATOMIC / RETURN expr / LANGUAGE ... AS '<file>','<symbol>'), or a decoy header PostgreSQL never lexed (ADR-0007 Addendum 18 D142(d))")
		}
		next, consumed, terr := skipLexicalToken(source, at)
		if terr != nil {
			return 0, terr
		}
		if consumed {
			at = next
			continue
		}
		if tok, next, ok := lexPgIdentifier(source, at); ok {
			if tok == "as" {
				return next, nil
			}
			at = next
			continue
		}
		at++
	}
	return 0, fmt.Errorf("reached end of source before finding an 'AS' keyword")
}

// isStuckAtUnterminatedComment reports whether skipWSAndComments(source,
// from) returning `at` means it got stuck at an unterminated block
// comment's own start, rather than having cleanly finished. Any time
// skipWSAndComments returns positioned exactly at a "/*" byte pair, it can
// only be because it was unable to consume that comment (depth never
// returned to 0) -- a cleanly finished skip never leaves "/*" unconsumed,
// because skipWSAndComments's own loop re-checks for a comment start after
// every whitespace run it consumes.
func isStuckAtUnterminatedComment(source string, at int) bool {
	return at+1 < len(source) && source[at] == '/' && source[at+1] == '*'
}

// skipLexicalToken is ADR-0007 Addendum 18 D142(c): recognizes and
// consumes, starting at `at`, one of the four kinds of PostgreSQL lexical
// element whose interior is never tokenized -- a string literal (plain,
// `E'...'`, `U&'...'`, `B'...'`, `X'...'`), a dollar-quoted string, or a
// quoted identifier (plain or `U&"..."`) -- checked in the order PostgreSQL
// itself requires (a prefix letter must sit immediately against its quote,
// with no separating whitespace, exactly PostgreSQL's own lexer rule).
// consumed=false, err=nil means `at` is not the start of any of these; the
// caller falls through to lexPgIdentifier (an ordinary identifier or
// keyword token) or a single-byte advance (an operator or punctuation
// character, none of which can carry the letters "AS" as data). A non-nil
// err is a named, surfaced failure -- an unterminated region, or (D142(c)'s
// own measured result) a plain '...' string containing a raw backslash,
// whose extent depends on standard_conforming_strings, a value this
// DSN-free gate has no way to read, so it refuses rather than guessing in
// either direction.
func skipLexicalToken(source string, at int) (next int, consumed bool, err error) {
	if at >= len(source) {
		return at, false, nil
	}
	b := source[at]
	if (b == 'U' || b == 'u') && at+2 < len(source) && source[at+1] == '&' {
		switch source[at+2] {
		case '\'':
			n, serr := scanQuotedRegion(source, at+3, '\'', false, false)
			return n, true, serr
		case '"':
			_, n, ok := lexQuotedIdentifier(source, at+2)
			if !ok {
				return 0, true, fmt.Errorf("an unterminated U&\"...\" quoted identifier")
			}
			return n, true, nil
		}
	}
	if (b == 'E' || b == 'e') && at+1 < len(source) && source[at+1] == '\'' {
		n, serr := scanQuotedRegion(source, at+2, '\'', true, false)
		return n, true, serr
	}
	if (b == 'B' || b == 'b' || b == 'X' || b == 'x') && at+1 < len(source) && source[at+1] == '\'' {
		n, serr := scanQuotedRegion(source, at+2, '\'', false, false)
		return n, true, serr
	}
	switch b {
	case '\'':
		n, serr := scanQuotedRegion(source, at+1, '\'', false, true)
		return n, true, serr
	case '"':
		_, n, ok := lexQuotedIdentifier(source, at)
		if !ok {
			return 0, true, fmt.Errorf("an unterminated quoted identifier")
		}
		return n, true, nil
	case '$':
		if tag, n, ok := lexDollarQuoteTag(source, at); ok {
			closeRel := strings.Index(source[n:], tag)
			if closeRel < 0 {
				return 0, true, fmt.Errorf("a dollar-quoted string whose tag %s is never closed", tag)
			}
			return n + closeRel + len(tag), true, nil
		}
		return at, false, nil
	}
	return at, false, nil
}

// scanQuotedRegion scans a quoted region's content starting at
// contentStart (the byte immediately after its opening delimiter) for
// closeByte, treating a DOUBLED closeByte as an escaped literal delimiter
// -- the rule every one of these string forms shares. If
// allowBackslashEscape, a backslash consumes itself and the following byte
// as one escaped pair (E'...' 's own rule), so an escaped delimiter is
// never reached via doubling either. If refuseOnBackslash, a bare
// backslash before the close is ADR-0007 Addendum 18 D142(c)'s named,
// surfaced ambiguity: a plain '...' string's extent depends on
// standard_conforming_strings (measured on PG 17: the same bytes are
// either 3 characters with the backslash as literal data, or an
// unterminated string, depending on that session setting), which this
// DSN-free gate has no way to read, so it refuses rather than assuming
// either direction.
func scanQuotedRegion(source string, contentStart int, closeByte byte, allowBackslashEscape, refuseOnBackslash bool) (next int, err error) {
	j := contentStart
	for {
		if j >= len(source) {
			return 0, fmt.Errorf("an unterminated quoted region")
		}
		switch {
		case allowBackslashEscape && source[j] == '\\':
			j += 2
		case refuseOnBackslash && source[j] == '\\':
			return 0, fmt.Errorf("a plain quoted string contains a backslash before its closing quote -- its extent depends on standard_conforming_strings, which this DSN-free gate cannot read (ADR-0007 Addendum 18 D142(c)): refusing rather than guessing")
		case source[j] == closeByte:
			if j+1 < len(source) && source[j+1] == closeByte {
				j += 2
				continue
			}
			return j + 1, nil
		default:
			j++
		}
	}
}

// lexDollarQuoteTag is ADR-0007 Addendum 18 D143(c): lexes a PostgreSQL
// dollar-quote tag starting at idx (source[idx] must be '$') by
// PostgreSQL's own grammar, $([A-Za-z\200-\377_][A-Za-z\200-\377_0-9]*)?$,
// applied at the BYTE level rather than the rune level -- every byte of a
// multi-byte UTF-8 rune is >= 0x80, which is exactly PostgreSQL's own
// \200-\377 class, so a byte-level test is exact (not merely approximate)
// for a non-ASCII tag. Replaces `dollarTagRe`
// (`^\s*(\$[A-Za-z0-9_]*\$)`), which both ACCEPTS the digit-leading tags
// PostgreSQL rejects (a tag body may not start with a digit) and REJECTS
// the non-ASCII tags PostgreSQL accepts (its class has no \200-\377
// member) -- measured server-side, both directions, in this package's
// TestD143DollarQuoteTagGrammarDifferentialMatrix.
func lexDollarQuoteTag(source string, idx int) (tag string, next int, ok bool) {
	if idx >= len(source) || source[idx] != '$' {
		return "", idx, false
	}
	j := idx + 1
	if j < len(source) && isDollarTagStart(source[j]) {
		j++
		for j < len(source) && isDollarTagCont(source[j]) {
			j++
		}
	}
	if j >= len(source) || source[j] != '$' {
		return "", idx, false
	}
	j++
	return source[idx:j], j, true
}

func isDollarTagStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b >= 0x80
}

func isDollarTagCont(b byte) bool {
	return isDollarTagStart(b) || (b >= '0' && b <= '9')
}
