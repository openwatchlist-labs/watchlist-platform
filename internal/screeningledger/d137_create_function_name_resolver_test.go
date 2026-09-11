// ADR-0007 Addendum 16 D137 (CAP #15's H-A, MEDIUM): extractFunctionBodies
// (d92_digest_gate_derivation_test.go) located a declared function's
// bodies with a BARE-NAME regex -- CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+
// <bare funcName>\s*\( -- which is blind to any schema-qualified,
// differently-cased, or quoted spelling of the identical function: a
// valid `CREATE OR REPLACE FUNCTION public.screening_ledger_purge_snapshots(...)`
// places `public.` between the keyword and the name, the pattern never
// matches, and the body enters no population at all (zero bodies found,
// silently). Every source-gate member routes through this one extractor,
// so its blindness was a fail-open hole shared by all of them.
//
// This file supplies the fix: a deliberately narrow, hand-written,
// stdlib-only parser for exactly the CREATE FUNCTION name production --
// [ schema_ident . ] func_ident -- lexed with PostgreSQL's own rules
// (unquoted folds to lowercase; quoted preserves case, "" unescaped;
// arbitrary whitespace and -- / block comments between tokens). The
// extractor keeps its shipped FLAT scan (does not skip comments or
// dollar-quoted regions -- a top-level tokenizer that does was built and
// refuted by execution: SchemaSQL's own guard/definer functions live
// INSIDE `EXECUTE $exec$CREATE ... FUNCTION ...$func$ $exec$`, a live
// bootstrap path, and a region-skipping scan misses every one of them).
// The name-then-"(" shape is the SOLE discriminator between a real
// declaration and a prose mention (the `020:165` comment contains
// "CREATE OR REPLACE FUNCTION succeeds without a preceding", which
// resolves to a legitimate identifier "succeeds" not followed by "(",
// and is therefore skipped rather than treated as a declaration or a
// parse failure). A name this narrow parser cannot resolve to an
// identity -- U&"..." Unicode-escape identifiers, the one PostgreSQL
// identifier form outside {unquoted, quoted} it does not model -- is a
// NAMED, SURFACED failure (an error returned to the caller), never a
// silently skipped body: R64's accepted risk is that this may false-fail
// a future declaration using such a form, which is the safe direction.
//
// No SQL-parser dependency (pg_query_go / libpg_query / pganalyze) is
// used or introduced -- CLAUDE.md rule 1 forbids it, and this parser
// models exactly one grammar production, never a general SQL grammar.
// No live-connection resolve is used -- D92's own property is that this
// gate is DSN-free, and identity resolution here is entirely offline,
// over the source text.
package screeningledger

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ADR-0007 Addendum 17 D139 (CAP #16's K-A, MEDIUM): stage-1 keyword
// detection was a regexp, `\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b`,
// whose `\s+` matches whitespace but NOT a SQL comment. PostgreSQL treats
// a comment between the CREATE/OR/REPLACE/FUNCTION keyword tokens as
// whitespace and creates/replaces the identical function (measured on PG
// 17: `CREATE OR/**/REPLACE FUNCTION ...` is accepted), so a
// comment-mid-keyword rogue was invisible to the regex -- the flat scan
// found nothing and extractFunctionBodies returned 0 bodies with a nil
// error (a silent fail-open, one token earlier than D137's H-A). D137 had
// already made the *name* production (stage 2, resolveCreateFunctionName)
// comment/whitespace-tolerant via skipWSAndComments; K-A is that same
// tolerance un-applied to the keyword sequence that precedes it.
//
// The fix closes the WHOLE CREATE FUNCTION header's tokenization as one
// mechanism rather than a second regex spelling: the same skipWSAndComments
// D137 wrote for the name production is now applied between EVERY adjacent
// header token -- the keyword sequence AND the name -- so any run of
// whitespace and comments is a uniform separator throughout, by
// construction. scanCreateFunctionKeyword replaces the regex, matching the
// keyword tokens with lexPgIdentifier (whose maximal-run lexing gives the
// `\b` word-boundary property more tightly than `\b` did: procreate /
// FUNCTIONAL cannot false-match) and skipWSAndComments between them.
//
// Two subtleties measured against live PG 17 and handled by construction:
//   - PG block comments NEST (SQL-standard): `/* a /* b */ c */` is one
//     comment; `/* a /* b */` alone is "unterminated". skipWSAndComments
//     is depth-tracked so its balance rule matches PG's exactly (balanced
//     <=> PG accepts <=> the skip completes) -- a first-"*/" scan would
//     stop early and mis-parse a nested comment into a fail-open miss.
//   - The START boundary is `\b` (ASCII letter/digit/_), which must EXCLUDE
//     '$' from the boundary set, because SchemaSQL's declarations are
//     $exec$CREATE FUNCTION... -- the flat scan must reach a CREATE that
//     immediately follows a dollar-quote '$'. isAsciiWordChar is that set.

// isAsciiWordChar is the `\b` word-character set the removed
// createFunctionKeywordRe relied on: ASCII letter, digit, or underscore.
// It deliberately EXCLUDES '$' so a CREATE immediately following a
// dollar-quote delimiter ($exec$CREATE FUNCTION..., SchemaSQL's own shape,
// postgres.go:2010/2047/2121/2122) is still a keyword-scan candidate.
func isAsciiWordChar(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// matchCreateFunctionKeyword verifies the token sequence
// CREATE [OR REPLACE] FUNCTION beginning at idx (the start of a "create"
// token), applying skipWSAndComments -- the SAME whitespace/comment skipper
// stage 2 uses for the name production -- between every adjacent keyword
// token. Each keyword is matched by lexing one identifier token
// (lexPgIdentifier folds unquoted identifiers to lowercase, so case is
// handled) and comparing the folded value. Returns the byte offset
// immediately after FUNCTION and true on a full match; false otherwise (a
// different CREATE ..., or an unterminated comment PG itself rejects, in
// which case the caller simply keeps scanning -- PG created nothing, so
// there is no body to miss).
func matchCreateFunctionKeyword(source string, idx int) (afterKeyword int, ok bool) {
	expect := func(word string, at int) (int, bool) {
		tok, next, lok := lexPgIdentifier(source, at)
		if !lok || tok != word {
			return at, false
		}
		return next, true
	}
	at, ok := expect("create", idx)
	if !ok {
		return idx, false
	}
	at = skipWSAndComments(source, at)
	if tok, next, lok := lexPgIdentifier(source, at); lok && tok == "or" {
		at = skipWSAndComments(source, next)
		if at, ok = expect("replace", at); !ok {
			return idx, false
		}
		at = skipWSAndComments(source, at)
	}
	if at, ok = expect("function", at); !ok {
		return idx, false
	}
	return at, true
}

// scanCreateFunctionKeyword finds the next CREATE [OR REPLACE] FUNCTION
// keyword header at or after `from`, returning the header's start, the
// offset immediately after FUNCTION, and ok=true; ok=false when none
// remains. This is the flat-scan replacement for createFunctionKeywordRe
// (D139): it keeps the shipped flat scan (it does NOT skip comments or
// dollar-quoted regions at the scan level, so SchemaSQL's $exec$-embedded
// declarations are still found) and defers comment tolerance entirely to
// skipWSAndComments inside matchCreateFunctionKeyword.
func scanCreateFunctionKeyword(source string, from int) (kwStart, afterKeyword int, ok bool) {
	for pos := from; pos < len(source); {
		cand := indexFoldC(source, pos)
		if cand < 0 {
			return 0, 0, false
		}
		if cand > 0 && isAsciiWordChar(source[cand-1]) {
			// not a token start (procreate, a_create, $-excluded handled by
			// isAsciiWordChar): advance past this 'c'/'C' and keep scanning.
			pos = cand + 1
			continue
		}
		if after, matched := matchCreateFunctionKeyword(source, cand); matched {
			return cand, after, true
		}
		pos = cand + 1
	}
	return 0, 0, false
}

// indexFoldC returns the next index >= from whose byte is 'c' or 'C', or -1.
func indexFoldC(source string, from int) int {
	for i := from; i < len(source); i++ {
		if source[i] == 'c' || source[i] == 'C' {
			return i
		}
	}
	return -1
}

// resolveCreateFunctionName parses the PostgreSQL grammar production
// "[ schema_ident . ] func_ident" starting at byte offset idx in source
// (idx is normally immediately after a CREATE [OR REPLACE] FUNCTION
// keyword match, but the parser itself skips leading whitespace/comments
// so the caller need not). It returns:
//   - schema: "" if the schema part is absent (search-path-relative);
//     otherwise the resolved schema identifier (folded if unquoted,
//     preserved if quoted).
//   - name: the resolved function-name identifier, same rules.
//   - afterIdx: the byte offset immediately following the name
//     production, itself past any trailing whitespace/comments -- so a
//     caller can test source[afterIdx] == '(' directly as the
//     declaration-vs-prose discriminator.
//   - ok: false iff the text at idx does not begin with a syntactically
//     valid PostgreSQL identifier this narrow parser models (including
//     a U&"..." Unicode-escape identifier, which it explicitly does NOT
//     model) -- the caller's contract is to treat ok==false as a
//     surfaced failure, never a silent skip.
func resolveCreateFunctionName(source string, idx int) (schema, name string, afterIdx int, ok bool) {
	idx = skipWSAndComments(source, idx)
	ident1, next1, ok1 := lexPgIdentifier(source, idx)
	if !ok1 {
		return "", "", idx, false
	}
	afterIdent1 := skipWSAndComments(source, next1)
	if afterIdent1 < len(source) && source[afterIdent1] == '.' {
		afterDot := skipWSAndComments(source, afterIdent1+1)
		ident2, next2, ok2 := lexPgIdentifier(source, afterDot)
		if !ok2 {
			return "", "", idx, false
		}
		return ident1, ident2, skipWSAndComments(source, next2), true
	}
	return "", ident1, afterIdent1, true
}

// lexPgIdentifier lexes exactly one PostgreSQL identifier token starting
// at idx: a double-quoted delimited identifier (case preserved, ""
// unescaped to "), or an unquoted identifier (letter/underscore start,
// letter/digit/underscore/$ continuation, folded to lower case -- this
// repository's own identifiers are ASCII throughout, so ASCII case
// folding is exact for every spelling this repository ships or could
// ship under D137's own grammar-production argument).
//
// A U&"..." (or u&"...") Unicode-escape identifier is detected and
// explicitly rejected (ok=false) BEFORE the unquoted path would
// otherwise mis-lex it as the one-letter identifier "u" followed by
// unconsumed "&\"...\"" -- CLAUDE.md's own "no tolerance" rule: a form
// this narrow parser does not model must fail closed, never silently
// resolve to the wrong (or a truncated) identity.
func lexPgIdentifier(source string, idx int) (normalized string, next int, ok bool) {
	if idx >= len(source) {
		return "", idx, false
	}
	if source[idx] == '"' {
		return lexQuotedIdentifier(source, idx)
	}
	if (source[idx] == 'U' || source[idx] == 'u') &&
		idx+2 < len(source) && source[idx+1] == '&' && source[idx+2] == '"' {
		return "", idx, false
	}
	r, size := utf8.DecodeRuneInString(source[idx:])
	if r == utf8.RuneError || !isPgIdentStart(r) {
		return "", idx, false
	}
	j := idx + size
	for j < len(source) {
		r2, size2 := utf8.DecodeRuneInString(source[j:])
		if r2 == utf8.RuneError || !isPgIdentCont(r2) {
			break
		}
		j += size2
	}
	return strings.ToLower(source[idx:j]), j, true
}

// lexQuotedIdentifier lexes a double-quoted delimited identifier
// starting at idx (source[idx] == '"'), preserving case and unescaping
// the doubled-quote "" -> " rule PostgreSQL itself applies. ok=false on
// an unterminated quote.
func lexQuotedIdentifier(source string, idx int) (normalized string, next int, ok bool) {
	var b strings.Builder
	j := idx + 1
	for {
		if j >= len(source) {
			return "", idx, false
		}
		if source[j] == '"' {
			if j+1 < len(source) && source[j+1] == '"' {
				b.WriteByte('"')
				j += 2
				continue
			}
			return b.String(), j + 1, true
		}
		b.WriteByte(source[j])
		j++
	}
}

// skipWSAndComments advances idx past any run of whitespace, "--" line
// comments, and "/* */" block comments -- the "optional whitespace and
// -- / /* */ comments" separating tokens throughout the CREATE FUNCTION
// header (ADR-0007 Addendum 17 D139: applied between the keyword tokens
// too, not only around the name's dot D137(a) named). Returns the start of
// an unterminated block comment (rather than failing) so the caller's own
// subsequent parse (identifier lex, or the final "(" check) fails closed
// on the resulting malformed text -- which PG itself also rejects, so no
// function is created.
//
// ADR-0007 Addendum 17 D139: block comments NEST in PostgreSQL (measured on
// PG 17: "/* a /* b */ c */" is ONE comment; "/* a /* b */" alone is
// "unterminated"). depth is tracked so the whole balanced run is consumed
// as a single separator; a first-"*/" scan (the pre-D139 code) stops after
// the inner close and, applied to the keyword header, mis-parses a nested
// comment into a fail-open miss. The nested balance rule matches PG's lexer
// exactly: balanced <=> PG accepts <=> this skip completes.
func skipWSAndComments(source string, idx int) int {
	for idx < len(source) {
		switch {
		case isPgSpace(source[idx]):
			idx++
		case idx+1 < len(source) && source[idx] == '-' && source[idx+1] == '-':
			idx += 2
			for idx < len(source) && source[idx] != '\n' {
				idx++
			}
		case idx+1 < len(source) && source[idx] == '/' && source[idx+1] == '*':
			start := idx
			depth := 1
			idx += 2
			for idx < len(source) && depth > 0 {
				switch {
				case idx+1 < len(source) && source[idx] == '/' && source[idx+1] == '*':
					depth++
					idx += 2
				case idx+1 < len(source) && source[idx] == '*' && source[idx+1] == '/':
					depth--
					idx += 2
				default:
					idx++
				}
			}
			if depth > 0 {
				return start // unterminated -- PG rejects; caller fails closed
			}
		default:
			return idx
		}
	}
	return idx
}

func isPgSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

func isPgIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}

func isPgIdentCont(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
