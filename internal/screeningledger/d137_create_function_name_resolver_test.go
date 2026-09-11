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
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// createFunctionKeywordRe finds every occurrence of the CREATE [OR
// REPLACE] FUNCTION keyword sequence, independent of what follows it --
// the flat scan D137(b) requires, so a declaration inside a dollar-quoted
// EXECUTE string (SchemaSQL's own shape) is still found. \b anchors both
// ends so "FUNCTIONAL" or similar cannot false-match.
var createFunctionKeywordRe = regexp.MustCompile(`\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b`)

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
// -- / /* */ comments around the dot" D137(a) names explicitly. Returns
// idx unchanged (rather than failing) on an unterminated block comment;
// the caller's own subsequent parse (identifier lex, or the final "("
// check) fails closed on the resulting malformed text.
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
			end := strings.Index(source[idx+2:], "*/")
			if end < 0 {
				return idx
			}
			idx += 2 + end + 2
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
