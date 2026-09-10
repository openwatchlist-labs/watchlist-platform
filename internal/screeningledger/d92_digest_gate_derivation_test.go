// ADR-0007 Addendum 10 D92/D95 test 6 (N-D, MEDIUM), rewritten by
// Addendum 11 D99 (O-B): the gate that is supposed to keep D77/D87's
// declared digests honest computed a digest, but derived its population
// from a HAND-LISTED set of three files (012, 008g, 020) rather than
// R35's own named mitigation ("extracts both bootstrap paths' literal
// function bodies from db/migrations/*.sql ... and asserts the declared
// set is exactly that set"). Measured at the tree D99 was written
// against: the committed literal set for screening_ledger_purge_snapshots
// is five (008g:1, 019:2, 020:2), the hand list covered two (020's), and
// CLAUDE.md's own named trap -- a hand-maintained enumeration silently
// drifting out of sync with the directory it describes -- is exactly
// what fired. Addendum 11 adds a sixth and seventh literal (021's two
// ALL-expired bodies, D98), which is what makes the population a moving
// target this gate must track by scan, not by list.
//
// This file derives its population from db/migrations/*.sql by directory
// glob -- the same one .github/workflows/ci.yml and run-ci.sh apply --
// plus SchemaSQL, for every declared function. Files are walked in the
// glob's own sorted order (the same lexical order the migration runner
// applies them in), and for a function with more than one CREATE [OR
// REPLACE] FUNCTION statement across that ordered population, the LAST
// one is the live body a fully-migrated database actually has -- exactly
// Postgres's own CREATE OR REPLACE semantics. The gate asserts that live
// literal's digest EQUALS the declared accepted digest for that
// bootstrap path (not merely that the accepted digest appears somewhere
// in history), which is what makes a new migration file that changes a
// declared function's body without updating the declared constant a gate
// failure -- with no edit to this file, since the file list is never
// named here.
//
// D99(b): every OTHER (non-live, historical) committed literal for a
// declared function must digest to something outside every declared
// accepted set for that function, so a superseded body (008g's original
// ON CONFLICT DO NOTHING form, or 020's now-superseded ANY-expired
// predicate) can never be silently readopted by a future edit that
// happens to reproduce it.
package screeningledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// extractedBody is one CREATE [OR REPLACE] FUNCTION statement's
// dollar-quoted body, found by scanning a source text (a migration
// file's full contents, or SchemaSQL) for a declared function name.
type extractedBody struct {
	source string // file path, or "SchemaSQL"
	args   string // the raw parameter-list text, for overload disambiguation
	body   string
}

var dollarTagRe = regexp.MustCompile(`^\s*(\$[A-Za-z0-9_]*\$)`)

// extractFunctionBodies scans source for every occurrence of "CREATE [OR
// REPLACE] FUNCTION <funcName>(...) ... AS <tag> <body> <tag>", in the
// order they appear, and returns each body found, tagged with
// sourceLabel and its raw parameter list (so a caller can disambiguate
// overloads sharing one name). None of the parameter lists or return
// types this repository ships contain a literal ")" before the argument
// list's own close, so the first ")" after the opening "(" is that
// close; none contain the literal substring "AS" before their own
// dollar-quote tag either.
func extractFunctionBodies(t *testing.T, source, sourceLabel, funcName string) []extractedBody {
	t.Helper()
	var results []extractedBody
	nameRe := regexp.MustCompile(`CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+` + regexp.QuoteMeta(funcName) + `\s*\(`)
	rest := source
	for {
		loc := nameRe.FindStringIndex(rest)
		if loc == nil {
			break
		}
		argsStart := loc[1]
		closeRel := strings.Index(rest[argsStart:], ")")
		if closeRel < 0 {
			t.Fatalf("%s: found %q with no closing ')' for its argument list", sourceLabel, funcName)
		}
		argsText := rest[argsStart : argsStart+closeRel]
		afterArgs := rest[argsStart+closeRel+1:]
		asIdx := strings.Index(afterArgs, "AS")
		if asIdx < 0 {
			t.Fatalf("%s: found %q with no 'AS' after its argument list", sourceLabel, funcName)
		}
		afterAS := afterArgs[asIdx+2:]
		tagMatch := dollarTagRe.FindStringSubmatch(afterAS)
		if tagMatch == nil {
			t.Fatalf("%s: found %q with no dollar-quote tag immediately after AS", sourceLabel, funcName)
		}
		tag := tagMatch[1]
		bodyStart := strings.Index(afterAS, tag) + len(tag)
		closeIdx := strings.Index(afterAS[bodyStart:], tag)
		if closeIdx < 0 {
			t.Fatalf("%s: found %q whose dollar-quote tag %s is never closed", sourceLabel, funcName, tag)
		}
		body := afterAS[bodyStart : bodyStart+closeIdx]
		results = append(results, extractedBody{source: sourceLabel, args: strings.TrimSpace(argsText), body: body})
		advance := argsStart + closeRel + 1 + asIdx + 2 + bodyStart + closeIdx + len(tag)
		rest = rest[advance:]
	}
	return results
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

// declaredFunction is one function (or one overload of a function that
// has more than one) this gate holds a declared, accepted digest for,
// per bootstrap path -- exactly one accepted digest per path, since that
// is the live body a fully-migrated or SchemaSQL-bootstrapped database
// actually has.
type declaredFunction struct {
	label    string // for failure messages
	funcName string
	// typeList is ADR-0007 Addendum 13 D118: "" if the function has only
	// one overload; otherwise the complete canonicalized argument TYPE
	// list (argTypeList's own output shape, e.g. "text,bigint,
	// timestamptz,text,text") that disambiguates which CREATE FUNCTION
	// match is this overload -- matched by EQUALITY against a candidate
	// body's own canonicalized type list, never by a prefix of the raw
	// parameter TEXT (D108's pre-D118 rule, which keyed on a leading
	// parameter's NAME and was blind to everything after it).
	typeList          string
	acceptedMigration string
	acceptedSchemaSQL string
}

func declaredFunctions() []declaredFunction {
	return []declaredFunction{
		{
			label:    "owl_reject_truncate",
			funcName: "owl_reject_truncate",
			// ADR-0007 Addendum 9: owl_reject_truncate() has two
			// legitimate digests that differ by bootstrap PATH, not by
			// migration history -- a single declared value false-fails
			// whichever path it wasn't measured on. Both accepted values
			// are checked against BOTH derived populations below via
			// acceptEither.
		},
		{
			label:             "screening_ledger_reject_mutation",
			funcName:          "screening_ledger_reject_mutation",
			acceptedMigration: screeningLedgerRejectMutationBodySHA256,
			acceptedSchemaSQL: screeningLedgerRejectMutationBodySHA256,
		},
		{
			// ADR-0007 Addendum 13 D118: selection is now by the complete
			// canonicalized argument TYPE list, matched by equality --
			// the identity pg_get_function_identity_arguments itself
			// returns -- not by a prefix of the raw parameter TEXT.
			// D34's own finding: a prefix match keys on a leading
			// parameter's NAME, so a rogue body whose leading parameter
			// is merely respelled ("p_before" vs "p_notbefore") is caught
			// by name alone, while one that keeps the declared name
			// ("p_before") is invisible regardless of what follows it --
			// a type list is blind to names and requires every position
			// to agree.
			label:             "screening_ledger_purge_snapshots(ledger scalar corroboration,...)",
			funcName:          "screening_ledger_purge_snapshots",
			typeList:          "text,bigint,timestamptz,text,text",
			acceptedMigration: purgeSnapshotsTimeFloorBodySHA256Migration,
			acceptedSchemaSQL: purgeSnapshotsTimeFloorBodySHA256SchemaSQLBoot,
		},
		{
			label:             "screening_ledger_purge_snapshots(p_snapshot_sha256 text[],...)",
			funcName:          "screening_ledger_purge_snapshots",
			typeList:          "text[],text,int[],timestamptz[],text,text",
			acceptedMigration: purgeSnapshotsArrayFormBodySHA256Migration,
			acceptedSchemaSQL: purgeSnapshotsArrayFormBodySHA256SchemaSQLBoot,
		},
	}
}

// migrationFilePaths glob-scans dir (the same glob shape
// .github/workflows/ci.yml's "Apply database migrations" step and
// run-ci.sh apply), sorted -- filepath.Glob already returns lexical
// order, which is migration application order for this repository's
// NNN_name.sql convention.
func migrationFilePaths(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no *.sql files found under %s -- glob is broken", dir)
	}
	return paths
}

// typeSpellingAliases is ADR-0007 Addendum 12 D108(a): a declared,
// closed map from every type spelling PostgreSQL accepts for a type
// this repository's declared functions actually use, to one canonical
// spelling -- measured over db/migrations/*.sql's declared-function
// signatures rather than guessed. Four types are in use there:
// timestamptz, text[], int (PostgreSQL's own alias for int4/integer,
// used for p_expected_count in 022), and bigint. Each gains its
// documented PostgreSQL alias -- the exact "timestamptz" <-> "timestamp
// with time zone" respelling P-C demonstrated pg_dump/psql \df emit
// routinely, plus the same equivalence for the other three types a
// future migration or pg_dump run could just as easily spell
// differently. This is D72's shape exactly: an explicit, declared
// allowlist whose membership is enumerated from the tree, not a pattern
// and not a range -- and it is normalisation ONLY, never a substitute
// for D108(b)'s no-body-dropped assertion below, which is the half that
// survives an alias this map does not yet know about.
var typeSpellingAliases = []struct{ from, to string }{
	{"timestamp with time zone", "timestamptz"},
	{"text ARRAY", "text[]"},
	{"integer", "int"},
	{"int4", "int"},
	{"int8", "bigint"},
}

// canonicalizeArgs applies typeSpellingAliases to a raw parameter-list
// text, so two signatures that differ only in which PostgreSQL-
// recognized spelling they use for the same type compare equal. Applied
// to BOTH sides of every comparison below -- the gate's own selection
// rule, D108's fix -- so an unmapped spelling still fails safe (falls
// through unchanged and simply fails to match, which
// derivedPopulationForFunction's no-drop assertion then catches and
// names, rather than the pre-D108 gate's silent population drop).
func canonicalizeArgs(args string) string {
	for _, a := range typeSpellingAliases {
		args = strings.ReplaceAll(args, a.from, a.to)
	}
	return args
}

// argTypeList is ADR-0007 Addendum 13 D118: the complete canonicalized
// argument TYPE list, in order, comma-joined -- e.g.
// "text[],text,int[],timestamptz[],text,text" -- extracted from a raw
// parameter-list text already run through canonicalizeArgs. This is the
// identity PostgreSQL itself resolves overloads by
// (pg_get_function_identity_arguments returns exactly this shape), used
// in place of a HasPrefix match on the raw parameter TEXT: D34's own
// finding is that a leading parameter's NAME (not its type) is what a
// prefix match keys on, so a rogue body whose leading parameter is
// merely renamed ("p_notbefore" vs the declared "p_before") is caught
// by name alone -- while one whose leading parameter matches
// ("p_before") is invisible regardless of what follows it, because a
// prefix match never inspects the rest of the list. A type list, by
// contrast, is blind to parameter names entirely and requires every
// position to agree.
func argTypeList(canonicalArgs string) string {
	if strings.TrimSpace(canonicalArgs) == "" {
		return ""
	}
	parts := splitTopLevelComma(canonicalArgs)
	types := make([]string, 0, len(parts))
	for _, p := range parts {
		fields := strings.Fields(p)
		if len(fields) == 0 {
			continue
		}
		// ADR-0007 Addendum 14 D127(b): PostgreSQL excludes OUT
		// parameters from a function's IDENTITY arguments (IN, INOUT and
		// VARIADIC are all included -- pg_get_function_identity_arguments
		// itself omits only OUT). Counting an OUT parameter here shifts
		// the computed type list away from what Postgres itself would
		// resolve -- the gate and the server disagreeing about which
		// object a body declares -- and (measured) can make the shifted
		// list collide with a shorter DECLARED or RETIRED signature that
		// the true identity does not match at all.
		if len(fields) >= 2 && strings.EqualFold(fields[0], "OUT") {
			continue
		}
		types = append(types, fields[len(fields)-1])
	}
	return strings.Join(types, ",")
}

// splitTopLevelComma splits s on "," outside of any parenthesized
// group. None of this repository's declared parameter-list types
// contain a literal comma (int[], text[], timestamptz, bigint, text),
// so this is defensive rather than load-bearing today, matching the
// same posture extractFunctionBodies already takes on ")".
func splitTopLevelComma(s string) []string {
	var parts []string
	depth := 0
	last := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(s[last:i]))
				last = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(s[last:]))
	return parts
}

// derivedPopulation returns every body extracted for this
// declaredFunction across migrationDir's *.sql files (in apply order)
// and SchemaSQL, each tagged with its source.
func (d declaredFunction) derivedPopulation(t *testing.T, migrationDir string) (migration []extractedBody, schemaSQL []extractedBody) {
	t.Helper()
	for _, path := range migrationFilePaths(t, migrationDir) {
		content := mustReadFile(t, path)
		for _, found := range extractFunctionBodies(t, content, path, d.funcName) {
			if d.typeList != "" && argTypeList(canonicalizeArgs(found.args)) != d.typeList {
				continue
			}
			migration = append(migration, found)
		}
	}
	for _, found := range extractFunctionBodies(t, SchemaSQL, "SchemaSQL", d.funcName) {
		if d.typeList != "" && argTypeList(canonicalizeArgs(found.args)) != d.typeList {
			continue
		}
		schemaSQL = append(schemaSQL, found)
	}
	return migration, schemaSQL
}

// retiredFunctionTypeLists is ADR-0007 Addendum 12 D107's own DROP
// FUNCTION targets (022_screening_ledger_purge_chain_corroboration.sql),
// re-declared by ADR-0007 Addendum 13 D118 as a closed set of complete
// canonicalized argument TYPE lists rather than name-prefixes: two
// signatures that were once live and are now deliberately, entirely
// retired -- not respelled, not superseded-but-still-the-same-shape
// (that is D99(b)'s own, separate concern), but DROPPED, so no current
// declaredFunctions() entry describes them at all and none ever should
// again. Declared here as a closed set (D31's "a closed set of objects,
// not a name pattern") specifically so assertNoBodyDropped below can
// tell "this body belongs to a signature that no longer exists at all"
// apart from "this body is an unplaceable respelling of one that does"
// -- the two are opposite findings and must not share a code path.
// acceptedBodySHA256 is ADR-0007 Addendum 14 D127(a): a retired type
// list classifies a body, it does not exempt one. Every historical
// committed literal that ever bore this signature, measured (not
// guessed) as sha256(prosrc) directly from db/migrations/008g, 019, 020
// and 021 -- so a resurrected retired signature (a rogue file that
// redeclares this exact type list) must digest to a body this repository
// actually, provably shipped under that signature, or it is a named
// failure identifying the file, the signature and the live digest,
// exactly as an unplaceable body already is.
var retiredFunctionTypeLists = []struct {
	funcName           string
	typeList           string
	acceptedBodySHA256 []string
}{
	{
		funcName: "screening_ledger_purge_snapshots",
		typeList: "timestamptz,text,text",
		acceptedBodySHA256: []string{
			"8c79260649f6cdb70371fa480c9c47fe59ab414f513c01aaa497a9d5fd3ef218", // 008g
			"e80813611e57d750ca54ecb04898bc22bbf3ee63ac5ef7c0a52c825b2e082aea", // 019
			"eed7e96d9d341a3f2e9b53a64e8367e9bbeaeae4747fbb1eda28552ec2b079c5", // 020
			"5e919d8e7e9fb4716e2f081e73e370d1411785944f7015460771e5b4376a5482", // 021 (last, before 022 dropped it)
		},
	},
	{
		funcName: "screening_ledger_purge_snapshots",
		typeList: "text[],timestamptz,text,text",
		acceptedBodySHA256: []string{
			"e679f4a157c743fa375da26b3625ad1e08a31cd0a430ab786c78fe4769ee065a", // 019
			"67964968abee18790da2bc609ba653a1cc287a6ea10e02e30a12ad8a92f113c4", // 020 (D87/D86 row 8's own constant)
			"ccb592a2abaff65e144b79be5be4a0bea5449f7bc3394e7fd496b3e4efb75d8c", // 021 (last, before 022 dropped it)
		},
	},
}

// retiredSignatureAcceptedDigests returns the known historical accepted
// digest set for a retired signature, or nil if canonicalArgs does not
// match one (callers check isRetiredSignature first).
func retiredSignatureAcceptedDigests(funcName, canonicalArgs string) []string {
	found := argTypeList(canonicalArgs)
	for _, r := range retiredFunctionTypeLists {
		if r.funcName == funcName && found == r.typeList {
			return r.acceptedBodySHA256
		}
	}
	return nil
}

func isRetiredSignature(funcName, canonicalArgs string) bool {
	found := argTypeList(canonicalArgs)
	for _, r := range retiredFunctionTypeLists {
		if r.funcName == funcName && found == r.typeList {
			return true
		}
	}
	return false
}

// assertNoBodyDropped is ADR-0007 Addendum 12 D108(b), corrected by
// ADR-0007 Addendum 13 D118 (AR7): the half that survives an alias
// typeSpellingAliases does not yet know about, now selecting and
// retiring by the complete canonicalized argument TYPE list, matched by
// EQUALITY, rather than a HasPrefix match on the raw parameter TEXT.
// D118's own finding: the pre-D118 rule keyed on a leading parameter's
// NAME (its shortest disambiguating prefix), so a rogue body whose
// leading parameter is respelled ("p_before" -> "p_notbefore") was
// caught, while one that keeps the declared retired name ("p_before")
// was invisible regardless of every parameter after it -- D108(b)'s own
// stated property ("a body that fails to map to any declared overload
// is a failure, never a silent discard") was false for exactly that
// class. For every *.sql file under migrationDir, and for every
// declared function NAME appearing in declaredFunctions() (grouped,
// since screening_ledger_purge_snapshots has two): every extracted body
// that is not a known-retired signature (retiredFunctionTypeLists) must
// match EXACTLY ONE declared overload's canonicalized type list. A body
// matching NONE is named as a failure -- an unplaceable body, exactly
// what a differently-spelled OR differently-named-but-same-shape
// signature produced under the pre-D118 gate: the population silently
// one smaller, the gate reporting PASS. A body matching MORE THAN ONE
// overload is also named as a failure -- two declared overloads whose
// canonicalized type lists are not mutually exclusive is a defect in
// the declaration, not a body to silently prefer one reading of.
func assertNoBodyDropped(t *testing.T, migrationDir string) error {
	t.Helper()
	byName := map[string][]declaredFunction{}
	for _, d := range declaredFunctions() {
		byName[d.funcName] = append(byName[d.funcName], d)
	}
	for _, path := range migrationFilePaths(t, migrationDir) {
		content := mustReadFile(t, path)
		for funcName, overloads := range byName {
			for _, f := range extractFunctionBodies(t, content, path, funcName) {
				canonicalFound := canonicalizeArgs(f.args)
				if isRetiredSignature(funcName, canonicalFound) {
					// ADR-0007 Addendum 14 D127(a): a retired type list
					// classifies a body, it does NOT exempt one -- the
					// body must still digest to a known historical
					// committed literal for that signature, or this is a
					// named failure (a resurrected retired signature
					// carrying a body this repository never shipped
					// under it), not a silent skip.
					digest := digestHexString(f.body)
					accepted := retiredSignatureAcceptedDigests(funcName, canonicalFound)
					placed := false
					for _, a := range accepted {
						if a == digest {
							placed = true
							break
						}
					}
					if !placed {
						return fmt.Errorf("ADR-0007 Addendum 14 D127: %s defines %s(%s), a retired signature (type list %s) whose body digests to %s -- not a member of the known historical committed set %v: a retired type list classifies a body, it does not exempt one", path, funcName, f.args, argTypeList(canonicalFound), digest, accepted)
					}
					continue
				}
				foundTypeList := argTypeList(canonicalFound)
				var matched []string
				for _, d := range overloads {
					if d.typeList == "" || foundTypeList == d.typeList {
						matched = append(matched, d.label)
					}
				}
				if len(matched) == 0 {
					return fmt.Errorf("ADR-0007 Addendum 13 D118: %s defines %s(%s), which does not match any declared overload's argument type list (checked against typeSpellingAliases) and is not a declared-retired signature either -- an unplaceable body, dropped from every declared overload's population rather than silently discarded", path, funcName, f.args)
				}
				if len(matched) > 1 {
					return fmt.Errorf("ADR-0007 Addendum 13 D118: %s defines %s(%s), which matches MORE THAN ONE declared overload (%v) -- their typeList values are not mutually exclusive", path, funcName, f.args, matched)
				}
			}
		}
	}
	return nil
}

// checkLiveDigestMatchesAccepted asserts the LAST literal in migration
// (apply order) -- the one CREATE OR REPLACE FUNCTION actually leaves
// live -- digests to the declared accepted value, and does the same for
// the (necessarily singular) SchemaSQL literal. Returns a descriptive
// error rather than failing a *testing.T directly, so it can be run
// against a constructed directory in the required negative test without
// aborting that test's own goroutine.
func checkLiveDigestMatchesAccepted(t *testing.T, d declaredFunction, migrationDir string) error {
	t.Helper()
	migration, schemaSQL := d.derivedPopulation(t, migrationDir)
	if len(migration) == 0 {
		return fmt.Errorf("no committed literal found for %s across %s/*.sql", d.label, migrationDir)
	}
	if len(schemaSQL) == 0 {
		return fmt.Errorf("no committed literal found for %s in SchemaSQL", d.label)
	}
	liveMigration := migration[len(migration)-1]
	liveDigest := digestHexString(liveMigration.body)
	if d.acceptedMigration != "" && liveDigest != d.acceptedMigration {
		return fmt.Errorf("ADR-0007 Addendum 11 D99: %s's LIVE migration-path literal (last applied, in %s) digests to %s, which is not the declared accepted digest %s -- either the body changed without updating the declared constant, or an unaccounted-for migration file now runs last", d.label, liveMigration.source, liveDigest, d.acceptedMigration)
	}
	if len(schemaSQL) != 1 {
		return fmt.Errorf("expected exactly 1 SchemaSQL literal for %s, found %d", d.label, len(schemaSQL))
	}
	schemaDigest := digestHexString(schemaSQL[0].body)
	if d.acceptedSchemaSQL != "" && schemaDigest != d.acceptedSchemaSQL {
		return fmt.Errorf("ADR-0007 Addendum 11 D99: %s's SchemaSQL literal digests to %s, which is not the declared accepted digest %s", d.label, schemaDigest, d.acceptedSchemaSQL)
	}
	// owl_reject_truncate (D77/D79): both bootstrap paths may legitimately
	// carry EITHER of the two accepted digests (they diverge by which
	// path built them, not by which is "migration" vs "SchemaSQL"), so
	// for that one function the two acceptedMigration/acceptedSchemaSQL
	// fields above are left blank and this fallback checks membership in
	// owlRejectTruncateAcceptedBodySHA256 instead.
	if d.acceptedMigration == "" && d.acceptedSchemaSQL == "" {
		accepted := map[string]bool{}
		for _, a := range owlRejectTruncateAcceptedBodySHA256 {
			accepted[a] = true
		}
		if !accepted[liveDigest] {
			return fmt.Errorf("ADR-0007 Addendum 9: %s's LIVE migration-path literal digests to %s, not in the declared two-member accepted set %v", d.label, liveDigest, owlRejectTruncateAcceptedBodySHA256)
		}
		if !accepted[schemaDigest] {
			return fmt.Errorf("ADR-0007 Addendum 9: %s's SchemaSQL literal digests to %s, not in the declared two-member accepted set %v", d.label, schemaDigest, owlRejectTruncateAcceptedBodySHA256)
		}
	}
	return nil
}

// TestGuardAndDefinerBodyDigestsAreDerivedFromCommittedLiterals is D92's
// gate, D99's population: the LIVE literal on each bootstrap path -- the
// one a fully-migrated or SchemaSQL-bootstrapped database actually has --
// must digest to the declared accepted value, derived by scanning
// db/migrations/*.sql and SchemaSQL rather than a hand-picked file list.
// Runs with no DSN.
func TestGuardAndDefinerBodyDigestsAreDerivedFromCommittedLiterals(t *testing.T) {
	for _, d := range declaredFunctions() {
		t.Run(d.label, func(t *testing.T) {
			if err := checkLiveDigestMatchesAccepted(t, d, "../../db/migrations"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestSupersededPurgeSnapshotsLiteralsAreNotAccepted is D99(b)'s stronger
// property: every committed literal for a declared function which is NOT
// the live one must digest to something outside EVERY declared accepted
// digest for that function (both bootstrap paths) -- so a superseded
// body (008g's original ON CONFLICT DO NOTHING form, or 020's
// now-superseded ANY-expired predicate) can never be silently readopted,
// and a literal that drifts into agreement with an accepted digest fails
// the gate. 008g's own surviving ON CONFLICT ... DO NOTHING body
// (D99(c): left as committed history, not edited) is the case that
// exists today and is asserted here by derivation, not by naming the
// file.
func TestSupersededPurgeSnapshotsLiteralsAreNotAccepted(t *testing.T) {
	// D87/D86 row 8's own measured digest for 020's now-superseded
	// ANY-expired array-form body, confirmed directly (not through
	// derivedPopulation, which no longer includes it -- see below) so
	// the "measured, not guessed" standard this file's other constants
	// meet is not lost along with the constant that used to hold it.
	//
	// ADR-0007 Addendum 12 D108, corrected by Addendum 13 D118 (AR7):
	// under D118's own type-list-equality selection, NEITHER overload's
	// pre-D107 (p_before timestamptz,...) history matches its current
	// declaration's type list any more. The time-floor overload's OLD
	// signature ("timestamptz,text,text") no longer equals its current
	// type list ("text,bigint,timestamptz,text,text"); the array form's
	// OLD signature ("text[],timestamptz,text,text") no longer equals
	// its current type list either ("text[],text,int[],timestamptz[],
	// text,text") -- under the pre-D118 prefix rule the array form's
	// history was (incorrectly) still matched, because "p_snapshot_sha256
	// text[]" is a prefix of both the old and new signatures alike. Both
	// retired shapes are members of retiredFunctionTypeLists instead, so
	// neither appears in derivedPopulation for any declaredFunctions()
	// entry any more.
	const purgeSnapshotsArrayFormBodySHA256Superseded020 = "67964968abee18790da2bc609ba653a1cc287a6ea10e02e30a12ad8a92f113c4"
	found020Retired := false
	for _, got := range extractFunctionBodies(t, mustReadFile(t, "../../db/migrations/020_screening_ledger_purge_server_side_floor.sql"), "020", "screening_ledger_purge_snapshots") {
		canonicalArgs := canonicalizeArgs(got.args)
		if !isRetiredSignature("screening_ledger_purge_snapshots", canonicalArgs) {
			continue
		}
		if argTypeList(canonicalArgs) != "text[],timestamptz,text,text" {
			continue // the time-floor overload's own retired body, not this one
		}
		found020Retired = true
		if digest := digestHexString(got.body); digest != purgeSnapshotsArrayFormBodySHA256Superseded020 {
			t.Fatalf("ADR-0007 Addendum 10 D87/D86 row 8: expected 020's own retired array-form literal to digest to the known measured value %s, got %s", purgeSnapshotsArrayFormBodySHA256Superseded020, digest)
		}
	}
	if !found020Retired {
		t.Fatal("test construction error: expected 020's own retired array-form signature to be found and classified as retired")
	}
	for _, d := range declaredFunctions() {
		t.Run(d.label, func(t *testing.T) {
			migration, schemaSQL := d.derivedPopulation(t, "../../db/migrations")
			accepted := map[string]bool{}
			if d.acceptedMigration != "" {
				accepted[d.acceptedMigration] = true
			}
			if d.acceptedSchemaSQL != "" {
				accepted[d.acceptedSchemaSQL] = true
			}
			for _, a := range owlRejectTruncateAcceptedBodySHA256 {
				accepted[a] = true // covers the owl_reject_truncate two-member case
			}
			liveMigrationIdx := len(migration) - 1
			for i, got := range migration {
				if i == liveMigrationIdx {
					continue // the live body -- expected to be accepted
				}
				digest := digestHexString(got.body)
				if accepted[digest] {
					t.Fatalf("ADR-0007 Addendum 11 D99: a superseded literal for %s in %s digests to %s, which IS a declared accepted digest -- a superseded body must not silently agree with the live one", d.label, got.source, digest)
				}
			}
			for _, got := range schemaSQL[:len(schemaSQL)-1] {
				digest := digestHexString(got.body)
				if accepted[digest] {
					t.Fatalf("ADR-0007 Addendum 11 D99: a superseded SchemaSQL literal for %s in %s digests to %s, which IS a declared accepted digest", d.label, got.source, digest)
				}
			}
		})
	}
}

// TestDigestGateCatchesWhitespaceAlteredCopy is D92/D95's own required
// negative: the gate must FAIL against a deliberately whitespace-altered
// copy of the live literal for each declared function, while the
// extraction marker still matches -- the exact two variants R35/D92's
// own measurement used (extra leading/trailing space inside the
// delimiters, a trailing newline added). A gate that cannot fail here is
// the shape D92 replaced.
func TestDigestGateCatchesWhitespaceAlteredCopy(t *testing.T) {
	for _, d := range declaredFunctions() {
		t.Run(d.label, func(t *testing.T) {
			migration, _ := d.derivedPopulation(t, "../../db/migrations")
			body := migration[len(migration)-1].body
			original := digestHexString(body)
			accepted := map[string]bool{}
			if d.acceptedMigration != "" {
				accepted[d.acceptedMigration] = true
			}
			for _, a := range owlRejectTruncateAcceptedBodySHA256 {
				accepted[a] = true
			}
			variants := map[string]string{
				"leading_and_trailing_space_doubled": "  " + body + "  ",
				"trailing_newline_added":             body + "\n",
			}
			for name, altered := range variants {
				if digestHexString(altered) == original {
					t.Fatalf("test bug: %s variant %q did not actually change the digest", d.label, name)
				}
				if accepted[digestHexString(altered)] {
					t.Fatalf("ADR-0007 Addendum 10 D92: %s variant %q unexpectedly matched a declared accepted digest -- the gate is not sensitive to whitespace", d.label, name)
				}
			}
		})
	}
}

// TestDigestGateCoversANewMigrationFileWithNoEdit is ADR-0007 Addendum 11
// D99/D103 test 7: the gate must FAIL if a new db/migrations/*.sql file
// introduces a literal for a declared function that no declared digest
// covers -- WITHOUT that file being named anywhere in this test. Built
// by copying the real db/migrations/ directory into a temp directory
// (never named beyond that copy) and appending one rogue file whose name
// sorts after every real migration, so it becomes the LIVE body under
// this gate's own "last in apply order wins" rule; the SAME
// checkLiveDigestMatchesAccepted the real gate above uses is run against
// that temp directory, not a hand-simulated shortcut.
func TestDigestGateCoversANewMigrationFileWithNoEdit(t *testing.T) {
	tempDir := t.TempDir()
	for _, path := range migrationFilePaths(t, "../../db/migrations") {
		content := mustReadFile(t, path)
		dest := filepath.Join(tempDir, filepath.Base(path))
		if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rogueBody := "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_ledger_id text, p_expected_count bigint, p_expected_max timestamptz, p_operator text, p_reason text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN 0; END; $$;\n"
	if err := os.WriteFile(filepath.Join(tempDir, "999_rogue_purge_snapshots.sql"), []byte(rogueBody), 0o644); err != nil {
		t.Fatal(err)
	}

	d := declaredFunctions()[2] // screening_ledger_purge_snapshots(ledger scalar corroboration,...)
	if d.label != "screening_ledger_purge_snapshots(ledger scalar corroboration,...)" {
		t.Fatalf("test construction error: wrong declaredFunctions() index")
	}
	err := checkLiveDigestMatchesAccepted(t, d, tempDir)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 11 D99/D103 test 7: expected the gate to FAIL once a new migration file changes the live body without updating the declared digest -- it passed instead")
	}
	if !strings.Contains(err.Error(), "999_rogue_purge_snapshots.sql") {
		t.Fatalf("expected the failure to name the rogue file as the new LIVE literal's source, got: %v", err)
	}

	// Positive control: the SAME temp-directory check, without the rogue
	// file, must still pass -- proving the failure above came from the
	// rogue file and not from copying the real tree into a temp dir.
	tempDirClean := t.TempDir()
	for _, path := range migrationFilePaths(t, "../../db/migrations") {
		content := mustReadFile(t, path)
		dest := filepath.Join(tempDirClean, filepath.Base(path))
		if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkLiveDigestMatchesAccepted(t, d, tempDirClean); err != nil {
		t.Fatalf("positive control: an unmodified copy of the real migrations directory must still pass the gate, got: %v", err)
	}
}

// TestAssertNoBodyDroppedPassesOnRealTree is ADR-0007 Addendum 12
// D112 item 5's baseline: the real, unmodified db/migrations/ tree has
// no body assertNoBodyDropped cannot place. Runs with no DSN.
func TestAssertNoBodyDroppedPassesOnRealTree(t *testing.T) {
	if err := assertNoBodyDropped(t, "../../db/migrations"); err != nil {
		t.Fatal(err)
	}
}

// TestAssertNoBodyDroppedCatchesRespelledSignature is ADR-0007 Addendum
// 12 D112 item 5: the gate must FAIL against a db/migrations/*.sql file
// that defines a declared function under an equivalent but differently-
// spelled signature -- D99's stated property ("a file added later is
// covered without an edit") is false for a spelling pg_dump and psql
// \df both emit routinely (P-C's own measurement). Respells the
// array-form overload's OWN leading parameter's type ("text[]" -> "text
// ARRAY"). First confirms the raw, uncanonicalized type list misses it
// entirely (D108(a)'s own reason to exist); then shows derivedPopulation's
// canonicalization (D108(a)) alone already makes it the LIVE (last) body
// under this rogue file's name, so checkLiveDigestMatchesAccepted
// correctly FAILS on the digest mismatch rather than silently passing.
func TestAssertNoBodyDroppedCatchesRespelledSignature(t *testing.T) {
	tempDir := t.TempDir()
	for _, path := range migrationFilePaths(t, "../../db/migrations") {
		content := mustReadFile(t, path)
		if err := os.WriteFile(filepath.Join(tempDir, filepath.Base(path)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	respelledBody := "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text ARRAY, p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN ARRAY[]::text[]; END; $$;\n"
	if err := os.WriteFile(filepath.Join(tempDir, "zzz999_respelled.sql"), []byte(respelledBody), 0o644); err != nil {
		t.Fatal(err)
	}

	d := declaredFunctions()[3]
	if d.label != "screening_ledger_purge_snapshots(p_snapshot_sha256 text[],...)" {
		t.Fatalf("test construction error: wrong declaredFunctions() index")
	}

	// Without canonicalization, the raw type list never even recognises
	// the respelled body as belonging to this overload.
	preD108Population := 0
	for _, found := range extractFunctionBodies(t, mustReadFile(t, filepath.Join(tempDir, "zzz999_respelled.sql")), "zzz999_respelled.sql", d.funcName) {
		if argTypeList(found.args) == d.typeList { // no canonicalization
			preD108Population++
		}
	}
	if preD108Population != 0 {
		t.Fatalf("test construction error: expected the raw, uncanonicalized type list to miss the respelled body entirely, matched %d", preD108Population)
	}

	// D108(a): canonicalization recognises it as THIS overload's new
	// live body, and its digest does not match the declared accepted
	// one, so the gate correctly fails rather than silently passing.
	err := checkLiveDigestMatchesAccepted(t, d, tempDir)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 12 D108(a): expected checkLiveDigestMatchesAccepted to FAIL once canonicalization recognises the respelled body as this overload's new live literal (wrong digest) -- it passed instead")
	}
	if !strings.Contains(err.Error(), "zzz999_respelled.sql") {
		t.Fatalf("expected the failure to name the respelled file as the new LIVE literal's source, got: %v", err)
	}

	// D108(b) still holds: no body is left unplaced.
	if err := assertNoBodyDropped(t, tempDir); err != nil {
		t.Fatalf("ADR-0007 Addendum 12 D108(b): expected the respelled body to be correctly placed (it maps to the array-form overload once canonicalized), got: %v", err)
	}
}

// TestAssertNoBodyDroppedCatchesUnmappedSynonym is ADR-0007 Addendum 12
// D112 item 5's own required proof: part (b) must work even when part
// (a)'s alias map is INCOMPLETE. Uses a schema-qualified spelling
// ("pg_catalog.text[]" for "text[]") that typeSpellingAliases does NOT
// declare -- deliberately, so this test fails if a future edit adds it
// to the map without noticing it defeats this test's own purpose.
func TestAssertNoBodyDroppedCatchesUnmappedSynonym(t *testing.T) {
	for _, a := range typeSpellingAliases {
		if a.from == "pg_catalog.text[]" || a.to == "pg_catalog.text[]" {
			t.Fatal("test construction error: typeSpellingAliases now maps pg_catalog.text[] -- this test no longer exercises an UNMAPPED synonym; pick a different one")
		}
	}

	tempDir := t.TempDir()
	for _, path := range migrationFilePaths(t, "../../db/migrations") {
		content := mustReadFile(t, path)
		if err := os.WriteFile(filepath.Join(tempDir, filepath.Base(path)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	unmappedBody := "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 pg_catalog.text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN ARRAY[]::text[]; END; $$;\n"
	if err := os.WriteFile(filepath.Join(tempDir, "zzz999_unmapped_synonym.sql"), []byte(unmappedBody), 0o644); err != nil {
		t.Fatal(err)
	}

	err := assertNoBodyDropped(t, tempDir)
	if err == nil {
		t.Fatal("ADR-0007 Addendum 12 D108(b): expected assertNoBodyDropped to FAIL against a synonym typeSpellingAliases does not map -- it passed instead, meaning an unplaceable body was silently discarded")
	}
	if !strings.Contains(err.Error(), "zzz999_unmapped_synonym.sql") {
		t.Fatalf("expected the failure to name the file carrying the unmapped-synonym body, got: %v", err)
	}
}

// TestAssertNoBodyDroppedSelectsByTypeIdentityNotParameterName is
// ADR-0007 Addendum 13 D118's own required reproduction (D122 item 8):
// a rogue body whose leading parameter keeps the declared-retired name
// "p_before" is INVISIBLE to the pre-D118 prefix rule -- caught here by
// showing the shipped rule (a HasPrefix on raw parameter text) matches
// it against nothing, then that the type-list rule catches it -- while
// a control with a merely respelled leading parameter name
// ("p_notbefore") was already caught by both rules, proving this test
// exercises the actual gap rather than a rule that never worked at all.
// D108(a)'s alias map is unregressed (exercised via canonicalizeArgs
// same as every other test in this file); D99's
// TestDigestGateCoversANewMigrationFileWithNoEdit and D92's whitespace/
// both-directions assertions are unregressed by the other tests in this
// file; the gate still runs with no DSN.
func TestAssertNoBodyDroppedSelectsByTypeIdentityNotParameterName(t *testing.T) {
	rogueTemplate := "CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(%s timestamptz, p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN ARRAY[]::text[]; END; $$;\n"

	buildTempDir := func(t *testing.T, leadingParam string) string {
		t.Helper()
		tempDir := t.TempDir()
		for _, path := range migrationFilePaths(t, "../../db/migrations") {
			content := mustReadFile(t, path)
			if err := os.WriteFile(filepath.Join(tempDir, filepath.Base(path)), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		rogue := fmt.Sprintf(rogueTemplate, leadingParam)
		if err := os.WriteFile(filepath.Join(tempDir, "zzz999_rogue.sql"), []byte(rogue), 0o644); err != nil {
			t.Fatal(err)
		}
		return tempDir
	}

	t.Run("p_before_invisible_under_the_shipped_prefix_rule", func(t *testing.T) {
		tempDir := buildTempDir(t, "p_before")
		rogueBodies := extractFunctionBodies(t, mustReadFile(t, filepath.Join(tempDir, "zzz999_rogue.sql")), "zzz999_rogue.sql", "screening_ledger_purge_snapshots")
		if len(rogueBodies) != 1 {
			t.Fatalf("test construction error: expected exactly 1 extracted rogue body, got %d", len(rogueBodies))
		}
		// The shipped (pre-D118) selection rule: HasPrefix on raw
		// parameter text. Reconstructed here rather than reintroduced
		// into production code, since it is exactly the defect this
		// decision removes.
		shippedRulePlacesIt := false
		for _, d := range declaredFunctions() {
			if d.funcName != "screening_ledger_purge_snapshots" {
				continue
			}
			if d.typeList != "" && strings.HasPrefix(canonicalizeArgs(rogueBodies[0].args), canonicalizeArgs("p_before timestamptz")) {
				shippedRulePlacesIt = true
			}
		}
		if !shippedRulePlacesIt {
			t.Fatal("test construction error: expected the reconstructed shipped prefix rule to match the p_before-leading rogue body (matching D118's own finding) -- if it no longer does, this test needs a different reproduction")
		}
		// D118's type-list rule: this rogue body's full type list
		// ("timestamptz,text[],text,int[],timestamptz[],text,text") is
		// NOT equal to either declared overload's type list and is NOT
		// a member of retiredFunctionTypeLists (which requires an EXACT
		// match, and this rogue has one extra leading timestamptz
		// parameter) -- so assertNoBodyDropped must catch it as
		// unplaceable.
		err := assertNoBodyDropped(t, tempDir)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 13 D118: expected assertNoBodyDropped to FAIL against a rogue body whose leading parameter is named p_before -- it passed instead, meaning the body was silently discarded (invisible under the pre-D118 name-prefix rule)")
		}
		if !strings.Contains(err.Error(), "zzz999_rogue.sql") {
			t.Fatalf("expected the failure to name zzz999_rogue.sql as the source of the unplaceable body, got: %v", err)
		}
	})

	t.Run("p_notbefore_control_caught_by_both_rules", func(t *testing.T) {
		tempDir := buildTempDir(t, "p_notbefore")
		err := assertNoBodyDropped(t, tempDir)
		if err == nil {
			t.Fatal("expected assertNoBodyDropped to FAIL against the p_notbefore control rogue body")
		}
		if !strings.Contains(err.Error(), "zzz999_rogue.sql") {
			t.Fatalf("expected the failure to name zzz999_rogue.sql, got: %v", err)
		}
	})
}

// TestArgTypeListMatchesDeclaredOverloadsExactly is D118's own type-list
// derivation, checked directly against the declared constants and
// against a spelling variant D108(a)'s alias map already covers --
// confirming argTypeList composes correctly with canonicalizeArgs
// rather than merely asserting the two declaredFunctions() entries
// happen to pass elsewhere.
func TestArgTypeListMatchesDeclaredOverloadsExactly(t *testing.T) {
	cases := []struct {
		name string
		args string
		want string
	}{
		{
			name: "array_form_canonical_spelling",
			args: "p_snapshot_sha256 text[], p_ledger_id text, p_expected_count int[], p_expected_max timestamptz[], p_operator text, p_reason text",
			want: "text[],text,int[],timestamptz[],text,text",
		},
		{
			name: "array_form_pg_dump_spelling",
			args: "p_snapshot_sha256 text ARRAY, p_ledger_id text, p_expected_count integer[], p_expected_max timestamp with time zone[], p_operator text, p_reason text",
			want: "text[],text,int[],timestamptz[],text,text",
		},
		{
			name: "time_floor_canonical_spelling",
			args: "p_ledger_id text, p_expected_count bigint, p_expected_max timestamptz, p_operator text, p_reason text",
			want: "text,bigint,timestamptz,text,text",
		},
		{
			name: "time_floor_pg_dump_spelling",
			args: "p_ledger_id text, p_expected_count int8, p_expected_max timestamp with time zone, p_operator text, p_reason text",
			want: "text,bigint,timestamptz,text,text",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := argTypeList(canonicalizeArgs(c.args))
			if got != c.want {
				t.Fatalf("argTypeList(canonicalizeArgs(%q)) = %q, want %q", c.args, got, c.want)
			}
		})
	}
	for _, d := range declaredFunctions() {
		if d.typeList == "" {
			continue
		}
		found := false
		for _, c := range cases {
			if argTypeList(canonicalizeArgs(c.args)) == d.typeList {
				found = true
			}
		}
		if !found {
			t.Fatalf("declaredFunctions() entry %q has typeList %q, which no case above exercises -- add a case matching it", d.label, d.typeList)
		}
	}
}
