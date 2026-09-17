// ADR-0007 Addendum 19 D147/D148/D151: the signed-policy duplicate-key
// scan must compare member names by the identity encoding/json resolves
// them to (bytes.EqualFold), not by byte equality -- D38(a)'s referent
// principle applied one level below where D38(a) itself stopped. D148
// closes the loader's non-strict decode, which D147 alone would leave
// open for the one homoglyph class (U+FF53 FULLWIDTH LATIN SMALL LETTER
// S) that does not simple-fold onto ASCII.
//
// Every test in this file was run against the shipped, unmodified
// policy.go before D147/D148 were implemented (CLAUDE.md rule 5) -- the
// producer/consumer per-field cases and the D148 unknown-key cases all
// failed (accepted what they must refuse) on that run. The mechanism
// tests (exhaustive per-rune differential, composition, unquoting
// parity, precondition) do not depend on the fix at all: they pin facts
// about bytes.EqualFold and encoding/json that D147's correctness
// argument rests on, independent of which comparison policy.go uses.
package screeningledger

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// ---------------------------------------------------------------------
// D151 item 3: D147's precondition, pinned as a standing test.
// ---------------------------------------------------------------------

// TestD147EqualFoldPreconditionNoCollidingTags is ADR-0007 Addendum 19
// D151 item 3: bytes.EqualFold(k1, k2) means "k1 and k2 resolve to the
// same field" only if no two tags in the target struct are themselves
// EqualFold-equal (encode.go's folded index keeps the FIRST field on a
// collision). A tag added later that breaks this must fail here, naming
// both tags, rather than silently changing what D147 means.
func TestD147EqualFoldPreconditionNoCollidingTags(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(VerificationPolicy{}),
		reflect.TypeOf(unsignedPolicyInput{}),
		reflect.TypeOf(SignedVerificationPolicy{}),
	} {
		tags := structJSONTags(typ)
		for i := range tags {
			for j := i + 1; j < len(tags); j++ {
				if bytes.EqualFold([]byte(tags[i]), []byte(tags[j])) {
					t.Fatalf("ADR-0007 Addendum 19 D151 item 3: %s has EqualFold-colliding tags %q and %q -- D147's exactness argument no longer holds; this addendum must be amended, not silently outrun", typ.Name(), tags[i], tags[j])
				}
			}
		}
	}
}

func structJSONTags(typ reflect.Type) []string {
	tags := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		tags = append(tags, strings.Split(tag, ",")[0])
	}
	return tags
}

// ---------------------------------------------------------------------
// D151 item 2: the exhaustive per-rune differential and the composition
// check -- pinned so a future Go toolchain change to encoding/json's
// folding rule fails this test rather than silently redefining D147.
// ---------------------------------------------------------------------

// TestD147ExhaustiveRuneDifferential reproduces ADR-0007 Addendum 19's
// own measurement: every Unicode scalar value (1,112,064 of them, all
// code points minus the 2,048 surrogates), decoded as a one-member
// object into a probe struct with one field per tag character measured
// from the three real structs' tags, must agree between the real
// decoder's field resolution and bytes.EqualFold's prediction.
func TestD147ExhaustiveRuneDifferential(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive over all Unicode scalar values; skipped under -short")
	}
	tagCharSet := map[rune]bool{}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(VerificationPolicy{}),
		reflect.TypeOf(unsignedPolicyInput{}),
		reflect.TypeOf(SignedVerificationPolicy{}),
	} {
		for _, tag := range structJSONTags(typ) {
			for _, r := range tag {
				tagCharSet[r] = true
			}
		}
	}
	chars := make([]rune, 0, len(tagCharSet))
	for r := range tagCharSet {
		chars = append(chars, r)
	}
	sort.Slice(chars, func(i, j int) bool { return chars[i] < chars[j] })
	var pop strings.Builder
	for _, r := range chars {
		pop.WriteRune(r)
	}
	t.Logf("A19EQ tag character population (measured from the three structs' tags, %d): %q", len(chars), pop.String())

	// One struct, one field per tag character, each field tagged with
	// exactly that character -- matches the design's own methodology:
	// a single scalar-value decode either resolves into at most one of
	// these fields or into none.
	fields := make([]reflect.StructField, len(chars))
	for i, r := range chars {
		fields[i] = reflect.StructField{
			Name: fmt.Sprintf("F%d", i),
			Type: reflect.TypeOf(0),
			Tag:  reflect.StructTag(fmt.Sprintf("json:%q", string(r))),
		}
	}
	probeType := reflect.StructOf(fields)

	checked := 0
	resolved := 0
	disagreements := 0
	var samples []string
	var nonIdentical []string

	for r := rune(0); r <= 0x10FFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // surrogates are not valid Unicode scalar values
		}
		checked++
		keyStr := string(r)
		v := reflect.New(probeType)
		err := json.Unmarshal([]byte(fmt.Sprintf(`{%q:1}`, keyStr)), v.Interface())
		var resolvedIdx = -1
		if err == nil {
			for i := range chars {
				if v.Elem().Field(i).Int() == 1 {
					resolvedIdx = i
					break
				}
			}
		}
		if resolvedIdx >= 0 {
			resolved++
			if r != chars[resolvedIdx] {
				nonIdentical = append(nonIdentical, fmt.Sprintf("U+%04X->%q", r, string(chars[resolvedIdx])))
			}
		}
		for i, c := range chars {
			predicted := bytes.EqualFold([]byte(keyStr), []byte(string(c)))
			gotThis := i == resolvedIdx
			if predicted != gotThis {
				disagreements++
				if len(samples) < 10 {
					samples = append(samples, fmt.Sprintf("U+%04X vs tag %q: decoder=%v EqualFold=%v", r, string(c), gotThis, predicted))
				}
			}
		}
	}
	sort.Strings(nonIdentical)
	t.Logf("A19EQ exhaustive per-rune differential: scalar values checked=%d resolved-to-a-field=%d Go-decoder-vs-bytes.EqualFold-disagreements=%d", checked, resolved, disagreements)
	t.Logf("A19EQ non-identical runes Go resolves onto a tag character: %v", nonIdentical)
	if checked != 1112064 {
		t.Fatalf("test construction bug: expected 1112064 scalar values (1114112 code points - 2048 surrogates), checked %d", checked)
	}
	if disagreements != 0 {
		t.Fatalf("ADR-0007 Addendum 19 D147/R70: bytes.EqualFold disagrees with the real encoding/json decoder on %d cases, e.g. %v -- D147's exactness no longer holds under this Go toolchain", disagreements, samples)
	}
}

func foldOrbit(r rune) []rune {
	orbit := []rune{r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		orbit = append(orbit, f)
	}
	return orbit
}

// TestD147CompositionOnRealTags reproduces the composition check: for
// every tag of every real struct, at every character position, every
// member of that character's SimpleFold orbit is substituted and the
// real decoder's resolution is checked against bytes.EqualFold's
// prediction for every field of that struct. Also reproduces D151 item
// 3's precondition as a byproduct (zero colliding tag pairs), matching
// the design pass's own combination counts exactly.
func TestD147CompositionOnRealTags(t *testing.T) {
	check := func(name string, typ reflect.Type) {
		tags := structJSONTags(typ)
		collisions := 0
		for i := range tags {
			for j := i + 1; j < len(tags); j++ {
				if bytes.EqualFold([]byte(tags[i]), []byte(tags[j])) {
					collisions++
				}
			}
		}
		fields := make([]reflect.StructField, len(tags))
		for i, tg := range tags {
			fields[i] = reflect.StructField{
				Name: fmt.Sprintf("F%d", i),
				Type: reflect.TypeOf(0),
				Tag:  reflect.StructTag(fmt.Sprintf("json:%q", tg)),
			}
		}
		probeType := reflect.StructOf(fields)

		combos := 0
		disagreements := 0
		for _, tag := range tags {
			runes := []rune(tag)
			for pos, r := range runes {
				for _, alt := range foldOrbit(r) {
					altRunes := append([]rune{}, runes...)
					altRunes[pos] = alt
					altTag := string(altRunes)
					combos++
					v := reflect.New(probeType)
					_ = json.Unmarshal([]byte(fmt.Sprintf(`{%q:1}`, altTag)), v.Interface())
					for i, tg := range tags {
						resolved := v.Elem().Field(i).Int() == 1
						predicted := bytes.EqualFold([]byte(altTag), []byte(tg))
						if resolved != predicted {
							disagreements++
						}
					}
				}
			}
		}
		t.Logf("A19COMP %s tags=%d EqualFold-colliding-tag-pairs=%d (key x field) combinations=%d Go-vs-EqualFold-disagreements=%d", name, len(tags), collisions, combos*len(tags), disagreements)
		if collisions != 0 {
			t.Fatalf("%s has %d EqualFold-colliding tag pairs -- D147's precondition violated", name, collisions)
		}
		if disagreements != 0 {
			t.Fatalf("%s: %d (key,field) disagreements between the real decoder and bytes.EqualFold", name, disagreements)
		}
	}
	check("screeningledger.VerificationPolicy", reflect.TypeOf(VerificationPolicy{}))
	check("screeningledger.unsignedPolicyInput", reflect.TypeOf(unsignedPolicyInput{}))
	check("screeningledger.SignedVerificationPolicy", reflect.TypeOf(SignedVerificationPolicy{}))
}

// TestD147UnquotingParity reproduces D147's point (3): the scan sees
// member names through json.Decoder.Token(), the decoder resolves them
// after its own unquoting. Both must unquote identically (including
// invalid UTF-8 and lone surrogate escapes, both replaced with U+FFFD)
// or the scan and the resolver would be comparing different strings.
func TestD147UnquotingParity(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"fold_escape", `{"min_anchor_ſequence":1}`},
		{"upper_mixed", `{"SCHEMA_version":1}`},
		{"invalid_utf8_byte", "{\"min_anchor_\xffsequence\":1}"},
		{"raw_nonascii", "{\"min_anchor_ſequence\":1}"},
		{"lone_surrogate_escape", `{"min_anchor_\ud800sequence":1}`},
	}
	type probe struct {
		MinAnchor int `json:"min_anchor_sequence"`
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dec := json.NewDecoder(strings.NewReader(c.input))
			tok, err := dec.Token() // '{'
			if err != nil {
				t.Fatal(err)
			}
			if tok != json.Delim('{') {
				t.Fatalf("expected object open, got %v", tok)
			}
			keyTok, err := dec.Token()
			if err != nil {
				t.Fatal(err)
			}
			tokenKey, ok := keyTok.(string)
			if !ok {
				t.Fatalf("expected string key token, got %T", keyTok)
			}
			var p probe
			if err := json.Unmarshal([]byte(c.input), &p); err != nil {
				t.Fatalf("json.Unmarshal must accept invalid UTF-8/lone surrogates by U+FFFD substitution, not error: %v", err)
			}
			predicted := bytes.EqualFold([]byte(tokenKey), []byte("min_anchor_sequence"))
			resolved := p.MinAnchor == 1
			t.Logf("A19UQ input=%q token_key=%q struct_resolved=%v EqualFold(min_anchor_sequence)=%v", c.input, tokenKey, resolved, predicted)
			if predicted != resolved {
				t.Fatalf("unquoting parity broken: token key %q -- decoder resolved=%v but bytes.EqualFold predicted=%v", tokenKey, resolved, predicted)
			}
		})
	}
}

// ---------------------------------------------------------------------
// D151 item 1: D147 refuses every confirmed fold-colliding construction,
// at both the producer (DecodeUnsignedPolicy) and consumer
// (LoadSignedVerificationPolicy) ends, across all eleven policy fields
// and all three envelope fields, naming both spellings.
// ---------------------------------------------------------------------

// a19PolicyBaseFields is the baseline, VALID unsigned policy document,
// one entry per VerificationPolicy tag in struct order -- the value that
// must end up signed/loaded once the fix is in place.
var a19PolicyBaseFields = []struct{ tag, value string }{
	{"schema_version", `"` + VerificationPolicySchemaV4 + `"`},
	{"ledger_id", `"a19-d147-base"`},
	{"min_event_schema", `"` + EventSchemaV2 + `"`},
	{"min_audit_schema", `"` + AuditSchemaV2 + `"`},
	{"genesis_event_sequence", `1`},
	{"genesis_audit_sequence", `1`},
	{"allow_unanchored", `false`},
	{"min_anchor_sequence", `0`},
	{"genesis_event_sha256", `""`},
	{"genesis_audit_sha256", `""`},
	{"tenancy", `"` + TenancyExclusive + `"`},
}

// a19PolicyReviewerValue is the DIFFERENT value a reviewer reading the
// canonical spelling first would see -- CAP #19's own construction
// pattern (schema_version v3 vs v4, tenancy exclusive vs shared, etc).
var a19PolicyReviewerValue = map[string]string{
	"schema_version":         `"` + VerificationPolicySchemaV3 + `"`,
	"ledger_id":              `"ledger-reviewed"`,
	"min_event_schema":       `"` + EventSchemaV1 + `"`,
	"min_audit_schema":       `"` + AuditSchemaV1 + `"`,
	"genesis_event_sequence": `2`,
	"genesis_audit_sequence": `2`,
	"allow_unanchored":       `true`,
	"min_anchor_sequence":    `500`,
	"genesis_event_sha256":   `"` + strings.Repeat("a", 64) + `"`,
	"genesis_audit_sha256":   `"` + strings.Repeat("b", 64) + `"`,
	"tenancy":                `"` + TenancyShared + `"`,
}

// a19FoldVariants returns the label->alternate-spelling map D147 must
// treat as a duplicate of tag: always the all-uppercase form, plus (for
// every tag containing 's') the U+017F LONG S form at the first 's'.
func a19FoldVariants(tag string) map[string]string {
	variants := map[string]string{"UPPER": strings.ToUpper(tag)}
	if idx := strings.IndexByte(tag, 's'); idx >= 0 {
		variants["U+017F(long s)"] = tag[:idx] + "ſ" + tag[idx+1:]
	}
	if idx := strings.IndexByte(tag, 'k'); idx >= 0 {
		variants["U+212A(Kelvin)"] = tag[:idx] + "K" + tag[idx+1:]
	}
	return variants
}

// buildA19ProducerDoc places tag (canonical spelling) FIRST holding the
// reviewer/bait value, then altSpelling SECOND holding the real
// baseline value -- CAP #19's own construction: "the canonical key with
// the value the reviewer reads first, followed by a second spelling ...
// carrying the value the decoder takes."
func buildA19ProducerDoc(targetTag, altSpelling string) []byte {
	parts := make([]string, 0, len(a19PolicyBaseFields)+1)
	for _, f := range a19PolicyBaseFields {
		if f.tag == targetTag {
			parts = append(parts, fmt.Sprintf("%q:%s", f.tag, a19PolicyReviewerValue[f.tag]))
			parts = append(parts, fmt.Sprintf("%q:%s", altSpelling, f.value))
			continue
		}
		parts = append(parts, fmt.Sprintf("%q:%s", f.tag, f.value))
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

// TestD147ProducerRefusesFoldDuplicatesPerField is ADR-0007 Addendum 19
// D151 item 1(a): every VerificationPolicy tag, in every applicable
// fold-colliding spelling, must be refused by DecodeUnsignedPolicy,
// naming both spellings. Run against the unmodified shipped code before
// D147 was implemented, every case here ACCEPTED the bait document and
// signed the value the reviewer never read (matching CAP #19's own
// transcript) -- confirming this test genuinely failed pre-fix.
func TestD147ProducerRefusesFoldDuplicatesPerField(t *testing.T) {
	for _, f := range a19PolicyBaseFields {
		for label, alt := range a19FoldVariants(f.tag) {
			t.Run(f.tag+"/"+label, func(t *testing.T) {
				doc := buildA19ProducerDoc(f.tag, alt)
				if _, err := DecodeUnsignedPolicy(bytes.NewReader(doc)); err == nil {
					t.Fatalf("ADR-0007 Addendum 19 D147: DecodeUnsignedPolicy accepted a %s-spelled duplicate of %q -- a reviewer reading %q=%s would not know the signed value came from %q=%s", label, f.tag, f.tag, a19PolicyReviewerValue[f.tag], alt, f.value)
				} else if !strings.Contains(err.Error(), f.tag) || !strings.Contains(err.Error(), alt) {
					t.Fatalf("expected the refusal to name BOTH %q and %q, got: %v", f.tag, alt, err)
				}
			})
		}
	}
}

// TestD147SignCommandRefusesCAP19OwnDocuments is D151 item 1's own
// pre-declared requirement: CAP #19's exact case.json (UPPER-cased
// duplicates of allow_unanchored/min_anchor_sequence/tenancy) and
// fold.json (U+017F duplicate of min_anchor_sequence) through the real
// `cmd/screening-ledger-policy sign` binary -- via DecodeUnsignedPolicy,
// the sole path that binary's sign command uses to read its input.
func TestD147SignCommandRefusesCAP19OwnDocuments(t *testing.T) {
	caseJSON := []byte(`{
		"schema_version":"` + VerificationPolicySchemaV4 + `",
		"ledger_id":"cap19-case",
		"min_event_schema":"` + EventSchemaV2 + `",
		"min_audit_schema":"` + AuditSchemaV2 + `",
		"genesis_event_sequence":1,
		"genesis_audit_sequence":1,
		"min_anchor_sequence":500,
		"allow_unanchored":false,
		"genesis_event_sha256":"",
		"genesis_audit_sha256":"",
		"MIN_ANCHOR_SEQUENCE":0,
		"Tenancy":"shared",
		"Allow_Unanchored":true,
		"tenancy":"exclusive"
	}`)
	if _, err := DecodeUnsignedPolicy(bytes.NewReader(caseJSON)); err == nil {
		t.Fatal("ADR-0007 Addendum 19 D147: CAP #19's own case.json (UPPER/mixed-case duplicates) must be refused")
	}

	foldJSON := []byte(`{
		"schema_version":"` + VerificationPolicySchemaV4 + `",
		"ledger_id":"cap19-fold",
		"min_event_schema":"` + EventSchemaV2 + `",
		"min_audit_schema":"` + AuditSchemaV2 + `",
		"genesis_event_sequence":1,
		"genesis_audit_sequence":1,
		"min_anchor_sequence":500,
		"allow_unanchored":false,
		"genesis_event_sha256":"",
		"genesis_audit_sha256":"",
		"tenancy":"exclusive",
		"min_anchor_ſequence":0
	}`)
	if _, err := DecodeUnsignedPolicy(bytes.NewReader(foldJSON)); err == nil {
		t.Fatal("ADR-0007 Addendum 19 D147: CAP #19's own fold.json (U+017F duplicate) must be refused")
	}

	// A genuine, ordinary, non-colliding document must still sign --
	// D37's positive-control requirement.
	ordinary := buildA19ProducerDoc("", "")
	if _, err := DecodeUnsignedPolicy(bytes.NewReader(ordinary)); err != nil {
		t.Fatalf("an ordinary, non-colliding policy document must still decode: %v", err)
	}
}

// buildA19SignedEnvelope signs a19PolicyBaseFields's values (parsed into
// a real VerificationPolicy) and returns the marshaled envelope bytes,
// plus the trust-root public key.
func buildA19SignedEnvelope(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := VerificationPolicy{
		SchemaVersion:        VerificationPolicySchemaV4,
		LedgerID:             "a19-d147-base",
		MinEventSchema:       EventSchemaV2,
		MinAuditSchema:       AuditSchemaV2,
		GenesisEventSequence: 1,
		GenesisAuditSequence: 1,
		AllowUnanchored:      false,
		MinAnchorSequence:    0,
		GenesisEventSHA256:   "",
		GenesisAuditSHA256:   "",
		Tenancy:              TenancyExclusive,
	}
	signed, err := SignVerificationPolicy(policy, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw, pub
}

func writeA19Tmp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "envelope.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestD147ConsumerRefusesFoldDuplicatesPerField is ADR-0007 Addendum 19
// D151 item 1(b): a genuinely-signed envelope with a differently-spelled
// duplicate of a policy field PREPENDED (so a reviewer of the
// distributed file reads the planted spelling first) must be refused by
// LoadSignedVerificationPolicy, naming both spellings. Run against the
// unmodified shipped code before D147, every case here loaded silently.
func TestD147ConsumerRefusesFoldDuplicatesPerField(t *testing.T) {
	envRaw, pub := buildA19SignedEnvelope(t)
	for _, f := range a19PolicyBaseFields {
		for label, alt := range a19FoldVariants(f.tag) {
			t.Run(f.tag+"/"+label, func(t *testing.T) {
				bait := fmt.Sprintf(`"%s":%s,`, alt, a19PolicyReviewerValue[f.tag])
				tampered := strings.Replace(string(envRaw), `"policy":{`, `"policy":{`+bait, 1)
				path := writeA19Tmp(t, []byte(tampered))
				if _, _, err := LoadSignedVerificationPolicy(path, pub); err == nil {
					t.Fatalf("ADR-0007 Addendum 19 D147: LoadSignedVerificationPolicy accepted an envelope with %s prepended into policy.%s", alt, f.tag)
				} else if !strings.Contains(err.Error(), f.tag) || !strings.Contains(err.Error(), alt) {
					t.Fatalf("expected the refusal to name BOTH %q and %q, got: %v", "policy."+f.tag, alt, err)
				}
			})
		}
	}
}

// a19EnvelopeFields mirrors a19PolicyBaseFields for SignedVerificationPolicy's
// own three tags -- D147's scan is recursive and type-agnostic, so the
// envelope level gets the same rule with no separate code path.
var a19EnvelopeDecoys = map[string]string{
	"policy":            `{"schema_version":"x"}`,
	"signature_base64":  `"AAAA"`,
	"public_key_base64": `"AAAA"`,
}

// TestD147EnvelopeLevelDuplicates is D151 item 1's "plus the three
// SignedVerificationPolicy tags at envelope level."
func TestD147EnvelopeLevelDuplicates(t *testing.T) {
	envRaw, pub := buildA19SignedEnvelope(t)
	for _, tag := range structJSONTags(reflect.TypeOf(SignedVerificationPolicy{})) {
		for label, alt := range a19FoldVariants(tag) {
			t.Run(tag+"/"+label, func(t *testing.T) {
				bait := fmt.Sprintf(`"%s":%s,`, alt, a19EnvelopeDecoys[tag])
				tampered := strings.Replace(string(envRaw), "{", "{"+bait, 1)
				path := writeA19Tmp(t, []byte(tampered))
				if _, _, err := LoadSignedVerificationPolicy(path, pub); err == nil {
					t.Fatalf("ADR-0007 Addendum 19 D147: LoadSignedVerificationPolicy accepted envelope-level %s prepended beside %q", alt, tag)
				} else if !strings.Contains(err.Error(), tag) || !strings.Contains(err.Error(), alt) {
					t.Fatalf("expected the refusal to name BOTH %q and %q, got: %v", tag, alt, err)
				}
			})
		}
	}
}

// TestD147SingleSpellingWithNoCanonicalTwinIsAccepted is D151 item 4's
// "single-spelling positive": a document whose ONLY spelling of a tag is
// uppercase decodes to that value -- D147 must not be tightened into a
// spelling-exactness rule that refuses documents Go reads unambiguously.
// Identical before and after the fix.
func TestD147SingleSpellingWithNoCanonicalTwinIsAccepted(t *testing.T) {
	parts := make([]string, 0, len(a19PolicyBaseFields))
	for _, f := range a19PolicyBaseFields {
		if f.tag == "min_anchor_sequence" {
			parts = append(parts, `"MIN_ANCHOR_SEQUENCE":500`)
			continue
		}
		parts = append(parts, fmt.Sprintf("%q:%s", f.tag, f.value))
	}
	doc := []byte("{" + strings.Join(parts, ",") + "}")
	p, err := DecodeUnsignedPolicy(bytes.NewReader(doc))
	if err != nil {
		t.Fatalf("a single differently-spelled key with no canonical twin must be accepted, got: %v", err)
	}
	if p.MinAnchorSequence != 500 {
		t.Fatalf("MinAnchorSequence = %d, want 500 (the only spelling present)", p.MinAnchorSequence)
	}
}

// ---------------------------------------------------------------------
// D151 item 5: D148 closes the non-fold homoglyph route at the loader.
// ---------------------------------------------------------------------

// TestD148LoaderRejectsUnknownFields is ADR-0007 Addendum 19 D151 item
// 5: a policy-level unknown key, an envelope-level unknown key, and the
// U+FF53 FULLWIDTH LATIN SMALL LETTER S homoglyph (which is NOT
// bytes.EqualFold-equal to ASCII 's', so D147 alone does not catch it)
// must each be refused by LoadSignedVerificationPolicy. Run against the
// unmodified shipped code (bare json.Unmarshal) before D148, all three
// loaded silently.
func TestD148LoaderRejectsUnknownFields(t *testing.T) {
	fullwidthS := "ｓ"
	if bytes.EqualFold([]byte("min_anchor_"+fullwidthS+"equence"), []byte("min_anchor_sequence")) {
		t.Fatal("test construction bug: U+FF53 must NOT be bytes.EqualFold-equal to ASCII 's' -- that is the whole reason D148 exists as a separate decision from D147")
	}

	cases := []struct {
		name string
		bait string
		at   string // "policy" or "envelope"
	}{
		{"policy_level_unknown_key", `"min_anchor_seqence":500,`, "policy"},
		{"envelope_level_unknown_key", `"unexpected_field":true,`, "envelope"},
		{"fullwidth_s_homoglyph", `"min_anchor_` + fullwidthS + `equence":500,`, "policy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			envRaw, pub := buildA19SignedEnvelope(t)
			var tampered string
			if c.at == "policy" {
				tampered = strings.Replace(string(envRaw), `"policy":{`, `"policy":{`+c.bait, 1)
			} else {
				tampered = strings.Replace(string(envRaw), "{", "{"+c.bait, 1)
			}
			path := writeA19Tmp(t, []byte(tampered))
			if _, _, err := LoadSignedVerificationPolicy(path, pub); err == nil {
				t.Fatalf("ADR-0007 Addendum 19 D148: LoadSignedVerificationPolicy silently accepted an unknown key (%s)", c.bait)
			} else if !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("expected an unknown-field refusal, got: %v", err)
			}
		})
	}
}

// TestD148ProducerSideAlreadyRefusesFullwidthHomoglyph confirms D36's
// existing strict decode at the signer already refuses the U+FF53
// construction -- unregressed by D147/D148, which only extend the same
// treatment to the loader.
func TestD148ProducerSideAlreadyRefusesFullwidthHomoglyph(t *testing.T) {
	fullwidthS := "ｓ"
	doc := []byte(`{
		"schema_version":"` + VerificationPolicySchemaV4 + `",
		"ledger_id":"a19-d148-producer",
		"min_event_schema":"` + EventSchemaV2 + `",
		"min_audit_schema":"` + AuditSchemaV2 + `",
		"genesis_event_sequence":1,
		"genesis_audit_sequence":1,
		"allow_unanchored":false,
		"min_anchor_` + fullwidthS + `equence":500,
		"min_anchor_sequence":0,
		"genesis_event_sha256":"",
		"genesis_audit_sha256":"",
		"tenancy":"exclusive"
	}`)
	if _, err := DecodeUnsignedPolicy(bytes.NewReader(doc)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected DecodeUnsignedPolicy to refuse the U+FF53 construction with an unknown-field error (D36, unregressed), got: %v", err)
	}
}

// ---------------------------------------------------------------------
// D151 item 6: positive controls -- a shipping requirement (D37), not a
// nicety. The committed fixture must load unchanged.
// ---------------------------------------------------------------------

// a19CommittedFixturePolicySHA256 is the committed
// test/fixtures/screening-ledger/policy/example-policy.signed.json's own
// PolicySHA256, measured against the unmodified shipped code before
// D147/D148 (matching CAP #19's own DR-walkthrough value, ADR-0007
// Addendum 19 §"positive controls": "8b7a67c0904980a9..."). D147/D148
// change no canonical policy bytes, so this must be identical after.
const a19CommittedFixturePolicySHA256 = "8b7a67c0904980a96f3d3cbc270d9166cefac489ebea21a00fd9c91a575d86ac"

func TestD148CommittedFixtureLoadsWithUnchangedPolicySHA256(t *testing.T) {
	pubHex, err := os.ReadFile("../../test/fixtures/screening-ledger/policy/example-public-key.hex")
	if err != nil {
		t.Fatal(err)
	}
	trustRoot := decodeHexPublicKeyForTest(t, strings.TrimSpace(string(pubHex)))
	loaded, sha, err := LoadSignedVerificationPolicy("../../test/fixtures/screening-ledger/policy/example-policy.signed.json", trustRoot)
	if err != nil {
		t.Fatalf("ADR-0007 Addendum 19 D37: the committed example policy fixture must still load cleanly under D147/D148, got: %v", err)
	}
	if loaded.LedgerID != "screening-api-v8g-example" {
		t.Fatalf("unexpected ledger_id from committed fixture: %q", loaded.LedgerID)
	}
	if sha != a19CommittedFixturePolicySHA256 {
		t.Fatalf("committed fixture policy_sha256 changed: got %s, want %s (D147/D148 must change no canonical policy bytes)", sha, a19CommittedFixturePolicySHA256)
	}
}

// TestD148FreshOrdinaryPolicyRoundTrips is D151 item 6's "a freshly
// authored ordinary policy decodes, signs through the real CLI[-equivalent
// path] and loads" -- the CLI itself is exercised by
// cmd/screening-ledger-policy's own TestKeygenSignFingerprintRoundTrip;
// this pins the same property at the package level.
func TestD148FreshOrdinaryPolicyRoundTrips(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildA19ProducerDoc("", "")
	policy, err := DecodeUnsignedPolicy(bytes.NewReader(doc))
	if err != nil {
		t.Fatalf("an ordinary policy document must decode: %v", err)
	}
	signed, err := SignVerificationPolicy(policy, priv)
	if err != nil {
		t.Fatalf("an ordinary, valid policy must sign: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	path := writeA19Tmp(t, raw)
	loaded, _, err := LoadSignedVerificationPolicy(path, pub)
	if err != nil {
		t.Fatalf("a freshly signed, ordinary policy must load: %v", err)
	}
	if loaded.LedgerID != policy.LedgerID {
		t.Fatalf("round-tripped ledger_id = %q, want %q", loaded.LedgerID, policy.LedgerID)
	}
}
