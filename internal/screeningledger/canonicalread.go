package screeningledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// readCanonicalChainFile is ADR-0007 Addendum 20 D153, the fix for G1: a
// party who can write the ledger directory, with no key of any kind, could
// add a JSON key spelling (a case fold, a duplicate, a single differently-
// spelled key with no canonical twin) so that jq, Python and Postgres jsonb
// read a forged value while hashEvent/hashAudit still recomputed the
// authentic one from Go's own folded decode -- demonstrated end to end on
// a real sanctions hit (sdn-1001): every exact-match JSON reader saw an
// empty candidate list while `verify`/`status` reported "verified".
//
// Every chain file (D152's rows 1-6: events/<id>.json, audit/<seq>-<sha>.json,
// snapshots/<sha>.json, head.json, audit-head.json, pending.json) has
// exactly one deterministic writer -- marshalAndWrite/writeSnapshot, always
// json.Marshal of the struct -- so, unlike the hand-authored signed
// verification policy (D147/D148, resolved identity, no canonical writer),
// a chain file can be bound by its bytes: accept it only if it is
// byte-identical to the canonical serialization of the value it decodes
// to. Composed with the unchanged MAC (hashEvent/hashAudit, run after by
// the caller), this gives -- by construction, not by enumerating
// divergence kinds -- "a verified file's bytes are exactly what every
// RFC 8259 reader reads."
//
// This was measured, not argued, to be the correct rule: a prototype
// combining D147's EqualFold duplicate scan with DisallowUnknownFields
// (the policy-path mechanism, applied here instead) still ACCEPTS a single
// differently-spelled key with no canonical twin (e.g. "CANDIDATE_SUMMARY"
// alone, no "candidate_summary") -- it is neither a duplicate nor an
// unknown field, and is exactly D148's own accepted case for the
// human-reviewed policy. For a machine-written evidence file that same
// acceptance is the whole of G1: the sanctions field then reads as ABSENT
// to every exact-match reader. Byte-equality refuses it by construction.
//
// Two positive controls, committed as regression tests (D161), are the
// reason this rule is safe to install with no fixture regenerated: every
// committed fixture file and every legitimate Store.Append/writeSnapshot
// output round-trips byte-identically to json.Marshal of the struct it
// decodes to.
func readCanonicalChainFile[T any](path string) (T, []byte, error) {
	var zero T
	raw, err := os.ReadFile(path)
	if err != nil {
		return zero, nil, err
	}
	var decoded T
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return zero, nil, err
	}
	canon, err := json.Marshal(decoded)
	if err != nil {
		return zero, nil, err
	}
	if !bytes.Equal(raw, canon) {
		return zero, nil, canonicalBytesMismatchError(path, raw, canon)
	}
	return decoded, raw, nil
}

// canonicalBytesMismatchError names the first divergent byte offset
// between the file's raw bytes and its own type's canonical serialization
// (the same canon readCanonicalChainFile already computed -- never
// recomputed through a generic `any` decode, whose map-key alphabetical
// reordering would report a misleading offset unrelated to the struct's
// declared field order) and -- D46's arrangement, so a diagnostic can never
// widen what passes -- only on this already-failing path, reuses D147's own
// checkNoDuplicateJSONKeys (not a reimplementation) to name a duplicate or
// fold-spelled key when that is what diverges, rather than leaving an
// operator with a bare offset for what CAP #20's own transcript showed is
// usually one mis-cased or mis-folded field name.
func canonicalBytesMismatchError(path string, raw, canon []byte) error {
	base := fmt.Sprintf("chain file %s is not byte-identical to the canonical serialization of the value it decodes to (ADR-0007 Addendum 20 D153): this file has been reformatted, reordered, or carries a duplicate or differently-spelled JSON key that a reader other than this package's own decoder would resolve differently than the chain's own MAC does -- refusing rather than trusting bytes that do not say what they appear to say (first divergent byte offset %d)", path, firstDivergentOffset(raw, canon))
	if dupErr := checkNoDuplicateJSONKeys(raw); dupErr != nil {
		return fmt.Errorf("%s: %w", base, dupErr)
	}
	return fmt.Errorf("%s", base)
}

func firstDivergentOffset(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
