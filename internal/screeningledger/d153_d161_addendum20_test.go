package screeningledger

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ADR-0007 Addendum 20 (SEC-7, twentieth round): D153-D161. G1's
// review-evasion class was closed on the signed policy by D147/D148
// (Addendum 19); this addendum applies the same class one layer down, on
// the ledger's own evidence files, via the canonical-bytes rule (D153).
// Every test in this file must fail against a bare json.Unmarshal (the
// shipped behavior before this addendum) -- confirmed during design by
// running each construction against the pre-fix code (see the addendum
// text's own transcripts); readCanonicalChainFile is what makes them pass
// here.

// eventFixtureRaw returns the real committed fixture's sequence-1 event
// (the sdn-1001 sanctions hit), unmodified.
func eventFixtureRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../test/fixtures/screening-ledger/state/events/9c15117914fe574d9af9b89279417f1312537b55f8f7462d320e1179515b2236.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func replaceOnceInBytes(t *testing.T, raw []byte, old, new string) []byte {
	t.Helper()
	s := string(raw)
	i := bytes.Index(raw, []byte(old))
	if i < 0 {
		t.Fatalf("construction target %q not found in fixture", old)
	}
	return []byte(s[:i] + new + s[i+len(old):])
}

// TestD153CanonicalBytesRefusesEveryG1Construction is the table-driven
// T1-T6-class matrix, reproducing G1's own transcript: each construction
// is byte-exact (so a bare json.Unmarshal decodes it, and jq/Python/
// Postgres jsonb would read whatever exact-spelled key is present), and
// each must be REFUSED by readCanonicalChainFile with a named error.
func TestD153CanonicalBytesRefusesEveryG1Construction(t *testing.T) {
	clean := eventFixtureRaw(t)

	cases := []struct {
		name string
		raw  []byte
	}{
		{"exact_dup", replaceOnceInBytes(t, clean, `"http_status":200`, `"http_status":403,"http_status":200`)},
		{"upper_fold", replaceOnceInBytes(t, clean, `"http_status":200`, `"http_status":403,"HTTP_STATUS":200`)},
		{"longs_fold", replaceOnceInBytes(t, clean, `"http_status":200`, `"http_status":403,"http_`+string(rune(0x17F))+`tatu`+string(rune(0x17F))+`":200`)},
		// single_fold: the decisive counterexample D153's design phase
		// measured -- neither a duplicate nor an unknown field, so a
		// D147/D148-style scan (protoA) ACCEPTS it; only byte-equality
		// refuses it, because it hides http_status from every exact-match
		// reader (the key is renamed, not duplicated).
		{"single_fold_http_status", replaceOnceInBytes(t, clean, `"http_status":`, `"HTTP_STATUS":`)},
		{"single_fold_candidate_summary", replaceOnceInBytes(t, clean, `"candidate_summary":`, `"CANDIDATE_SUMMARY":`)},
		{"unknown_key", replaceOnceInBytes(t, clean, `"http_status":200`, `"http_status":200,"x_unknown":1`)},
		{"u_escaped_key", replaceOnceInBytes(t, clean, `"http_status":200`, `"http_`+string(rune(0x5C))+`u0073tatus":200`)},
		{"leading_whitespace", append([]byte(" \n\t"), clean...)},
		// Note: BOM-prefixed and trailing-document constructions are
		// deliberately not table rows here -- this codebase's shipped
		// reader before D153 was a bare json.Unmarshal (not a
		// token-based json.Decoder, which the design-phase protoA/protoB
		// comparison used), and json.Unmarshal already rejects both
		// outright. They are not part of G1's actual exposure on this
		// decode path, and CLAUDE.md rule 5 requires every row here to
		// fail before the fix -- these two do not.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Confirm this construction decodes cleanly through a bare
			// json.Unmarshal (the pre-fix behavior) -- otherwise this row
			// tests nothing.
			var decoded Event
			if err := json.Unmarshal(tc.raw, &decoded); err != nil {
				t.Fatalf("construction bug: bare json.Unmarshal must succeed on this row (it is what makes the row dangerous), got: %v", err)
			}
			path := filepath.Join(t.TempDir(), "event.json")
			if err := os.WriteFile(path, tc.raw, 0o640); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readCanonicalChainFile[Event](path); err == nil {
				t.Fatalf("expected readCanonicalChainFile to refuse construction %q, but it accepted it", tc.name)
			}
		})
	}

	// pretty_whitespace / reordered are legitimate-content, non-canonical-
	// bytes rows (R74's stated false-refusal direction): re-serialize the
	// clean fixture through json.MarshalIndent (whitespace) and through a
	// map (key reordering) and confirm both are refused too, even though
	// their DECODED value is identical to the authentic one.
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(clean, &asMap); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(asMap)
	if err != nil {
		t.Fatal(err)
	}
	var asAny any
	if err := json.Unmarshal(clean, &asAny); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(asAny, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{{"reordered", reordered}, {"pretty_whitespace", pretty}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "event.json")
			if err := os.WriteFile(path, tc.raw, 0o640); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readCanonicalChainFile[Event](path); err == nil {
				t.Fatalf("expected readCanonicalChainFile to refuse construction %q (R74's stated false-refusal direction), but it accepted it", tc.name)
			}
		})
	}
}

// TestD153RefusesBOMAndTrailingDocumentToo confirms readCanonicalChainFile
// also refuses a BOM-prefixed or trailing-document file, even though
// (unlike the table above) json.Unmarshal already rejects both outright
// on this codebase's decode path -- so this is a defense-in-depth
// assertion, not a "must fail before the fix" row.
func TestD153RefusesBOMAndTrailingDocumentToo(t *testing.T) {
	clean := eventFixtureRaw(t)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"bom", append([]byte(string(rune(0xFEFF))), clean...)},
		{"trailing_document", append(append([]byte{}, clean...), []byte(`{"extra":"document"}`)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "event.json")
			if err := os.WriteFile(path, tc.raw, 0o640); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readCanonicalChainFile[Event](path); err == nil {
				t.Fatalf("expected readCanonicalChainFile to refuse %q", tc.name)
			}
		})
	}
}

// TestD153SingleFoldDecidesTheDirection is the measurement that decided
// D153's design: a D147/D148-style scan (EqualFold duplicate check plus
// DisallowUnknownFields) ACCEPTS the single-fold construction; the
// canonical-bytes rule REFUSES it. This is the row that rules out
// "D147/D148 applied to chain files" as D153's mechanism (D161's
// withdrawal condition).
func TestD153SingleFoldDecidesTheDirection(t *testing.T) {
	clean := eventFixtureRaw(t)
	singleFold := replaceOnceInBytes(t, clean, `"candidate_summary":`, `"CANDIDATE_SUMMARY":`)

	// protoA: D147's own checkNoDuplicateJSONKeys plus DisallowUnknownFields.
	if err := checkNoDuplicateJSONKeys(singleFold); err != nil {
		t.Fatalf("expected the single-fold construction to have no duplicate key (that is the whole point of the row), got: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(singleFold))
	dec.DisallowUnknownFields()
	var viaProtoA Event
	if err := dec.Decode(&viaProtoA); err != nil {
		t.Fatalf("expected protoA (D147/D148-style) to ACCEPT the single-fold construction, got: %v", err)
	}

	// The exact-match reader (jq/Python/Postgres jsonb equivalent): the
	// field is ABSENT, not merely differently valued.
	var reader map[string]json.RawMessage
	if err := json.Unmarshal(singleFold, &reader); err != nil {
		t.Fatal(err)
	}
	if _, present := reader["candidate_summary"]; present {
		t.Fatal("expected candidate_summary to be absent to an exact-match reader on the single-fold construction")
	}

	// protoB: the canonical-bytes rule, shipped as readCanonicalChainFile.
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, singleFold, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCanonicalChainFile[Event](path); err == nil {
		t.Fatal("expected readCanonicalChainFile (protoB) to REFUSE the single-fold construction")
	}
}

// TestD153RefusalNamesTheFoldedKey confirms D153's diagnostic
// arrangement (D46's pattern, reused not reimplemented): on a byte
// mismatch caused by a duplicate/fold-spelled key, the error names it.
func TestD153RefusalNamesTheFoldedKey(t *testing.T) {
	clean := eventFixtureRaw(t)
	raw := replaceOnceInBytes(t, clean, `"http_status":200`, `"http_status":403,"HTTP_STATUS":200`)
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	_, _, err := readCanonicalChainFile[Event](path)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("repeated JSON key")) {
		t.Fatalf("expected the error to name the fold-spelled key via checkNoDuplicateJSONKeys, got: %v", err)
	}
}

// TestD153RefusesAcrossEveryChainStructType confirms the same rule
// applies uniformly to AuditEvent, SnapshotEnvelope and Head (D152's
// sweep found the same class on every chain file type: the audit
// "operator", the snapshot "retention_class" (G4), and the head
// "sequence").
func TestD153RefusesAcrossEveryChainStructType(t *testing.T) {
	t.Run("AuditEvent", func(t *testing.T) {
		clean := `{"schema_version":"openwatchlist.screening-ledger-audit.v2","ledger_id":"l","sequence":1,"previous_audit_sha256":"","audit_sha256":"x","occurred_at":"2026-01-01T00:00:00Z","action":"a","operator":"alice"}`
		var v AuditEvent
		if err := json.Unmarshal([]byte(clean), &v); err != nil {
			t.Fatal(err)
		}
		canon, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte(clean), canon) {
			t.Fatalf("test construction bug: control fixture is not itself canonical -- want %s got %s", canon, clean)
		}
		folded := replaceOnceInBytes(t, canon, `"operator":"alice"`, `"OPERATOR":"forged-operator","operator":"alice"`)
		path := filepath.Join(t.TempDir(), "audit.json")
		os.WriteFile(path, folded, 0o640)
		if _, _, err := readCanonicalChainFile[AuditEvent](path); err == nil {
			t.Fatal("expected a folded 'OPERATOR' to be refused")
		}
	})
	t.Run("SnapshotEnvelope_G4", func(t *testing.T) {
		clean := `{"schema_version":"openwatchlist.screening-ledger-snapshot.v1","snapshot_sha256":"s","plaintext_sha256":"p","kind":"request","cipher":"AES-256-GCM","nonce_base64":"n","ciphertext_base64":"c","aad":"a","plaintext_bytes":1,"created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:00:00Z","retention_class":"screening-standard"}`
		var v SnapshotEnvelope
		if err := json.Unmarshal([]byte(clean), &v); err != nil {
			t.Fatal(err)
		}
		canon, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte(clean), canon) {
			t.Fatalf("test construction bug: control fixture is not itself canonical -- want %s got %s", canon, clean)
		}
		folded := replaceOnceInBytes(t, canon, `"retention_class":"screening-standard"`, `"RETENTION_CLASS":"legal-hold-indefinite","retention_class":"screening-standard"`)
		path := filepath.Join(t.TempDir(), "snapshot.json")
		os.WriteFile(path, folded, 0o640)
		if _, _, err := readCanonicalChainFile[SnapshotEnvelope](path); err == nil {
			t.Fatal("expected a folded 'RETENTION_CLASS' (G4) to be refused")
		}
	})
	t.Run("Head", func(t *testing.T) {
		clean := `{"schema_version":"openwatchlist.screening-ledger-head.v2","ledger_id":"l","sequence":2,"event_id":"e","event_sha256":"s"}`
		var v Head
		if err := json.Unmarshal([]byte(clean), &v); err != nil {
			t.Fatal(err)
		}
		canon, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte(clean), canon) {
			t.Fatalf("test construction bug: control fixture is not itself canonical -- want %s got %s", canon, clean)
		}
		folded := replaceOnceInBytes(t, canon, `"sequence":2`, `"SEQUENCE":999,"sequence":2`)
		path := filepath.Join(t.TempDir(), "head.json")
		os.WriteFile(path, folded, 0o640)
		if _, _, err := readCanonicalChainFile[Head](path); err == nil {
			t.Fatal("expected a folded 'SEQUENCE' to be refused")
		}
	})
}

// TestD153PositiveControlFixturesAreByteCanonical is D161's shipping
// requirement, committed as a real regression test rather than a one-time
// verification: every committed fixture chain file must be byte-identical
// to json.Marshal of the struct it decodes to, or the canonical-bytes rule
// would false-refuse this repository's own committed evidence. Per D161's
// withdrawal condition, if this ever fails, no fixture is regenerated to
// silence it -- the design is amended instead.
func TestD153PositiveControlFixturesAreByteCanonical(t *testing.T) {
	roots := []string{
		"../../test/fixtures/screening-ledger/state",
		"../../test/fixtures/screening-ledger/frozen-v1-synthetic/state",
	}
	checked := 0
	for _, root := range roots {
		for _, sub := range []struct {
			dir  string
			read func(string) error
		}{
			{"events", func(p string) error { _, _, err := readCanonicalChainFile[Event](p); return err }},
			{"audit", func(p string) error { _, _, err := readCanonicalChainFile[AuditEvent](p); return err }},
			{"snapshots", func(p string) error { _, _, err := readCanonicalChainFile[SnapshotEnvelope](p); return err }},
		} {
			dir := filepath.Join(root, sub.dir)
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				checked++
				if err := sub.read(filepath.Join(dir, e.Name())); err != nil {
					t.Errorf("STOP CONDITION (D161): committed fixture %s is not byte-canonical: %v", filepath.Join(dir, e.Name()), err)
				}
			}
		}
		headPath := filepath.Join(root, "head.json")
		if _, err := os.Stat(headPath); err == nil {
			checked++
			if _, _, err := readCanonicalChainFile[Head](headPath); err != nil {
				t.Errorf("STOP CONDITION (D161): committed fixture %s is not byte-canonical: %v", headPath, err)
			}
		}
	}
	auditHeadPath := "../../test/fixtures/screening-ledger/state/audit-head.json"
	checked++
	if _, _, err := readCanonicalChainFile[Head](auditHeadPath); err != nil {
		t.Errorf("STOP CONDITION (D161): committed fixture %s is not byte-canonical: %v", auditHeadPath, err)
	}
	if checked == 0 {
		t.Fatal("test construction bug: checked 0 fixture files")
	}
	t.Logf("checked %d committed fixture chain files, all byte-canonical", checked)
}

// TestD153PositiveControlAppendRoundTripIsByteCanonical is D161's other
// shipping requirement: a real Store.Append over adversarial body shapes
// (Unicode, HTML-special characters, big numbers, duplicate keys in a
// nested response, tabs/newlines) must produce byte-canonical output --
// otherwise every legitimate future write would be false-refused on its
// very next read.
func TestD153PositiveControlAppendRoundTripIsByteCanonical(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x37}, 32)
	store, err := NewStore(dir, key, "a20-roundtrip-ledger")
	if err != nil {
		t.Fatal(err)
	}
	bodies := [][]byte{
		[]byte(`{"candidates":[{"candidate_id":"sdn-ünïcödé-1","score":930,"reason_codes":["name_exact"]},{"candidate_id":"sdn-emoji-` + string(rune(0x1F600)) + `","score":10}],"blockers":[]}`),
		[]byte(`{"note":"<script>alert('x')</script> & \"quoted\" <tag>","candidates":[]}`),
		[]byte(`{"big_int":9223372036854775807,"big_float":1.7976931348623157e+308,"candidates":[]}`),
		[]byte(`{"dup":"first","dup":"second","tabs":"a` + string(rune(0x5C)) + `tb` + string(rune(0x5C)) + `nc","candidates":[]}`),
	}
	checked := 0
	for i, body := range bodies {
		result, err := store.Append(AppendInput{
			Route: "/v1/screenings", HTTPStatus: 200,
			CorrelationID: "corr-" + string(rune('a'+i)),
			RequestBytes:  []byte(`{"query":"test"}`),
			ResponseBytes: body,
			OccurredAt:    "2026-09-17T00:00:00Z",
		})
		if err != nil {
			t.Fatal(err)
		}
		checks := []struct {
			path string
			read func(string) error
		}{
			{filepath.Join(dir, "events", result.Event.EventID+".json"), func(p string) error { _, _, err := readCanonicalChainFile[Event](p); return err }},
			{filepath.Join(dir, "head.json"), func(p string) error { _, _, err := readCanonicalChainFile[Head](p); return err }},
			{filepath.Join(dir, "snapshots", result.Event.RequestSnapshotSHA256+".json"), func(p string) error { _, _, err := readCanonicalChainFile[SnapshotEnvelope](p); return err }},
			{filepath.Join(dir, "snapshots", result.Event.ResponseSnapshotSHA256+".json"), func(p string) error { _, _, err := readCanonicalChainFile[SnapshotEnvelope](p); return err }},
		}
		for _, c := range checks {
			checked++
			if err := c.read(c.path); err != nil {
				t.Errorf("STOP CONDITION (D161): a real Store.Append output is not byte-canonical: %s: %v", c.path, err)
			}
		}
	}
	t.Logf("checked %d real Store.Append outputs across %d adversarial body shapes, all byte-canonical", checked, len(bodies))
}

// TestD157AssertAnchorKeyDisjointRefusesEveryDerivedSubkey is ADR-0007
// Addendum 20 D157 (G5): §5.3 point 1's "K_anchor is not derived from R"
// was asserted only by a unit test on deriveChainKeys's own output before
// this addendum; measured against a freshly provisioned, never-anchored
// mirror, loading the same bytes for both R and K_anchor produced a
// genesis anchor with no refusal anywhere. This asserts the runtime
// check against the loaded bytes.
func TestD157AssertAnchorKeyDisjointRefusesEveryDerivedSubkey(t *testing.T) {
	root := bytes.Repeat([]byte{0x11}, 32)
	ledgerID := "d157-ledger"
	keys, err := deriveChainKeys(root, ledgerID)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		key  []byte
	}{
		{"equals_root", root},
		{"equals_K_snap", keys.snap},
		{"equals_K_redact", keys.redact},
		{"equals_K_chain", keys.chain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := AssertAnchorKeyDisjoint(root, tc.key, ledgerID); err == nil {
				t.Fatalf("expected AssertAnchorKeyDisjoint to refuse K_anchor %s", tc.name)
			}
		})
	}
	t.Run("genuinely_independent_key_is_accepted", func(t *testing.T) {
		independent := bytes.Repeat([]byte{0x22}, 32)
		if err := AssertAnchorKeyDisjoint(root, independent, ledgerID); err != nil {
			t.Fatalf("expected a genuinely independent K_anchor to be accepted, got: %v", err)
		}
	})
	t.Run("wrong_length_is_refused", func(t *testing.T) {
		if err := AssertAnchorKeyDisjoint(root, []byte{0x01, 0x02}, ledgerID); err == nil {
			t.Fatal("expected a non-32-byte K_anchor to be refused")
		}
	})
}

// TestD153CtlDirectIsCaughtByTheMACNotTheByteRule confirms the stated
// boundary: a plain value edit (no spelling trickery) is byte-canonical
// (it IS json.Marshal of its own forged struct) and is refused by the
// unchanged MAC, not by the new canonical-bytes check -- the two layers
// are orthogonal and compose.
func TestD153CtlDirectIsCaughtByTheMACNotTheByteRule(t *testing.T) {
	clean := eventFixtureRaw(t)
	edited := replaceOnceInBytes(t, clean, `"http_status":200`, `"http_status":403`)
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, edited, 0o640); err != nil {
		t.Fatal(err)
	}
	decoded, _, err := readCanonicalChainFile[Event](path)
	if err != nil {
		t.Fatalf("expected the canonical-bytes rule to ACCEPT a plain value edit (byte-canonical by construction), got: %v", err)
	}
	key, err := LoadKey("../../test/fixtures/screening-ledger/snapshot-key.hex", "")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := deriveChainKeys(key, decoded.LedgerID)
	if err != nil {
		t.Fatal(err)
	}
	recomputed, err := hashEvent(decoded, keys.chain)
	if err != nil {
		t.Fatal(err)
	}
	if recomputed == decoded.EventSHA256 {
		t.Fatal("expected the MAC to catch this plain value edit (it did not -- test construction bug)")
	}
}
