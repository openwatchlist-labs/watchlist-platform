package screeningledger

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// testPolicy is the "default secure" policy most tests want: no v1
// prefix permitted at all (genesis sequence 1, ADR-0007 EA2's stated
// meaning of that value), floor at v2 for both chains, unanchored not
// allowed. Tests that need a genuine frozen v1 prefix or a relaxed
// policy build their own.
func testPolicy(ledgerID string) VerificationPolicy {
	return VerificationPolicy{
		SchemaVersion:        VerificationPolicySchemaV1,
		LedgerID:             ledgerID,
		MinEventSchema:       EventSchemaV2,
		MinAuditSchema:       AuditSchemaV2,
		GenesisEventSequence: 1,
		GenesisAuditSequence: 1,
	}
}

// testPolicySHA256 wraps PolicySHA256 for tests that don't care about a
// marshal failure (VerificationPolicy has no field that can fail to
// marshal).
func testPolicySHA256(t *testing.T, policy VerificationPolicy) string {
	t.Helper()
	sha, err := PolicySHA256(policy)
	if err != nil {
		t.Fatal(err)
	}
	return sha
}

func testAppendInput() AppendInput {
	return AppendInput{
		Route:          "/v1/screenings",
		HTTPStatus:     200,
		CorrelationID:  "corr-ledger-001",
		IdempotencyKey: "idem-ledger-001",
		RequestBytes:   []byte(`{"request_id":"req-1","name":"ALICE EXAMPLE","account_number":"123456789"}`),
		ResponseBytes:  []byte(`{"request_id":"req-1","activation_tuple":{"activation_id":"activation-a","catalog_package_sha256":"cat","projection_package_sha256":"proj","scoring_policy_sha256":"policy","normalization_profile":"unicode-upper-alnum-space-v1"},"promotion":{"intent_id":"promotion-a","phase":"promoted"},"candidates":[{"candidate_id":"cand-1","score":910,"band":"high_similarity","reason_codes":["name_exact"]}],"blockers":[]}`),
		OccurredAt:     "2026-07-14T22:30:00Z",
		Retention:      RetentionPolicy{Class: "screening-standard", RetentionDays: 1, RedactKeys: []string{"account_number"}, HashKeys: []string{"name"}, MaxSnapshotBytes: 2 * 1024 * 1024},
	}
}

func TestMarshalAndWriteSurfacesMarshalError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.json")
	if err := marshalAndWrite(path, make(chan int), 0o640); err == nil {
		t.Fatal("expected marshalAndWrite to return an error for a value json.Marshal cannot encode")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected no file to be written when marshaling fails, stat error: %v", statErr)
	}
}

func TestAppendReplayVerifyExportReplayAndPurge(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), "ledger-test")
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Append(testAppendInput())
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Append(testAppendInput())
	if err != nil {
		t.Fatal(err)
	}
	if second.Event.EventID != first.Event.EventID || !second.Replayed {
		t.Fatalf("idempotent replay mismatch: %#v", second)
	}
	verifyReport, err := store.VerifyPolicy(context.Background(), VerifyOptions{Policy: testPolicy("ledger-test")})
	if err != nil {
		t.Fatal(err)
	}
	head := verifyReport.Head
	if head.Sequence != 1 || head.EventID != first.Event.EventID {
		t.Fatalf("unexpected head: %#v", head)
	}
	if first.Event.RequestSHA256 != digestHex(testAppendInput().RequestBytes) || first.Event.ResponseSHA256 != digestHex(testAppendInput().ResponseBytes) {
		t.Fatal("raw byte checksum mismatch")
	}

	snapshotEntries, err := os.ReadDir(filepath.Join(directory, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range snapshotEntries {
		raw, err := os.ReadFile(filepath.Join(directory, "snapshots", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("123456789")) || bytes.Contains(raw, []byte("ALICE EXAMPLE")) {
			t.Fatalf("plaintext leaked into %s", entry.Name())
		}
	}

	bundle := filepath.Join(t.TempDir(), "audit.zip")
	manifest, err := store.ExportBundle(first.Event.EventID, bundle, "redacted", testAppendInput().Retention)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.EventID != first.Event.EventID || manifest.BundleSHA256 == "" {
		t.Fatalf("invalid manifest: %#v", manifest)
	}
	zr, err := zip.OpenReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	foundRedaction := false
	for _, file := range zr.File {
		if file.Name != "request.json" {
			continue
		}
		rc, _ := file.Open()
		raw, _ := io.ReadAll(rc)
		_ = rc.Close()
		if strings.Contains(string(raw), "[REDACTED]") && !strings.Contains(string(raw), "123456789") {
			foundRedaction = true
		}
	}
	if !foundRedaction {
		t.Fatal("redacted request not found in audit bundle")
	}

	exactServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(testAppendInput().ResponseBytes)
	}))
	defer exactServer.Close()
	report, err := store.Replay(context.Background(), first.Event.EventID, exactServer.URL, exactServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "exact" {
		t.Fatalf("expected exact replay: %#v", report)
	}

	driftServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"candidates":[{"candidate_id":"cand-2","score":800}]}`))
	}))
	defer driftServer.Close()
	report, err = store.Replay(context.Background(), first.Event.EventID, driftServer.URL, driftServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "explainable_drift" || len(report.CandidateDelta) == 0 {
		t.Fatalf("expected drift report: %#v", report)
	}

	count, err := store.PurgeExpired(time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC), "retention-test", "expired")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected two purged snapshots, got %d", count)
	}
	if _, err := store.DecryptSnapshot(first.Event.RequestSnapshotSHA256); err == nil {
		t.Fatal("purged snapshot unexpectedly decryptable")
	}
	// Filesystem-only (no PurgeChecker): the purged snapshots above have
	// no independent record available, so anchored mode's default fails
	// them (ADR-0007 D13/F8) -- explicitly select historical-unanchored
	// with a policy that allows it to confirm the rest of the chain still
	// verifies.
	unanchoredPolicy := testPolicy("ledger-test")
	unanchoredPolicy.AllowUnanchored = true
	if _, err := store.VerifyPolicy(context.Background(), VerifyOptions{Policy: unanchoredPolicy, Mode: VerificationModeHistoricalUnanchored}); err != nil {
		t.Fatalf("event chain must remain verifiable after purge: %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey(), "ledger-tamper")
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Append(testAppendInput())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Directory(), "events", result.Event.EventID+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	event.HTTPStatus = 500
	raw, _ = json.Marshal(event)
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyPolicy(context.Background(), VerifyOptions{Policy: testPolicy("ledger-tamper")}); err == nil {
		t.Fatal("tampered event was accepted")
	}
}

// PostgresSink's own contract -- migration, persistence, the
// idempotency-conflict guard, purge, and external audit -- is exercised
// against a live Postgres connection in postgres_pgx_test.go (ADR-0005
// §8.2). It cannot be tested with a fake command runner any more: pgx
// speaks the wire protocol directly, there is no fork to intercept.

func TestLegalHoldAndInterruptedRecovery(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), "ledger-recovery")
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Append(testAppendInput())
	if err != nil {
		t.Fatal(err)
	}

	holdPath := filepath.Join(directory, "holds", result.Event.EventID)
	if err := os.WriteFile(holdPath, []byte("legal hold\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	count, err := store.PurgeExpired(time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC), "retention-test", "expired")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("legal hold did not prevent purge: %d", count)
	}
	if err := os.Remove(holdPath); err != nil {
		t.Fatal(err)
	}

	eventRaw, err := os.ReadFile(filepath.Join(directory, "events", result.Event.EventID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "pending.json"), eventRaw, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, "head.json")); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewStore(directory, testKey(), "ledger-recovery")
	if err != nil {
		t.Fatal(err)
	}
	report, err := recovered.VerifyPolicy(context.Background(), VerifyOptions{Policy: testPolicy("ledger-recovery")})
	if err != nil {
		t.Fatal(err)
	}
	head := report.Head
	if head.EventID != result.Event.EventID {
		t.Fatalf("interrupted head was not recovered: %#v", head)
	}
	if _, err := os.Stat(filepath.Join(directory, "pending.json")); !os.IsNotExist(err) {
		t.Fatal("pending transaction was not removed")
	}
}

func TestPhase8FAuditVerificationAndImport(t *testing.T) {
	directory := t.TempDir()
	event := phase8fAuditEvent{SchemaVersion: "openwatchlist.activation-promotion-audit-event.v1", Sequence: 1, Timestamp: "2026-07-14T22:02:51Z", EventType: "promotion_prepared", IntentID: "promotion-fixture", Revision: 1, Actor: "validator", Payload: map[string]any{"candidate_activation_id": "activation-candidate"}}
	canonical, _ := json.Marshal(event)
	event.EventSHA256 = digestHex(append(canonical, '\n'))
	raw, _ := json.Marshal(event)
	path := filepath.Join(directory, "00000000000000000001-"+event.EventSHA256+".json")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	records, err := LoadExternalAuditDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].EventSHA256 != event.EventSHA256 {
		t.Fatalf("unexpected imported audit: %#v", records)
	}
	// ImportExternalAudit's actual persistence to watchlist_operational_audit
	// is covered against a live Postgres connection in
	// TestImportExternalAuditRoundTrip (postgres_pgx_test.go, ADR-0005 §8.2).
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExternalAuditDirectory(directory); err == nil {
		t.Fatal("tampered Phase 8F audit was accepted")
	}
}
