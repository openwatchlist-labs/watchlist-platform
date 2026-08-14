// ADR-0007 D5, the two §7.1 cases that need a live anchor row and
// therefore a live Postgres connection (case 2, tail truncation vs
// anchor; case 4, anchor divergence), plus the real committed fixture's
// own genesis anchor -- exercising Store.VerifyAnchored end to end, file
// chain and DB anchor together, the same empirical standard Stage 2 held
// D3's role-separation proof to (anchor_pgx_test.go).
package screeningledger

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// anchorTestKeys builds a Store, appends n events, and returns the store
// plus the K_anchor this test will use to write and check anchor rows.
func anchorTestKeys(t *testing.T, n int) (*Store, []byte) {
	t.Helper()
	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), uniqueID("ledger-anchor-verify"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		// testAppendInput() is identical every call; Append's own
		// idempotency check (identityParts includes CorrelationID and
		// IdempotencyKey) would otherwise collapse all n calls into one
		// replayed event instead of n distinct ones.
		input := testAppendInput()
		input.CorrelationID = uniqueID("corr")
		input.IdempotencyKey = uniqueID("idem")
		if _, err := store.Append(input); err != nil {
			t.Fatal(err)
		}
	}
	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 1)
	}
	return store, kAnchor
}

// TestVerifyAnchoredRealFixtureGenesis is the real committed fixture's
// own genesis anchor, written for real over a live connection (not
// asserted as data-only) and cross-checked by the real VerifyAnchored
// path -- ADR-0007 §6's "the genesis is anchored immediately" made
// concrete, and the combined file+DB empirical proof this stage's
// kickoff asked for explicitly.
func TestVerifyAnchoredRealFixtureGenesis(t *testing.T) {
	anchorDSN := requireAnchorDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	directory := t.TempDir()
	copyDir(t, "../../test/fixtures/screening-ledger/state", directory)
	key, err := LoadKey("../../test/fixtures/screening-ledger/snapshot-key.hex", "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(directory, key, "screening-api-v8g-example")
	if err != nil {
		t.Fatal(err)
	}
	report, err := store.VerifyDetail()
	if err != nil {
		t.Fatalf("real fixture must verify before it can be anchored: %v", err)
	}
	if report.EventFrozenPrefixLength != 0 {
		t.Fatalf("real fixture's event chain was relabeled v2, not frozen (ADR-0007 §6 correction note); expected frozen prefix length 0, got %d", report.EventFrozenPrefixLength)
	}

	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 100)
	}

	// Use a unique ledger ID for the anchor row so repeated local runs
	// against a persistent database don't collide on the anchor table's
	// primary key -- the file chain's own ledger ID stays the fixture's
	// real one (durable ledger-id file, checked by NewStore), so this
	// substitutes only the identifier the anchor row is keyed under.
	anchorLedgerID := uniqueID("screening-api-v8g-example-genesis")

	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	defer anchorSink.Close(context.Background())
	if err := anchorSink.WriteAnchor(ctx, kAnchor, anchorLedgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256); err != nil {
		t.Fatalf("WriteAnchor for real fixture genesis: %v", err)
	}

	readerSink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer readerSink.Close(context.Background())

	// store's own ledgerID is the fixture's real, durable one
	// ("screening-api-v8g-example" -- NewStore pins it from the
	// committed ledger-id file and rejects a mismatched override), so
	// this adapter redirects VerifyAnchored's anchor lookup to the
	// disposable anchorLedgerID the row above was actually written
	// under, without needing to mutate the committed fixture's identity.
	result, err := store.VerifyAnchored(ctx, &anchorReaderForLedger{sink: readerSink, ledgerID: anchorLedgerID}, kAnchor)
	if err != nil {
		t.Fatalf("VerifyAnchored: %v", err)
	}
	if result.AnchorStatus != AnchorStatusVerified {
		t.Fatalf("expected AnchorStatusVerified, got %q", result.AnchorStatus)
	}
	if result.AnchorSequence != int64(report.Head.Sequence) {
		t.Fatalf("anchor sequence = %d, want %d", result.AnchorSequence, report.Head.Sequence)
	}
}

// anchorReaderForLedger adapts PostgresSink.LatestAnchor to look up a
// different ledger ID than the Store's own -- only needed by the test
// above, which anchors the real fixture under a disposable, collision-free
// ID while the file chain keeps its real, fixture-pinned ledger ID.
type anchorReaderForLedger struct {
	sink     *PostgresSink
	ledgerID string
}

func (a *anchorReaderForLedger) LatestAnchor(ctx context.Context, _ string) (Anchor, bool, error) {
	return a.sink.LatestAnchor(ctx, a.ledgerID)
}

// TestVerifyAnchoredDetectsTailTruncation is ADR-0007 §7.1 case 2: delete
// the newest entries, rewrite the head consistently (so the file chain
// alone, per Store.Verify, looks perfectly fine), and confirm
// VerifyAnchored still catches the shortfall by comparing against the
// newest anchor -- ADR-0007 §5.3 point 4's "fails if the current head is
// behind the newest anchor... even when the head file itself was
// rewritten consistently."
func TestVerifyAnchoredDetectsTailTruncation(t *testing.T) {
	anchorDSN := requireAnchorDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	store, kAnchor := anchorTestKeys(t, 3)
	report, err := store.VerifyDetail()
	if err != nil {
		t.Fatal(err)
	}

	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer anchorSink.Close(context.Background())
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	// Truncate the tail: delete the newest event and rewrite head.json
	// to point at the entry before it -- internally consistent, and
	// Store.Verify alone accepts it, since nothing about the remaining
	// two entries is individually wrong.
	events, err := store.ListEvents()
	if err != nil {
		t.Fatal(err)
	}
	newest := events[len(events)-1]
	remaining := events[len(events)-2]
	if err := os.Remove(store.eventPath(newest.EventID)); err != nil {
		t.Fatal(err)
	}
	truncatedHead := Head{SchemaVersion: HeadSchemaV2, LedgerID: store.ledgerID, Sequence: remaining.Sequence, EventID: remaining.EventID, EventSHA256: remaining.EventSHA256}
	if err := marshalAndWrite(filepath.Join(store.Directory(), "head.json"), truncatedHead, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(); err != nil {
		t.Fatalf("file-only Verify must accept the consistently-rewritten (truncated) chain -- that is the whole point of needing the anchor cross-check: %v", err)
	}

	readerSink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer readerSink.Close(context.Background())

	if _, err := store.VerifyAnchored(ctx, readerSink, kAnchor); err == nil {
		t.Fatal("SEC-7 D5 case 2: tail truncation behind the newest anchor was not detected")
	} else if !strings.Contains(err.Error(), "tail truncation") {
		t.Fatalf("expected a tail-truncation error, got: %v", err)
	}
}

// TestVerifyAnchoredDetectsDivergence is ADR-0007 §7.1 case 4: a chain
// that is fully valid and correctly MACed under K_chain, but disagrees
// with what a stored anchor row committed to, must fail. This is
// distinct from case 1 (D5's load-bearing proof, an adversary without
// K_chain) -- this models an adversary who DOES hold K_chain (the
// residual ADR-0007 §5.2 names explicitly) tampering an already-anchored
// entry and correctly re-MACing everything downstream, which Store.Verify
// alone cannot catch since every HMAC is genuinely valid. Only the
// anchor, written by a different key and a different role the adversary
// in this scenario does not also control, catches it.
func TestVerifyAnchoredDetectsDivergence(t *testing.T) {
	anchorDSN := requireAnchorDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	store, kAnchor := anchorTestKeys(t, 2)
	report, err := store.VerifyDetail()
	if err != nil {
		t.Fatal(err)
	}

	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer anchorSink.Close(context.Background())
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	// Tamper the anchored (newest) entry's content and re-MAC it under
	// the real K_chain -- a holder of K_chain, but not K_anchor, doing
	// exactly what they can do.
	events, err := store.ListEvents()
	if err != nil {
		t.Fatal(err)
	}
	tampered := events[len(events)-1]
	tampered.HTTPStatus = 777
	newSHA, err := hashEvent(tampered, store.keys.chain)
	if err != nil {
		t.Fatal(err)
	}
	tampered.EventSHA256 = newSHA
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.eventPath(tampered.EventID), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	newHead := Head{SchemaVersion: HeadSchemaV2, LedgerID: store.ledgerID, Sequence: tampered.Sequence, EventID: tampered.EventID, EventSHA256: tampered.EventSHA256}
	if err := marshalAndWrite(filepath.Join(store.Directory(), "head.json"), newHead, 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Verify(); err != nil {
		t.Fatalf("file-only Verify must accept the re-MACed tamper (the holder has K_chain) -- that is the residual ADR-0007 §5.2/5.3 exist to close: %v", err)
	}

	readerSink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer readerSink.Close(context.Background())

	if _, err := store.VerifyAnchored(ctx, readerSink, kAnchor); err == nil {
		t.Fatal("SEC-7 D5 case 4: a chain valid under K_chain but diverging from the anchor was not detected")
	} else if !strings.Contains(err.Error(), "disagrees with the anchor") {
		t.Fatalf("expected an anchor-divergence error, got: %v", err)
	}
}

// TestVerifyAnchoredAbsentAndUnavailable rounds out the AnchorVerifyStatus
// states: AnchorStatusAbsent (database reachable, no anchor row for this
// ledger yet) must not be conflated with AnchorStatusVerified, and a nil
// AnchorReader (no database configured at all) must produce
// AnchorStatusUnavailable rather than silently reporting success --
// ADR-0007 Consequences: "verify on a host with no database becomes a
// partial check that must say so rather than returning ok."
func TestVerifyAnchoredAbsentAndUnavailable(t *testing.T) {
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	store, kAnchor := anchorTestKeys(t, 1)

	readerSink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer readerSink.Close(context.Background())

	result, err := store.VerifyAnchored(ctx, readerSink, kAnchor)
	if err != nil {
		t.Fatalf("an unanchored ledger must not error: %v", err)
	}
	if result.AnchorStatus != AnchorStatusAbsent {
		t.Fatalf("expected AnchorStatusAbsent, got %q", result.AnchorStatus)
	}

	result, err = store.VerifyAnchored(ctx, nil, kAnchor)
	if err != nil {
		t.Fatalf("nil AnchorReader must not error: %v", err)
	}
	if result.AnchorStatus != AnchorStatusUnavailable {
		t.Fatalf("expected AnchorStatusUnavailable for a nil AnchorReader, got %q", result.AnchorStatus)
	}
}
