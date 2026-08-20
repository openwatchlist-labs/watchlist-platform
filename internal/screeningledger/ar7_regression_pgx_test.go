// ADR-0007 Addendum 2 D29 (F-B, LOW): AR7's audit-chain cross-check
// (anchor.go's audit-sequence half of VerifyAnchored) was probed live by
// the CAP and found correct -- this is coverage closure, not a design
// question. The three cases here are the ones no committed test reached:
// grepping every *_test.go in this package for AuditSequence,
// eventAtSequence and auditEntryAtSequence before this file returns no
// test usage at all (CAP §7.2/D29's own finding). Each test asserts both
// halves D29 requires: that VerifyPolicy ALONE accepts the manipulated
// chain (proving the anchor, not some other check, is what catches it),
// and that VerifyAnchored rejects it.
package screeningledger

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// anchorTestKeysWithAudit is anchorTestKeys extended to also append n
// real audit entries via AppendAudit -- anchorTestKeys's own plain
// Append loop never writes one (AppendAudit's call sites are
// postgres_replicated/replay/export_bundle/purge_expired, none of which
// a bare Append reaches), so AR7's audit-chain cross-check has nothing
// to exercise against without this.
func anchorTestKeysWithAudit(t *testing.T, nEvents, nAudit int) (*Store, []byte) {
	t.Helper()
	store, kAnchor := anchorTestKeys(t, nEvents)
	for i := 0; i < nAudit; i++ {
		if _, err := store.AppendAudit("postgres_replicated", "test-operator", "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	return store, kAnchor
}

// relinkEventChainFrom recomputes EventSHA256/PreviousEventSHA256 for
// every event at sequence >= fromSeq (mutate is applied to the entry AT
// fromSeq only, before recomputation), writes each entry back under the
// real chain key, and rewrites head.json to match -- an adversary
// holding K_chain re-MACing everything downstream of a historical
// tamper, exactly as ADR-0007 §5.2's residual describes.
func relinkEventChainFrom(t *testing.T, store *Store, fromSeq uint64, mutate func(*Event)) {
	t.Helper()
	events, err := store.ListEvents()
	if err != nil {
		t.Fatal(err)
	}
	previous := ""
	if fromSeq > 1 {
		prior, err := store.eventAtSequence(fromSeq - 1)
		if err != nil {
			t.Fatal(err)
		}
		previous = prior.EventSHA256
	}
	var newHead Head
	for _, event := range events {
		if event.Sequence < fromSeq {
			previous = event.EventSHA256
			continue
		}
		if event.Sequence == fromSeq {
			mutate(&event)
		}
		event.PreviousEventSHA256 = previous
		sha, err := hashEvent(event, store.keys.chain)
		if err != nil {
			t.Fatal(err)
		}
		event.EventSHA256 = sha
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.eventPath(event.EventID), raw, 0o640); err != nil {
			t.Fatal(err)
		}
		previous = event.EventSHA256
		newHead = Head{SchemaVersion: HeadSchemaV2, LedgerID: store.ledgerID, Sequence: event.Sequence, EventID: event.EventID, EventSHA256: event.EventSHA256}
	}
	if err := marshalAndWrite(filepath.Join(store.Directory(), "head.json"), newHead, 0o640); err != nil {
		t.Fatal(err)
	}
}

// relinkAuditChainFrom mirrors relinkEventChainFrom for the audit chain.
// Audit entry files are named by sequence and digest
// (audit.go:AppendAudit's "%020d-%s.json"), so the tampered/relinked
// entry is written under a fresh filename and the stale one removed.
func relinkAuditChainFrom(t *testing.T, store *Store, fromSeq uint64, mutate func(*AuditEvent)) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(store.Directory(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	type pair struct {
		name  string
		event AuditEvent
	}
	all := make([]pair, 0, len(entries))
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(store.Directory(), "audit", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var ev AuditEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		all = append(all, pair{name: e.Name(), event: ev})
	}
	previous := ""
	if fromSeq > 1 {
		prior, err := store.auditEntryAtSequence(fromSeq - 1)
		if err != nil {
			t.Fatal(err)
		}
		previous = prior.AuditSHA256
	}
	var newHead Head
	for _, p := range all {
		event := p.event
		if event.Sequence < fromSeq {
			previous = event.AuditSHA256
			continue
		}
		if err := os.Remove(filepath.Join(store.Directory(), "audit", p.name)); err != nil {
			t.Fatal(err)
		}
		if event.Sequence == fromSeq {
			mutate(&event)
		}
		event.PreviousAuditSHA256 = previous
		sha, err := hashAudit(event, store.keys.chain)
		if err != nil {
			t.Fatal(err)
		}
		event.AuditSHA256 = sha
		newName := auditFileName(event.Sequence, event.AuditSHA256)
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store.Directory(), "audit", newName), raw, 0o640); err != nil {
			t.Fatal(err)
		}
		previous = event.AuditSHA256
		newHead = Head{SchemaVersion: HeadSchemaV2, LedgerID: store.ledgerID, Sequence: event.Sequence, EventSHA256: event.AuditSHA256}
	}
	if err := marshalAndWrite(filepath.Join(store.Directory(), "audit-head.json"), newHead, 0o640); err != nil {
		t.Fatal(err)
	}
}

// auditFileName mirrors AppendAudit's own naming (audit.go), so tests can
// address a specific audit entry's file directly.
func auditFileName(seq uint64, sha string) string {
	return fmt.Sprintf("%020d-%s.json", seq, sha)
}

// TestVerifyAnchoredDetectsAuditTailTruncation is D29 case 1, the
// audit-chain counterpart of verify_anchor_pgx_test.go's
// TestVerifyAnchoredDetectsTailTruncation (event chain).
func TestVerifyAnchoredDetectsAuditTailTruncation(t *testing.T) {
	anchorDSN := requireAnchorDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	store, kAnchor := anchorTestKeysWithAudit(t, 2, 3)
	policy := testPolicy(store.ledgerID)
	policySHA256 := testPolicySHA256(t, policy)
	report, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}

	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer anchorSink.Close(context.Background())
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), policySHA256); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	// Delete the newest audit entry and rewrite audit-head.json to point
	// at the entry before it -- internally consistent, so VerifyPolicy
	// alone accepts it.
	newest, err := store.auditEntryAtSequence(3)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := store.auditEntryAtSequence(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store.Directory(), "audit", auditFileName(newest.Sequence, newest.AuditSHA256))); err != nil {
		t.Fatal(err)
	}
	truncatedHead := Head{SchemaVersion: HeadSchemaV2, LedgerID: store.ledgerID, Sequence: remaining.Sequence, EventSHA256: remaining.AuditSHA256}
	if err := marshalAndWrite(filepath.Join(store.Directory(), "audit-head.json"), truncatedHead, 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy}); err != nil {
		t.Fatalf("file-only VerifyPolicy must accept the consistently-rewritten (truncated) audit chain: %v", err)
	}

	readerSink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer readerSink.Close(context.Background())

	_, err = store.VerifyAnchored(ctx, AnchorOptions{VerifyOptions: VerifyOptions{Policy: policy}, Anchors: readerSink, KAnchor: kAnchor, PolicySHA256: policySHA256})
	if err == nil {
		t.Fatal("AR7: audit-chain tail truncation behind the newest anchor's audit_sequence was not detected")
	}
	if !strings.Contains(err.Error(), "possible tail truncation (AR7)") {
		t.Fatalf("expected an AR7 tail-truncation error, got: %v", err)
	}
}

// TestVerifyAnchoredDetectsAuditDivergence is D29 case 2: an audit entry
// tampered and re-MACed under the real K_chain (the adversary §5.2/§5.3
// name explicitly -- holds the chain key, not the anchor key) must be
// caught by the anchor's committed audit digest, not by VerifyPolicy.
func TestVerifyAnchoredDetectsAuditDivergence(t *testing.T) {
	anchorDSN := requireAnchorDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	store, kAnchor := anchorTestKeysWithAudit(t, 2, 2)
	policy := testPolicy(store.ledgerID)
	policySHA256 := testPolicySHA256(t, policy)
	report, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}

	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer anchorSink.Close(context.Background())
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), policySHA256); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	// Tamper the newest (anchored) audit entry's content and re-MAC it
	// under the real K_chain -- no cascading relink needed since it's
	// already the tail.
	relinkAuditChainFrom(t, store, report.AuditHead.Sequence, func(e *AuditEvent) {
		e.Reason = "tampered-by-K_chain-holder"
	})

	if _, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy}); err != nil {
		t.Fatalf("file-only VerifyPolicy must accept the re-MACed audit tamper (the holder has K_chain): %v", err)
	}

	readerSink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer readerSink.Close(context.Background())

	_, err = store.VerifyAnchored(ctx, AnchorOptions{VerifyOptions: VerifyOptions{Policy: policy}, Anchors: readerSink, KAnchor: kAnchor, PolicySHA256: policySHA256})
	if err == nil {
		t.Fatal("AR7: an audit chain valid under K_chain but diverging from the anchor's committed audit digest was not detected")
	}
	if !strings.Contains(err.Error(), "disagrees with the anchor's committed audit digest") {
		t.Fatalf("expected an AR7 audit-divergence error, got: %v", err)
	}
}

// TestVerifyAnchoredDetectsHistoricalTamperBelowAnchor is D29 case 3, the
// most load-bearing one: anchor at an early sequence, let both chains
// legitimately grow past it, then tamper the entry AT the anchored
// sequence (both event and audit) and re-MAC everything downstream. This
// is the only case that drives latest.Sequence != report.Head.Sequence
// AND latest.AuditSequence != report.AuditHead.Sequence simultaneously,
// so it is the first exercise by anything of both eventAtSequence and
// auditEntryAtSequence (otherwise dead code) in the same run. Both
// branches are asserted -- covering only one would leave half the
// historical lookup still dead, exactly the gap D29 names.
func TestVerifyAnchoredDetectsHistoricalTamperBelowAnchor(t *testing.T) {
	anchorDSN := requireAnchorDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	// 4 events, 4 audit entries: anchor at sequence 2, then sequences 3-4
	// are the legitimate growth past the anchor.
	store, kAnchor := anchorTestKeysWithAudit(t, 4, 4)
	policy := testPolicy(store.ledgerID)
	policySHA256 := testPolicySHA256(t, policy)

	eventAtTwo, err := store.eventAtSequence(2)
	if err != nil {
		t.Fatal(err)
	}
	auditAtTwo, err := store.auditEntryAtSequence(2)
	if err != nil {
		t.Fatal(err)
	}

	anchorSink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer anchorSink.Close(context.Background())
	if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, 2, eventAtTwo.EventSHA256, auditAtTwo.AuditSHA256, 2, policySHA256); err != nil {
		t.Fatalf("WriteAnchor at sequence 2: %v", err)
	}

	// Tamper the anchored entries themselves (sequence 2) and cascade the
	// re-link through sequences 3-4, under the real K_chain.
	relinkEventChainFrom(t, store, 2, func(e *Event) { e.HTTPStatus = 555 })
	relinkAuditChainFrom(t, store, 2, func(e *AuditEvent) { e.Reason = "historically-tampered" })

	report, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy})
	if err != nil {
		t.Fatalf("file-only VerifyPolicy must accept the re-MACed historical tamper (the holder has K_chain): %v", err)
	}
	if report.Head.Sequence != 4 {
		t.Fatalf("expected the chain to have legitimately grown to sequence 4, got %d", report.Head.Sequence)
	}

	readerSink, err := NewPostgresSink(ctx, migratorDSN, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer readerSink.Close(context.Background())

	_, err = store.VerifyAnchored(ctx, AnchorOptions{VerifyOptions: VerifyOptions{Policy: policy}, Anchors: readerSink, KAnchor: kAnchor, PolicySHA256: policySHA256})
	if err == nil {
		t.Fatal("a historical tamper at the anchored sequence, re-MACed and re-linked through legitimate growth, was not detected")
	}
	if !strings.Contains(err.Error(), "chain digest at sequence 2") || !strings.Contains(err.Error(), "disagrees with the anchor's committed digest") {
		t.Fatalf("expected the event-chain historical-divergence error naming sequence 2, got: %v", err)
	}

	// Second half: with the event tamper fixed (re-anchor would be the
	// real remediation, but for this test's purpose of driving the AUDIT
	// half of the historical lookup independently), tamper only the
	// audit chain at the anchored sequence on a second, otherwise-clean
	// store instance built the same way.
	store2, kAnchor2 := anchorTestKeysWithAudit(t, 4, 4)
	eventAtTwo2, err := store2.eventAtSequence(2)
	if err != nil {
		t.Fatal(err)
	}
	auditAtTwo2, err := store2.auditEntryAtSequence(2)
	if err != nil {
		t.Fatal(err)
	}
	policy2 := testPolicy(store2.ledgerID)
	policySHA2562 := testPolicySHA256(t, policy2)
	if err := anchorSink.WriteAnchor(ctx, kAnchor2, store2.ledgerID, 2, eventAtTwo2.EventSHA256, auditAtTwo2.AuditSHA256, 2, policySHA2562); err != nil {
		t.Fatalf("WriteAnchor (audit-only case) at sequence 2: %v", err)
	}
	relinkAuditChainFrom(t, store2, 2, func(e *AuditEvent) { e.Reason = "audit-only-historical-tamper" })

	if _, err := store2.VerifyPolicy(ctx, VerifyOptions{Policy: policy2}); err != nil {
		t.Fatalf("file-only VerifyPolicy must accept the audit-only re-MACed historical tamper: %v", err)
	}

	_, err = store2.VerifyAnchored(ctx, AnchorOptions{VerifyOptions: VerifyOptions{Policy: policy2}, Anchors: readerSink, KAnchor: kAnchor2, PolicySHA256: policySHA2562})
	if err == nil {
		t.Fatal("a historical AUDIT tamper at the anchored sequence, re-MACed and re-linked through legitimate growth, was not detected")
	}
	if !strings.Contains(err.Error(), "audit chain digest at sequence 2") || !strings.Contains(err.Error(), "disagrees with the anchor's committed audit digest") {
		t.Fatalf("expected the audit-chain historical-divergence error naming sequence 2, got: %v", err)
	}
}
