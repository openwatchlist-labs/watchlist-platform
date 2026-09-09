// ADR-0007 Addendum 10 shared test scaffolding, used by the D87/D88/D89
// test files. a10Chain extends newD70Chain's pattern with an extra,
// deliberately unanchored event so an anchor gap exists (anchors at
// event sequences 1, 2 and 4, sequence 3 unanchored) -- the shape N-A's
// limb 2 needs to plant a spurious anchor into.
package screeningledger

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type a10Chain struct {
	store           *Store
	sink            *PostgresSink
	anchorSink      *AnchorSink
	kAnchor         []byte
	policy          VerificationPolicy
	policySHA256    string
	purgedSHA       string
	purgedEvent     Event
	clone           d50CloneFixture
	migratorDSN     string
	ledgerAnchorDSN string
	scriptPath      string
	superuserDSN    string
}

func newA10Chain(t *testing.T, ctx context.Context) a10Chain {
	t.Helper()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	anchorDSN := requireAnchorDatabaseURL(t)

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
	cloneAnchorDSN := withDatabase(t, anchorDSN, clone.dbName)

	directory := t.TempDir()
	store, err := NewStore(directory, testKey(), uniqueID("sec7-a10"))
	if err != nil {
		t.Fatal(err)
	}

	kAnchor := make([]byte, 32)
	for i := range kAnchor {
		kAnchor[i] = byte(i + 11)
	}

	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	t.Cleanup(func() { sink.Close(context.Background()) })

	mirror := func(result AppendResult) {
		request, err := store.LoadSnapshot(result.Event.RequestSnapshotSHA256)
		if err != nil {
			t.Fatal(err)
		}
		response, err := store.LoadSnapshot(result.Event.ResponseSnapshotSHA256)
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.Persist(ctx, result.Event, request, response, ReplicationVerification{}); err != nil {
			t.Fatal(err)
		}
	}

	policy := testPolicy(store.ledgerID)
	policySHA256 := testPolicySHA256(t, policy)

	anchorSink, err := NewAnchorSink(ctx, cloneAnchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	t.Cleanup(func() { anchorSink.Close(context.Background()) })

	if _, err := store.AppendAudit("a10-setup", "", "", "", nil); err != nil {
		t.Fatal(err)
	}

	appendEvent := func(expired bool, tag string) AppendResult {
		input := testAppendInput()
		input.CorrelationID = uniqueID("corr-" + tag)
		input.IdempotencyKey = uniqueID("idem-" + tag)
		input.RequestBytes = []byte(`{"unique":"` + uniqueID("req-"+tag) + `"}`)
		input.ResponseBytes = []byte(`{"unique":"` + uniqueID("resp-"+tag) + `"}`)
		if expired {
			input.OccurredAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
			input.Retention.RetentionDays = 1
		} else {
			input.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
			input.Retention.RetentionDays = 3650
		}
		result, err := store.Append(input)
		if err != nil {
			t.Fatal(err)
		}
		mirror(result)
		return result
	}

	anchorAt := func(report VerifyReport) {
		if err := anchorSink.WriteAnchor(ctx, kAnchor, store.ledgerID, int64(report.Head.Sequence), report.Head.EventSHA256, report.AuditHead.EventSHA256, int64(report.AuditHead.Sequence), policySHA256); err != nil {
			t.Fatalf("WriteAnchor: %v", err)
		}
	}

	result1 := appendEvent(true, "e1")
	report1, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy, Purges: sink})
	if err != nil {
		t.Fatalf("VerifyPolicy after event1: %v", err)
	}
	anchorAt(report1) // anchor seq=1

	appendEvent(false, "e2")
	report2, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy, Purges: sink})
	if err != nil {
		t.Fatalf("VerifyPolicy after event2: %v", err)
	}
	anchorAt(report2) // anchor seq=2

	appendEvent(false, "e3") // deliberately unanchored -- the gap

	purgedCount, err := store.PurgeExpired(ctx, time.Now(), "legit-operator", "legit-reason", TenancyExclusive, sink)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if purgedCount != 2 {
		t.Fatalf("expected 2 purged snapshots (event1's request+response), got %d", purgedCount)
	}

	appendEvent(false, "e4")
	report4, err := store.VerifyPolicy(ctx, VerifyOptions{Policy: policy, Purges: sink, allowDeferredPurgeClaims: true})
	if err != nil {
		t.Fatalf("VerifyPolicy after event4: %v", err)
	}
	anchorAt(report4) // anchor seq=4, attests to the purge

	return a10Chain{
		store: store, sink: sink, anchorSink: anchorSink, kAnchor: kAnchor,
		policy: policy, policySHA256: policySHA256, purgedSHA: result1.Event.RequestSnapshotSHA256,
		purgedEvent: result1.Event,
		clone:       clone, migratorDSN: cloneMigratorDSN, ledgerAnchorDSN: cloneAnchorDSN,
		scriptPath: d62ScriptPath(t), superuserDSN: clone.superuserDSN,
	}
}

func (chain a10Chain) verify(t *testing.T, ctx context.Context) (AnchorVerifyResult, error) {
	t.Helper()
	return chain.store.VerifyAnchored(ctx, AnchorOptions{
		VerifyOptions: VerifyOptions{Policy: chain.policy, Purges: chain.sink},
		Anchors:       chain.sink, Provisioning: chain.sink, KAnchor: chain.kAnchor, PolicySHA256: chain.policySHA256,
	})
}

func (chain a10Chain) ledgerDDLConn(t *testing.T, ctx context.Context) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, withDatabase(t, requireLedgerDDLDatabaseURL(t), chain.clone.dbName))
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	return conn
}

func (chain a10Chain) anchorConn(t *testing.T, ctx context.Context) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, chain.ledgerAnchorDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_anchor: %v", err)
	}
	return conn
}
