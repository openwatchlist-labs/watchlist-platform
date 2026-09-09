// ADR-0007 Addendum 13 D120 test file (D122 item 10): F-F's six shapes,
// reproduced independently against the real, unmodified
// ShortfallExplainedByUnreplicatedEvents through a real Store.Append/
// MarkReplicated/IsReplicated chain, before this addendum's fix was
// designed -- these tests build them fresh, not re-derived from the ADR
// transcript. DSN-free: the discriminator's own mirror-side input is a
// fakeMirrorEventReader standing in for PostgresSink.
// MirroredEventIDsForSnapshot, the same convention fakePurgeRecorder
// (store_test.go) already establishes for PurgeRecorder.
package screeningledger

import (
	"context"
	"fmt"
	"testing"
)

// fakeMirrorEventReader implements MirrorEventReader by returning a
// fixed, pre-declared set of event ids for any snapshot -- letting each
// subtest control exactly which of a shape's events the "mirror" has,
// independent of a live Postgres connection.
type fakeMirrorEventReader struct {
	mirroredEventIDs map[string]bool
}

func (f fakeMirrorEventReader) MirroredEventIDsForSnapshot(ctx context.Context, snapshotSHA256, ledgerID string) ([]string, error) {
	var ids []string
	for id, ok := range f.mirroredEventIDs {
		if ok {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// letterState is one event's (mirrored, replicated) pair -- m = Persist
// + MarkReplicated, p = Persist only (a crash between sync.go's own
// Persist and MarkReplicated calls), k = MarkReplicated only (this
// ledger's chain claims replicated, but the mirror never received it),
// n = neither.
type letterState struct{ mirrored, replicated bool }

var (
	letterM = letterState{mirrored: true, replicated: true}
	letterP = letterState{mirrored: true, replicated: false}
	letterK = letterState{mirrored: false, replicated: true}
	letterN = letterState{mirrored: false, replicated: false}
)

// buildShape appends one baseline event (already mirrored and
// replicated, matching the ADR's own "baseline (clean, anchored)" row)
// plus one event per entry in shape, all referencing the SAME
// content-addressed snapshot sha, through the real Store.Append and
// Store.MarkReplicated. Returns the constructed divergence (chain count
// = 1 + len(shape); mirror count = the number of `mirrored` entries,
// baseline included) and a fakeMirrorEventReader reporting exactly
// those events' ids as mirrored.
func buildShape(t *testing.T, shape []letterState) (*Store, *MirrorChainCountDivergence, fakeMirrorEventReader) {
	t.Helper()
	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d120"))
	if err != nil {
		t.Fatal(err)
	}
	full := append([]letterState{letterM}, shape...)
	sharedRequestBytes := []byte(`{"d120":"shared"}`)
	mirrored := fakeMirrorEventReader{mirroredEventIDs: map[string]bool{}}
	chainCount, mirrorCount := 0, 0
	var snapshotSHA string
	for i, l := range full {
		input := testAppendInput()
		input.RequestBytes = sharedRequestBytes
		input.ResponseBytes = []byte(fmt.Sprintf(`{"d120":"resp-%d"}`, i))
		input.CorrelationID = uniqueID(fmt.Sprintf("d120-corr-%d", i))
		input.IdempotencyKey = uniqueID(fmt.Sprintf("d120-idem-%d", i))
		res, err := store.Append(input)
		if err != nil {
			t.Fatal(err)
		}
		snapshotSHA = res.Event.RequestSnapshotSHA256
		chainCount++
		if l.mirrored {
			mirrored.mirroredEventIDs[res.Event.EventID] = true
			mirrorCount++
		}
		if l.replicated {
			if err := store.MarkReplicated(res.Event.EventID, "2026-09-08T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
		}
	}
	div := &MirrorChainCountDivergence{SnapshotSHA256: snapshotSHA, MirrorCount: mirrorCount, ChainCount: chainCount}
	return store, div, mirrored
}

// TestShortfallExplainedByUnreplicatedEventsMissingSetDiscriminator is
// D122 item 10: all six shapes, asserting the shipped discriminator's
// verdict TODAY and the missing-set rule's verdict AFTER, with (3) and
// (6) the rows that change -- reproduced through the real, unmodified
// ShortfallExplainedByUnreplicatedEvents, not asserted from the ADR's
// own numbers.
func TestShortfallExplainedByUnreplicatedEventsMissingSetDiscriminator(t *testing.T) {
	cases := []struct {
		name          string
		shape         []letterState
		wantChain     int
		wantMirror    int
		wantCandidate bool
	}{
		{"(1) D109's own window [m,n]", []letterState{letterM, letterN}, 3, 2, true},
		{"(2) two crash windows [m,n,n]", []letterState{letterM, letterN, letterN}, 4, 2, true},
		{"(3) crash mid-step + backlog [m,p,n]", []letterState{letterM, letterP, letterN}, 4, 3, true},
		{"(5) marked but NOT mirrored [m,k]", []letterState{letterM, letterK}, 3, 2, false},
		{"(6) cancelling pair [m,p,k]", []letterState{letterM, letterP, letterK}, 4, 3, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store, div, mirrored := buildShape(t, c.shape)
			if div.ChainCount != c.wantChain || div.MirrorCount != c.wantMirror {
				t.Fatalf("test construction error: chain=%d mirror=%d, want chain=%d mirror=%d", div.ChainCount, div.MirrorCount, c.wantChain, c.wantMirror)
			}
			got, err := store.ShortfallExplainedByUnreplicatedEvents(context.Background(), mirrored, div)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.wantCandidate {
				t.Fatalf("ADR-0007 Addendum 13 D120: shape %s (chain=%d mirror=%d): got explained=%v, want %v", c.name, div.ChainCount, div.MirrorCount, got, c.wantCandidate)
			}
		})
	}
}

// TestShortfallExplainedByUnreplicatedEventsShippedRuleWouldHaveDiffered
// pins the two shapes (3 and 6) where the shipped count-identity rule
// (replicatedCount == div.MirrorCount) and the missing-set rule
// disagree -- the measured proof that D120 is a behavior change, not a
// refactor, reconstructing the shipped rule directly (not reintroduced
// into production code) the same way D118's own rogue-reproduction test
// reconstructs its own superseded rule.
func TestShortfallExplainedByUnreplicatedEventsShippedRuleWouldHaveDiffered(t *testing.T) {
	cases := []struct {
		name          string
		shape         []letterState
		wantShipped   bool
		wantCandidate bool
	}{
		{"(3) crash mid-step + backlog [m,p,n]", []letterState{letterM, letterP, letterN}, false, true},
		{"(6) cancelling pair [m,p,k]", []letterState{letterM, letterP, letterK}, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store, div, mirrored := buildShape(t, c.shape)

			// Reconstruct the shipped rule directly against the real
			// chain: replicatedCount == div.MirrorCount.
			events, err := store.ListEvents()
			if err != nil {
				t.Fatal(err)
			}
			replicatedCount := 0
			for _, e := range events {
				if e.RequestSnapshotSHA256 != div.SnapshotSHA256 && e.ResponseSnapshotSHA256 != div.SnapshotSHA256 {
					continue
				}
				if store.IsReplicated(e.EventID) {
					replicatedCount++
				}
			}
			shipped := replicatedCount == div.MirrorCount
			if shipped != c.wantShipped {
				t.Fatalf("test construction error: reconstructed shipped rule = %v, want %v", shipped, c.wantShipped)
			}

			candidate, err := store.ShortfallExplainedByUnreplicatedEvents(context.Background(), mirrored, div)
			if err != nil {
				t.Fatal(err)
			}
			if candidate != c.wantCandidate {
				t.Fatalf("candidate rule = %v, want %v", candidate, c.wantCandidate)
			}
			if shipped == candidate {
				t.Fatalf("test construction error: shape %s was supposed to be a shape where the shipped and candidate rules DISAGREE (shipped=%v candidate=%v)", c.name, shipped, candidate)
			}
		})
	}
}
