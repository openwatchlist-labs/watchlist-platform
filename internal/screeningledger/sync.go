package screeningledger

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// SyncResult is what Store.Sync reports back to its caller (cmd/
// screening-ledger's `sync` subcommand): how many events were mirrored,
// the final verification result, and -- ADR-0007 Addendum 12 D109 --
// whether a narrow, named condition was deferred on the way there.
// DeferredReason is empty when nothing was deferred, so "I mirrored
// past a divergence I chose to defer" and "I verified clean" never
// share an output (D12's rule, applied to a deferral rather than a
// mode).
type SyncResult struct {
	VerifyResult     AnchorVerifyResult
	SyncedEventCount int
	DeferredReason   string
}

// Sync is ADR-0007 D19/F5's mirror-with-verification command, extended
// by Addendum 12 D109: `sync` alone may defer EXACTLY one condition -- a
// chain/mirror event COUNT shortfall for one snapshot, fully accounted
// for by events this ledger's own store already knows are unreplicated
// (Store.IsReplicated) -- mirroring the backlog before re-running the
// SAME, unmodified verification in full. Every other divergence still
// aborts before the first Persist, exactly as it did before this
// addendum: D19 put the verification there precisely so forged rows are
// not mirrored into tables an immutability trigger then makes
// permanent, and the deferral narrows what it defers to a condition
// that is, by construction, about rows that are not in the mirror yet.
//
// status and verify do not call this -- they are not repair paths and
// have no business deferring anything; the deferral belongs to the one
// command whose job is to make the mirror agree.
func (s *Store) Sync(ctx context.Context, sink *PostgresSink, opts AnchorOptions, operator string) (SyncResult, error) {
	verifyResult, err := s.VerifyAnchored(ctx, opts)
	deferredReason := ""
	if err != nil {
		var divergence *MirrorChainCountDivergence
		explained := false
		if errors.As(err, &divergence) {
			var checkErr error
			explained, checkErr = s.ShortfallExplainedByUnreplicatedEvents(ctx, sink, divergence)
			if checkErr != nil {
				return SyncResult{}, checkErr
			}
		}
		if !explained {
			return SyncResult{VerifyResult: verifyResult}, err
		}
		deferredReason = fmt.Sprintf("mirror/chain count shortfall for snapshot %s (mirror=%d, chain=%d) deferred: fully accounted for by this ledger's own unreplicated events (ADR-0007 Addendum 12 D109)", divergence.SnapshotSHA256, divergence.MirrorCount, divergence.ChainCount)
	}

	events, err := s.ListEvents()
	if err != nil {
		return SyncResult{}, err
	}
	synced := 0
	verifiedAt := time.Now().UTC().Format(time.RFC3339Nano)
	verification := ReplicationVerification{VerifiedAt: verifiedAt, Mode: verifyResult.VerificationMode}
	for _, event := range events {
		if s.IsReplicated(event.EventID) {
			continue
		}
		request, err := s.LoadSnapshot(event.RequestSnapshotSHA256)
		if err != nil {
			return SyncResult{}, err
		}
		response, err := s.LoadSnapshot(event.ResponseSnapshotSHA256)
		if err != nil {
			return SyncResult{}, err
		}
		// ADR-0007 D19: verified_at/verification_mode are written in
		// the same transaction as the replication row (Persist's
		// INSERT into screening_ledger_replication) -- the row's own
		// immutability trigger means this can never be added later.
		if err := sink.Persist(ctx, event, request, response, verification); err != nil {
			return SyncResult{}, err
		}
		if err := s.MarkReplicated(event.EventID, ""); err != nil {
			return SyncResult{}, err
		}
		audit, err := s.AppendAudit("postgres_replicated", operator, "manual sync", event.EventID, nil)
		if err != nil {
			return SyncResult{}, err
		}
		if err := sink.PersistAudit(ctx, audit); err != nil {
			return SyncResult{}, err
		}
		synced++
	}

	// ADR-0007 Addendum 12 D109: the deferred condition is the GATE, not
	// a formality -- re-run the SAME, unmodified verification in full. A
	// run that would fail today and still fail after mirroring still
	// fails; nothing about the deferral is exempt from D19's own
	// requirement.
	if deferredReason != "" {
		verifyResult, err = s.VerifyAnchored(ctx, opts)
		if err != nil {
			// ADR-0007 Addendum 13 D120: SyncedEventCount must survive
			// this path. The mirroring loop above already ran and wrote
			// rows into tables whose immutability triggers make them
			// permanent -- dropping the count here (the shipped
			// behavior, defaulting to the zero value) would report that
			// nothing happened when synced rows genuinely exist,
			// exactly the deferred-then-failed path D109 requires the
			// caller be able to see.
			return SyncResult{VerifyResult: verifyResult, SyncedEventCount: synced, DeferredReason: deferredReason}, err
		}
	}

	return SyncResult{VerifyResult: verifyResult, SyncedEventCount: synced, DeferredReason: deferredReason}, nil
}
