package screeningledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// VerificationMode selects how VerifyPolicy/VerifyAnchored treat the
// facts D8 calls EA4 (the anchor) and F8 (unconfirmed purged snapshots).
// ADR-0007 D12: anchored is the default and the only mode reachable
// without an explicit flag; historical-unanchored requires BOTH this
// mode selected on the command line AND the signed policy's
// allow_unanchored set -- neither alone is sufficient.
type VerificationMode string

const (
	VerificationModeAnchored             VerificationMode = "anchored"
	VerificationModeHistoricalUnanchored VerificationMode = "historical-unanchored"
)

// PurgeChecker answers whether a snapshot's purged_at is backed by an
// independent record outside the envelope being checked (ADR-0007 D13 /
// F8) -- e.g. a row in screening_ledger_retention_tombstone. A nil
// PurgeChecker means no such independent record is available (a
// filesystem-only verification run); see verifySnapshotChecked.
type PurgeChecker interface {
	IsPurgeRecorded(ctx context.Context, snapshotSHA256 string) (bool, error)
}

// PurgeRecorder is ADR-0007 Addendum 2 D27/D28's write-time counterpart
// to PurgeChecker: records a purge as an independent decision the caller
// cannot forge, rather than the caller directly writing the record
// itself. eligibleSHA256 is the set Store.PurgeExpired's local pass
// already narrowed to (legal holds honored there, the server does not
// and should not learn about a filesystem directory); RecordPurge
// re-validates every one of them against its own expiry floor and
// returns exactly the subset it actually recorded -- local-narrows,
// server-floors, per D28. Only that returned subset may be marked purged
// in local envelopes.
type PurgeRecorder interface {
	RecordPurge(ctx context.Context, eligibleSHA256 []string, before time.Time, operator, reason string) (recorded []string, err error)
}

// VerifyOptions carries what VerifyPolicy needs to check the file chain
// alone, with no anchor and no database required (ADR-0007 D9's decisive
// property: "the F1 defence becomes runnable in run-ci.sh
// unconditionally"). Purges may be nil (filesystem-only); Mode governs
// how an unconfirmable purged snapshot is treated in that case (D13).
type VerifyOptions struct {
	Policy VerificationPolicy
	Mode   VerificationMode
	Purges PurgeChecker
	// allowDeferredPurgeClaims is ADR-0007 Addendum 3 D32's collect/
	// adjudicate split, deliberately unexported: a purge claim's
	// legitimacy requires the anchored audit chain, which is not
	// available inside VerifyPolicy's own file-chain walk. VerifyPolicy
	// fails closed on any unadjudicated PurgeClaim in anchored mode
	// unless this is set -- and because it is unexported, only code in
	// this package (VerifyAnchored) can set it. "I collected this for
	// someone else to judge" and "I judged it" must not share a return
	// value (D12's rule, applied to this new boundary).
	allowDeferredPurgeClaims bool
}

// PurgeClaim is ADR-0007 Addendum 3 D32: a snapshot VerifyPolicy's
// event-chain walk found marked purged, whose legitimacy it no longer
// decides itself. VerifyAnchored adjudicates each claim after its own
// anchor cross-check succeeds, against the three-condition rule D32
// specifies (an attesting audit entry exists, at or below the anchored
// audit sequence, corroborated by an independent tombstone).
type PurgeClaim struct {
	SnapshotSHA256 string
	EventSequence  uint64
}

func (o VerifyOptions) modeOrDefault() VerificationMode {
	if o.Mode == "" {
		return VerificationModeAnchored
	}
	return o.Mode
}

// eventSchemaOrdinal and auditSchemaOrdinal give EA1's "minimum accepted
// schema version" a total order to compare against, so a floor check is
// "is this entry's schema at least as strong as the policy's floor",
// not "does this entry's schema string equal one specific value".
func eventSchemaOrdinal(v string) (int, bool) {
	switch v {
	case EventSchemaV1:
		return 1, true
	case EventSchemaV2:
		return 2, true
	default:
		return 0, false
	}
}
func auditSchemaOrdinal(v string) (int, bool) {
	switch v {
	case AuditSchemaV1:
		return 1, true
	case AuditSchemaV2:
		return 2, true
	default:
		return 0, false
	}
}

type Store struct {
	directory string
	keys      chainKeys
	ledgerID  string
	mu        sync.Mutex
}

func NewStore(directory string, key []byte, requestedLedgerID ...string) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("ledger directory is required")
	}
	if len(key) != 32 {
		return nil, errors.New("snapshot key must be 32 bytes")
	}
	ledgerID, err := ensureLedgerID(directory, requestedLedgerID)
	if err != nil {
		return nil, err
	}
	keys, err := deriveChainKeys(key, ledgerID)
	if err != nil {
		return nil, err
	}
	store := &Store{directory: directory, keys: keys, ledgerID: ledgerID}
	for _, sub := range []string{"events", "snapshots", "audit", "replication", "holds", "purged"} {
		if err := os.MkdirAll(filepath.Join(directory, sub), 0o750); err != nil {
			return nil, err
		}
	}
	if err := store.Recover(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Directory() string { return s.directory }

func (s *Store) Append(input AppendInput) (AppendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.recoverLocked(); err != nil {
		return AppendResult{}, err
	}
	if input.OccurredAt == "" {
		input.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if input.Retention.Class == "" {
		input.Retention.Class = "screening-standard"
	}
	if input.Retention.RetentionDays <= 0 {
		input.Retention.RetentionDays = 2555
	}
	if input.Retention.MaxSnapshotBytes <= 0 {
		input.Retention.MaxSnapshotBytes = 2 * 1024 * 1024
	}
	requestCanonical, err := canonicalJSON(input.RequestBytes)
	if err != nil {
		return AppendResult{}, fmt.Errorf("canonical request: %w", err)
	}
	responseCanonical, err := canonicalJSON(input.ResponseBytes)
	if err != nil {
		return AppendResult{}, fmt.Errorf("canonical response: %w", err)
	}
	if len(requestCanonical) > input.Retention.MaxSnapshotBytes || len(responseCanonical) > input.Retention.MaxSnapshotBytes {
		return AppendResult{}, errors.New("decision snapshot exceeds configured maximum")
	}
	expires := mustExpires(input.OccurredAt, input.Retention.RetentionDays)
	reqEnvelope, err := encryptSnapshot(s.keys.snap, "request", requestCanonical, input.OccurredAt, expires, input.Retention.Class)
	if err != nil {
		return AppendResult{}, err
	}
	respEnvelope, err := encryptSnapshot(s.keys.snap, "response", responseCanonical, input.OccurredAt, expires, input.Retention.Class)
	if err != nil {
		return AppendResult{}, err
	}
	requestSHA := digestHex(input.RequestBytes)
	responseSHA := digestHex(input.ResponseBytes)
	correlationHash := digestHex([]byte(input.CorrelationID))
	idempotencyHash := ""
	if input.IdempotencyKey != "" {
		idempotencyHash = digestHex([]byte(input.IdempotencyKey))
	}
	identityParts := []string{s.ledgerID, input.Route, requestSHA, responseSHA, correlationHash}
	if idempotencyHash != "" {
		identityParts = append(identityParts, idempotencyHash)
	} else {
		identityParts = append(identityParts, input.OccurredAt)
	}
	eventID := digestHex([]byte(strings.Join(identityParts, "\n")))
	path := s.eventPath(eventID)
	if raw, err := os.ReadFile(path); err == nil {
		var existing Event
		if json.Unmarshal(raw, &existing) != nil {
			return AppendResult{}, errors.New("existing ledger event is invalid")
		}
		return AppendResult{Event: existing, Replayed: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return AppendResult{}, err
	}
	head, err := s.loadHead()
	if err != nil {
		return AppendResult{}, err
	}
	activation, promotion, candidates := extractBoundedMetadata(responseCanonical)
	// SchemaVersion is always v2 (ADR-0007 D4): every new event is written
	// under the keyed, anchorable scheme. v1 exists only as frozen,
	// pre-D2 history that predates this repository's only ledger writer
	// ever appending anything -- see Verify's genesis-boundary handling.
	event := Event{SchemaVersion: EventSchemaV2, EventID: eventID, LedgerID: s.ledgerID, Sequence: head.Sequence + 1, PreviousEventSHA256: head.EventSHA256, OccurredAt: input.OccurredAt, Route: input.Route, HTTPStatus: input.HTTPStatus, CorrelationIDHash: correlationHash, IdempotencyKeyHash: idempotencyHash, RequestSHA256: requestSHA, ResponseSHA256: responseSHA, RequestSnapshotSHA256: reqEnvelope.SnapshotSHA256, ResponseSnapshotSHA256: respEnvelope.SnapshotSHA256, ActivationLineage: activation, PromotionLineage: promotion, CandidateSummary: candidates, RetentionClass: input.Retention.Class, ExpiresAt: expires}
	eventSHA, err := hashEvent(event, s.keys.chain)
	if err != nil {
		return AppendResult{}, err
	}
	event.EventSHA256 = eventSHA
	if err := s.writeSnapshot(reqEnvelope); err != nil {
		return AppendResult{}, err
	}
	if err := s.writeSnapshot(respEnvelope); err != nil {
		return AppendResult{}, err
	}
	pending := filepath.Join(s.directory, "pending.json")
	if err := marshalAndWrite(pending, event, 0o640); err != nil {
		return AppendResult{}, err
	}
	if err := marshalAndWrite(path, event, 0o640); err != nil {
		return AppendResult{}, err
	}
	newHead := Head{SchemaVersion: HeadSchemaV2, LedgerID: s.ledgerID, Sequence: event.Sequence, EventID: event.EventID, EventSHA256: event.EventSHA256}
	if err := marshalAndWrite(filepath.Join(s.directory, "head.json"), newHead, 0o640); err != nil {
		return AppendResult{}, err
	}
	if err := os.Remove(pending); err != nil && !errors.Is(err, os.ErrNotExist) {
		return AppendResult{}, err
	}
	_ = syncDirectory(s.directory)
	return AppendResult{Event: event}, nil
}

func (s *Store) Recover() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoverLocked()
}

func (s *Store) recoverLocked() error {
	pending := filepath.Join(s.directory, "pending.json")
	raw, err := os.ReadFile(pending)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return err
	}
	if _, err := os.Stat(s.eventPath(event.EventID)); err == nil {
		headRaw, _ := json.Marshal(Head{SchemaVersion: headSchemaFor(event.SchemaVersion), LedgerID: s.ledgerID, Sequence: event.Sequence, EventID: event.EventID, EventSHA256: event.EventSHA256})
		if err := atomicWrite(filepath.Join(s.directory, "head.json"), headRaw, 0o640); err != nil {
			return err
		}
	}
	return os.Remove(pending)
}

// VerifyReport is VerifyPolicy's full result: the event and audit chain
// heads, how much of each chain, from the start, is pre-D2 frozen
// history (ADR-0007 D4) rather than covered by the D2 keyed chain, and
// how many snapshot checks were actually performed vs. skipped (D13) --
// so "every snapshot was skipped" cannot look like "every snapshot
// passed" in the output. A nonzero frozen-prefix length is not itself a
// failure -- it is honest reporting that the corresponding leading
// entries carry the weaker, unkeyed, unanchored guarantee, per CLAUDE.md
// rule 5's spirit: a control that silently reports "ok" without saying
// which portion of history it actually protects is the same
// silent-absence bug this ADR exists to fix, one level up.
type VerifyReport struct {
	Head                    Head
	AuditHead               Head
	EventFrozenPrefixLength int
	AuditFrozenPrefixLength int
	SnapshotChecksTotal     int
	SnapshotChecksPerformed int
	// PurgeClaims (ADR-0007 Addendum 3 D32) is every snapshot this report
	// found marked purged, collected rather than decided -- see
	// VerifyOptions.allowDeferredPurgeClaims. Empty whenever no claim was
	// deferred, which is the common case (no purges, or a filesystem-only
	// run that decided them immediately).
	PurgeClaims []PurgeClaim
}

// VerifyPolicy is the F1 fix's entry point (ADR-0007 D8, D9 option (c)):
// checks the event and audit chains, the genesis boundary, and the
// ledger identity against an externally-authenticated policy -- not
// against any field read out of the ledger directory being checked. It
// requires no database and no anchor row (D9's decisive property: "the
// F1 defence becomes runnable in run-ci.sh unconditionally, with no
// Postgres service and no credential"). VerifyAnchored layers D3's
// anchor cross-check (EA4) on top of this.
func (s *Store) VerifyPolicy(ctx context.Context, opts VerifyOptions) (VerifyReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyPolicyLocked(ctx, opts)
}

func (s *Store) verifyPolicyLocked(ctx context.Context, opts VerifyOptions) (VerifyReport, error) {
	if err := s.recoverLocked(); err != nil {
		return VerifyReport{}, err
	}
	policy := opts.Policy
	mode := opts.modeOrDefault()
	// D12's double gate applies here too, not only in VerifyAnchored's
	// anchor-cross-check relaxation: historical-unanchored mode requires
	// BOTH the mode selected on the command line AND the signed policy's
	// allow_unanchored -- otherwise a caller could pass the mode alone to
	// relax D13/F8's purge handling without the policy owner's consent.
	if mode == VerificationModeHistoricalUnanchored && !policy.AllowUnanchored {
		return VerifyReport{}, errors.New("historical-unanchored mode was requested but the signed policy does not set allow_unanchored: both must agree, per ADR-0007 D12 -- neither alone is sufficient")
	}
	if policy.LedgerID != s.ledgerID {
		return VerifyReport{}, fmt.Errorf("EA3: policy ledger_id %q does not match this ledger's durable ledger-id %q", policy.LedgerID, s.ledgerID)
	}
	if policy.GenesisEventSequence == 0 {
		return VerifyReport{}, errors.New("policy genesis_event_sequence must be >= 1 (1 means no v1 prefix is permitted at all)")
	}
	if policy.GenesisAuditSequence == 0 {
		return VerifyReport{}, errors.New("policy genesis_audit_sequence must be >= 1 (1 means no v1 prefix is permitted at all)")
	}
	minEventOrdinal, ok := eventSchemaOrdinal(policy.MinEventSchema)
	if !ok {
		return VerifyReport{}, fmt.Errorf("policy min_event_schema %q is not a recognized event schema version", policy.MinEventSchema)
	}
	entries, err := os.ReadDir(filepath.Join(s.directory, "events"))
	if err != nil {
		return VerifyReport{}, err
	}
	type pair struct {
		seq   uint64
		event Event
	}
	pairs := make([]pair, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.directory, "events", entry.Name()))
		if err != nil {
			return VerifyReport{}, err
		}
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return VerifyReport{}, err
		}
		pairs = append(pairs, pair{event.Sequence, event})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].seq < pairs[j].seq })
	previous := ""
	last := Head{SchemaVersion: HeadSchemaV1, LedgerID: s.ledgerID}
	frozenPrefixLength := 0
	snapshotChecksTotal := 0
	snapshotChecksPerformed := 0
	purgeClaims := []PurgeClaim{}
	for i, p := range pairs {
		if p.event.Sequence != uint64(i+1) {
			return VerifyReport{}, fmt.Errorf("ledger sequence gap at %d", i+1)
		}
		if p.event.PreviousEventSHA256 != previous {
			return VerifyReport{}, fmt.Errorf("ledger chain mismatch at sequence %d", p.event.Sequence)
		}
		// ADR-0007 D8 EA1/EA2: which formula applies, and which schema
		// label is even legal, is chosen by this entry's POSITION
		// against the externally-supplied genesis boundary -- never by
		// the entry's own SchemaVersion field. That field is the
		// adversary's to set (§2's threat model); the boundary is not.
		// This is the actual F1 fix: relabelling every entry to v1 no
		// longer moves which formula verifies it, because the position
		// in the sequence, not the label, selects the branch.
		var eventSHA string
		if p.event.Sequence < policy.GenesisEventSequence {
			if p.event.SchemaVersion != EventSchemaV1 {
				return VerifyReport{}, fmt.Errorf("entry at sequence %d is below the policy genesis boundary (%d) and must be schema %q, got %q", p.event.Sequence, policy.GenesisEventSequence, EventSchemaV1, p.event.SchemaVersion)
			}
			eventSHA, err = legacyHashEvent(p.event)
			frozenPrefixLength = i + 1
		} else {
			ordinal, recognized := eventSchemaOrdinal(p.event.SchemaVersion)
			if !recognized || ordinal < minEventOrdinal {
				return VerifyReport{}, fmt.Errorf("entry at sequence %d (schema %q) is at or after the policy genesis boundary (%d) and does not meet the minimum accepted schema version %q: hard failure per ADR-0007 D8 EA1/EA2", p.event.Sequence, p.event.SchemaVersion, policy.GenesisEventSequence, policy.MinEventSchema)
			}
			switch p.event.SchemaVersion {
			case EventSchemaV2:
				eventSHA, err = hashEvent(p.event, s.keys.chain)
			default:
				return VerifyReport{}, fmt.Errorf("entry at sequence %d has schema %q with no known digest algorithm", p.event.Sequence, p.event.SchemaVersion)
			}
		}
		if err != nil {
			return VerifyReport{}, err
		}
		if eventSHA != p.event.EventSHA256 {
			return VerifyReport{}, fmt.Errorf("ledger event checksum mismatch at sequence %d", p.event.Sequence)
		}
		for _, sha := range []string{p.event.RequestSnapshotSHA256, p.event.ResponseSnapshotSHA256} {
			snapshotChecksTotal++
			performed, claim, err := s.verifySnapshotChecked(ctx, sha, p.event.Sequence, mode, opts.Purges)
			if err != nil {
				return VerifyReport{}, err
			}
			if performed {
				snapshotChecksPerformed++
			}
			if claim != nil {
				purgeClaims = append(purgeClaims, *claim)
			}
		}
		previous = p.event.EventSHA256
		last = Head{SchemaVersion: headSchemaFor(p.event.SchemaVersion), LedgerID: s.ledgerID, Sequence: p.event.Sequence, EventID: p.event.EventID, EventSHA256: p.event.EventSHA256}
	}
	head, err := s.loadHead()
	if err != nil {
		return VerifyReport{}, err
	}
	if head.Sequence != last.Sequence || head.EventSHA256 != last.EventSHA256 {
		return VerifyReport{}, errors.New("ledger head does not match event chain")
	}
	auditHead, auditFrozenPrefixLength, err := s.verifyAuditPolicyLocked(policy)
	if err != nil {
		return VerifyReport{}, err
	}
	// ADR-0007 Addendum 3 D32 supersedes Addendum 2 D28's inline gate here.
	// D28 asked "did at least one snapshot check actually run" -- a
	// partial-skip budget that CAP #2 §7.3 walked straight past by hiding
	// exactly one snapshot of four. D32 replaces it with a stronger
	// property enforced one layer up: every PurgeClaim below must
	// individually adjudicate against the anchored audit chain
	// (VerifyAnchored.adjudicatePurgeClaims) before SnapshotChecksPerformed
	// is allowed to reach SnapshotChecksTotal -- there is no partial-skip
	// budget left to walk past. A direct VerifyPolicy caller (anything
	// other than VerifyAnchored) cannot reach that adjudication at all, so
	// it fails closed on any claim right here instead.
	if len(purgeClaims) > 0 {
		switch {
		case mode == VerificationModeHistoricalUnanchored:
			// D13's existing double gate (mode + policy.AllowUnanchored,
			// already enforced above) already tolerates skipped snapshot
			// checks in this mode -- there is no anchor for D32's
			// adjudication to check against, and none is required here.
		case !opts.allowDeferredPurgeClaims:
			return VerifyReport{}, fmt.Errorf("%d snapshot(s) are marked purged and require anchored adjudication (ADR-0007 Addendum 3 D32): call VerifyAnchored, which cross-checks each against the anchored audit chain, rather than VerifyPolicy directly", len(purgeClaims))
		}
	}
	return VerifyReport{
		Head:                    head,
		AuditHead:               auditHead,
		EventFrozenPrefixLength: frozenPrefixLength,
		AuditFrozenPrefixLength: auditFrozenPrefixLength,
		SnapshotChecksTotal:     snapshotChecksTotal,
		SnapshotChecksPerformed: snapshotChecksPerformed,
		PurgeClaims:             purgeClaims,
	}, nil
}

// headSchemaFor picks the Head schema-version label matching an event or
// audit entry's own SchemaVersion, so a Head built from a frozen v1
// prefix entry is itself labeled v1, not silently promoted to v2.
func headSchemaFor(entrySchema string) string {
	if entrySchema == EventSchemaV1 || entrySchema == AuditSchemaV1 {
		return HeadSchemaV1
	}
	return HeadSchemaV2
}

// eventAtSequence returns the event at the given chain sequence, for
// VerifyAnchored's historical-divergence check when the anchored
// sequence is behind the current head.
func (s *Store) eventAtSequence(seq uint64) (Event, error) {
	entries, err := os.ReadDir(filepath.Join(s.directory, "events"))
	if err != nil {
		return Event{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.directory, "events", entry.Name()))
		if err != nil {
			return Event{}, err
		}
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return Event{}, err
		}
		if event.Sequence == seq {
			return event, nil
		}
	}
	return Event{}, fmt.Errorf("no event found at sequence %d", seq)
}

// auditEntryAtSequence mirrors eventAtSequence for AR7's audit-chain
// anchor cross-check.
func (s *Store) auditEntryAtSequence(seq uint64) (AuditEvent, error) {
	entries, err := os.ReadDir(filepath.Join(s.directory, "audit"))
	if err != nil {
		return AuditEvent{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.directory, "audit", entry.Name()))
		if err != nil {
			return AuditEvent{}, err
		}
		var event AuditEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			return AuditEvent{}, err
		}
		if event.Sequence == seq {
			return event, nil
		}
	}
	return AuditEvent{}, fmt.Errorf("no audit entry found at sequence %d", seq)
}

func (s *Store) GetEvent(eventID string) (Event, error) {
	raw, err := os.ReadFile(s.eventPath(eventID))
	if err != nil {
		return Event{}, err
	}
	var event Event
	err = json.Unmarshal(raw, &event)
	return event, err
}

// ListEvents used to silently skip any file it could not read or parse
// (CLAUDE.md's silent-absence trap, and ADR-0007 D19): a file that
// cannot be parsed is a chain the caller has not seen all of, not an
// empty slot to skip past.
func (s *Store) ListEvents() ([]Event, error) {
	entries, err := os.ReadDir(filepath.Join(s.directory, "events"))
	if err != nil {
		return nil, err
	}
	out := []Event{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.directory, "events", e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read event file %s: %w", e.Name(), err)
		}
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil, fmt.Errorf("unmarshal event file %s: %w", e.Name(), err)
		}
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out, nil
}
func (s *Store) LoadSnapshot(sha string) (SnapshotEnvelope, error) {
	raw, err := os.ReadFile(s.snapshotPath(sha))
	if err != nil {
		return SnapshotEnvelope{}, err
	}
	var env SnapshotEnvelope
	err = json.Unmarshal(raw, &env)
	return env, err
}
func (s *Store) DecryptSnapshot(sha string) ([]byte, error) {
	env, err := s.LoadSnapshot(sha)
	if err != nil {
		return nil, err
	}
	return decryptSnapshot(s.keys.snap, env)
}
func (s *Store) MarkReplicated(eventID, occurredAt string) error {
	if occurredAt == "" {
		occurredAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	raw, _ := json.Marshal(map[string]string{"event_id": eventID, "replicated_at": occurredAt})
	return atomicWrite(filepath.Join(s.directory, "replication", eventID+".json"), raw, 0o640)
}
func (s *Store) IsReplicated(eventID string) bool {
	_, err := os.Stat(filepath.Join(s.directory, "replication", eventID+".json"))
	return err == nil
}

func (s *Store) writeSnapshot(env SnapshotEnvelope) error {
	path := s.snapshotPath(env.SnapshotSHA256)
	if raw, err := os.ReadFile(path); err == nil {
		var existing SnapshotEnvelope
		if json.Unmarshal(raw, &existing) == nil && existing.SnapshotSHA256 == env.SnapshotSHA256 {
			return nil
		}
		return errors.New("snapshot path collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, _ := json.Marshal(env)
	return atomicWrite(path, raw, 0o600)
}

// verifySnapshotChecked is ADR-0007 D13 (F8): env.PurgedAt is a plain
// field inside the ledger directory the threat model already grants the
// adversary write access to, so it is never trusted on its own to skip
// the one key-dependent check the event chain still had.
//
// ADR-0007 Addendum 3 D32: a purged envelope no longer gets decided here.
// CAP #2 §7.3 showed the independent tombstone this function used to
// trust as authority is itself forgeable through the sanctioned
// SECURITY DEFINER path (G-C) -- the same "verified data chooses its own
// acceptance criteria" class D8 already named. Deciding legitimacy
// requires the anchored audit chain, which this per-event walk does not
// have; if a database is configured, this returns a PurgeClaim for
// VerifyAnchored to adjudicate later instead. If purges is nil
// (filesystem-only), there is no way to confirm the purge is legitimate
// at all: that is a hard failure in anchored mode (the default) and a
// tolerated, uncounted condition only under explicitly-selected
// historical-unanchored mode -- unchanged from before this decision.
// performed reports whether a real decrypt-and-digest check actually
// ran, so the caller can report "checks performed" vs. "checks skipped"
// rather than letting a fully-skipped verification look identical to a
// fully-passed one.
func (s *Store) verifySnapshotChecked(ctx context.Context, sha string, seq uint64, mode VerificationMode, purges PurgeChecker) (performed bool, claim *PurgeClaim, err error) {
	env, err := s.LoadSnapshot(sha)
	if err != nil {
		return false, nil, err
	}
	if env.SnapshotSHA256 != sha {
		return false, nil, errors.New("snapshot filename checksum mismatch")
	}
	if env.PurgedAt != "" {
		if purges != nil {
			return false, &PurgeClaim{SnapshotSHA256: sha, EventSequence: seq}, nil
		}
		if mode == VerificationModeHistoricalUnanchored {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("snapshot %s is marked purged and no independent purge record is available (no database configured): failing in anchored mode rather than trusting the self-reported field (ADR-0007 D13/F8)", sha)
	}
	plaintext, err := decryptSnapshot(s.keys.snap, env)
	if err != nil {
		return false, nil, err
	}
	if digestHex(plaintext) != env.PlaintextSHA256 {
		return false, nil, errors.New("snapshot checksum mismatch")
	}
	return true, nil, nil
}
func (s *Store) eventPath(id string) string { return filepath.Join(s.directory, "events", id+".json") }
func (s *Store) snapshotPath(sha string) string {
	return filepath.Join(s.directory, "snapshots", sha+".json")
}
func (s *Store) loadHead() (Head, error) {
	raw, err := os.ReadFile(filepath.Join(s.directory, "head.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Head{SchemaVersion: HeadSchemaV1, LedgerID: s.ledgerID}, nil
	}
	if err != nil {
		return Head{}, err
	}
	var head Head
	err = json.Unmarshal(raw, &head)
	return head, err
}
func ensureLedgerID(directory string, requested []string) (string, error) {
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "ledger-id")
	if raw, err := os.ReadFile(path); err == nil {
		existing := strings.TrimSpace(string(raw))
		if len(requested) > 0 && strings.TrimSpace(requested[0]) != "" && existing != strings.TrimSpace(requested[0]) {
			return "", errors.New("configured ledger ID does not match durable ledger-id")
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	id := ""
	if len(requested) > 0 {
		id = strings.TrimSpace(requested[0])
	}
	if id == "" {
		absolute, _ := filepath.Abs(directory)
		id = "ledger-" + digestHex([]byte(absolute))[:24]
	}
	if err := atomicWrite(path, []byte(id+"\n"), 0o640); err != nil {
		return "", err
	}
	return id, nil
}

// legacyHashEvent is the pre-D2 algorithm, preserved so Verify can check
// the frozen v1 prefix (ADR-0007 D4) against the same formula it was
// originally written under: plain sha256.Sum256(json(event)), no key.
// This is deliberately NOT reachable from Append -- every new event is
// v2 (see Append's comment) -- it exists only for reading genuinely
// pre-D2 history, real or, in tests, reconstructed from it.
func legacyHashEvent(event Event) (string, error) {
	event.EventSHA256 = ""
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return digestHex(raw), nil
}

// hashEvent is ADR-0007 D2: HMAC-SHA256 under the derived chain key,
// replacing the pre-D2 plain sha256.Sum256(json(event)).
func hashEvent(event Event, chainKey []byte) (string, error) {
	event.EventSHA256 = ""
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return macHex(chainKey, raw), nil
}
func mustExpires(occurred string, days int) string {
	parsed, err := time.Parse(time.RFC3339Nano, occurred)
	if err != nil {
		parsed = time.Now().UTC()
	}
	return parsed.Add(time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
}
func marshalAndWrite(path string, v any, mode os.FileMode) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return atomicWrite(path, raw, mode)
}
func atomicWrite(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func extractBoundedMetadata(response []byte) (json.RawMessage, json.RawMessage, json.RawMessage) {
	var doc map[string]any
	if json.Unmarshal(response, &doc) != nil {
		return nil, nil, nil
	}
	encode := func(v any) json.RawMessage {
		if v == nil {
			return nil
		}
		raw, _ := json.Marshal(v)
		return raw
	}
	activation := doc["activation_tuple"]
	if activation == nil {
		activation = doc["activation"]
	}
	promotion := doc["promotion"]
	summary := map[string]any{}
	if candidates, ok := doc["candidates"].([]any); ok {
		bounded := make([]any, 0, len(candidates))
		for _, raw := range candidates {
			if candidate, ok := raw.(map[string]any); ok {
				item := map[string]any{}
				for _, key := range []string{"candidate_id", "score", "similarity_band", "reason_codes", "evidence_sha256"} {
					if v, exists := candidate[key]; exists {
						item[key] = v
					}
				}
				bounded = append(bounded, item)
			}
		}
		summary["candidates"] = bounded
	}
	if blockers, ok := doc["blockers"]; ok {
		summary["blockers"] = blockers
	}
	return encode(activation), encode(promotion), encode(summary)
}
