package screeningledger

import (
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

type Store struct {
	directory string
	key       []byte
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
	store := &Store{directory: directory, key: append([]byte(nil), key...), ledgerID: ledgerID}
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
	reqEnvelope, err := encryptSnapshot(s.key, "request", requestCanonical, input.OccurredAt, expires, input.Retention.Class)
	if err != nil {
		return AppendResult{}, err
	}
	respEnvelope, err := encryptSnapshot(s.key, "response", responseCanonical, input.OccurredAt, expires, input.Retention.Class)
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
	event := Event{SchemaVersion: EventSchemaV1, EventID: eventID, LedgerID: s.ledgerID, Sequence: head.Sequence + 1, PreviousEventSHA256: head.EventSHA256, OccurredAt: input.OccurredAt, Route: input.Route, HTTPStatus: input.HTTPStatus, CorrelationIDHash: correlationHash, IdempotencyKeyHash: idempotencyHash, RequestSHA256: requestSHA, ResponseSHA256: responseSHA, RequestSnapshotSHA256: reqEnvelope.SnapshotSHA256, ResponseSnapshotSHA256: respEnvelope.SnapshotSHA256, ActivationLineage: activation, PromotionLineage: promotion, CandidateSummary: candidates, RetentionClass: input.Retention.Class, ExpiresAt: expires}
	eventSHA, err := hashEvent(event)
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
	newHead := Head{SchemaVersion: HeadSchemaV1, LedgerID: s.ledgerID, Sequence: event.Sequence, EventID: event.EventID, EventSHA256: event.EventSHA256}
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
		headRaw, _ := json.Marshal(Head{SchemaVersion: HeadSchemaV1, LedgerID: s.ledgerID, Sequence: event.Sequence, EventID: event.EventID, EventSHA256: event.EventSHA256})
		if err := atomicWrite(filepath.Join(s.directory, "head.json"), headRaw, 0o640); err != nil {
			return err
		}
	}
	return os.Remove(pending)
}

func (s *Store) Verify() (Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.recoverLocked(); err != nil {
		return Head{}, err
	}
	entries, err := os.ReadDir(filepath.Join(s.directory, "events"))
	if err != nil {
		return Head{}, err
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
			return Head{}, err
		}
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return Head{}, err
		}
		pairs = append(pairs, pair{event.Sequence, event})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].seq < pairs[j].seq })
	previous := ""
	last := Head{SchemaVersion: HeadSchemaV1, LedgerID: s.ledgerID}
	for i, p := range pairs {
		if p.event.Sequence != uint64(i+1) {
			return Head{}, fmt.Errorf("ledger sequence gap at %d", i+1)
		}
		if p.event.PreviousEventSHA256 != previous {
			return Head{}, fmt.Errorf("ledger chain mismatch at sequence %d", p.event.Sequence)
		}
		eventSHA, err := hashEvent(p.event)
		if err != nil {
			return Head{}, err
		}
		if eventSHA != p.event.EventSHA256 {
			return Head{}, fmt.Errorf("ledger event checksum mismatch at sequence %d", p.event.Sequence)
		}
		if err := s.verifySnapshot(p.event.RequestSnapshotSHA256); err != nil {
			return Head{}, err
		}
		if err := s.verifySnapshot(p.event.ResponseSnapshotSHA256); err != nil {
			return Head{}, err
		}
		previous = p.event.EventSHA256
		last = Head{SchemaVersion: HeadSchemaV1, LedgerID: s.ledgerID, Sequence: p.event.Sequence, EventID: p.event.EventID, EventSHA256: p.event.EventSHA256}
	}
	head, err := s.loadHead()
	if err != nil {
		return Head{}, err
	}
	if head.Sequence != last.Sequence || head.EventSHA256 != last.EventSHA256 {
		return Head{}, errors.New("ledger head does not match event chain")
	}
	if _, err := s.VerifyAudit(); err != nil {
		return Head{}, err
	}
	return head, nil
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
		raw, _ := os.ReadFile(filepath.Join(s.directory, "events", e.Name()))
		var event Event
		if json.Unmarshal(raw, &event) == nil {
			out = append(out, event)
		}
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
	return decryptSnapshot(s.key, env)
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
func (s *Store) verifySnapshot(sha string) error {
	env, err := s.LoadSnapshot(sha)
	if err != nil {
		return err
	}
	if env.SnapshotSHA256 != sha {
		return errors.New("snapshot filename checksum mismatch")
	}
	if env.PurgedAt != "" {
		return nil
	}
	plaintext, err := decryptSnapshot(s.key, env)
	if err != nil {
		return err
	}
	if digestHex(plaintext) != env.PlaintextSHA256 {
		return errors.New("snapshot checksum mismatch")
	}
	return nil
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
func hashEvent(event Event) (string, error) {
	event.EventSHA256 = ""
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return digestHex(raw), nil
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
