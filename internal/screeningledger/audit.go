package screeningledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (s *Store) AppendAudit(action, operator, reason, eventID string, details any) (AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	head, err := s.loadAuditHead()
	if err != nil {
		return AuditEvent{}, err
	}
	var detailRaw json.RawMessage
	if details != nil {
		detailRaw, err = json.Marshal(details)
		if err != nil {
			return AuditEvent{}, err
		}
	}
	// SchemaVersion is always v2 (ADR-0007 D4), symmetric with Append's
	// event-chain default: every new audit entry is written under the
	// keyed scheme. This repository's audit chain has zero pre-D2 entries
	// (test/fixtures/screening-ledger/state/ has never had an audit/
	// directory), so there is no genuine v1 audit prefix to freeze -- see
	// the ADR-0007 §6 correction note.
	event := AuditEvent{SchemaVersion: AuditSchemaV2, LedgerID: s.ledgerID, Sequence: head.Sequence + 1, PreviousAuditSHA256: head.EventSHA256, OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Action: action, Operator: operator, Reason: reason, EventID: eventID, Details: detailRaw}
	auditSHA, err := hashAudit(event, s.keys.chain)
	if err != nil {
		return AuditEvent{}, err
	}
	event.AuditSHA256 = auditSHA
	name := fmt.Sprintf("%020d-%s.json", event.Sequence, event.AuditSHA256)
	if err := marshalAndWrite(filepath.Join(s.directory, "audit", name), event, 0o640); err != nil {
		return AuditEvent{}, err
	}
	if err := marshalAndWrite(filepath.Join(s.directory, "audit-head.json"), Head{SchemaVersion: headSchemaFor(event.SchemaVersion), LedgerID: s.ledgerID, Sequence: event.Sequence, EventSHA256: event.AuditSHA256}, 0o640); err != nil {
		return AuditEvent{}, err
	}
	return event, nil
}

// VerifyAudit acquires the store lock and verifies the audit chain alone.
// Nothing in this package calls it directly today -- verifyLocked (via
// Verify) does the equivalent work inline while already holding the lock
// -- but it is kept as a public, independently-lockable entry point for
// symmetry with Verify and for future callers that want to check only
// the audit chain.
func (s *Store) VerifyAudit() (Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	head, _, err := s.verifyAuditLocked()
	return head, err
}

// verifyAuditLocked assumes the caller already holds s.mu. It mirrors
// verifyLocked's v1/v2 genesis-boundary handling (ADR-0007 D4): audit
// entries stay frozen-prefix v1 verified under the legacy, unkeyed
// algorithm up to the first v2 entry, and any v1 entry after that is a
// hard failure. In practice this repository's audit chain has always
// been empty pre-D2 (see AppendAudit's comment), so frozenPrefixLength is
// 0 for the real ledger; the logic exists for symmetry and for any
// sibling chain that adopts this package's pattern with genuine v1 audit
// history (ADR-0007 §7.2).
func (s *Store) verifyAuditLocked() (Head, int, error) {
	entries, err := os.ReadDir(filepath.Join(s.directory, "audit"))
	if err != nil {
		return Head{}, 0, err
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	previous := ""
	last := Head{SchemaVersion: HeadSchemaV1, LedgerID: s.ledgerID}
	sawV2 := false
	frozenPrefixLength := 0
	for i, name := range names {
		raw, err := os.ReadFile(filepath.Join(s.directory, "audit", name))
		if err != nil {
			return Head{}, 0, err
		}
		var event AuditEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			return Head{}, 0, err
		}
		if event.Sequence != uint64(i+1) || event.PreviousAuditSHA256 != previous {
			return Head{}, 0, errors.New("audit chain sequence mismatch")
		}
		var auditSHA string
		switch event.SchemaVersion {
		case AuditSchemaV1:
			if sawV2 {
				return Head{}, 0, fmt.Errorf("v1 (pre-D2, unkeyed) audit entry at sequence %d appears after the v2 genesis boundary: hard failure per ADR-0007 D4 point 6", event.Sequence)
			}
			auditSHA, err = legacyHashAudit(event)
			frozenPrefixLength = i + 1
		case AuditSchemaV2:
			sawV2 = true
			auditSHA, err = hashAudit(event, s.keys.chain)
		default:
			return Head{}, 0, fmt.Errorf("unrecognized audit schema version %q at sequence %d", event.SchemaVersion, event.Sequence)
		}
		if err != nil {
			return Head{}, 0, err
		}
		if auditSHA != event.AuditSHA256 {
			return Head{}, 0, errors.New("audit checksum mismatch")
		}
		previous = event.AuditSHA256
		last = Head{SchemaVersion: headSchemaFor(event.SchemaVersion), LedgerID: s.ledgerID, Sequence: event.Sequence, EventSHA256: event.AuditSHA256}
	}
	head, err := s.loadAuditHead()
	if err != nil {
		return Head{}, 0, err
	}
	if head.Sequence != last.Sequence || head.EventSHA256 != last.EventSHA256 {
		return Head{}, 0, errors.New("audit head mismatch")
	}
	return head, frozenPrefixLength, nil
}
func (s *Store) loadAuditHead() (Head, error) {
	raw, err := os.ReadFile(filepath.Join(s.directory, "audit-head.json"))
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

// legacyHashAudit mirrors legacyHashEvent for the audit chain: the pre-D2
// plain sha256.Sum256(json(event)), no key. See legacyHashEvent's comment.
func legacyHashAudit(event AuditEvent) (string, error) {
	event.AuditSHA256 = ""
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return digestHex(raw), nil
}

// hashAudit is ADR-0007 D2: HMAC-SHA256 under the derived chain key,
// replacing the pre-D2 plain sha256.Sum256(json(event)).
func hashAudit(event AuditEvent, chainKey []byte) (string, error) {
	event.AuditSHA256 = ""
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return macHex(chainKey, raw), nil
}
