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

// verifyAuditPolicyLocked assumes the caller already holds s.mu. It
// mirrors verifyPolicyLocked's EA1/EA2 handling (ADR-0007 D8): which
// entry is even allowed to claim v1 is chosen by this entry's position
// against policy.GenesisAuditSequence, not by the entry's own
// SchemaVersion -- an audit-chain relabelling attack (F1's audit-chain
// half, which has no snapshot check at all to bound it) is closed the
// same way the event chain's is.
func (s *Store) verifyAuditPolicyLocked(policy VerificationPolicy) (Head, int, error) {
	minAuditOrdinal, ok := auditSchemaOrdinal(policy.MinAuditSchema)
	if !ok {
		return Head{}, 0, fmt.Errorf("policy min_audit_schema %q is not a recognized audit schema version", policy.MinAuditSchema)
	}
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
		if event.Sequence < policy.GenesisAuditSequence {
			if event.SchemaVersion != AuditSchemaV1 {
				return Head{}, 0, fmt.Errorf("audit entry at sequence %d is below the policy genesis boundary (%d) and must be schema %q, got %q", event.Sequence, policy.GenesisAuditSequence, AuditSchemaV1, event.SchemaVersion)
			}
			auditSHA, err = legacyHashAudit(event)
			frozenPrefixLength = i + 1
		} else {
			ordinal, recognized := auditSchemaOrdinal(event.SchemaVersion)
			if !recognized || ordinal < minAuditOrdinal {
				return Head{}, 0, fmt.Errorf("audit entry at sequence %d (schema %q) is at or after the policy genesis boundary (%d) and does not meet the minimum accepted schema version %q: hard failure per ADR-0007 D8 EA1/EA2", event.Sequence, event.SchemaVersion, policy.GenesisAuditSequence, policy.MinAuditSchema)
			}
			switch event.SchemaVersion {
			case AuditSchemaV2:
				auditSHA, err = hashAudit(event, s.keys.chain)
			default:
				return Head{}, 0, fmt.Errorf("audit entry at sequence %d has schema %q with no known digest algorithm", event.Sequence, event.SchemaVersion)
			}
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
