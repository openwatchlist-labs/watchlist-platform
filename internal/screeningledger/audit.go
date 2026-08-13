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
	event := AuditEvent{SchemaVersion: AuditSchemaV1, LedgerID: s.ledgerID, Sequence: head.Sequence + 1, PreviousAuditSHA256: head.EventSHA256, OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Action: action, Operator: operator, Reason: reason, EventID: eventID, Details: detailRaw}
	auditSHA, err := hashAudit(event)
	if err != nil {
		return AuditEvent{}, err
	}
	event.AuditSHA256 = auditSHA
	name := fmt.Sprintf("%020d-%s.json", event.Sequence, event.AuditSHA256)
	if err := marshalAndWrite(filepath.Join(s.directory, "audit", name), event, 0o640); err != nil {
		return AuditEvent{}, err
	}
	if err := marshalAndWrite(filepath.Join(s.directory, "audit-head.json"), Head{SchemaVersion: HeadSchemaV1, LedgerID: s.ledgerID, Sequence: event.Sequence, EventSHA256: event.AuditSHA256}, 0o640); err != nil {
		return AuditEvent{}, err
	}
	return event, nil
}

func (s *Store) VerifyAudit() (Head, error) {
	entries, err := os.ReadDir(filepath.Join(s.directory, "audit"))
	if err != nil {
		return Head{}, err
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
	for i, name := range names {
		raw, err := os.ReadFile(filepath.Join(s.directory, "audit", name))
		if err != nil {
			return Head{}, err
		}
		var event AuditEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			return Head{}, err
		}
		if event.Sequence != uint64(i+1) || event.PreviousAuditSHA256 != previous {
			return Head{}, errors.New("audit chain sequence mismatch")
		}
		auditSHA, err := hashAudit(event)
		if err != nil {
			return Head{}, err
		}
		if auditSHA != event.AuditSHA256 {
			return Head{}, errors.New("audit checksum mismatch")
		}
		previous = event.AuditSHA256
		last = Head{SchemaVersion: HeadSchemaV1, LedgerID: s.ledgerID, Sequence: event.Sequence, EventSHA256: event.AuditSHA256}
	}
	head, err := s.loadAuditHead()
	if err != nil {
		return Head{}, err
	}
	if head.Sequence != last.Sequence || head.EventSHA256 != last.EventSHA256 {
		return Head{}, errors.New("audit head mismatch")
	}
	return head, nil
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
func hashAudit(event AuditEvent) (string, error) {
	event.AuditSHA256 = ""
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return digestHex(raw), nil
}
