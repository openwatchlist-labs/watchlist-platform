package activationpromotion

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func (m *Manager) nextAuditEvent(eventType string, state State, actor, reason string, payload map[string]any) AuditEvent {
	head, err := m.loadAuditHead()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		panic(err)
	}
	event := AuditEvent{
		SchemaVersion:       AuditEventSchemaV1,
		Sequence:            head.Sequence + 1,
		Timestamp:           m.timestamp(),
		EventType:           eventType,
		IntentID:            state.IntentID,
		Revision:            state.Revision,
		Actor:               actor,
		Reason:              reason,
		Payload:             payload,
		PreviousEventSHA256: head.EventSHA256,
	}
	raw, _ := canonical(event)
	event.EventSHA256 = shaHex(raw)
	return event
}

func (m *Manager) appendAudit(event AuditEvent) error {
	if err := verifyAuditEvent(event); err != nil {
		return err
	}
	head, err := m.loadAuditHead()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if head.Sequence == event.Sequence && head.EventSHA256 == event.EventSHA256 {
		return nil
	}
	if event.Sequence != head.Sequence+1 || event.PreviousEventSHA256 != head.EventSHA256 {
		return fmt.Errorf("audit append CAS mismatch: head sequence %d hash %q, event sequence %d previous %q", head.Sequence, head.EventSHA256, event.Sequence, event.PreviousEventSHA256)
	}
	path := filepath.Join(m.auditDirectory(), fmt.Sprintf("%020d-%s.json", event.Sequence, event.EventSHA256))
	if err := m.writeImmutable(path, event); err != nil {
		return err
	}
	newHead := AuditHead{SchemaVersion: AuditHeadSchemaV1, Sequence: event.Sequence, EventSHA256: event.EventSHA256}
	raw, _ := canonical(newHead)
	return atomicWrite(m.auditHeadPath(), raw, 0o644)
}

func (m *Manager) loadAuditHead() (AuditHead, error) {
	var head AuditHead
	if err := decodeStrictFile(m.auditHeadPath(), &head); err != nil {
		return AuditHead{}, err
	}
	if head.SchemaVersion != AuditHeadSchemaV1 || head.Sequence < 1 || head.EventSHA256 == "" {
		return AuditHead{}, errors.New("invalid audit head")
	}
	return head, nil
}

func verifyAuditEvent(event AuditEvent) error {
	if event.SchemaVersion != AuditEventSchemaV1 || event.Sequence < 1 || event.EventSHA256 == "" {
		return errors.New("invalid audit event")
	}
	expected := event.EventSHA256
	event.EventSHA256 = ""
	raw, err := canonical(event)
	if err != nil {
		return err
	}
	if shaHex(raw) != expected {
		return errors.New("audit event checksum mismatch")
	}
	return nil
}
