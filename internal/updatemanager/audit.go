package updatemanager

import (
	"fmt"
	"time"
)

func appendAudit(history AuditHistory, eventType, subjectID string, occurredAt time.Time, payload any) (AuditHistory, AuditEvent, error) {
	if history.SchemaVersion == "" {
		history.SchemaVersion = AuditHistorySchemaVersion
	}
	if history.SchemaVersion != AuditHistorySchemaVersion || eventType == "" || subjectID == "" || occurredAt.IsZero() {
		return AuditHistory{}, AuditEvent{}, fmt.Errorf("%w: invalid audit event input", ErrInvalidUpdate)
	}
	event := AuditEvent{
		SchemaVersion: AuditEventSchemaVersion,
		Sequence:      uint64(len(history.Events) + 1),
		PreviousHash:  history.HeadHash,
		EventType:     eventType,
		SubjectID:     subjectID,
		OccurredAt:    occurredAt.UTC(),
		PayloadSHA256: sha256JSON(payload),
	}
	seed := event
	seed.EventID = ""
	seed.EventHash = ""
	event.EventHash = sha256JSON(seed)
	event.EventID = "audit_" + event.EventHash[:24]
	history.Events = append(history.Events, event)
	history.HeadHash = event.EventHash
	return history, event, nil
}

func ValidateAuditHistory(history AuditHistory) error {
	if history.SchemaVersion != AuditHistorySchemaVersion {
		return fmt.Errorf("%w: invalid audit history schema", ErrInvalidUpdate)
	}
	previous := ""
	for index, event := range history.Events {
		if event.SchemaVersion != AuditEventSchemaVersion || event.Sequence != uint64(index+1) || event.PreviousHash != previous || event.EventID == "" || event.EventHash == "" || event.EventType == "" || event.SubjectID == "" || event.OccurredAt.IsZero() || event.PayloadSHA256 == "" {
			return fmt.Errorf("%w: invalid audit event at index %d", ErrInvalidUpdate, index)
		}
		seed := event
		seed.EventID = ""
		seed.EventHash = ""
		if sha256JSON(seed) != event.EventHash || event.EventID != "audit_"+event.EventHash[:24] {
			return fmt.Errorf("%w: audit hash-chain drift at index %d", ErrInvalidUpdate, index)
		}
		previous = event.EventHash
	}
	if history.HeadHash != previous {
		return fmt.Errorf("%w: audit head mismatch", ErrInvalidUpdate)
	}
	return nil
}
