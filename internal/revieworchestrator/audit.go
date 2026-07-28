package revieworchestrator

import "fmt"

type auditBuilder struct{ events []AuditEvent }

func (b *auditBuilder) add(eventType, caseID string, payload any) {
	previous := ""
	if len(b.events) > 0 {
		previous = b.events[len(b.events)-1].EventHash
	}
	e := AuditEvent{SchemaVersion: AuditEventSchema, Sequence: len(b.events) + 1, EventType: eventType, CaseID: caseID, PayloadDigest: digest(payload), PreviousHash: previous}
	e.EventID = hashID("review_event_", struct {
		Sequence                                       int
		EventType, CaseID, PayloadDigest, PreviousHash string
	}{e.Sequence, e.EventType, e.CaseID, e.PayloadDigest, e.PreviousHash})
	e.EventHash = digest(struct {
		Sequence                                                int
		EventID, EventType, CaseID, PayloadDigest, PreviousHash string
	}{e.Sequence, e.EventID, e.EventType, e.CaseID, e.PayloadDigest, e.PreviousHash})
	b.events = append(b.events, e)
}

func validateAudit(events []AuditEvent, head string) error {
	previous := ""
	for i, e := range events {
		if e.SchemaVersion != AuditEventSchema || e.Sequence != i+1 || e.EventType == "" || e.PayloadDigest == "" || e.PreviousHash != previous {
			return fmt.Errorf("invalid audit event at index %d", i)
		}
		expectedID := hashID("review_event_", struct {
			Sequence                                       int
			EventType, CaseID, PayloadDigest, PreviousHash string
		}{e.Sequence, e.EventType, e.CaseID, e.PayloadDigest, e.PreviousHash})
		expectedHash := digest(struct {
			Sequence                                                int
			EventID, EventType, CaseID, PayloadDigest, PreviousHash string
		}{e.Sequence, expectedID, e.EventType, e.CaseID, e.PayloadDigest, e.PreviousHash})
		if e.EventID != expectedID || e.EventHash != expectedHash {
			return fmt.Errorf("audit event %d hash mismatch", i+1)
		}
		previous = e.EventHash
	}
	if len(events) == 0 || head != previous {
		return fmt.Errorf("audit head mismatch")
	}
	return nil
}
