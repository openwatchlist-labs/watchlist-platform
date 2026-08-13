package screeningledger

import (
	"encoding/json"
	"testing"
)

func TestAppendAuditSurfacesDetailsMarshalError(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey(), "ledger-audit-marshal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendAudit("action", "operator", "reason", "event-1", make(chan int)); err == nil {
		t.Fatal("expected AppendAudit to return an error when details cannot be marshaled")
	}
	head, err := store.loadAuditHead()
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence != 0 {
		t.Fatalf("expected no audit event to be recorded when details marshaling fails, got sequence %d", head.Sequence)
	}
}

func TestHashAuditSurfacesMarshalError(t *testing.T) {
	bad := AuditEvent{SchemaVersion: AuditSchemaV1, Details: json.RawMessage("not valid json")}
	if _, err := hashAudit(bad); err == nil {
		t.Fatal("expected hashAudit to return an error for an audit event with an invalid Details payload")
	}
}
