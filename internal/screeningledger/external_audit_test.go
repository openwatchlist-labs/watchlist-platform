package screeningledger

import "testing"

func TestPhase8fEventChecksumSurfacesMarshalError(t *testing.T) {
	bad := phase8fAuditEvent{Payload: map[string]any{"bad": make(chan int)}}
	if _, err := phase8fEventChecksum(bad); err == nil {
		t.Fatal("expected phase8fEventChecksum to return an error when Payload cannot be marshaled")
	}
}
