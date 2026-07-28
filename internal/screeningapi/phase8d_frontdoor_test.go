package screeningapi

import (
	"net/http"
	"testing"
)

func TestPhase8DFrontDoorExportsPolicyBoundIntegration(t *testing.T) {
	client := &http.Client{}
	upstream := NewPhase8DHTTPUpstream("http://127.0.0.1:18090", client)
	if upstream == nil {
		t.Fatal("Phase 8D upstream bridge is nil")
	}
	if Phase8DShutdownTimeout <= 0 {
		t.Fatal("Phase 8D shutdown timeout is not bounded")
	}
}
