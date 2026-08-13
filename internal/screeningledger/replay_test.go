package screeningledger

import (
	"encoding/json"
	"testing"
)

func TestHashEventSurfacesMarshalError(t *testing.T) {
	bad := Event{SchemaVersion: EventSchemaV1, ActivationLineage: json.RawMessage("not valid json")}
	if _, err := hashEvent(bad); err == nil {
		t.Fatal("expected hashEvent to return an error for an event with an invalid ActivationLineage payload")
	}
}
