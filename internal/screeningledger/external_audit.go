package screeningledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ExternalAuditRecord struct {
	Sequence            uint64
	EventSHA256         string
	PreviousEventSHA256 string
	OccurredAt          string
	Action              string
	StreamID            string
	Payload             []byte
}
type phase8fAuditEvent struct {
	SchemaVersion       string         `json:"schema_version"`
	Sequence            int64          `json:"sequence"`
	Timestamp           string         `json:"timestamp"`
	EventType           string         `json:"event_type"`
	IntentID            string         `json:"intent_id"`
	Revision            int64          `json:"revision"`
	Actor               string         `json:"actor"`
	Reason              string         `json:"reason,omitempty"`
	Payload             map[string]any `json:"payload,omitempty"`
	PreviousEventSHA256 string         `json:"previous_event_sha256,omitempty"`
	EventSHA256         string         `json:"event_sha256"`
}

func phase8fEventChecksum(event phase8fAuditEvent) (string, error) {
	event.EventSHA256 = ""
	canonical, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	canonical = append(canonical, '\n')
	return digestHex(canonical), nil
}
func LoadExternalAuditDirectory(directory string) ([]ExternalAuditRecord, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	records := []ExternalAuditRecord{}
	previous := ""
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return nil, err
		}
		var typed phase8fAuditEvent
		if err := json.Unmarshal(raw, &typed); err != nil {
			return nil, err
		}
		expected := typed.EventSHA256
		checksum, err := phase8fEventChecksum(typed)
		if err != nil {
			return nil, err
		}
		if checksum != expected {
			return nil, fmt.Errorf("%s checksum mismatch", name)
		}
		if typed.Sequence != int64(len(records)+1) || typed.PreviousEventSHA256 != previous {
			return nil, fmt.Errorf("%s audit chain mismatch", name)
		}
		records = append(records, ExternalAuditRecord{Sequence: uint64(typed.Sequence), EventSHA256: expected, PreviousEventSHA256: previous, OccurredAt: typed.Timestamp, Action: typed.EventType, StreamID: typed.IntentID, Payload: raw})
		previous = expected
	}
	return records, nil
}
func ImportExternalAudit(ctx context.Context, sink *PostgresSink, source, directory string) (int, error) {
	if sink == nil {
		return 0, errors.New("PostgreSQL sink is required")
	}
	if strings.TrimSpace(source) == "" {
		return 0, errors.New("audit source is required")
	}
	records, err := LoadExternalAuditDirectory(directory)
	if err != nil {
		return 0, err
	}
	for _, r := range records {
		if err := sink.PersistExternalAudit(ctx, source, r.StreamID, r.Sequence, r.EventSHA256, r.PreviousEventSHA256, r.OccurredAt, r.Action, r.Payload); err != nil {
			return 0, err
		}
	}
	return len(records), nil
}
