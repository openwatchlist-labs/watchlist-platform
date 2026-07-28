package vendoradapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
)

func repoRoot(t *testing.T) string {
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(d, "..", ".."))
}
func TestProfilesConvertAndAlertCaseCompatibility(t *testing.T) {
	root := repoRoot(t)
	profiles, err := LoadProfiles(filepath.Join(root, "configs", "vendor-adapters"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 15, 15, 0, 0, 0, time.UTC)
	fixtures := map[string]string{"generic-json-v1": "generic-alert.json", "fircosoft-reference-json-v1": "fircosoft-alert.json", "actimize-reference-json-v1": "actimize-alert.json"}
	policy := alertcase.Policy{SchemaVersion: alertcase.PolicySchemaV1, PolicyID: "test", Version: "r1", HighScoreThreshold: 90, ReviewScoreThreshold: 50, ExternalEscalateThreshold: 80}
	for id, file := range fixtures {
		p := profiles[id]
		raw, err := os.ReadFile(filepath.Join(root, "test", "fixtures", "vendor-adapters", file))
		if err != nil {
			t.Fatal(err)
		}
		e, err := Convert(p, "fixture:"+file, raw, now)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if e.CreateAlertRequest.SourceType != "external_alert" || e.CreateAlertRequest.ExternalAlert.SchemaVersion != alertcase.ExternalAlertSchemaV1 {
			t.Fatalf("invalid bridge for %s", id)
		}
		dir := t.TempDir()
		s, err := alertcase.NewStore(dir, policy, "test")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.CreateAlert(e.CreateAlertRequest); err != nil {
			t.Fatalf("alertcase compatibility %s: %v", id, err)
		}
	}
}
func TestStoreReplayConflictAndAudit(t *testing.T) {
	root := repoRoot(t)
	p, err := LoadProfile(filepath.Join(root, "configs", "vendor-adapters", "generic-json-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "test", "fixtures", "vendor-adapters", "generic-alert.json"))
	clock := func() time.Time { return time.Date(2026, 7, 15, 15, 0, 0, 0, time.UTC) }
	s, _ := NewStore(t.TempDir(), "test", clock)
	a, replayed, err := s.Process(p, "fixture:generic", raw)
	if err != nil || replayed {
		t.Fatalf("first: %v %v", replayed, err)
	}
	b, replayed, err := s.Process(p, "fixture:generic", raw)
	if err != nil || !replayed || a.RecordID != b.RecordID {
		t.Fatalf("replay: %v %v", replayed, err)
	}
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	doc["alert_id"] = "GEN-CONFLICT"
	changed, _ := json.Marshal(doc)
	if _, _, err := s.Process(p, "fixture:changed", changed); err == nil {
		t.Fatal("expected idempotency conflict")
	}
	st, err := s.Verify()
	if err != nil || st.RecordCount != 1 || st.ReceiptCount != 1 || st.AuditCount != 1 {
		t.Fatalf("status=%+v err=%v", st, err)
	}
}
func TestBatchQuarantine(t *testing.T) {
	root := repoRoot(t)
	p, _ := LoadProfile(filepath.Join(root, "configs", "vendor-adapters", "generic-json-v1.json"))
	good, _ := os.ReadFile(filepath.Join(root, "test", "fixtures", "vendor-adapters", "generic-alert.json"))
	bad := []byte(`{"tenant_id":"tenant-a"}`)
	b, err := ConvertBatch(p, []BatchInput{{"good", good}, {"bad", bad}}, time.Date(2026, 7, 15, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if b.AcceptedCount != 1 || b.RejectedCount != 1 || b.Items[1].ErrorCode != "missing_required_field" {
		t.Fatalf("unexpected batch %+v", b)
	}
}
