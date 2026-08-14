package vendoradapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

// TestConvertPerVendorMappedFields is the regression test for the coverage
// gap TestProfilesConvertAndAlertCaseCompatibility leaves open: that test
// only checks structural properties shared by every profile (SourceType,
// ExternalAlert schema version), so it would still pass even if
// fircosoft-reference-json-v1's and actimize-reference-json-v1's source
// paths were accidentally swapped -- e.g. fircosoft's source_system_id
// mapping pointing at caseAlert.product instead of message.source. Here
// every expected value is taken from the vendor's actual fixture and the
// two profiles use disjoint values for every field asserted, so any
// cross-profile or intra-profile path swap changes an assertion's actual
// value away from its hardcoded expectation.
func TestConvertPerVendorMappedFields(t *testing.T) {
	root := repoRoot(t)
	profiles, err := LoadProfiles(filepath.Join(root, "configs", "vendor-adapters"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 15, 15, 0, 0, 0, time.UTC)

	type want struct {
		tenantID        string
		sourceSystemID  string
		sourceAlertID   string
		rawListName     string
		occurredAt      string
		externalScore   int
		externalReasons []string
		matchedFields   []string
		candidateRefs   []string
		messageRefs     []string
		attachmentRefs  []string
		correlationID   string
		idempotencyKey  string
		subjectName     string
		matchedName     string
		screenedName    string
		vendorStatus    string
		canonicalListID string
		listMappingID   string
	}

	cases := []struct {
		adapterID string
		fixture   string
		want      want
	}{
		{
			adapterID: "fircosoft-reference-json-v1",
			fixture:   "fircosoft-alert.json",
			want: want{
				tenantID:        "tenant-a",
				sourceSystemID:  "fircosoft-reference",
				sourceAlertID:   "FIR-1001",
				rawListName:     "OFAC",
				occurredAt:      "2026-07-15T14:31:00Z",
				externalScore:   88,
				externalReasons: []string{"name_exact"},
				matchedFields:   []string{"OrderingCustomer"},
				candidateRefs:   []string{"sdn:12345"},
				messageRefs:     []string{"MSG-9E-2"},
				attachmentRefs:  []string{"doc:def"},
				correlationID:   "corr-phase9e-fir",
				idempotencyKey:  "idem-phase9e-fir",
				subjectName:     "BETA EXPORTS LLC",
				matchedName:     "BETA EXPORTS",
				screenedName:    "BETA EXPORTS LLC",
				vendorStatus:    "PENDING",
				canonicalListID: "ofac-sdn",
				listMappingID:   "phase9e-ofac-alias",
			},
		},
		{
			adapterID: "actimize-reference-json-v1",
			fixture:   "actimize-alert.json",
			want: want{
				tenantID:        "tenant-a",
				sourceSystemID:  "actimize-reference",
				sourceAlertID:   "ACT-1001",
				rawListName:     "OFAC SDN",
				occurredAt:      "2026-07-15T14:32:00Z",
				externalScore:   84,
				externalReasons: []string{"name_exact"},
				matchedFields:   []string{"beneficiary.name"},
				candidateRefs:   []string{"sdn:67890"},
				messageRefs:     []string{"MSG-9E-3"},
				attachmentRefs:  []string{"doc:ghi"},
				correlationID:   "corr-phase9e-act",
				idempotencyKey:  "idem-phase9e-act",
				subjectName:     "GAMMA IMPORTS INC",
				matchedName:     "GAMMA IMPORTS",
				screenedName:    "GAMMA IMPORTS INC",
				vendorStatus:    "NEW",
				canonicalListID: "ofac-sdn",
				listMappingID:   "phase9e-ofac-sdn",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.adapterID, func(t *testing.T) {
			p, ok := profiles[tc.adapterID]
			if !ok {
				t.Fatalf("profile %s not loaded", tc.adapterID)
			}
			raw, err := os.ReadFile(filepath.Join(root, "test", "fixtures", "vendor-adapters", tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			e, err := Convert(p, "fixture:"+tc.fixture, raw, now)
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			req := e.CreateAlertRequest
			ea := req.ExternalAlert

			if req.TenantID != tc.want.tenantID {
				t.Errorf("tenant_id = %q, want %q", req.TenantID, tc.want.tenantID)
			}
			if ea.SourceSystemID != tc.want.sourceSystemID {
				t.Errorf("source_system_id = %q, want %q", ea.SourceSystemID, tc.want.sourceSystemID)
			}
			if ea.SourceAlertID != tc.want.sourceAlertID {
				t.Errorf("source_alert_id = %q, want %q", ea.SourceAlertID, tc.want.sourceAlertID)
			}
			if ea.RawListName != tc.want.rawListName {
				t.Errorf("raw_list_name = %q, want %q", ea.RawListName, tc.want.rawListName)
			}
			if ea.OccurredAt != tc.want.occurredAt {
				t.Errorf("occurred_at = %q, want %q", ea.OccurredAt, tc.want.occurredAt)
			}
			if ea.ExternalScore != tc.want.externalScore {
				t.Errorf("external_score = %d, want %d", ea.ExternalScore, tc.want.externalScore)
			}
			if !reflect.DeepEqual(ea.ExternalReasons, tc.want.externalReasons) {
				t.Errorf("external_reason_codes = %v, want %v", ea.ExternalReasons, tc.want.externalReasons)
			}
			if !reflect.DeepEqual(ea.MatchedFields, tc.want.matchedFields) {
				t.Errorf("matched_fields = %v, want %v", ea.MatchedFields, tc.want.matchedFields)
			}
			if !reflect.DeepEqual(ea.CandidateReferences, tc.want.candidateRefs) {
				t.Errorf("candidate_references = %v, want %v", ea.CandidateReferences, tc.want.candidateRefs)
			}
			if !reflect.DeepEqual(ea.MessageReferences, tc.want.messageRefs) {
				t.Errorf("message_references = %v, want %v", ea.MessageReferences, tc.want.messageRefs)
			}
			if !reflect.DeepEqual(ea.AttachmentReferences, tc.want.attachmentRefs) {
				t.Errorf("attachment_references = %v, want %v", ea.AttachmentReferences, tc.want.attachmentRefs)
			}
			if req.CorrelationID != tc.want.correlationID {
				t.Errorf("correlation_id = %q, want %q", req.CorrelationID, tc.want.correlationID)
			}
			if req.IdempotencyKey != tc.want.idempotencyKey {
				t.Errorf("idempotency_key = %q, want %q", req.IdempotencyKey, tc.want.idempotencyKey)
			}
			if ea.AdditionalEvidence["matched_name"] != tc.want.matchedName {
				t.Errorf("additional_evidence.matched_name = %q, want %q", ea.AdditionalEvidence["matched_name"], tc.want.matchedName)
			}
			if ea.AdditionalEvidence["screened_name"] != tc.want.screenedName {
				t.Errorf("additional_evidence.screened_name = %q, want %q", ea.AdditionalEvidence["screened_name"], tc.want.screenedName)
			}
			if ea.AdditionalEvidence["vendor_status"] != tc.want.vendorStatus {
				t.Errorf("additional_evidence.vendor_status = %q, want %q", ea.AdditionalEvidence["vendor_status"], tc.want.vendorStatus)
			}

			var subject struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(req.Subject, &subject); err != nil {
				t.Fatalf("unmarshal subject: %v", err)
			}
			if subject.Name != tc.want.subjectName {
				t.Errorf("subject.name = %q, want %q", subject.Name, tc.want.subjectName)
			}

			var resolution struct {
				CanonicalListID string `json:"canonical_list_id"`
				MappingID       string `json:"mapping_id"`
			}
			if err := json.Unmarshal(ea.AlertListResolution, &resolution); err != nil {
				t.Fatalf("unmarshal alert_list_resolution: %v", err)
			}
			if resolution.CanonicalListID != tc.want.canonicalListID {
				t.Errorf("alert_list_resolution.canonical_list_id = %q, want %q", resolution.CanonicalListID, tc.want.canonicalListID)
			}
			if resolution.MappingID != tc.want.listMappingID {
				t.Errorf("alert_list_resolution.mapping_id = %q, want %q", resolution.MappingID, tc.want.listMappingID)
			}
		})
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
