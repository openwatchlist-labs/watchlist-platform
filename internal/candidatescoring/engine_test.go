package candidatescoring

import (
	"encoding/json"
	"reflect"
	"testing"
)

func testPolicy(t *testing.T) LoadedPolicy {
	t.Helper()
	raw := []byte(`{
  "schema_version":"openwatchlist.candidate-scoring-policy.v1",
  "policy_id":"candidate-scoring-r1",
  "policy_version":"1.0.0",
  "normalization_profile":"unicode-upper-alnum-space-v1",
  "max_evidence_items":12,
  "score_floor":0,
  "score_ceiling":1000,
  "weights":{
    "typed_identifier_exact":550,
    "name_exact":400,
    "name_token_set":340,
    "name_prefix":250,
    "name_containment":180,
    "date_of_birth_exact":120,
    "date_of_birth_year":60,
    "country_exact":60,
    "entity_type_exact":40,
    "date_of_birth_conflict":-180,
    "country_conflict":-60,
    "entity_type_conflict":-100
  },
  "thresholds":{"strong_candidate":700,"review_candidate":400,"weak_candidate":1}
}`)
	policy, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testRequest() Request {
	return Request{
		SchemaVersion: RequestSchemaV1,
		RequestID:     "req-001",
		Subject: Subject{
			Names:       []string{"Acme Trading LLC"},
			Identifiers: []Identifier{{Type: "LEI", Value: "5493001KJTIIGC8Y1R12"}},
			Countries:   []string{"US"},
			EntityType:  "organization",
		},
		Lineage: Lineage{
			Provider: "ofac-direct", CatalogID: "catalog-1", ComponentID: "sdn",
			ComponentVersion: "2026-07-14", ActivationID: "activation-1",
			NormalizationProfile: "unicode-upper-alnum-space-v1",
		},
		Candidates: []CandidateEnvelope{
			{Candidate: Candidate{CandidateID: "z-candidate", Names: []string{"ACME TRADING LLC"}, Countries: []string{"US"}, EntityType: "entity"}},
			{Candidate: Candidate{CandidateID: "a-candidate", Names: []string{"Acme Trading"}, Identifiers: []Identifier{{Type: "lei", Value: "5493001KJTIIGC8Y1R12"}}, Countries: []string{"GB"}, EntityType: "organization"}},
		},
	}
}

func TestScoreIsDeterministicAndCanonicallyOrdered(t *testing.T) {
	engine, err := NewEngine(testPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := engine.Score(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Score(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("responses differ\nfirst=%+v\nsecond=%+v", first, second)
	}
	if got := first.Candidates[0].CandidateID; got != "a-candidate" {
		t.Fatalf("first candidate = %q, want a-candidate", got)
	}
	if first.Candidates[0].Score != 780 {
		t.Fatalf("score = %d, want 780", first.Candidates[0].Score)
	}
	if first.Candidates[0].StrengthBand != "strong_candidate" {
		t.Fatalf("strength band = %q", first.Candidates[0].StrengthBand)
	}
}

func TestEvidenceIsBoundedAndContainsNoDisposition(t *testing.T) {
	policy := testPolicy(t).Policy
	policy.MaxEvidenceItems = 2
	rawPolicy, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ParsePolicy(rawPolicy)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(loaded)
	if err != nil {
		t.Fatal(err)
	}
	response, err := engine.Score(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Candidates[0].Evidence) != 2 {
		t.Fatalf("evidence length = %d, want 2", len(response.Candidates[0].Evidence))
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"disposition", "clearance", "analyst_decision", "full_record"} {
		if contains(string(raw), forbidden) {
			t.Fatalf("response contains forbidden field %q: %s", forbidden, raw)
		}
	}
}

func TestBatchPreservesItemOrder(t *testing.T) {
	engine, err := NewEngine(testPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	first := testRequest()
	first.RequestID = "first"
	second := testRequest()
	second.RequestID = "second"
	response, err := engine.ScoreBatch(BatchRequest{SchemaVersion: BatchRequestSchemaV1, BatchID: "batch-1", Items: []Request{first, second}})
	if err != nil {
		t.Fatal(err)
	}
	if response.Items[0].RequestID != "first" || response.Items[1].RequestID != "second" {
		t.Fatalf("batch order changed: %+v", response.Items)
	}
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
