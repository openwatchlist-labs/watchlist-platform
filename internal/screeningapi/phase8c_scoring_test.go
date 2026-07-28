package screeningapi

import (
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
)

func TestPhase8CBridgeUsesOneEngineForRealtimeAndBatch(t *testing.T) {
	policy, err := candidatescoring.ParsePolicy([]byte(`{
  "schema_version":"openwatchlist.candidate-scoring-policy.v1",
  "policy_id":"bridge-test",
  "policy_version":"1.0.0",
  "normalization_profile":"unicode-upper-alnum-space-v1",
  "max_evidence_items":4,
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
}`))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := candidatescoring.NewEngine(policy)
	if err != nil {
		t.Fatal(err)
	}
	bridge := NewPhase8CCandidateScorer(engine)
	request := candidatescoring.Request{
		SchemaVersion: candidatescoring.RequestSchemaV1,
		RequestID:     "bridge-1",
		Subject:       candidatescoring.Subject{Names: []string{"Jane Doe"}},
		Lineage: candidatescoring.Lineage{
			Provider: "ofac-direct", CatalogID: "catalog", ComponentID: "sdn",
			ComponentVersion: "v1", ActivationID: "active",
			NormalizationProfile: "unicode-upper-alnum-space-v1",
		},
		Candidates: []candidatescoring.CandidateEnvelope{{Candidate: candidatescoring.Candidate{CandidateID: "candidate-1", Names: []string{"JANE DOE"}}}},
	}
	realtime, err := bridge.Score(request)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := bridge.ScoreBatch(candidatescoring.BatchRequest{SchemaVersion: candidatescoring.BatchRequestSchemaV1, BatchID: "batch-1", Items: []candidatescoring.Request{request}})
	if err != nil {
		t.Fatal(err)
	}
	if realtime.RequestSHA256 != batch.Items[0].RequestSHA256 || realtime.Candidates[0].Score != batch.Items[0].Candidates[0].Score {
		t.Fatalf("real-time and batch scoring drifted: realtime=%+v batch=%+v", realtime, batch.Items[0])
	}
}
