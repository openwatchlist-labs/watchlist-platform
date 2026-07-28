package policyengine

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
)

const (
	policyPath  = "../../configs/policies/transaction-screening-r1.yaml"
	overlayPath = "../../configs/policies/tenant-overlays/conservative-review-r1.yaml"
)

func TestBaselinePolicyDecisions(t *testing.T) {
	policy := mustPolicy(t)
	engine, err := NewEngine(policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := mustClassificationBatch(t, "../../test/golden/false-positive/pattern-classifications.json")
	output, err := engine.EvaluateBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	assertCount(t, output.Summary.DispositionCounts, string(DispositionClear), 6)
	assertCount(t, output.Summary.DispositionCounts, string(DispositionInvestigate), 8)
	assertCount(t, output.Summary.DispositionCounts, string(DispositionEscalate), 2)
	assertDecision(t, output, "fp-01-substring-scuba-cuba", 0, DispositionClear, ReviewRouteAutoRelease)
	assertDecision(t, output, "fp-10-legal-control-context", 4500, DispositionInvestigate, ReviewRouteManualReview)
	assertDecision(t, output, "fp-11-exact-lei-countervailing", 8500, DispositionEscalate, ReviewRouteEscalationReview)
	assertDecision(t, output, "fp-12-exact-bic-countervailing", 8500, DispositionEscalate, ReviewRouteEscalationReview)
	assertDecision(t, output, "fp-15-supporting-exact-date", 7300, DispositionInvestigate, ReviewRouteStandardReview)
	assertDecision(t, output, "fp-16-supporting-exact-account", 7700, DispositionInvestigate, ReviewRouteStandardReview)
	assertGolden(t, output, "../../test/golden/policy/pattern-decisions.json")
}

func TestPhase3BAdaptationPolicyDecisions(t *testing.T) {
	engine, err := NewEngine(mustPolicy(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	input := mustClassificationBatch(t, "../../test/golden/false-positive/phase3b-contextual-classifications.json")
	output, err := engine.EvaluateBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	assertCount(t, output.Summary.DispositionCounts, string(DispositionClear), 1)
	assertCount(t, output.Summary.DispositionCounts, string(DispositionInvestigate), 14)
	assertCount(t, output.Summary.DispositionCounts, string(DispositionEscalate), 1)
	assertGolden(t, output, "../../test/golden/policy/phase3b-contextual-decisions.json")
}

func TestTenantOverlayChangesBehaviorWithoutMutatingBase(t *testing.T) {
	policy := mustPolicy(t)
	before := PolicyChecksum(policy)
	overlay, err := LoadOverlay(overlayPath, policy)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(policy, &overlay)
	if err != nil {
		t.Fatal(err)
	}
	if after := PolicyChecksum(policy); before != after {
		t.Fatalf("base policy mutated: before=%s after=%s", before, after)
	}
	input := mustClassificationBatch(t, "../../test/golden/false-positive/pattern-classifications.json")
	output, err := engine.EvaluateBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	assertCount(t, output.Summary.DispositionCounts, string(DispositionInvestigate), 16)
	if len(output.Summary.DispositionCounts) != 1 {
		t.Fatalf("unexpected disposition counts: %+v", output.Summary.DispositionCounts)
	}
	for _, decision := range output.Decisions {
		if decision.Overlay == nil || decision.Overlay.OverlayChecksum != overlay.OverlayChecksum {
			t.Fatalf("missing overlay lineage for %s", decision.DecisionID)
		}
	}
	assertGolden(t, output, "../../test/golden/policy/pattern-decisions-conservative-overlay.json")
}

func TestDeterministicRerunEquality(t *testing.T) {
	engine, err := NewEngine(mustPolicy(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	input := mustClassificationBatch(t, "../../test/golden/false-positive/pattern-classifications.json")
	first, err := engine.EvaluateBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.EvaluateBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("deterministic rerun mismatch")
	}
}

func TestPolicyStrictYAMLAndChecksumGates(t *testing.T) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("unknown field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "unknown.yaml")
		modified := bytes.Replace(data, []byte("policy_version: 1.0.0\n"), []byte("policy_version: 1.0.0\nunknown_policy_field: rejected\n"), 1)
		if err := os.WriteFile(path, modified, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("expected unknown-field rejection, got %v", err)
		}
	})
	t.Run("checksum drift", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "drift.yaml")
		modified := bytes.Replace(data, []byte("screening_score: 4500"), []byte("screening_score: 4501"), 1)
		if err := os.WriteFile(path, modified, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(path); err == nil || !strings.Contains(err.Error(), "policy_checksum") {
			t.Fatalf("expected checksum rejection, got %v", err)
		}
	})
	t.Run("sequence syntax", func(t *testing.T) {
		if _, err := parseYAMLMap([]byte("items:\n  - unsafe\n")); err == nil {
			t.Fatal("expected sequence rejection")
		}
	})
}

func TestSupportingEvidenceCannotEscalate(t *testing.T) {
	engine, err := NewEngine(mustPolicy(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	input := mustClassificationBatch(t, "../../test/golden/false-positive/pattern-classifications.json")
	output, err := engine.EvaluateBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, decision := range output.Decisions {
		if decision.Classification.Observation.TriggerPolicy == "supporting_evidence" && decision.Disposition == DispositionEscalate {
			t.Fatalf("supporting evidence escalated: %s", decision.Classification.Observation.CaseID)
		}
	}
}

func mustPolicy(t *testing.T) Policy {
	t.Helper()
	policy, err := LoadPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
func mustClassificationBatch(t *testing.T, path string) falsepositive.ClassificationBatch {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input falsepositive.ClassificationBatch
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal(err)
	}
	return input
}
func assertGolden(t *testing.T, value any, path string) {
	t.Helper()
	actual, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("golden mismatch: %s", path)
	}
}
func assertCount(t *testing.T, counts []NamedCount, name string, expected int) {
	t.Helper()
	for _, count := range counts {
		if count.Name == name {
			if count.Count != expected {
				t.Fatalf("count %s=%d expected %d", name, count.Count, expected)
			}
			return
		}
	}
	t.Fatalf("count %s missing", name)
}
func assertDecision(t *testing.T, batch DecisionBatch, caseID string, score int, disposition Disposition, route ReviewRoute) {
	t.Helper()
	for _, decision := range batch.Decisions {
		if decision.Classification.Observation.CaseID == caseID {
			if decision.PolicyScore != score || decision.Disposition != disposition || decision.ReviewRoute != route {
				t.Fatalf("case %s got score=%d disposition=%s route=%s", caseID, decision.PolicyScore, decision.Disposition, decision.ReviewRoute)
			}
			return
		}
	}
	t.Fatalf("case %s missing", caseID)
}
