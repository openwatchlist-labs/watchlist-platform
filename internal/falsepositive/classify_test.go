package falsepositive

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

func repoPath(parts ...string) string {
	all := append([]string{"..", ".."}, parts...)
	return filepath.Join(all...)
}

func loadObservationFixture(t *testing.T) ObservationBatch {
	t.Helper()
	data, err := os.ReadFile(repoPath("test", "fixtures", "false-positive", "pattern-observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var batch ObservationBatch
	if err := decoder.Decode(&batch); err != nil {
		t.Fatal(err)
	}
	return CanonicalizeObservationBatch(batch)
}

func loadLibrary(t *testing.T) PatternLibrary {
	t.Helper()
	library, err := LoadPatternLibrary(repoPath("configs", "false-positive-patterns", "baseline-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return library
}

func loadCountervailingPolicy(t *testing.T) CountervailingPolicy {
	t.Helper()
	policy, err := LoadCountervailingPolicy(repoPath("configs", "false-positive-patterns", "countervailing-evidence-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestPatternFixtureClassification(t *testing.T) {
	classifier, err := NewClassifier(loadLibrary(t), loadCountervailingPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	output, err := classifier.ClassifyBatch(loadObservationFixture(t))
	if err != nil {
		t.Fatal(err)
	}

	type expected struct {
		patterns      []string
		route         RouteHint
		blockers      []string
		signalCode    string
		evidenceClass EvidenceClass
		eligible      bool
	}
	expectedByCase := map[string]expected{
		"fp-01-substring-scuba-cuba":       {patterns: []string{PatternSubstringContainment}, route: RouteClearEligible, blockers: []string{"substring_only_match"}},
		"fp-02-wrong-field-account-vessel": {patterns: []string{PatternEntityTypeMismatch, PatternWrongFieldDataType}, route: RouteClearEligible, blockers: []string{"entity_type_conflict", "wrong_field_context"}},
		"fp-03-entity-type-mismatch":       {patterns: []string{PatternEntityTypeMismatch}, route: RouteInvestigate, blockers: []string{"entity_type_conflict"}},
		"fp-04-missing-bank-qualifier":     {patterns: []string{PatternMissingQualifier}, route: RouteInvestigate, blockers: []string{"missing_critical_watchlist_terms"}},
		"fp-05-routing-bic-collision":      {patterns: []string{PatternEntityTypeMismatch, PatternRoutingBICCollision}, route: RouteClearEligible, blockers: []string{"entity_type_conflict", "routing_code_collision"}},
		"fp-06-acronym-reference":          {patterns: []string{PatternAcronymCollision, PatternWrongFieldDataType}, route: RouteClearEligible, blockers: []string{"acronym_field_collision", "wrong_field_context"}},
		"fp-07-phonetic-only":              {patterns: []string{PatternPhoneticTransliterationOnly}, route: RouteInvestigate, blockers: []string{"secondary_identifier_missing"}},
		"fp-08-narrative-denial":           {patterns: []string{PatternNarrativeDenialContext}, route: RouteClearEligible, blockers: []string{"denial_context"}},
		"fp-09-technical-artifact":         {patterns: []string{PatternTechnicalSystemArtifact, PatternWrongFieldDataType}, route: RouteClearEligible, blockers: []string{"technical_artifact", "wrong_field_context"}},
		"fp-10-legal-control-context":      {patterns: []string{PatternLegalControlContext}, route: RouteManualReview, blockers: []string{"legal_control_evidence_required"}},
		"fp-11-exact-lei-countervailing":   {route: RouteEscalationCandidate, signalCode: "exact_primary_identifier_match", evidenceClass: EvidenceClassPrimaryIdentifier, eligible: true},
		"fp-12-exact-bic-countervailing":   {route: RouteEscalationCandidate, signalCode: "exact_primary_identifier_match", evidenceClass: EvidenceClassPrimaryIdentifier, eligible: true},
		"fp-13-whole-token-geography":      {route: RouteInvestigate},
		"fp-14-multifeature-fuzzy-name":    {route: RouteInvestigate},
		"fp-15-supporting-exact-date":      {route: RouteInvestigate, blockers: []string{"supporting_evidence_cannot_escalate"}, signalCode: "exact_secondary_attribute_match", evidenceClass: EvidenceClassSecondaryAttribute},
		"fp-16-supporting-exact-account":   {route: RouteInvestigate, blockers: []string{"supporting_evidence_cannot_escalate"}, signalCode: "exact_secondary_attribute_match", evidenceClass: EvidenceClassSecondaryAttribute},
	}
	if len(output.Classifications) != len(expectedByCase) {
		t.Fatalf("classifications=%d expected %d", len(output.Classifications), len(expectedByCase))
	}
	for _, classification := range output.Classifications {
		expected, ok := expectedByCase[classification.Observation.CaseID]
		if !ok {
			t.Fatalf("unexpected case %s", classification.Observation.CaseID)
		}
		codes := make([]string, len(classification.Patterns))
		for index, pattern := range classification.Patterns {
			codes[index] = pattern.Code
		}
		if !slices.Equal(codes, expected.patterns) {
			t.Errorf("%s patterns=%v expected %v", classification.Observation.CaseID, codes, expected.patterns)
		}
		if classification.RouteHint != expected.route {
			t.Errorf("%s route=%s expected %s", classification.Observation.CaseID, classification.RouteHint, expected.route)
		}
		if !reflect.DeepEqual(classification.EscalationBlockers, expected.blockers) {
			t.Errorf("%s blockers=%v expected %v", classification.Observation.CaseID, classification.EscalationBlockers, expected.blockers)
		}
		if expected.signalCode == "" {
			if len(classification.CountervailingSignals) != 0 {
				t.Errorf("%s unexpected countervailing signals: %+v", classification.Observation.CaseID, classification.CountervailingSignals)
			}
		} else {
			if len(classification.CountervailingSignals) != 1 {
				t.Errorf("%s signals=%d expected 1", classification.Observation.CaseID, len(classification.CountervailingSignals))
			} else {
				signal := classification.CountervailingSignals[0]
				if signal.Code != expected.signalCode || signal.EvidenceClass != expected.evidenceClass || signal.EscalationEligible != expected.eligible {
					t.Errorf("%s signal=%+v expected code=%s class=%s eligible=%t", classification.Observation.CaseID, signal, expected.signalCode, expected.evidenceClass, expected.eligible)
				}
			}
		}
	}
}

func TestDeterministicClassification(t *testing.T) {
	classifier, err := NewClassifier(loadLibrary(t), loadCountervailingPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	input := loadObservationFixture(t)
	left, err := classifier.ClassifyBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	right, err := classifier.ClassifyBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatal("classification is not deterministic")
	}
}

func TestMatcherResultAdapter(t *testing.T) {
	data, err := os.ReadFile(repoPath("test", "golden", "matcher-context", "pacs008-contextual.results.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var results matcherprovider.ResultBatch
	if err := decoder.Decode(&results); err != nil {
		t.Fatal(err)
	}
	observations, err := ObservationsFromMatcherResults(results, "golden:phase3b-contextual-results")
	if err != nil {
		t.Fatal(err)
	}
	if len(observations.Observations) != results.Summary.TotalCandidates+1 {
		t.Fatalf("observations=%d expected %d", len(observations.Observations), results.Summary.TotalCandidates+1)
	}
	classifier, err := NewClassifier(loadLibrary(t), loadCountervailingPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	classified, err := classifier.ClassifyBatch(observations)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, item := range classified.Summary.PatternCounts {
		counts[item.Name] = item.Count
	}
	if counts[PatternEntityTypeMismatch] != 0 {
		// The Phase 3B fixture contains denial but its entity mismatch belongs to the Phase 3A fixture.
		t.Fatalf("unexpected entity mismatch count %d", counts[PatternEntityTypeMismatch])
	}
	if counts[PatternNarrativeDenialContext] != 1 {
		t.Fatalf("denial count=%d expected 1", counts[PatternNarrativeDenialContext])
	}
	if counts[PatternPhoneticTransliterationOnly] != 1 {
		t.Fatalf("transliteration-only count=%d expected 1", counts[PatternPhoneticTransliterationOnly])
	}
	routes := map[string]int{}
	for _, item := range classified.Summary.RouteHintCounts {
		routes[item.Name] = item.Count
	}
	if !reflect.DeepEqual(routes, map[string]int{
		string(RouteClearEligible):       1,
		string(RouteEscalationCandidate): 1,
		string(RouteInvestigate):         14,
	}) {
		t.Fatalf("Phase 3B route counts=%v", routes)
	}
	for _, classification := range classified.Classifications {
		if classification.Observation.TriggerPolicy != "candidate_alert" && classification.RouteHint == RouteEscalationCandidate {
			t.Fatalf("supporting evidence escalated: %s", classification.Observation.CaseID)
		}
	}
}

func TestPatternLibraryRejectsChecksumDrift(t *testing.T) {
	library := loadLibrary(t)
	library.Patterns[0].DefaultStrengthBasisPoints++
	if err := ValidatePatternLibrary(library); err == nil {
		t.Fatal("expected checksum drift rejection")
	}
}

func TestPatternLibraryRejectsUnknownFields(t *testing.T) {
	data, err := os.ReadFile(repoPath("configs", "false-positive-patterns", "baseline-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"library_id"`), []byte(`"unknown_field":true,"library_id"`), 1)
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPatternLibrary(path); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func TestCountervailingPolicyRejectsChecksumDrift(t *testing.T) {
	policy := loadCountervailingPolicy(t)
	policy.ExactRouteRules[0].StrengthBasisPoints++
	if err := ValidateCountervailingPolicy(policy); err == nil {
		t.Fatal("expected countervailing policy checksum drift rejection")
	}
}

func TestCountervailingPolicyRejectsUnknownFields(t *testing.T) {
	data, err := os.ReadFile(repoPath("configs", "false-positive-patterns", "countervailing-evidence-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"policy_id"`), []byte(`"unknown_field":true,"policy_id"`), 1)
	path := filepath.Join(t.TempDir(), "bad-policy.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCountervailingPolicy(path); err == nil {
		t.Fatal("expected unknown policy field rejection")
	}
}

func TestSupportingEvidenceCannotEscalateEvenWithPrimaryRoute(t *testing.T) {
	input := loadObservationFixture(t)
	observation := input.Observations[0]
	observation.CaseID = "supporting-primary-route-gate"
	observation.MatchedField = "creditor.identification.lei"
	observation.SemanticRole = "creditor.identification.lei"
	observation.ValueType = "lei"
	observation.TriggerPolicy = "supporting_evidence"
	observation.InputValue = "529900T8BM49AURSDO55"
	observation.WatchlistValue = observation.InputValue
	observation.MatchRoute = "exact_lei"
	observation.Exact = true
	observation.WatchlistEntityType = "organization"
	observation.TargetEntityTypes = nil
	input.Observations = []Observation{observation}
	input = CanonicalizeObservationBatch(input)
	classifier, err := NewClassifier(loadLibrary(t), loadCountervailingPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	output, err := classifier.ClassifyBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	classification := output.Classifications[0]
	if classification.RouteHint != RouteInvestigate {
		t.Fatalf("route=%s expected investigate", classification.RouteHint)
	}
	if !reflect.DeepEqual(classification.EscalationBlockers, []string{"supporting_evidence_cannot_escalate"}) {
		t.Fatalf("blockers=%v", classification.EscalationBlockers)
	}
	if len(classification.CountervailingSignals) != 1 || !classification.CountervailingSignals[0].EscalationEligible {
		t.Fatalf("expected primary eligible signal retained for audit: %+v", classification.CountervailingSignals)
	}
}

func TestGoldenPatternClassifications(t *testing.T) {
	classifier, err := NewClassifier(loadLibrary(t), loadCountervailingPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	output, err := classifier.ClassifyBatch(loadObservationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	expected, err := os.ReadFile(repoPath("test", "golden", "false-positive", "pattern-classifications.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("pattern classification golden drift")
	}
}

func TestGoldenPhase3BAdapterClassifications(t *testing.T) {
	data, err := os.ReadFile(repoPath("test", "golden", "matcher-context", "pacs008-contextual.results.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var results matcherprovider.ResultBatch
	if err := decoder.Decode(&results); err != nil {
		t.Fatal(err)
	}
	observations, err := ObservationsFromMatcherResults(results, "golden:phase3b-contextual-results")
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := NewClassifier(loadLibrary(t), loadCountervailingPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	output, err := classifier.ClassifyBatch(observations)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	expected, err := os.ReadFile(repoPath("test", "golden", "false-positive", "phase3b-contextual-classifications.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("Phase 3B adapter classification golden drift")
	}
}
