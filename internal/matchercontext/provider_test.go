package matchercontext

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherbaseline"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
)

func TestProviderContextRoutes(t *testing.T) {
	provider := loadTestProvider(t)
	tests := []struct {
		name        string
		request     matcherrequest.CandidateSearchRequest
		candidateID string
		diagnostic  string
	}{
		{name: "jurisdiction alpha2", request: request(canonical.RouteJurisdictionPolicy, "CU", "jurisdiction_context_r1", []canonical.CandidateType{canonical.CandidateJurisdiction}), candidateID: "jurisdiction-policy:synthetic-cu"},
		{name: "narrative primary", request: request(canonical.RouteContextualPhrase, "Invoice settlement for Acme Imports LLC", "narrative_context_r1", []canonical.CandidateType{canonical.CandidateOrganization}), candidateID: "ofac:sdn:1001"},
		{name: "narrative denial", request: request(canonical.RouteContextualPhrase, "NO BUSINESS RELATIONSHIP WITH JORDAN EXAMPLE", "narrative_context_r1", []canonical.CandidateType{canonical.CandidateIndividual}), diagnostic: "narrative_denial_context"},
		{name: "substring boundary", request: request(canonical.RouteContextualPhrase, "SCUBA equipment purchase", "narrative_context_r1", []canonical.CandidateType{canonical.CandidateJurisdiction})},
		{name: "vessel alias", request: request(canonical.RouteContextualPhrase, "Freight charges for MV EXAMPLE", "narrative_context_r1", []canonical.CandidateType{canonical.CandidateVessel}), candidateID: "ofac:sdn:3003"},
		{name: "jurisdiction phrase", request: request(canonical.RouteContextualPhrase, "Shipment routed via CUBA", "narrative_context_r1", []canonical.CandidateType{canonical.CandidateJurisdiction}), candidateID: "jurisdiction-policy:synthetic-cu"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidates, diagnostics, err := provider.SearchWithDiagnostics(context.Background(), test.request)
			if err != nil {
				t.Fatal(err)
			}
			if test.candidateID == "" {
				if len(candidates) != 0 {
					t.Fatalf("expected no candidates, got %#v", candidates)
				}
			} else {
				if len(candidates) != 1 || candidates[0].ProviderRecordID != test.candidateID {
					t.Fatalf("unexpected candidates %#v", candidates)
				}
				if candidates[0].Evidence == nil || candidates[0].Evidence.Context == nil {
					t.Fatalf("context evidence is required")
				}
			}
			if test.diagnostic == "" {
				if len(diagnostics) != 0 {
					t.Fatalf("unexpected diagnostics %#v", diagnostics)
				}
			} else if len(diagnostics) != 1 || diagnostics[0].Code != test.diagnostic {
				t.Fatalf("unexpected diagnostics %#v", diagnostics)
			}
		})
	}
}

func TestProfileAndPolicyStrictJSON(t *testing.T) {
	profileData, err := os.ReadFile("../../configs/matcher-profiles/ofac-context-baseline-r1.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err := json.Unmarshal(profileData, &profile); err != nil {
		t.Fatal(err)
	}
	profile["unknown"] = true
	mutated, _ := json.Marshal(profile)
	if _, err := LoadProfileSet(strings.NewReader(string(mutated))); err == nil {
		t.Fatal("unknown profile field was accepted")
	}
	policyData, err := os.ReadFile("../../test/fixtures/matcher-context/jurisdiction-policy-synthetic-r1.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy JurisdictionPolicySet
	if err := json.Unmarshal(policyData, &policy); err != nil {
		t.Fatal(err)
	}
	policy.PolicySetChecksum = strings.Repeat("0", 64)
	mutated, _ = json.Marshal(policy)
	if _, err := LoadPolicySet(strings.NewReader(string(mutated))); err == nil {
		t.Fatal("policy checksum drift was accepted")
	}
}

func loadTestProvider(t *testing.T) *Provider {
	t.Helper()
	packageBytes, err := os.ReadFile("../../test/golden/ofac/ofac-sdn-fixture.runtime.owpcat")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ofacruntime.Load(packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	nameFile, err := os.Open("../../configs/matcher-profiles/ofac-name-baseline-r1.json")
	if err != nil {
		t.Fatal(err)
	}
	nameProfiles, err := matcherbaseline.LoadProfileSet(nameFile)
	_ = nameFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	contextFile, err := os.Open("../../configs/matcher-profiles/ofac-context-baseline-r1.json")
	if err != nil {
		t.Fatal(err)
	}
	contextProfiles, err := LoadProfileSet(contextFile)
	_ = contextFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	policyFile, err := os.Open("../../test/fixtures/matcher-context/jurisdiction-policy-synthetic-r1.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadPolicySet(policyFile)
	_ = policyFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(loaded.Payload, nameProfiles, contextProfiles, policy)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func request(route canonical.MatchRoute, query, profile string, types []canonical.CandidateType) matcherrequest.CandidateSearchRequest {
	return matcherrequest.CandidateSearchRequest{
		RequestID: "request-test", SemanticRole: canonical.SemanticRole("remittance.unstructured"),
		MatchRoutes: []canonical.MatchRoute{route}, TargetEntityTypes: types,
		ThresholdProfile: profile, Query: matcherrequest.QueryValue{OriginalValue: query, NormalizedValue: query},
	}
}
