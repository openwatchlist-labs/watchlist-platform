// Package adversarialtest runs the adversarial/messy-data scenario bank
// (test/fixtures/adversarial/adversarial-scenarios-v*.json) against the
// real matcherbaseline fuzzy/phonetic engine, compiled from
// test/fixtures/adversarial/adversarial-catalog.direct-list.json into
// test/golden/adversarial/adversarial.runtime.owpcat.
//
// Design intent (see docs/TEST_COVERAGE.md for the full writeup):
//
//   - "baseline" scenarios must always pass - they test alias lookup on
//     data already registered in the catalog, which is the easy case.
//   - "stress" scenarios test whether the matcher generalizes to name
//     variants NOT registered as aliases. As of the scenario bank's
//     creation (2026-07-30), many of these fail - that's expected and
//     tracked via each scenario's known_status field, not hidden.
//   - Each scenario carries a known_status ("pass", "fail",
//     "ambiguous_as_expected", or "unscored") captured from an actual run.
//     This test asserts the CURRENT run matches known_status:
//   - known_status "pass" that now fails -> hard test failure (a real
//     regression in matching behavior).
//   - known_status "fail" that now passes -> logged as good news, not a
//     failure. Update known_status in the fixture once confirmed.
//   - "ambiguous_as_expected" -> logged; the correct behavior (routing
//     to human review) is a policy-layer decision this package can't
//     fully evaluate on its own, so we only check the matcher didn't
//     confidently return exactly one candidate.
//   - "clear" -> asserted: Search() only ever returns candidates that
//     already cleared the confident-match threshold (verified by reading
//     the provider code, not assumed), so "clear" means exactly "zero
//     candidates returned" and is checked as such, following the same
//     known_status regression-lock pattern as "match" scenarios.
//   - "unscored" -> logged only. See docs/TEST_COVERAGE.md for any
//     scenario truth values not yet wired into pass/fail logic.
//
// This means the suite is safe to run in ordinary CI today - it will not
// turn red because of a known, already-tracked gap - while still making
// every gap visible in test output and catching real regressions.
package adversarialtest

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherbaseline"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
)

type scenario struct {
	ScenarioID             string `json:"scenario_id"`
	Category               string `json:"category"`
	Tag                    string `json:"tag"`
	QueryName              string `json:"query_name"`
	TargetProviderRecordID string `json:"target_provider_record_id"`
	Truth                  string `json:"truth"`
	KnownStatus            string `json:"known_status"`
	Rationale              string `json:"rationale"`
}

type scenarioFile struct {
	Scenarios []scenario `json:"scenarios"`
}

// recordIDMap translates the human-readable record IDs used in the
// scenario JSON files to the ofac:sdn:NNNN IDs required by the strict
// ofaccatalog validator that adversarial-catalog.direct-list.json
// satisfies. Keep this in sync when adding new catalog entries.
var recordIDMap = map[string]string{
	"record-acme-imports":        "ofac:sdn:1001",
	"record-yevgeni-example":     "ofac:sdn:9001",
	"record-muhammad-example":    "ofac:sdn:9002",
	"record-jose-example":        "ofac:sdn:9003",
	"record-orion-trading-gmbh":  "ofac:sdn:9004",
	"record-orion-holdings-gmbh": "ofac:sdn:9005",
	"record-chen-example":        "ofac:sdn:9006",
	"record-novak-example":       "ofac:sdn:9007",
	"record-hiroshi-example":     "ofac:sdn:9008",
	"record-nguyen-example":      "ofac:sdn:9009",
	"record-oleksandr-example":   "ofac:sdn:9010",
	"record-william-example":     "ofac:sdn:9011",
}

const (
	runtimePackagePath = "../../test/golden/adversarial/adversarial.runtime.owpcat"
	profilesPath       = "../../configs/matcher-profiles/ofac-name-baseline-r1.json"
)

var scenarioFiles = []string{
	"../../test/fixtures/adversarial/adversarial-scenarios-v1.json",
	"../../test/fixtures/adversarial/adversarial-scenarios-v2.json",
}

func loadProvider(t *testing.T) *matcherbaseline.Provider {
	t.Helper()
	pkgData, err := os.ReadFile(runtimePackagePath)
	if err != nil {
		t.Fatalf("read compiled adversarial runtime package: %v", err)
	}
	loaded, err := ofacruntime.Load(pkgData)
	if err != nil {
		t.Fatalf("load compiled adversarial runtime package: %v", err)
	}
	profilesFile, err := os.Open(profilesPath)
	if err != nil {
		t.Fatalf("open matcher profiles: %v", err)
	}
	defer profilesFile.Close()
	profiles, err := matcherbaseline.LoadProfileSet(profilesFile)
	if err != nil {
		t.Fatalf("load matcher profiles: %v", err)
	}
	provider, err := matcherbaseline.NewProvider(loaded.Payload, profiles)
	if err != nil {
		t.Fatalf("construct matcherbaseline provider: %v", err)
	}
	return provider
}

func loadScenarios(t *testing.T) []scenario {
	t.Helper()
	var all []scenario
	for _, path := range scenarioFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read scenario file %s: %v", path, err)
		}
		var sf scenarioFile
		if err := json.Unmarshal(raw, &sf); err != nil {
			t.Fatalf("decode scenario file %s: %v", path, err)
		}
		all = append(all, sf.Scenarios...)
	}
	if len(all) == 0 {
		t.Fatal("no adversarial scenarios loaded - check scenarioFiles paths")
	}
	return all
}

func TestAdversarialScenarioBank(t *testing.T) {
	provider := loadProvider(t)
	scenarios := loadScenarios(t)

	var passCount, failCount, ambiguousCount, unscoredCount, newlyPassingCount int

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.ScenarioID, func(t *testing.T) {
			req := matcherrequest.CandidateSearchRequest{
				RequestID:    sc.ScenarioID,
				SemanticRole: "debtor.name",
				Query: matcherrequest.QueryValue{
					OriginalValue:   sc.QueryName,
					NormalizedValue: sc.QueryName,
				},
				MatchRoutes:       []canonical.MatchRoute{canonical.RouteAlias, canonical.RouteNormalizedName, canonical.RouteTransliteration},
				TargetEntityTypes: []canonical.CandidateType{canonical.CandidateIndividual, canonical.CandidateOrganization},
				ThresholdProfile:  "party_name_r1",
			}
			candidates, err := provider.Search(context.Background(), req)
			if err != nil {
				t.Fatalf("Search failed: %v", err)
			}

			var top string
			if len(candidates) > 0 {
				top = candidates[0].ProviderRecordID
			}
			expected := recordIDMap[sc.TargetProviderRecordID]

			switch sc.Truth {
			case "match", "match_on_name_not_identifier", "match_on_name_dob_should_not_hard_exclude":
				actualPass := top == expected && expected != ""
				assessAgainstKnownStatus(t, sc, actualPass, top, expected, &passCount, &failCount, &newlyPassingCount)
			case "clear":
				// Search() only ever returns candidates that already
				// cleared profile.ThresholdBasisPoints - every append
				// path in SearchWithDiagnostics checks
				// "score < profile.ThresholdBasisPoints { continue }"
				// first (verified by reading internal/matcherbaseline/provider.go
				// before writing this, not assumed). So a non-empty
				// candidates list here is ALWAYS a confident match by
				// definition; there is no such thing as a sub-threshold
				// entry to additionally check the score of. "clear"
				// means exactly and only "zero candidates returned."
				actualClear := len(candidates) == 0
				assessAgainstKnownStatus(t, sc, actualClear, top, "(no confident match)", &passCount, &failCount, &newlyPassingCount)
			case "ambiguous_by_design":
				ambiguousCount++
				if len(candidates) == 1 {
					t.Logf("KNOWN GAP: expected ambiguity (multiple or zero candidates), got exactly one confident candidate %s. %s", top, sc.Rationale)
				} else {
					t.Logf("ambiguous as expected (%d candidates returned): %s", len(candidates), sc.Rationale)
				}
			default:
				unscoredCount++
				t.Logf("UNSCORED (truth=%q, not yet wired into pass/fail logic - see docs/TEST_COVERAGE.md): %s", sc.Truth, sc.Rationale)
			}
		})
	}

	t.Logf("adversarial scenario bank summary: pass=%d fail=%d ambiguous=%d unscored=%d newly_passing=%d",
		passCount, failCount, ambiguousCount, unscoredCount, newlyPassingCount)
}

func assessAgainstKnownStatus(t *testing.T, sc scenario, actualPass bool, top, expected string, passCount, failCount, newlyPassingCount *int) {
	t.Helper()
	switch sc.KnownStatus {
	case "pass":
		if actualPass {
			*passCount++
			return
		}
		*failCount++
		t.Errorf("REGRESSION: scenario known to pass now fails. query=%q expected=%s got=%s. %s",
			sc.QueryName, expected, top, sc.Rationale)
	case "fail":
		if actualPass {
			*newlyPassingCount++
			t.Logf("IMPROVEMENT: scenario known to fail now passes (query=%q -> %s). Update known_status to \"pass\" in the fixture once confirmed intentional, not coincidental.",
				sc.QueryName, top)
			return
		}
		*failCount++
		t.Logf("KNOWN GAP (tracked, not failing build): query=%q expected=%s got=%s. %s",
			sc.QueryName, expected, top, sc.Rationale)
	default:
		t.Fatalf("scenario %s has unrecognized known_status %q - every match-type or clear-type scenario must be pass or fail", sc.ScenarioID, sc.KnownStatus)
	}
}
