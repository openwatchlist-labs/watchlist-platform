package matcherbaseline

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
)

func testProvider(t *testing.T) *Provider {
	t.Helper()
	artifact, err := os.ReadFile("../../test/golden/ofac/ofac-sdn-fixture.runtime.owpcat")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ofacruntime.Load(artifact)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("../../configs/matcher-profiles/ofac-name-baseline-r1.json")
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := LoadProfileSet(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(loaded.Payload, profiles)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func request(value string, targets ...canonical.CandidateType) matcherrequest.CandidateSearchRequest {
	return matcherrequest.CandidateSearchRequest{
		RequestID: "request-test", SemanticRole: "debtor.name",
		Query:             matcherrequest.QueryValue{OriginalValue: value, NormalizedValue: value},
		MatchRoutes:       []canonical.MatchRoute{canonical.RouteAlias, canonical.RouteNormalizedName, canonical.RouteTransliteration},
		TargetEntityTypes: targets, ThresholdProfile: "party_name_r1",
	}
}

func TestFuzzyOrganization(t *testing.T) {
	c, d, e := testProvider(t).SearchWithDiagnostics(context.Background(), request("ACME IMPORT LLC", canonical.CandidateOrganization))
	if e != nil {
		t.Fatal(e)
	}
	if len(c) != 1 || len(d) != 0 || c[0].ProviderRecordID != "ofac:sdn:1001" || c[0].ScoreBasisPoints != 9605 || c[0].Exact {
		t.Fatalf("unexpected: %+v %+v", c, d)
	}
}
func TestFuzzyIndividual(t *testing.T) {
	c, _, e := testProvider(t).SearchWithDiagnostics(context.Background(), request("JORDON EXAMPLE", canonical.CandidateIndividual))
	if e != nil {
		t.Fatal(e)
	}
	if len(c) != 1 || c[0].ProviderRecordID != "ofac:sdn:2002" || c[0].ScoreBasisPoints != 9534 {
		t.Fatalf("unexpected: %+v", c)
	}
}
func TestTransliterationFold(t *testing.T) {
	c, _, e := testProvider(t).SearchWithDiagnostics(context.Background(), request("J EXAMPLE", canonical.CandidateIndividual))
	if e != nil {
		t.Fatal(e)
	}
	if len(c) != 1 || c[0].MatchRoute != canonical.RouteAlias || c[0].ScoreBasisPoints != 10000 || c[0].Exact || c[0].Evidence.ReasonCodes[0] != "transliteration_fold_exact" {
		t.Fatalf("unexpected: %+v", c)
	}
}
func TestEntityMismatchDiagnostic(t *testing.T) {
	c, d, e := testProvider(t).SearchWithDiagnostics(context.Background(), request("EXAMPLE VESSEL", canonical.CandidateIndividual, canonical.CandidateOrganization))
	if e != nil {
		t.Fatal(e)
	}
	if len(c) != 0 || len(d) != 1 || d[0].Code != "entity_type_mismatch" || d[0].EntityType != canonical.CandidateVessel || d[0].ScoreBasisPoints != 10000 {
		t.Fatalf("unexpected: %+v %+v", c, d)
	}
}
func TestProfileTamper(t *testing.T) {
	f, err := os.Open("../../configs/matcher-profiles/ofac-name-baseline-r1.json")
	if err != nil {
		t.Fatal(err)
	}
	set, err := LoadProfileSet(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	set.Profiles[0].ThresholdBasisPoints++
	if ValidateProfileSet(set) == nil {
		t.Fatal("expected checksum failure")
	}
}

func TestProfileUnknownFieldRejected(t *testing.T) {
	input := `{"schema_version":"matcher-threshold-profile-set/v1alpha1","unexpected":true}`
	if _, err := LoadProfileSet(strings.NewReader(input)); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}
