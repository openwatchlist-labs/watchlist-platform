package matcherbaseline

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
)

type Provider struct {
	descriptor    matcherprovider.ProviderDescriptor
	profiles      ProfileSet
	exactProvider *ofacruntime.Provider
	nameEntries   []nameEntry
}

func NewProvider(payload ofacruntime.RuntimePayload, profiles ProfileSet) (*Provider, error) {
	if err := ofacruntime.ValidatePayload(payload); err != nil {
		return nil, err
	}
	if err := ValidateProfileSet(profiles); err != nil {
		return nil, err
	}
	exact, err := ofacruntime.NewProvider(payload)
	if err != nil {
		return nil, err
	}
	descriptor := payload.Provider
	descriptor.ProviderID, descriptor.ProviderVersion = ProviderID, ProviderVersion
	entries := make([]nameEntry, 0)
	for _, e := range payload.Entries {
		if isNameRoute(e.MatchRoute) {
			entries = append(entries, nameEntry{e.ProviderRecordID, e.EntityType, e.PrimaryName, e.MatchedValue, e.NormalizedMatchedValue, e.MatchRoute, cloneAttributes(e.Attributes), cloneAssertions(e.SourceAssertions)})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		l, r := entries[i], entries[j]
		if l.ProviderRecordID != r.ProviderRecordID {
			return l.ProviderRecordID < r.ProviderRecordID
		}
		if l.MatchRoute != r.MatchRoute {
			return l.MatchRoute < r.MatchRoute
		}
		return l.NormalizedMatchedValue < r.NormalizedMatchedValue
	})
	return &Provider{descriptor: descriptor, profiles: profiles, exactProvider: exact, nameEntries: entries}, nil
}
func (p *Provider) Descriptor() matcherprovider.ProviderDescriptor { return p.descriptor }
func (p *Provider) Search(ctx context.Context, r matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, error) {
	c, _, e := p.SearchWithDiagnostics(ctx, r)
	return c, e
}

func (p *Provider) SearchWithDiagnostics(ctx context.Context, request matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, []matcherprovider.CandidateDiagnostic, error) {
	var candidates []matcherprovider.ProviderCandidate
	var diagnostics []matcherprovider.CandidateDiagnostic
	var nonName []canonical.MatchRoute
	for _, r := range request.MatchRoutes {
		if !isNameRoute(r) {
			nonName = append(nonName, r)
		}
	}
	if len(nonName) > 0 {
		q := request
		q.MatchRoutes = nonName
		exact, err := p.exactProvider.Search(ctx, q)
		if err != nil {
			return nil, nil, err
		}
		candidates = append(candidates, exact...)
	}
	if !hasNameRoute(request.MatchRoutes) {
		return candidates, nil, nil
	}
	profile, ok := p.profiles.Profile(request.ThresholdProfile)
	if !ok {
		return nil, nil, fmt.Errorf("matcher profile %q is not defined in profile set %q", request.ThresholdProfile, p.profiles.ProfileSetID)
	}
	query := fold(request.Query.NormalizedValue)
	if query == "" {
		return candidates, nil, nil
	}
	best := map[string]matcherprovider.ProviderCandidate{}
	diag := map[string]matcherprovider.CandidateDiagnostic{}
	for _, entry := range p.nameEntries {
		if !containsRoute(request.MatchRoutes, entry.MatchRoute) {
			continue
		}
		candFold := fold(entry.NormalizedMatchedValue)
		if candFold == "" {
			continue
		}
		rawExact := strings.EqualFold(strings.TrimSpace(request.Query.NormalizedValue), strings.TrimSpace(entry.NormalizedMatchedValue))
		foldExact := query == candFold
		score, features, penalty := scoreName(query, candFold, profile)
		if strings.EqualFold(entry.Attributes["alias_strength"], "weak") {
			penalty += profile.WeakAliasPenaltyBasisPoints
			score -= profile.WeakAliasPenaltyBasisPoints
			if score < 0 {
				score = 0
			}
		}
		evidence := buildEvidence(p.profiles, profile, reasonCodes(entry.MatchRoute, rawExact, foldExact, features), features, penalty)
		if score < profile.DiagnosticFloorBasisPoints {
			continue
		}
		if !containsType(request.TargetEntityTypes, entry.EntityType) {
			if score < profile.ThresholdBasisPoints {
				continue
			}
			d := matcherprovider.CandidateDiagnostic{SchemaVersion: matcherprovider.CandidateDiagnosticSchemaVersion, Code: "entity_type_mismatch", ProviderRecordID: entry.ProviderRecordID, EntityType: entry.EntityType, PrimaryName: entry.PrimaryName, MatchedValue: entry.MatchedValue, MatchRoute: entry.MatchRoute, ScoreBasisPoints: score, ThresholdBasisPoints: profile.ThresholdBasisPoints, Detail: fmt.Sprintf("strong name match suppressed: catalog entity type %q is not allowed for semantic role %q", entry.EntityType, request.SemanticRole), Evidence: evidence, SourceAssertions: cloneAssertions(entry.SourceAssertions)}
			if cur, ok := diag[entry.ProviderRecordID]; !ok || betterDiagnostic(d, cur) {
				diag[entry.ProviderRecordID] = d
			}
			continue
		}
		if score < profile.ThresholdBasisPoints {
			continue
		}
		attrs := cloneAttributes(entry.Attributes)
		attrs["matcher_profile_set_id"] = p.profiles.ProfileSetID
		attrs["matcher_threshold_profile"] = profile.ProfileID
		c := matcherprovider.ProviderCandidate{ProviderRecordID: entry.ProviderRecordID, EntityType: entry.EntityType, PrimaryName: entry.PrimaryName, MatchedValue: entry.MatchedValue, NormalizedMatchedValue: entry.NormalizedMatchedValue, MatchRoute: entry.MatchRoute, ScoreBasisPoints: score, Exact: rawExact, Attributes: attrs, Evidence: evidence, SourceAssertions: cloneAssertions(entry.SourceAssertions)}
		if cur, ok := best[entry.ProviderRecordID]; !ok || betterCandidate(c, cur) {
			best[entry.ProviderRecordID] = c
		}
	}
	for _, c := range best {
		candidates = append(candidates, c)
	}
	for _, d := range diag {
		diagnostics = append(diagnostics, d)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].ProviderRecordID != candidates[j].ProviderRecordID {
			return candidates[i].ProviderRecordID < candidates[j].ProviderRecordID
		}
		return candidates[i].MatchRoute < candidates[j].MatchRoute
	})
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].ScoreBasisPoints != diagnostics[j].ScoreBasisPoints {
			return diagnostics[i].ScoreBasisPoints > diagnostics[j].ScoreBasisPoints
		}
		return diagnostics[i].ProviderRecordID < diagnostics[j].ProviderRecordID
	})
	return candidates, diagnostics, nil
}

func buildEvidence(set ProfileSet, p ThresholdProfile, reasons []string, features []featureScore, penalty int) *matcherprovider.MatchEvidence {
	out := &matcherprovider.MatchEvidence{SchemaVersion: matcherprovider.MatchEvidenceSchemaVersion, MatcherVersion: MatcherVersion, ProfileSetID: set.ProfileSetID, ProfileSetChecksum: set.ProfileSetChecksum, ThresholdProfile: p.ProfileID, ThresholdBasisPoints: p.ThresholdBasisPoints, ReasonCodes: append([]string(nil), reasons...), PenaltyBasisPoints: penalty}
	for _, f := range features {
		out.Features = append(out.Features, matcherprovider.FeatureEvidence{Name: f.name, ScoreBasisPoints: f.score, WeightBasisPoints: f.weight, ContributionBasisPoints: f.contribution})
	}
	return out
}
func reasonCodes(route canonical.MatchRoute, rawExact, foldExact bool, features []featureScore) []string {
	var c []string
	switch {
	case rawExact && route == canonical.RouteNormalizedName:
		c = []string{"primary_name_exact"}
	case rawExact && route == canonical.RouteAlias:
		c = []string{"alias_exact"}
	case rawExact && route == canonical.RouteTransliteration:
		c = []string{"transliteration_exact"}
	case foldExact:
		c = []string{"transliteration_fold_exact"}
	default:
		c = []string{"name_fuzzy_edit", "name_fuzzy_token_alignment"}
		for _, f := range features {
			if f.name == "phonetic_similarity" && f.score >= 8000 {
				c = append(c, "name_fuzzy_phonetic")
			}
		}
	}
	sort.Strings(c)
	return c
}
func betterCandidate(l, r matcherprovider.ProviderCandidate) bool {
	if l.ScoreBasisPoints != r.ScoreBasisPoints {
		return l.ScoreBasisPoints > r.ScoreBasisPoints
	}
	if l.Exact != r.Exact {
		return l.Exact
	}
	if l.MatchRoute != r.MatchRoute {
		return l.MatchRoute < r.MatchRoute
	}
	return l.MatchedValue < r.MatchedValue
}
func betterDiagnostic(l, r matcherprovider.CandidateDiagnostic) bool {
	if l.ScoreBasisPoints != r.ScoreBasisPoints {
		return l.ScoreBasisPoints > r.ScoreBasisPoints
	}
	if l.MatchRoute != r.MatchRoute {
		return l.MatchRoute < r.MatchRoute
	}
	return l.MatchedValue < r.MatchedValue
}
func hasNameRoute(v []canonical.MatchRoute) bool {
	for _, r := range v {
		if isNameRoute(r) {
			return true
		}
	}
	return false
}
func isNameRoute(r canonical.MatchRoute) bool {
	return r == canonical.RouteNormalizedName || r == canonical.RouteAlias || r == canonical.RouteTransliteration
}
func containsRoute(v []canonical.MatchRoute, t canonical.MatchRoute) bool {
	for _, x := range v {
		if x == t {
			return true
		}
	}
	return false
}
func containsType(v []canonical.CandidateType, t canonical.CandidateType) bool {
	for _, x := range v {
		if x == t {
			return true
		}
	}
	return false
}
func cloneAttributes(v map[string]string) map[string]string {
	o := map[string]string{}
	for k, x := range v {
		o[k] = x
	}
	return o
}
func cloneAssertions(v []matcherprovider.SourceAssertion) []matcherprovider.SourceAssertion {
	o := append([]matcherprovider.SourceAssertion(nil), v...)
	for i := range o {
		o[i].Programs = append([]string(nil), o[i].Programs...)
		sort.Strings(o[i].Programs)
	}
	sort.Slice(o, func(i, j int) bool {
		if o[i].SourceID != o[j].SourceID {
			return o[i].SourceID < o[j].SourceID
		}
		if o[i].ListID != o[j].ListID {
			return o[i].ListID < o[j].ListID
		}
		return o[i].SourceRecordID < o[j].SourceRecordID
	})
	return o
}
