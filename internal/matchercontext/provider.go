package matchercontext

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherbaseline"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
)

type Provider struct {
	descriptor       matcherprovider.ProviderDescriptor
	baseline         *matcherbaseline.Provider
	profiles         ProfileSet
	policy           JurisdictionPolicySet
	policyByAlias    map[string]JurisdictionEntry
	narrativeEntries []narrativeEntry
}

func NewProvider(payload ofacruntime.RuntimePayload, nameProfiles matcherbaseline.ProfileSet, contextProfiles ProfileSet, policy JurisdictionPolicySet) (*Provider, error) {
	if err := ofacruntime.ValidatePayload(payload); err != nil {
		return nil, err
	}
	if err := matcherbaseline.ValidateProfileSet(nameProfiles); err != nil {
		return nil, err
	}
	if err := ValidateProfileSet(contextProfiles); err != nil {
		return nil, err
	}
	if err := ValidatePolicySet(policy); err != nil {
		return nil, err
	}
	baseline, err := matcherbaseline.NewProvider(payload, nameProfiles)
	if err != nil {
		return nil, err
	}
	descriptor := baseline.Descriptor()
	descriptor.ProviderID = ProviderID
	descriptor.ProviderVersion = ProviderVersion
	entries := buildNarrativeEntries(payload)
	policyByAlias := make(map[string]JurisdictionEntry)
	for _, entry := range policy.Entries {
		for _, alias := range append([]string{entry.CountryCodeAlpha2, entry.CountryCodeAlpha3, entry.CountryName}, entry.Aliases...) {
			if alias != "" {
				policyByAlias[alias] = entry
			}
		}
	}
	return &Provider{descriptor: descriptor, baseline: baseline, profiles: contextProfiles, policy: policy, policyByAlias: policyByAlias, narrativeEntries: entries}, nil
}

func (p *Provider) Descriptor() matcherprovider.ProviderDescriptor { return p.descriptor }

func (p *Provider) Search(ctx context.Context, request matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, error) {
	candidates, _, err := p.SearchWithDiagnostics(ctx, request)
	return candidates, err
}

func (p *Provider) SearchWithDiagnostics(ctx context.Context, request matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, []matcherprovider.CandidateDiagnostic, error) {
	baseRoutes := make([]canonical.MatchRoute, 0, len(request.MatchRoutes))
	for _, route := range request.MatchRoutes {
		if route != canonical.RouteJurisdictionPolicy && route != canonical.RouteContextualPhrase {
			baseRoutes = append(baseRoutes, route)
		}
	}
	var candidates []matcherprovider.ProviderCandidate
	var diagnostics []matcherprovider.CandidateDiagnostic
	if len(baseRoutes) > 0 {
		baseRequest := request
		baseRequest.MatchRoutes = baseRoutes
		baseCandidates, baseDiagnostics, err := p.baseline.SearchWithDiagnostics(ctx, baseRequest)
		if err != nil {
			return nil, nil, err
		}
		candidates = append(candidates, baseCandidates...)
		diagnostics = append(diagnostics, baseDiagnostics...)
	}
	if containsRoute(request.MatchRoutes, canonical.RouteJurisdictionPolicy) {
		jurisdiction, err := p.searchJurisdiction(request)
		if err != nil {
			return nil, nil, err
		}
		candidates = append(candidates, jurisdiction...)
	}
	if containsRoute(request.MatchRoutes, canonical.RouteContextualPhrase) {
		contextCandidates, contextDiagnostics, err := p.searchNarrative(request)
		if err != nil {
			return nil, nil, err
		}
		candidates = append(candidates, contextCandidates...)
		diagnostics = append(diagnostics, contextDiagnostics...)
	}
	candidates = bestCandidates(candidates)
	diagnostics = bestDiagnostics(diagnostics)
	return candidates, diagnostics, nil
}

func (p *Provider) searchJurisdiction(request matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, error) {
	profile, ok := p.profiles.Profile(request.ThresholdProfile, ContextKindJurisdiction)
	if !ok {
		return nil, fmt.Errorf("context profile %q is not defined as jurisdiction in profile set %q", request.ThresholdProfile, p.profiles.ProfileSetID)
	}
	query := fold(request.Query.NormalizedValue)
	entry, ok := p.policyByAlias[query]
	if !ok || !containsType(request.TargetEntityTypes, canonical.CandidateJurisdiction) {
		return nil, nil
	}
	matchKind := "alias"
	switch query {
	case entry.CountryCodeAlpha2:
		matchKind = "alpha2"
	case entry.CountryCodeAlpha3:
		matchKind = "alpha3"
	case entry.CountryName:
		matchKind = "country_name"
	}
	features := scoreFeatures(profile, map[string]int{"country_equivalence": 10000, "policy_status": 10000})
	evidence := &matcherprovider.MatchEvidence{
		SchemaVersion: matcherprovider.MatchEvidenceSchemaVersion, MatcherVersion: MatcherVersion,
		ProfileSetID: p.profiles.ProfileSetID, ProfileSetChecksum: p.profiles.ProfileSetChecksum,
		ThresholdProfile: profile.ProfileID, ThresholdBasisPoints: profile.ThresholdBasisPoints,
		ReasonCodes: []string{"jurisdiction_" + matchKind + "_exact", "jurisdiction_policy_restricted"}, Features: features,
		Context: &matcherprovider.ContextEvidence{
			SchemaVersion: matcherprovider.ContextEvidenceSchemaVersion,
			QueryTokens:   tokens(query), MatchedTokens: tokens(query),
			Policy: &matcherprovider.PolicyContext{PolicySetID: p.policy.PolicySetID, PolicySetChecksum: p.policy.PolicySetChecksum, PolicyEntryID: entry.EntryID, CountryCodeAlpha2: entry.CountryCodeAlpha2, CountryCodeAlpha3: entry.CountryCodeAlpha3, CountryName: entry.CountryName},
		},
	}
	sort.Strings(evidence.ReasonCodes)
	attributes := map[string]string{
		"context_profile_set_id":           p.profiles.ProfileSetID,
		"context_profile_set_checksum":     p.profiles.ProfileSetChecksum,
		"jurisdiction_policy_set_id":       p.policy.PolicySetID,
		"jurisdiction_policy_set_checksum": p.policy.PolicySetChecksum,
		"jurisdiction_policy_entry_id":     entry.EntryID,
		"jurisdiction_match_kind":          matchKind,
	}
	assertion := matcherprovider.SourceAssertion{SourceID: p.policy.Source.SourceID, Authority: p.policy.Source.Authority, ListID: p.policy.Source.ListID, SourceRecordID: entry.EntryID, Programs: append([]string(nil), entry.Programs...)}
	return []matcherprovider.ProviderCandidate{{
		ProviderRecordID: "jurisdiction-policy:" + entry.EntryID, EntityType: canonical.CandidateJurisdiction,
		PrimaryName: entry.CountryName, MatchedValue: query, NormalizedMatchedValue: query,
		MatchRoute: canonical.RouteJurisdictionPolicy, ScoreBasisPoints: featureTotal(features), Exact: true,
		Attributes: attributes, Evidence: evidence, SourceAssertions: []matcherprovider.SourceAssertion{assertion},
	}}, nil
}

func (p *Provider) searchNarrative(request matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, []matcherprovider.CandidateDiagnostic, error) {
	profile, ok := p.profiles.Profile(request.ThresholdProfile, ContextKindNarrative)
	if !ok {
		return nil, nil, fmt.Errorf("context profile %q is not defined as narrative in profile set %q", request.ThresholdProfile, p.profiles.ProfileSetID)
	}
	queryTokens := tokens(request.Query.NormalizedValue)
	if len(queryTokens) == 0 {
		return nil, nil, nil
	}
	var candidates []matcherprovider.ProviderCandidate
	var diagnostics []matcherprovider.CandidateDiagnostic
	for _, entry := range p.narrativeEntries {
		matchedTokens := tokens(entry.MatchedValue)
		span, contiguous, ok := findPhraseWindow(queryTokens, matchedTokens, profile.MaxWindowExtraTokens, profile.MinSingleTokenLength)
		if !ok {
			continue
		}
		phraseScore := profile.OrderedWindowScoreBasisPoints
		if contiguous {
			phraseScore = 10000
		}
		windowLength := span.end - span.start
		compactness := len(matchedTokens) * 10000 / windowLength
		sourceQuality := sourceQuality(entry)
		features := scoreFeatures(profile, map[string]int{"boundary_phrase_match": phraseScore, "source_quality": sourceQuality, "window_compactness": compactness})
		penalty := 0
		if strings.EqualFold(entry.AliasStrength, "weak") {
			penalty += profile.WeakAliasPenaltyBasisPoints
		}
		markers := denialMarkers(queryTokens, span.start, span.end, profile)
		if len(markers) > 0 {
			penalty += profile.DenialPenaltyBasisPoints
		}
		score := featureTotal(features) - penalty
		if score < 0 {
			score = 0
		}
		reasons := narrativeReasons(entry, contiguous, markers)
		windowText := strings.Join(queryTokens[span.start:span.end], " ")
		evidence := &matcherprovider.MatchEvidence{
			SchemaVersion: matcherprovider.MatchEvidenceSchemaVersion, MatcherVersion: MatcherVersion,
			ProfileSetID: p.profiles.ProfileSetID, ProfileSetChecksum: p.profiles.ProfileSetChecksum,
			ThresholdProfile: profile.ProfileID, ThresholdBasisPoints: profile.ThresholdBasisPoints,
			ReasonCodes: reasons, Features: features, PenaltyBasisPoints: penalty,
			Context: &matcherprovider.ContextEvidence{SchemaVersion: matcherprovider.ContextEvidenceSchemaVersion, QueryTokens: append([]string(nil), queryTokens...), MatchedTokens: append([]string(nil), matchedTokens...), Window: &matcherprovider.TokenWindow{Start: span.start, End: span.end, Text: windowText}, NegationMarkers: markers},
		}
		if score < profile.DiagnosticFloorBasisPoints {
			continue
		}
		if !containsType(request.TargetEntityTypes, entry.EntityType) {
			if score >= profile.ThresholdBasisPoints {
				diagnostics = append(diagnostics, matcherprovider.CandidateDiagnostic{SchemaVersion: matcherprovider.CandidateDiagnosticSchemaVersion, Code: "entity_type_mismatch", ProviderRecordID: entry.ProviderRecordID, EntityType: entry.EntityType, PrimaryName: entry.PrimaryName, MatchedValue: entry.MatchedValue, MatchRoute: canonical.RouteContextualPhrase, ScoreBasisPoints: score, ThresholdBasisPoints: profile.ThresholdBasisPoints, Detail: fmt.Sprintf("narrative phrase match suppressed: catalog entity type %q is not allowed for semantic role %q", entry.EntityType, request.SemanticRole), Evidence: evidence, SourceAssertions: cloneAssertions(entry.SourceAssertions)})
			}
			continue
		}
		if len(markers) > 0 {
			diagnostics = append(diagnostics, matcherprovider.CandidateDiagnostic{SchemaVersion: matcherprovider.CandidateDiagnosticSchemaVersion, Code: "narrative_denial_context", ProviderRecordID: entry.ProviderRecordID, EntityType: entry.EntityType, PrimaryName: entry.PrimaryName, MatchedValue: entry.MatchedValue, MatchRoute: canonical.RouteContextualPhrase, ScoreBasisPoints: score, ThresholdBasisPoints: profile.ThresholdBasisPoints, Detail: fmt.Sprintf("sanctions phrase appears within denial context markers %q", strings.Join(markers, ", ")), Evidence: evidence, SourceAssertions: cloneAssertions(entry.SourceAssertions)})
			continue
		}
		if score < profile.ThresholdBasisPoints {
			continue
		}
		attrs := map[string]string{"context_profile_set_id": p.profiles.ProfileSetID, "context_profile_set_checksum": p.profiles.ProfileSetChecksum, "context_source_route": string(entry.SourceRoute)}
		if entry.AliasStrength != "" {
			attrs["alias_strength"] = entry.AliasStrength
		}
		candidates = append(candidates, matcherprovider.ProviderCandidate{ProviderRecordID: entry.ProviderRecordID, EntityType: entry.EntityType, PrimaryName: entry.PrimaryName, MatchedValue: entry.MatchedValue, NormalizedMatchedValue: fold(entry.MatchedValue), MatchRoute: canonical.RouteContextualPhrase, ScoreBasisPoints: score, Exact: span.start == 0 && span.end == len(queryTokens), Attributes: attrs, Evidence: evidence, SourceAssertions: cloneAssertions(entry.SourceAssertions)})
	}
	for _, policyEntry := range p.policy.Entries {
		for _, phrase := range append([]string{policyEntry.CountryName, policyEntry.CountryCodeAlpha2, policyEntry.CountryCodeAlpha3}, policyEntry.Aliases...) {
			if phrase == "" {
				continue
			}
			matchedTokens := tokens(phrase)
			span, contiguous, ok := findPhraseWindow(queryTokens, matchedTokens, profile.MaxWindowExtraTokens, 1)
			if !ok {
				continue
			}
			phraseScore := profile.OrderedWindowScoreBasisPoints
			if contiguous {
				phraseScore = 10000
			}
			features := scoreFeatures(profile, map[string]int{"boundary_phrase_match": phraseScore, "source_quality": 10000, "window_compactness": len(matchedTokens) * 10000 / (span.end - span.start)})
			markers := denialMarkers(queryTokens, span.start, span.end, profile)
			penalty := 0
			if len(markers) > 0 {
				penalty = profile.DenialPenaltyBasisPoints
			}
			score := featureTotal(features) - penalty
			if score < profile.DiagnosticFloorBasisPoints || !containsType(request.TargetEntityTypes, canonical.CandidateJurisdiction) {
				continue
			}
			reasons := []string{"jurisdiction_phrase_context", "narrative_phrase_exact"}
			if !contiguous {
				reasons[1] = "narrative_ordered_window"
			}
			if len(markers) > 0 {
				reasons = append(reasons, "narrative_denial_context")
			}
			sort.Strings(reasons)
			evidence := &matcherprovider.MatchEvidence{SchemaVersion: matcherprovider.MatchEvidenceSchemaVersion, MatcherVersion: MatcherVersion, ProfileSetID: p.profiles.ProfileSetID, ProfileSetChecksum: p.profiles.ProfileSetChecksum, ThresholdProfile: profile.ProfileID, ThresholdBasisPoints: profile.ThresholdBasisPoints, ReasonCodes: reasons, Features: features, PenaltyBasisPoints: penalty, Context: &matcherprovider.ContextEvidence{SchemaVersion: matcherprovider.ContextEvidenceSchemaVersion, QueryTokens: append([]string(nil), queryTokens...), MatchedTokens: matchedTokens, Window: &matcherprovider.TokenWindow{Start: span.start, End: span.end, Text: strings.Join(queryTokens[span.start:span.end], " ")}, NegationMarkers: markers, Policy: &matcherprovider.PolicyContext{PolicySetID: p.policy.PolicySetID, PolicySetChecksum: p.policy.PolicySetChecksum, PolicyEntryID: policyEntry.EntryID, CountryCodeAlpha2: policyEntry.CountryCodeAlpha2, CountryCodeAlpha3: policyEntry.CountryCodeAlpha3, CountryName: policyEntry.CountryName}}}
			assertion := matcherprovider.SourceAssertion{SourceID: p.policy.Source.SourceID, Authority: p.policy.Source.Authority, ListID: p.policy.Source.ListID, SourceRecordID: policyEntry.EntryID, Programs: append([]string(nil), policyEntry.Programs...)}
			if len(markers) > 0 {
				diagnostics = append(diagnostics, matcherprovider.CandidateDiagnostic{SchemaVersion: matcherprovider.CandidateDiagnosticSchemaVersion, Code: "narrative_denial_context", ProviderRecordID: "jurisdiction-policy:" + policyEntry.EntryID, EntityType: canonical.CandidateJurisdiction, PrimaryName: policyEntry.CountryName, MatchedValue: phrase, MatchRoute: canonical.RouteContextualPhrase, ScoreBasisPoints: score, ThresholdBasisPoints: profile.ThresholdBasisPoints, Detail: fmt.Sprintf("jurisdiction phrase appears within denial context markers %q", strings.Join(markers, ", ")), Evidence: evidence, SourceAssertions: []matcherprovider.SourceAssertion{assertion}})
			} else if score >= profile.ThresholdBasisPoints {
				candidates = append(candidates, matcherprovider.ProviderCandidate{ProviderRecordID: "jurisdiction-policy:" + policyEntry.EntryID, EntityType: canonical.CandidateJurisdiction, PrimaryName: policyEntry.CountryName, MatchedValue: phrase, NormalizedMatchedValue: fold(phrase), MatchRoute: canonical.RouteContextualPhrase, ScoreBasisPoints: score, Exact: span.start == 0 && span.end == len(queryTokens), Attributes: map[string]string{"context_profile_set_id": p.profiles.ProfileSetID, "context_profile_set_checksum": p.profiles.ProfileSetChecksum, "jurisdiction_policy_set_id": p.policy.PolicySetID, "jurisdiction_policy_set_checksum": p.policy.PolicySetChecksum, "jurisdiction_policy_entry_id": policyEntry.EntryID}, Evidence: evidence, SourceAssertions: []matcherprovider.SourceAssertion{assertion}})
			}
			break
		}
	}
	return candidates, diagnostics, nil
}

type tokenSpan struct{ start, end int }

func findPhraseWindow(query, matched []string, maxExtra, minSingleLength int) (tokenSpan, bool, bool) {
	if len(query) == 0 || len(matched) == 0 {
		return tokenSpan{}, false, false
	}
	if len(matched) == 1 && len([]rune(matched[0])) < minSingleLength {
		return tokenSpan{}, false, false
	}
	for start := 0; start+len(matched) <= len(query); start++ {
		ok := true
		for index := range matched {
			if query[start+index] != matched[index] {
				ok = false
				break
			}
		}
		if ok {
			return tokenSpan{start: start, end: start + len(matched)}, true, true
		}
	}
	for start := 0; start < len(query); start++ {
		if query[start] != matched[0] {
			continue
		}
		position := start + 1
		matchedIndex := 1
		limit := start + len(matched) + maxExtra
		if limit > len(query) {
			limit = len(query)
		}
		for position < limit && matchedIndex < len(matched) {
			if query[position] == matched[matchedIndex] {
				matchedIndex++
			}
			position++
		}
		if matchedIndex == len(matched) {
			return tokenSpan{start: start, end: position}, false, true
		}
	}
	return tokenSpan{}, false, false
}

func denialMarkers(query []string, start, end int, profile ContextProfile) []string {
	left := start - profile.DenialWindowTokens
	if left < 0 {
		left = 0
	}
	right := end + profile.DenialWindowTokens
	if right > len(query) {
		right = len(query)
	}
	context := query[left:right]
	var found []string
	for _, marker := range profile.DenialMarkers {
		markerTokens := tokens(marker)
		for index := 0; index+len(markerTokens) <= len(context); index++ {
			match := true
			for markerIndex := range markerTokens {
				if context[index+markerIndex] != markerTokens[markerIndex] {
					match = false
					break
				}
			}
			if match {
				found = append(found, marker)
				break
			}
		}
	}
	sort.Strings(found)
	return found
}

func narrativeReasons(entry narrativeEntry, contiguous bool, markers []string) []string {
	reasons := []string{"narrative_ordered_window"}
	if contiguous {
		reasons[0] = "narrative_phrase_exact"
	}
	switch entry.SourceRoute {
	case canonical.RouteNormalizedName:
		reasons = append(reasons, "primary_name_context")
	case canonical.RouteAlias:
		reasons = append(reasons, "alias_context")
	case canonical.RouteTransliteration:
		reasons = append(reasons, "transliteration_context")
	}
	if len(markers) > 0 {
		reasons = append(reasons, "narrative_denial_context")
	}
	sort.Strings(reasons)
	return reasons
}

func sourceQuality(entry narrativeEntry) int {
	switch entry.SourceRoute {
	case canonical.RouteNormalizedName:
		return 10000
	case canonical.RouteAlias:
		if strings.EqualFold(entry.AliasStrength, "weak") {
			return 8000
		}
		return 9500
	case canonical.RouteTransliteration:
		return 9000
	default:
		return 8500
	}
}

func scoreFeatures(profile ContextProfile, values map[string]int) []matcherprovider.FeatureEvidence {
	features := make([]matcherprovider.FeatureEvidence, 0, len(profile.FeatureWeights))
	for _, configured := range profile.FeatureWeights {
		score := values[configured.Name]
		features = append(features, matcherprovider.FeatureEvidence{Name: configured.Name, ScoreBasisPoints: score, WeightBasisPoints: configured.WeightBasisPoints, ContributionBasisPoints: score * configured.WeightBasisPoints / 10000})
	}
	return features
}

func featureTotal(features []matcherprovider.FeatureEvidence) int {
	total := 0
	for _, feature := range features {
		total += feature.ContributionBasisPoints
	}
	return total
}

func buildNarrativeEntries(payload ofacruntime.RuntimePayload) []narrativeEntry {
	seen := map[string]struct{}{}
	var entries []narrativeEntry
	for _, entry := range payload.Entries {
		if entry.MatchRoute != canonical.RouteNormalizedName && entry.MatchRoute != canonical.RouteAlias && entry.MatchRoute != canonical.RouteTransliteration {
			continue
		}
		key := entry.ProviderRecordID + "\x1f" + string(entry.MatchRoute) + "\x1f" + fold(entry.MatchedValue)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, narrativeEntry{ProviderRecordID: entry.ProviderRecordID, EntityType: entry.EntityType, PrimaryName: entry.PrimaryName, MatchedValue: entry.MatchedValue, SourceRoute: entry.MatchRoute, AliasStrength: entry.Attributes["alias_strength"], SourceAssertions: cloneAssertions(entry.SourceAssertions)})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ProviderRecordID != entries[j].ProviderRecordID {
			return entries[i].ProviderRecordID < entries[j].ProviderRecordID
		}
		if entries[i].SourceRoute != entries[j].SourceRoute {
			return entries[i].SourceRoute < entries[j].SourceRoute
		}
		return fold(entries[i].MatchedValue) < fold(entries[j].MatchedValue)
	})
	return entries
}

func bestCandidates(values []matcherprovider.ProviderCandidate) []matcherprovider.ProviderCandidate {
	best := map[string]matcherprovider.ProviderCandidate{}
	for _, candidate := range values {
		key := candidate.ProviderRecordID + "\x1f" + string(candidate.MatchRoute)
		current, exists := best[key]
		if !exists || candidate.ScoreBasisPoints > current.ScoreBasisPoints || (candidate.ScoreBasisPoints == current.ScoreBasisPoints && candidate.MatchedValue < current.MatchedValue) {
			best[key] = candidate
		}
	}
	out := make([]matcherprovider.ProviderCandidate, 0, len(best))
	for _, candidate := range best {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProviderRecordID != out[j].ProviderRecordID {
			return out[i].ProviderRecordID < out[j].ProviderRecordID
		}
		return out[i].MatchRoute < out[j].MatchRoute
	})
	return out
}

func bestDiagnostics(values []matcherprovider.CandidateDiagnostic) []matcherprovider.CandidateDiagnostic {
	best := map[string]matcherprovider.CandidateDiagnostic{}
	for _, diagnostic := range values {
		key := diagnostic.Code + "\x1f" + diagnostic.ProviderRecordID + "\x1f" + string(diagnostic.MatchRoute)
		current, exists := best[key]
		if !exists || diagnostic.ScoreBasisPoints > current.ScoreBasisPoints {
			best[key] = diagnostic
		}
	}
	out := make([]matcherprovider.CandidateDiagnostic, 0, len(best))
	for _, diagnostic := range best {
		out = append(out, diagnostic)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScoreBasisPoints != out[j].ScoreBasisPoints {
			return out[i].ScoreBasisPoints > out[j].ScoreBasisPoints
		}
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		if out[i].ProviderRecordID != out[j].ProviderRecordID {
			return out[i].ProviderRecordID < out[j].ProviderRecordID
		}
		return out[i].MatchRoute < out[j].MatchRoute
	})
	return out
}

func containsRoute(values []canonical.MatchRoute, target canonical.MatchRoute) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsType(values []canonical.CandidateType, target canonical.CandidateType) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func cloneAssertions(values []matcherprovider.SourceAssertion) []matcherprovider.SourceAssertion {
	out := append([]matcherprovider.SourceAssertion(nil), values...)
	for index := range out {
		out[index].Programs = append([]string(nil), out[index].Programs...)
		sort.Strings(out[index].Programs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceID != out[j].SourceID {
			return out[i].SourceID < out[j].SourceID
		}
		if out[i].ListID != out[j].ListID {
			return out[i].ListID < out[j].ListID
		}
		return out[i].SourceRecordID < out[j].SourceRecordID
	})
	return out
}
