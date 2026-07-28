package providerentity

import (
	"context"
	"sort"

	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

type HybridProvider struct {
	descriptor matcherprovider.ProviderDescriptor
	base       *Provider
	overlay    *ofaccatalog.Provider
	hybrid     HybridCatalog
}

func NewHybridProvider(baseCatalog Catalog, overlayCatalog ofaccatalog.Catalog) (*HybridProvider, HybridCatalog, error) {
	base, err := NewProvider(baseCatalog)
	if err != nil {
		return nil, HybridCatalog{}, err
	}
	overlay, err := ofaccatalog.NewProvider(overlayCatalog)
	if err != nil {
		return nil, HybridCatalog{}, err
	}
	hybrid, err := BuildHybridCatalog(baseCatalog, overlay.Descriptor().Catalog)
	if err != nil {
		return nil, HybridCatalog{}, err
	}
	descriptor := matcherprovider.ProviderDescriptor{
		SchemaVersion:   matcherprovider.ProviderDescriptorSchemaVersion,
		ProviderID:      HybridProviderID,
		ProviderVersion: HybridProviderVersion,
		Catalog: matcherprovider.CatalogReference{
			CatalogID: hybrid.CatalogID, CatalogVersion: hybrid.CatalogVersion,
			CatalogChecksum: hybrid.CatalogChecksum, CatalogMode: matcherprovider.CatalogModeHybridOverlay,
		},
		Capabilities: defaultCapabilities(),
	}
	if err := matcherprovider.ValidateDescriptor(descriptor); err != nil {
		return nil, HybridCatalog{}, err
	}
	return &HybridProvider{descriptor: descriptor, base: base, overlay: overlay, hybrid: hybrid}, hybrid, nil
}

func (p *HybridProvider) Descriptor() matcherprovider.ProviderDescriptor { return p.descriptor }

func (p *HybridProvider) Search(ctx context.Context, request matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, error) {
	baseCandidates, err := p.base.Search(ctx, request)
	if err != nil {
		return nil, err
	}
	overlayCandidates, err := p.overlay.Search(ctx, request)
	if err != nil {
		return nil, err
	}
	byEntity := map[string]matcherprovider.ProviderCandidate{}
	var unlinked []matcherprovider.ProviderCandidate
	for _, candidate := range baseCandidates {
		candidate.Attributes = cloneAttributes(candidate.Attributes)
		candidate.Attributes["hybrid_origin"] = "provider_entity"
		byEntity[candidate.ProviderEntityID] = candidate
	}
	for _, candidate := range overlayCandidates {
		entity, linked := entityForAssertions(p.base, candidate.SourceAssertions)
		if !linked {
			candidate.Attributes = cloneAttributes(candidate.Attributes)
			candidate.Attributes["hybrid_origin"] = "official_overlay_unlinked"
			unlinked = append(unlinked, candidate)
			continue
		}
		linkedCandidate := matcherprovider.ProviderCandidate{
			ProviderRecordID: entity.ProviderRecordID, ProviderEntityID: entity.ProviderEntityID,
			EntityType: entity.EntityType, PrimaryName: entity.PrimaryName,
			MatchedValue: candidate.MatchedValue, NormalizedMatchedValue: candidate.NormalizedMatchedValue,
			MatchRoute: candidate.MatchRoute, ScoreBasisPoints: candidate.ScoreBasisPoints,
			Exact: candidate.Exact, Attributes: cloneAttributes(candidate.Attributes),
			SourceAssertions: mergeAssertions(assertions(entity.SourceMemberships), candidate.SourceAssertions),
		}
		linkedCandidate.Attributes["hybrid_origin"] = "official_overlay_linked"
		linkedCandidate.Attributes["provider_entity_id"] = entity.ProviderEntityID
		linkedCandidate.Attributes["overlay_provider_record_id"] = candidate.ProviderRecordID
		if existing, ok := byEntity[entity.ProviderEntityID]; ok {
			winner := existing
			if betterCandidate(linkedCandidate, existing) {
				winner = linkedCandidate
			}
			winner.SourceAssertions = mergeAssertions(existing.SourceAssertions, linkedCandidate.SourceAssertions)
			winner.Attributes = mergeAttributes(existing.Attributes, linkedCandidate.Attributes)
			winner.Attributes["hybrid_origin"] = "provider_plus_official_overlay"
			byEntity[entity.ProviderEntityID] = winner
		} else {
			byEntity[entity.ProviderEntityID] = linkedCandidate
		}
	}
	out := make([]matcherprovider.ProviderCandidate, 0, len(byEntity)+len(unlinked))
	for _, candidate := range byEntity {
		out = append(out, candidate)
	}
	out = append(out, unlinked...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProviderRecordID != out[j].ProviderRecordID {
			return out[i].ProviderRecordID < out[j].ProviderRecordID
		}
		return out[i].MatchRoute < out[j].MatchRoute
	})
	return out, nil
}

func entityForAssertions(provider *Provider, values []matcherprovider.SourceAssertion) (Entity, bool) {
	for _, value := range values {
		key := value.SourceID + "\x1f" + value.ListID + "\x1f" + value.SourceRecordID
		if entity, ok := provider.EntityForSourceKey(key); ok {
			return entity, true
		}
	}
	return Entity{}, false
}

func betterCandidate(left, right matcherprovider.ProviderCandidate) bool {
	if left.ScoreBasisPoints != right.ScoreBasisPoints {
		return left.ScoreBasisPoints > right.ScoreBasisPoints
	}
	if left.Exact != right.Exact {
		return left.Exact
	}
	return left.MatchRoute < right.MatchRoute
}

func mergeAssertions(left, right []matcherprovider.SourceAssertion) []matcherprovider.SourceAssertion {
	seen := map[string]matcherprovider.SourceAssertion{}
	for _, assertion := range append(append([]matcherprovider.SourceAssertion(nil), left...), right...) {
		key := assertion.SourceID + "\x1f" + assertion.ListID + "\x1f" + assertion.SourceRecordID
		assertion.Programs = sortedUnique(assertion.Programs)
		seen[key] = assertion
	}
	out := make([]matcherprovider.SourceAssertion, 0, len(seen))
	for _, assertion := range seen {
		out = append(out, assertion)
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

func cloneAttributes(values map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range values {
		out[key] = value
	}
	return out
}
func mergeAttributes(left, right map[string]string) map[string]string {
	out := cloneAttributes(left)
	for key, value := range right {
		out[key] = value
	}
	return out
}
