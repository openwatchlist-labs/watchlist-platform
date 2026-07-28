package ofacruntime

import (
	"context"
	"sort"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
)

type Provider struct {
	descriptor matcherprovider.ProviderDescriptor
	index      map[string][]CompiledEntry
}

func NewProvider(payload RuntimePayload) (*Provider, error) {
	if err := ValidatePayload(payload); err != nil {
		return nil, err
	}
	index := make(map[string][]CompiledEntry)
	for _, entry := range payload.Entries {
		key := indexKey(entry.MatchRoute, entry.NormalizedQuery)
		index[key] = append(index[key], entry)
	}
	return &Provider{descriptor: payload.Provider, index: index}, nil
}

func (provider *Provider) Descriptor() matcherprovider.ProviderDescriptor {
	return provider.descriptor
}

func (provider *Provider) Search(_ context.Context, request matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, error) {
	query := normalize(request.Query.NormalizedValue)
	best := map[string]matcherprovider.ProviderCandidate{}
	for _, route := range request.MatchRoutes {
		for _, entry := range provider.index[indexKey(route, query)] {
			if !containsType(request.TargetEntityTypes, entry.EntityType) {
				continue
			}
			candidate := matcherprovider.ProviderCandidate{
				ProviderRecordID:       entry.ProviderRecordID,
				EntityType:             entry.EntityType,
				PrimaryName:            entry.PrimaryName,
				MatchedValue:           entry.MatchedValue,
				NormalizedMatchedValue: entry.NormalizedMatchedValue,
				MatchRoute:             entry.MatchRoute,
				ScoreBasisPoints:       entry.ScoreBasisPoints,
				Exact:                  entry.Exact,
				Attributes:             cloneAttributes(entry.Attributes),
				SourceAssertions:       append([]matcherprovider.SourceAssertion(nil), entry.SourceAssertions...),
			}
			current, exists := best[entry.ProviderRecordID]
			if !exists || better(candidate, current) {
				best[entry.ProviderRecordID] = candidate
			}
		}
	}
	out := make([]matcherprovider.ProviderCandidate, 0, len(best))
	for _, candidate := range best {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProviderRecordID < out[j].ProviderRecordID })
	return out, nil
}

func better(left, right matcherprovider.ProviderCandidate) bool {
	if left.ScoreBasisPoints != right.ScoreBasisPoints {
		return left.ScoreBasisPoints > right.ScoreBasisPoints
	}
	if left.Exact != right.Exact {
		return left.Exact
	}
	return left.MatchRoute < right.MatchRoute
}

func indexKey(route canonical.MatchRoute, query string) string {
	return string(route) + "\x1f" + query
}

func containsType(values []canonical.CandidateType, target canonical.CandidateType) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
