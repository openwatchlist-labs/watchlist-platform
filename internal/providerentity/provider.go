package providerentity

import (
	"context"
	"sort"
	"strings"
	"unicode"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
)

type Provider struct {
	descriptor matcherprovider.ProviderDescriptor
	catalog    Catalog
	bySource   map[string]Entity
}

func NewProvider(catalog Catalog) (*Provider, error) {
	if err := ValidateCatalog(catalog); err != nil {
		return nil, err
	}
	descriptor := matcherprovider.ProviderDescriptor{
		SchemaVersion:   matcherprovider.ProviderDescriptorSchemaVersion,
		ProviderID:      ProviderID,
		ProviderVersion: ProviderVersion,
		Catalog: matcherprovider.CatalogReference{
			CatalogID: catalog.CatalogID, CatalogVersion: catalog.CatalogVersion,
			CatalogChecksum: catalog.CatalogChecksum, CatalogMode: matcherprovider.CatalogModeProviderEntity,
		},
		Capabilities: defaultCapabilities(),
	}
	if err := matcherprovider.ValidateDescriptor(descriptor); err != nil {
		return nil, err
	}
	bySource := map[string]Entity{}
	for _, entity := range catalog.Entities {
		for _, membership := range entity.SourceMemberships {
			if membership.Active {
				bySource[membershipKey(membership)] = entity
			}
		}
	}
	return &Provider{descriptor: descriptor, catalog: catalog, bySource: bySource}, nil
}

func (p *Provider) Descriptor() matcherprovider.ProviderDescriptor { return p.descriptor }

func (p *Provider) Search(_ context.Context, request matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, error) {
	query := normalize(request.Query.NormalizedValue)
	var candidates []matcherprovider.ProviderCandidate
	for _, entity := range p.catalog.Entities {
		if !containsType(request.TargetEntityTypes, entity.EntityType) {
			continue
		}
		candidate, ok := matchEntity(request, query, entity, p.catalog.ProviderName)
		if ok {
			candidates = append(candidates, candidate)
		}
	}
	return candidates, nil
}

func (p *Provider) EntityForSourceKey(key string) (Entity, bool) {
	entity, ok := p.bySource[key]
	return entity, ok
}

func matchEntity(request matcherrequest.CandidateSearchRequest, query string, entity Entity, providerName string) (matcherprovider.ProviderCandidate, bool) {
	var matches []matcherprovider.ProviderCandidate
	for _, route := range request.MatchRoutes {
		value, score, exact, attributes, ok := matchRoute(route, query, entity)
		if !ok {
			continue
		}
		base := map[string]string{
			"provider_entity_id":      entity.ProviderEntityID,
			"provider_name":           providerName,
			"source_membership_count": itoa(len(activeMemberships(entity.SourceMemberships))),
		}
		for key, item := range entity.Attributes {
			base[key] = item
		}
		for key, item := range attributes {
			base[key] = item
		}
		matches = append(matches, matcherprovider.ProviderCandidate{
			ProviderRecordID: entity.ProviderRecordID, ProviderEntityID: entity.ProviderEntityID,
			EntityType: entity.EntityType, PrimaryName: entity.PrimaryName,
			MatchedValue: value, NormalizedMatchedValue: normalize(value), MatchRoute: route,
			ScoreBasisPoints: score, Exact: exact, Attributes: base,
			SourceAssertions: assertions(entity.SourceMemberships),
		})
	}
	if len(matches) == 0 {
		return matcherprovider.ProviderCandidate{}, false
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].ScoreBasisPoints != matches[j].ScoreBasisPoints {
			return matches[i].ScoreBasisPoints > matches[j].ScoreBasisPoints
		}
		if matches[i].Exact != matches[j].Exact {
			return matches[i].Exact
		}
		return matches[i].MatchRoute < matches[j].MatchRoute
	})
	return matches[0], true
}

func matchRoute(route canonical.MatchRoute, query string, entity Entity) (string, int, bool, map[string]string, bool) {
	switch route {
	case canonical.RouteNormalizedName:
		if query == normalize(entity.PrimaryName) {
			return entity.PrimaryName, 10000, true, nil, true
		}
	case canonical.RouteAlias, canonical.RouteTransliteration:
		for _, alias := range entity.Aliases {
			if query == normalize(alias.Name) {
				attributes := map[string]string{"alias_type": alias.Type}
				if alias.Strength != "" {
					attributes["alias_strength"] = alias.Strength
				}
				return alias.Name, 9700, true, attributes, true
			}
		}
	case canonical.RouteExactDate:
		for _, value := range entity.DatesOfBirth {
			if query == normalize(value) {
				return value, 10000, true, nil, true
			}
		}
	case canonical.RouteJurisdictionPolicy:
		for _, address := range entity.Addresses {
			if query == normalize(address.Country) {
				return address.Country, 10000, true, nil, true
			}
		}
	case canonical.RouteContextualAddress:
		for _, address := range entity.Addresses {
			for _, value := range []string{address.Line1, address.Line2, address.City, address.Region, address.PostalCode, address.Country} {
				if value != "" && query == normalize(value) {
					return value, 9000, true, nil, true
				}
			}
		}
	case canonical.RouteContextualPhrase:
		if entity.Remarks != "" && query == normalize(entity.Remarks) {
			return entity.Remarks, 10000, true, nil, true
		}
	case canonical.RouteExactBIC, canonical.RouteExactLEI, canonical.RouteExactAccount:
		for _, identifier := range entity.Identifiers {
			if identifierSupports(route, identifier.Type) && query == normalize(identifier.Value) {
				return identifier.Value, 10000, true, map[string]string{"identifier_type": identifier.Type}, true
			}
		}
	}
	return "", 0, false, nil, false
}

func defaultCapabilities() matcherprovider.ProviderCapabilities {
	return matcherprovider.ProviderCapabilities{
		SupportedRoutes: []canonical.MatchRoute{
			canonical.RouteAlias, canonical.RouteContextualAddress, canonical.RouteContextualPhrase,
			canonical.RouteExactAccount, canonical.RouteExactBIC, canonical.RouteExactDate,
			canonical.RouteExactLEI, canonical.RouteJurisdictionPolicy, canonical.RouteNormalizedName,
			canonical.RouteTransliteration,
		},
		SupportedEntityTypes: []canonical.CandidateType{
			canonical.CandidateAircraft, canonical.CandidateFinancialInstitution,
			canonical.CandidateGovernmentEntity, canonical.CandidateIndividual,
			canonical.CandidateJurisdiction, canonical.CandidateOrganization, canonical.CandidateVessel,
		},
		MaxCandidatesPerRequest: 25, Deterministic: true, SourceAssertionsIncluded: true,
	}
}

func assertions(memberships []SourceMembership) []matcherprovider.SourceAssertion {
	var out []matcherprovider.SourceAssertion
	for _, membership := range memberships {
		if !membership.Active {
			continue
		}
		out = append(out, matcherprovider.SourceAssertion{
			SourceID: membership.SourceID, Authority: membership.Authority,
			ListID: membership.ListID, SourceRecordID: membership.SourceRecordID,
			Programs: append([]string(nil), membership.Programs...),
		})
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

func activeMemberships(values []SourceMembership) []SourceMembership {
	var out []SourceMembership
	for _, value := range values {
		if value.Active {
			out = append(out, value)
		}
	}
	return out
}

func identifierSupports(route canonical.MatchRoute, value string) bool {
	kind := strings.ToLower(strings.TrimSpace(value))
	switch route {
	case canonical.RouteExactBIC:
		return strings.Contains(kind, "bic") || strings.Contains(kind, "swift")
	case canonical.RouteExactLEI:
		return kind == "lei" || strings.Contains(kind, "legal entity identifier")
	case canonical.RouteExactAccount:
		return (strings.Contains(kind, "account") || strings.Contains(kind, "iban")) && !strings.Contains(kind, "imo")
	default:
		return false
	}
}

func normalize(value string) string {
	return strings.Join(strings.FieldsFunc(strings.ToUpper(strings.TrimSpace(value)), func(r rune) bool { return unicode.IsSpace(r) }), " ")
}

func containsType(values []canonical.CandidateType, wanted canonical.CandidateType) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
