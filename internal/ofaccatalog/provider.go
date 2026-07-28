package ofaccatalog

import (
	"context"
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"sort"
	"strings"
	"unicode"
)

type Provider struct {
	descriptor matcherprovider.ProviderDescriptor
	records    []DirectListRecord
}

func NewProvider(c Catalog) (*Provider, error) {
	if err := ValidateCatalog(c); err != nil {
		return nil, err
	}
	d := matcherprovider.ProviderDescriptor{SchemaVersion: matcherprovider.ProviderDescriptorSchemaVersion, ProviderID: ProviderID, ProviderVersion: ProviderVersion, Catalog: matcherprovider.CatalogReference{CatalogID: c.CatalogID, CatalogVersion: c.CatalogVersion, CatalogChecksum: c.CatalogChecksum, CatalogMode: matcherprovider.CatalogModeDirectList}, Capabilities: matcherprovider.ProviderCapabilities{SupportedRoutes: []canonical.MatchRoute{canonical.RouteAlias, canonical.RouteContextualAddress, canonical.RouteContextualPhrase, canonical.RouteExactAccount, canonical.RouteExactBIC, canonical.RouteExactDate, canonical.RouteExactLEI, canonical.RouteJurisdictionPolicy, canonical.RouteNormalizedName, canonical.RouteTransliteration}, SupportedEntityTypes: []canonical.CandidateType{canonical.CandidateAircraft, canonical.CandidateFinancialInstitution, canonical.CandidateGovernmentEntity, canonical.CandidateIndividual, canonical.CandidateJurisdiction, canonical.CandidateOrganization, canonical.CandidateVessel}, MaxCandidatesPerRequest: 25, Deterministic: true, SourceAssertionsIncluded: true}}
	if err := matcherprovider.ValidateDescriptor(d); err != nil {
		return nil, err
	}
	return &Provider{descriptor: d, records: append([]DirectListRecord(nil), c.Records...)}, nil
}
func (p *Provider) Descriptor() matcherprovider.ProviderDescriptor { return p.descriptor }
func (p *Provider) Search(_ context.Context, r matcherrequest.CandidateSearchRequest) ([]matcherprovider.ProviderCandidate, error) {
	q := normalize(r.Query.NormalizedValue)
	var out []matcherprovider.ProviderCandidate
	for _, record := range p.records {
		if !containsType(r.TargetEntityTypes, record.EntityType) {
			continue
		}
		if c, ok := matchRecord(r, q, record); ok {
			out = append(out, c)
		}
	}
	return out, nil
}
func matchRecord(req matcherrequest.CandidateSearchRequest, q string, r DirectListRecord) (matcherprovider.ProviderCandidate, bool) {
	var all []matcherprovider.ProviderCandidate
	for _, route := range req.MatchRoutes {
		value, score, exact, attrs, ok := matchRoute(route, q, r)
		if !ok {
			continue
		}
		all = append(all, matcherprovider.ProviderCandidate{ProviderRecordID: r.ProviderRecordID, EntityType: r.EntityType, PrimaryName: r.PrimaryName, MatchedValue: value, NormalizedMatchedValue: normalize(value), MatchRoute: route, ScoreBasisPoints: score, Exact: exact, Attributes: attrs, SourceAssertions: []matcherprovider.SourceAssertion{r.SourceAssertion}})
	}
	if len(all) == 0 {
		return matcherprovider.ProviderCandidate{}, false
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].ScoreBasisPoints != all[j].ScoreBasisPoints {
			return all[i].ScoreBasisPoints > all[j].ScoreBasisPoints
		}
		if all[i].Exact != all[j].Exact {
			return all[i].Exact
		}
		return all[i].MatchRoute < all[j].MatchRoute
	})
	return all[0], true
}
func matchRoute(route canonical.MatchRoute, q string, r DirectListRecord) (string, int, bool, map[string]string, bool) {
	attrs := map[string]string{"ofac_uid": r.SourceUID, "sdn_type": r.SDNType}
	switch route {
	case canonical.RouteNormalizedName:
		if q == normalize(r.PrimaryName) {
			return r.PrimaryName, 10000, true, attrs, true
		}
	case canonical.RouteAlias, canonical.RouteTransliteration:
		for _, a := range r.Aliases {
			if q == normalize(a.Name) {
				x := clone(attrs)
				x["alias_type"] = a.Type
				if a.Strength != "" {
					x["alias_strength"] = a.Strength
				}
				return a.Name, 9700, true, x, true
			}
		}
	case canonical.RouteExactDate:
		for _, v := range r.DatesOfBirth {
			if q == normalize(v) {
				return v, 10000, true, attrs, true
			}
		}
	case canonical.RouteJurisdictionPolicy:
		for _, a := range r.Addresses {
			if q == normalize(a.Country) {
				return a.Country, 10000, true, attrs, true
			}
		}
	case canonical.RouteContextualAddress:
		for _, a := range r.Addresses {
			for _, v := range []string{a.Address1, a.Address2, a.Address3, a.City, a.State, a.PostalCode, a.Country} {
				if v != "" && q == normalize(v) {
					return v, 9000, true, attrs, true
				}
			}
		}
	case canonical.RouteContextualPhrase:
		if q == normalize(r.Remarks) {
			return r.Remarks, 10000, true, attrs, true
		}
	case canonical.RouteExactBIC, canonical.RouteExactLEI, canonical.RouteExactAccount:
		for _, id := range r.Identifiers {
			if identifierSupports(route, id.Type) && q == normalize(id.Number) {
				x := clone(attrs)
				x["identifier_type"] = id.Type
				return id.Number, 10000, true, x, true
			}
		}
	}
	return "", 0, false, nil, false
}
func identifierSupports(route canonical.MatchRoute, t string) bool {
	x := strings.ToLower(t)
	switch route {
	case canonical.RouteExactBIC:
		return strings.Contains(x, "bic") || strings.Contains(x, "swift")
	case canonical.RouteExactLEI:
		return strings.Contains(x, "legal entity identifier") || x == "lei"
	case canonical.RouteExactAccount:
		return (strings.Contains(x, "account") || strings.Contains(x, "iban")) && !strings.Contains(x, "imo")
	}
	return false
}
func normalize(v string) string {
	return strings.Join(strings.FieldsFunc(strings.ToUpper(strings.TrimSpace(v)), func(r rune) bool { return unicode.IsSpace(r) }), " ")
}
func containsType(values []canonical.CandidateType, w canonical.CandidateType) bool {
	for _, v := range values {
		if v == w {
			return true
		}
	}
	return false
}
func clone(m map[string]string) map[string]string {
	o := make(map[string]string, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}
