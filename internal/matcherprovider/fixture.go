// Package matcherprovider defines the shared Provider interface used by
// every name-matching backend in this repository, plus one concrete
// implementation: ExactMatchFixtureProvider.
//
// IMPORTANT, easy to get wrong: there are two very different providers in
// this codebase that both satisfy the same Provider interface, and a
// pass/fail against one says nothing about the other:
//
//   - ExactMatchFixtureProvider (this package) reads a plain JSON
//     FixtureCatalog and matches on case/whitespace-normalized string
//     EQUALITY ONLY - no fuzzy matching, no phonetic matching, no
//     transliteration handling beyond what's literally registered as an
//     alias in the catalog data itself.
//   - matcherbaseline.Provider (a different package) is the real
//     fuzzy/token-alignment/phonetic matching engine, but it only loads
//     from a compiled runtime package (built via cmd/ofac-runtime), not
//     directly from a FixtureCatalog JSON file.
//
// A demo or integration test using ExactMatchFixtureProvider can look
// superficially identical to one using matcherbaseline.Provider from the
// outside - both just look like "the matcher returned some candidates" -
// but only the latter exercises real matching robustness. See issue #12
// and docs/TEST_DATA.md for the fuller history of this confusion.
package matcherprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
)

const FixtureCatalogSchemaVersion = "fixture-provider-catalog/v1alpha1"

var ErrInvalidFixtureCatalog = errors.New("invalid fixture provider catalog")

type FixtureRecord struct {
	ProviderRecordID string                  `json:"provider_record_id"`
	ProviderEntityID string                  `json:"provider_entity_id,omitempty"`
	EntityType       canonical.CandidateType `json:"entity_type"`
	PrimaryName      string                  `json:"primary_name"`
	Aliases          []string                `json:"aliases,omitempty"`
	Transliterations []string                `json:"transliterations,omitempty"`
	Identifiers      map[string][]string     `json:"identifiers,omitempty"`
	Jurisdictions    []string                `json:"jurisdictions,omitempty"`
	Addresses        []string                `json:"addresses,omitempty"`
	Dates            []string                `json:"dates,omitempty"`
	Phrases          []string                `json:"phrases,omitempty"`
	Attributes       map[string]string       `json:"attributes,omitempty"`
	SourceAssertions []SourceAssertion       `json:"source_assertions"`
}

type FixtureCatalog struct {
	SchemaVersion   string          `json:"schema_version"`
	ProviderID      string          `json:"provider_id"`
	ProviderVersion string          `json:"provider_version"`
	CatalogID       string          `json:"catalog_id"`
	CatalogVersion  string          `json:"catalog_version"`
	CatalogMode     CatalogMode     `json:"catalog_mode"`
	Records         []FixtureRecord `json:"records"`
}

// ExactMatchFixtureProvider is a Provider backed by a plain JSON catalog
// (FixtureCatalog), matching purely on case/whitespace-normalized string
// equality. It is NOT the same matching engine as matcherbaseline.Provider,
// which does real fuzzy/token-alignment/phonetic matching against a
// compiled runtime package - see the package doc comment above for the
// full distinction. This type was previously named just "FixtureProvider",
// which invited exactly that confusion (see issue #12); the name now says
// what it actually does.
type ExactMatchFixtureProvider struct {
	descriptor ProviderDescriptor
	records    []FixtureRecord
}

// LoadExactMatchFixtureProvider reads a FixtureCatalog from reader and
// returns an ExactMatchFixtureProvider backed by it. Previously named
// LoadFixtureProvider.
func LoadExactMatchFixtureProvider(reader io.Reader) (*ExactMatchFixtureProvider, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var catalog FixtureCatalog
	if err := decoder.Decode(&catalog); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidFixtureCatalog, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values are not allowed")
		}
		return nil, fmt.Errorf("%w: decode trailing content: %v", ErrInvalidFixtureCatalog, err)
	}
	if err := validateFixtureCatalog(catalog); err != nil {
		return nil, err
	}
	canonicalBytes, err := json.Marshal(catalog)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal for checksum: %v", ErrInvalidFixtureCatalog, err)
	}
	sum := sha256.Sum256(canonicalBytes)
	descriptor := ProviderDescriptor{
		SchemaVersion:   ProviderDescriptorSchemaVersion,
		ProviderID:      catalog.ProviderID,
		ProviderVersion: catalog.ProviderVersion,
		Catalog: CatalogReference{
			CatalogID:       catalog.CatalogID,
			CatalogVersion:  catalog.CatalogVersion,
			CatalogChecksum: hex.EncodeToString(sum[:]),
			CatalogMode:     catalog.CatalogMode,
		},
		Capabilities: ProviderCapabilities{
			SupportedRoutes: []canonical.MatchRoute{
				canonical.RouteAlias,
				canonical.RouteContextualAddress,
				canonical.RouteContextualPhrase,
				canonical.RouteExactAccount,
				canonical.RouteExactBIC,
				canonical.RouteExactDate,
				canonical.RouteExactLEI,
				canonical.RouteJurisdictionPolicy,
				canonical.RouteNormalizedName,
				canonical.RouteTransliteration,
			},
			SupportedEntityTypes: []canonical.CandidateType{
				canonical.CandidateAircraft,
				canonical.CandidateFinancialInstitution,
				canonical.CandidateGovernmentEntity,
				canonical.CandidateIndividual,
				canonical.CandidateJurisdiction,
				canonical.CandidateOrganization,
				canonical.CandidateVessel,
			},
			MaxCandidatesPerRequest:  25,
			Deterministic:            true,
			SourceAssertionsIncluded: true,
		},
	}
	if err := ValidateDescriptor(descriptor); err != nil {
		return nil, fmt.Errorf("%w: descriptor: %v", ErrInvalidFixtureCatalog, err)
	}
	return &ExactMatchFixtureProvider{descriptor: descriptor, records: append([]FixtureRecord(nil), catalog.Records...)}, nil
}

func (provider *ExactMatchFixtureProvider) Descriptor() ProviderDescriptor {
	return provider.descriptor
}

func (provider *ExactMatchFixtureProvider) Search(_ context.Context, request matcherrequest.CandidateSearchRequest) ([]ProviderCandidate, error) {
	query := normalizeFixtureValue(request.Query.NormalizedValue)
	matches := make([]ProviderCandidate, 0)
	for _, record := range provider.records {
		if !containsType(request.TargetEntityTypes, record.EntityType) {
			continue
		}
		candidate, ok := matchFixtureRecord(request, query, record)
		if ok {
			matches = append(matches, candidate)
		}
	}
	return matches, nil
}

func matchFixtureRecord(request matcherrequest.CandidateSearchRequest, query string, record FixtureRecord) (ProviderCandidate, bool) {
	var candidates []ProviderCandidate
	for _, route := range request.MatchRoutes {
		matchedValue, score, exact, ok := fixtureRouteMatch(route, query, record)
		if !ok {
			continue
		}
		candidates = append(candidates, ProviderCandidate{
			ProviderRecordID:       record.ProviderRecordID,
			ProviderEntityID:       record.ProviderEntityID,
			EntityType:             record.EntityType,
			PrimaryName:            record.PrimaryName,
			MatchedValue:           matchedValue,
			NormalizedMatchedValue: normalizeFixtureValue(matchedValue),
			MatchRoute:             route,
			ScoreBasisPoints:       score,
			Exact:                  exact,
			Attributes:             cloneStringMap(record.Attributes),
			SourceAssertions:       cloneAssertions(record.SourceAssertions),
		})
	}
	if len(candidates) == 0 {
		return ProviderCandidate{}, false
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.ScoreBasisPoints != right.ScoreBasisPoints {
			return left.ScoreBasisPoints > right.ScoreBasisPoints
		}
		if left.Exact != right.Exact {
			return left.Exact
		}
		return left.MatchRoute < right.MatchRoute
	})
	return candidates[0], true
}

func fixtureRouteMatch(route canonical.MatchRoute, query string, record FixtureRecord) (string, int, bool, bool) {
	switch route {
	case canonical.RouteNormalizedName:
		return exactValue(query, []string{record.PrimaryName}, 10000, true)
	case canonical.RouteAlias:
		return exactValue(query, record.Aliases, 9700, true)
	case canonical.RouteTransliteration:
		return exactValue(query, record.Transliterations, 9300, true)
	case canonical.RouteExactBIC, canonical.RouteExactLEI, canonical.RouteExactAccount:
		return exactValue(query, record.Identifiers[string(route)], 10000, true)
	case canonical.RouteExactDate:
		return exactValue(query, record.Dates, 10000, true)
	case canonical.RouteJurisdictionPolicy:
		return exactValue(query, record.Jurisdictions, 10000, true)
	case canonical.RouteContextualAddress:
		return exactValue(query, record.Addresses, 9000, true)
	case canonical.RouteContextualPhrase:
		for _, phrase := range record.Phrases {
			normalized := normalizeFixtureValue(phrase)
			if normalized != "" && strings.Contains(query, normalized) {
				return phrase, 8500, false, true
			}
		}
	}
	return "", 0, false, false
}

func exactValue(query string, values []string, score int, exact bool) (string, int, bool, bool) {
	for _, value := range values {
		if query == normalizeFixtureValue(value) {
			return value, score, exact, true
		}
	}
	return "", 0, false, false
}

func validateFixtureCatalog(catalog FixtureCatalog) error {
	if catalog.SchemaVersion != FixtureCatalogSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidFixtureCatalog, FixtureCatalogSchemaVersion)
	}
	for field, value := range map[string]string{
		"provider_id":      catalog.ProviderID,
		"provider_version": catalog.ProviderVersion,
		"catalog_id":       catalog.CatalogID,
		"catalog_version":  catalog.CatalogVersion,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidFixtureCatalog, field)
		}
	}
	if catalog.CatalogMode != CatalogModeProviderEntity && catalog.CatalogMode != CatalogModeDirectList && catalog.CatalogMode != CatalogModeHybridOverlay {
		return fmt.Errorf("%w: unsupported catalog_mode %q", ErrInvalidFixtureCatalog, catalog.CatalogMode)
	}
	if len(catalog.Records) == 0 {
		return fmt.Errorf("%w: records must not be empty", ErrInvalidFixtureCatalog)
	}
	seen := map[string]struct{}{}
	for index, record := range catalog.Records {
		if strings.TrimSpace(record.ProviderRecordID) == "" || strings.TrimSpace(record.PrimaryName) == "" || strings.TrimSpace(string(record.EntityType)) == "" {
			return fmt.Errorf("%w: records[%d] requires provider_record_id, entity_type, and primary_name", ErrInvalidFixtureCatalog, index)
		}
		if catalog.CatalogMode == CatalogModeProviderEntity && strings.TrimSpace(record.ProviderEntityID) == "" {
			return fmt.Errorf("%w: records[%d].provider_entity_id is required", ErrInvalidFixtureCatalog, index)
		}
		if _, exists := seen[record.ProviderRecordID]; exists {
			return fmt.Errorf("%w: duplicate provider_record_id %q", ErrInvalidFixtureCatalog, record.ProviderRecordID)
		}
		seen[record.ProviderRecordID] = struct{}{}
		candidate := ProviderCandidate{
			ProviderRecordID:       record.ProviderRecordID,
			ProviderEntityID:       record.ProviderEntityID,
			EntityType:             record.EntityType,
			PrimaryName:            record.PrimaryName,
			MatchedValue:           record.PrimaryName,
			NormalizedMatchedValue: normalizeFixtureValue(record.PrimaryName),
			MatchRoute:             canonical.RouteNormalizedName,
			ScoreBasisPoints:       10000,
			Exact:                  true,
			SourceAssertions:       record.SourceAssertions,
		}
		if err := validateFixtureCandidateBasics(catalog.CatalogMode, candidate); err != nil {
			return fmt.Errorf("%w: records[%d]: %v", ErrInvalidFixtureCatalog, index, err)
		}
	}
	return nil
}

func validateFixtureCandidateBasics(mode CatalogMode, candidate ProviderCandidate) error {
	if mode == CatalogModeProviderEntity && strings.TrimSpace(candidate.ProviderEntityID) == "" {
		return errors.New("provider_entity_id is required")
	}
	if len(candidate.SourceAssertions) == 0 {
		return errors.New("source_assertions must not be empty")
	}
	for index, assertion := range candidate.SourceAssertions {
		if strings.TrimSpace(assertion.SourceID) == "" || strings.TrimSpace(assertion.Authority) == "" || strings.TrimSpace(assertion.ListID) == "" || strings.TrimSpace(assertion.SourceRecordID) == "" {
			return fmt.Errorf("source_assertions[%d] requires source_id, authority, list_id, and source_record_id", index)
		}
	}
	return nil
}

func normalizeFixtureValue(value string) string {
	return strings.Join(strings.Fields(strings.ToUpper(value)), " ")
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneAssertions(values []SourceAssertion) []SourceAssertion {
	result := make([]SourceAssertion, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Programs = append([]string(nil), value.Programs...)
	}
	return result
}

func StrictDecodeExactMatchFixtureProvider(data []byte) (*ExactMatchFixtureProvider, error) {
	return LoadExactMatchFixtureProvider(bytes.NewReader(data))
}
