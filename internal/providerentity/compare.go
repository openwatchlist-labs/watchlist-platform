package providerentity

import (
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

func Compare(provider Catalog, direct ofaccatalog.Catalog) (Comparison, error) {
	if err := ValidateCatalog(provider); err != nil {
		return Comparison{}, err
	}
	if err := ofaccatalog.ValidateCatalog(direct); err != nil {
		return Comparison{}, err
	}
	directByKey := map[string]ofaccatalog.DirectListRecord{}
	for _, record := range direct.Records {
		key := record.SourceAssertion.SourceID + "\x1f" + record.SourceAssertion.ListID + "\x1f" + record.SourceAssertion.SourceRecordID
		directByKey[key] = record
	}
	providerLinked := map[string]bool{}
	var links []ComparisonLink
	var providerOnly []string
	for _, entity := range provider.Entities {
		linked := false
		for _, membership := range entity.SourceMemberships {
			if !membership.Active {
				continue
			}
			key := membershipKey(membership)
			record, ok := directByKey[key]
			if !ok {
				continue
			}
			linked = true
			providerLinked[key] = true
			nameEqual := normalize(entity.PrimaryName) == normalize(record.PrimaryName)
			typeEqual := entity.EntityType == record.EntityType
			programsEqual := stringSliceEqual(sortedUnique(membership.Programs), sortedUnique(record.Programs))
			status := "linked_equal"
			if !nameEqual || !typeEqual || !programsEqual {
				status = "linked_different"
			}
			links = append(links, ComparisonLink{
				ProviderEntityID: entity.ProviderEntityID, ProviderRecordID: entity.ProviderRecordID,
				DirectRecordID: record.ProviderRecordID, SourceKey: key, Status: status,
				NameEqual: nameEqual, EntityTypeEqual: typeEqual, ProgramsEqual: programsEqual,
			})
		}
		if !linked {
			providerOnly = append(providerOnly, entity.ProviderEntityID)
		}
	}
	var directOnly []string
	for key, record := range directByKey {
		if !providerLinked[key] {
			directOnly = append(directOnly, record.ProviderRecordID)
		}
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].ProviderEntityID != links[j].ProviderEntityID {
			return links[i].ProviderEntityID < links[j].ProviderEntityID
		}
		return links[i].DirectRecordID < links[j].DirectRecordID
	})
	sort.Strings(providerOnly)
	sort.Strings(directOnly)
	summary := ComparisonSummary{ProviderEntities: len(provider.Entities), DirectRecords: len(direct.Records), LinkedRecords: len(links), ProviderOnly: len(providerOnly), DirectOnly: len(directOnly)}
	for _, link := range links {
		if !link.NameEqual {
			summary.NameDifferences++
		}
		if !link.EntityTypeEqual {
			summary.TypeDifferences++
		}
		if !link.ProgramsEqual {
			summary.ProgramDifferences++
		}
	}
	comparison := Comparison{
		SchemaVersion:   ComparisonSchemaVersion,
		ProviderCatalog: matcherprovider.CatalogReference{CatalogID: provider.CatalogID, CatalogVersion: provider.CatalogVersion, CatalogChecksum: provider.CatalogChecksum, CatalogMode: provider.CatalogMode},
		DirectCatalog:   matcherprovider.CatalogReference{CatalogID: direct.CatalogID, CatalogVersion: direct.CatalogVersion, CatalogChecksum: direct.CatalogChecksum, CatalogMode: direct.CatalogMode},
		Summary:         summary, Links: links, ProviderOnlyIDs: providerOnly, DirectOnlyIDs: directOnly,
	}
	comparison.ComparisonChecksum = comparisonChecksum(comparison)
	comparison.ComparisonID = hashID("catalog_comparison_", comparison.ComparisonChecksum)
	return comparison, ValidateComparison(comparison)
}

func ValidateComparison(comparison Comparison) error {
	if comparison.SchemaVersion != ComparisonSchemaVersion || comparison.ComparisonID == "" || comparison.ComparisonChecksum == "" {
		return ErrInvalidProviderCatalog
	}
	if comparison.ProviderCatalog.CatalogMode != matcherprovider.CatalogModeProviderEntity || comparison.DirectCatalog.CatalogMode != matcherprovider.CatalogModeDirectList {
		return ErrInvalidProviderCatalog
	}
	if comparison.ComparisonChecksum != comparisonChecksum(comparison) || comparison.ComparisonID != hashID("catalog_comparison_", comparison.ComparisonChecksum) {
		return ErrInvalidProviderCatalog
	}
	return nil
}

func comparisonChecksum(comparison Comparison) string {
	copy := comparison
	copy.ComparisonID = ""
	copy.ComparisonChecksum = ""
	return digest(copy)
}

func stringSliceEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if strings.TrimSpace(left[i]) != strings.TrimSpace(right[i]) {
			return false
		}
	}
	return true
}
