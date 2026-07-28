package ofacruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

func Compile(catalog ofaccatalog.Catalog) ([]byte, PackageInfo, error) {
	if err := ofaccatalog.ValidateCatalog(catalog); err != nil {
		return nil, PackageInfo{}, err
	}
	provider, err := ofaccatalog.NewProvider(catalog)
	if err != nil {
		return nil, PackageInfo{}, err
	}
	entries := compileEntries(catalog)
	payload := RuntimePayload{
		SchemaVersion:    RuntimePayloadSchemaVersion,
		CompilerVersion:  CompilerVersion,
		Provider:         provider.Descriptor(),
		SourceManifestID: catalog.SourceManifest.ManifestID,
		RecordCount:      catalog.RecordCount,
		EntryCount:       len(entries),
		Entries:          entries,
	}
	if err := ValidatePayload(payload); err != nil {
		return nil, PackageInfo{}, err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, PackageInfo{}, err
	}
	payloadSum := sha256.Sum256(payloadBytes)
	manifest := PackageManifest{
		SchemaVersion:       PackageManifestSchemaVersion,
		PackageFormat:       PackageFormatVersion,
		CompilerVersion:     CompilerVersion,
		PayloadSchema:       RuntimePayloadSchemaVersion,
		Provider:            payload.Provider,
		SourceManifestID:    catalog.SourceManifest.ManifestID,
		SourceContentSHA256: catalog.SourceManifest.ContentSHA256,
		RecordCount:         catalog.RecordCount,
		EntryCount:          len(entries),
		PayloadSHA256:       hex.EncodeToString(payloadSum[:]),
		PayloadSize:         int64(len(payloadBytes)),
	}
	manifest.PackageID = stablePackageID(manifest)
	if err := ValidateManifest(manifest); err != nil {
		return nil, PackageInfo{}, err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, PackageInfo{}, err
	}
	var artifact bytes.Buffer
	artifact.WriteString(PackageMagic)
	if err := binary.Write(&artifact, binary.BigEndian, uint64(len(manifestBytes))); err != nil {
		return nil, PackageInfo{}, err
	}
	artifact.Write(manifestBytes)
	if err := binary.Write(&artifact, binary.BigEndian, uint64(len(payloadBytes))); err != nil {
		return nil, PackageInfo{}, err
	}
	artifact.Write(payloadBytes)
	data := artifact.Bytes()
	artifactSum := sha256.Sum256(data)
	info := PackageInfo{
		SchemaVersion:   PackageInfoSchemaVersion,
		PackageID:       manifest.PackageID,
		PackageChecksum: hex.EncodeToString(artifactSum[:]),
		ArtifactSize:    int64(len(data)),
		Manifest:        manifest,
	}
	if err := ValidateInfo(info); err != nil {
		return nil, PackageInfo{}, err
	}
	return data, info, nil
}

func compileEntries(catalog ofaccatalog.Catalog) []CompiledEntry {
	var entries []CompiledEntry
	for _, record := range catalog.Records {
		base := map[string]string{"ofac_uid": record.SourceUID, "sdn_type": record.SDNType}
		appendEntry := func(route canonical.MatchRoute, value string, score int, attrs map[string]string) {
			value = strings.TrimSpace(value)
			if value == "" {
				return
			}
			entries = append(entries, CompiledEntry{
				MatchRoute:             route,
				NormalizedQuery:        normalize(value),
				ProviderRecordID:       record.ProviderRecordID,
				EntityType:             record.EntityType,
				PrimaryName:            record.PrimaryName,
				MatchedValue:           value,
				NormalizedMatchedValue: normalize(value),
				ScoreBasisPoints:       score,
				Exact:                  true,
				Attributes:             cloneAttributes(attrs),
				SourceAssertions:       []matcherprovider.SourceAssertion{record.SourceAssertion},
			})
		}
		appendEntry(canonical.RouteNormalizedName, record.PrimaryName, 10000, base)
		for _, alias := range record.Aliases {
			attrs := cloneAttributes(base)
			attrs["alias_type"] = alias.Type
			if alias.Strength != "" {
				attrs["alias_strength"] = alias.Strength
			}
			appendEntry(canonical.RouteAlias, alias.Name, 9700, attrs)
			appendEntry(canonical.RouteTransliteration, alias.Name, 9700, attrs)
		}
		for _, value := range record.DatesOfBirth {
			appendEntry(canonical.RouteExactDate, value, 10000, base)
		}
		for _, address := range record.Addresses {
			appendEntry(canonical.RouteJurisdictionPolicy, address.Country, 10000, base)
			for _, value := range []string{address.Address1, address.Address2, address.Address3, address.City, address.State, address.PostalCode, address.Country} {
				appendEntry(canonical.RouteContextualAddress, value, 9000, base)
			}
		}
		appendEntry(canonical.RouteContextualPhrase, record.Remarks, 10000, base)
		for _, identifier := range record.Identifiers {
			attrs := cloneAttributes(base)
			attrs["identifier_type"] = identifier.Type
			for _, route := range []canonical.MatchRoute{canonical.RouteExactBIC, canonical.RouteExactLEI, canonical.RouteExactAccount} {
				if identifierSupports(route, identifier.Type) {
					appendEntry(route, identifier.Number, 10000, attrs)
				}
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		left, right := entries[i], entries[j]
		if left.MatchRoute != right.MatchRoute {
			return left.MatchRoute < right.MatchRoute
		}
		if left.NormalizedQuery != right.NormalizedQuery {
			return left.NormalizedQuery < right.NormalizedQuery
		}
		if left.ProviderRecordID != right.ProviderRecordID {
			return left.ProviderRecordID < right.ProviderRecordID
		}
		if left.ScoreBasisPoints != right.ScoreBasisPoints {
			return left.ScoreBasisPoints > right.ScoreBasisPoints
		}
		return left.MatchedValue < right.MatchedValue
	})
	out := entries[:0]
	var previous string
	for _, entry := range entries {
		key := string(entry.MatchRoute) + "\x1f" + entry.NormalizedQuery + "\x1f" + entry.ProviderRecordID + "\x1f" + entry.MatchedValue
		if key == previous {
			continue
		}
		previous = key
		out = append(out, entry)
	}
	return out
}

func identifierSupports(route canonical.MatchRoute, value string) bool {
	kind := strings.ToLower(value)
	switch route {
	case canonical.RouteExactBIC:
		return strings.Contains(kind, "bic") || strings.Contains(kind, "swift")
	case canonical.RouteExactLEI:
		return strings.Contains(kind, "legal entity identifier") || kind == "lei"
	case canonical.RouteExactAccount:
		return (strings.Contains(kind, "account") || strings.Contains(kind, "iban")) && !strings.Contains(kind, "imo")
	}
	return false
}

func normalize(value string) string {
	return strings.Join(strings.FieldsFunc(strings.ToUpper(strings.TrimSpace(value)), func(r rune) bool { return unicode.IsSpace(r) }), " ")
}

func cloneAttributes(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func packageSeed(manifest PackageManifest) []string {
	return []string{
		PackageManifestSchemaVersion,
		manifest.PackageFormat,
		manifest.CompilerVersion,
		manifest.PayloadSchema,
		manifest.Provider.ProviderID,
		manifest.Provider.ProviderVersion,
		manifest.Provider.Catalog.CatalogID,
		manifest.Provider.Catalog.CatalogVersion,
		manifest.Provider.Catalog.CatalogChecksum,
		string(manifest.Provider.Catalog.CatalogMode),
		manifest.SourceManifestID,
		manifest.SourceContentSHA256,
		fmt.Sprint(manifest.RecordCount),
		fmt.Sprint(manifest.EntryCount),
		manifest.PayloadSHA256,
		fmt.Sprint(manifest.PayloadSize),
	}
}
