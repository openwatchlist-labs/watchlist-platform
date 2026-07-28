package ofaccatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
	"sort"
	"strconv"
	"strings"
)

var ErrInvalidCatalog = errors.New("invalid OFAC direct-list catalog")

func Project(src ofacsource.SourcePackage) (Catalog, error) {
	if src.SchemaVersion != ofacsource.PackageSchemaVersion {
		return Catalog{}, fmt.Errorf("%w: invalid source package", ErrInvalidCatalog)
	}
	records := make([]DirectListRecord, 0, len(src.Document.Entries))
	for _, entry := range src.Document.Entries {
		r, err := projectEntry(entry)
		if err != nil {
			return Catalog{}, err
		}
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool { return uidNumber(records[i].SourceUID) < uidNumber(records[j].SourceUID) })
	c := Catalog{SchemaVersion: CatalogSchemaVersion, CatalogID: CatalogID, CatalogVersion: src.Document.PublishDate + "-" + src.Manifest.ContentSHA256[:12], CatalogMode: matcherprovider.CatalogModeDirectList, ProjectorVersion: ProjectorVersion, SourceManifest: src.Manifest, RecordCount: len(records), Records: records}
	sum, err := catalogChecksum(c)
	if err != nil {
		return Catalog{}, err
	}
	c.CatalogChecksum = sum
	if err = ValidateCatalog(c); err != nil {
		return Catalog{}, err
	}
	return c, nil
}

func projectEntry(e ofacsource.Entry) (DirectListRecord, error) {
	typ, err := mapType(e.SDNType)
	if err != nil {
		return DirectListRecord{}, err
	}
	uid := strconv.Itoa(e.UID)
	r := DirectListRecord{ProviderRecordID: "ofac:sdn:" + uid, SourceUID: uid, EntityType: typ, SDNType: e.SDNType, PrimaryName: joinName(e.FirstName, e.LastName), Title: e.Title, Remarks: e.Remarks, Programs: sortedUnique(e.Programs), DatesOfBirth: sortedUnique(e.DatesOfBirth), PlacesOfBirth: sortedUnique(e.PlacesOfBirth), Nationalities: sortedUnique(e.Nationalities), Citizenships: sortedUnique(e.Citizenships), SourceAssertion: matcherprovider.SourceAssertion{SourceID: "ofac-sls", Authority: "U.S. Department of the Treasury, Office of Foreign Assets Control", ListID: "SDN", SourceRecordID: uid, Programs: sortedUnique(e.Programs)}}
	for _, a := range e.Aliases {
		r.Aliases = append(r.Aliases, Alias{SourceUID: strconv.Itoa(a.UID), Type: a.Type, Strength: strings.ToLower(a.Category), Name: joinName(a.FirstName, a.LastName)})
	}
	for _, a := range e.Addresses {
		r.Addresses = append(r.Addresses, Address{SourceUID: strconv.Itoa(a.UID), Address1: a.Address1, Address2: a.Address2, Address3: a.Address3, City: a.City, State: a.State, PostalCode: a.PostalCode, Country: a.Country})
	}
	for _, id := range e.Identifiers {
		r.Identifiers = append(r.Identifiers, Identifier{SourceUID: strconv.Itoa(id.UID), Type: id.Type, Number: id.Number, Country: id.Country, IssueDate: id.Issue, ExpiryDate: id.Expiry})
	}
	sort.Slice(r.Aliases, func(i, j int) bool { return r.Aliases[i].SourceUID < r.Aliases[j].SourceUID })
	sort.Slice(r.Addresses, func(i, j int) bool { return r.Addresses[i].SourceUID < r.Addresses[j].SourceUID })
	sort.Slice(r.Identifiers, func(i, j int) bool { return r.Identifiers[i].SourceUID < r.Identifiers[j].SourceUID })
	v := map[string]string{"call_sign": e.Vessel.CallSign, "vessel_type": e.Vessel.Type, "flag": e.Vessel.Flag, "owner": e.Vessel.Owner, "tonnage": e.Vessel.Tonnage, "grt": e.Vessel.GRT}
	for k, x := range v {
		if strings.TrimSpace(x) == "" {
			delete(v, k)
		}
	}
	if len(v) > 0 {
		r.VesselAttributes = v
	}
	return r, nil
}

func ValidateCatalog(c Catalog) error {
	if c.SchemaVersion != CatalogSchemaVersion || c.CatalogID != CatalogID || c.CatalogMode != matcherprovider.CatalogModeDirectList || c.ProjectorVersion != ProjectorVersion {
		return fmt.Errorf("%w: invalid header", ErrInvalidCatalog)
	}
	if err := ofacsource.ValidateManifest(c.SourceManifest); err != nil {
		return fmt.Errorf("%w: source manifest: %v", ErrInvalidCatalog, err)
	}
	if c.RecordCount < 1 || c.RecordCount != len(c.Records) {
		return fmt.Errorf("%w: invalid record count", ErrInvalidCatalog)
	}
	seen := map[string]struct{}{}
	last := 0
	for i, r := range c.Records {
		n := uidNumber(r.SourceUID)
		if n <= 0 || n < last {
			return fmt.Errorf("%w: records not UID ordered at %d", ErrInvalidCatalog, i)
		}
		last = n
		if r.ProviderRecordID != "ofac:sdn:"+r.SourceUID || strings.TrimSpace(r.PrimaryName) == "" || len(r.Programs) == 0 {
			return fmt.Errorf("%w: invalid record %d", ErrInvalidCatalog, i)
		}
		if _, ok := seen[r.ProviderRecordID]; ok {
			return fmt.Errorf("%w: duplicate record", ErrInvalidCatalog)
		}
		seen[r.ProviderRecordID] = struct{}{}
		if r.SourceAssertion.SourceID != "ofac-sls" || r.SourceAssertion.ListID != "SDN" || r.SourceAssertion.SourceRecordID != r.SourceUID {
			return fmt.Errorf("%w: invalid source assertion", ErrInvalidCatalog)
		}
	}
	want, err := catalogChecksum(c)
	if err != nil {
		return err
	}
	if c.CatalogChecksum != want {
		return fmt.Errorf("%w: catalog checksum mismatch", ErrInvalidCatalog)
	}
	return nil
}

func catalogChecksum(c Catalog) (string, error) {
	material := struct {
		SchemaVersion       string                      `json:"schema_version"`
		CatalogID           string                      `json:"catalog_id"`
		CatalogVersion      string                      `json:"catalog_version"`
		CatalogMode         matcherprovider.CatalogMode `json:"catalog_mode"`
		ProjectorVersion    string                      `json:"projector_version"`
		SourceDatasetID     string                      `json:"source_dataset_id"`
		SourceContentSHA256 string                      `json:"source_content_sha256"`
		SourceNamespace     string                      `json:"source_namespace"`
		PublishDate         string                      `json:"publish_date"`
		RecordCount         int                         `json:"record_count"`
		Records             []DirectListRecord          `json:"records"`
	}{c.SchemaVersion, c.CatalogID, c.CatalogVersion, c.CatalogMode, c.ProjectorVersion, c.SourceManifest.DatasetID, c.SourceManifest.ContentSHA256, c.SourceManifest.XMLNamespace, c.SourceManifest.PublishDate, c.RecordCount, c.Records}
	b, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func mapType(v string) (canonical.CandidateType, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "individual":
		return canonical.CandidateIndividual, nil
	case "entity":
		return canonical.CandidateOrganization, nil
	case "vessel":
		return canonical.CandidateVessel, nil
	case "aircraft":
		return canonical.CandidateAircraft, nil
	default:
		return "", fmt.Errorf("%w: unsupported sdnType %q", ErrInvalidCatalog, v)
	}
}
func joinName(a, b string) string {
	return strings.TrimSpace(strings.TrimSpace(a) + " " + strings.TrimSpace(b))
}
func sortedUnique(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func uidNumber(v string) int { n, _ := strconv.Atoi(v); return n }

// Checksum returns the deterministic content checksum used by the direct-list catalog contract.
// The checksum excludes acquisition timestamps but includes source-content identity and projected records.
func Checksum(c Catalog) (string, error) { return catalogChecksum(c) }
