package ofacadvanced

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

func fixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "test", "fixtures", "ofac", "advanced", "sdn-advanced-fixture.xml")
}

func TestParseAdvancedFixtureAndProjectCompatibilityCatalog(t *testing.T) {
	path := fixturePath(t)
	a, err := AcquireLocal(path, OfficialSDNXMLURL, time.Date(2026, 7, 14, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	if result.Snapshot.RecordCount != 3 || result.Snapshot.DateOfIssue != "2026-07-13" {
		t.Fatalf("unexpected snapshot header: %+v", result.Snapshot)
	}
	if result.Snapshot.SourceStats.DistinctPartyCount != 3 || result.Snapshot.SourceStats.ProfileCount != 3 || result.Snapshot.SourceStats.SanctionsEntryCount != 3 || result.Snapshot.SourceStats.SelectedSDNEntryCount != 3 || result.Snapshot.SourceStats.FilteredNonSDNEntryCount != 0 {
		t.Fatalf("unexpected source stats: %+v", result.Snapshot.SourceStats)
	}
	if result.Snapshot.SourceManifest.SourceFormat != SourceFormat || result.Snapshot.SourceManifest.XMLSchemaVersion != "3" {
		t.Fatalf("advanced manifest fields missing: %+v", result.Snapshot.SourceManifest)
	}
	var individual Party
	for _, p := range result.Snapshot.Parties {
		if p.UID == 2002 {
			individual = p
		}
	}
	if individual.PrimaryName != "Jordan Example" || len(individual.Names) != 3 {
		t.Fatalf("multiscript names not preserved: %+v", individual.Names)
	}
	foundCyrillic := false
	for _, name := range individual.Names {
		if strings.Contains(strings.ToLower(name.Script), "cyrillic") {
			foundCyrillic = true
		}
	}
	if !foundCyrillic {
		t.Fatal("Cyrillic name was not preserved")
	}
	catalog, err := ofaccatalog.Project(result.Package)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.RecordCount != 3 || catalog.SourceManifest.ParserVersion != ParserVersion {
		t.Fatalf("unexpected compatibility catalog: %+v", catalog)
	}
	if catalog.Records[0].SourceUID != "1001" || catalog.Records[0].PrimaryName != "Acme Imports LLC" {
		t.Fatalf("unexpected first record: %+v", catalog.Records[0])
	}
}

func TestAdvancedFixtureParityWithLegacyFixture(t *testing.T) {
	path := fixturePath(t)
	a, err := AcquireLocal(path, OfficialSDNXMLURL, time.Date(2026, 7, 14, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	advanced, err := ofaccatalog.Project(result.Package)
	if err != nil {
		t.Fatal(err)
	}
	legacyFile, err := os.Open(filepath.Join("..", "..", "test", "golden", "ofac", "ofac-sdn-fixture.catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer legacyFile.Close()
	legacy, err := ofaccatalog.Load(legacyFile)
	if err != nil {
		t.Fatal(err)
	}
	report, err := CompareCatalogs(advanced, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.LinkedUIDs != 3 || report.Summary.AdvancedOnly != 0 || report.Summary.LegacyOnly != 0 || report.Summary.EntityTypeDifferences != 0 || report.Summary.ProgramDifferences != 0 {
		t.Fatalf("unexpected parity summary: %+v", report.Summary)
	}
}

func TestRejectsLegacyNamespaceAndDoctype(t *testing.T) {
	for name, data := range map[string]string{
		"legacy":  `<?xml version="1.0"?><sdnList xmlns="https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML"/>`,
		"doctype": `<?xml version="1.0"?><!DOCTYPE Sanctions><Sanctions xmlns="` + AdvancedXMLNamespace + `" Version="3"/>`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".xml")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			a, err := AcquireLocal(path, OfficialSDNXMLURL, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(a); err == nil {
				t.Fatal("invalid XML accepted")
			}
		})
	}
}

func TestAdvancedURLPolicy(t *testing.T) {
	good := "https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/release/SDN_ADVANCED.XML?X-Amz-Signature=secret"
	if _, err := validateOfficialURL(good); err != nil {
		t.Fatalf("approved redirect rejected: %v", err)
	}
	for _, bad := range []string{
		"http://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN_ADVANCED.XML",
		"https://evil.example/SDN_ADVANCED.XML",
		"https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/release/SDN.XML",
		"https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/private/SDN_ADVANCED.XML",
	} {
		if _, err := validateOfficialURL(bad); err == nil {
			t.Fatalf("bad URL accepted: %s", bad)
		}
	}
	if got := redactURL(good); strings.Contains(got, "Signature") || strings.Contains(got, "secret") {
		t.Fatalf("signed query leaked: %s", got)
	}
}

func TestParseFiltersNonSDNEntriesAndMergesMultipleSDNEntries(t *testing.T) {
	data, err := os.ReadFile(fixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	xmlText := string(data)
	xmlText = strings.Replace(xmlText,
		`<ListValues><List ID="1550">SDN List</List></ListValues>`,
		`<ListValues><List ID="1550">SDN List</List><List ID="1551">Non-SDN Palestinian Legislative Council List</List></ListValues>`, 1)
	nonSDNProfile := `<Profile ID="1002" PartySubTypeID="2"><Identity ID="11002"><Alias FixedRef="100200" ID="100200" AliasTypeID="1" Primary="true" LowQuality="false"><DocumentedName FixedRef="100200" ID="100200"><DocumentedNamePart><NamePartValue NamePartGroupID="21002" ScriptID="215" ScriptStatusID="1" Acronym="false">Filtered PLC Profile</NamePartValue></DocumentedNamePart></DocumentedName></Alias><NamePartGroups><MasterNamePartGroup><NamePartGroup ID="21002" NamePartTypeID="12"/></MasterNamePartGroup></NamePartGroups></Identity></Profile>`
	xmlText = strings.Replace(xmlText, "</Profile>\n    </DistinctParty>", "</Profile>"+nonSDNProfile+"\n    </DistinctParty>", 1)
	extraEntries := `<SanctionsEntry ID="6004" ProfileID="1002" ListID="1551"><EntryEvent ID="6104" LegalBasisID="300" EntryEventTypeID="301"><Date CalendarTypeID="1"><Year>2026</Year><Month>7</Month><Day>13</Day></Date></EntryEvent><SanctionsMeasure SanctionsTypeID="1704"/></SanctionsEntry><SanctionsEntry ID="6005" ProfileID="1001" ListID="1550"><EntryEvent ID="6105" LegalBasisID="300" EntryEventTypeID="301"><Date CalendarTypeID="1"><Year>2026</Year><Month>7</Month><Day>13</Day></Date></EntryEvent><SanctionsMeasure SanctionsTypeID="1705"><Comment>DEMO-TERTIARY</Comment></SanctionsMeasure></SanctionsEntry>`
	xmlText = strings.Replace(xmlText, `</SanctionsEntries>`, extraEntries+`</SanctionsEntries>`, 1)
	path := filepath.Join(t.TempDir(), "sdn-advanced-mixed-lists.xml")
	if err := os.WriteFile(path, []byte(xmlText), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := AcquireLocal(path, OfficialSDNXMLURL, time.Date(2026, 7, 14, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	if result.Snapshot.RecordCount != 3 {
		t.Fatalf("non-SDN profile leaked into the catalog: %d", result.Snapshot.RecordCount)
	}
	stats := result.Snapshot.SourceStats
	if stats.DistinctPartyCount != 3 || stats.ProfileCount != 4 || stats.SanctionsEntryCount != 5 || stats.SelectedSDNEntryCount != 4 || stats.FilteredNonSDNEntryCount != 1 {
		t.Fatalf("unexpected mixed-list stats: %+v", stats)
	}
	for _, party := range result.Snapshot.Parties {
		if party.UID != 1001 {
			continue
		}
		if len(party.ProfileIDs) != 1 || party.ProfileIDs[0] != "1001" {
			t.Fatalf("non-SDN profile was merged: %+v", party.ProfileIDs)
		}
		if !containsString(party.Programs, "DEMO-TERTIARY") {
			t.Fatalf("second SDN entry was not aggregated: %+v", party.Programs)
		}
	}
}

func TestSDNListSelectionUsesExactReferenceValue(t *testing.T) {
	for _, label := range []string{"SDN List", "  sdn   list  "} {
		if !isSDNListLabel(label) {
			t.Fatalf("official SDN label rejected: %q", label)
		}
	}
	for _, label := range []string{"SDN", "Non-SDN List", "Non-SDN Palestinian Legislative Council List", "SSI List", "Consolidated Sanctions List"} {
		if isSDNListLabel(label) {
			t.Fatalf("non-canonical or non-SDN label accepted: %q", label)
		}
	}
}

func TestMissingListIDIsRejectedWhenReferenceDictionaryIsAmbiguous(t *testing.T) {
	data, err := os.ReadFile(fixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	xmlText := string(data)
	xmlText = strings.Replace(xmlText,
		`<ListValues><List ID="1550">SDN List</List></ListValues>`,
		`<ListValues><List ID="1550">SDN List</List><List ID="1551">Non-SDN Palestinian Legislative Council List</List></ListValues>`, 1)
	xmlText = strings.Replace(xmlText, ` ProfileID="1001" ListID="1550"`, ` ProfileID="1001"`, 1)
	path := filepath.Join(t.TempDir(), "ambiguous-list.xml")
	if err := os.WriteFile(path, []byte(xmlText), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := AcquireLocal(path, OfficialSDNXMLURL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(a); err == nil || !strings.Contains(err.Error(), "without ListID is ambiguous") {
		t.Fatalf("ambiguous missing ListID was not rejected: %v", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestParseMergesMultipleProfilesAndIdentitiesPerXSDCardinality(t *testing.T) {
	data, err := os.ReadFile(fixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	xmlText := string(data)
	secondIdentity := `<Identity ID="11004"><Alias FixedRef="100400" ID="100400" AliasTypeID="1" Primary="false" LowQuality="false"><DocumentedName FixedRef="100400" ID="100400"><DocumentedNamePart><NamePartValue NamePartGroupID="21004" ScriptID="215" ScriptStatusID="1" Acronym="false">Acme Secondary Identity</NamePartValue></DocumentedNamePart></DocumentedName></Alias><NamePartGroups><MasterNamePartGroup><NamePartGroup ID="21004" NamePartTypeID="12"/></MasterNamePartGroup></NamePartGroups></Identity>`
	xmlText = strings.Replace(xmlText, `</Identity>
        <Feature ID="1001-F1"`, `</Identity>`+secondIdentity+`
        <Feature ID="1001-F1"`, 1)
	secondProfile := `<Profile ID="1004" PartySubTypeID="2"><Identity ID="11005"><Alias FixedRef="100500" ID="100500" AliasTypeID="1" Primary="true" LowQuality="false"><DocumentedName FixedRef="100500" ID="100500"><DocumentedNamePart><NamePartValue NamePartGroupID="21005" ScriptID="215" ScriptStatusID="1" Acronym="false">Acme Affiliate Profile</NamePartValue></DocumentedNamePart></DocumentedName></Alias><NamePartGroups><MasterNamePartGroup><NamePartGroup ID="21005" NamePartTypeID="12"/></MasterNamePartGroup></NamePartGroups></Identity></Profile>`
	xmlText = strings.Replace(xmlText, `</Profile>
    </DistinctParty>`, `</Profile>`+secondProfile+`
    </DistinctParty>`, 1)
	entry := `<SanctionsEntry ID="6006" ProfileID="1004" ListID="1550"><EntryEvent ID="6106" LegalBasisID="300" EntryEventTypeID="301"><Date CalendarTypeID="1"><Year>2026</Year><Month>7</Month><Day>13</Day></Date></EntryEvent><SanctionsMeasure SanctionsTypeID="1705"><Comment>DEMO-AFFILIATE</Comment></SanctionsMeasure></SanctionsEntry>`
	xmlText = strings.Replace(xmlText, `</SanctionsEntries>`, entry+`</SanctionsEntries>`, 1)
	path := filepath.Join(t.TempDir(), "sdn-advanced-multi-cardinality.xml")
	if err := os.WriteFile(path, []byte(xmlText), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := AcquireLocal(path, OfficialSDNXMLURL, time.Date(2026, 7, 14, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	stats := result.Snapshot.SourceStats
	if stats.DistinctPartyCount != 3 || stats.ProfileCount != 4 || stats.SanctionsEntryCount != 4 || stats.SelectedSDNEntryCount != 4 || stats.FilteredNonSDNEntryCount != 0 {
		t.Fatalf("unexpected multi-cardinality stats: %+v", stats)
	}
	for _, party := range result.Snapshot.Parties {
		if party.UID != 1001 {
			continue
		}
		if len(party.ProfileIDs) != 2 || !containsString(party.ProfileIDs, "1001") || !containsString(party.ProfileIDs, "1004") {
			t.Fatalf("multiple selected profiles were not merged: %+v", party.ProfileIDs)
		}
		for _, identityID := range []string{"11001", "11004", "11005"} {
			if !containsString(party.IdentityIDs, identityID) {
				t.Fatalf("identity %s was not preserved: %+v", identityID, party.IdentityIDs)
			}
		}
		if !containsString(party.Programs, "DEMO-AFFILIATE") {
			t.Fatalf("second profile sanctions entry was not aggregated: %+v", party.Programs)
		}
		if !containsNameValue(party.Names, "Acme Secondary Identity") || !containsNameValue(party.Names, "Acme Affiliate Profile") {
			t.Fatalf("multi-identity/profile names were not merged: %+v", party.Names)
		}
		return
	}
	t.Fatal("UID 1001 not found")
}

func containsNameValue(names []Name, want string) bool {
	for _, name := range names {
		if name.Value == want {
			return true
		}
	}
	return false
}
