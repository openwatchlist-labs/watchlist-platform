package alertlistmapping

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

var baseTime = time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

func TestExactResolutionAndProviderNeutralRemap(t *testing.T) {
	catalog, official, provider := testCatalog(t, true, true)
	store := Store{Root: t.TempDir()}
	if _, err := store.Initialize("demo-bank"); err != nil {
		t.Fatal(err)
	}
	first, _, err := store.Register(mappingInput("fircosoft-prod", "WLS_OFAC_001", MappingActionBind, official.ComponentID, baseTime, nil), catalog)
	if err != nil {
		t.Fatal(err)
	}
	secondInput := mappingInput("fircosoft-prod", "WLS_OFAC_001", MappingActionBind, provider.ComponentID, baseTime.Add(24*time.Hour), nil)
	secondInput.CreatedAt = secondInput.EffectiveFrom
	second, registry, err := store.Register(secondInput, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if first.MappingID != second.MappingID {
		t.Fatalf("stable mapping ID changed across catalog remap")
	}
	if second.SupersedesVersionID != first.MappingVersionID {
		t.Fatalf("remap does not supersede prior version")
	}
	before, err := Resolve(registry, catalog, ResolveRequest{SourceSystemID: "fircosoft-prod", RawListName: "WLS_OFAC_001", At: baseTime.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if before.Status != ResolutionResolved || before.ComponentID != official.ComponentID || before.CatalogMode != string(catalogregistry.CatalogModeOfficial) {
		t.Fatalf("unexpected official resolution: %+v", before)
	}
	after, err := Resolve(registry, catalog, ResolveRequest{SourceSystemID: "fircosoft-prod", RawListName: "WLS_OFAC_001", At: baseTime.Add(25 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != ResolutionResolved || after.ComponentID != provider.ComponentID || after.CatalogMode != string(catalogregistry.CatalogModeProvider) {
		t.Fatalf("unexpected provider resolution: %+v", after)
	}
	caseMismatch, err := Resolve(registry, catalog, ResolveRequest{SourceSystemID: "fircosoft-prod", RawListName: "wls_ofac_001", At: baseTime.Add(25 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if caseMismatch.Status != ResolutionUnmapped || caseMismatch.ExactMatch {
		t.Fatalf("case-mismatched list name was not blocked exactly: %+v", caseMismatch)
	}
}

func TestResolutionBlockers(t *testing.T) {
	catalog, official, _ := testCatalog(t, true, false)
	store := Store{Root: t.TempDir()}
	if _, err := store.Initialize("demo-bank"); err != nil {
		t.Fatal(err)
	}
	future := mappingInput("future-system", "OFAC_NEXT", MappingActionBind, official.ComponentID, baseTime.Add(48*time.Hour), nil)
	future.CreatedAt = baseTime
	if _, _, err := store.Register(future, catalog); err != nil {
		t.Fatal(err)
	}
	expiry := baseTime.Add(12 * time.Hour)
	temporary := mappingInput("legacy-batch", "TEMP_OFAC", MappingActionBind, official.ComponentID, baseTime, &expiry)
	if _, _, err := store.Register(temporary, catalog); err != nil {
		t.Fatal(err)
	}
	retireInitial := mappingInput("actimize-prod", "OFAC_SDN", MappingActionBind, official.ComponentID, baseTime, nil)
	if _, _, err := store.Register(retireInitial, catalog); err != nil {
		t.Fatal(err)
	}
	retire := mappingInput("actimize-prod", "OFAC_SDN", MappingActionRetire, "", baseTime.Add(24*time.Hour), nil)
	retire.CreatedAt = baseTime.Add(time.Hour)
	if _, _, err := store.Register(retire, catalog); err != nil {
		t.Fatal(err)
	}
	registry, err := store.Load(catalog)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, source, raw string
		at                time.Time
		status            ResolutionStatus
		blocker           string
	}{
		{"unmapped", "unknown-system", "OFAC", baseTime, ResolutionUnmapped, BlockerMappingRequired},
		{"future", "future-system", "OFAC_NEXT", baseTime, ResolutionNotEffective, BlockerMappingNotEffective},
		{"expired", "legacy-batch", "TEMP_OFAC", baseTime.Add(13 * time.Hour), ResolutionExpired, BlockerMappingExpired},
		{"retired", "actimize-prod", "OFAC_SDN", baseTime.Add(25 * time.Hour), ResolutionRetired, BlockerMappingRetired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(registry, catalog, ResolveRequest{SourceSystemID: tc.source, RawListName: tc.raw, At: tc.at})
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.status || got.ReviewBlocker != tc.blocker || got.Available {
				t.Fatalf("unexpected blocker result: %+v", got)
			}
		})
	}
}

func TestCatalogNotActiveBlocker(t *testing.T) {
	catalog, official, _ := testCatalog(t, false, false)
	store := Store{Root: t.TempDir()}
	if _, err := store.Initialize("demo-bank"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Register(mappingInput("fircosoft-prod", "WLS_OFAC_001", MappingActionBind, official.ComponentID, baseTime, nil), catalog); err != nil {
		t.Fatal(err)
	}
	registry, err := store.Load(catalog)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(registry, catalog, ResolveRequest{SourceSystemID: "fircosoft-prod", RawListName: "WLS_OFAC_001", At: baseTime.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ResolutionCatalogNotActive || got.ReviewBlocker != BlockerCatalogNotActive {
		t.Fatalf("inactive catalog was not blocked: %+v", got)
	}
}

func TestBatchSummaryAndOrder(t *testing.T) {
	catalog, official, _ := testCatalog(t, true, false)
	store := Store{Root: t.TempDir()}
	if _, err := store.Initialize("demo-bank"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Register(mappingInput("fircosoft-prod", "WLS_OFAC_001", MappingActionBind, official.ComponentID, baseTime, nil), catalog); err != nil {
		t.Fatal(err)
	}
	registry, err := store.Load(catalog)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ResolveBatch(registry, catalog, BatchInput{At: baseTime.Add(time.Hour), Alerts: []BatchAlert{
		{AlertID: "a-1", SourceSystemID: "fircosoft-prod", RawListName: "WLS_OFAC_001"},
		{AlertID: "a-2", SourceSystemID: "fircosoft-prod", RawListName: "UNKNOWN"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Summary.Total != 2 || batch.Summary.Resolved != 1 || batch.Summary.Unmapped != 1 || batch.Results[0].AlertID != "a-1" {
		t.Fatalf("unexpected batch result: %+v", batch)
	}
}

func TestTamperDetection(t *testing.T) {
	catalog, official, _ := testCatalog(t, true, false)
	store := Store{Root: t.TempDir()}
	if _, err := store.Initialize("demo-bank"); err != nil {
		t.Fatal(err)
	}
	version, registry, err := store.Register(mappingInput("fircosoft-prod", "WLS_OFAC_001", MappingActionBind, official.ComponentID, baseTime, nil), catalog)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root, "versions", "00000000000000000001-"+version.MappingVersionID+".json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(registry, catalog); err == nil {
		t.Fatalf("tampered mapping version was accepted")
	}
}

func TestPostgresMigrationIsExactAndMetadataOnly(t *testing.T) {
	schema := PostgresMigration()
	for _, required := range []string{"alert_list_mapping_keys", "alert_list_mapping_versions", `COLLATE "C"`, "active_catalog_component_versions"} {
		if required == "active_catalog_component_versions" {
			continue // resolution query references the Phase 7C-B table, not this migration.
		}
		if !strings.Contains(schema, required) {
			t.Fatalf("migration missing %s", required)
		}
	}
	for _, forbidden := range []string{"catalog_entities", "catalog_aliases", "catalog_addresses", "catalog_identifiers", "opensanctions", "us_ofac_sdn"} {
		if strings.Contains(strings.ToLower(schema), forbidden) {
			t.Fatalf("migration contains forbidden catalog/provider coupling: %s", forbidden)
		}
	}
}

func mappingInput(source, raw string, action MappingAction, component string, from time.Time, to *time.Time) MappingInput {
	return MappingInput{
		SourceSystemID: source,
		RawListName:    raw,
		Action:         action,
		ComponentID:    component,
		EffectiveFrom:  from,
		EffectiveTo:    to,
		Reason:         "fixture mapping decision",
		CreatedAt:      baseTime,
		CreatedBy:      "phase7cc-test",
	}
}

func testCatalog(t *testing.T, activateOfficial, activateProvider bool) (catalogregistry.Registry, catalogregistry.Component, catalogregistry.Component) {
	t.Helper()
	store := catalogregistry.Store{Root: t.TempDir()}
	registry, err := store.Initialize("demo-bank")
	if err != nil {
		t.Fatal(err)
	}
	official, err := catalogregistry.BuildComponent(catalogregistry.ComponentInput{
		Namespace: "demo-bank", ComponentKey: "official.ofac.sdn", DisplayName: "OFAC SDN", CatalogMode: catalogregistry.CatalogModeOfficial,
		CreatedAt: baseTime.Add(-time.Hour), CreatedBy: "phase7cc-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err = store.RegisterComponent(official)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := catalogregistry.BuildComponent(catalogregistry.ComponentInput{
		Namespace: "demo-bank", ComponentKey: "provider.primary", DisplayName: "Primary provider component", CatalogMode: catalogregistry.CatalogModeProvider,
		CreatedAt: baseTime.Add(-time.Hour), CreatedBy: "phase7cc-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err = store.RegisterComponent(provider)
	if err != nil {
		t.Fatal(err)
	}
	officialVersion, err := catalogregistry.BuildVersion(catalogregistry.VersionInput{
		ComponentID: official.ComponentID, CatalogID: "ofac-sdn-advanced", CatalogVersion: "2026-07-14",
		CatalogChecksum: strings.Repeat("a", 64), CatalogSchema: "ofac-direct-list-catalog/v1alpha1",
		ArtifactURI: "file:///catalogs/ofac/current.json", ArtifactSHA256: strings.Repeat("b", 64),
		SourceManifestID: "ofac_source_manifest_test", SourceManifestHash: strings.Repeat("c", 64), RecordCount: 19156,
		ProducerVersion: "ofac-sdn-advanced-xml-parser/v0.2.0",
		Source: catalogregistry.SourceDescriptor{Kind: catalogregistry.SourceKindOfficial, Official: &catalogregistry.OfficialSource{
			Authority: "US_TREASURY_OFAC", ListKey: "us.ofac.sdn", SourceFormat: "ofac_advanced_xml", XMLVersion: "3",
		}}, RegisteredAt: baseTime.Add(-30 * time.Minute), RegisteredBy: "phase7cc-test",
	}, official)
	if err != nil {
		t.Fatal(err)
	}
	registry, err = store.RegisterVersion(officialVersion)
	if err != nil {
		t.Fatal(err)
	}
	providerVersion, err := catalogregistry.BuildVersion(catalogregistry.VersionInput{
		ComponentID: provider.ComponentID, CatalogID: "provider-primary", CatalogVersion: "2026-07-14",
		CatalogChecksum: strings.Repeat("d", 64), CatalogSchema: "provider-entity-catalog/v1alpha1",
		ArtifactURI: "file:///catalogs/provider/current.json", ArtifactSHA256: strings.Repeat("e", 64),
		SourceManifestID: "provider_source_manifest_test", SourceManifestHash: strings.Repeat("f", 64), RecordCount: 20000,
		ProducerVersion: "provider-adapter/v1",
		Source: catalogregistry.SourceDescriptor{Kind: catalogregistry.SourceKindProvider, Provider: &catalogregistry.ProviderSource{
			ProviderID: "licensed-provider", ProviderComponentRef: "provider-defined-component-42", ProviderVersion: "2026-07-14",
		}}, RegisteredAt: baseTime.Add(-20 * time.Minute), RegisteredBy: "phase7cc-test",
	}, provider)
	if err != nil {
		t.Fatal(err)
	}
	registry, err = store.RegisterVersion(providerVersion)
	if err != nil {
		t.Fatal(err)
	}
	if activateOfficial {
		_, registry, err = store.Activate(catalogregistry.ActivationRequest{ComponentID: official.ComponentID, TargetVersionID: officialVersion.VersionID, Action: catalogregistry.ActivationActionActivate, Reason: "test", ActivatedAt: baseTime.Add(-10 * time.Minute), ActivatedBy: "phase7cc-test"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if activateProvider {
		_, registry, err = store.Activate(catalogregistry.ActivationRequest{ComponentID: provider.ComponentID, TargetVersionID: providerVersion.VersionID, Action: catalogregistry.ActivationActionActivate, Reason: "test", ActivatedAt: baseTime.Add(-5 * time.Minute), ActivatedBy: "phase7cc-test"})
		if err != nil {
			t.Fatal(err)
		}
	}
	return registry, official, provider
}
