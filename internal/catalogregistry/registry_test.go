package catalogregistry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, 7, 14, 18, 30, 0, 0, time.UTC)

func TestStableComponentIDDoesNotDependOnProviderReference(t *testing.T) {
	component, err := BuildComponent(ComponentInput{
		Namespace: "tenant-a", ComponentKey: "sanctions.primary", DisplayName: "Primary sanctions catalog",
		CatalogMode: CatalogModeProvider, CreatedAt: testTime, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildVersion(providerVersionInput(component.ComponentID, "provider-dataset-old", "1", strings.Repeat("1", 64)), component)
	if err != nil {
		t.Fatal(err)
	}
	secondInput := providerVersionInput(component.ComponentID, "provider-dataset-renamed", "2", strings.Repeat("2", 64))
	second, err := BuildVersion(secondInput, component)
	if err != nil {
		t.Fatal(err)
	}
	if first.ComponentID != second.ComponentID || component.ComponentID != componentID("tenant-a", "sanctions.primary") {
		t.Fatalf("stable component ID changed across provider references")
	}
	if first.Source.Provider.ProviderComponentRef == second.Source.Provider.ProviderComponentRef {
		t.Fatalf("fixture did not model provider reference change")
	}
}

func TestOfficialOFACAcceptsAdvancedXMLOnly(t *testing.T) {
	component, err := BuildComponent(ComponentInput{
		Namespace: "tenant-a", ComponentKey: "official.ofac.sdn", DisplayName: "OFAC SDN",
		CatalogMode: CatalogModeOfficial, CreatedAt: testTime, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	input := officialVersionInput(component.ComponentID, "1", strings.Repeat("a", 64))
	if _, err := BuildVersion(input, component); err != nil {
		t.Fatalf("advanced XML rejected: %v", err)
	}
	input.Source.Official.SourceFormat = "ofac_legacy_sdn_xml"
	if _, err := BuildVersion(input, component); err == nil || !strings.Contains(err.Error(), "only ofac_advanced_xml") {
		t.Fatalf("legacy OFAC format was not rejected: %v", err)
	}
}

func TestFileStoreActivationAndRollbackAuditChain(t *testing.T) {
	store := Store{Root: t.TempDir()}
	registry, err := store.Initialize("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	component, err := BuildComponent(ComponentInput{
		Namespace: registry.Namespace, ComponentKey: "official.ofac.sdn", DisplayName: "OFAC SDN",
		CatalogMode: CatalogModeOfficial, CreatedAt: testTime, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.RegisterComponent(component); err != nil {
		t.Fatal(err)
	}
	v1, err := BuildVersion(officialVersionInput(component.ComponentID, "1", strings.Repeat("a", 64)), component)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := BuildVersion(officialVersionInput(component.ComponentID, "2", strings.Repeat("b", 64)), component)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.RegisterVersion(v1); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RegisterVersion(v2); err != nil {
		t.Fatal(err)
	}
	first, _, err := store.Activate(ActivationRequest{
		ComponentID: component.ComponentID, TargetVersionID: v1.VersionID, Action: ActivationActionActivate,
		Reason: "initial production activation", ActivatedAt: testTime.Add(time.Hour), ActivatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := store.Activate(ActivationRequest{
		ComponentID: component.ComponentID, TargetVersionID: v2.VersionID, Action: ActivationActionActivate,
		ExpectedCurrentVersionID: v1.VersionID, Reason: "approved refresh", ActivatedAt: testTime.Add(2 * time.Hour), ActivatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	rollback, final, err := store.Activate(ActivationRequest{
		ComponentID: component.ComponentID, TargetVersionID: v1.VersionID, Action: ActivationActionRollback,
		ExpectedCurrentVersionID: v2.VersionID, Reason: "rollback rehearsal", ActivatedAt: testTime.Add(3 * time.Hour), ActivatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || second.PreviousEventHash != first.EventHash || rollback.PreviousEventHash != second.EventHash {
		t.Fatalf("activation audit chain is not continuous")
	}
	if len(final.Active) != 1 || final.Active[0].VersionID != v1.VersionID || final.Active[0].Epoch != 3 {
		t.Fatalf("unexpected active pointer: %+v", final.Active)
	}
	if err := store.Verify(final); err != nil {
		t.Fatal(err)
	}
}

func TestStoreDetectsTamperedImmutableVersion(t *testing.T) {
	store := Store{Root: t.TempDir()}
	registry, err := store.Initialize("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	component, _ := BuildComponent(ComponentInput{
		Namespace: registry.Namespace, ComponentKey: "provider.primary", DisplayName: "Provider catalog",
		CatalogMode: CatalogModeProvider, CreatedAt: testTime, CreatedBy: "admin",
	})
	if _, err = store.RegisterComponent(component); err != nil {
		t.Fatal(err)
	}
	version, _ := BuildVersion(providerVersionInput(component.ComponentID, "dataset-a", "1", strings.Repeat("c", 64)), component)
	registry, err = store.RegisterVersion(version)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root, "versions", version.VersionID+".json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(registry); err == nil {
		t.Fatalf("tampered immutable version was accepted")
	}
}

func TestPostgresMigrationStoresOnlyControlPlaneMetadata(t *testing.T) {
	schema := PostgresMigration()
	for _, table := range []string{"catalog_components", "catalog_component_versions", "catalog_component_activations", "active_catalog_component_versions"} {
		if !strings.Contains(schema, table) {
			t.Fatalf("migration missing %s", table)
		}
	}
	for _, forbidden := range []string{"catalog_entity", "catalog_alias", "catalog_address", "catalog_identifier"} {
		if strings.Contains(schema, forbidden) {
			t.Fatalf("migration unexpectedly stores full catalog rows: %s", forbidden)
		}
	}
}

func officialVersionInput(componentID, version, checksum string) VersionInput {
	return VersionInput{
		ComponentID: componentID, CatalogID: "ofac-sdn-advanced", CatalogVersion: version,
		CatalogChecksum: checksum, CatalogSchema: "ofac-direct-list-catalog/v1alpha1",
		ArtifactURI: "file:///catalogs/ofac/" + version + "/ofac-sdn-catalog.json", ArtifactSHA256: checksum,
		SourceManifestID: "ofac_source_manifest_" + version, SourceManifestHash: strings.Repeat("d", 64), RecordCount: 19156,
		ProducerVersion: "ofac-sdn-advanced-xml-parser/v0.2.0",
		Source: SourceDescriptor{Kind: SourceKindOfficial, Official: &OfficialSource{
			Authority: "US_TREASURY_OFAC", ListKey: "us.ofac.sdn", SourceFormat: "ofac_advanced_xml", XMLVersion: "3",
		}},
		RegisteredAt: testTime.Add(time.Duration(len(version)) * time.Minute), RegisteredBy: "admin",
	}
}

func providerVersionInput(componentID, ref, version, checksum string) VersionInput {
	return VersionInput{
		ComponentID: componentID, CatalogID: "provider-primary", CatalogVersion: version,
		CatalogChecksum: checksum, CatalogSchema: "provider-entity-catalog/v1alpha1",
		ArtifactURI: "s3://catalogs/provider/" + version + "/catalog.json", ArtifactSHA256: checksum,
		SourceManifestID: "provider_source_manifest_" + version, SourceManifestHash: strings.Repeat("e", 64), RecordCount: 20000,
		ProducerVersion: "provider-adapter/v1",
		Source: SourceDescriptor{Kind: SourceKindProvider, Provider: &ProviderSource{
			ProviderID: "licensed-provider", ProviderComponentRef: ref, ProviderTitle: "Provider-defined sanctions component", ProviderVersion: version,
		}},
		RegisteredAt: testTime.Add(time.Duration(len(version)) * time.Minute), RegisteredBy: "admin",
	}
}
