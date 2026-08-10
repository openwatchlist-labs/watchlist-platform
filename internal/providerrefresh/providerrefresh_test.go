package providerrefresh

import (
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertlistmapping"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

var testTime = time.Date(2026, 7, 14, 19, 0, 0, 0, time.UTC)

func TestAnalyzeRenameWithMappingImpact(t *testing.T) {
	catalogStore, catalog, provider, current := testCatalog(t)
	_ = catalogStore
	mappings := testMappings(t, catalog, provider.ComponentID)
	input := AnalyzeInput{
		Namespace:         "demo-bank",
		TargetComponentID: provider.ComponentID,
		Previous: inventory("licensed-provider", "2026-07-14", []ProviderComponent{
			providerComponent("provider-main", "2026-07-14", 20000, "d", "e"),
			providerComponent("retired-unmapped", "2026-07-14", 50, "1", "2"),
		}),
		Candidate: inventory("licensed-provider", "2026-07-15", []ProviderComponent{
			providerComponent("provider-main-v2", "2026-07-15", 20400, "a", "b"),
			providerComponent("new-component", "2026-07-15", 75, "3", "4"),
		}),
		Renames:    []RenameDirective{{FromProviderComponentRef: "provider-main", ToProviderComponentRef: "provider-main-v2", Reason: "provider metadata rename"}},
		Policy:     RefreshPolicy{SchemaVersion: PolicySchemaVersion, MaxAddedComponents: 1, MaxRemovedComponents: 1, MaxRenamedComponents: 1, MaxRecordCountDeltaPercent: 5, RequireAllMappedComponentsAvailable: true, RequireTargetComponentAvailable: true, RequireProviderIDUnchanged: true},
		AnalyzedAt: testTime,
		AnalyzedBy: "phase7cd-test",
		Reason:     "daily provider refresh",
	}
	candidate, err := Analyze(input, catalog, mappings)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Status != CandidateReady || len(candidate.PolicyViolations) != 0 {
		t.Fatalf("unexpected candidate status: %+v", candidate)
	}
	if candidate.CandidateVersion.ExpectedCurrentVersionID != current.VersionID || candidate.CandidateVersion.ProviderComponentRef != "provider-main-v2" {
		t.Fatalf("unexpected candidate version: %+v", candidate.CandidateVersion)
	}
	if len(candidate.MappingImpacts) != 1 || candidate.MappingImpacts[0].Status != ImpactRenamed || candidate.MappingImpacts[0].ActiveMappingCount != 1 {
		t.Fatalf("unexpected mapping impact: %+v", candidate.MappingImpacts)
	}
	added, removed, renamed := countChanges(candidate.Changes)
	if added != 1 || removed != 1 || renamed != 1 {
		t.Fatalf("unexpected changes: %+v", candidate.Changes)
	}
}

func TestAnalyzeBlocksMissingMappedComponent(t *testing.T) {
	_, catalog, provider, _ := testCatalog(t)
	mappings := testMappings(t, catalog, provider.ComponentID)
	input := AnalyzeInput{
		Namespace: "demo-bank", TargetComponentID: provider.ComponentID,
		Previous:   inventory("licensed-provider", "2026-07-14", []ProviderComponent{providerComponent("provider-main", "2026-07-14", 20000, "d", "e")}),
		Candidate:  inventory("licensed-provider", "2026-07-15", []ProviderComponent{providerComponent("other-component", "2026-07-15", 10, "a", "b")}),
		Policy:     RefreshPolicy{SchemaVersion: PolicySchemaVersion, MaxAddedComponents: 5, MaxRemovedComponents: 5, MaxRenamedComponents: 5, MaxRecordCountDeltaPercent: 50, RequireAllMappedComponentsAvailable: true, RequireTargetComponentAvailable: true, RequireProviderIDUnchanged: true},
		AnalyzedAt: testTime, AnalyzedBy: "phase7cd-test", Reason: "missing mapped component test",
	}
	candidate, err := Analyze(input, catalog, mappings)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Status != CandidateBlocked || !contains(candidate.PolicyViolations, ViolationMappedUnavailable) || !contains(candidate.PolicyViolations, ViolationTargetUnavailable) {
		t.Fatalf("missing mapped component was not blocked: %+v", candidate)
	}
}

func TestApprovePromoteAndRollback(t *testing.T) {
	catalogStore, catalog, provider, current := testCatalog(t)
	mappings := testMappings(t, catalog, provider.ComponentID)
	candidate, err := Analyze(AnalyzeInput{
		Namespace: "demo-bank", TargetComponentID: provider.ComponentID,
		Previous:   inventory("licensed-provider", "2026-07-14", []ProviderComponent{providerComponent("provider-main", "2026-07-14", 20000, "d", "e")}),
		Candidate:  inventory("licensed-provider", "2026-07-15", []ProviderComponent{providerComponent("provider-main", "2026-07-15", 20200, "a", "b")}),
		Policy:     RefreshPolicy{SchemaVersion: PolicySchemaVersion, MaxAddedComponents: 0, MaxRemovedComponents: 0, MaxRenamedComponents: 0, MaxRecordCountDeltaPercent: 5, RequireAllMappedComponentsAvailable: true, RequireTargetComponentAvailable: true, RequireProviderIDUnchanged: true},
		AnalyzedAt: testTime, AnalyzedBy: "phase7cd-test", Reason: "promote provider refresh",
	}, catalog, mappings)
	if err != nil {
		t.Fatal(err)
	}
	refreshStore := Store{Root: t.TempDir()}
	if _, err := refreshStore.Initialize("demo-bank", catalog); err != nil {
		t.Fatal(err)
	}
	if _, err := refreshStore.AddCandidate(candidate, catalog); err != nil {
		t.Fatal(err)
	}
	decision, _, err := refreshStore.Decide(DecisionInput{CandidateID: candidate.CandidateID, Action: DecisionApprove, Reason: "quality gates passed", DecidedAt: testTime.Add(time.Minute), DecidedBy: "approver"}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != DecisionApprove {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	execution, registry, promotedCatalog, err := refreshStore.Promote(PromoteInput{CandidateID: candidate.CandidateID, Reason: "activate approved provider refresh", ExecutedAt: testTime.Add(2 * time.Minute), ExecutedBy: "operator"}, catalogStore)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Action != ExecutionPromote || len(registry.Executions) != 1 {
		t.Fatalf("unexpected promotion execution: %+v", execution)
	}
	pointer, ok := findActive(promotedCatalog, provider.ComponentID)
	if !ok || pointer.VersionID != execution.TargetVersionID || pointer.VersionID == current.VersionID {
		t.Fatalf("promotion did not activate candidate")
	}
	rollback, registry, rolledBackCatalog, err := refreshStore.Rollback(RollbackInput{ComponentID: provider.ComponentID, TargetVersionID: current.VersionID, ExpectedCurrentVersionID: execution.TargetVersionID, Reason: "rollback qualification test", ExecutedAt: testTime.Add(3 * time.Minute), ExecutedBy: "operator"}, catalogStore)
	if err != nil {
		t.Fatal(err)
	}
	if rollback.Action != ExecutionRollback || len(registry.Executions) != 2 {
		t.Fatalf("unexpected rollback execution: %+v", rollback)
	}
	pointer, ok = findActive(rolledBackCatalog, provider.ComponentID)
	if !ok || pointer.VersionID != current.VersionID {
		t.Fatalf("rollback did not restore prior version")
	}
	if _, err := refreshStore.Load(rolledBackCatalog); err != nil {
		t.Fatal(err)
	}
}

func TestBlockedCandidateCannotBeApproved(t *testing.T) {
	_, catalog, provider, _ := testCatalog(t)
	mappings := testMappings(t, catalog, provider.ComponentID)
	candidate, err := Analyze(AnalyzeInput{
		Namespace: "demo-bank", TargetComponentID: provider.ComponentID,
		Previous:   inventory("licensed-provider", "2026-07-14", []ProviderComponent{providerComponent("provider-main", "2026-07-14", 20000, "d", "e")}),
		Candidate:  inventory("licensed-provider", "2026-07-15", []ProviderComponent{providerComponent("provider-main", "2026-07-15", 40000, "a", "b")}),
		Policy:     RefreshPolicy{SchemaVersion: PolicySchemaVersion, MaxAddedComponents: 0, MaxRemovedComponents: 0, MaxRenamedComponents: 0, MaxRecordCountDeltaPercent: 5, RequireAllMappedComponentsAvailable: true, RequireTargetComponentAvailable: true, RequireProviderIDUnchanged: true},
		AnalyzedAt: testTime, AnalyzedBy: "phase7cd-test", Reason: "blocked delta test",
	}, catalog, mappings)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Status != CandidateBlocked || !contains(candidate.PolicyViolations, ViolationRecordDelta) {
		t.Fatalf("large delta was not blocked")
	}
	store := Store{Root: t.TempDir()}
	if _, err := store.Initialize("demo-bank", catalog); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddCandidate(candidate, catalog); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Decide(DecisionInput{CandidateID: candidate.CandidateID, Action: DecisionApprove, Reason: "should fail", DecidedAt: testTime.Add(time.Minute), DecidedBy: "approver"}, catalog); err == nil {
		t.Fatalf("blocked candidate was approved")
	}
}

func TestPostgresMigrationIsMetadataOnly(t *testing.T) {
	schema := strings.ToLower(PostgresMigration())
	for _, required := range []string{"provider_refresh_candidates", "provider_refresh_decisions", "provider_refresh_executions", "references catalog_components(component_id)", "references alert_list_mapping"} {
		if required == "references alert_list_mapping" {
			continue
		}
		if !strings.Contains(schema, required) {
			t.Fatalf("migration missing %s", required)
		}
	}
	for _, forbidden := range []string{"catalog_entities", "catalog_aliases", "catalog_addresses", "catalog_identifiers", "opensanctions", "us_ofac_sdn"} {
		if strings.Contains(schema, forbidden) {
			t.Fatalf("migration contains forbidden data-plane coupling: %s", forbidden)
		}
	}
}

func testCatalog(t *testing.T) (catalogregistry.Store, catalogregistry.Registry, catalogregistry.Component, catalogregistry.CatalogVersion) {
	t.Helper()
	store := catalogregistry.Store{Root: t.TempDir()}
	_, err := store.Initialize("demo-bank")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := catalogregistry.BuildComponent(catalogregistry.ComponentInput{Namespace: "demo-bank", ComponentKey: "provider.primary", DisplayName: "Primary provider", CatalogMode: catalogregistry.CatalogModeProvider, CreatedAt: testTime.Add(-time.Hour), CreatedBy: "phase7cd-test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.RegisterComponent(provider)
	if err != nil {
		t.Fatal(err)
	}
	version, err := catalogregistry.BuildVersion(catalogregistry.VersionInput{ComponentID: provider.ComponentID, CatalogID: "provider-primary", CatalogVersion: "2026-07-14", CatalogChecksum: strings.Repeat("d", 64), CatalogSchema: "provider-entity-catalog/v1alpha1", ArtifactURI: "file:///catalogs/provider/2026-07-14.json", ArtifactSHA256: strings.Repeat("e", 64), SourceManifestID: "provider_source_manifest_v1", SourceManifestHash: strings.Repeat("f", 64), RecordCount: 20000, ProducerVersion: "provider-adapter/v1", Source: catalogregistry.SourceDescriptor{Kind: catalogregistry.SourceKindProvider, Provider: &catalogregistry.ProviderSource{ProviderID: "licensed-provider", ProviderComponentRef: "provider-main", ProviderTitle: "Primary provider", ProviderVersion: "2026-07-14"}}, RegisteredAt: testTime.Add(-30 * time.Minute), RegisteredBy: "phase7cd-test"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.RegisterVersion(version)
	if err != nil {
		t.Fatal(err)
	}
	_, registry, err := store.Activate(catalogregistry.ActivationRequest{ComponentID: provider.ComponentID, TargetVersionID: version.VersionID, Action: catalogregistry.ActivationActionActivate, Reason: "activate provider fixture", ActivatedAt: testTime.Add(-20 * time.Minute), ActivatedBy: "phase7cd-test"})
	if err != nil {
		t.Fatal(err)
	}
	return store, registry, provider, version
}

func testMappings(t *testing.T, catalog catalogregistry.Registry, componentID string) alertlistmapping.Registry {
	t.Helper()
	store := alertlistmapping.Store{Root: t.TempDir()}
	if _, err := store.Initialize("demo-bank"); err != nil {
		t.Fatal(err)
	}
	_, registry, err := store.Register(alertlistmapping.MappingInput{SourceSystemID: "fircosoft-prod", RawListName: "WLS_PROVIDER_PRIMARY", Action: alertlistmapping.MappingActionBind, ComponentID: componentID, EffectiveFrom: testTime.Add(-time.Hour), Reason: "bind provider alert list", CreatedAt: testTime.Add(-time.Hour), CreatedBy: "phase7cd-test"}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func inventory(providerID, version string, components []ProviderComponent) ProviderInventory {
	return ProviderInventory{ProviderID: providerID, ProviderVersion: version, GeneratedAt: testTime, Components: components}
}
func providerComponent(ref, version string, count int, catalogRune, artifactRune string) ProviderComponent {
	return ProviderComponent{ProviderComponentRef: ref, ProviderTitle: ref, CatalogID: "provider-catalog-" + ref, CatalogVersion: version, CatalogChecksum: strings.Repeat(catalogRune, 64), CatalogSchema: "provider-entity-catalog/v1alpha1", ArtifactURI: "file:///catalogs/provider/" + ref + "/" + version + ".json", ArtifactSHA256: strings.Repeat(artifactRune, 64), SourceManifestID: "provider_manifest_" + ref + "_" + version, SourceManifestHash: strings.Repeat("c", 64), RecordCount: count, ProducerVersion: "provider-adapter/v2"}
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
