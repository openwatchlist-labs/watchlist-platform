package screeningapi

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertlistmapping"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

// This file is DOM-1's regression guard, not DOM-1 itself (see README.md's
// Table 1, "Current matching capability"). It proves, against the LIVE
// screening path and the real compiled Rust runtime, that today's system
// genuinely returns no candidates for the variant classes Table 1 marks
// "Not supported". It must never gain fuzzy/transliteration/phonetic/
// reordering logic to make a case here pass -- that is DOM-1 itself, a
// separate, deliberately-unstarted initiative. When DOM-1 lands and one of
// these variants starts matching on purpose, the corresponding case here
// must be UPDATED (its assertion flipped and comment revised), not deleted.
//
// Unlike service_test.go and scoring_integration_test.go, which stand up
// Service against a fakeRuntime that returns a fixed candidate list
// regardless of the query (a fine choice for exercising response shaping,
// blockers, and scoring wiring, but useless here -- it would make every
// case in this file pass by construction and prove nothing about real
// matching behavior), these tests build and run the actual
// runtime/catalog-mmap Rust worker binary against the real compiled
// package this service serves in production
// (test/golden/runtime-mmap/ofac-fixture.owmmap, package_sha256
// 8c5e581a...), through the same StartRuntimeManager/RuntimeManager
// production wiring cmd/screening-api/main.go uses. Query values are known
// variants of real names/aliases in that compiled catalog's 3-record
// source (test/golden/ofac-advanced/ofac-sdn-catalog.json), confirmed
// against the live worker before being committed here.

var (
	dom1RuntimeBinaryOnce sync.Once
	dom1RuntimeBinaryPath string
	dom1RuntimeBinaryErr  error
)

// buildDOM1RuntimeBinary compiles the real catalog-mmap worker
// (runtime/catalog-mmap, dependency-free per CLAUDE.md rule 1, so this is a
// fast, offline build) into a private temp directory, once per test
// process. It skips (rather than fails) when the Rust toolchain isn't on
// PATH, so a Go-only environment can still run `go test ./...` cleanly;
// every environment that runs scripts/ci/run-ci.sh has cargo/rustc as a
// hard requirement already, so this suite is a no-op skip only outside
// that gate.
func buildDOM1RuntimeBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not on PATH: DOM-1 regression suite needs the real runtime/catalog-mmap worker built from source")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc not on PATH: DOM-1 regression suite needs the real runtime/catalog-mmap worker built from source")
	}
	dom1RuntimeBinaryOnce.Do(func() {
		manifest, err := filepath.Abs(filepath.Join("..", "..", "runtime", "catalog-mmap", "Cargo.toml"))
		if err != nil {
			dom1RuntimeBinaryErr = err
			return
		}
		outDir, err := os.MkdirTemp("", "dom1-catalog-mmap-*")
		if err != nil {
			dom1RuntimeBinaryErr = err
			return
		}
		cmd := exec.Command("cargo", "build", "--locked", "--manifest-path", manifest, "--bin", "catalog-mmap", "--target-dir", outDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			dom1RuntimeBinaryErr = fmt.Errorf("cargo build catalog-mmap worker: %w\n%s", err, out)
			return
		}
		dom1RuntimeBinaryPath = filepath.Join(outDir, "debug", "catalog-mmap")
	})
	if dom1RuntimeBinaryErr != nil {
		t.Fatalf("build real catalog-mmap runtime worker: %v", dom1RuntimeBinaryErr)
	}
	return dom1RuntimeBinaryPath
}

// dom1LiveService builds a *Service wired to the real Rust runtime worker
// serving the real compiled ofac-fixture.owmmap package, through the exact
// production RuntimeManager wiring (StartRuntimeManager) cmd/screening-api
// uses -- not a mock. The catalog/mapping registries are the same golden
// fixtures every other screeningapi test loads (loadGoldenState), and the
// runtime binding below mirrors test/fixtures/screening-api/config.json's
// real production binding for this exact package.
func dom1LiveService(t *testing.T) *Service {
	t.Helper()
	binaryPath := buildDOM1RuntimeBinary(t)
	state := loadGoldenState(t)
	packagePath, err := filepath.Abs(filepath.Join("..", "..", "test", "golden", "runtime-mmap", "ofac-fixture.owmmap"))
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		RuntimeBinaryPath: binaryPath,
		RuntimeBindings: []RuntimeBinding{
			{
				ComponentID:   "catalog_component_ed835720fdb2b3a505927488",
				VersionID:     "catalog_version_10c16906983641525bcc85a4",
				PackagePath:   packagePath,
				PackageSHA256: "8c5e581ad36807c15a2ae00c5cb4e8b7f9154e208b369ff3227617294a473367",
				WorkerCount:   1,
			},
		},
	}
	// StartRuntimeManager's internal Ready() check requires a bound
	// runtime for every active component in the catalog it's given, not
	// just the one this test cares about -- the golden registry's second,
	// unrelated provider component (catalog_component_da31b8f4...) has no
	// package fixture here. That check is only about what this call is
	// asked to validate, so it's given a copy with Active filtered to the
	// OFAC component; the Service below still loads the real, unfiltered
	// golden state via staticLoader, so request-time list mapping and
	// catalog-version resolution are untouched.
	runtimeCheckCatalog := state.Catalog
	runtimeCheckCatalog.Active = nil
	for _, pointer := range state.Catalog.Active {
		if pointer.ComponentID == "catalog_component_ed835720fdb2b3a505927488" {
			runtimeCheckCatalog.Active = append(runtimeCheckCatalog.Active, pointer)
		}
	}
	manager, err := StartRuntimeManager(context.Background(), config, runtimeCheckCatalog)
	if err != nil {
		t.Fatalf("start real runtime manager against the compiled fixture package: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return &Service{
		Loader:        staticLoader{state},
		Runtime:       manager,
		MaxCandidates: 20,
		Clock:         func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") },
		Scoring:       testScoringBinding(t),
	}
}

// dom1Request builds a name-query ScreeningRequest against the same
// mapped list (WLS_OFAC_001 -> catalog_component_ed835720fdb2b3a505927488)
// every other screeningapi test resolves through loadGoldenState's golden
// mapping registry. TargetEntityTypes is left empty so entity-type
// filtering never masks a would-be match -- a case here must fail to match
// because the runtime found nothing, not because a type filter discarded a
// real hit.
func dom1Request(id, queryValue string) ScreeningRequest {
	at, _ := time.Parse(time.RFC3339, "2026-07-20T12:00:00Z")
	return ScreeningRequest{
		SchemaVersion:  RequestSchemaVersion,
		RequestID:      id,
		SourceSystemID: "fircosoft-prod",
		RawListName:    "WLS_OFAC_001",
		EffectiveAt:    at,
		Query:          Query{Kind: QueryName, Value: queryValue, Limit: 20},
	}
}

// TestDOM1LiveRuntimeSanityControlsStillMatch is not a Table-1 "Not
// supported" case. It proves this file's harness actually exercises live
// matching (rather than, say, a misconfigured binding that returns zero
// candidates for every query, which would make every "Not supported" case
// below pass vacuously). Each value here is a real, exact alias in the
// compiled catalog's source
// (test/golden/ofac-advanced/ofac-sdn-catalog.json) and must still match
// today per Table 1's "Exact normalized name | Supported" row.
func TestDOM1LiveRuntimeSanityControlsStillMatch(t *testing.T) {
	service := dom1LiveService(t)
	ctx := context.Background()
	controls := []struct {
		name, query, wantRecordID string
	}{
		{"acme-imports-alias", "ACME IMPORTS", "ofac:sdn:1001"},
		{"mv-example-alias", "MV EXAMPLE", "ofac:sdn:3003"},
		{"cyrillic-alias-exact-bytes", "Джордан Экзампл", "ofac:sdn:2002"},
	}
	for _, control := range controls {
		t.Run(control.name, func(t *testing.T) {
			response, err := service.Screen(ctx, dom1Request("dom1-control-"+control.name, control.query), "corr-dom1-control", "idem-dom1-control-"+control.name)
			if err != nil {
				t.Fatal(err)
			}
			if response.Status != StatusMatched || response.CandidateCount == 0 || response.Candidates[0].RecordID != control.wantRecordID {
				t.Fatalf("control query %q: expected a match on %s, got status=%s candidates=%+v (if this control fails, the cases below are not a valid regression guard)", control.query, control.wantRecordID, response.Status, response.Candidates)
			}
		})
	}
}

// TestDOM1UnsupportedMatchingVariantsProduceNoMatchToday is the regression
// guard itself: one case per "Not supported" row in README.md Table 1,
// each a known variant of a real name/alias in the compiled catalog's
// source (test/golden/ofac-advanced/ofac-sdn-catalog.json, compiled into
// test/golden/runtime-mmap/ofac-fixture.owmmap). Every query below was
// run against the live worker before being committed and confirmed to
// return zero candidates.
func TestDOM1UnsupportedMatchingVariantsProduceNoMatchToday(t *testing.T) {
	service := dom1LiveService(t)
	ctx := context.Background()

	cases := []struct {
		name, query string
	}{
		{
			// Table 1: "Typo / character transposition | Not supported".
			// One-character transposition of the real alias "ACME IMPORTS"
			// (ofac:sdn:1001, org): O/R swapped, IMPORTS -> IMPROTS.
			name:  "typo_character_transposition",
			query: "ACME IMPROTS",
		},
		{
			// Table 1: "Token reordering | Not supported". Real alias
			// "ACME IMPORTS" (ofac:sdn:1001) with its two tokens swapped.
			name:  "token_reordering",
			query: "IMPORTS ACME",
		},
		// Table 1: "Name particles and compounds (AL, BIN, VAN DER) | Not
		// supported" is NOT a case in this slice. It used to live here as
		// query "EXAMPLE" against the real vessel alias "MV EXAMPLE"
		// (ofac:sdn:3003), reasoned as a stand-in because none of the 3
		// records in this shared catalog
		// (test/golden/ofac-advanced/ofac-sdn-catalog.json) contain a true
		// name particle. Investigation for issue #115's parent DOM-1
		// scoping work confirmed that case passed for an unrelated reason:
		// internal/screeningapi/service.go always sends the runtime wire
		// protocol's prefix field as 0 (see
		// runtime/catalog-mmap/src/format.rs's PackageView::lookup_name),
		// and the Go client never tokenizes a query or strips a leading
		// word like "MV" -- so "EXAMPLE" was just an exact-match miss
		// against "Example Vessel"/"MV EXAMPLE" on ordinary string
		// inequality, not a prefix collision and not a particle-aware
		// match attempt of any kind. No particle logic was exercised
		// either way. See
		// TestDOM1UnsupportedMatchingVariantParticleAndCompoundProducesNoMatchToday
		// below, which tests a genuine particle/compound record (Klaas van
		// der Berg, a real "van der" particle) in a small, dedicated
		// compiled package instead.
		{
			// Table 1: "Concatenation splitting (KRAYINVESTBANK <-> KRAY
			// INVEST BANK) | Not supported". Direct structural analog: the
			// real two-token alias "ACME IMPORTS" (ofac:sdn:1001)
			// concatenated with no space, exactly as KRAYINVESTBANK
			// relates to KRAY INVEST BANK.
			name:  "concatenation_splitting",
			query: "ACMEIMPORTS",
		},
		{
			// Table 1: "Transliteration / cross-script | Not supported".
			// The real record ofac:sdn:2002 carries a genuine Cyrillic
			// alias, "Джордан Экзампл" (a.k.a. of primary_name "Jordan
			// Example"). "DZHORDAN EKZAMPL" is a reasoned Latin
			// transliteration of that Cyrillic alias's pronunciation,
			// deliberately spelled differently from the record's own Latin
			// primary_name "Jordan Example" so this case cannot pass via
			// an unrelated exact-name hit -- a match here could only come
			// from genuine cross-script transliteration equivalence.
			name:  "transliteration_cross_script",
			query: "DZHORDAN EKZAMPL",
		},
		{
			// Table 1: "Phonetic | Not supported". Reasoned synthetic
			// phonetic-equivalent misspelling of the real alias "ACME
			// IMPORTS" (ofac:sdn:1001): same approximate pronunciation,
			// different letters (AKMEE ~ ACME, IMPORTZ ~ IMPORTS). We have
			// no verified phonetic-algorithm ground truth for this
			// fixture, so this stands in for a genuine same-Soundex/
			// same-Metaphone pair.
			name:  "phonetic",
			query: "AKMEE IMPORTZ",
		},
		{
			// Table 1: "Non-ASCII case variants (Cyrillic, Greek, Arabic)
			// | Not supported; normalize_ascii folds only bytes < 0x80".
			// Real Cyrillic alias "Джордан Экзампл" (ofac:sdn:2002)
			// lower-cased. Since normalize_ascii only folds ASCII bytes,
			// this byte-for-byte differs from the stored alias's case and
			// must not match.
			name:  "non_ascii_case_variants",
			query: "джордан экзампл",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			response, err := service.Screen(ctx, dom1Request("dom1-"+testCase.name, testCase.query), "corr-"+testCase.name, "idem-"+testCase.name)
			if err != nil {
				t.Fatal(err)
			}
			if response.Status != StatusNoCandidates || response.CandidateCount != 0 || len(response.Candidates) != 0 {
				t.Fatalf("query %q unexpectedly matched against the live runtime -- this test exists to prove Table 1's claim is accurate today, and must be updated (not deleted) when DOM-1 changes this behavior: status=%s candidates=%+v", testCase.query, response.Status, response.Candidates)
			}
		})
	}
}

// dom1ParticleService builds a *Service against a small, dedicated compiled
// package (test/fixtures/screening-api/dom1-particle/dom1-particle-fixture.owmmap)
// containing exactly one record with a genuine name particle/compound,
// "Klaas van der Berg" -- rather than extending the shared
// test/golden/runtime-mmap/ofac-fixture.owmmap package dom1LiveService uses.
// That shared package's exact package_sha256 is pinned in many places
// outside this file (test/fixtures/screening-api/config.json,
// test/fixtures/scoring-activation/state-ofac-sdn-direct/**,
// internal/mmapcatalogcontract's format/decode tests, and even the
// read-only .clean-restart/import-manifest.json), so adding a record to it
// would not be the "small, isolated fix" this task calls for. The
// catalog/registry/mapping wiring below is built fresh in memory (via
// catalogregistry.Store / alertlistmapping.Store, same as
// internal/providerrefresh's tests) so nothing on disk outside this
// package's own new fixture files is touched.
//
// The compiled package and its source catalog were produced with, in
// order (source XML at
// test/fixtures/screening-api/dom1-particle/sdn-particle-fixture.xml):
//
//	go run ./cmd/live-catalog-sync ofac \
//	  --input test/fixtures/screening-api/dom1-particle/sdn-particle-fixture.xml \
//	  --acquired-at 2026-08-14T00:00:00Z --output-dir <dir>
//	go run ./cmd/runtime-catalog-input \
//	  --catalog <dir>/ofac-sdn-catalog.json \
//	  --component-id catalog_component_b1bed6f60480cb3272a9cf77 \
//	  --output <dir>/dom1-particle-fixture.owcin
//	cargo run --manifest-path runtime/catalog-mmap/Cargo.toml --bin catalog-mmap -- \
//	  compile --input <dir>/dom1-particle-fixture.owcin \
//	  --output test/fixtures/screening-api/dom1-particle/dom1-particle-fixture.owmmap
//
// which also fixes the component_id, catalog_checksum, and package_sha256
// constants below; they are not independently chosen.
func dom1ParticleService(t *testing.T) *Service {
	t.Helper()
	binaryPath := buildDOM1RuntimeBinary(t)
	packagePath, err := filepath.Abs(filepath.Join("..", "..", "test", "fixtures", "screening-api", "dom1-particle", "dom1-particle-fixture.owmmap"))
	if err != nil {
		t.Fatal(err)
	}
	const (
		namespace       = "dom1-regression"
		componentID     = "catalog_component_b1bed6f60480cb3272a9cf77"
		catalogChecksum = "efa1c6c25fd4ea5dc57b3ca2fe7e5e31b7d7bc79e4dcd7649e415e29e213a198"
		packageSHA256   = "c2d2235a3cdd4cf01686cbc424560d77f636da5e896c11764655b0f37f680e7e"
		sourceSystemID  = "fircosoft-prod"
		rawListName     = "WLS_OFAC_DOM1_PARTICLE"
	)
	created := mustTime(t, "2026-08-14T00:00:00Z")

	catalogStore := catalogregistry.Store{Root: t.TempDir()}
	if _, err := catalogStore.Initialize(namespace); err != nil {
		t.Fatal(err)
	}
	component, err := catalogregistry.BuildComponent(catalogregistry.ComponentInput{
		Namespace:    namespace,
		ComponentKey: "ofac-sdn-particle-fixture",
		DisplayName:  "DOM-1 particle/compound regression fixture",
		CatalogMode:  catalogregistry.CatalogModeOfficial,
		CreatedAt:    created,
		CreatedBy:    "dom1-particle-fix",
	})
	if err != nil {
		t.Fatal(err)
	}
	if component.ComponentID != componentID {
		t.Fatalf("component_id drifted from the compiled package binding: got %s want %s (see the regeneration commands in this function's doc comment)", component.ComponentID, componentID)
	}
	if _, err := catalogStore.RegisterComponent(component); err != nil {
		t.Fatal(err)
	}
	version, err := catalogregistry.BuildVersion(catalogregistry.VersionInput{
		ComponentID:      component.ComponentID,
		CatalogID:        "ofac-sdn-direct",
		CatalogVersion:   "2026-08-14-c5bc60d8e702",
		CatalogChecksum:  catalogChecksum,
		CatalogSchema:    "ofac-direct-list-catalog/v1alpha1",
		ArtifactURI:      "file://test/fixtures/screening-api/dom1-particle/dom1-particle-fixture.owmmap",
		ArtifactSHA256:   packageSHA256,
		SourceManifestID: "ofac_source_d52d568dbf4c020d0528e7df",
		RecordCount:      1,
		ProducerVersion:  "catalog-mmap-compiler/v0.1.0",
		Source: catalogregistry.SourceDescriptor{
			Kind: catalogregistry.SourceKindOfficial,
			Official: &catalogregistry.OfficialSource{
				Authority:    "US_TREASURY_OFAC",
				ListKey:      "SDN",
				SourceFormat: "ofac_advanced_xml",
				XMLVersion:   "3",
			},
		},
		RegisteredAt: created,
		RegisteredBy: "dom1-particle-fix",
	}, component)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalogStore.RegisterVersion(version); err != nil {
		t.Fatal(err)
	}
	_, catalog, err := catalogStore.Activate(catalogregistry.ActivationRequest{
		ComponentID:     component.ComponentID,
		TargetVersionID: version.VersionID,
		Action:          catalogregistry.ActivationActionActivate,
		Reason:          "activate DOM-1 particle regression fixture",
		ActivatedAt:     created,
		ActivatedBy:     "dom1-particle-fix",
	})
	if err != nil {
		t.Fatal(err)
	}

	mappingStore := alertlistmapping.Store{Root: t.TempDir()}
	if _, err := mappingStore.Initialize(namespace); err != nil {
		t.Fatal(err)
	}
	_, mapping, err := mappingStore.Register(alertlistmapping.MappingInput{
		SourceSystemID: sourceSystemID,
		RawListName:    rawListName,
		Action:         alertlistmapping.MappingActionBind,
		ComponentID:    component.ComponentID,
		EffectiveFrom:  mustTime(t, "2026-01-01T00:00:00Z"),
		Reason:         "bind DOM-1 particle regression list",
		CreatedAt:      created,
		CreatedBy:      "dom1-particle-fix",
	}, catalog)
	if err != nil {
		t.Fatal(err)
	}

	config := Config{
		RuntimeBinaryPath: binaryPath,
		RuntimeBindings: []RuntimeBinding{
			{
				ComponentID:   component.ComponentID,
				VersionID:     version.VersionID,
				PackagePath:   packagePath,
				PackageSHA256: packageSHA256,
				WorkerCount:   1,
			},
		},
	}
	manager, err := StartRuntimeManager(context.Background(), config, catalog)
	if err != nil {
		t.Fatalf("start real runtime manager against the compiled particle fixture package: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return &Service{
		Loader:        staticLoader{State{Catalog: catalog, Mapping: mapping}},
		Runtime:       manager,
		MaxCandidates: 20,
		Clock:         func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") },
		Scoring:       testScoringBinding(t),
	}
}

func dom1ParticleRequest(id, queryValue string) ScreeningRequest {
	at, _ := time.Parse(time.RFC3339, "2026-07-20T12:00:00Z")
	return ScreeningRequest{
		SchemaVersion:  RequestSchemaVersion,
		RequestID:      id,
		SourceSystemID: "fircosoft-prod",
		RawListName:    "WLS_OFAC_DOM1_PARTICLE",
		EffectiveAt:    at,
		Query:          Query{Kind: QueryName, Value: queryValue, Limit: 20},
	}
}

// TestDOM1UnsupportedMatchingVariantParticleAndCompoundProducesNoMatchToday
// is the Table 1 "Name particles and compounds (AL, BIN, VAN DER) | Not
// supported" case, against a genuine particle record instead of the
// unrelated-vessel stand-in this file used to carry (see the comment left
// in its place in TestDOM1UnsupportedMatchingVariantsProduceNoMatchToday's
// cases slice). The dedicated fixture's sole record has primary_name
// "Klaas van der Berg", carrying the real two-word particle "van der"
// Table 1 names explicitly. The query strips that particle entirely --
// "Klaas Berg" -- which is exactly the transformation a particle-aware
// matcher would need to recognize as equivalent and today's exact-only
// matching (runtime/catalog-mmap/src/format.rs's PackageView::lookup_name)
// cannot. Confirmed against the live worker via its lookup-name CLI before
// being committed here: the sole record's exact primary_name still
// matches (control), and "Klaas Berg" / "Berg Klaas" both return zero
// candidates -- and, because the package holds exactly one record, there
// is no second record this query could accidentally collide with the way
// the old "EXAMPLE" case collided with an unrelated vessel alias.
func TestDOM1UnsupportedMatchingVariantParticleAndCompoundProducesNoMatchToday(t *testing.T) {
	service := dom1ParticleService(t)
	ctx := context.Background()

	t.Run("control_exact_stored_name_still_matches", func(t *testing.T) {
		// This asserts the runtime layer surfaced the exact-match candidate,
		// not response.Status == StatusMatched: ofac:sdn:4004 was deliberately
		// never added to test/fixtures/scoring-activation's projection index
		// (internal/candidatescoring and internal/screeningapi's scoring path
		// are #115's separate, higher-priority fix, out of scope here), so
		// service.go's screenAt blocks on BlockerCandidateProjectionUnavailable
		// after the runtime match -- a scoring-data gap, not a matching
		// failure. What this control needs to prove -- that this harness
		// genuinely exercises live matching rather than vacuously returning
		// zero candidates for every query -- is fully established by the
		// runtime having found the record at all.
		response, err := service.Screen(ctx, dom1ParticleRequest("dom1-particle-control", "Klaas van der Berg"), "corr-dom1-particle-control", "idem-dom1-particle-control")
		if err != nil {
			t.Fatal(err)
		}
		if response.CandidateCount != 1 || response.Candidates[0].RecordID != "ofac:sdn:4004" {
			t.Fatalf("control query: expected the runtime to surface exactly one candidate on ofac:sdn:4004, got status=%s candidates=%+v (if this control fails, the case below is not a valid regression guard)", response.Status, response.Candidates)
		}
	})

	t.Run("name_particles_and_compounds", func(t *testing.T) {
		response, err := service.Screen(ctx, dom1ParticleRequest("dom1-name_particles_and_compounds", "Klaas Berg"), "corr-name_particles_and_compounds", "idem-name_particles_and_compounds")
		if err != nil {
			t.Fatal(err)
		}
		if response.Status != StatusNoCandidates || response.CandidateCount != 0 || len(response.Candidates) != 0 {
			t.Fatalf("query \"Klaas Berg\" unexpectedly matched against the live runtime -- this test exists to prove Table 1's claim is accurate today, and must be updated (not deleted) when DOM-1 changes this behavior: status=%s candidates=%+v", response.Status, response.Candidates)
		}
	})
}
