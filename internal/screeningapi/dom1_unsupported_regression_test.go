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
// (test/golden/ofac-advanced/ofac-sdn-catalog.json) and the runtime must
// still retrieve it today per Table 1's "Exact normalized name | Supported"
// row.
func TestDOM1LiveRuntimeSanityControlsStillMatch(t *testing.T) {
	service := dom1LiveService(t)
	ctx := context.Background()
	controls := []struct {
		name, query, wantRecordID string
	}{
		{"acme-imports-alias", "ACME IMPORTS", "ofac:sdn:1001"},
		{"mv-example-alias", "MV EXAMPLE", "ofac:sdn:3003"},
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

// TestDOM1LiveRuntimeCyrillicAliasControlIsRetrievedButBlocked is the same
// harness sanity control as above, split out for a different reason: since
// issue #115's fix, this control's expected *response shape* changed, not
// just its assertion value. "Джордан Экзампл" is a real, exact alias of
// ofac:sdn:2002 in the compiled catalog's source, and the live runtime does
// retrieve it -- proving the harness is not broken, same as the ASCII
// controls above. But the DOM-3 scoring projection this fixture tuple binds
// (test/fixtures/projection-package/packages/1f4397.../projections.json)
// does not carry that Cyrillic alias among ofac:sdn:2002's projected Names
// (issue #115), so the response can no longer honestly report
// StatusMatched: the catalog's own retrieval hit is real evidence, but the
// projection cannot corroborate it. Before #115's fix this silently reported
// status "matched" with score 0 -- indistinguishable from a genuine
// non-match. After the fix it reports StatusBlocked with
// BlockerNameMatchUncorroboratedByProjection naming the record, which is
// what this test now asserts. The retrieval evidence (RecordID, MatchKind,
// MatchedValue) stays in response.Candidates, unscored, so it is still
// proof the runtime found the record.
func TestDOM1LiveRuntimeCyrillicAliasControlIsRetrievedButBlocked(t *testing.T) {
	service := dom1LiveService(t)
	ctx := context.Background()
	response, err := service.Screen(ctx, dom1Request("dom1-control-cyrillic-alias-exact-bytes", "Джордан Экзампл"), "corr-dom1-control", "idem-dom1-control-cyrillic-alias-exact-bytes")
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusBlocked || len(response.Candidates) != 1 || response.Candidates[0].RecordID != "ofac:sdn:2002" {
		t.Fatalf("expected the runtime to retrieve ofac:sdn:2002 but the response to be blocked (issue #115), got status=%s candidates=%+v", response.Status, response.Candidates)
	}
	if response.Candidates[0].Score != 0 || response.Candidates[0].StrengthBand != "" {
		t.Fatalf("a blocked candidate must not carry scored-looking fields: %+v", response.Candidates[0])
	}
	var foundCode, foundDetail bool
	for _, blocker := range response.ReviewBlockers {
		if blocker == BlockerNameMatchUncorroboratedByProjection {
			foundCode = true
		}
		if blocker == BlockerNameMatchUncorroboratedByProjection+":ofac:sdn:2002" {
			foundDetail = true
		}
	}
	if !foundCode || !foundDetail {
		t.Fatalf("expected review_blockers to name %s and ofac:sdn:2002, got %+v", BlockerNameMatchUncorroboratedByProjection, response.ReviewBlockers)
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
		{
			// Table 1: "Name particles and compounds (AL, BIN, VAN DER) |
			// Not supported". None of the 3 fixture records contain a true
			// name particle (AL/BIN/VAN DER), so this is a reasoned
			// synthetic stand-in, not a genuine particle case: the real
			// vessel alias "MV EXAMPLE" (ofac:sdn:3003) carries "MV"
			// (Motor Vessel) as a semantically-void prefix token, playing
			// the same structural role a particle-aware matcher would
			// strip that a name particle does. Querying the bare name with
			// that token removed is the closest real-fixture analog
			// available; a genuine AL/BIN/VAN DER case would need a
			// catalog fixture that doesn't exist today.
			name:  "name_particles_and_compounds",
			query: "EXAMPLE",
		},
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
