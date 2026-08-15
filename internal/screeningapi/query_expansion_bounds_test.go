package screeningapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimemmapclient"
)

// countingFakeRuntime is fakeRuntime's PackageInfo/candidate behavior (same
// fixed candidate list regardless of query) but exists separately here so
// this file's intent -- counting round trips -- is not tangled with
// service_test.go's unrelated assertions on fakeRuntime.lookups.
type countingFakeRuntime struct {
	lookups int
	info    runtimemmapclient.PackageInfo
	values  []runtimemmapclient.Candidate
}

func (runtime *countingFakeRuntime) Lookup(_ context.Context, _, _ string, _ runtimemmapclient.Query) (RuntimeResult, error) {
	runtime.lookups++
	return RuntimeResult{Info: runtime.info, Candidates: append([]runtimemmapclient.Candidate(nil), runtime.values...)}, nil
}
func (runtime *countingFakeRuntime) Ready(catalogregistry.Registry) error { return nil }
func (runtime *countingFakeRuntime) Close() error                         { return nil }
func (runtime *countingFakeRuntime) PackageInfo(packageSHA256 string) (runtimemmapclient.PackageInfo, bool) {
	if runtime.info.PackageSHA256 == packageSHA256 {
		return runtime.info, true
	}
	return runtimemmapclient.PackageInfo{}, false
}

func goldenOFACRuntimeInfo() runtimemmapclient.PackageInfo {
	return runtimemmapclient.PackageInfo{
		ProtocolVersion: "1",
		ComponentID:     "catalog_component_ed835720fdb2b3a505927488",
		CatalogID:       "ofac-sdn-direct",
		CatalogVersion:  "2026-07-13-427847835cb4",
		CatalogChecksum: "339b64d9a9d8ffa9ea5b9ab243a320faeef1ade6f3dc5a3e8891e437adccc582",
		CatalogMode:     "official_list",
		PackageSHA256:   "8c5e581ad36807c15a2ae00c5cb4e8b7f9154e208b369ff3227617294a473367",
		RecordCount:     3,
	}
}

func nameQueryRequest(t *testing.T, id, value string, limit int) ScreeningRequest {
	t.Helper()
	return ScreeningRequest{
		SchemaVersion:  RequestSchemaVersion,
		RequestID:      id,
		SourceSystemID: "fircosoft-prod",
		RawListName:    "WLS_OFAC_001",
		EffectiveAt:    mustTime(t, "2026-07-20T12:00:00Z"),
		Query:          Query{Kind: QueryName, Value: value, Limit: limit},
	}
}

// TestNameQueryExpansionRoundTripsAreBoundedForLongSingleToken is issue
// #124: AD4's concatenation-split probe (nameQueryExpansions) fires on any
// single-token query with no bound on token length, issuing N-1 additional
// serialized runtime round trips for an N-character token. The reported
// case is a 4,096-byte single token -- the maximum query.value ValidateRequest
// allows (service.go:323-325) -- which issues 4,095 split-probe round trips
// plus the baseline lookup and the first-token prefix probe, 4,097 total.
// This asserts the fixed, bounded shape: above a maximum token length the
// split probe must not fire at all, so the long-token request costs the
// same small, fixed number of round trips (baseline + prefix probe) as any
// other single-token query, not a number that scales with query length.
func TestNameQueryExpansionRoundTripsAreBoundedForLongSingleToken(t *testing.T) {
	state := loadGoldenState(t)
	longToken := strings.Repeat("A", 4096)
	runtime := &countingFakeRuntime{
		info:   goldenOFACRuntimeInfo(),
		values: nil, // no candidates: this test is about round-trip count, not matching
	}
	service := Service{
		Loader:        staticLoader{state},
		Runtime:       runtime,
		MaxCandidates: 20,
		Clock:         func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") },
		Scoring:       testScoringBinding(t),
	}
	request := nameQueryRequest(t, "long-token-124", longToken, 20)
	_, err := service.Screen(context.Background(), request, "corr-124", "idem-124")
	if err != nil {
		t.Fatal(err)
	}
	// baseline lookup + first-token prefix probe = 2, regardless of the
	// query's length, once the split probe is bounded. Before the fix this
	// was 4,097 (baseline + prefix probe + 4,095 split-probe round trips).
	const wantLookups = 2
	if runtime.lookups != wantLookups {
		t.Fatalf("4096-byte single-token query issued %d runtime round trips, want %d (concatenation-split probe must not fire above the bounded token length -- see issue #124)", runtime.lookups, wantLookups)
	}
}

// sequencedFakeRuntime returns a different, caller-supplied candidate slice
// on each successive Lookup call (falling back to no candidates once calls
// runs out), so a test can simulate DOM-1 Stage 1's real behavior: the
// baseline lookup and each query-expansion lookup returning genuinely
// distinct record IDs, unioned by the caller. fakeRuntime and
// countingFakeRuntime in this package always return the same fixed slice
// for every call, which cannot exercise a union that grows past any single
// lookup's own result.
type sequencedFakeRuntime struct {
	lookups int
	info    runtimemmapclient.PackageInfo
	calls   [][]runtimemmapclient.Candidate
}

func (runtime *sequencedFakeRuntime) Lookup(_ context.Context, _, _ string, _ runtimemmapclient.Query) (RuntimeResult, error) {
	index := runtime.lookups
	runtime.lookups++
	var candidates []runtimemmapclient.Candidate
	if index < len(runtime.calls) {
		candidates = runtime.calls[index]
	}
	return RuntimeResult{Info: runtime.info, Candidates: append([]runtimemmapclient.Candidate(nil), candidates...)}, nil
}
func (runtime *sequencedFakeRuntime) Ready(catalogregistry.Registry) error { return nil }
func (runtime *sequencedFakeRuntime) Close() error                         { return nil }
func (runtime *sequencedFakeRuntime) PackageInfo(packageSHA256 string) (runtimemmapclient.PackageInfo, bool) {
	if runtime.info.PackageSHA256 == packageSHA256 {
		return runtime.info, true
	}
	return runtimemmapclient.PackageInfo{}, false
}

// TestMaxCandidatesBoundsMergedExpansionUnion is issue #125: each
// individual runtime lookup already honors query.limit
// (effectiveLimit(request.Query.Limit, service.MaxCandidates) at
// service.go:92), but DOM-1 Stage 1's expansion results are appended into
// response.Candidates and deduplicated by record ID with no re-truncation
// to that limit (service.go:132-159), so a name query with E expansions can
// return up to limit*(E+1) distinct candidates.
//
// The query "IMPORTS ACME" (two tokens, both in the golden OFAC mapping)
// produces exactly two DOM-1 Stage 1 expansions -- the token-sorted
// permutation ("ACME IMPORTS") and the first-token prefix probe
// ("IMPORTS") -- so three runtime lookups fire in total: baseline,
// token-sorted, prefix. sequencedFakeRuntime is set up to return one
// distinct, never-before-seen record ID per lookup, so deduplication by
// record ID does not collapse them: the union is genuinely 3 distinct
// candidates. query.limit is set to 2. This must never exceed 2, the same
// guarantee a single-lookup query already got from the runtime honoring
// Limit directly -- restored here for the multi-lookup case by truncating
// the merged, deduplicated set.
//
// None of the 3 synthetic record IDs exist in the golden scoring
// projection, so the response blocks on BlockerCandidateProjectionUnavailable
// before scoring runs (service.go:185-197) -- CandidateCount is set there,
// directly from len(response.Candidates), which is exactly the unbounded
// merged/deduplicated set issue #125 is about; scoring is irrelevant to
// reproducing this defect.
func TestMaxCandidatesBoundsMergedExpansionUnion(t *testing.T) {
	state := loadGoldenState(t)
	runtime := &sequencedFakeRuntime{
		info: goldenOFACRuntimeInfo(),
		calls: [][]runtimemmapclient.Candidate{
			{{RecordID: "synthetic:125:baseline", EntityType: "organization", MatchKind: "alias", MatchedValue: "IMPORTS ACME"}},
			{{RecordID: "synthetic:125:token-sorted", EntityType: "organization", MatchKind: "alias", MatchedValue: "ACME IMPORTS"}},
			{{RecordID: "synthetic:125:prefix", EntityType: "organization", MatchKind: "alias", MatchedValue: "IMPORTS"}},
		},
	}
	service := Service{
		Loader:        staticLoader{state},
		Runtime:       runtime,
		MaxCandidates: 20,
		Clock:         func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") },
		Scoring:       testScoringBinding(t),
	}
	const limit = 2
	request := nameQueryRequest(t, "merged-union-125", "IMPORTS ACME", limit)
	response, err := service.Screen(context.Background(), request, "corr-125", "idem-125")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.lookups != 3 {
		t.Fatalf("expected 3 runtime lookups (baseline + token-sorted + prefix probe) to set up this reproduction, got %d -- fixture or expansion set drifted", runtime.lookups)
	}
	if response.CandidateCount > limit || len(response.Candidates) > limit {
		t.Fatalf("query.limit=%d but the merged/deduplicated expansion union returned %d candidates (response.CandidateCount=%d) -- max_candidates must bound the merged response set, not just each individual lookup (issue #125)", limit, len(response.Candidates), response.CandidateCount)
	}
}

// TestBaselineCandidateSurvivesTruncationOverExpansionSourcedCandidates
// locks in the ordering guarantee issue #125's truncation fix depends on:
// response.Candidates is built by merging the baseline (un-expanded)
// lookup's own results first -- `runtimeCandidates := append(nil,
// result.Candidates...)` runs before the QueryName branch below it even
// starts (service.go:114-130) -- and every expansion's results are only
// ever appended onto that same slice afterward, in expansion order, never
// prepended or reordered. The merge/dedup loop (service.go:132-169) then
// walks runtimeCandidates in that exact order and stops once
// response.Candidates reaches query.limit, so a baseline candidate is
// always considered -- and, barring an entity-type filter or an earlier
// duplicate, appended -- before any expansion-sourced candidate can claim
// a slot in the same limit budget. This is a structural property of a
// single, one-directional construction site, not an incidental ordering
// of some other source list that could silently drift.
//
// query.limit=1 here with 3 distinct candidates available across the
// baseline lookup and its two Stage 1 expansions (token-sorted, prefix) --
// more than the limit, so truncation must choose. The survivor must
// always be the baseline's own exact-match candidate, never one sourced
// only from an expansion, regardless of which expansions also matched.
func TestBaselineCandidateSurvivesTruncationOverExpansionSourcedCandidates(t *testing.T) {
	state := loadGoldenState(t)
	runtime := &sequencedFakeRuntime{
		info: goldenOFACRuntimeInfo(),
		calls: [][]runtimemmapclient.Candidate{
			{{RecordID: "synthetic:baseline-exact-match", EntityType: "organization", MatchKind: "alias", MatchedValue: "IMPORTS ACME"}},
			{{RecordID: "synthetic:token-sorted-only", EntityType: "organization", MatchKind: "alias", MatchedValue: "ACME IMPORTS"}},
			{{RecordID: "synthetic:prefix-only", EntityType: "organization", MatchKind: "alias", MatchedValue: "IMPORTS"}},
		},
	}
	service := Service{
		Loader:        staticLoader{state},
		Runtime:       runtime,
		MaxCandidates: 20,
		Clock:         func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") },
		Scoring:       testScoringBinding(t),
	}
	const limit = 1
	request := nameQueryRequest(t, "baseline-priority-125", "IMPORTS ACME", limit)
	response, err := service.Screen(context.Background(), request, "corr-baseline-priority", "idem-baseline-priority")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.lookups != 3 {
		t.Fatalf("expected 3 runtime lookups (baseline + token-sorted + prefix probe) to set up this reproduction, got %d -- fixture or expansion set drifted", runtime.lookups)
	}
	if len(response.Candidates) != 1 || response.Candidates[0].RecordID != "synthetic:baseline-exact-match" {
		t.Fatalf("with query.limit=1 and 3 distinct candidates across the baseline lookup and its expansions, expected only the baseline's own exact-match candidate to survive truncation, got %+v", response.Candidates)
	}
}
