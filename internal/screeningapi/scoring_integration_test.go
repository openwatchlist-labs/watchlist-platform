package screeningapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimemmapclient"
	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
)

// acmeImportsRuntimeCandidate is the real retrieval hit the DOM-3 fixture
// tuple was built to join against: catalog record ofac:sdn:1001, matched by
// alias "ACME IMPORTS" (test/golden/ofac/ofac-sdn-fixture.catalog.json).
func acmeImportsRuntimeCandidate() runtimemmapclient.Candidate {
	return runtimemmapclient.Candidate{
		RecordID: "ofac:sdn:1001", EntityType: "organization", PrimaryName: "Acme Imports LLC",
		MatchKind: "alias", MatchedValue: "ACME IMPORTS", NormalizedQuery: "acme imports",
	}
}

func realCatalogPackageInfo() runtimemmapclient.PackageInfo {
	return runtimemmapclient.PackageInfo{
		ProtocolVersion: "1", ComponentID: "catalog_component_ed835720fdb2b3a505927488",
		CatalogID: "ofac-sdn-direct", CatalogVersion: "2026-07-13-427847835cb4",
		CatalogChecksum: "339b64d9a9d8ffa9ea5b9ab243a320faeef1ade6f3dc5a3e8891e437adccc582",
		CatalogMode:     "official_list",
		PackageSHA256:   "8c5e581ad36807c15a2ae00c5cb4e8b7f9154e208b369ff3227617294a473367",
		RecordCount:     3,
	}
}

// TestScoringE2EPopulatesScoreOverHTTP is ADR-0004 §9.1's bar: a real
// authenticated HTTP request through NewAuthenticatedHandler, over the real
// compiled ofac-fixture.owmmap catalog and the real DOM-3 projection/policy
// tuple, returning a populated score field -- not a bridge-level unit test.
//
// Failing-first (§9.2): before this change, ScreeningResponse had no Score
// field at all (types.go), so `candidate.Score` below did not compile
// against the pre-change struct, and the pre-change JSON never carried the
// field. Verified by stashing the implementation and re-running this test
// file alone: it fails to compile, exactly as §9.2 requires.
func TestScoringE2EPopulatesScoreOverHTTP(t *testing.T) {
	state := loadGoldenState(t)
	runtime := &fakeRuntime{info: realCatalogPackageInfo(), values: []runtimemmapclient.Candidate{acmeImportsRuntimeCandidate()}}
	binding := testScoringBinding(t)
	service := &Service{Loader: staticLoader{state}, Runtime: runtime, MaxCandidates: 20, Clock: func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") }, Scoring: binding}
	config := Config{MaxBodyBytes: 1 << 20, MaxBatchItems: 100, MaxCandidates: 20, RequestTimeoutMS: 2000}
	handler := &Handler{Config: config, Service: service, Store: IdempotencyStore{Root: t.TempDir()}}
	tokens := loadFixtureTokenService(t)
	token, _, err := tokens.Issue("alice", "tenant-a", time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := NewAuthenticatedHandler(handler, tokens, nil)
	if err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(fixtureRequest("screen-score-1", "fircosoft-prod", "WLS_OFAC_001", "2026-07-20T12:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "idem-score-1")
	req.Header.Set("Authorization", "Bearer "+token)
	guarded.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var decoded ScreeningResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != StatusMatched || len(decoded.Candidates) != 1 {
		t.Fatalf("unexpected response: %+v", decoded)
	}
	candidate := decoded.Candidates[0]
	if candidate.Score <= 0 {
		t.Fatalf("candidates[0].score = %d, want > 0", candidate.Score)
	}
	if candidate.StrengthBand == "" {
		t.Fatal("candidates[0].strength_band is empty")
	}
	if len(candidate.ReasonCodes) == 0 {
		t.Fatal("candidates[0].reason_codes is empty")
	}
	if decoded.Policy.PolicySHA256 == "" || decoded.Policy.PolicySHA256 != binding.policy.PolicySHA256 {
		t.Fatalf("policy.policy_sha256 = %q, want the loaded policy's digest %q", decoded.Policy.PolicySHA256, binding.policy.PolicySHA256)
	}
}

// TestScoringProjectionMissBlocksLoudly is ADR-0004 §9.3: a retrieved
// record_id absent from the active projection index yields HTTP 200 with
// status "blocked" and blocker candidate_projection_unavailable naming the
// missing record -- retrieval evidence stays in the response, and the gap
// is never disguised as a scored-zero result.
func TestScoringProjectionMissBlocksLoudly(t *testing.T) {
	state := loadGoldenState(t)
	missing := runtimemmapclient.Candidate{
		RecordID: "ofac:sdn:9999", EntityType: "organization", PrimaryName: "Not In Projection",
		MatchKind: "exact", MatchedValue: "ACME IMPORTS", NormalizedQuery: "acme imports",
	}
	runtime := &fakeRuntime{info: realCatalogPackageInfo(), values: []runtimemmapclient.Candidate{missing}}
	service := Service{Loader: staticLoader{state}, Runtime: runtime, MaxCandidates: 20, Clock: func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") }, Scoring: testScoringBinding(t)}

	request := fixtureRequest("screen-miss-1", "fircosoft-prod", "WLS_OFAC_001", "2026-07-20T12:00:00Z")
	response, err := service.Screen(context.Background(), request, "corr-miss", "idem-miss")
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusBlocked {
		t.Fatalf("status = %q, want blocked: %+v", response.Status, response)
	}
	if len(response.Candidates) != 1 || response.Candidates[0].RecordID != "ofac:sdn:9999" {
		t.Fatalf("retrieval evidence was not preserved: %+v", response.Candidates)
	}
	if response.Candidates[0].Score != 0 || response.Candidates[0].StrengthBand != "" {
		t.Fatalf("a blocked candidate must not carry scored-looking fields: %+v", response.Candidates[0])
	}
	var foundCode, foundDetail bool
	for _, blocker := range response.ReviewBlockers {
		if blocker == BlockerCandidateProjectionUnavailable {
			foundCode = true
		}
		if blocker == BlockerCandidateProjectionUnavailable+":ofac:sdn:9999" {
			foundDetail = true
		}
	}
	if !foundCode || !foundDetail {
		t.Fatalf("expected review_blockers to name candidate_projection_unavailable and the missing record_id, got %+v", response.ReviewBlockers)
	}
}

// TestScoringNameMatchUncorroboratedByProjectionBlocksLoudly is issue
// #115's regression guard: a retrieval hit whose match_kind is a genuine
// name match ("primary_name" or "alias") but whose matched name the active
// DOM-3 scoring projection does not carry for that record must not be
// scored as a silent 0 -- it must block loudly, the same way a missing
// record_id does (ADR-0004 §6).
//
// The scenario is real, not synthesized: ofac:sdn:2002's Cyrillic alias
// "Джордан Экзампл" is present in the compiled catalog
// (test/fixtures/runtime-mmap/ofac-fixture.owcin:19, compiled into
// test/golden/runtime-mmap/ofac-fixture.owmmap) but absent from the DOM-3
// projection package testScoringBinding loads
// (test/fixtures/projection-package/packages/1f4397.../projections.json --
// ofac:sdn:2002 carries only "J EXAMPLE" and "JORDAN EXAMPLE"). This test
// simulates the runtime's retrieval hit for that alias directly (a
// fakeRuntime, not the live Rust worker -- TestDOM1LiveRuntime
// CyrillicAliasControlIsRetrievedButBlocked in dom1_unsupported_regression_
// test.go covers the same scenario end to end against the real worker) so
// it stays fast and needs no cargo/rustc toolchain.
//
// Failing-first (CLAUDE.md rule 5): before the fix, screenAt() returns this
// candidate with status "matched", score 0, strength_band
// "no_candidate_support", and empty reason_codes -- indistinguishable from
// a genuine non-match. That is exactly the silent degradation ADR-0004 §6
// rejects.
func TestScoringNameMatchUncorroboratedByProjectionBlocksLoudly(t *testing.T) {
	state := loadGoldenState(t)
	cyrillicAliasHit := runtimemmapclient.Candidate{
		RecordID: "ofac:sdn:2002", EntityType: "individual", PrimaryName: "Jordan Example",
		MatchKind: "alias", MatchedValue: "Джордан Экзампл", NormalizedQuery: "Джордан Экзампл",
	}
	runtime := &fakeRuntime{info: realCatalogPackageInfo(), values: []runtimemmapclient.Candidate{cyrillicAliasHit}}
	service := Service{Loader: staticLoader{state}, Runtime: runtime, MaxCandidates: 20, Clock: func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") }, Scoring: testScoringBinding(t)}

	request := fixtureRequest("screen-name-gap-1", "fircosoft-prod", "WLS_OFAC_001", "2026-07-20T12:00:00Z")
	request.Query = Query{Kind: QueryName, Value: "Джордан Экзампл", Limit: 20}
	response, err := service.Screen(context.Background(), request, "corr-name-gap", "idem-name-gap")
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusBlocked {
		t.Fatalf("status = %q, want blocked: %+v", response.Status, response)
	}
	if len(response.Candidates) != 1 || response.Candidates[0].RecordID != "ofac:sdn:2002" {
		t.Fatalf("retrieval evidence was not preserved: %+v", response.Candidates)
	}
	if response.Candidates[0].Score != 0 || response.Candidates[0].StrengthBand != "" || response.Candidates[0].ExactNameMatched {
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
		t.Fatalf("expected review_blockers to name %s and the uncorroborated record_id, got %+v", BlockerNameMatchUncorroboratedByProjection, response.ReviewBlockers)
	}
}

// TestScoringRecordIDQueryBlocksAsScoringSubjectUnavailable covers §4/§6's
// other named blocker: a record_id query has no subject to score against,
// so it is blocked rather than returned with an unpopulated score.
func TestScoringRecordIDQueryBlocksAsScoringSubjectUnavailable(t *testing.T) {
	state := loadGoldenState(t)
	runtime := &fakeRuntime{info: realCatalogPackageInfo(), values: []runtimemmapclient.Candidate{acmeImportsRuntimeCandidate()}}
	service := Service{Loader: staticLoader{state}, Runtime: runtime, MaxCandidates: 20, Clock: func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") }, Scoring: testScoringBinding(t)}

	request := fixtureRequest("screen-recid-1", "fircosoft-prod", "WLS_OFAC_001", "2026-07-20T12:00:00Z")
	request.Query = Query{Kind: QueryRecordID, Value: "ofac:sdn:1001", Limit: 20}
	response, err := service.Screen(context.Background(), request, "corr-recid", "idem-recid")
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusBlocked {
		t.Fatalf("status = %q, want blocked: %+v", response.Status, response)
	}
	found := false
	for _, blocker := range response.ReviewBlockers {
		if blocker == BlockerScoringSubjectUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected review_blockers to contain %q, got %+v", BlockerScoringSubjectUnavailable, response.ReviewBlockers)
	}
}

// TestValidateScoringRuntimeProfileReadsRuntimeNotConfig is ADR-0004 §9.4:
// the profile check must read PackageInfo.NormalizationProfile off the
// runtime the service actually serves, not any config-declared descriptor
// field. Constructed so a config-declared value would pass and the real
// runtime header fails -- the regression test for §2's v8d anti-pattern
// (v8d compared its own config.DefaultLineage.NormalizationProfile against
// the policy's, which is config-against-config and always agrees).
func TestValidateScoringRuntimeProfileReadsRuntimeNotConfig(t *testing.T) {
	manager, err := scoringactivation.NewManager(filepath.Join("..", "..", "test", "fixtures", "scoring-activation", "state-ofac-sdn-direct"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.LoadActive()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("runtime profile matches policy", func(t *testing.T) {
		runtime := &fakeRuntime{info: runtimemmapclient.PackageInfo{
			PackageSHA256:        snapshot.Activation.Catalog.CatalogPackageSHA256,
			NormalizationProfile: snapshot.Policy.Policy.NormalizationProfile,
		}}
		if err := ValidateScoringRuntimeProfile(runtime, snapshot); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("real runtime header disagrees despite the config-declared descriptor agreeing", func(t *testing.T) {
		// The activation's own descriptor.normalization_profile already
		// equals the policy's -- validateTuple guarantees that for any
		// snapshot that loads at all. That agreement is exactly what v8d
		// checked, and exactly what must NOT be sufficient here.
		if snapshot.Activation.Catalog.NormalizationProfile != snapshot.Policy.Policy.NormalizationProfile {
			t.Fatal("test setup invariant violated: descriptor/policy profile should already agree")
		}
		runtime := &fakeRuntime{info: runtimemmapclient.PackageInfo{
			PackageSHA256:        snapshot.Activation.Catalog.CatalogPackageSHA256,
			NormalizationProfile: "unicode-upper-alnum-space-v1", // a real profile value, just the wrong one
		}}
		if err := ValidateScoringRuntimeProfile(runtime, snapshot); err == nil {
			t.Fatal("expected an error: the runtime's actual header profile disagrees with the policy")
		}
	})

	t.Run("no bound runtime package matches the activation's catalog", func(t *testing.T) {
		runtime := &fakeRuntime{info: runtimemmapclient.PackageInfo{PackageSHA256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}
		if err := ValidateScoringRuntimeProfile(runtime, snapshot); err == nil {
			t.Fatal("expected an error when no bound runtime package matches catalog_package_sha256")
		}
	})
}

// TestScoringSingleAndBatchParity is ADR-0004 §9.5: the same subject
// through /v1/screenings-equivalent single scoring and batch scoring
// produces identical scores, bands, and reason codes -- batch stays on
// screenAt(), never ScoreBatch, so single and batch cannot drift.
func TestScoringSingleAndBatchParity(t *testing.T) {
	state := loadGoldenState(t)
	newRuntime := func() *fakeRuntime {
		return &fakeRuntime{info: realCatalogPackageInfo(), values: []runtimemmapclient.Candidate{acmeImportsRuntimeCandidate()}}
	}
	clock := func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") }
	binding := testScoringBinding(t)
	single := Service{Loader: staticLoader{state}, Runtime: newRuntime(), MaxCandidates: 20, Clock: clock, Scoring: binding}
	batchSvc := Service{Loader: staticLoader{state}, Runtime: newRuntime(), MaxCandidates: 20, Clock: clock, Scoring: binding}

	request := fixtureRequest("screen-parity-1", "fircosoft-prod", "WLS_OFAC_001", "2026-07-20T12:00:00Z")
	singleResp, err := single.Screen(context.Background(), request, "corr-parity", "idem-parity-single")
	if err != nil {
		t.Fatal(err)
	}
	batchResp, err := batchSvc.ScreenBatch(context.Background(), BatchRequest{SchemaVersion: BatchRequestSchemaVersion, Requests: []ScreeningRequest{request}}, "corr-parity", "idem-parity-batch")
	if err != nil {
		t.Fatal(err)
	}
	if len(batchResp.Results) != 1 {
		t.Fatalf("expected 1 batch result, got %d", len(batchResp.Results))
	}
	batchItem := batchResp.Results[0]
	if len(singleResp.Candidates) != 1 || len(batchItem.Candidates) != 1 {
		t.Fatalf("expected exactly one scored candidate on each path: single=%+v batch=%+v", singleResp.Candidates, batchItem.Candidates)
	}
	a, b := singleResp.Candidates[0], batchItem.Candidates[0]
	if a.Score != b.Score || a.StrengthBand != b.StrengthBand || a.ExactIdentifierMatched != b.ExactIdentifierMatched || a.ExactNameMatched != b.ExactNameMatched {
		t.Fatalf("single and batch scoring diverged: single=%+v batch=%+v", a, b)
	}
	if !reflect.DeepEqual(a.ReasonCodes, b.ReasonCodes) {
		t.Fatalf("reason_codes diverged: single=%v batch=%v", a.ReasonCodes, b.ReasonCodes)
	}
}

// TestScoringLineageTracesToActivationSnapshot is ADR-0004 §9.6: every
// field of the request lineage the binding builds must trace to
// Snapshot.Activation content -- none may be a value that appears only in
// a config file (the exact property v8d's fabricated default_lineage
// violated).
func TestScoringLineageTracesToActivationSnapshot(t *testing.T) {
	manager, err := scoringactivation.NewManager(filepath.Join("..", "..", "test", "fixtures", "scoring-activation", "state-ofac-sdn-direct"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.LoadActive()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewScoringBinding(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	want := candidatescoring.Lineage{
		Provider:             snapshot.Activation.Catalog.Provider,
		CatalogID:            snapshot.Activation.Catalog.CatalogID,
		ComponentID:          snapshot.Activation.Catalog.ComponentID,
		ComponentVersion:     snapshot.Activation.Catalog.ComponentVersion,
		ActivationID:         snapshot.Activation.ActivationID,
		NormalizationProfile: snapshot.Activation.Catalog.NormalizationProfile,
	}
	if binding.lineage != want {
		t.Fatalf("lineage = %+v, want %+v (every field must trace to Snapshot.Activation)", binding.lineage, want)
	}
	for name, value := range map[string]string{
		"provider": want.Provider, "catalog_id": want.CatalogID, "component_id": want.ComponentID,
		"component_version": want.ComponentVersion, "activation_id": want.ActivationID,
		"normalization_profile": want.NormalizationProfile,
	} {
		if value == "" {
			t.Fatalf("lineage field %s is empty", name)
		}
	}
}

// TestScoringBindingConcurrentRequestsRace is ADR-0004 §9.7: concurrent
// requests share one read-only *ScoringBinding (engine, lineage, index).
// Run with -race; each goroutine gets its own Service/runtime so the only
// state genuinely shared across goroutines is the binding under test.
func TestScoringBindingConcurrentRequestsRace(t *testing.T) {
	state := loadGoldenState(t)
	binding := testScoringBinding(t)
	clock := func() time.Time { return mustTime(t, "2026-07-14T20:00:00Z") }

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			runtime := &fakeRuntime{info: realCatalogPackageInfo(), values: []runtimemmapclient.Candidate{acmeImportsRuntimeCandidate()}}
			service := Service{Loader: staticLoader{state}, Runtime: runtime, MaxCandidates: 20, Clock: clock, Scoring: binding}
			request := fixtureRequest(fmt.Sprintf("screen-race-%d", index), "fircosoft-prod", "WLS_OFAC_001", "2026-07-20T12:00:00Z")
			response, err := service.Screen(context.Background(), request, "corr-race", fmt.Sprintf("idem-race-%d", index))
			if err != nil {
				errs <- err
				return
			}
			if response.Status != StatusMatched || len(response.Candidates) != 1 || response.Candidates[0].Score <= 0 {
				errs <- fmt.Errorf("worker %d: unexpected response %+v", index, response)
			}
		}(index)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
