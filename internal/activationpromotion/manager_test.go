package activationpromotion

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/projectionpackage"
	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
)

type testEnvironment struct {
	promotions  *Manager
	activations *scoringactivation.Manager
	baseID      string
	candidateID string
}

func setupPromotion(t *testing.T) testEnvironment {
	t.Helper()
	root := t.TempDir()
	descriptorSource := filepath.Join("..", "..", "test", "fixtures", "projection-package", "catalog-descriptor.json")
	inputSource := filepath.Join("..", "..", "test", "fixtures", "projection-package", "canonical-input.json")
	catalogSource := filepath.Join("..", "..", "test", "fixtures", "projection-package", "catalog-fixture.mmap")
	policySource := filepath.Join("..", "..", "configs", "scoring", "candidate-scoring-r1.json")
	descriptorPath := filepath.Join(root, "catalog-descriptor.json")
	catalogPath := filepath.Join(root, "catalog-fixture.mmap")
	policyPath := filepath.Join(root, "policy.json")
	copyTestFile(t, descriptorSource, descriptorPath)
	copyTestFile(t, catalogSource, catalogPath)
	copyTestFile(t, policySource, policyPath)
	descriptor, err := projectionpackage.LoadCatalogDescriptor(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	input, err := projectionpackage.LoadCanonicalInput(inputSource)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := projectionpackage.Compile(descriptor, input, filepath.Join(root, "packages"))
	if err != nil {
		t.Fatal(err)
	}
	activationManager, err := scoringactivation.NewManager(filepath.Join(root, "activation-state"))
	if err != nil {
		t.Fatal(err)
	}
	baseID := "activation-base"
	candidateID := "activation-candidate"
	if _, err := activationManager.Activate(scoringactivation.ActivateRequest{
		ActivationID: baseID, CatalogDescriptorPath: descriptorPath,
		ProjectionPackagePath: pkg.Directory, ScoringPolicyPath: policyPath,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := activationManager.Stage(scoringactivation.ActivateRequest{
		ActivationID: candidateID, CatalogDescriptorPath: descriptorPath,
		ProjectionPackagePath: pkg.Directory, ScoringPolicyPath: policyPath,
	}, baseID); err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 7, 14, 22, 0, 0, 0, time.UTC)
	promotionManager, err := newManager(filepath.Join(root, "promotion-state"), activationManager, func() time.Time {
		fixed = fixed.Add(time.Second)
		return fixed
	})
	if err != nil {
		t.Fatal(err)
	}
	return testEnvironment{promotions: promotionManager, activations: activationManager, baseID: baseID, candidateID: candidateID}
}

func copyTestFile(t *testing.T, source, destination string) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func defaultPrepare(environment testEnvironment) PrepareRequest {
	return PrepareRequest{
		IntentID: "promotion-fixture", CandidateActivationID: environment.candidateID,
		Operator: "operator@example.test", Reason: "validate candidate tuple",
		CanaryBasisPoints: 1000, CanaryCorrelationAllowlist: []string{"corr-allowlisted"},
		RequiredReadyAcks: 1,
		Thresholds:        Thresholds{MaxScoreDelta: 0, MaxTopCandidateChangeBPS: 0, MaxCandidateSetChangeBPS: 0},
	}
}

func TestPromotionLifecycleCASAuditAndRollback(t *testing.T) {
	environment := setupPromotion(t)
	status, err := environment.promotions.Prepare(defaultPrepare(environment))
	if err != nil {
		t.Fatal(err)
	}
	if status.State.Phase != PhasePrepared || status.State.Revision != 1 {
		t.Fatalf("unexpected prepared state: %#v", status.State)
	}
	response := []byte(`{"candidates":[{"candidate_id":"a","score":900}],"blockers":[]}`)
	observation, err := CompareResponses(status.Intent.IntentID, "corr-shadow", response, response, "2026-07-14T22:01:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if err := environment.promotions.RecordObservation(observation); err != nil {
		t.Fatal(err)
	}
	summary, err := environment.promotions.SummarizeObservations(status.Intent.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	status, err = environment.promotions.Evaluate(1, summary, "validator", "shadow report passed")
	if err != nil || status.State.Phase != PhaseValidated || status.State.Revision != 2 {
		t.Fatalf("evaluate failed: %v %#v", err, status.State)
	}
	if _, err := environment.promotions.StartCanary(99, "operator", "wrong revision"); err == nil || !strings.Contains(err.Error(), "CAS mismatch") {
		t.Fatalf("expected revision CAS rejection, got %v", err)
	}
	status, err = environment.promotions.StartCanary(2, "operator", "start bounded canary")
	if err != nil || status.State.Phase != PhaseCanary || status.State.Revision != 3 {
		t.Fatalf("start canary failed: %v %#v", err, status.State)
	}
	route, _, err := environment.promotions.Route("corr-allowlisted")
	if err != nil || route != "candidate" {
		t.Fatalf("allowlisted route=%q err=%v", route, err)
	}
	status, err = environment.promotions.Acknowledge(Ack{
		IntentID: status.Intent.IntentID, InstanceID: "instance-a", ActivationID: environment.candidateID,
		Status: AckReady, TupleSHA256: status.Intent.CandidateActivationSHA256,
	})
	if err != nil || status.ReadyAckCount != 1 {
		t.Fatalf("ack failed: %v %#v", err, status)
	}
	status, err = environment.promotions.Promote(3, "operator", "canary healthy")
	if err != nil || status.State.Phase != PhasePromoted || status.State.Revision != 4 {
		t.Fatalf("promote failed: %v %#v", err, status.State)
	}
	active, err := environment.activations.LoadActive()
	if err != nil || active.Activation.ActivationID != environment.candidateID {
		t.Fatalf("candidate not active: %v %#v", err, active.Activation)
	}
	status, err = environment.promotions.Rollback(4, "operator", "rollback drill")
	if err != nil || status.State.Phase != PhaseRolledBack || status.State.Revision != 5 {
		t.Fatalf("rollback failed: %v %#v", err, status.State)
	}
	active, err = environment.activations.LoadActive()
	if err != nil || active.Activation.ActivationID != environment.baseID {
		t.Fatalf("base not restored: %v %#v", err, active.Activation)
	}
	if err := environment.promotions.VerifyAudit(); err != nil {
		t.Fatal(err)
	}
	if status.AuditHead.Sequence < 6 {
		t.Fatalf("audit sequence too small: %d", status.AuditHead.Sequence)
	}
}

func TestThresholdBlockAndAuditTamperDetection(t *testing.T) {
	environment := setupPromotion(t)
	request := defaultPrepare(environment)
	request.Thresholds.MaxScoreDelta = 10
	status, err := environment.promotions.Prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	current := []byte(`{"candidates":[{"candidate_id":"a","score":900}],"blockers":[]}`)
	candidate := []byte(`{"candidates":[{"candidate_id":"a","score":850}],"blockers":[{"code":"new"}]}`)
	observation, err := CompareResponses(status.Intent.IntentID, "corr-drift", current, candidate, "2026-07-14T22:02:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if err := environment.promotions.RecordObservation(observation); err != nil {
		t.Fatal(err)
	}
	summary, err := environment.promotions.SummarizeObservations(status.Intent.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	status, err = environment.promotions.Evaluate(1, summary, "validator", "drift gate")
	if err != nil {
		t.Fatal(err)
	}
	if status.State.Phase != PhaseBlocked || len(status.State.Blockers) == 0 {
		t.Fatalf("expected blocked state: %#v", status.State)
	}
	matches, err := filepath.Glob(filepath.Join(environment.promotions.auditDirectory(), "*.json"))
	if err != nil || len(matches) == 0 {
		t.Fatal("audit event not found")
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "promotion_prepared", "promotion_tampered", 1))
	if err := os.WriteFile(matches[0], raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := environment.promotions.VerifyAudit(); err == nil {
		t.Fatal("tampered audit event was accepted")
	}
}

func TestShadowComparisonDetectsOrderCoverageAndScoreDrift(t *testing.T) {
	current := []byte(`{"candidates":[{"candidate_id":"a","score":900},{"candidate_id":"b","score":700}],"blockers":[]}`)
	candidate := []byte(`{"candidates":[{"candidate_id":"b","score":730}],"blockers":[{"code":"projection_missing"}]}`)
	observation, err := CompareResponses("intent", "corr", current, candidate, "2026-07-14T22:03:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if observation.CandidateSetChanges != 1 || observation.TopCandidateChanges != 1 || observation.CoverageLossCount != 1 || observation.MaxAbsoluteScoreDelta != 30 || observation.AdditionalBlockerCount != 1 {
		t.Fatalf("unexpected observation: %#v", observation)
	}
	if err := verifyObservation(observation); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverCompletesPendingStateAndAudit(t *testing.T) {
	environment := setupPromotion(t)
	status, err := environment.promotions.Prepare(defaultPrepare(environment))
	if err != nil {
		t.Fatal(err)
	}
	state := status.State
	state.Revision = 2
	state.Phase = PhaseValidated
	state.UpdatedAt = "2026-07-14T22:10:00Z"
	event := environment.promotions.nextAuditEvent("promotion_validated", state, "recovery-test", "simulate interrupted pointer write", nil)
	if err := environment.promotions.writeImmutable(environment.promotions.stateSnapshotPath(state.IntentID, state.Revision), state); err != nil {
		t.Fatal(err)
	}
	pending := pendingDocument{SchemaVersion: PendingSchemaV1, State: state, AuditEvent: event}
	raw, _ := canonical(pending)
	if err := atomicWrite(environment.promotions.pendingPath(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := environment.promotions.Recover()
	if err != nil || result != "completed" {
		t.Fatalf("recover result=%q err=%v", result, err)
	}
	recovered, err := environment.promotions.Status()
	if err != nil || recovered.State.Revision != 2 || recovered.State.Phase != PhaseValidated {
		t.Fatalf("pending state not completed: %v %#v", err, recovered.State)
	}
	if err := environment.promotions.VerifyAudit(); err != nil {
		t.Fatal(err)
	}
}
