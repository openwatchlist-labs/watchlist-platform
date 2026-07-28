package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/activationpromotion"
	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "stage":
		err = runStage(os.Args[2:])
	case "prepare":
		err = runPrepare(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "compare-shadow":
		err = runCompareShadow(os.Args[2:])
	case "summarize-shadow":
		err = runSummarize(os.Args[2:])
	case "evaluate":
		err = runEvaluate(os.Args[2:])
	case "start-canary":
		err = runStartCanary(os.Args[2:])
	case "ack":
		err = runAck(os.Args[2:])
	case "promote":
		err = runPromote(os.Args[2:])
	case "rollback":
		err = runRollback(os.Args[2:])
	case "recover":
		err = runRecover(os.Args[2:])
	case "verify-audit":
		err = runVerifyAudit(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "activation-promotion:", err)
		os.Exit(1)
	}
}

func runStage(args []string) error {
	flags := flag.NewFlagSet("stage", flag.ContinueOnError)
	activationState := flags.String("activation-state-dir", "", "Phase 8E activation state directory")
	activationID := flags.String("activation-id", "", "candidate activation ID")
	expectedCurrent := flags.String("expected-current-activation", "", "current activation CAS value")
	descriptor := flags.String("catalog-descriptor", "", "catalog descriptor")
	projectionPackage := flags.String("projection-package", "", "projection package")
	policy := flags.String("policy", "", "scoring policy")
	if err := flags.Parse(args); err != nil {
		return err
	}
	manager, err := scoringactivation.NewManager(*activationState)
	if err != nil {
		return err
	}
	snapshot, err := manager.Stage(scoringactivation.ActivateRequest{
		ActivationID: *activationID, CatalogDescriptorPath: *descriptor,
		ProjectionPackagePath: *projectionPackage, ScoringPolicyPath: *policy,
	}, *expectedCurrent)
	if err != nil {
		return err
	}
	digest, _ := manager.ActivationDocumentSHA256(snapshot.Activation.ActivationID)
	return encode(map[string]any{"status": "ok", "activation_id": snapshot.Activation.ActivationID, "previous_activation_id": snapshot.Activation.PreviousActivationID, "activation_sha256": digest})
}

func runPrepare(args []string) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	activationState, promotionState := stateFlags(flags)
	intentID := flags.String("intent-id", "", "immutable promotion intent ID")
	candidateID := flags.String("candidate-activation", "", "staged candidate activation ID")
	operator := flags.String("operator", "", "operator identity")
	reason := flags.String("reason", "", "promotion reason")
	canaryBPS := flags.Int("canary-bps", 500, "canary traffic in basis points")
	allowlist := flags.String("allowlist", "", "comma-separated correlation IDs")
	requiredAcks := flags.Int("required-ready-acks", 1, "required ready instance acknowledgements")
	maxScoreDelta := flags.Int("max-score-delta", 0, "maximum absolute candidate score delta")
	maxTopBPS := flags.Int("max-top-candidate-change-bps", 0, "maximum top candidate change rate")
	maxSetBPS := flags.Int("max-candidate-set-change-bps", 0, "maximum candidate set change rate")
	maxCoverageLoss := flags.Int("max-coverage-loss", 0, "maximum missing candidates")
	maxBlockers := flags.Int("max-additional-blockers", 0, "maximum additional blockers")
	if err := flags.Parse(args); err != nil {
		return err
	}
	manager, err := promotionManager(*activationState, *promotionState)
	if err != nil {
		return err
	}
	status, err := manager.Prepare(activationpromotion.PrepareRequest{
		IntentID: *intentID, CandidateActivationID: *candidateID, Operator: *operator, Reason: *reason,
		CanaryBasisPoints: *canaryBPS, CanaryCorrelationAllowlist: splitCSV(*allowlist), RequiredReadyAcks: *requiredAcks,
		Thresholds: activationpromotion.Thresholds{
			MaxScoreDelta: *maxScoreDelta, MaxTopCandidateChangeBPS: *maxTopBPS,
			MaxCandidateSetChangeBPS: *maxSetBPS, MaxCoverageLossCount: *maxCoverageLoss,
			MaxAdditionalBlockerCount: *maxBlockers,
		},
	})
	if err != nil {
		return err
	}
	return encode(status)
}

func runStatus(args []string) error {
	manager, err := managerFromArgs("status", args)
	if err != nil {
		return err
	}
	status, err := manager.Status()
	if err != nil {
		return err
	}
	return encode(status)
}

func runCompareShadow(args []string) error {
	flags := flag.NewFlagSet("compare-shadow", flag.ContinueOnError)
	activationState, promotionState := stateFlags(flags)
	intentID := flags.String("intent-id", "", "promotion intent ID")
	correlationID := flags.String("correlation-id", "", "shadow correlation ID")
	currentPath := flags.String("current-response", "", "current response JSON")
	candidatePath := flags.String("candidate-response", "", "candidate response JSON")
	observedAt := flags.String("observed-at", "", "RFC3339 observation time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	currentRaw, err := os.ReadFile(*currentPath)
	if err != nil {
		return err
	}
	candidateRaw, err := os.ReadFile(*candidatePath)
	if err != nil {
		return err
	}
	if *observedAt == "" {
		return fmt.Errorf("--observed-at is required")
	}
	observation, err := activationpromotion.CompareResponses(*intentID, *correlationID, currentRaw, candidateRaw, *observedAt)
	if err != nil {
		return err
	}
	manager, err := promotionManager(*activationState, *promotionState)
	if err != nil {
		return err
	}
	if err := manager.RecordObservation(observation); err != nil {
		return err
	}
	return encode(observation)
}

func runSummarize(args []string) error {
	flags := flag.NewFlagSet("summarize-shadow", flag.ContinueOnError)
	activationState, promotionState := stateFlags(flags)
	intentID := flags.String("intent-id", "", "promotion intent ID")
	output := flags.String("output", "", "optional summary output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	manager, err := promotionManager(*activationState, *promotionState)
	if err != nil {
		return err
	}
	summary, err := manager.SummarizeObservations(*intentID)
	if err != nil {
		return err
	}
	if *output != "" {
		raw, _ := json.MarshalIndent(summary, "", "  ")
		raw = append(raw, '\n')
		if err := os.WriteFile(*output, raw, 0o644); err != nil {
			return err
		}
	}
	return encode(summary)
}

func runEvaluate(args []string) error {
	flags := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	activationState, promotionState := stateFlags(flags)
	revision := flags.Int64("expected-revision", 0, "promotion revision CAS value")
	report := flags.String("report", "", "shadow summary JSON")
	actor := flags.String("actor", "", "operator or validation identity")
	reason := flags.String("reason", "", "evaluation reason")
	if err := flags.Parse(args); err != nil {
		return err
	}
	var summary activationpromotion.ShadowSummary
	if err := decodeStrict(*report, &summary); err != nil {
		return err
	}
	manager, err := promotionManager(*activationState, *promotionState)
	if err != nil {
		return err
	}
	status, err := manager.Evaluate(*revision, summary, *actor, *reason)
	if err != nil {
		return err
	}
	return encode(status)
}

func runStartCanary(args []string) error {
	manager, revision, actor, reason, err := transitionArgs("start-canary", args)
	if err != nil {
		return err
	}
	status, err := manager.StartCanary(revision, actor, reason)
	if err != nil {
		return err
	}
	return encode(status)
}

func runAck(args []string) error {
	flags := flag.NewFlagSet("ack", flag.ContinueOnError)
	activationState, promotionState := stateFlags(flags)
	intentID := flags.String("intent-id", "", "promotion intent ID")
	instanceID := flags.String("instance-id", "", "runtime instance ID")
	activationID := flags.String("activation-id", "", "loaded candidate activation ID")
	statusValue := flags.String("status", activationpromotion.AckReady, "ready or not_ready")
	tupleSHA := flags.String("tuple-sha256", "", "loaded activation tuple SHA-256")
	if err := flags.Parse(args); err != nil {
		return err
	}
	manager, err := promotionManager(*activationState, *promotionState)
	if err != nil {
		return err
	}
	status, err := manager.Acknowledge(activationpromotion.Ack{
		IntentID: *intentID, InstanceID: *instanceID, ActivationID: *activationID, Status: *statusValue, TupleSHA256: *tupleSHA,
	})
	if err != nil {
		return err
	}
	return encode(status)
}

func runPromote(args []string) error {
	manager, revision, actor, reason, err := transitionArgs("promote", args)
	if err != nil {
		return err
	}
	status, err := manager.Promote(revision, actor, reason)
	if err != nil {
		return err
	}
	return encode(status)
}

func runRollback(args []string) error {
	manager, revision, actor, reason, err := transitionArgs("rollback", args)
	if err != nil {
		return err
	}
	status, err := manager.Rollback(revision, actor, reason)
	if err != nil {
		return err
	}
	return encode(status)
}

func runRecover(args []string) error {
	manager, err := managerFromArgs("recover", args)
	if err != nil {
		return err
	}
	result, err := manager.Recover()
	if err != nil {
		return err
	}
	return encode(map[string]any{"status": "ok", "recovery": result})
}

func runVerifyAudit(args []string) error {
	manager, err := managerFromArgs("verify-audit", args)
	if err != nil {
		return err
	}
	if err := manager.VerifyAudit(); err != nil {
		return err
	}
	status, err := manager.Status()
	if err != nil {
		return err
	}
	return encode(map[string]any{"status": "ok", "audit_head": status.AuditHead})
}

func transitionArgs(name string, args []string) (*activationpromotion.Manager, int64, string, string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	activationState, promotionState := stateFlags(flags)
	revision := flags.Int64("expected-revision", 0, "promotion revision CAS value")
	actor := flags.String("actor", "", "operator identity")
	reason := flags.String("reason", "", "transition reason")
	if err := flags.Parse(args); err != nil {
		return nil, 0, "", "", err
	}
	manager, err := promotionManager(*activationState, *promotionState)
	return manager, *revision, *actor, *reason, err
}

func managerFromArgs(name string, args []string) (*activationpromotion.Manager, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	activationState, promotionState := stateFlags(flags)
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	return promotionManager(*activationState, *promotionState)
}

func stateFlags(flags *flag.FlagSet) (*string, *string) {
	return flags.String("activation-state-dir", "", "Phase 8E activation state directory"), flags.String("promotion-state-dir", "", "Phase 8F promotion state directory")
}

func promotionManager(activationState, promotionState string) (*activationpromotion.Manager, error) {
	activations, err := scoringactivation.NewManager(activationState)
	if err != nil {
		return nil, err
	}
	return activationpromotion.NewManager(promotionState, activations)
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func decodeStrict(path string, destination any) error {
	if path == "" {
		return fmt.Errorf("report path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func encode(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }

func usage() {
	fmt.Fprintln(os.Stderr, "usage: activation-promotion <stage|prepare|status|compare-shadow|summarize-shadow|evaluate|start-canary|ack|promote|rollback|recover|verify-audit> [options]")
	os.Exit(2)
}
