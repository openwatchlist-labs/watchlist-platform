package catalogrefresh

import (
	"fmt"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

func Evaluate(base ofaccatalog.Catalog, delta Delta, policy PromotionPolicy, expectedSequence uint64, evaluatedAt time.Time, fullTarget *ofaccatalog.Catalog) (PromotionDecision, ofaccatalog.Catalog, error) {
	decision := PromotionDecision{SchemaVersion: DecisionSchemaVersion, EngineVersion: EngineVersion, Outcome: OutcomeReject, Policy: policy, DeltaID: delta.DeltaID, Sequence: delta.Sequence, ExpectedSequence: expectedSequence, Base: CatalogReference(base), Target: delta.Target, EvaluatedAt: evaluatedAt.UTC()}
	finish := func() PromotionDecision {
		decision.DecisionID = stableID("promotion_decision", struct {
			Outcome            PromotionOutcome
			PolicyID, DeltaID  string
			Sequence, Expected uint64
			Base, Target       CatalogRef
			Reasons            []DecisionReason
			Checksum           string
			Verified           bool
		}{decision.Outcome, policy.PolicyID, delta.DeltaID, delta.Sequence, expectedSequence, decision.Base, decision.Target, decision.Reasons, decision.ReconstructedCatalogChecksum, decision.FullRebuildVerified})
		return decision
	}
	if err := ValidatePolicy(policy); err != nil {
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "invalid_policy", Detail: err.Error()})
		return finish(), ofaccatalog.Catalog{}, nil
	}
	if err := ValidateDelta(delta); err != nil {
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "invalid_delta", Detail: err.Error()})
		return finish(), ofaccatalog.Catalog{}, nil
	}
	if policy.RequireContiguousSequence && delta.Sequence != expectedSequence {
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "delta_sequence_gap", Detail: fmt.Sprintf("got %d, expected %d", delta.Sequence, expectedSequence)})
		return finish(), ofaccatalog.Catalog{}, nil
	}
	if policy.RequireBaseChecksumMatch && delta.Base.CatalogChecksum != base.CatalogChecksum {
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "base_catalog_mismatch", Detail: "delta base checksum does not match active base catalog"})
		return finish(), ofaccatalog.Catalog{}, nil
	}
	target, err := Apply(base, delta, expectedSequence)
	if err != nil {
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "delta_apply_failed", Detail: err.Error()})
		return finish(), ofaccatalog.Catalog{}, nil
	}
	decision.ReconstructedCatalogChecksum = target.CatalogChecksum
	diff, err := Diff(base, target)
	if err != nil {
		return PromotionDecision{}, ofaccatalog.Catalog{}, err
	}
	decision.Diff = &diff
	if fullTarget != nil {
		if err := ofaccatalog.ValidateCatalog(*fullTarget); err != nil {
			decision.Reasons = append(decision.Reasons, DecisionReason{Code: "invalid_full_rebuild", Detail: err.Error()})
			return finish(), ofaccatalog.Catalog{}, nil
		}
		if fullTarget.CatalogChecksum != target.CatalogChecksum || fullTarget.RecordCount != target.RecordCount {
			decision.Reasons = append(decision.Reasons, DecisionReason{Code: "full_rebuild_parity_failed", Detail: "delta reconstruction differs from independently rebuilt target"})
			return finish(), ofaccatalog.Catalog{}, nil
		}
		decision.FullRebuildVerified = true
	}
	if policy.RequireTargetChecksumMatch && target.CatalogChecksum != delta.Target.CatalogChecksum {
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "target_checksum_mismatch", Detail: "reconstructed target checksum differs from delta target"})
		return finish(), ofaccatalog.Catalog{}, nil
	}
	forceAt := func(value, threshold int) bool {
		if policy.ForceFullAtOrAboveThreshold {
			return value >= threshold
		}
		return value > threshold
	}
	if len(delta.Operations) > policy.MaxOperations {
		decision.Outcome = OutcomeForceFull
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "operation_limit_exceeded", Detail: fmt.Sprintf("%d operations exceed policy maximum %d", len(delta.Operations), policy.MaxOperations)})
	}
	if forceAt(diff.ChangeRatioBasisPoints, policy.MaxChangeRatioBasisPoints) {
		decision.Outcome = OutcomeForceFull
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "change_ratio_threshold", Detail: fmt.Sprintf("%d basis points meets or exceeds threshold %d", diff.ChangeRatioBasisPoints, policy.MaxChangeRatioBasisPoints)})
	}
	if forceAt(diff.DeletionRatioBasisPoints, policy.MaxDeletionRatioBasisPoints) {
		decision.Outcome = OutcomeForceFull
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "deletion_ratio_threshold", Detail: fmt.Sprintf("%d basis points meets or exceeds threshold %d", diff.DeletionRatioBasisPoints, policy.MaxDeletionRatioBasisPoints)})
	}
	if policy.FullRebuildVerificationInterval > 0 && delta.Sequence%policy.FullRebuildVerificationInterval == 0 && !decision.FullRebuildVerified {
		decision.Outcome = OutcomeForceFull
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "periodic_full_rebuild_due", Detail: fmt.Sprintf("sequence %d requires independent full rebuild verification", delta.Sequence)})
	}
	if decision.Outcome == OutcomeReject {
		decision.Outcome = OutcomePromoteDelta
		decision.Reasons = append(decision.Reasons, DecisionReason{Code: "delta_within_policy", Detail: "delta reconstructed a complete catalog within configured promotion thresholds"})
	}
	return finish(), target, nil
}
