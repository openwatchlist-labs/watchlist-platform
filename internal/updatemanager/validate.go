package updatemanager

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
)

var (
	ErrInvalidUpdate       = errors.New("invalid update manager contract")
	ErrNotDue              = errors.New("scheduled update is not due")
	ErrFleetNotReady       = errors.New("fleet is not ready")
	ErrCanaryFailed        = errors.New("canary activation failed")
	ErrActivationFailed    = errors.New("fleet activation failed")
	ErrFullRebuildRequired = errors.New("full catalog rebuild required")
	ErrDeltaRejected       = errors.New("catalog delta rejected")
)

func ValidateSpec(spec UpdateSpec) error {
	if spec.SchemaVersion != UpdateSpecSchemaVersion || strings.TrimSpace(spec.UpdateID) == "" || strings.TrimSpace(spec.SourceURL) == "" || spec.ScheduledFor.IsZero() || spec.RequestedAt.IsZero() {
		return fmt.Errorf("%w: invalid update spec header", ErrInvalidUpdate)
	}
	spec.CanaryWorkers = normalizedIDs(spec.CanaryWorkers)
	spec.RequiredWorkers = normalizedIDs(spec.RequiredWorkers)
	if len(spec.RequiredWorkers) == 0 || len(spec.CanaryWorkers) == 0 {
		return fmt.Errorf("%w: required and canary workers are required", ErrInvalidUpdate)
	}
	required := map[string]struct{}{}
	for _, id := range spec.RequiredWorkers {
		required[id] = struct{}{}
	}
	for _, id := range spec.CanaryWorkers {
		if _, ok := required[id]; !ok {
			return fmt.Errorf("%w: canary %q is not required", ErrInvalidUpdate, id)
		}
	}
	return nil
}

func ValidateWorkerDescriptor(worker WorkerDescriptor) error {
	if worker.SchemaVersion != WorkerDescriptorSchemaVersion || strings.TrimSpace(worker.WorkerID) == "" || strings.TrimSpace(worker.Zone) == "" {
		return fmt.Errorf("%w: invalid worker descriptor", ErrInvalidUpdate)
	}
	return nil
}

func ValidateReadinessAck(ack WorkerReadinessAck) error {
	if ack.SchemaVersion != WorkerReadinessSchemaVersion || ack.AckID == "" || ack.UpdateID == "" || ack.PackageID == "" || ack.PackageChecksum == "" || ack.CheckedAt.IsZero() || len(ack.Checks) == 0 {
		return fmt.Errorf("%w: invalid readiness ack", ErrInvalidUpdate)
	}
	if err := ValidateWorkerDescriptor(ack.Worker); err != nil {
		return err
	}
	expectedReady := true
	for _, check := range ack.Checks {
		if check.Status != catalogruntime.CheckPass {
			expectedReady = false
		}
	}
	if ack.Ready != expectedReady {
		return fmt.Errorf("%w: readiness value disagrees with checks", ErrInvalidUpdate)
	}
	copyAck := ack
	copyAck.AckID = ""
	if ack.AckID != stableID("worker_readiness", copyAck) {
		return fmt.Errorf("%w: readiness ack id drift", ErrInvalidUpdate)
	}
	return nil
}

func ValidateActivationAck(ack WorkerActivationAck) error {
	if ack.SchemaVersion != WorkerActivationSchemaVersion || ack.AckID == "" || ack.UpdateID == "" || ack.FleetEpoch == 0 || ack.ActivatedAt.IsZero() || ack.Detail == "" {
		return fmt.Errorf("%w: invalid activation ack", ErrInvalidUpdate)
	}
	if ack.Phase != PhaseCanary && ack.Phase != PhaseBroad && ack.Phase != PhaseRollback {
		return fmt.Errorf("%w: invalid rollout phase", ErrInvalidUpdate)
	}
	if ack.Status != AckPass && ack.Status != AckFail {
		return fmt.Errorf("%w: invalid ack status", ErrInvalidUpdate)
	}
	if err := ValidateWorkerDescriptor(ack.Worker); err != nil {
		return err
	}
	if err := catalogruntime.ValidateGenerationStamp(ack.Generation); err != nil {
		return err
	}
	copyAck := ack
	copyAck.AckID = ""
	if ack.AckID != stableID("worker_activation", copyAck) {
		return fmt.Errorf("%w: activation ack id drift", ErrInvalidUpdate)
	}
	return nil
}

func ValidateFleetActivation(record FleetActivationRecord) error {
	if record.SchemaVersion != FleetActivationSchemaVersion || record.ActivationID == "" || record.UpdateID == "" || record.FleetEpoch == 0 || record.StartedAt.IsZero() || record.CompletedAt.IsZero() {
		return fmt.Errorf("%w: invalid fleet activation header", ErrInvalidUpdate)
	}
	if err := ofacruntime.ValidateInfo(record.PackageInfo); err != nil {
		return err
	}
	if len(record.ReadinessAcks) != len(record.RequiredWorkers) || len(record.ActivationAcks) != len(record.RequiredWorkers) {
		return fmt.Errorf("%w: incomplete fleet acknowledgements", ErrInvalidUpdate)
	}
	ids := append([]string(nil), record.RequiredWorkers...)
	sort.Strings(ids)
	for _, ack := range record.ReadinessAcks {
		if err := ValidateReadinessAck(ack); err != nil {
			return err
		}
	}
	for _, ack := range record.ActivationAcks {
		if err := ValidateActivationAck(ack); err != nil {
			return err
		}
		if ack.FleetEpoch != record.FleetEpoch {
			return fmt.Errorf("%w: activation epoch mismatch", ErrInvalidUpdate)
		}
	}
	if record.State == FleetActivationComplete && record.Failure != "" {
		return fmt.Errorf("%w: completed activation has failure", ErrInvalidUpdate)
	}
	if record.State == FleetActivationFailed && record.Failure == "" {
		return fmt.Errorf("%w: failed activation lacks reason", ErrInvalidUpdate)
	}
	copyRecord := record
	copyRecord.ActivationID = ""
	if record.ActivationID != stableID("fleet_activation", copyRecord) {
		return fmt.Errorf("%w: fleet activation id drift", ErrInvalidUpdate)
	}
	return nil
}
