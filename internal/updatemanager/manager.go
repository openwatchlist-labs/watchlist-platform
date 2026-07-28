package updatemanager

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

type Manager struct {
	StateDir   string
	ArchiveDir string
	Workers    []Worker
	Audit      AuditHistory
}

func NewSpec(sourcePath, sourceURL string, scheduledFor, requestedAt time.Time, canaries, required []string) (UpdateSpec, error) {
	seed := struct {
		SourcePath, SourceURL string
		ScheduledFor          time.Time
		Required              []string
	}{sourcePath, sourceURL, scheduledFor.UTC(), normalizedIDs(required)}
	spec := UpdateSpec{SchemaVersion: UpdateSpecSchemaVersion, UpdateID: stableID("update", seed), SourcePath: sourcePath, SourceURL: sourceURL, ScheduledFor: scheduledFor.UTC(), RequestedAt: requestedAt.UTC(), CanaryWorkers: normalizedIDs(canaries), RequiredWorkers: normalizedIDs(required)}
	return spec, ValidateSpec(spec)
}

func (m *Manager) Prepare(ctx context.Context, spec UpdateSpec, now, compiledAt time.Time) (UpdateRecord, []byte, error) {
	if err := ValidateSpec(spec); err != nil {
		return UpdateRecord{}, nil, err
	}
	if now.Before(spec.ScheduledFor) {
		return UpdateRecord{}, nil, fmt.Errorf("%w: scheduled_for=%s now=%s", ErrNotDue, spec.ScheduledFor, now)
	}
	record := UpdateRecord{SchemaVersion: UpdateRecordSchemaVersion, UpdateID: spec.UpdateID, ManagerVersion: ManagerVersion, Status: StatusScheduled, Spec: spec, UpdatedAt: now.UTC()}
	m.appendEvent("update_due", spec.UpdateID, now, spec)
	var acquired ofacsource.Acquired
	var err error
	if spec.SourcePath != "" {
		acquired, err = ofacsource.AcquireLocal(spec.SourcePath, spec.SourceURL, now)
	} else {
		acquired, err = ofacsource.AcquireHTTP(ctx, spec.SourceURL, now)
	}
	if err != nil {
		return m.failRecord(record, now, err)
	}
	sourcePackage, err := ofacsource.Parse(acquired)
	if err != nil {
		return m.failRecord(record, now, err)
	}
	archivePath, err := ofacsource.Archive(m.ArchiveDir, acquired, sourcePackage.Manifest)
	if err != nil {
		return m.failRecord(record, now, err)
	}
	record.Status = StatusStaged
	record.UpdatedAt = now.UTC()
	m.appendEvent("source_staged", spec.UpdateID, now, sourcePackage.Manifest)
	catalog, err := ofaccatalog.Project(sourcePackage)
	if err != nil {
		return m.failRecord(record, now, err)
	}
	artifact, info, err := ofacruntime.Compile(catalog)
	if err != nil {
		return m.failRecord(record, now, err)
	}
	if compiledAt.IsZero() {
		compiledAt = now
	}
	packagePath, err := persistImmutablePackage(m.StateDir, info.PackageID, info.PackageChecksum, artifact)
	if err != nil {
		return m.failRecord(record, now, err)
	}
	record.Status = StatusCompiled
	record.Staged = &StagedArtifacts{SourceManifest: sourcePackage.Manifest, PackageInfo: info, PackagePath: packagePath, SourceArchivePath: archivePath, CompiledAt: compiledAt.UTC()}
	record.UpdatedAt = now.UTC()
	m.appendEvent("package_compiled", spec.UpdateID, compiledAt, info)
	if err := (Store{Root: m.StateDir}).PersistUpdate(record); err != nil {
		return m.failRecord(record, now, err)
	}
	return record, artifact, nil
}

func (m *Manager) Activate(ctx context.Context, record UpdateRecord, artifact []byte, checkedAt, activatedAt time.Time) (FleetActivationRecord, error) {
	if record.Staged == nil {
		return FleetActivationRecord{}, fmt.Errorf("%w: update has no staged package", ErrInvalidUpdate)
	}
	workers := m.workerMap()
	readiness := make([]WorkerReadinessAck, 0, len(record.Spec.RequiredWorkers))
	for _, id := range record.Spec.RequiredWorkers {
		worker, ok := workers[id]
		if !ok {
			return FleetActivationRecord{}, fmt.Errorf("%w: required worker %q unavailable", ErrFleetNotReady, id)
		}
		ack, err := worker.Stage(ctx, record.UpdateID, artifact, record.Staged.PackageInfo, record.Staged.CompiledAt, checkedAt)
		if err != nil {
			return FleetActivationRecord{}, err
		}
		readiness = append(readiness, ack)
		_ = (Store{Root: m.StateDir}).PersistReadiness(record.UpdateID, ack)
		m.appendEvent("worker_readiness", record.UpdateID, checkedAt, ack)
		if !ack.Ready {
			return FleetActivationRecord{}, fmt.Errorf("%w: worker %s", ErrFleetNotReady, id)
		}
	}
	previous, _ := (Store{Root: m.StateDir}).Active()
	epoch := uint64(1)
	if previous != nil {
		epoch = previous.FleetEpoch + 1
	}
	activation := FleetActivationRecord{SchemaVersion: FleetActivationSchemaVersion, UpdateID: record.UpdateID, FleetEpoch: epoch, State: FleetActivationComplete, PackageInfo: record.Staged.PackageInfo, CanaryWorkers: record.Spec.CanaryWorkers, RequiredWorkers: record.Spec.RequiredWorkers, ReadinessAcks: readiness, Previous: previous, StartedAt: activatedAt.UTC()}
	canarySet := map[string]struct{}{}
	for _, id := range record.Spec.CanaryWorkers {
		canarySet[id] = struct{}{}
	}
	activateOne := func(id string, phase RolloutPhase) (WorkerActivationAck, error) {
		return workers[id].Activate(ctx, ActivationCommand{UpdateID: record.UpdateID, FleetEpoch: epoch, Phase: phase, PackageData: artifact, PackageInfo: record.Staged.PackageInfo, CompiledAt: record.Staged.CompiledAt, ActivatedAt: activatedAt})
	}
	for _, id := range record.Spec.CanaryWorkers {
		ack, err := activateOne(id, PhaseCanary)
		if err != nil {
			return FleetActivationRecord{}, err
		}
		activation.ActivationAcks = append(activation.ActivationAcks, ack)
		m.appendEvent("canary_activation", record.UpdateID, activatedAt, ack)
		if ack.Status != AckPass || !ack.ProbePassed {
			activation.State = FleetActivationFailed
			activation.Failure = "canary worker " + id + " failed"
			activation.CompletedAt = activatedAt.UTC()
			activation.ActivationID = stableID("fleet_activation", activation)
			_ = (Store{Root: m.StateDir}).PersistActivation(activation)
			return activation, ErrCanaryFailed
		}
	}
	for _, id := range record.Spec.RequiredWorkers {
		if _, ok := canarySet[id]; ok {
			continue
		}
		ack, err := activateOne(id, PhaseBroad)
		if err != nil {
			return FleetActivationRecord{}, err
		}
		activation.ActivationAcks = append(activation.ActivationAcks, ack)
		m.appendEvent("worker_activation", record.UpdateID, activatedAt, ack)
		if ack.Status != AckPass || !ack.ProbePassed {
			activation.State = FleetActivationFailed
			activation.Failure = "worker " + id + " failed"
			activation.CompletedAt = activatedAt.UTC()
			activation.ActivationID = stableID("fleet_activation", activation)
			_ = (Store{Root: m.StateDir}).PersistActivation(activation)
			return activation, ErrActivationFailed
		}
	}
	sort.Slice(activation.ReadinessAcks, func(i, j int) bool {
		return activation.ReadinessAcks[i].Worker.WorkerID < activation.ReadinessAcks[j].Worker.WorkerID
	})
	sort.Slice(activation.ActivationAcks, func(i, j int) bool {
		return activation.ActivationAcks[i].Worker.WorkerID < activation.ActivationAcks[j].Worker.WorkerID
	})
	activation.CompletedAt = activatedAt.UTC()
	activation.ActivationID = stableID("fleet_activation", activation)
	if err := ValidateFleetActivation(activation); err != nil {
		return FleetActivationRecord{}, err
	}
	store := Store{Root: m.StateDir}
	if err := store.PersistActivation(activation); err != nil {
		return FleetActivationRecord{}, err
	}
	manifest := record.Staged.PackageInfo.Manifest
	pointer := FleetPointer{SchemaVersion: FleetPointerSchemaVersion, ActivationID: activation.ActivationID, UpdateID: record.UpdateID, FleetEpoch: epoch, PackageID: record.Staged.PackageInfo.PackageID, PackageChecksum: record.Staged.PackageInfo.PackageChecksum, CatalogID: manifest.Provider.Catalog.CatalogID, CatalogVersion: manifest.Provider.Catalog.CatalogVersion, CatalogChecksum: manifest.Provider.Catalog.CatalogChecksum, SourceManifestID: manifest.SourceManifestID, ActivatedAt: activatedAt.UTC()}
	if err := store.SetActive(pointer); err != nil {
		return FleetActivationRecord{}, err
	}
	m.appendEvent("fleet_active", record.UpdateID, activatedAt, pointer)
	return activation, nil
}

func (m *Manager) Rollback(ctx context.Context, from FleetActivationRecord, target UpdateRecord, artifact []byte, reason string, at time.Time) (FleetRollbackRecord, error) {
	if target.Staged == nil || reason == "" {
		return FleetRollbackRecord{}, fmt.Errorf("%w: rollback target and reason required", ErrInvalidUpdate)
	}
	workers := m.workerMap()
	epoch := from.FleetEpoch + 1
	acks := make([]WorkerActivationAck, 0, len(from.RequiredWorkers))
	for _, id := range from.RequiredWorkers {
		worker := workers[id]
		_, err := worker.Stage(ctx, target.UpdateID, artifact, target.Staged.PackageInfo, target.Staged.CompiledAt, at)
		if err != nil {
			return FleetRollbackRecord{}, err
		}
		ack, err := worker.Activate(ctx, ActivationCommand{UpdateID: target.UpdateID, FleetEpoch: epoch, Phase: PhaseRollback, PackageData: artifact, PackageInfo: target.Staged.PackageInfo, CompiledAt: target.Staged.CompiledAt, ActivatedAt: at})
		if err != nil {
			return FleetRollbackRecord{}, err
		}
		if ack.Status != AckPass {
			return FleetRollbackRecord{}, ErrActivationFailed
		}
		acks = append(acks, ack)
		m.appendEvent("worker_rollback", target.UpdateID, at, ack)
	}
	sort.Slice(acks, func(i, j int) bool { return acks[i].Worker.WorkerID < acks[j].Worker.WorkerID })
	rollback := FleetRollbackRecord{SchemaVersion: FleetRollbackSchemaVersion, FromActivationID: from.ActivationID, ToPackageID: target.Staged.PackageInfo.PackageID, Reason: reason, FleetEpoch: epoch, ActivationAcks: acks, RequestedAt: at.UTC(), CompletedAt: at.UTC()}
	rollback.RollbackID = stableID("fleet_rollback", rollback)
	store := Store{Root: m.StateDir}
	if err := store.PersistRollback(rollback); err != nil {
		return FleetRollbackRecord{}, err
	}
	manifest := target.Staged.PackageInfo.Manifest
	pointer := FleetPointer{SchemaVersion: FleetPointerSchemaVersion, ActivationID: rollback.RollbackID, UpdateID: target.UpdateID, FleetEpoch: epoch, PackageID: target.Staged.PackageInfo.PackageID, PackageChecksum: target.Staged.PackageInfo.PackageChecksum, CatalogID: manifest.Provider.Catalog.CatalogID, CatalogVersion: manifest.Provider.Catalog.CatalogVersion, CatalogChecksum: manifest.Provider.Catalog.CatalogChecksum, SourceManifestID: manifest.SourceManifestID, ActivatedAt: at.UTC()}
	if err := store.SetActive(pointer); err != nil {
		return FleetRollbackRecord{}, err
	}
	m.appendEvent("fleet_rollback", target.UpdateID, at, rollback)
	return rollback, nil
}

func (m *Manager) workerMap() map[string]Worker {
	out := map[string]Worker{}
	for _, w := range m.Workers {
		out[w.Descriptor().WorkerID] = w
	}
	return out
}
func (m *Manager) appendEvent(eventType, subject string, at time.Time, payload any) {
	history, event, err := appendAudit(m.Audit, eventType, subject, at, payload)
	if err == nil {
		m.Audit = history
		_ = (Store{Root: m.StateDir}).PersistAudit(event)
	}
}
func (m *Manager) failRecord(record UpdateRecord, at time.Time, err error) (UpdateRecord, []byte, error) {
	record.Status = StatusFailed
	record.Failure = err.Error()
	record.UpdatedAt = at.UTC()
	m.appendEvent("update_failed", record.UpdateID, at, record)
	return record, nil, err
}
