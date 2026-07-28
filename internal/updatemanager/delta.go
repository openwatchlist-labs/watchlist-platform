package updatemanager

import (
	"fmt"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogrefresh"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
)

// PrepareDelta reconstructs a complete candidate catalog off-path and only
// compiles it when the immutable promotion decision permits delta promotion.
// It never mutates an active catalog or worker runtime in place.
func (m *Manager) PrepareDelta(spec UpdateSpec, base ofaccatalog.Catalog, delta catalogrefresh.Delta, policy catalogrefresh.PromotionPolicy, expectedSequence uint64, fullTarget *ofaccatalog.Catalog, now, compiledAt time.Time) (UpdateRecord, []byte, catalogrefresh.PromotionDecision, error) {
	if err := ValidateSpec(spec); err != nil {
		return UpdateRecord{}, nil, catalogrefresh.PromotionDecision{}, err
	}
	if now.Before(spec.ScheduledFor) {
		return UpdateRecord{}, nil, catalogrefresh.PromotionDecision{}, fmt.Errorf("%w: scheduled_for=%s now=%s", ErrNotDue, spec.ScheduledFor, now)
	}
	record := UpdateRecord{SchemaVersion: UpdateRecordSchemaVersion, UpdateID: spec.UpdateID, ManagerVersion: ManagerVersion, Status: StatusScheduled, Spec: spec, UpdatedAt: now.UTC()}
	m.appendEvent("delta_update_due", spec.UpdateID, now, spec)
	deltaPath, err := catalogrefresh.PersistDelta(m.StateDir, delta)
	if err != nil {
		failed, _, failErr := m.failRecord(record, now, err)
		return failed, nil, catalogrefresh.PromotionDecision{}, failErr
	}
	m.appendEvent("delta_staged", spec.UpdateID, now, delta)
	decision, target, err := catalogrefresh.Evaluate(base, delta, policy, expectedSequence, now, fullTarget)
	if err != nil {
		failed, _, failErr := m.failRecord(record, now, err)
		return failed, nil, decision, failErr
	}
	if _, err = catalogrefresh.PersistDecision(m.StateDir, decision); err != nil {
		failed, _, failErr := m.failRecord(record, now, err)
		return failed, nil, decision, failErr
	}
	m.appendEvent("catalog_promotion_decision", spec.UpdateID, now, decision)
	switch decision.Outcome {
	case catalogrefresh.OutcomeReject:
		record.Status = StatusFailed
		record.Failure = "catalog delta rejected"
		record.UpdatedAt = now.UTC()
		if err = (Store{Root: m.StateDir}).PersistUpdate(record); err != nil {
			return record, nil, decision, err
		}
		return record, nil, decision, ErrDeltaRejected
	case catalogrefresh.OutcomeForceFull:
		record.Status = StatusFullRebuildRequired
		record.UpdatedAt = now.UTC()
		if err = (Store{Root: m.StateDir}).PersistUpdate(record); err != nil {
			return record, nil, decision, err
		}
		return record, nil, decision, ErrFullRebuildRequired
	case catalogrefresh.OutcomePromoteDelta:
	default:
		return UpdateRecord{}, nil, decision, fmt.Errorf("%w: unsupported promotion outcome %q", ErrInvalidUpdate, decision.Outcome)
	}
	artifact, info, err := ofacruntime.Compile(target)
	if err != nil {
		failed, _, failErr := m.failRecord(record, now, err)
		return failed, nil, decision, failErr
	}
	if compiledAt.IsZero() {
		compiledAt = now
	}
	packagePath, err := persistImmutablePackage(m.StateDir, info.PackageID, info.PackageChecksum, artifact)
	if err != nil {
		failed, _, failErr := m.failRecord(record, now, err)
		return failed, nil, decision, failErr
	}
	record.Status = StatusCompiled
	record.Staged = &StagedArtifacts{Promotion: &decision, DeltaPath: deltaPath, SourceManifest: target.SourceManifest, PackageInfo: info, PackagePath: packagePath, CompiledAt: compiledAt.UTC()}
	record.UpdatedAt = now.UTC()
	m.appendEvent("delta_package_compiled", spec.UpdateID, compiledAt, info)
	if err = (Store{Root: m.StateDir}).PersistUpdate(record); err != nil {
		failed, _, failErr := m.failRecord(record, now, err)
		return failed, nil, decision, failErr
	}
	return record, artifact, decision, nil
}
