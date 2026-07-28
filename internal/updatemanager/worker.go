package updatemanager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
)

type Worker interface {
	Descriptor() WorkerDescriptor
	Stage(context.Context, string, []byte, ofacruntime.PackageInfo, time.Time, time.Time) (WorkerReadinessAck, error)
	Activate(context.Context, ActivationCommand) (WorkerActivationAck, error)
}

type MemoryWorker struct {
	DescriptorValue WorkerDescriptor
	FailStage       bool
	FailCanary      bool
	FailBroad       bool
	FailRollback    bool
	mu              sync.Mutex
	packages        map[string][]byte
	active          *catalogruntime.GenerationStamp
}

func NewMemoryWorker(id, zone string, required bool) *MemoryWorker {
	return &MemoryWorker{DescriptorValue: WorkerDescriptor{SchemaVersion: WorkerDescriptorSchemaVersion, WorkerID: id, Zone: zone, Required: required}, packages: map[string][]byte{}}
}
func (w *MemoryWorker) Descriptor() WorkerDescriptor { return w.DescriptorValue }
func (w *MemoryWorker) Stage(_ context.Context, updateID string, data []byte, info ofacruntime.PackageInfo, compiledAt, checkedAt time.Time) (WorkerReadinessAck, error) {
	if err := ValidateWorkerDescriptor(w.DescriptorValue); err != nil {
		return WorkerReadinessAck{}, err
	}
	loaded, err := ofacruntime.Load(data)
	if err != nil {
		return WorkerReadinessAck{}, err
	}
	if loaded.Info.PackageID != info.PackageID || loaded.Info.PackageChecksum != info.PackageChecksum {
		return WorkerReadinessAck{}, fmt.Errorf("package info mismatch")
	}
	report, err := ofacruntime.Readiness(loaded, compiledAt, checkedAt)
	if err != nil {
		return WorkerReadinessAck{}, err
	}
	checks := append([]catalogruntime.ReadinessCheck(nil), report.Checks...)
	ready := report.Ready && !w.FailStage
	if w.FailStage {
		checks = append(checks, catalogruntime.ReadinessCheck{Name: "worker_local_policy", Status: catalogruntime.CheckFail, Detail: "worker rejected package for test"})
	}
	ack := WorkerReadinessAck{SchemaVersion: WorkerReadinessSchemaVersion, UpdateID: updateID, Worker: w.DescriptorValue, PackageID: info.PackageID, PackageChecksum: info.PackageChecksum, CheckedAt: checkedAt.UTC(), Ready: ready, Checks: checks}
	ack.AckID = stableID("worker_readiness", ack)
	if ready {
		w.mu.Lock()
		w.packages[info.PackageID] = append([]byte(nil), data...)
		w.mu.Unlock()
	}
	return ack, ValidateReadinessAck(ack)
}
func (w *MemoryWorker) Activate(_ context.Context, command ActivationCommand) (WorkerActivationAck, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	data, ok := w.packages[command.PackageInfo.PackageID]
	if !ok {
		return WorkerActivationAck{}, fmt.Errorf("package not staged")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != command.PackageInfo.PackageChecksum {
		return WorkerActivationAck{}, fmt.Errorf("staged package checksum mismatch")
	}
	fail := (command.Phase == PhaseCanary && w.FailCanary) || (command.Phase == PhaseBroad && w.FailBroad) || (command.Phase == PhaseRollback && w.FailRollback)
	status, probe, detail := AckPass, true, "package activated and local smoke probe passed"
	if fail {
		status, probe, detail = AckFail, false, "worker activation rejected for test"
	}
	manifest := command.PackageInfo.Manifest
	generationSeed := struct {
		WorkerID, PackageID string
		Epoch               uint64
	}{w.DescriptorValue.WorkerID, command.PackageInfo.PackageID, command.FleetEpoch}
	stamp := catalogruntime.GenerationStamp{SchemaVersion: catalogruntime.GenerationStampSchemaVersion, GenerationID: stableID("generation", generationSeed), ActivationEpoch: command.FleetEpoch, PackageID: command.PackageInfo.PackageID, PackageChecksum: command.PackageInfo.PackageChecksum, CatalogID: manifest.Provider.Catalog.CatalogID, CatalogVersion: manifest.Provider.Catalog.CatalogVersion, CatalogChecksum: manifest.Provider.Catalog.CatalogChecksum, SourceManifestID: manifest.SourceManifestID, CompiledAt: command.CompiledAt.UTC(), ActivatedAt: command.ActivatedAt.UTC()}
	ack := WorkerActivationAck{SchemaVersion: WorkerActivationSchemaVersion, UpdateID: command.UpdateID, Worker: w.DescriptorValue, FleetEpoch: command.FleetEpoch, Phase: command.Phase, Status: status, ProbePassed: probe, Detail: detail, Generation: stamp, ActivatedAt: command.ActivatedAt.UTC()}
	ack.AckID = stableID("worker_activation", ack)
	if status == AckPass {
		copyStamp := stamp
		w.active = &copyStamp
	}
	return ack, ValidateActivationAck(ack)
}
func (w *MemoryWorker) Active() *catalogruntime.GenerationStamp {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.active == nil {
		return nil
	}
	c := *w.active
	return &c
}
