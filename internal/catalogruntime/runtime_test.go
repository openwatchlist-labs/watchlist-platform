package catalogruntime

import (
	"context"
	"testing"
	"time"
)

func TestAtomicSwapPinsInflightDrainsAndSupportsAuditedRollback(t *testing.T) {
	var r Registry
	at := time.Date(2026, 7, 13, 16, 0, 0, 0, time.UTC)
	newGeneration := func(id, version, checksum, manifest string, compiled time.Time, payload string) *Generation {
		g, err := NewGeneration(GenerationMetadata{
			SchemaVersion:    GenerationSchemaVersion,
			GenerationID:     id,
			CatalogID:        "ofac-sdn-direct",
			CatalogVersion:   version,
			CatalogChecksum:  checksum,
			SourceManifestID: manifest,
			CompiledAt:       compiled,
		}, payload)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	a := newGeneration("A", "A", "aaa", "manifest-a", at, "a")
	b := newGeneration("B", "B", "bbb", "manifest-b", at.Add(time.Minute), "b")
	if _, _, err := r.Activate(a); err != nil {
		t.Fatal(err)
	}
	oldLease, err := r.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.Activate(b); err != nil {
		t.Fatal(err)
	}
	freshLease, err := r.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if oldLease.Metadata().CatalogVersion != "A" || oldLease.Metadata().ActivationEpoch != 1 {
		t.Fatalf("old lease not pinned to A/epoch 1: %+v", oldLease.Metadata())
	}
	if freshLease.Metadata().CatalogVersion != "B" || freshLease.Metadata().ActivationEpoch != 2 {
		t.Fatalf("fresh lease not pinned to B/epoch 2: %+v", freshLease.Metadata())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.WaitDrained(ctx) }()
	select {
	case <-done:
		t.Fatal("drained before release")
	case <-time.After(20 * time.Millisecond):
	}
	oldLease.Release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	freshLease.Release()

	// Rollback rehydrates the retained immutable A artifact as a new runtime
	// generation. It preserves catalog/source identity but receives a new
	// generation ID and activation epoch for auditability.
	rollback := newGeneration("A-rollback-1", "A", "aaa", "manifest-a", at.Add(2*time.Minute), "a")
	retired, hadOld, err := r.Activate(rollback)
	if err != nil || !hadOld || retired.CatalogVersion != "B" {
		t.Fatalf("rollback activation failed: retired=%+v hadOld=%v err=%v", retired, hadOld, err)
	}
	rollbackLease, err := r.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if got := rollbackLease.Metadata(); got.CatalogVersion != "A" || got.CatalogChecksum != "aaa" || got.SourceManifestID != "manifest-a" || got.ActivationEpoch != 3 {
		t.Fatalf("rollback audit lineage mismatch: %+v", got)
	}
	rollbackLease.Release()
}

func TestNewGenerationRejectsPreassignedEpoch(t *testing.T) {
	_, err := NewGeneration(GenerationMetadata{
		SchemaVersion:    GenerationSchemaVersion,
		GenerationID:     "spoofed",
		CatalogID:        "ofac-sdn-direct",
		CatalogVersion:   "v1",
		CatalogChecksum:  "checksum",
		SourceManifestID: "manifest",
		CompiledAt:       time.Now().UTC(),
		ActivationEpoch:  99,
	}, "payload")
	if err == nil {
		t.Fatal("preassigned activation epoch accepted")
	}
}
