package catalogruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const GenerationSchemaVersion = "catalog-runtime-generation/v1alpha1"

var ErrNoActiveGeneration = errors.New("no active catalog generation")

type GenerationMetadata struct {
	SchemaVersion    string    `json:"schema_version"`
	GenerationID     string    `json:"generation_id"`
	PackageID        string    `json:"package_id,omitempty"`
	PackageChecksum  string    `json:"package_checksum,omitempty"`
	CatalogID        string    `json:"catalog_id"`
	CatalogVersion   string    `json:"catalog_version"`
	CatalogChecksum  string    `json:"catalog_checksum"`
	SourceManifestID string    `json:"source_manifest_id"`
	CompiledAt       time.Time `json:"compiled_at"`
	ActivatedAt      time.Time `json:"activated_at,omitempty"`
	ActivationEpoch  uint64    `json:"activation_epoch"`
}

type Generation struct {
	metadata GenerationMetadata
	payload  any
	readers  atomic.Int64
	retired  atomic.Bool
	drained  chan struct{}
	once     sync.Once
}

type Registry struct {
	active atomic.Pointer[Generation]
	epoch  atomic.Uint64
	mu     sync.Mutex
}

type Lease struct {
	generation *Generation
	released   atomic.Bool
}

func NewGeneration(m GenerationMetadata, payload any) (*Generation, error) {
	if m.SchemaVersion != GenerationSchemaVersion || m.GenerationID == "" || m.CatalogID == "" || m.CatalogVersion == "" || m.CatalogChecksum == "" || m.SourceManifestID == "" || m.CompiledAt.IsZero() || m.ActivationEpoch != 0 || payload == nil {
		return nil, fmt.Errorf("invalid catalog generation")
	}
	return &Generation{metadata: m, payload: payload, drained: make(chan struct{})}, nil
}

func (r *Registry) Activate(next *Generation) (GenerationMetadata, bool, error) {
	if next == nil {
		return GenerationMetadata{}, false, errors.New("next generation nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if next.retired.Load() {
		return GenerationMetadata{}, false, errors.New("retired generation cannot activate")
	}
	if next.metadata.ActivationEpoch != 0 {
		return GenerationMetadata{}, false, errors.New("generation already activated")
	}
	next.metadata.ActivationEpoch = r.epoch.Add(1)
	old := r.active.Swap(next)
	if old == nil {
		return GenerationMetadata{}, false, nil
	}
	old.retired.Store(true)
	old.signal()
	return old.metadata, true, nil
}

func (r *Registry) Acquire() (Lease, error) {
	for {
		g := r.active.Load()
		if g == nil {
			return Lease{}, ErrNoActiveGeneration
		}
		g.readers.Add(1)
		if r.active.Load() == g && !g.retired.Load() {
			return Lease{generation: g}, nil
		}
		if g.readers.Add(-1) == 0 {
			g.signal()
		}
	}
}

func (l *Lease) Metadata() GenerationMetadata {
	if l == nil || l.generation == nil {
		return GenerationMetadata{}
	}
	return l.generation.metadata
}

func (l *Lease) Stamp() (GenerationStamp, error) {
	if l == nil || l.generation == nil {
		return GenerationStamp{}, ErrNoActiveGeneration
	}
	return StampFromMetadata(l.generation.metadata)
}

func (l *Lease) Payload() any {
	if l == nil || l.generation == nil {
		return nil
	}
	return l.generation.payload
}

func (l *Lease) Release() {
	if l == nil || l.generation == nil || !l.released.CompareAndSwap(false, true) {
		return
	}
	if l.generation.readers.Add(-1) == 0 {
		l.generation.signal()
	}
}

func (g *Generation) WaitDrained(ctx context.Context) error {
	select {
	case <-g.drained:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait drain: %w", ctx.Err())
	}
}

func (g *Generation) signal() {
	if g.retired.Load() && g.readers.Load() == 0 {
		g.once.Do(func() { close(g.drained) })
	}
}
