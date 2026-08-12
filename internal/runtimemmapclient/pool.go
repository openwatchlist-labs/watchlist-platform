package runtimemmapclient

import (
	"context"
	"fmt"
	"sync"
)

type Pool struct {
	info    PackageInfo
	workers chan *Worker
	all     []*Worker
	once    sync.Once

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func StartPool(ctx context.Context, binaryPath, packagePath string, size int) (*Pool, error) {
	if size <= 0 || size > 64 {
		return nil, fmt.Errorf("worker pool size must be between 1 and 64")
	}
	pool := &Pool{workers: make(chan *Worker, size)}
	for index := 0; index < size; index++ {
		worker, err := Start(ctx, binaryPath, packagePath)
		if err != nil {
			_ = pool.Close()
			return nil, fmt.Errorf("start worker %d: %w", index, err)
		}
		if index == 0 {
			pool.info = worker.Info()
		} else if worker.Info() != pool.info {
			_ = worker.Close()
			_ = pool.Close()
			return nil, fmt.Errorf("runtime workers reported different package metadata")
		}
		pool.all = append(pool.all, worker)
		pool.workers <- worker
	}
	return pool, nil
}

func (pool *Pool) Info() PackageInfo { return pool.info }

func (pool *Pool) Lookup(ctx context.Context, query Query) ([]Candidate, error) {
	pool.mu.Lock()
	if pool.closed {
		pool.mu.Unlock()
		return nil, fmt.Errorf("runtime worker pool is closed")
	}
	pool.wg.Add(1)
	pool.mu.Unlock()
	defer pool.wg.Done()

	select {
	case worker, ok := <-pool.workers:
		if !ok {
			return nil, fmt.Errorf("runtime worker pool is closed")
		}
		// Safe to send unconditionally: Close() marks the pool closed and
		// waits for every in-flight Lookup (tracked by pool.wg) to finish
		// before it closes pool.workers, so this send can never race a
		// closed channel. The channel also can never be over capacity --
		// each worker is either checked out by exactly one in-flight
		// Lookup or sitting in the channel, never both.
		defer func() {
			pool.workers <- worker
		}()
		return worker.Lookup(ctx, query)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (pool *Pool) Close() error {
	var first error
	pool.once.Do(func() {
		pool.mu.Lock()
		pool.closed = true
		pool.mu.Unlock()
		pool.wg.Wait()
		close(pool.workers)
		for _, worker := range pool.all {
			if err := worker.Close(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}
