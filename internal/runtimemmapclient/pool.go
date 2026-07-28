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
	select {
	case worker, ok := <-pool.workers:
		if !ok {
			return nil, fmt.Errorf("runtime worker pool is closed")
		}
		defer func() {
			select {
			case pool.workers <- worker:
			default:
			}
		}()
		return worker.Lookup(ctx, query)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (pool *Pool) Close() error {
	var first error
	pool.once.Do(func() {
		close(pool.workers)
		for _, worker := range pool.all {
			if err := worker.Close(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}
