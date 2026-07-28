package productionops

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
}

func NewRateLimiter() *RateLimiter { return &RateLimiter{buckets: map[string]bucket{}} }
func (l *RateLimiter) Allow(key string, now time.Time, perMinute, burst int) bool {
	if perMinute <= 0 || burst <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b.last.IsZero() {
		b.tokens = float64(burst)
		b.last = now
	}
	if now.After(b.last) {
		b.tokens += (now.Sub(b.last).Minutes() * float64(perMinute))
		if b.tokens > float64(burst) {
			b.tokens = float64(burst)
		}
		b.last = now
	}
	if b.tokens < 1 {
		l.buckets[key] = b
		return false
	}
	b.tokens--
	l.buckets[key] = b
	return true
}

type ConcurrencyLimiter struct {
	global       chan struct{}
	mu           sync.Mutex
	tenant       map[string]chan struct{}
	defaultLimit int
}

func NewConcurrencyLimiter(global, tenant int) *ConcurrencyLimiter {
	if global < 1 {
		global = 1
	}
	if tenant < 1 {
		tenant = 1
	}
	return &ConcurrencyLimiter{global: make(chan struct{}, global), tenant: map[string]chan struct{}{}, defaultLimit: tenant}
}
func (l *ConcurrencyLimiter) tenantCh(id string, limit int) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit < 1 {
		limit = l.defaultLimit
	}
	ch := l.tenant[id]
	if ch == nil || cap(ch) != limit {
		ch = make(chan struct{}, limit)
		l.tenant[id] = ch
	}
	return ch
}
func (l *ConcurrencyLimiter) Acquire(id string, limit int) bool {
	select {
	case l.global <- struct{}{}:
	default:
		return false
	}
	ch := l.tenantCh(id, limit)
	select {
	case ch <- struct{}{}:
		return true
	default:
		<-l.global
		return false
	}
}
func (l *ConcurrencyLimiter) Release(id string, limit int) {
	ch := l.tenantCh(id, limit)
	select {
	case <-ch:
	default:
	}
	select {
	case <-l.global:
	default:
	}
}
