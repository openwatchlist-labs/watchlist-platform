package productionops

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	started       time.Time
	inFlight      atomic.Int64
	requests      atomic.Uint64
	denied        atomic.Uint64
	rateLimited   atomic.Uint64
	overloaded    atomic.Uint64
	panics        atomic.Uint64
	mu            sync.Mutex
	byStatus      map[int]uint64
	durationNanos uint64
}

func NewMetrics() *Metrics { return &Metrics{started: time.Now(), byStatus: map[int]uint64{}} }
func (m *Metrics) Begin()  { m.requests.Add(1); m.inFlight.Add(1) }
func (m *Metrics) End(status int, d time.Duration) {
	m.inFlight.Add(-1)
	m.mu.Lock()
	m.byStatus[status]++
	m.durationNanos += uint64(d)
	m.mu.Unlock()
	if status == 401 || status == 403 {
		m.denied.Add(1)
	}
}
func (m *Metrics) RateLimited()    { m.rateLimited.Add(1) }
func (m *Metrics) Overloaded()     { m.overloaded.Add(1) }
func (m *Metrics) Panic()          { m.panics.Add(1) }
func (m *Metrics) InFlight() int64 { return m.inFlight.Load() }
func (m *Metrics) Render(configHash, quotaHash string) string {
	m.mu.Lock()
	keys := make([]int, 0, len(m.byStatus))
	for k := range m.byStatus {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var statuses strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&statuses, "openwatchlist_http_responses_total{status=\"%d\"} %d\n", k, m.byStatus[k])
	}
	dur := m.durationNanos
	m.mu.Unlock()
	return fmt.Sprintf("# TYPE openwatchlist_uptime_seconds gauge\nopenwatchlist_uptime_seconds %.0f\n# TYPE openwatchlist_http_requests_total counter\nopenwatchlist_http_requests_total %d\n# TYPE openwatchlist_http_in_flight gauge\nopenwatchlist_http_in_flight %d\n# TYPE openwatchlist_http_request_duration_seconds_total counter\nopenwatchlist_http_request_duration_seconds_total %.6f\n# TYPE openwatchlist_auth_denied_total counter\nopenwatchlist_auth_denied_total %d\n# TYPE openwatchlist_rate_limited_total counter\nopenwatchlist_rate_limited_total %d\n# TYPE openwatchlist_overloaded_total counter\nopenwatchlist_overloaded_total %d\n# TYPE openwatchlist_panics_total counter\nopenwatchlist_panics_total %d\nopenwatchlist_runtime_info{config_sha256=\"%s\",quota_registry_sha256=\"%s\"} 1\n%s", time.Since(m.started).Seconds(), m.requests.Load(), m.inFlight.Load(), float64(dur)/float64(time.Second), m.denied.Load(), m.rateLimited.Load(), m.overloaded.Load(), m.panics.Load(), configHash, quotaHash, statuses.String())
}
