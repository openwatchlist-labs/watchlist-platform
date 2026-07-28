package releasebenchmark

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const SchemaV1 = "openwatchlist.target-benchmark.v1"

type Config struct {
	URL              string
	Path             string
	Token            string
	Requests         int
	WarmupRequests   int
	Concurrency      int
	Timeout          time.Duration
	InsecureTLS      bool
	MaxP95MS         float64
	MinThroughputRPS float64
}

type Report struct {
	SchemaVersion       string         `json:"schema_version"`
	Target              string         `json:"target"`
	Path                string         `json:"path"`
	Workload            string         `json:"workload"`
	Requests            int            `json:"requests"`
	WarmupRequests      int            `json:"warmup_requests"`
	Concurrency         int            `json:"concurrency"`
	Succeeded           int            `json:"succeeded"`
	Failed              int            `json:"failed"`
	StatusCounts        map[string]int `json:"status_counts"`
	BytesRead           int64          `json:"bytes_read"`
	DurationMS          float64        `json:"duration_ms"`
	ThroughputRPS       float64        `json:"throughput_rps"`
	P50LatencyMS        float64        `json:"p50_latency_ms"`
	P95LatencyMS        float64        `json:"p95_latency_ms"`
	P99LatencyMS        float64        `json:"p99_latency_ms"`
	Qualified           bool           `json:"qualified"`
	QualificationErrors []string       `json:"qualification_errors,omitempty"`
	ReportSHA256        string         `json:"report_sha256"`
}

type result struct {
	duration time.Duration
	status   int
	bytes    int64
	err      error
}

func Run(ctx context.Context, c Config) (Report, error) {
	if c.URL == "" || c.Path == "" {
		return Report{}, errors.New("url and path are required")
	}
	if c.Requests <= 0 || c.Concurrency <= 0 || c.Concurrency > c.Requests {
		return Report{}, errors.New("requests and concurrency must be positive and concurrency must not exceed requests")
	}
	if c.WarmupRequests < 0 {
		return Report{}, errors.New("warmup requests must not be negative")
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}

	tr := benchmarkTransport(c)
	client := &http.Client{Transport: tr, Timeout: c.Timeout}
	defer tr.CloseIdleConnections()

	if c.WarmupRequests > 0 {
		warmup, _ := execute(ctx, client, c, c.WarmupRequests)
		failed := 0
		for _, x := range warmup {
			if x.err != nil || x.status < 200 || x.status >= 300 {
				failed++
			}
		}
		if failed > 0 {
			return Report{}, fmt.Errorf("benchmark warmup failed: %d of %d requests were unsuccessful", failed, c.WarmupRequests)
		}
	}

	measured, elapsed := execute(ctx, client, c, c.Requests)
	r := Report{
		SchemaVersion:  SchemaV1,
		Target:         c.URL,
		Path:           c.Path,
		Workload:       "authenticated_read",
		Requests:       c.Requests,
		WarmupRequests: c.WarmupRequests,
		Concurrency:    c.Concurrency,
		StatusCounts:   map[string]int{},
	}
	lat := make([]float64, 0, c.Requests)
	var bytesRead atomic.Int64
	for _, x := range measured {
		lat = append(lat, float64(x.duration.Microseconds())/1000)
		bytesRead.Add(x.bytes)
		if x.err != nil {
			r.Failed++
			continue
		}
		r.StatusCounts[strconv.Itoa(x.status)]++
		if x.status >= 200 && x.status < 300 {
			r.Succeeded++
		} else {
			r.Failed++
		}
	}
	r.BytesRead = bytesRead.Load()
	r.DurationMS = float64(elapsed.Microseconds()) / 1000
	r.ThroughputRPS = float64(c.Requests) / elapsed.Seconds()
	sort.Float64s(lat)
	r.P50LatencyMS = quantile(lat, .50)
	r.P95LatencyMS = quantile(lat, .95)
	r.P99LatencyMS = quantile(lat, .99)
	if r.Failed > 0 {
		r.QualificationErrors = append(r.QualificationErrors, fmt.Sprintf("%d requests failed", r.Failed))
	}
	if c.MaxP95MS > 0 && r.P95LatencyMS > c.MaxP95MS {
		r.QualificationErrors = append(r.QualificationErrors, fmt.Sprintf("p95 %.3fms exceeds %.3fms", r.P95LatencyMS, c.MaxP95MS))
	}
	if c.MinThroughputRPS > 0 && r.ThroughputRPS < c.MinThroughputRPS {
		r.QualificationErrors = append(r.QualificationErrors, fmt.Sprintf("throughput %.3frps below %.3frps", r.ThroughputRPS, c.MinThroughputRPS))
	}
	r.Qualified = len(r.QualificationErrors) == 0
	h, err := hashReport(r)
	if err != nil {
		return Report{}, err
	}
	r.ReportSHA256 = h
	return r, nil
}

func benchmarkTransport(c Config) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureTLS} // #nosec G402: explicit local qualification option
	tr.MaxIdleConns = max(100, c.Concurrency*2)
	tr.MaxIdleConnsPerHost = c.Concurrency
	tr.MaxConnsPerHost = c.Concurrency
	tr.IdleConnTimeout = 90 * time.Second
	return tr
}

func execute(ctx context.Context, client *http.Client, c Config, requests int) ([]result, time.Duration) {
	jobs := make(chan struct{})
	results := make(chan result, requests)
	workers := min(c.Concurrency, requests)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				results <- executeOne(ctx, client, c)
			}
		}()
	}
	start := time.Now()
	go func() {
		for i := 0; i < requests; i++ {
			jobs <- struct{}{}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	out := make([]result, 0, requests)
	for x := range results {
		out = append(out, x)
	}
	return out, time.Since(start)
}

func executeOne(ctx context.Context, client *http.Client, c Config) result {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+c.Path, nil)
	if err != nil {
		return result{err: err}
	}
	req.Header.Set("Accept", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return result{duration: time.Since(start), err: err}
	}
	n, readErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	duration := time.Since(start)
	if readErr != nil {
		err = readErr
	} else if closeErr != nil {
		err = closeErr
	}
	return result{duration: duration, status: resp.StatusCode, bytes: n, err: err}
}

func quantile(v []float64, q float64) float64 {
	if len(v) == 0 {
		return 0
	}
	i := int(float64(len(v)-1)*q + .5)
	if i < 0 {
		i = 0
	}
	if i >= len(v) {
		i = len(v) - 1
	}
	return v[i]
}

func hashReport(r Report) (string, error) {
	r.ReportSHA256 = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func Verify(r Report) error {
	expected := r.ReportSHA256
	actual, err := hashReport(r)
	if err != nil {
		return err
	}
	if expected == "" || expected != actual {
		return fmt.Errorf("report checksum mismatch: expected %s calculated %s", expected, actual)
	}
	return nil
}
