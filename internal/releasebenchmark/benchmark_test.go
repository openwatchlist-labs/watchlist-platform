package releasebenchmark

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunAndVerify(t *testing.T) {
	var calls atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer x" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer s.Close()
	r, e := Run(context.Background(), Config{
		URL:              s.URL,
		Path:             "/v1/alerts",
		Token:            "x",
		Requests:         20,
		WarmupRequests:   8,
		Concurrency:      4,
		Timeout:          time.Second,
		MaxP95MS:         1000,
		MinThroughputRPS: 1,
	})
	if e != nil {
		t.Fatal(e)
	}
	if !r.Qualified || r.Succeeded != 20 || r.WarmupRequests != 8 {
		t.Fatalf("bad report: %+v", r)
	}
	if got := calls.Load(); got != 28 {
		t.Fatalf("warmup was not executed or leaked into measured count: calls=%d", got)
	}
	if e = Verify(r); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(r)
	var x Report
	_ = json.Unmarshal(b, &x)
	x.Requests++
	if Verify(x) == nil {
		t.Fatal("tamper accepted")
	}
}

func TestBenchmarkTransportMatchesConcurrency(t *testing.T) {
	tr := benchmarkTransport(Config{Concurrency: 16, InsecureTLS: true})
	defer tr.CloseIdleConnections()
	if tr.MaxIdleConnsPerHost != 16 {
		t.Fatalf("MaxIdleConnsPerHost=%d", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxConnsPerHost != 16 {
		t.Fatalf("MaxConnsPerHost=%d", tr.MaxConnsPerHost)
	}
	if tr.MaxIdleConns < 32 {
		t.Fatalf("MaxIdleConns=%d", tr.MaxIdleConns)
	}
}

func TestWarmupFailureBlocksMeasurement(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer s.Close()
	_, err := Run(context.Background(), Config{
		URL:            s.URL,
		Path:           "/v1/alerts",
		Requests:       4,
		WarmupRequests: 2,
		Concurrency:    2,
		Timeout:        time.Second,
	})
	if err == nil {
		t.Fatal("failed warmup was accepted")
	}
}
