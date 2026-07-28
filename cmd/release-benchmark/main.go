package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/openwatchlist-labs/watchlist-platform/internal/releasebenchmark"
	"os"
	"strings"
	"time"
)

func main() {
	url := flag.String("url", "https://localhost:8443", "base URL")
	path := flag.String("path", "/v1/alerts", "request path")
	tokenFile := flag.String("token-file", "", "bearer token file")
	requests := flag.Int("requests", 1000, "measured request count")
	warmupRequests := flag.Int("warmup-requests", 64, "unmeasured warmup request count")
	concurrency := flag.Int("concurrency", 16, "concurrency")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	insecure := flag.Bool("insecure", false, "allow self-signed TLS for local qualification")
	maxP95 := flag.Float64("max-p95-ms", 250, "release-blocking maximum p95 latency")
	minRPS := flag.Float64("min-throughput-rps", 100, "release-blocking minimum throughput")
	output := flag.String("output", "", "output JSON")
	flag.Parse()
	token := ""
	if *tokenFile != "" {
		b, e := os.ReadFile(*tokenFile)
		check(e)
		token = strings.TrimSpace(string(b))
	}
	r, e := releasebenchmark.Run(context.Background(), releasebenchmark.Config{
		URL:              *url,
		Path:             *path,
		Token:            token,
		Requests:         *requests,
		WarmupRequests:   *warmupRequests,
		Concurrency:      *concurrency,
		Timeout:          *timeout,
		InsecureTLS:      *insecure,
		MaxP95MS:         *maxP95,
		MinThroughputRPS: *minRPS,
	})
	check(e)
	b, e := json.MarshalIndent(r, "", "  ")
	check(e)
	b = append(b, '\n')
	if *output == "" {
		_, e = os.Stdout.Write(b)
	} else {
		e = os.WriteFile(*output, b, 0644)
	}
	check(e)
	if !r.Qualified {
		os.Exit(1)
	}
}

func check(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
