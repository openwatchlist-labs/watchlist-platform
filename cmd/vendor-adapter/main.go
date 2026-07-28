package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/vendoradapter"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "profiles":
		err = profiles(os.Args[2:])
	case "check-profile":
		err = check(os.Args[2:])
	case "convert":
		err = convert(os.Args[2:], false)
	case "ingest":
		err = convert(os.Args[2:], true)
	case "batch":
		err = batch(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "submit":
		err = submit(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "vendor-adapter profiles|check-profile|convert|ingest|batch|verify|submit")
}
func output(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
func profiles(args []string) error {
	fs := flag.NewFlagSet("profiles", flag.ContinueOnError)
	dir := fs.String("profiles-dir", "configs/vendor-adapters", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ps, err := vendoradapter.LoadProfiles(*dir)
	if err != nil {
		return err
	}
	return output(map[string]any{"schema_version": "openwatchlist.vendor-adapter-registry.v1", "profiles": vendoradapter.ProfileSummary(ps)})
}
func check(args []string) error {
	fs := flag.NewFlagSet("check-profile", flag.ContinueOnError)
	path := fs.String("profile", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := vendoradapter.LoadProfile(*path)
	if err != nil {
		return err
	}
	return output(map[string]any{"status": "ok", "adapter_id": p.AdapterID, "version": p.Version, "profile_sha256": p.ProfileSHA256})
}
func common(args []string, name string) (*flag.FlagSet, *string, *string, *string, *string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	profile := fs.String("profile", "", "")
	source := fs.String("source-ref", "stdin", "")
	state := fs.String("state-dir", "", "")
	at := fs.String("at", "2026-07-15T15:00:00Z", "")
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return fs, profile, source, state, at, nil
}
func convert(args []string, ingest bool) error {
	fs, pp, source, state, at, err := common(args, map[bool]string{true: "ingest", false: "convert"}[ingest])
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("input JSON file is required")
	}
	p, err := vendoradapter.LoadProfile(*pp)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	tm, err := time.Parse(time.RFC3339, *at)
	if err != nil {
		return err
	}
	if !ingest {
		e, err := vendoradapter.Convert(p, *source, raw, tm)
		if err != nil {
			return err
		}
		return output(e)
	}
	if *state == "" {
		return fmt.Errorf("--state-dir is required")
	}
	s, err := vendoradapter.NewStore(*state, "phase9e", func() time.Time { return tm })
	if err != nil {
		return err
	}
	e, replay, err := s.Process(p, *source, raw)
	if err != nil {
		return err
	}
	return output(map[string]any{"envelope": e, "replayed": replay})
}
func batch(args []string) error {
	fs := flag.NewFlagSet("batch", flag.ContinueOnError)
	pp := fs.String("profile", "", "")
	prefix := fs.String("source-prefix", "file:", "")
	at := fs.String("at", "2026-07-15T15:00:00Z", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := vendoradapter.LoadProfile(*pp)
	if err != nil {
		return err
	}
	tm, err := time.Parse(time.RFC3339, *at)
	if err != nil {
		return err
	}
	var ins []vendoradapter.BatchInput
	for _, f := range fs.Args() {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		ins = append(ins, vendoradapter.BatchInput{SourceRef: *prefix + filepath.Base(f), Bytes: b})
	}
	b, err := vendoradapter.ConvertBatch(p, ins, tm)
	if err != nil {
		return err
	}
	return output(b)
}
func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	state := fs.String("state-dir", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := vendoradapter.NewStore(*state, "phase9e", nil)
	if err != nil {
		return err
	}
	st, err := s.Verify()
	if err != nil {
		return err
	}
	return output(st)
}
func submit(args []string) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	pp := fs.String("profile", "", "")
	source := fs.String("source-ref", "stdin", "")
	base := fs.String("alert-case-url", "", "")
	at := fs.String("at", "2026-07-15T15:00:00Z", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *base == "" {
		return fmt.Errorf("input file and --alert-case-url are required")
	}
	p, err := vendoradapter.LoadProfile(*pp)
	if err != nil {
		return err
	}
	raw, _ := os.ReadFile(fs.Arg(0))
	tm, _ := time.Parse(time.RFC3339, *at)
	e, err := vendoradapter.Convert(p, *source, raw, tm)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(e.CreateAlertRequest)
	req, _ := http.NewRequest(http.MethodPost, *base+"/v1/alerts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", e.CreateAlertRequest.IdempotencyKey)
	req.Header.Set("X-Correlation-ID", e.CreateAlertRequest.CorrelationID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("alert-case API returned %s: %s", resp.Status, string(out))
	}
	os.Stdout.Write(out)
	return nil
}
