package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
)

func main() {
	policyPath := flag.String("policy", "configs/policies/transaction-screening-r1.yaml", "base transaction-screening policy YAML")
	overlayPath := flag.String("overlay", "", "optional tenant policy overlay YAML")
	flag.Parse()
	if flag.NArg() != 1 {
		fatalf("usage: policy-evaluate [flags] <classification-batch.json>")
	}
	policy, err := policyengine.LoadPolicy(*policyPath)
	check(err, "load policy")
	var overlay *policyengine.Overlay
	if *overlayPath != "" {
		value, err := policyengine.LoadOverlay(*overlayPath, policy)
		check(err, "load overlay")
		overlay = &value
	}
	engine, err := policyengine.NewEngine(policy, overlay)
	check(err, "create policy engine")
	data, err := os.ReadFile(flag.Arg(0))
	check(err, "read input")
	var input falsepositive.ClassificationBatch
	check(decodeStrict(data, &input), "decode classification batch")
	output, err := engine.EvaluateBatch(input)
	check(err, "evaluate policy")
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(output), "encode output")
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}
func check(err error, action string) {
	if err != nil {
		fatalf("%s: %v", action, err)
	}
}
func fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
