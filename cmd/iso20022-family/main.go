package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openwatchlist-labs/watchlist-platform/internal/iso20022coverage"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "matrix":
		err = runMatrix(os.Args[2:])
	case "inspect":
		err = runInspect(os.Args[2:], false)
	case "project":
		err = runInspect(os.Args[2:], true)
	case "batch":
		err = runBatch(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "iso20022-family:", err)
		os.Exit(1)
	}
}

func common(name string, args []string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	matrix := fs.String("matrix", "configs/iso20022/family-matrix-r1.json", "support matrix JSON")
	return fs, matrix
}

func runMatrix(args []string) error {
	fs, matrixPath := common("matrix", args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := iso20022coverage.LoadMatrix(*matrixPath)
	if err != nil {
		return err
	}
	return writeJSON(m)
}

func runInspect(args []string, projection bool) error {
	fs, matrixPath := common("inspect", args)
	sourceRef := fs.String("source-ref", "", "immutable source reference")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("exactly one XML file is required")
	}
	path := fs.Arg(0)
	if *sourceRef == "" {
		*sourceRef = "file:" + filepath.Base(path)
	}
	m, err := iso20022coverage.LoadMatrix(*matrixPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	env, err := iso20022coverage.Parse(m, *sourceRef, data)
	if err != nil {
		return err
	}
	if projection {
		return writeJSON(iso20022coverage.Project(env))
	}
	return writeJSON(env)
}

func runBatch(args []string) error {
	fs, matrixPath := common("batch", args)
	sourcePrefix := fs.String("source-prefix", "file:", "source reference prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("at least one XML file is required")
	}
	m, err := iso20022coverage.LoadMatrix(*matrixPath)
	if err != nil {
		return err
	}
	docs := make([]iso20022coverage.EvidenceEnvelope, 0, fs.NArg())
	for _, path := range fs.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		env, err := iso20022coverage.Parse(m, *sourcePrefix+filepath.Base(path), data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		docs = append(docs, *env)
	}
	return writeJSON(iso20022coverage.BuildBatch(docs))
}

func runVerify(args []string) error {
	fs, matrixPath := common("verify", args)
	input := fs.String("input", "", "evidence JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	m, err := iso20022coverage.LoadMatrix(*matrixPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var env iso20022coverage.EvidenceEnvelope
	if err := dec.Decode(&env); err != nil {
		return err
	}
	if err := iso20022coverage.VerifyEnvelope(m, &env); err != nil {
		return err
	}
	return writeJSON(map[string]any{"status": "ok", "profile_id": env.ProfileID, "envelope_sha256": env.EnvelopeSHA256})
}

func writeJSON(v any) error {
	b, err := iso20022coverage.MarshalCanonical(v)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(b)
	return err
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: iso20022-family <matrix|inspect|project|batch|verify> [flags]")
	os.Exit(2)
}
