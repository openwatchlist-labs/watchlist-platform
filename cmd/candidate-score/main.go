package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "candidate-score:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: candidate-score <score|batch|check-policy> --policy FILE [--input FILE]")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	policyPath := flags.String("policy", "", "candidate scoring policy JSON")
	inputPath := flags.String("input", "-", "request JSON or - for stdin")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *policyPath == "" {
		return errors.New("--policy is required")
	}
	loaded, err := candidatescoring.LoadPolicy(*policyPath)
	if err != nil {
		return err
	}
	if command == "check-policy" {
		return writeJSON(stdout, candidatescoring.PolicyReference{
			PolicyID:             loaded.Policy.PolicyID,
			PolicyVersion:        loaded.Policy.PolicyVersion,
			PolicySHA256:         loaded.SHA256,
			NormalizationProfile: loaded.Policy.NormalizationProfile,
		})
	}
	engine, err := candidatescoring.NewEngine(loaded)
	if err != nil {
		return err
	}
	raw, err := readInput(*inputPath)
	if err != nil {
		return err
	}
	switch command {
	case "score":
		request, err := candidatescoring.DecodeRequest(raw)
		if err != nil {
			return err
		}
		response, err := engine.Score(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, response)
	case "batch":
		request, err := candidatescoring.DecodeBatchRequest(raw)
		if err != nil {
			return err
		}
		response, err := engine.ScoreBatch(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, response)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	return raw, nil
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
