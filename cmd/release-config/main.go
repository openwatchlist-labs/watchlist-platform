package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/productionops"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: release-config <seal-runtime|seal-quotas> --input FILE --output FILE")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	in := fs.String("input", "", "input JSON")
	out := fs.String("output", "", "output JSON; defaults to stdout")
	_ = fs.Parse(os.Args[2:])
	raw, err := os.ReadFile(*in)
	check(err)
	var value any
	switch os.Args[1] {
	case "seal-runtime":
		var c productionops.RuntimeConfig
		decode(raw, &c)
		c, err = productionops.SealRuntimeConfig(c)
		check(err)
		value = c
	case "seal-quotas":
		var q productionops.QuotaRegistry
		decode(raw, &q)
		q, err = productionops.SealQuotaRegistry(q)
		check(err)
		value = q
	default:
		fatal("unknown command %q", os.Args[1])
	}
	b, err := json.MarshalIndent(value, "", "  ")
	check(err)
	b = append(b, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(b)
	} else {
		err = os.WriteFile(*out, b, 0644)
	}
	check(err)
}
func decode(b []byte, v any) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	check(d.Decode(v))
}
func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}
func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
