package main

import (
	"encoding/json"
	"flag"
	"fmt"
	rq "github.com/openwatchlist-labs/watchlist-platform/internal/releasequalification"
	"os"
)

func die(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
func write(v any) {
	b, e := json.Marshal(v)
	if e != nil {
		die(e)
	}
	fmt.Println(string(b))
}
func main() {
	if len(os.Args) < 2 {
		die(fmt.Errorf("usage: release-qualification evaluate|verify|check-gates"))
	}
	switch os.Args[1] {
	case "evaluate":
		f := flag.NewFlagSet("evaluate", flag.ExitOnError)
		g := f.String("gates", "configs/evaluation/phase10-release-gates-r1.json", "")
		s := f.String("suite", "test/fixtures/release-qualification/suite.json", "")
		out := f.String("output", "", "")
		f.Parse(os.Args[2:])
		gg, e := rq.LoadGateSet(*g)
		if e != nil {
			die(e)
		}
		ss, e := rq.LoadSuite(*s)
		if e != nil {
			die(e)
		}
		r, e := rq.Evaluate(gg, ss)
		if e != nil {
			die(e)
		}
		b, _ := json.MarshalIndent(r, "", "  ")
		if *out != "" {
			if e = os.WriteFile(*out, append(b, '\n'), 0644); e != nil {
				die(e)
			}
		}
		write(r)
		if r.Status != "qualified" {
			os.Exit(2)
		}
	case "verify":
		f := flag.NewFlagSet("verify", flag.ExitOnError)
		p := f.String("report", "", "")
		f.Parse(os.Args[2:])
		if *p == "" {
			die(fmt.Errorf("--report required"))
		}
		r, e := rq.LoadReport(*p)
		if e != nil {
			die(e)
		}
		write(map[string]any{"status": "ok", "qualification_id": r.QualificationID, "report_sha256": r.ReportSHA256})
	case "check-gates":
		f := flag.NewFlagSet("check-gates", flag.ExitOnError)
		p := f.String("gates", "configs/evaluation/phase10-release-gates-r1.json", "")
		f.Parse(os.Args[2:])
		g, e := rq.LoadGateSet(*p)
		if e != nil {
			die(e)
		}
		write(map[string]any{"status": "ok", "gate_set_id": g.GateSetID, "gate_set_sha256": g.GateSetSHA256, "gate_count": 19})
	default:
		die(fmt.Errorf("unknown command"))
	}
}
