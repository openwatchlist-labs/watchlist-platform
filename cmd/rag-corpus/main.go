package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: rag-corpus <compile|verify|query>")
	}
	switch os.Args[1] {
	case "compile":
		fs := flag.NewFlagSet("compile", flag.ExitOnError)
		manifestPath := fs.String("manifest", "", "manifest JSON")
		output := fs.String("output", "", "snapshot output")
		_ = fs.Parse(os.Args[2:])
		manifest, err := assistancerag.LoadManifest(*manifestPath)
		check(err)
		snapshot, err := assistancerag.CompileSnapshot(manifest)
		check(err)
		check(assistancerag.WriteSnapshot(*output, snapshot))
		write(map[string]any{"status": "ok", "snapshot_sha256": snapshot.SnapshotSHA256, "passage_count": snapshot.PassageCount, "output": *output})
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		snapshotPath := fs.String("snapshot", "", "snapshot JSON")
		_ = fs.Parse(os.Args[2:])
		snapshot, err := assistancerag.LoadSnapshot(*snapshotPath)
		check(err)
		write(map[string]any{"status": "ok", "corpus_id": snapshot.CorpusID, "version": snapshot.Version, "snapshot_sha256": snapshot.SnapshotSHA256, "passage_count": snapshot.PassageCount})
	case "query":
		fs := flag.NewFlagSet("query", flag.ExitOnError)
		snapshotPath := fs.String("snapshot", "", "snapshot JSON")
		input := fs.String("input", "", "query JSON")
		_ = fs.Parse(os.Args[2:])
		snapshot, err := assistancerag.LoadSnapshot(*snapshotPath)
		check(err)
		var q assistancerag.RetrievalQuery
		readJSON(*input, &q)
		result, err := assistancerag.Query(snapshot, q)
		check(err)
		write(result)
	default:
		fatal("unknown command %q", os.Args[1])
	}
}
func readJSON(path string, dst any) {
	raw, err := os.ReadFile(path)
	check(err)
	check(json.Unmarshal(raw, dst))
}
func write(v any) { enc := json.NewEncoder(os.Stdout); enc.SetEscapeHTML(false); check(enc.Encode(v)) }
func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}
func fatal(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
