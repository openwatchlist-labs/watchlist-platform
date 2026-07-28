package main

import (
	"flag"
	"fmt"
	"github.com/openwatchlist-labs/watchlist-platform/internal/releaseartifact"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: release-artifact <manifest|verify|bundle|verify-bundle>")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	root := fs.String("root", ".", "release tree")
	manifest := fs.String("manifest", "release-manifest.json", "manifest")
	output := fs.String("output", "release-bundle.zip", "bundle output")
	version := fs.String("version", "dev", "version")
	vcs := fs.String("vcs-ref", "unknown", "VCS ref")
	epoch := fs.Int64("source-date-epoch", 0, "reproducible timestamp")
	exclude := fs.String("exclude", "", "comma-separated relative paths")
	fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "manifest":
		m, e := releaseartifact.BuildManifest(*root, *version, *vcs, *epoch, split(*exclude))
		check(e)
		check(releaseartifact.WriteManifest(*manifest, m))
		fmt.Printf("%s\n", m.ManifestSHA256)
	case "verify":
		m, e := releaseartifact.ReadManifest(*manifest)
		check(e)
		check(releaseartifact.Verify(*root, m))
		fmt.Println("ok")
	case "bundle":
		m, e := releaseartifact.ReadManifest(*manifest)
		check(e)
		check(releaseartifact.Verify(*root, m))
		check(releaseartifact.Bundle(*root, *output, m))
		check(releaseartifact.VerifyBundle(*output, m))
		fmt.Println(*output)
	case "verify-bundle":
		m, e := releaseartifact.ReadManifest(*manifest)
		check(e)
		check(releaseartifact.VerifyBundle(*output, m))
		fmt.Println("ok")
	default:
		fatal("unknown command %q", os.Args[1])
	}
}
func split(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var o []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			o = append(o, x)
		}
	}
	return o
}
func check(e error) {
	if e != nil {
		fatal("%v", e)
	}
}
func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
