package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewconsoleapi"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: review-console <check|registry|issue-token|verify-token|verify-security-audit>")
	}
	switch os.Args[1] {
	case "check":
		f := flag.NewFlagSet("check", flag.ExitOnError)
		p := f.String("config", "", "config")
		f.Parse(os.Args[2:])
		l, s := load(*p)
		check(s.Check(context.Background()))
		write(map[string]any{"status": "ok", "registry_sha256": l.Registry.RegistrySHA256, "model_mode": l.Config.ModelMode, "console_enabled": l.Config.ConsoleEnabled})
	case "registry":
		f := flag.NewFlagSet("registry", flag.ExitOnError)
		p := f.String("config", "", "config")
		f.Parse(os.Args[2:])
		l, _ := load(*p)
		write(map[string]any{"schema_version": l.Registry.SchemaVersion, "registry_id": l.Registry.RegistryID, "version": l.Registry.Version, "registry_sha256": l.Registry.RegistrySHA256, "role_count": len(l.Registry.Roles), "user_count": len(l.Registry.Users)})
	case "issue-token":
		f := flag.NewFlagSet("issue-token", flag.ExitOnError)
		p := f.String("config", "", "config")
		u := f.String("user", "", "user")
		t := f.String("tenant", "", "tenant")
		ttl := f.Duration("ttl", 30*time.Minute, "ttl")
		f.Parse(os.Args[2:])
		_, s := load(*p)
		tok, c, e := s.Tokens.Issue(*u, *t, *ttl, time.Now().UTC())
		check(e)
		write(map[string]any{"token": tok, "claims": c})
	case "verify-token":
		f := flag.NewFlagSet("verify-token", flag.ExitOnError)
		p := f.String("config", "", "config")
		tok := f.String("token", "", "token")
		f.Parse(os.Args[2:])
		v := strings.TrimSpace(*tok)
		if v == "" {
			b, e := os.ReadFile("/dev/stdin")
			check(e)
			v = strings.TrimSpace(string(b))
		}
		_, s := load(*p)
		c, e := s.Tokens.Parse(v, time.Now().UTC())
		check(e)
		write(map[string]any{"status": "ok", "claims": c, "permissions": s.Registry.Permissions(c.Roles)})
	case "verify-security-audit":
		f := flag.NewFlagSet("verify-security-audit", flag.ExitOnError)
		p := f.String("config", "", "config")
		f.Parse(os.Args[2:])
		_, s := load(*p)
		x, e := s.SecurityAudit.Verify()
		check(e)
		write(x)
	default:
		fatal("unknown command")
	}
}
func load(p string) (reviewconsoleapi.Loaded, *reviewconsoleapi.Server) {
	l, e := reviewconsoleapi.LoadConfig(p)
	check(e)
	s, e := reviewconsoleapi.New(l)
	check(e)
	return l, s
}
func write(v any) { e := json.NewEncoder(os.Stdout).Encode(v); check(e) }
func check(e error) {
	if e != nil {
		fatal("%v", e)
	}
}
func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
