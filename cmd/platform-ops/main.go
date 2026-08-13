package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/productionops"
)

type roots []string

func (r *roots) String() string     { return strings.Join(*r, ",") }
func (r *roots) Set(v string) error { *r = append(*r, v); return nil }
func main() {
	if len(os.Args) < 2 {
		fatal("usage: platform-ops <check-config|render-config|render-quota|readiness|quota|outbox-enqueue|outbox-claim|outbox-complete|outbox-retry|outbox-recover|outbox-status|backup-create|backup-verify|backup-restore|sync-vendor-adapter|sync-outbox>")
	}
	switch os.Args[1] {
	case "check-config":
		fs := flag.NewFlagSet("check-config", flag.ExitOnError)
		p := fs.String("config", "", "config")
		_ = fs.Parse(os.Args[2:])
		c := loadConfig(*p)
		q, err := productionops.LoadQuotaRegistry(c.QuotaRegistryPath)
		check(err)
		check(productionops.EnsureProductionSecretBoundary(c))
		write(map[string]any{"status": "ok", "environment": c.Environment, "config_sha256": c.ConfigSHA256, "quota_registry_sha256": q.RegistrySHA256})
	case "render-config":
		fs := flag.NewFlagSet("render-config", flag.ExitOnError)
		input := fs.String("input", "", "source fixture config")
		root := fs.String("runtime-root", "", "runtime root")
		listen := fs.String("listen", "", "listen address")
		reviewConfig := fs.String("review-config", "", "review console config override")
		quotaRegistry := fs.String("quota-registry", "", "quota registry override")
		output := fs.String("output", "", "output")
		_ = fs.Parse(os.Args[2:])
		c := loadConfig(*input)
		if c.Environment != "fixture" {
			fatal("render-config is fixture-only")
		}
		abs := func(v string) string { a, err := filepath.Abs(v); check(err); return a }
		c.ReviewConsoleConfigPath = abs(c.ReviewConsoleConfigPath)
		c.QuotaRegistryPath = abs(c.QuotaRegistryPath)
		for i := range c.Readiness.RequiredPaths {
			c.Readiness.RequiredPaths[i] = abs(c.Readiness.RequiredPaths[i])
		}
		if *root == "" || *output == "" {
			fatal("runtime-root and output are required")
		}
		c.RuntimeStateDirectory = filepath.Join(*root, "runtime")
		c.OutboxDirectory = filepath.Join(*root, "outbox")
		c.BackupDirectory = filepath.Join(*root, "backups")
		if *listen != "" {
			c.ListenAddress = *listen
		}
		if *reviewConfig != "" {
			c.ReviewConsoleConfigPath = *reviewConfig
		}
		if *quotaRegistry != "" {
			c.QuotaRegistryPath = *quotaRegistry
		}
		c, err := productionops.SealRuntimeConfig(c)
		check(err)
		b, err := json.MarshalIndent(c, "", "  ")
		check(err)
		b = append(b, '\n')
		check(os.WriteFile(*output, b, 0600))
		write(map[string]any{"status": "ok", "config_sha256": c.ConfigSHA256, "output": *output})
	case "render-quota":
		fs := flag.NewFlagSet("render-quota", flag.ExitOnError)
		input := fs.String("input", "", "source quota registry")
		tenant := fs.String("tenant", "tenant-a", "tenant to override")
		rpm := fs.Int("rpm", 60, "requests per minute")
		burst := fs.Int("burst", 2, "burst")
		concurrent := fs.Int("concurrent", 2, "max concurrent")
		body := fs.Int64("body-bytes", 1024, "max body bytes")
		output := fs.String("output", "", "output")
		_ = fs.Parse(os.Args[2:])
		q, err := productionops.LoadQuotaRegistry(*input)
		check(err)
		found := false
		for i := range q.Tenants {
			if q.Tenants[i].TenantID == *tenant {
				q.Tenants[i].RequestsPerMinute = *rpm
				q.Tenants[i].Burst = *burst
				q.Tenants[i].MaxConcurrent = *concurrent
				q.Tenants[i].MaxBodyBytes = *body
				found = true
			}
		}
		if !found {
			q.Tenants = append(q.Tenants, productionops.TenantQuota{TenantID: *tenant, RequestsPerMinute: *rpm, Burst: *burst, MaxConcurrent: *concurrent, MaxBodyBytes: *body})
		}
		q, err = productionops.SealQuotaRegistry(q)
		check(err)
		b, err := json.MarshalIndent(q, "", "  ")
		check(err)
		b = append(b, '\n')
		check(os.WriteFile(*output, b, 0600))
		write(map[string]any{"status": "ok", "registry_sha256": q.RegistrySHA256, "output": *output})
	case "readiness":
		fs := flag.NewFlagSet("readiness", flag.ExitOnError)
		p := fs.String("config", "", "config")
		_ = fs.Parse(os.Args[2:])
		c := loadConfig(*p)
		q, err := productionops.LoadQuotaRegistry(c.QuotaRegistryPath)
		check(err)
		ctx := context.Background()
		// One connection for this one-shot invocation, not a pool
		// (ADR-0005 §3.1, D4) -- nil when PostgreSQL readiness isn't
		// configured, matching platformapi's pool-or-nil shape.
		conn, err := productionops.NewReadinessConn(ctx, c)
		check(err)
		var pg productionops.Pinger
		if conn != nil {
			defer conn.Close(ctx)
			pg = conn
		}
		r := productionops.CheckRuntime(ctx, c, q, pg)
		write(r)
		if r.Status != "ok" {
			os.Exit(1)
		}
	case "quota":
		fs := flag.NewFlagSet("quota", flag.ExitOnError)
		p := fs.String("config", "", "config")
		tenant := fs.String("tenant", "", "tenant")
		_ = fs.Parse(os.Args[2:])
		c := loadConfig(*p)
		q, err := productionops.LoadQuotaRegistry(c.QuotaRegistryPath)
		check(err)
		write(map[string]any{"registry_sha256": q.RegistrySHA256, "quota": q.ForTenant(*tenant)})
	case "outbox-enqueue":
		fs := flag.NewFlagSet("outbox-enqueue", flag.ExitOnError)
		state := fs.String("state", "", "state")
		topic := fs.String("topic", "", "topic")
		tenant := fs.String("tenant", "", "tenant")
		key := fs.String("key", "", "key")
		input := fs.String("input", "", "payload JSON")
		max := fs.Int("max-attempts", 5, "max attempts")
		now := fs.String("now", "", "RFC3339 time")
		_ = fs.Parse(os.Args[2:])
		b, err := os.ReadFile(*input)
		check(err)
		s := outbox(*state)
		m, re, err := s.Enqueue(*topic, *tenant, *key, b, *max, parseTime(*now))
		check(err)
		write(map[string]any{"message": m, "replayed": re})
	case "outbox-claim":
		fs := flag.NewFlagSet("outbox-claim", flag.ExitOnError)
		state := fs.String("state", "", "state")
		lease := fs.Duration("lease", 30*time.Second, "lease")
		now := fs.String("now", "", "time")
		_ = fs.Parse(os.Args[2:])
		p, t, err := outbox(*state).Claim(parseTime(*now), *lease)
		check(err)
		write(map[string]any{"projection": p, "lease_token": t})
	case "outbox-complete":
		fs := flag.NewFlagSet("outbox-complete", flag.ExitOnError)
		state := fs.String("state", "", "state")
		id := fs.String("id", "", "message")
		token := fs.String("token", "", "lease token")
		now := fs.String("now", "", "time")
		_ = fs.Parse(os.Args[2:])
		check(outbox(*state).Complete(*id, *token, parseTime(*now)))
		write(map[string]any{"status": "ok", "message_id": *id})
	case "outbox-retry":
		fs := flag.NewFlagSet("outbox-retry", flag.ExitOnError)
		state := fs.String("state", "", "state")
		id := fs.String("id", "", "message")
		token := fs.String("token", "", "lease token")
		delay := fs.Duration("delay", time.Second, "delay")
		detail := fs.String("detail", "retry", "detail")
		now := fs.String("now", "", "time")
		_ = fs.Parse(os.Args[2:])
		check(outbox(*state).Retry(*id, *token, *detail, *delay, parseTime(*now)))
		write(map[string]any{"status": "ok", "message_id": *id})
	case "outbox-recover":
		fs := flag.NewFlagSet("outbox-recover", flag.ExitOnError)
		state := fs.String("state", "", "state")
		now := fs.String("now", "", "time")
		_ = fs.Parse(os.Args[2:])
		check(outbox(*state).Recover(parseTime(*now)))
		st, err := outbox(*state).Status()
		check(err)
		write(st)
	case "outbox-status":
		fs := flag.NewFlagSet("outbox-status", flag.ExitOnError)
		state := fs.String("state", "", "state")
		_ = fs.Parse(os.Args[2:])
		st, err := outbox(*state).Verify()
		check(err)
		write(st)
	case "backup-create":
		fs := flag.NewFlagSet("backup-create", flag.ExitOnError)
		archive := fs.String("archive", "", "archive")
		now := fs.String("now", "", "time")
		var rr roots
		fs.Var(&rr, "root", "name=path (repeatable)")
		_ = fs.Parse(os.Args[2:])
		manifest, err := productionops.CreateBackup(*archive, parseRoots(rr), parseTime(*now))
		check(err)
		write(manifest)
	case "backup-verify":
		fs := flag.NewFlagSet("backup-verify", flag.ExitOnError)
		archive := fs.String("archive", "", "archive")
		_ = fs.Parse(os.Args[2:])
		m, err := productionops.VerifyBackup(*archive)
		check(err)
		write(m)
	case "backup-restore":
		fs := flag.NewFlagSet("backup-restore", flag.ExitOnError)
		archive := fs.String("archive", "", "archive")
		target := fs.String("target", "", "target")
		_ = fs.Parse(os.Args[2:])
		m, err := productionops.RestoreBackup(*archive, *target)
		check(err)
		write(m)
	case "sync-vendor-adapter":
		fs := flag.NewFlagSet("sync-vendor-adapter", flag.ExitOnError)
		dsnEnv := fs.String("postgres-dsn-env", "", "environment variable holding the PostgreSQL DSN")
		psql := fs.String("psql", "psql", "psql")
		state := fs.String("state", "", "state")
		_ = fs.Parse(os.Args[2:])
		p, err := productionops.NewPSQLRunner(dsnFromEnv(*dsnEnv), *psql, 30*time.Second)
		check(err)
		counts, err := productionops.SyncVendorAdapterState(context.Background(), p, *state)
		check(err)
		write(map[string]any{"status": "ok", "counts": counts})
	case "sync-outbox":
		fs := flag.NewFlagSet("sync-outbox", flag.ExitOnError)
		dsnEnv := fs.String("postgres-dsn-env", "", "environment variable holding the PostgreSQL DSN")
		psql := fs.String("psql", "psql", "psql")
		state := fs.String("state", "", "state")
		_ = fs.Parse(os.Args[2:])
		p, err := productionops.NewPSQLRunner(dsnFromEnv(*dsnEnv), *psql, 30*time.Second)
		check(err)
		counts, err := productionops.SyncOutbox(context.Background(), p, *state)
		check(err)
		write(map[string]any{"status": "ok", "counts": counts})
	default:
		fatal("unknown command %q", os.Args[1])
	}
}
func loadConfig(p string) productionops.RuntimeConfig {
	c, err := productionops.LoadRuntimeConfig(p)
	check(err)
	return c
}

// dsnFromEnv reads the PostgreSQL DSN from the named environment
// variable rather than accepting it as a flag value directly -- a DSN on
// argv is readable via `ps` by any local user (SEC-3, ADR-0005 §11.1,
// D11). There must be no sibling flag accepting the DSN itself; that
// would reopen the exposure this flag exists to close.
func dsnFromEnv(envName string) string {
	if strings.TrimSpace(envName) == "" {
		fatal("--postgres-dsn-env is required")
	}
	return os.Getenv(envName)
}
func outbox(p string) *productionops.OutboxStore {
	s, err := productionops.NewOutboxStore(p, "platform-outbox-phase9g")
	check(err)
	return s
}
func parseTime(v string) time.Time {
	if v == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	check(err)
	return t
}
func parseRoots(v []string) []productionops.BackupRoot {
	out := make([]productionops.BackupRoot, 0, len(v))
	for _, x := range v {
		a, b, ok := strings.Cut(x, "=")
		if !ok || a == "" || b == "" {
			fatal("invalid root %q", x)
		}
		out = append(out, productionops.BackupRoot{Name: a, Path: b})
	}
	return out
}
func write(v any) { e := json.NewEncoder(os.Stdout); e.SetEscapeHTML(false); check(e.Encode(v)) }
func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}
func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
