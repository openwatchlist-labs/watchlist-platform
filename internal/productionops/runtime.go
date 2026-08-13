package productionops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Pinger is the /readyz PostgreSQL probe's entire contract with the
// database: no DSN, no driver, nothing subprocess-shaped. Both
// *pgx.Conn (the one-shot CLI shape) and *pgxpool.Pool (the long-running
// service shape) satisfy it, which is what lets CheckRuntime stay
// ignorant of which one it was handed (ADR-0005 §3.1, §11.2, D4/D12).
// CheckRuntime previously forked `psql -c "SELECT 1"` on every call --
// the highest-frequency fork+exec site in the tree, since it ran on
// every readiness poll -- reading the DSN from the environment itself.
// Constructing the connection is now the caller's job (see
// NewReadinessPool, NewReadinessConn), done once at startup for a
// service or once per invocation for a CLI, not once per probe.
type Pinger interface {
	Ping(ctx context.Context) error
}

type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}
type ReadinessReport struct {
	Status              string        `json:"status"`
	ConfigSHA256        string        `json:"config_sha256"`
	QuotaRegistrySHA256 string        `json:"quota_registry_sha256"`
	Checks              []CheckResult `json:"checks"`
}

func CheckRuntime(ctx context.Context, c RuntimeConfig, q QuotaRegistry, pg Pinger) ReadinessReport {
	r := ReadinessReport{Status: "ok", ConfigSHA256: c.ConfigSHA256, QuotaRegistrySHA256: q.RegistrySHA256}
	add := func(n string, err error) {
		x := CheckResult{Name: n, Status: "ok"}
		if err != nil {
			x.Status = "failed"
			x.Detail = err.Error()
			r.Status = "not_ready"
		}
		r.Checks = append(r.Checks, x)
	}
	for _, p := range c.Readiness.RequiredPaths {
		_, err := os.Stat(p)
		add("path:"+p, err)
	}
	for _, p := range []string{c.RuntimeStateDirectory, c.OutboxDirectory, c.BackupDirectory} {
		err := os.MkdirAll(p, 0700)
		if err == nil {
			f, e := os.CreateTemp(p, ".writecheck-")
			if e == nil {
				n := f.Name()
				e = f.Close()
				os.Remove(n)
			}
			err = e
		}
		add("writable:"+p, err)
	}
	if c.Readiness.MinFreeBytes > 0 {
		var st syscall.Statfs_t
		err := syscall.Statfs(c.RuntimeStateDirectory, &st)
		if err == nil {
			free := uint64(st.Bavail) * uint64(st.Bsize)
			if free < c.Readiness.MinFreeBytes {
				err = fmt.Errorf("free bytes %d below required %d", free, c.Readiness.MinFreeBytes)
			}
		}
		add("disk_free", err)
	}
	if c.Readiness.VerifyOutbox {
		o, err := NewOutboxStore(c.OutboxDirectory, "platform-outbox-phase9g")
		if err == nil {
			_, err = o.Verify()
		}
		add("outbox_integrity", err)
	}
	if c.Readiness.PostgreSQLRequired {
		var err error
		if pg == nil {
			err = errors.New("postgresql readiness required but no connection was configured")
		} else {
			tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			err = pg.Ping(tctx)
		}
		add("postgresql", err)
	}
	return r
}
func (r ReadinessReport) JSON() []byte { b, _ := json.Marshal(r); return b }
func EnsureProductionSecretBoundary(c RuntimeConfig) error {
	if c.Environment != "production" {
		return nil
	}
	_, err := ResolveSigningKey(c)
	return err
}
func ResolvePath(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(base, path))
}
