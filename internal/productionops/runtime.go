package productionops

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

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

func CheckRuntime(ctx context.Context, c RuntimeConfig, q QuotaRegistry) ReadinessReport {
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
		dsn := strings.TrimSpace(os.Getenv(c.Readiness.PostgreSQLDSNEnv))
		var err error
		if dsn == "" {
			err = fmt.Errorf("%s is empty", c.Readiness.PostgreSQLDSNEnv)
		} else {
			tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(tctx, c.Readiness.PSQLPath, dsn, "-X", "-v", "ON_ERROR_STOP=1", "-q", "-c", "SELECT 1")
			if out, e := cmd.CombinedOutput(); e != nil {
				err = fmt.Errorf("postgres readiness: %w: %s", e, strings.TrimSpace(string(out)))
			}
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
