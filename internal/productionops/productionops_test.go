package productionops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRateLimiterAndConcurrency(t *testing.T) {
	r := NewRateLimiter()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	firstAllowed := r.Allow("a", now, 60, 2)
	secondAllowed := r.Allow("a", now, 60, 2)
	thirdAllowed := r.Allow("a", now, 60, 2)
	if !firstAllowed || !secondAllowed || thirdAllowed {
		t.Fatal("burst enforcement failed")
	}
	if !r.Allow("a", now.Add(time.Second), 60, 2) {
		t.Fatal("refill failed")
	}
	c := NewConcurrencyLimiter(2, 1)
	if !c.Acquire("tenant-a", 1) {
		t.Fatal("first acquire")
	}
	if c.Acquire("tenant-a", 1) {
		t.Fatal("tenant limit not enforced")
	}
	c.Release("tenant-a", 1)
	if !c.Acquire("tenant-a", 1) {
		t.Fatal("release failed")
	}
	c.Release("tenant-a", 1)
}

func TestOutboxLifecycleRecoveryAndConflict(t *testing.T) {
	dir := t.TempDir()
	s, err := NewOutboxStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	payload := []byte(`{"case_id":"case-1"}`)
	m, re, err := s.Enqueue("case.delivery", "tenant-a", "idem-1", payload, 3, t0)
	if err != nil || re {
		t.Fatalf("enqueue %v replay=%v", err, re)
	}
	m2, re, err := s.Enqueue("case.delivery", "tenant-a", "idem-1", payload, 3, t0)
	if err != nil || !re || m2.MessageID != m.MessageID {
		t.Fatalf("replay %v %v", re, err)
	}
	if _, _, err = s.Enqueue("case.delivery", "tenant-a", "idem-1", []byte(`{"case_id":"different"}`), 3, t0); err == nil {
		t.Fatal("expected conflict")
	}
	p, _, err := s.Claim(t0.Add(time.Second), 2*time.Second)
	if err != nil || p.State != "leased" {
		t.Fatalf("claim %v state=%s", err, p.State)
	}
	if err = s.Recover(t0.Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	p, token, err := s.Claim(t0.Add(5*time.Second), 10*time.Second)
	if err != nil || p.Attempt != 2 {
		t.Fatalf("reclaim %v attempt=%d", err, p.Attempt)
	}
	if err = s.Retry(m.MessageID, token, "downstream unavailable", time.Second, t0.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	p, token, err = s.Claim(t0.Add(8*time.Second), 10*time.Second)
	if err != nil || p.Attempt != 3 {
		t.Fatalf("retry claim %v attempt=%d", err, p.Attempt)
	}
	if err = s.Complete(m.MessageID, token, t0.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
	st, err := s.Verify()
	if err != nil || st.CompletedCount != 1 || st.EventCount != 7 {
		t.Fatalf("status %+v err=%v", st, err)
	}
}

func TestBackupRoundTripAndSecretRejection(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "state.json"), []byte("{\"ok\":true}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "backup.zip")
	m, err := CreateBackup(archive, []BackupRoot{{Name: "runtime", Path: root}}, time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC))
	if err != nil || m.EntryCount != 1 {
		t.Fatalf("backup %v %+v", err, m)
	}
	v, err := VerifyBackup(archive)
	if err != nil || v.ContentSHA256 != m.ContentSHA256 {
		t.Fatalf("verify %v", err)
	}
	target := t.TempDir()
	if _, err = RestoreBackup(archive, target); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(target, "runtime", "nested", "state.json"))
	if err != nil || string(b) != "{\"ok\":true}\n" {
		t.Fatalf("restore %v %q", err, b)
	}
	if err = os.WriteFile(filepath.Join(root, "signing-key.hex"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = CreateBackup(filepath.Join(t.TempDir(), "bad.zip"), []BackupRoot{{Name: "runtime", Path: root}}, time.Now()); err == nil {
		t.Fatal("secret-like file should be rejected")
	}
}

func TestCanonicalConfigAndQuota(t *testing.T) {
	base := t.TempDir()
	q := QuotaRegistry{SchemaVersion: QuotaSchemaV1, RegistryID: "q", Version: "r1", Default: TenantQuota{TenantID: "*", RequestsPerMinute: 10, Burst: 2, MaxConcurrent: 1, MaxBodyBytes: 100}, Tenants: []TenantQuota{{TenantID: "tenant-a", RequestsPerMinute: 20, Burst: 4, MaxConcurrent: 2, MaxBodyBytes: 200}}}
	h, _ := objectHash(q)
	q.RegistrySHA256 = h
	qb, _ := json.Marshal(q)
	qp := filepath.Join(base, "quota.json")
	os.WriteFile(qp, qb, 0600)
	loaded, err := LoadQuotaRegistry(qp)
	if err != nil || loaded.RegistrySHA256 != h {
		t.Fatalf("quota %v", err)
	}
	c := RuntimeConfig{SchemaVersion: ConfigSchemaV1, ConfigID: "c", Version: "r1", Environment: "fixture", ListenAddress: "127.0.0.1:1", ReviewConsoleConfigPath: "review.json", QuotaRegistryPath: "quota.json", RuntimeStateDirectory: "runtime", OutboxDirectory: "outbox", BackupDirectory: "backups", ShutdownGraceSeconds: 1, RequestTimeoutSeconds: 1, ReadHeaderTimeoutSeconds: 1, ReadTimeoutSeconds: 1, WriteTimeoutSeconds: 1, IdleTimeoutSeconds: 1, MaxHeaderBytes: 100, MaxBodyBytes: 100, GlobalConcurrency: 1, DefaultTenantConcurrency: 1, DefaultRequestsPerMinute: 1, DefaultBurst: 1, TLS: TLSConfig{ForwardedProtoHeader: "X-Forwarded-Proto"}, Readiness: ReadinessConfig{PSQLPath: "psql", PostgreSQLDSNEnv: "DSN"}}
	h, _ = objectHash(c)
	c.ConfigSHA256 = h
	cb, _ := json.Marshal(c)
	cp := filepath.Join(base, "config.json")
	os.WriteFile(cp, cb, 0600)
	lc, err := LoadRuntimeConfig(cp)
	if err != nil || lc.ConfigSHA256 != h {
		t.Fatalf("config %v", err)
	}
}
