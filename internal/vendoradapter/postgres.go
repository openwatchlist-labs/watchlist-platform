package vendoradapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type PostgresSink struct {
	DSN, PSQL string
	Timeout   time.Duration
}

func NewPostgresSink(dsn, psql string, timeout time.Duration) (*PostgresSink, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	if psql == "" {
		psql = "psql"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &PostgresSink{dsn, psql, timeout}, nil
}
func (p *PostgresSink) run(ctx context.Context, sql string) error {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.PSQL, p.DSN, "-v", "ON_ERROR_STOP=1", "-X", "-q", "-c", sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("psql: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
func (p *PostgresSink) Ping(ctx context.Context) error { return p.run(ctx, "SELECT 1") }
func (p *PostgresSink) Persist(ctx context.Context, e Envelope, r Receipt) error {
	eb, _ := json.Marshal(e)
	rb, _ := json.Marshal(r)
	sql := "BEGIN;\n" + "INSERT INTO vendor_adapter_record(record_id,adapter_id,adapter_version,profile_sha256,source_sha256,envelope_sha256,tenant_id,source_alert_id,occurred_at,envelope_json) VALUES (" + q(e.RecordID) + "," + q(e.AdapterID) + "," + q(e.AdapterVersion) + "," + q(e.ProfileSHA256) + "," + q(e.SourceSHA256) + "," + q(e.EnvelopeSHA256) + "," + q(e.CreateAlertRequest.TenantID) + "," + q(e.CreateAlertRequest.ExternalAlert.SourceAlertID) + "," + q(e.CreateAlertRequest.OccurredAt) + "::timestamptz," + q(string(eb)) + "::jsonb) ON CONFLICT(record_id) DO NOTHING;\n" + "INSERT INTO vendor_adapter_idempotency(scope,idempotency_key,source_sha256,record_id,receipt_json) VALUES (" + q(r.Scope) + "," + q(r.IdempotencyKey) + "," + q(r.SourceSHA256) + "," + q(r.RecordID) + "," + q(string(rb)) + "::jsonb) ON CONFLICT(scope,idempotency_key) DO NOTHING;\nCOMMIT;"
	return p.run(ctx, sql)
}
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
