package productionops

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/vendoradapter"
)

type PSQLRunner struct {
	DSN, Path string
	Timeout   time.Duration
}

func NewPSQLRunner(dsn, path string, timeout time.Duration) (*PSQLRunner, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	if path == "" {
		path = "psql"
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &PSQLRunner{dsn, path, timeout}, nil
}
func (p *PSQLRunner) Run(ctx context.Context, sql string) error {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Path, p.DSN, "-X", "-v", "ON_ERROR_STOP=1", "--no-psqlrc", "--quiet")
	cmd.Stdin = strings.NewReader(sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("psql: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
func pgText(s string) string {
	return "convert_from(decode('" + hex.EncodeToString([]byte(s)) + "','hex'),'UTF8')"
}
func pgJSON(b []byte) string {
	return "convert_from(decode('" + hex.EncodeToString(b) + "','hex'),'UTF8')::jsonb"
}

func SyncVendorAdapterState(ctx context.Context, p *PSQLRunner, state string) (map[string]int, error) {
	records, _ := filepath.Glob(filepath.Join(state, "records", "*.json"))
	receipts, _ := filepath.Glob(filepath.Join(state, "receipts", "*.json"))
	audits, _ := filepath.Glob(filepath.Join(state, "audit", "*.json"))
	sort.Strings(records)
	sort.Strings(receipts)
	sort.Strings(audits)
	sql := "BEGIN;\nSELECT pg_advisory_xact_lock(hashtext('openwatchlist-phase9g-vendor-sync'));\n"
	for _, f := range records {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var e vendoradapter.Envelope
		if err = json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		sql += "INSERT INTO vendor_adapter_record(record_id,adapter_id,adapter_version,profile_sha256,source_sha256,envelope_sha256,tenant_id,source_alert_id,occurred_at,envelope_json) VALUES (" + pgText(e.RecordID) + "," + pgText(e.AdapterID) + "," + pgText(e.AdapterVersion) + "," + pgText(e.ProfileSHA256) + "," + pgText(e.SourceSHA256) + "," + pgText(e.EnvelopeSHA256) + "," + pgText(e.CreateAlertRequest.TenantID) + "," + pgText(e.CreateAlertRequest.ExternalAlert.SourceAlertID) + "," + pgText(e.CreateAlertRequest.OccurredAt) + "::timestamptz," + pgJSON(b) + ") ON CONFLICT(record_id) DO NOTHING;\n"
	}
	for _, f := range receipts {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var r vendoradapter.Receipt
		if err = json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		sql += "INSERT INTO vendor_adapter_idempotency(scope,idempotency_key,source_sha256,record_id,receipt_json) VALUES (" + pgText(r.Scope) + "," + pgText(r.IdempotencyKey) + "," + pgText(r.SourceSHA256) + "," + pgText(r.RecordID) + "," + pgJSON(b) + ") ON CONFLICT(scope,idempotency_key) DO NOTHING;\n"
	}
	for _, f := range audits {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var a vendoradapter.AuditEvent
		if err = json.Unmarshal(b, &a); err != nil {
			return nil, err
		}
		sql += "INSERT INTO vendor_adapter_audit(stream_id,sequence,previous_audit_sha256,audit_sha256,occurred_at,action,object_type,object_id,details) VALUES (" + pgText(a.StreamID) + "," + fmt.Sprint(a.Sequence) + "," + pgText(a.PreviousAuditSHA256) + "," + pgText(a.AuditSHA256) + "," + pgText(a.OccurredAt) + "::timestamptz," + pgText(a.Action) + "," + pgText(a.ObjectType) + "," + pgText(a.ObjectID) + "," + pgJSON(a.Details) + ") ON CONFLICT(audit_sha256) DO NOTHING;\n"
	}
	sql += "COMMIT;\n"
	if err := p.Run(ctx, sql); err != nil {
		return nil, err
	}
	return map[string]int{"records": len(records), "receipts": len(receipts), "audits": len(audits)}, nil
}
func SyncOutbox(ctx context.Context, p *PSQLRunner, state string) (map[string]int, error) {
	messages, _ := filepath.Glob(filepath.Join(state, "messages", "*.json"))
	events, _ := filepath.Glob(filepath.Join(state, "events", "*.json"))
	sort.Strings(messages)
	sort.Strings(events)
	sql := "BEGIN;\nSELECT pg_advisory_xact_lock(hashtext('openwatchlist-phase9g-outbox-sync'));\n"
	for _, f := range messages {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var m OutboxMessage
		if err = json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		sql += "INSERT INTO operational_outbox_message(message_id,topic,tenant_id,idempotency_key,payload_sha256,message_sha256,max_attempts,created_at,message_json) VALUES (" + pgText(m.MessageID) + "," + pgText(m.Topic) + "," + pgText(m.TenantID) + "," + pgText(m.IdempotencyKey) + "," + pgText(m.PayloadSHA256) + "," + pgText(m.MessageSHA256) + "," + fmt.Sprint(m.MaxAttempts) + "," + pgText(m.CreatedAt) + "::timestamptz," + pgJSON(b) + ") ON CONFLICT(message_id) DO NOTHING;\n"
	}
	for _, f := range events {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var e OutboxEvent
		if err = json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		sql += "INSERT INTO operational_outbox_event(stream_id,sequence,event_sha256,previous_event_sha256,message_id,occurred_at,action,attempt,event_json) VALUES (" + pgText(e.StreamID) + "," + fmt.Sprint(e.Sequence) + "," + pgText(e.EventSHA256) + "," + pgText(e.PreviousEventSHA256) + "," + pgText(e.MessageID) + "," + pgText(e.OccurredAt) + "::timestamptz," + pgText(e.Action) + "," + fmt.Sprint(e.Attempt) + "," + pgJSON(b) + ") ON CONFLICT(event_sha256) DO NOTHING;\n"
	}
	sql += "COMMIT;\n"
	if err := p.Run(ctx, sql); err != nil {
		return nil, err
	}
	return map[string]int{"messages": len(messages), "events": len(events)}, nil
}
