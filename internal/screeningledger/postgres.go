package screeningledger

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// PostgresSink persists ledger events to PostgreSQL over a single
// connection, not a pool. cmd/screening-ledger's sync and import-audit
// loops are strictly sequential (ADR-0005 §3.1, D4) -- there is never a
// second goroutine writing concurrently -- so a pool would hold exactly
// one connection in use for the entire run while adding reconnect logic
// and lifecycle knobs that buy nothing. One *pgx.Conn per invocation,
// opened in NewPostgresSink and closed by the caller via Close, captures
// the entire available benefit.
//
// The DSN this sink connects with must be an identity with DDL rights on
// the ledger schema, not owl_app (ADR-0005 §4, "Role identity, which is
// currently unstated"). Migrate runs CREATE TABLE / CREATE TRIGGER on
// every sync and import-audit invocation, and owl_app is granted no
// privileges at all on these Class C relations --
// scripts/ci/provision_test_roles.sh grants owl_app only the tables
// listed in db/tenant_scoped_tables.txt, which does not include any
// screening_ledger_* or watchlist_operational_audit table. In this
// repository's role model that means owl_migrator or an equivalent
// DDL-capable identity. Splitting DDL (at deploy time) from DML (at sync
// time, as owl_app) is a separate change with its own reasoning, not
// something this migration does.
type PostgresSink struct {
	conn    *pgx.Conn
	timeout time.Duration
}

func NewPostgresSink(ctx context.Context, dsn string, timeout time.Duration) (*PostgresSink, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	// statement_timeout is a defense-in-depth backstop (ADR-0005 §3.2,
	// D7), set explicitly rather than left to server defaults. fork+exec
	// previously guaranteed a hung statement died when exec.CommandContext
	// killed the psql process on ctx expiry; a live connection has no such
	// property on its own -- ctx cancellation asks pgx to send a cancel
	// request, but the server-side backstop is what actually bounds a
	// runaway statement if that race is lost.
	connConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(timeout.Milliseconds(), 10)

	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(connectCtx, connConfig)
	if err != nil {
		return nil, err
	}
	return &PostgresSink{conn: conn, timeout: timeout}, nil
}

// Close releases the sink's single connection. Callers should close the
// sink once they are done with it, typically via defer right after
// NewPostgresSink succeeds.
func (p *PostgresSink) Close(ctx context.Context) error {
	return p.conn.Close(ctx)
}

func (p *PostgresSink) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return p.conn.Ping(ctx)
}

// Migrate executes SchemaSQL as one multi-statement script via the
// simple query protocol (PgConn.Exec), the same shape psql -f used --
// the extended protocol pgx.Conn.Exec uses by default cannot prepare a
// string containing multiple statements.
func (p *PostgresSink) Migrate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	_, err := p.conn.PgConn().Exec(ctx, SchemaSQL).ReadAll()
	return err
}

func (p *PostgresSink) Persist(ctx context.Context, event Event, request, response SnapshotEnvelope) error {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}
	reqJSON, err := json.Marshal(request)
	if err != nil {
		return err
	}
	respJSON, err := json.Marshal(response)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	tx, err := p.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Same idempotency-receipt conflict guard the previous DO $$ block
	// enforced, expressed as a parameterized SELECT plus an
	// application-side check rather than string-formatted PL/pgSQL --
	// DO blocks take no bind parameters. Same transaction, same check,
	// same error.
	if event.IdempotencyKeyHash != "" {
		var conflict bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM screening_idempotency_receipt WHERE scope=$1 AND idempotency_key_sha256=$2 AND (request_sha256<>$3 OR response_sha256<>$4 OR http_status<>$5))`,
			event.Route, event.IdempotencyKeyHash, event.RequestSHA256, event.ResponseSHA256, event.HTTPStatus,
		).Scan(&conflict); err != nil {
			return err
		}
		if conflict {
			return errors.New("idempotency receipt conflict")
		}
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO screening_ledger_event(event_id,ledger_id,sequence,event_sha256,previous_event_sha256,occurred_at,route,http_status,request_sha256,response_sha256,request_snapshot_sha256,response_snapshot_sha256,retention_class,expires_at,event_json)
		 VALUES ($1,$2,$3,$4,$5,$6::timestamptz,$7,$8,$9,$10,$11,$12,$13,$14::timestamptz,$15::jsonb)
		 ON CONFLICT (event_id) DO NOTHING`,
		event.EventID, event.LedgerID, int64(event.Sequence), event.EventSHA256, event.PreviousEventSHA256,
		event.OccurredAt, event.Route, event.HTTPStatus, event.RequestSHA256, event.ResponseSHA256,
		event.RequestSnapshotSHA256, event.ResponseSnapshotSHA256, event.RetentionClass, event.ExpiresAt, eventJSON,
	); err != nil {
		return err
	}

	if err := insertSnapshot(ctx, tx, request, reqJSON); err != nil {
		return err
	}
	if err := insertSnapshot(ctx, tx, response, respJSON); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO screening_ledger_replication(event_id,replicated_at) VALUES ($1,clock_timestamp()) ON CONFLICT (event_id) DO NOTHING`,
		event.EventID,
	); err != nil {
		return err
	}

	// $2 needs an explicit cast: a bare "$2 IS NOT NULL" in the WHERE
	// clause gives Postgres' parameter type inference nothing to resolve
	// against, even though the same parameter also feeds a text column
	// in the SELECT list -- confirmed against a live server, not assumed.
	if _, err := tx.Exec(ctx,
		`INSERT INTO screening_idempotency_receipt(scope,idempotency_key_sha256,request_sha256,response_sha256,http_status,event_id)
		 SELECT $1,$2::text,$3,$4,$5,$6 WHERE $2 IS NOT NULL
		 ON CONFLICT (scope,idempotency_key_sha256) DO NOTHING`,
		event.Route, nullableText(event.IdempotencyKeyHash), event.RequestSHA256, event.ResponseSHA256, event.HTTPStatus, event.EventID,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// PersistAudit previously issued this INSERT as a bare statement, outside
// any transaction. ADR-0001 SEC-1 §3 calls this out by name: a local
// set_config in that position would be silently a no-op, exactly the
// looks-installed-does-nothing class the ADR exists to eliminate. Wrapped
// here in the same BEGIN/COMMIT envelope Persist already uses. No tenant
// binding applies -- screening_ledger_audit is Class C (deferred by D2,
// ADR §4/§9), absent from db/tenant_scoped_tables.txt.
func (p *PostgresSink) PersistAudit(ctx context.Context, event AuditEvent) error {
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	tx, err := p.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO screening_ledger_audit(ledger_id,sequence,audit_sha256,previous_audit_sha256,occurred_at,action,event_id,audit_json)
		 VALUES ($1,$2,$3,$4,$5::timestamptz,$6,$7,$8::jsonb)
		 ON CONFLICT (audit_sha256) DO NOTHING`,
		event.LedgerID, int64(event.Sequence), event.AuditSHA256, event.PreviousAuditSHA256, event.OccurredAt, event.Action, nullableText(event.EventID), raw,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// PurgeExpired: see PersistAudit's doc comment -- same bare-statement
// hazard, same fix. screening_ledger_snapshot is Class C.
func (p *PostgresSink) PurgeExpired(ctx context.Context, before, operator, reason string) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	tx, err := p.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT screening_ledger_purge_snapshots($1::timestamptz,$2,$3)`, before, operator, reason); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// PersistExternalAudit: see PersistAudit's doc comment -- same
// bare-statement hazard, same fix. watchlist_operational_audit is Class C.
func (p *PostgresSink) PersistExternalAudit(ctx context.Context, source, streamID string, sequence uint64, eventSHA, previous, occurred, action string, payload []byte) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	tx, err := p.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO watchlist_operational_audit(source,stream_id,sequence,event_sha256,previous_event_sha256,occurred_at,action,payload_json)
		 VALUES ($1,$2,$3,$4,$5,$6::timestamptz,$7,$8::jsonb)
		 ON CONFLICT (source,event_sha256) DO NOTHING`,
		source, streamID, int64(sequence), eventSHA, previous, occurred, action, payload,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func insertSnapshot(ctx context.Context, tx pgx.Tx, e SnapshotEnvelope, raw []byte) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO screening_ledger_snapshot(snapshot_sha256,kind,created_at,expires_at,retention_class,envelope_json)
		 VALUES ($1,$2,$3::timestamptz,$4::timestamptz,$5,$6::jsonb)
		 ON CONFLICT (snapshot_sha256) DO NOTHING`,
		e.SnapshotSHA256, e.Kind, e.CreatedAt, e.ExpiresAt, e.RetentionClass, raw,
	)
	return err
}

// nullableText turns an empty string into a bound NULL, the parameterized
// replacement for the previous sqlNullableText's empty-string-to-NULL
// text substitution (ADR-0005 §4).
func nullableText(v string) any {
	if v == "" {
		return nil
	}
	return v
}

const SchemaSQL = `BEGIN;
CREATE TABLE IF NOT EXISTS screening_ledger_event (event_id text PRIMARY KEY,ledger_id text NOT NULL,sequence bigint NOT NULL,event_sha256 text NOT NULL UNIQUE,previous_event_sha256 text NOT NULL,occurred_at timestamptz NOT NULL,route text NOT NULL,http_status integer NOT NULL,request_sha256 text NOT NULL,response_sha256 text NOT NULL,request_snapshot_sha256 text NOT NULL,response_snapshot_sha256 text NOT NULL,retention_class text NOT NULL,expires_at timestamptz NOT NULL,event_json jsonb NOT NULL,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(ledger_id,sequence));
CREATE TABLE IF NOT EXISTS screening_ledger_snapshot (snapshot_sha256 text PRIMARY KEY,kind text NOT NULL CHECK(kind IN('request','response')),created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,retention_class text NOT NULL,envelope_json jsonb NOT NULL,purged_at timestamptz,purge_reason text,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS screening_ledger_replication (event_id text PRIMARY KEY REFERENCES screening_ledger_event(event_id),replicated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS screening_idempotency_receipt (scope text NOT NULL,idempotency_key_sha256 text NOT NULL,request_sha256 text NOT NULL,response_sha256 text NOT NULL,http_status integer NOT NULL,event_id text NOT NULL REFERENCES screening_ledger_event(event_id),inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(scope,idempotency_key_sha256));
CREATE TABLE IF NOT EXISTS screening_ledger_retention_tombstone(snapshot_sha256 text PRIMARY KEY,purged_at timestamptz NOT NULL,operator text NOT NULL,reason text NOT NULL);
CREATE TABLE IF NOT EXISTS watchlist_operational_audit(source text NOT NULL,stream_id text NOT NULL,sequence bigint NOT NULL,event_sha256 text NOT NULL,previous_event_sha256 text NOT NULL,occurred_at timestamptz NOT NULL,action text NOT NULL,payload_json jsonb NOT NULL,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(source,event_sha256),UNIQUE(source,stream_id,sequence));
CREATE TABLE IF NOT EXISTS screening_ledger_audit(ledger_id text NOT NULL,sequence bigint NOT NULL,audit_sha256 text PRIMARY KEY,previous_audit_sha256 text NOT NULL,occurred_at timestamptz NOT NULL,action text NOT NULL,event_id text,audit_json jsonb NOT NULL,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(ledger_id,sequence));
CREATE OR REPLACE FUNCTION screening_ledger_reject_mutation()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'screening ledger rows are append-only';END $$;
DROP TRIGGER IF EXISTS screening_ledger_event_immutable ON screening_ledger_event;CREATE TRIGGER screening_ledger_event_immutable BEFORE UPDATE OR DELETE ON screening_ledger_event FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_ledger_audit_immutable ON screening_ledger_audit;CREATE TRIGGER screening_ledger_audit_immutable BEFORE UPDATE OR DELETE ON screening_ledger_audit FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS watchlist_operational_audit_immutable ON watchlist_operational_audit;CREATE TRIGGER watchlist_operational_audit_immutable BEFORE UPDATE OR DELETE ON watchlist_operational_audit FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_idempotency_receipt_immutable ON screening_idempotency_receipt;CREATE TRIGGER screening_idempotency_receipt_immutable BEFORE UPDATE OR DELETE ON screening_idempotency_receipt FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_ledger_replication_immutable ON screening_ledger_replication;CREATE TRIGGER screening_ledger_replication_immutable BEFORE UPDATE OR DELETE ON screening_ledger_replication FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone;CREATE TRIGGER screening_ledger_retention_tombstone_immutable BEFORE UPDATE OR DELETE ON screening_ledger_retention_tombstone FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
CREATE OR REPLACE FUNCTION screening_ledger_snapshot_guard()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP='DELETE'THEN RAISE EXCEPTION 'screening snapshots cannot be deleted';END IF;IF OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL AND OLD.snapshot_sha256=NEW.snapshot_sha256 AND OLD.kind=NEW.kind AND OLD.created_at=NEW.created_at AND OLD.expires_at=NEW.expires_at AND OLD.retention_class=NEW.retention_class AND NOT(NEW.envelope_json?'ciphertext_base64')THEN RETURN NEW;END IF;RAISE EXCEPTION 'screening snapshot mutation is not an allowed retention transition';END $$;
DROP TRIGGER IF EXISTS screening_ledger_snapshot_guard_trigger ON screening_ledger_snapshot;CREATE TRIGGER screening_ledger_snapshot_guard_trigger BEFORE UPDATE OR DELETE ON screening_ledger_snapshot FOR EACH ROW EXECUTE FUNCTION screening_ledger_snapshot_guard();
CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz,p_operator text,p_reason text)RETURNS bigint LANGUAGE plpgsql AS $$ DECLARE affected bigint;BEGIN INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason)SELECT snapshot_sha256,clock_timestamp(),p_operator,p_reason FROM screening_ledger_snapshot WHERE expires_at<p_before AND purged_at IS NULL ON CONFLICT(snapshot_sha256)DO NOTHING;UPDATE screening_ledger_snapshot SET purged_at=clock_timestamp(),purge_reason=p_reason,envelope_json=(envelope_json-'nonce_base64'-'ciphertext_base64')||jsonb_build_object('purged_at',clock_timestamp(),'purge_reason',p_reason)WHERE expires_at<p_before AND purged_at IS NULL;GET DIAGNOSTICS affected=ROW_COUNT;RETURN affected;END $$;
-- REL-9-adjacent (found implementing SEC-7 Stage 2, ADR-0007 D3): Migrate
-- is a live, independently-executed bootstrap path that db/migrations/
-- never has to run before it, so it must carry its own TRUNCATE guard
-- rather than relying on db/migrations/012_truncate_guards.sql, which a
-- database provisioned through this path alone would never see. Same
-- function name and body as 012 uses, so the two sources cannot diverge
-- on behavior when both happen to run against the same database.
CREATE OR REPLACE FUNCTION owl_reject_truncate()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'relation % is append-only; TRUNCATE is prohibited', TG_TABLE_NAME;END $$;
DROP TRIGGER IF EXISTS screening_ledger_event_no_truncate ON screening_ledger_event;CREATE TRIGGER screening_ledger_event_no_truncate BEFORE TRUNCATE ON screening_ledger_event FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_snapshot_no_truncate ON screening_ledger_snapshot;CREATE TRIGGER screening_ledger_snapshot_no_truncate BEFORE TRUNCATE ON screening_ledger_snapshot FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_replication_no_truncate ON screening_ledger_replication;CREATE TRIGGER screening_ledger_replication_no_truncate BEFORE TRUNCATE ON screening_ledger_replication FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_idempotency_receipt_no_truncate ON screening_idempotency_receipt;CREATE TRIGGER screening_idempotency_receipt_no_truncate BEFORE TRUNCATE ON screening_idempotency_receipt FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_retention_tombstone_no_truncate ON screening_ledger_retention_tombstone;CREATE TRIGGER screening_ledger_retention_tombstone_no_truncate BEFORE TRUNCATE ON screening_ledger_retention_tombstone FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS watchlist_operational_audit_no_truncate ON watchlist_operational_audit;CREATE TRIGGER watchlist_operational_audit_no_truncate BEFORE TRUNCATE ON watchlist_operational_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_audit_no_truncate ON screening_ledger_audit;CREATE TRIGGER screening_ledger_audit_no_truncate BEFORE TRUNCATE ON screening_ledger_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
COMMIT;
`
