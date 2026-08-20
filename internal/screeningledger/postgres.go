package screeningledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
//
// ADR-0007 Addendum 2 D21 (F-E, CRITICAL): SchemaSQL executing without
// error is not the same fact as the schema having actually reached the
// state Migrate() is about to report as success -- the anchor table's own
// guard below (DO $$ ... IF to_regclass('screening_ledger_anchor') IS
// NULL) deliberately skips re-touching an already-existing table, which
// is correct once db/migrations/017 has run and wrong if it has not. This
// asserts the postcondition by querying the live catalog rather than
// trusting "no error" -- see checkRequiredSchemaObjects.
func (p *PostgresSink) Migrate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if _, err := p.conn.PgConn().Exec(ctx, SchemaSQL).ReadAll(); err != nil {
		return err
	}
	if err := p.checkRequiredSchemaObjects(ctx); err != nil {
		return err
	}
	return p.checkPurgeSnapshotsDefiner(ctx)
}

// requiredDefinerFunction is D21's general form applied to D27's two
// screening_ledger_purge_snapshots overloads: SchemaSQL's tombstone block
// (like the anchor block) skips re-touching these functions once they
// already exist, so Migrate() must confirm, by querying the live
// catalog, that whichever one actually got created is SECURITY DEFINER --
// not assume it because SchemaSQL executed without error.
type requiredDefinerFunction struct {
	name         string
	identityArgs string
	installedBy  string
}

var requiredDefinerFunctions = []requiredDefinerFunction{
	{
		name: "screening_ledger_purge_snapshots", identityArgs: "timestamptz,text,text",
		installedBy: "db/migrations/019_screening_ledger_purge_definer.sql",
	},
	{
		name: "screening_ledger_purge_snapshots", identityArgs: "text[],timestamptz,text,text",
		installedBy: "db/migrations/019_screening_ledger_purge_definer.sql",
	},
}

// checkPurgeSnapshotsDefiner is ADR-0007 Addendum 2 D27's postcondition:
// both screening_ledger_purge_snapshots overloads must exist and be
// SECURITY DEFINER (prosecdef). It deliberately does not check ownership
// -- the same "reported, not enforced" decision D21 point 3 made for the
// anchor table -- since a SchemaSQL-only bootstrap legitimately leaves
// these owned by owl_migrator, not owl_ledger_ddl.
func (p *PostgresSink) checkPurgeSnapshotsDefiner(ctx context.Context) error {
	for _, fn := range requiredDefinerFunctions {
		signature := fn.name + "(" + fn.identityArgs + ")"
		var definer bool
		if err := p.conn.QueryRow(ctx, `SELECT prosecdef FROM pg_proc WHERE oid = $1::regprocedure`, signature).Scan(&definer); err != nil {
			return fmt.Errorf("schema incomplete (ADR-0007 Addendum 2 D27): function %s does not exist (installed by %s): %w", signature, fn.installedBy, err)
		}
		if !definer {
			return fmt.Errorf("schema incomplete (ADR-0007 Addendum 2 D27): function %s exists but is not SECURITY DEFINER (installed by %s)", signature, fn.installedBy)
		}
	}
	return nil
}

// requiredSchemaObject is one relation Migrate() must confirm actually
// reached its claimed state: the table itself, its row-immutability
// trigger, its TRUNCATE-guard trigger, and any columns added after the
// table's original CREATE TABLE. Written out literally -- not derived by
// scanning SchemaSQL or by a naming-pattern guess -- per CLAUDE.md's
// "never enumerate targets by inference": a silently omitted table is an
// invisible security hole, and that applies to a generated list as much
// as a hand-picked one. This is the same eight-table set
// postgres_schema_test.go's protectedTables already lists;
// TestRequiredSchemaObjectsMatchProtectedTables keeps the two from
// drifting apart.
type requiredSchemaObject struct {
	table                 string
	tableInstalledBy      string
	immutableTrigger      string
	immutableInstalledBy  string
	noTruncateTrigger     string
	noTruncateInstalledBy string
	requiredColumns       []requiredColumn
}

type requiredColumn struct {
	name        string
	installedBy string
}

var requiredSchemaObjects = []requiredSchemaObject{
	{
		table: "screening_ledger_event", tableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		immutableTrigger: "screening_ledger_event_immutable", immutableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		noTruncateTrigger: "screening_ledger_event_no_truncate", noTruncateInstalledBy: "db/migrations/012_truncate_guards.sql",
	},
	{
		// The row-immutability control on this table is
		// screening_ledger_snapshot_guard_trigger (a retention-aware
		// guard, not the plain reject-mutation function every other
		// table uses) -- named literally here rather than assumed to
		// follow the "<table>_immutable" pattern the other seven do.
		table: "screening_ledger_snapshot", tableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		immutableTrigger: "screening_ledger_snapshot_guard_trigger", immutableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		noTruncateTrigger: "screening_ledger_snapshot_no_truncate", noTruncateInstalledBy: "db/migrations/012_truncate_guards.sql",
	},
	{
		table: "screening_ledger_replication", tableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		immutableTrigger: "screening_ledger_replication_immutable", immutableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		noTruncateTrigger: "screening_ledger_replication_no_truncate", noTruncateInstalledBy: "db/migrations/012_truncate_guards.sql",
	},
	{
		table: "screening_idempotency_receipt", tableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		immutableTrigger: "screening_idempotency_receipt_immutable", immutableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		noTruncateTrigger: "screening_idempotency_receipt_no_truncate", noTruncateInstalledBy: "db/migrations/012_truncate_guards.sql",
	},
	{
		table: "screening_ledger_retention_tombstone", tableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		immutableTrigger: "screening_ledger_retention_tombstone_immutable", immutableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		noTruncateTrigger: "screening_ledger_retention_tombstone_no_truncate", noTruncateInstalledBy: "db/migrations/012_truncate_guards.sql",
	},
	{
		table: "watchlist_operational_audit", tableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		immutableTrigger: "watchlist_operational_audit_immutable", immutableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		noTruncateTrigger: "watchlist_operational_audit_no_truncate", noTruncateInstalledBy: "db/migrations/012_truncate_guards.sql",
	},
	{
		table: "screening_ledger_audit", tableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		immutableTrigger: "screening_ledger_audit_immutable", immutableInstalledBy: "db/migrations/008g_screening_ledger.sql",
		noTruncateTrigger: "screening_ledger_audit_no_truncate", noTruncateInstalledBy: "db/migrations/012_truncate_guards.sql",
	},
	{
		// ADR-0007 Addendum 2 F-E: this is the object whose staleness the
		// bug was found on. Table and TRUNCATE guard come from 015;
		// row-immutability trigger and both extra columns come from 017,
		// which is exactly the migration a partially-migrated deployment
		// can be missing.
		table: "screening_ledger_anchor", tableInstalledBy: "db/migrations/015_screening_ledger_anchor.sql",
		immutableTrigger: "screening_ledger_anchor_immutable", immutableInstalledBy: "db/migrations/017_screening_ledger_anchor_policy_binding.sql",
		noTruncateTrigger: "screening_ledger_anchor_no_truncate", noTruncateInstalledBy: "db/migrations/015_screening_ledger_anchor.sql",
		requiredColumns: []requiredColumn{
			{name: "audit_sequence", installedBy: "db/migrations/017_screening_ledger_anchor_policy_binding.sql"},
			{name: "policy_sha256", installedBy: "db/migrations/017_screening_ledger_anchor_policy_binding.sql"},
		},
	},
}

// checkRequiredSchemaObjects is ADR-0007 Addendum 2 D21's postcondition
// query: one relation/trigger/column existence check per
// requiredSchemaObjects entry, run against the live catalog (pg_class via
// to_regclass, pg_trigger, pg_attribute) rather than asserted from
// SchemaSQL's own text. A missing object produces a named error
// identifying which object is absent and which migration installs it --
// never a generic "schema incomplete."
//
// Deliberately does not check ownership. A SchemaSQL-only bootstrap
// legitimately leaves these tables owned by owl_migrator; a fully
// provisioned deployment has screening_ledger_anchor (and, after D27,
// screening_ledger_retention_tombstone) owned by owl_ledger_ddl. Both are
// valid states -- ownership is reported by SchemaObjectOwner for a caller
// that wants to distinguish them, not asserted here.
func (p *PostgresSink) checkRequiredSchemaObjects(ctx context.Context) error {
	for _, obj := range requiredSchemaObjects {
		exists, err := p.regclassExists(ctx, obj.table)
		if err != nil {
			return fmt.Errorf("ADR-0007 D21: checking relation %s: %w", obj.table, err)
		}
		if !exists {
			return fmt.Errorf("schema incomplete (ADR-0007 D21): relation %s does not exist (installed by %s)", obj.table, obj.tableInstalledBy)
		}
		immutableOK, err := p.triggerExists(ctx, obj.table, obj.immutableTrigger)
		if err != nil {
			return fmt.Errorf("ADR-0007 D21: checking trigger %s on %s: %w", obj.immutableTrigger, obj.table, err)
		}
		if !immutableOK {
			return fmt.Errorf("schema incomplete (ADR-0007 D21): %s is missing its row-immutability trigger %s (installed by %s) -- Migrate() will not report success on a table whose protections are not actually present", obj.table, obj.immutableTrigger, obj.immutableInstalledBy)
		}
		noTruncateOK, err := p.triggerExists(ctx, obj.table, obj.noTruncateTrigger)
		if err != nil {
			return fmt.Errorf("ADR-0007 D21: checking trigger %s on %s: %w", obj.noTruncateTrigger, obj.table, err)
		}
		if !noTruncateOK {
			return fmt.Errorf("schema incomplete (ADR-0007 D21): %s is missing its TRUNCATE-guard trigger %s (installed by %s)", obj.table, obj.noTruncateTrigger, obj.noTruncateInstalledBy)
		}
		for _, col := range obj.requiredColumns {
			colOK, err := p.columnExists(ctx, obj.table, col.name)
			if err != nil {
				return fmt.Errorf("ADR-0007 D21: checking column %s on %s: %w", col.name, obj.table, err)
			}
			if !colOK {
				return fmt.Errorf("schema incomplete (ADR-0007 D21): %s is missing column %s (installed by %s)", obj.table, col.name, col.installedBy)
			}
		}
	}
	return nil
}

func (p *PostgresSink) regclassExists(ctx context.Context, table string) (bool, error) {
	var exists bool
	err := p.conn.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists)
	return exists, err
}

func (p *PostgresSink) triggerExists(ctx context.Context, table, trigger string) (bool, error) {
	var exists bool
	err := p.conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname=$1 AND tgrelid=$2::regclass AND NOT tgisinternal)`,
		trigger, table,
	).Scan(&exists)
	return exists, err
}

func (p *PostgresSink) columnExists(ctx context.Context, table, column string) (bool, error) {
	var exists bool
	err := p.conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=$1::regclass AND attname=$2 AND NOT attisdropped)`,
		table, column,
	).Scan(&exists)
	return exists, err
}

// SchemaObjectOwner reports table's current owner -- ADR-0007 Addendum 2
// D21 point 3: ownership is reported, not enforced by
// checkRequiredSchemaObjects, since a SchemaSQL-only bootstrap
// (owl_migrator) and a fully-provisioned deployment (owl_ledger_ddl, for
// screening_ledger_anchor) are both valid states. This is the hook D27's
// tombstone-table ownership move depends on: a caller that needs to know
// whether ownership has already moved (and therefore whether SchemaSQL's
// own DDL against that table would even succeed) reads it here rather
// than inferring it from a failed statement.
func (p *PostgresSink) SchemaObjectOwner(ctx context.Context, table string) (string, error) {
	var owner string
	err := p.conn.QueryRow(ctx, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=$1::regclass`, table).Scan(&owner)
	return owner, err
}

// ReplicationVerification is ADR-0007 D19: verified_at/verification_mode
// on screening_ledger_replication, written in the same transaction as
// the replication row they describe. The immutability trigger on that
// table (postgres.go's SchemaSQL) means a row mirrored without recording
// this can never afterwards be corrected, annotated or removed by the
// identity that wrote it -- so it must be recorded at write time or it
// is unrecordable.
type ReplicationVerification struct {
	VerifiedAt string
	Mode       VerificationMode
}

func (p *PostgresSink) Persist(ctx context.Context, event Event, request, response SnapshotEnvelope, verification ReplicationVerification) error {
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
		`INSERT INTO screening_ledger_replication(event_id,replicated_at,verified_at,verification_mode) VALUES ($1,clock_timestamp(),$2::timestamptz,$3) ON CONFLICT (event_id) DO NOTHING`,
		event.EventID, nullableText(verification.VerifiedAt), nullableText(string(verification.Mode)),
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

// LatestAnchor reads the highest-sequence row of screening_ledger_anchor
// for ledgerID, over this sink's own connection -- i.e. as owl_migrator,
// which Stage 3 grants SELECT (only) on that table
// (scripts/ci/provision_test_roles.sh's grant-anchor-ownership step).
// This is deliberately not a method on AnchorSink: AnchorSink connects as
// owl_ledger_anchor, the write-only identity, and reusing its connection
// for reads would blur the privilege boundary D3 exists to draw (see
// anchor.go's package comment). ok is false with a nil error when the
// ledger has no anchor row yet -- an unanchored ledger is a valid state
// (e.g. before genesis), not an error.
func (p *PostgresSink) LatestAnchor(ctx context.Context, ledgerID string) (anchor Anchor, ok bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	var sequence, auditSequence int64
	var eventSHA, auditSHA, policySHA256, mac string
	var anchoredAt time.Time
	row := p.conn.QueryRow(ctx,
		`SELECT sequence, event_sha256, audit_sha256, audit_sequence, policy_sha256, anchored_at, anchor_mac
		 FROM screening_ledger_anchor WHERE ledger_id=$1 ORDER BY sequence DESC LIMIT 1`,
		ledgerID)
	if err := row.Scan(&sequence, &eventSHA, &auditSHA, &auditSequence, &policySHA256, &anchoredAt, &mac); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Anchor{}, false, nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "42P01":
				// ADR-0007 Addendum 1 F3: a database bootstrapped through
				// Migrate alone never created screening_ledger_anchor
				// before D15. That used to surface here as a raw
				// undefined-relation error, accidentally fail-closed
				// (LatestAnchor's caller sees a non-nil error and treats
				// it as a plumbing failure) but not deliberately so --
				// named explicitly here per D15's requirement.
				return Anchor{}, false, fmt.Errorf("screening_ledger_anchor does not exist -- this database's schema is missing the SEC-7 anchor table (ADR-0007 F3): %w", err)
			case "42703":
				// ADR-0007 Addendum 2 D22 (F-E's second half): the table
				// exists but lacks audit_sequence/policy_sha256 -- 017 has
				// not run. This is D21's diagnostic backstop for a
				// database that reached this state some other way than
				// Migrate() (a partially applied db/migrations/ run, a
				// restore from an older dump): D21 prevents the state
				// being reached through Migrate() itself; this names it
				// when a caller reaches it anyway, rather than surfacing
				// as unnamed plumbing the way it did before this fix.
				return Anchor{}, false, fmt.Errorf("screening_ledger_anchor exists but is missing a column db/migrations/017_screening_ledger_anchor_policy_binding.sql adds (audit_sequence or policy_sha256) -- this database's schema is incomplete (ADR-0007 Addendum 2 F-E/D22): %w", err)
			}
		}
		return Anchor{}, false, err
	}
	return Anchor{LedgerID: ledgerID, Sequence: sequence, EventSHA256: eventSHA, AuditSHA256: auditSHA, AuditSequence: auditSequence, PolicySHA256: policySHA256, AnchoredAt: anchoredAt, AnchorMAC: mac}, true, nil
}

// IsPurgeRecorded implements PurgeChecker (ADR-0007 D13/F8): whether an
// independent tombstone exists for a snapshot the caller found marked
// purged in its own envelope, rather than trusting that self-reported
// field. screening_ledger_retention_tombstone is written server-side by
// screening_ledger_purge_snapshots, not by the envelope being checked.
func (p *PostgresSink) IsPurgeRecorded(ctx context.Context, snapshotSHA256 string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	var exists bool
	err := p.conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM screening_ledger_retention_tombstone WHERE snapshot_sha256=$1)`,
		snapshotSHA256,
	).Scan(&exists)
	return exists, err
}

// PurgeExpired calls the time-floor overload of screening_ledger_purge_
// snapshots directly -- a standalone, direct-database retention sweep
// ("purge everything expired as of before") independent of any local
// ledger directory or its legal holds. Distinct from RecordPurge (D28),
// which cmd/screening-ledger's purge command actually uses: that form
// takes the caller's already holds-filtered candidate set and lets the
// server re-check the expiry floor against exactly those snapshots.
// PurgeExpired's own predicate (SECURITY DEFINER since 019) is unchanged
// from 008g's version. See PersistAudit's doc comment for the
// bare-statement hazard this method also avoids.
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

// RecordPurge implements PurgeRecorder (ADR-0007 Addendum 2 D27/D28): the
// local-narrows/server-floors purge path. eligibleSHA256 is the set
// Store.PurgeExpired's local pass already determined eligible under this
// ledger's legal-holds rule (holds/, which this call does not and should
// not learn about); the array-form overload of screening_ledger_purge_
// snapshots re-validates every one of them against expires_at
// server-side and records only what is actually expired, regardless of
// what the caller claims. The caller may then mark purged, locally, only
// the snapshots this call reports as recorded.
func (p *PostgresSink) RecordPurge(ctx context.Context, eligibleSHA256 []string, before time.Time, operator, reason string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	tx, err := p.conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var recorded []string
	if err := tx.QueryRow(ctx,
		`SELECT screening_ledger_purge_snapshots($1::text[],$2::timestamptz,$3,$4)`,
		eligibleSHA256, before, operator, reason,
	).Scan(&recorded); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return recorded, nil
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
CREATE TABLE IF NOT EXISTS screening_ledger_replication (event_id text PRIMARY KEY REFERENCES screening_ledger_event(event_id),replicated_at timestamptz NOT NULL,verified_at timestamptz,verification_mode text);
CREATE TABLE IF NOT EXISTS screening_idempotency_receipt (scope text NOT NULL,idempotency_key_sha256 text NOT NULL,request_sha256 text NOT NULL,response_sha256 text NOT NULL,http_status integer NOT NULL,event_id text NOT NULL REFERENCES screening_ledger_event(event_id),inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(scope,idempotency_key_sha256));
CREATE TABLE IF NOT EXISTS watchlist_operational_audit(source text NOT NULL,stream_id text NOT NULL,sequence bigint NOT NULL,event_sha256 text NOT NULL,previous_event_sha256 text NOT NULL,occurred_at timestamptz NOT NULL,action text NOT NULL,payload_json jsonb NOT NULL,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(source,event_sha256),UNIQUE(source,stream_id,sequence));
CREATE TABLE IF NOT EXISTS screening_ledger_audit(ledger_id text NOT NULL,sequence bigint NOT NULL,audit_sha256 text PRIMARY KEY,previous_audit_sha256 text NOT NULL,occurred_at timestamptz NOT NULL,action text NOT NULL,event_id text,audit_json jsonb NOT NULL,inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(ledger_id,sequence));
CREATE OR REPLACE FUNCTION screening_ledger_reject_mutation()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'screening ledger rows are append-only';END $$;
DROP TRIGGER IF EXISTS screening_ledger_event_immutable ON screening_ledger_event;CREATE TRIGGER screening_ledger_event_immutable BEFORE UPDATE OR DELETE ON screening_ledger_event FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_ledger_audit_immutable ON screening_ledger_audit;CREATE TRIGGER screening_ledger_audit_immutable BEFORE UPDATE OR DELETE ON screening_ledger_audit FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS watchlist_operational_audit_immutable ON watchlist_operational_audit;CREATE TRIGGER watchlist_operational_audit_immutable BEFORE UPDATE OR DELETE ON watchlist_operational_audit FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_idempotency_receipt_immutable ON screening_idempotency_receipt;CREATE TRIGGER screening_idempotency_receipt_immutable BEFORE UPDATE OR DELETE ON screening_idempotency_receipt FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
DROP TRIGGER IF EXISTS screening_ledger_replication_immutable ON screening_ledger_replication;CREATE TRIGGER screening_ledger_replication_immutable BEFORE UPDATE OR DELETE ON screening_ledger_replication FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation();
CREATE OR REPLACE FUNCTION screening_ledger_snapshot_guard()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP='DELETE'THEN RAISE EXCEPTION 'screening snapshots cannot be deleted';END IF;IF OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL AND OLD.snapshot_sha256=NEW.snapshot_sha256 AND OLD.kind=NEW.kind AND OLD.created_at=NEW.created_at AND OLD.expires_at=NEW.expires_at AND OLD.retention_class=NEW.retention_class AND NOT(NEW.envelope_json?'ciphertext_base64')THEN RETURN NEW;END IF;RAISE EXCEPTION 'screening snapshot mutation is not an allowed retention transition';END $$;
DROP TRIGGER IF EXISTS screening_ledger_snapshot_guard_trigger ON screening_ledger_snapshot;CREATE TRIGGER screening_ledger_snapshot_guard_trigger BEFORE UPDATE OR DELETE ON screening_ledger_snapshot FOR EACH ROW EXECUTE FUNCTION screening_ledger_snapshot_guard();
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
DROP TRIGGER IF EXISTS watchlist_operational_audit_no_truncate ON watchlist_operational_audit;CREATE TRIGGER watchlist_operational_audit_no_truncate BEFORE TRUNCATE ON watchlist_operational_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
DROP TRIGGER IF EXISTS screening_ledger_audit_no_truncate ON screening_ledger_audit;CREATE TRIGGER screening_ledger_audit_no_truncate BEFORE TRUNCATE ON screening_ledger_audit FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();
-- ADR-0007 Addendum 1 D15/F3: SchemaSQL independently bootstraps this
-- schema with no dependency on db/migrations/ ever having run (same
-- REL-9-adjacent shape as the six tables above), and until this stage
-- never created screening_ledger_anchor at all -- a database provisioned
-- through Migrate() alone had zero anchor protection, silently. This
-- brings SchemaSQL to parity with db/migrations/015 and 017: the table,
-- its row-immutability trigger (D16), and its TRUNCATE guard.
--
-- Guarded on to_regclass(...) IS NULL, unlike the six tables above,
-- because this table's ownership -- unlike theirs -- moves away from
-- owl_migrator once scripts/ci/provision_test_roles.sh's
-- grant-anchor-ownership step runs (D17/F6: to owl_ledger_ddl, so the
-- runtime writer owl_ledger_anchor cannot alter or drop its own
-- protections). Migrate() runs as owl_migrator on every CLI invocation
-- (migrate, sync, import-audit), including every one after that
-- ownership transfer -- DROP/CREATE TRIGGER on a table owl_migrator no
-- longer owns would fail outright (discovered running the pgx suite
-- against a fully-provisioned database, not assumed). This is not the
-- fail-open "IF ... IS NOT NULL" shape CLAUDE.md warns against (which
-- skips a control when its target is ABSENT): this skips re-touching a
-- table only once it already exists, i.e. once its protections are
-- already in place -- created here on true first bootstrap, or by
-- db/migrations/015 and 017 otherwise -- and only because Postgres
-- permissions would refuse the attempt regardless once ownership has
-- moved on.
DO $$
BEGIN
  IF to_regclass('screening_ledger_anchor') IS NULL THEN
    EXECUTE 'CREATE TABLE screening_ledger_anchor (ledger_id text NOT NULL,sequence bigint NOT NULL,event_sha256 text NOT NULL,audit_sha256 text NOT NULL,audit_sequence bigint NOT NULL,policy_sha256 text NOT NULL,anchored_at timestamptz NOT NULL DEFAULT clock_timestamp(),anchor_mac text NOT NULL,PRIMARY KEY (ledger_id,sequence))';
    EXECUTE 'CREATE TRIGGER screening_ledger_anchor_immutable BEFORE UPDATE OR DELETE ON screening_ledger_anchor FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation()';
    EXECUTE 'CREATE TRIGGER screening_ledger_anchor_no_truncate BEFORE TRUNCATE ON screening_ledger_anchor FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate()';
  END IF;
END $$;
-- ADR-0007 Addendum 2 D27 (F-D): screening_ledger_retention_tombstone and
-- both screening_ledger_purge_snapshots overloads move to owl_ledger_ddl
-- ownership (scripts/ci/provision_test_roles.sh's grant-ddl-ownership),
-- so this table -- like screening_ledger_anchor above, for exactly the
-- same reason -- must move out of the unconditional CREATE TABLE/CREATE
-- TRIGGER blocks above: a DROP TRIGGER/CREATE TRIGGER or CREATE OR
-- REPLACE FUNCTION statement against an object owl_migrator no longer
-- owns would fail outright, reproducing F-E on a second object (D27's
-- own stated reasoning). Guarded on to_regclass(...) IS NULL, same as
-- the anchor block: skips re-touching this table only once it already
-- exists, relying on Migrate()'s checkRequiredSchemaObjects (D21) and
-- checkPurgeSnapshotsDefiner (D27) postcondition checks to verify the
-- final state actually holds rather than assuming it does.
--
-- The function bodies are dollar-quoted with distinct tags ($func$
-- nested inside $exec$, nested inside the DO block's own bare $$) since
-- EXECUTE is required for DDL inside PL/pgSQL and the function bodies
-- themselves contain single-quoted literals ('nonce_base64' etc.) that
-- would otherwise terminate a plain '...'-quoted EXECUTE string early.
DO $$
BEGIN
  IF to_regclass('screening_ledger_retention_tombstone') IS NULL THEN
    EXECUTE 'CREATE TABLE screening_ledger_retention_tombstone(snapshot_sha256 text PRIMARY KEY,purged_at timestamptz NOT NULL,operator text NOT NULL,reason text NOT NULL)';
    EXECUTE 'CREATE TRIGGER screening_ledger_retention_tombstone_immutable BEFORE UPDATE OR DELETE ON screening_ledger_retention_tombstone FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation()';
    EXECUTE 'CREATE TRIGGER screening_ledger_retention_tombstone_no_truncate BEFORE TRUNCATE ON screening_ledger_retention_tombstone FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate()';
    EXECUTE $exec$CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz,p_operator text,p_reason text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $func$ DECLARE affected bigint; BEGIN INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT snapshot_sha256,clock_timestamp(),p_operator,p_reason FROM screening_ledger_snapshot WHERE expires_at<p_before AND purged_at IS NULL ON CONFLICT(snapshot_sha256) DO NOTHING; UPDATE screening_ledger_snapshot SET purged_at=clock_timestamp(),purge_reason=p_reason,envelope_json=(envelope_json-'nonce_base64'-'ciphertext_base64')||jsonb_build_object('purged_at',clock_timestamp(),'purge_reason',p_reason) WHERE expires_at<p_before AND purged_at IS NULL; GET DIAGNOSTICS affected=ROW_COUNT; RETURN affected; END $func$ $exec$;
    EXECUTE $exec$CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[],p_before timestamptz,p_operator text,p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $func$ DECLARE recorded text[]; BEGIN WITH eligible AS (SELECT snapshot_sha256 FROM screening_ledger_snapshot WHERE snapshot_sha256=ANY(p_snapshot_sha256) AND expires_at<p_before AND purged_at IS NULL), inserted AS (INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT snapshot_sha256,clock_timestamp(),p_operator,p_reason FROM eligible ON CONFLICT(snapshot_sha256) DO NOTHING), updated AS (UPDATE screening_ledger_snapshot SET purged_at=clock_timestamp(),purge_reason=p_reason,envelope_json=(envelope_json-'nonce_base64'-'ciphertext_base64')||jsonb_build_object('purged_at',clock_timestamp(),'purge_reason',p_reason) WHERE snapshot_sha256 IN (SELECT snapshot_sha256 FROM eligible) RETURNING snapshot_sha256) SELECT array_agg(snapshot_sha256) INTO recorded FROM updated; RETURN COALESCE(recorded,ARRAY[]::text[]); END $func$ $exec$;
  END IF;
END $$;
COMMIT;
`
