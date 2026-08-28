package screeningledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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

// requiredEventTriggers is ADR-0007 Addendum 3 D33/D34: both DDL event
// triggers scripts/ci/provision_test_roles.sh grant-ddl-ownership
// installs, by name -- must exist and be ENABLE ALWAYS ('A'). This
// enumerates protected FACTS (which schema objects count as complete),
// which D31's principle permits; it is not an enumeration of expected
// actions.
var requiredEventTriggers = []string{
	"sec7_protect_ddl_objects_on_drop",
	"sec7_protect_ddl_objects_on_alter",
}

// requiredDDLOwnedTables is ADR-0007 Addendum 3 D33: relations that must
// be owned by owl_ledger_ddl once provisioning has actually run.
var requiredDDLOwnedTables = []string{
	"screening_ledger_anchor",
	"screening_ledger_retention_tombstone",
}

// ProvisioningState is ADR-0007 Addendum 3 D33: whether
// scripts/ci/provision_test_roles.sh grant-ddl-ownership has actually run
// against this database -- the second completion condition
// checkRequiredSchemaObjects does not and must not prove (D21 point 3:
// ownership is reported, not enforced, by the schema check, since a
// SchemaSQL-only bootstrap legitimately leaves it false). CAP #2 built a
// database with all migrations applied and provisioning skipped (owl_p4)
// and found nothing anywhere observed the difference. Migrate() reports
// this (does not fail on it); VerifyAnchored requires it whenever a
// database is supplied.
type ProvisioningState struct {
	Provisioned bool
	// Reason names the first fact found false or absent -- specific
	// enough for an operator to act on, per D21's own diagnostic
	// standard. Empty when Provisioned is true.
	Reason string
}

// checkProvisioningState queries every fact D33 names, in the order
// stated there: both event triggers by name (evtenabled='A'), the anchor
// and tombstone tables' ownership, both purge_snapshots overloads'
// prosecdef AND owner (tightening checkPurgeSnapshotsDefiner's
// deliberately ownership-blind check for this different question), and
// the three has_table_privilege facts naming what the writer/owner
// separation must NOT confer. Every one of these is readable by
// owl_migrator with no new role, DSN or grant -- confirmed by execution
// during this addendum's design pass, not assumed.
func (p *PostgresSink) checkProvisioningState(ctx context.Context) (ProvisioningState, error) {
	for _, name := range requiredEventTriggers {
		var enabled string
		err := p.conn.QueryRow(ctx, `SELECT evtenabled FROM pg_event_trigger WHERE evtname=$1`, name).Scan(&enabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return ProvisioningState{Reason: fmt.Sprintf("DDL event trigger %s does not exist (ADR-0007 Addendum 3 D33/D34): scripts/ci/provision_test_roles.sh grant-ddl-ownership has not run", name)}, nil
		}
		if err != nil {
			return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 3 D33: checking event trigger %s: %w", name, err)
		}
		if enabled != "A" {
			return ProvisioningState{Reason: fmt.Sprintf("DDL event trigger %s exists but is not ENABLE ALWAYS (evtenabled=%q) (ADR-0007 Addendum 3 D33)", name, enabled)}, nil
		}
	}
	for _, table := range requiredDDLOwnedTables {
		owner, err := p.SchemaObjectOwner(ctx, table)
		if err != nil {
			return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 3 D33: checking owner of %s: %w", table, err)
		}
		if owner != "owl_ledger_ddl" {
			return ProvisioningState{Reason: fmt.Sprintf("%s is owned by %q, not owl_ledger_ddl (ADR-0007 Addendum 3 D33): grant-ddl-ownership has not transferred ownership", table, owner)}, nil
		}
	}
	for _, fn := range requiredDefinerFunctions {
		signature := fn.name + "(" + fn.identityArgs + ")"
		var definer bool
		var owner string
		if err := p.conn.QueryRow(ctx, `SELECT prosecdef, pg_get_userbyid(proowner) FROM pg_proc WHERE oid = $1::regprocedure`, signature).Scan(&definer, &owner); err != nil {
			return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 3 D33: checking function %s: %w", signature, err)
		}
		if !definer {
			return ProvisioningState{Reason: fmt.Sprintf("function %s is not SECURITY DEFINER (ADR-0007 Addendum 3 D33)", signature)}, nil
		}
		if owner != "owl_ledger_ddl" {
			return ProvisioningState{Reason: fmt.Sprintf("function %s is owned by %q, not owl_ledger_ddl (ADR-0007 Addendum 3 D33): grant-ddl-ownership has not transferred ownership", signature, owner)}, nil
		}
	}
	// ADR-0007 Addendum 7 D61: D39's three named-role probes (H-C) are
	// re-quantified over the live role population rather than one named
	// role apiece -- CAP #6 §11 point 1(b)'s question, asked of every
	// probe in this file. A grantable table privilege can move to any
	// role the owner chooses (K-A's whole point), so "owl_migrator lacks
	// X" is the wrong shape even when it happens to be true; the right
	// question is "the complete set of roles holding X is the declared
	// one." This subsumes D39's column-granularity check entirely (no
	// second thing to keep in sync) and closes a coverage gap D39 never
	// had: a privilege *missing* from a role the design requires to have
	// it is now an equally named failure, not silently unchecked.
	if reason, err := p.tablePrivilegeHoldersReason(ctx); err != nil {
		return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 7 D61: checking table privilege holders: %w", err)
	} else if reason != "" {
		return ProvisioningState{Reason: reason}, nil
	}
	// ADR-0007 Addendum 7 D60: MAINTAIN on either protected table must be
	// held by no non-superuser role in the live population, not merely
	// absent from owl_ledger_ddl by name (Addendum 6 D51's shape). An
	// owner may GRANT a table privilege to any role whether or not it
	// still holds that privilege itself -- K-A's exact attack, confirmed
	// by execution during this addendum's design pass: GRANT MAINTAIN ...
	// TO owl_migrator leaves this check (previously scoped to
	// owl_ledger_ddl alone) reading Provisioned=true, while owl_migrator
	// -- inside the adversary set -- can now cancel a REINDEX ...
	// CONCURRENTLY and wedge the database. This converts an unobserved
	// capability transfer into an observed one; it does not prevent the
	// transfer (R27), and must not be cited as doing so.
	if reason, err := p.maintainHoldersReason(ctx); err != nil {
		return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 7 D60: checking MAINTAIN holders: %w", err)
	} else if reason != "" {
		return ProvisioningState{Reason: reason}, nil
	}
	// ADR-0007 Addendum 4 D41: sec7_protected_object's identity, asserted
	// against requiredProtectedObjects rather than the registry's own
	// `note` column. R15 claimed "every registry row's OID resolves to
	// THE OBJECT IT CLAIMS" -- the shipped three-way NOT EXISTS only ever
	// asserted "resolves to SOME object in one of three catalogs," which
	// passes for a row repointed to a different existing object of the
	// same or a different catalog, and passes vacuously on an emptied
	// registry (D34 then inert for every object). This closes both:
	// every required (classid, identity) pair must be present, resolved
	// via pg_identify_object rather than compared to the unchecked prose
	// note, and the registry must contain EXACTLY that set -- no more,
	// no fewer, so an emptied, truncated, or padded registry is each its
	// own named failure rather than a silent pass.
	if reason, err := p.protectedObjectIdentityReason(ctx); err != nil {
		return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 4 D41: checking sec7_protected_object identity/population: %w", err)
	} else if reason != "" {
		return ProvisioningState{Reason: reason}, nil
	}
	// ADR-0007 Addendum 4 D41: sec7_protected_relation (D40) gets the
	// same treatment -- a second registry inherits the first one's
	// failure mode exactly (R19).
	if reason, err := p.protectedRelationIdentityReason(ctx); err != nil {
		return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 4 D41: checking sec7_protected_relation identity/population: %w", err)
	} else if reason != "" {
		return ProvisioningState{Reason: reason}, nil
	}
	// ADR-0007 Addendum 5 D47: sec7_protected_relation's seven recorded
	// STATE columns -- everything besides objid -- get a referent of
	// their own. Runs only once identity/population has already passed
	// above, so every row this compares against is known to resolve to
	// the relation it claims.
	if reason, err := p.protectedRelationStateReason(ctx); err != nil {
		return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 5 D47: checking sec7_protected_relation recorded state: %w", err)
	} else if reason != "" {
		return ProvisioningState{Reason: reason}, nil
	}
	// ADR-0007 Addendum 4 D41 part three: the two CREATE privilege facts
	// H-F's shipped-configuration rating depended on (CAP #3 §7.4) but
	// which nothing asserted -- defence in depth behind D40, not the fix
	// for H-F (D40 does not depend on this coincidence; this asserts the
	// coincidence anyway, so a later change cannot remove D40 on the
	// strength of this alone, or vice versa).
	var ddlHasSchemaCreate, ddlHasDatabaseCreate bool
	if err := p.conn.QueryRow(ctx, `SELECT has_schema_privilege('owl_ledger_ddl', 'public', 'CREATE')`).Scan(&ddlHasSchemaCreate); err != nil {
		return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 4 D41: checking owl_ledger_ddl schema CREATE privilege: %w", err)
	}
	if ddlHasSchemaCreate {
		return ProvisioningState{Reason: "owl_ledger_ddl holds CREATE on schema public (ADR-0007 Addendum 4 D41): defence in depth behind D40 is not holding"}, nil
	}
	if err := p.conn.QueryRow(ctx, `SELECT has_database_privilege('owl_ledger_ddl', current_database(), 'CREATE')`).Scan(&ddlHasDatabaseCreate); err != nil {
		return ProvisioningState{}, fmt.Errorf("ADR-0007 Addendum 4 D41: checking owl_ledger_ddl database CREATE privilege: %w", err)
	}
	if ddlHasDatabaseCreate {
		return ProvisioningState{Reason: "owl_ledger_ddl holds CREATE on the current database (ADR-0007 Addendum 4 D41): defence in depth behind D40 is not holding"}, nil
	}
	return ProvisioningState{Provisioned: true}, nil
}

// protectedObjectIdentity is one required (classid, identity) pair for
// sec7_protected_object, written out literally rather than derived by
// scanning scripts/ci/provision_test_roles.sh or by a naming-pattern
// guess -- CLAUDE.md's "never enumerate targets by inference" applies to
// a generated list as much as a hand-picked one. classid names the
// system catalog (cast via ::regclass::oid at query time); identity is
// exactly what pg_identify_object(classid, objid, 0) returns for that
// object today -- confirmed by execution against a live database, not
// guessed from documentation.
type protectedObjectIdentity struct {
	classid  string
	identity string
}

// requiredProtectedObjects is scripts/ci/provision_test_roles.sh
// grant-ddl-ownership's thirteen-row sec7_protected_object population,
// named here independently so the verifier and the installer are two
// separate assertions of the same fact rather than one trusting the
// other (D41: "the property is checked by the installer AND by the
// verifier, which is the only arrangement that survives the installer
// not having run").
var requiredProtectedObjects = []protectedObjectIdentity{
	{"pg_class", "public.screening_ledger_anchor"},
	{"pg_class", "public.screening_ledger_retention_tombstone"},
	{"pg_class", "public.sec7_protected_object"},
	{"pg_class", "public.sec7_protected_relation"},
	{"pg_trigger", "screening_ledger_anchor_immutable on public.screening_ledger_anchor"},
	{"pg_trigger", "screening_ledger_anchor_no_truncate on public.screening_ledger_anchor"},
	{"pg_trigger", "screening_ledger_retention_tombstone_immutable on public.screening_ledger_retention_tombstone"},
	{"pg_trigger", "screening_ledger_retention_tombstone_no_truncate on public.screening_ledger_retention_tombstone"},
	{"pg_proc", "public.screening_ledger_reject_mutation()"},
	{"pg_proc", "public.owl_reject_truncate()"},
	{"pg_proc", "public.screening_ledger_purge_snapshots(timestamp with time zone,pg_catalog.text,pg_catalog.text)"},
	{"pg_proc", "public.screening_ledger_purge_snapshots(pg_catalog.text[],timestamp with time zone,pg_catalog.text,pg_catalog.text)"},
	// ADR-0007 Addendum 5 D45: sec7_instance_binding, the copy-diagnosis
	// marker, is itself a protected object -- same reasoning as the two
	// registries above it (R15: a registry is a new trust object).
	{"pg_class", "public.sec7_instance_binding"},
}

// protectedObjectIdentityReason asserts sec7_protected_object contains
// exactly requiredProtectedObjects's thirteen (classid, identity) pairs --
// no more, no fewer -- resolved via pg_identify_object rather than the
// registry's own unchecked `note` column. Returns a non-empty Reason on
// the first fact found false; empty Reason and nil error when the
// registry matches exactly.
func (p *PostgresSink) protectedObjectIdentityReason(ctx context.Context) (string, error) {
	exists, err := p.regclassExists(ctx, "sec7_protected_object")
	if err != nil {
		return "", fmt.Errorf("checking sec7_protected_object: %w", err)
	}
	if !exists {
		return "sec7_protected_object does not exist (ADR-0007 Addendum 3 D33/D34): grant-ddl-ownership has not run", nil
	}
	var totalRows int
	if err := p.conn.QueryRow(ctx, `SELECT count(*) FROM sec7_protected_object`).Scan(&totalRows); err != nil {
		return "", fmt.Errorf("counting sec7_protected_object rows: %w", err)
	}
	if totalRows != len(requiredProtectedObjects) {
		return fmt.Sprintf("sec7_protected_object has %d row(s), expected exactly %d (ADR-0007 Addendum 4 D41): the registry is emptied, truncated, or padded", totalRows, len(requiredProtectedObjects)), nil
	}
	for _, want := range requiredProtectedObjects {
		var matches int
		err := p.conn.QueryRow(ctx, `
			SELECT count(*) FROM sec7_protected_object r
			WHERE r.classid = $1::regclass::oid
			  AND (pg_identify_object(r.classid, r.objid, 0)).identity = $2
		`, want.classid, want.identity).Scan(&matches)
		if err != nil {
			return "", fmt.Errorf("checking sec7_protected_object for %s %s: %w", want.classid, want.identity, err)
		}
		if matches != 1 {
			return fmt.Sprintf("sec7_protected_object has no row whose OID resolves (via pg_identify_object) to %s %s (ADR-0007 Addendum 4 D41): the registry is stale, repointed, or was never populated with this object", want.classid, want.identity), nil
		}
	}
	return "", nil
}

// requiredProtectedRelations is sec7_protected_relation's expected
// population (D40), asserted the same way requiredProtectedObjects is:
// a literal declaration, not derived from the table's own contents.
var requiredProtectedRelations = []string{
	"public.screening_ledger_anchor",
	"public.screening_ledger_retention_tombstone",
}

// protectedRelationIdentityReason mirrors protectedObjectIdentityReason
// for sec7_protected_relation: every row's objid is a pg_class OID by
// construction (the table's own PRIMARY KEY constraint over what
// provision_test_roles.sh populates), so no classid column is needed --
// this asserts the identity each row resolves to, and that the set is
// exactly requiredProtectedRelations.
func (p *PostgresSink) protectedRelationIdentityReason(ctx context.Context) (string, error) {
	exists, err := p.regclassExists(ctx, "sec7_protected_relation")
	if err != nil {
		return "", fmt.Errorf("checking sec7_protected_relation: %w", err)
	}
	if !exists {
		return "sec7_protected_relation does not exist (ADR-0007 Addendum 4 D40/D41): grant-ddl-ownership has not run", nil
	}
	var totalRows int
	if err := p.conn.QueryRow(ctx, `SELECT count(*) FROM sec7_protected_relation`).Scan(&totalRows); err != nil {
		return "", fmt.Errorf("counting sec7_protected_relation rows: %w", err)
	}
	if totalRows != len(requiredProtectedRelations) {
		return fmt.Sprintf("sec7_protected_relation has %d row(s), expected exactly %d (ADR-0007 Addendum 4 D41): the registry is emptied, truncated, or padded", totalRows, len(requiredProtectedRelations)), nil
	}
	for _, identity := range requiredProtectedRelations {
		var matches int
		err := p.conn.QueryRow(ctx, `
			SELECT count(*) FROM sec7_protected_relation r
			WHERE (pg_identify_object('pg_class'::regclass, r.objid, 0)).identity = $1
		`, identity).Scan(&matches)
		if err != nil {
			return "", fmt.Errorf("checking sec7_protected_relation for %s: %w", identity, err)
		}
		if matches != 1 {
			return fmt.Sprintf("sec7_protected_relation has no row whose OID resolves (via pg_identify_object) to %s (ADR-0007 Addendum 4 D41): the registry is stale, repointed, or was never populated with this relation", identity), nil
		}
	}
	return "", nil
}

// requiredProtectedRelationState is ADR-0007 Addendum 5 D47: sec7_protected_
// relation's seven recorded STATE columns -- relowner, relkind,
// relrowsecurity, relforcerowsecurity, trigger_oids, index_defs (index_oids
// before ADR-0007 Addendum 6 D50), policy_oids -- are exactly what D40's
// second phase compares live catalog state AGAINST
// (provision_test_roles.sh:544-579 at Addendum 4), and until
// this addendum nothing compared the recorded values themselves to
// anything (CAP #4 §7.5 case G: rewriting trigger_oids alone, identity and
// population left intact, passed every existing check). This is a literal
// declaration independent of what any row in the table claims -- D41's own
// move (compare against an independent literal, not the artifact's account
// of itself) applied to the columns D41 skipped. Five of seven reduce to a
// fact this file already declares elsewhere (see the comment on each
// field); the other two are new, one character and one name apiece.
type requiredProtectedRelationState struct {
	// identity is D46's diagnostic column, resolved via
	// requiredProtectedRelations above -- covered by this same comparison
	// so it is not left as an unchecked claim the way D41's own `note`
	// column on sec7_protected_object was (H-E).
	identity string
	// relowner: requiredDDLOwnedTables already declares this fact and
	// D33 already asserts it live (SchemaObjectOwner); this is a second,
	// independently-scoped assertion of the same fact, not a new one --
	// D21 point 3 / D33's own "two assertions beside each other" design.
	relowner string
	// relkind: 'r', ordinary table. Both protected relations are plain
	// tables today; true of both, verified against the real schema.
	relkind string
	// Neither protected relation has row-level security enabled.
	relrowsecurity      bool
	relforcerowsecurity bool
	// triggers: requiredSchemaObjects above already declares each
	// relation's immutability and TRUNCATE-guard trigger names; the names
	// are reused here rather than re-declared, so the two lists cannot
	// drift apart. ADR-0007 Addendum 8 D69 adds, per trigger, the four
	// session-independent catalog properties that make it the control it
	// is -- see requiredProtectedTriggerState.
	triggers []requiredProtectedTriggerState
	// indexNames: the relation's own primary-key index, one per table,
	// named literally rather than derived from a naming-pattern guess.
	// ADR-0007 Addendum 6 D50: "the coordinated-edit surface does not
	// grow" -- this stays a name literal; only the query in
	// protectedRelationStateReason below changes, from reconciling the
	// recorded column against these names' OIDs to reconciling it
	// against these names' pg_get_indexdef() renderings.
	indexNames []string
	// No protected relation carries any RLS policy today -- policy_oids
	// must be empty.
}

// triggerNames returns just the names from triggers, for the existing
// recorded-trigger_oids comparison (protectedRelationStateReason) which
// predates D69 and is unaffected by it -- D69 adds a second, independent
// live-behavior comparison beside this one; it does not replace it.
func (w requiredProtectedRelationState) triggerNames() []string {
	names := make([]string, len(w.triggers))
	for i, trig := range w.triggers {
		names[i] = trig.name
	}
	return names
}

// requiredProtectedTriggerState is ADR-0007 Addendum 8 D69: the four
// session-independent catalog properties that make a declared trigger
// the control it is, not merely an object bearing the declared name.
// Every value was measured against the shipped baseline during the
// addendum's design pass -- see docs/adr/0007-audit-chain-integrity.md's
// D69 table -- rather than assumed from the migration that creates the
// trigger. Deliberately does NOT include pg_get_triggerdef's rendering:
// D69 investigated and rejected that (search_path-sensitive, so the
// recorder and the verifier can render the same substituted trigger
// differently at the same instant) -- see D69's own text before adding
// it back.
//
// tgqual is not a field here: all four declared triggers have no WHEN
// clause (tgqual IS NULL), asserted as a literal true in the query
// itself rather than threaded through as a per-trigger bool that would
// only ever be one value.
type requiredProtectedTriggerState struct {
	name string
	// tgtype is PostgreSQL's trigger-type bitmask (ROW/STATEMENT x
	// BEFORE/AFTER x INSERT/UPDATE/DELETE/TRUNCATE), a documented,
	// version-stable ABI -- unlike pg_get_triggerdef's text.
	tgtype int16
	// tgnargs and tgattr: no declared trigger takes arguments; tgattr
	// (rendered as text, e.g. "" for none) is the column list an
	// `UPDATE OF <column>` clause narrows the trigger to -- empty means
	// "every column," which is what every declared trigger requires.
	tgnargs     int16
	tgattr      string
	functionOID string // pg_identify_object('pg_proc', tgfoid, 0).identity
}

// requiredProtectedRelationStates is D47's literal declaration, written
// beside requiredProtectedRelations rather than derived from it or from
// scripts/ci/provision_test_roles.sh's own population query -- comparing
// two independent literals is the point (a name-to-OID reconciliation
// through the catalog, not a re-execution of provisioning).
var requiredProtectedRelationStates = []requiredProtectedRelationState{
	{
		identity: "public.screening_ledger_anchor",
		relowner: "owl_ledger_ddl",
		relkind:  "r",
		triggers: []requiredProtectedTriggerState{
			{name: "screening_ledger_anchor_immutable", tgtype: 27, tgnargs: 0, tgattr: "", functionOID: "public.screening_ledger_reject_mutation()"},
			{name: "screening_ledger_anchor_no_truncate", tgtype: 34, tgnargs: 0, tgattr: "", functionOID: "public.owl_reject_truncate()"},
		},
		indexNames: []string{"screening_ledger_anchor_pkey"},
	},
	{
		identity: "public.screening_ledger_retention_tombstone",
		relowner: "owl_ledger_ddl",
		relkind:  "r",
		triggers: []requiredProtectedTriggerState{
			{name: "screening_ledger_retention_tombstone_immutable", tgtype: 27, tgnargs: 0, tgattr: "", functionOID: "public.screening_ledger_reject_mutation()"},
			{name: "screening_ledger_retention_tombstone_no_truncate", tgtype: 34, tgnargs: 0, tgattr: "", functionOID: "public.owl_reject_truncate()"},
		},
		indexNames: []string{"screening_ledger_retention_tombstone_pkey"},
	},
}

// protectedRelationStateReason is D47: for each requiredProtectedRelationStates
// entry, reconciles sec7_protected_relation's seven recorded state columns
// (plus D46's identity column) against the literal declaration above,
// entirely through the catalog -- never through the row's own account of
// itself. Runs only after protectedRelationIdentityReason has already
// confirmed identity/population, so every identity below is known to
// resolve to exactly one row.
func (p *PostgresSink) protectedRelationStateReason(ctx context.Context) (string, error) {
	for _, want := range requiredProtectedRelationStates {
		var ownerOK, kindOK, rlsOK, forceRLSOK, triggersOK, indexesOK, indexesValidOK, indexesPresentOK, policiesOK, identityOK bool
		err := p.conn.QueryRow(ctx, `
			SELECT
				r.relowner = $2::regrole::oid,
				r.relkind = $3,
				r.relrowsecurity = $4,
				r.relforcerowsecurity = $5,
				r.trigger_oids = (
					SELECT COALESCE(array_agg(t.oid ORDER BY t.oid), ARRAY[]::oid[])
					FROM pg_trigger t
					WHERE t.tgrelid = r.objid AND NOT t.tgisinternal AND t.tgname = ANY($6)
				),
				r.index_defs = (
					SELECT COALESCE(array_agg(pg_get_indexdef(ix.indexrelid) ORDER BY pg_get_indexdef(ix.indexrelid)), ARRAY[]::text[])
					FROM pg_index ix JOIN pg_class ic ON ic.oid = ix.indexrelid
					WHERE ix.indrelid = r.objid AND ic.relname = ANY($7)
				),
				-- ADR-0007 Addendum 7 D65: pg_get_indexdef renders what an
				-- index IS, not whether it is IN FORCE -- the same gap D40's
				-- existing tgenabled branch (below, via the trigger function)
				-- already closes for triggers. A live check, not a recorded
				-- column: indisvalid/indisready are never written to
				-- index_defs (D49's second withdrawal condition is not
				-- engaged), so an invalidated declared index fails this
				-- assertion even though its definition rendering is
				-- unchanged.
				NOT EXISTS (
					SELECT 1 FROM pg_index ix JOIN pg_class ic ON ic.oid = ix.indexrelid
					WHERE ix.indrelid = r.objid AND ic.relname = ANY($7)
					  AND NOT (ix.indisvalid AND ix.indisready)
				),
				-- ADR-0007 Addendum 8 D71: a declared index name is
				-- asserted to resolve to a LIVE object, not merely
				-- compared through index_defs -- when nothing bears the
				-- name, both index_defs sides are the empty array and
				-- D65's validity branch above is vacuously true over zero
				-- rows too (both repaired by this same EXISTS). One row
				-- per declared name, so a partially-dropped set (some
				-- declared indexes present, others missing) is also
				-- caught, not just a fully-empty one.
				NOT EXISTS (
					SELECT 1 FROM unnest($7::text[]) AS decl(name)
					WHERE NOT EXISTS (
						SELECT 1 FROM pg_index ix JOIN pg_class ic ON ic.oid = ix.indexrelid
						WHERE ix.indrelid = r.objid AND ic.relname = decl.name
					)
				),
				r.policy_oids = ARRAY[]::oid[],
				r.identity = $1
			FROM sec7_protected_relation r
			WHERE (pg_identify_object('pg_class'::regclass, r.objid, 0)).identity = $1
		`, want.identity, want.relowner, want.relkind, want.relrowsecurity, want.relforcerowsecurity, want.triggerNames(), want.indexNames).
			Scan(&ownerOK, &kindOK, &rlsOK, &forceRLSOK, &triggersOK, &indexesOK, &indexesValidOK, &indexesPresentOK, &policiesOK, &identityOK)
		if err != nil {
			return "", fmt.Errorf("checking sec7_protected_relation recorded state for %s: %w", want.identity, err)
		}
		switch {
		case !ownerOK:
			return fmt.Sprintf("sec7_protected_relation's recorded relowner for %s does not match %s (ADR-0007 Addendum 5 D47): the recorded state and the row's identity have diverged", want.identity, want.relowner), nil
		case !kindOK:
			return fmt.Sprintf("sec7_protected_relation's recorded relkind for %s is not %q (ADR-0007 Addendum 5 D47)", want.identity, want.relkind), nil
		case !rlsOK || !forceRLSOK:
			return fmt.Sprintf("sec7_protected_relation's recorded row-level-security flags for %s do not match the declared state (ADR-0007 Addendum 5 D47)", want.identity), nil
		case !triggersOK:
			return fmt.Sprintf("sec7_protected_relation's recorded trigger_oids for %s do not match its two declared trigger names (ADR-0007 Addendum 5 D47): the recorded state was rewritten without D40's second phase seeing it happen", want.identity), nil
		case !indexesOK:
			return fmt.Sprintf("sec7_protected_relation's recorded index_defs for %s do not match its declared primary-key index (ADR-0007 Addendum 5 D47 / Addendum 6 D50)", want.identity), nil
		case !indexesValidOK:
			return fmt.Sprintf("%s: one of its declared indexes is not valid and ready (indisvalid/indisready) (ADR-0007 Addendum 7 D65)", want.identity), nil
		case !indexesPresentOK:
			return fmt.Sprintf("%s: one of its declared indexes does not exist (ADR-0007 Addendum 8 D71): a declared name that resolves to nothing must not pass this check vacuously", want.identity), nil
		case !policiesOK:
			return fmt.Sprintf("sec7_protected_relation's recorded policy_oids for %s is not empty (ADR-0007 Addendum 5 D47)", want.identity), nil
		case !identityOK:
			return fmt.Sprintf("sec7_protected_relation's recorded identity column for %s does not match (ADR-0007 Addendum 5 D46/D47)", want.identity), nil
		}
		// ADR-0007 Addendum 8 D69: the declared trigger's referent
		// becomes what it DOES, not merely a name that resolves to
		// something. Compared directly against the live catalog (never
		// through sec7_protected_relation's recorded trigger_oids column
		// above), because that recorded column is re-populated by
		// grant-ddl-ownership itself -- exactly the launder D69 closes,
		// so a comparison that trusts it cannot detect a substitution
		// that survived a re-run of the installer. pg_get_triggerdef is
		// deliberately not used here: D69 investigated and rejected it
		// (search_path-sensitive; a same-named no-op in another schema
		// renders byte-identically to the legitimate guard in exactly the
		// session that runs this check).
		for _, trig := range want.triggers {
			var tgtypeOK, tgqualIsNullOK, tgnargsOK, tgattrOK, functionOK, presentOK bool
			err := p.conn.QueryRow(ctx, `
				SELECT
					EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2),
					COALESCE((SELECT t.tgtype = $3 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false),
					COALESCE((SELECT t.tgqual IS NULL FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false),
					COALESCE((SELECT t.tgnargs = $4 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false),
					COALESCE((SELECT t.tgattr::text = $5 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false),
					COALESCE((SELECT (pg_identify_object('pg_proc'::regclass, t.tgfoid, 0)).identity = $6 FROM pg_trigger t WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2), false)
			`, want.identity, trig.name, trig.tgtype, trig.tgnargs, trig.tgattr, trig.functionOID).
				Scan(&presentOK, &tgtypeOK, &tgqualIsNullOK, &tgnargsOK, &tgattrOK, &functionOK)
			if err != nil {
				return "", fmt.Errorf("checking trigger %s behavior on %s (ADR-0007 Addendum 8 D69): %w", trig.name, want.identity, err)
			}
			switch {
			case !presentOK:
				return fmt.Sprintf("%s: declared trigger %s does not exist (ADR-0007 Addendum 8 D69/D71)", want.identity, trig.name), nil
			case !functionOK:
				return fmt.Sprintf("%s: trigger %s is not bound to %s (ADR-0007 Addendum 8 D69): possible rebind to a substituted function", want.identity, trig.name, trig.functionOID), nil
			case !tgtypeOK:
				return fmt.Sprintf("%s: trigger %s's tgtype does not match the declared %d (ADR-0007 Addendum 8 D69)", want.identity, trig.name, trig.tgtype), nil
			case !tgqualIsNullOK:
				return fmt.Sprintf("%s: trigger %s has a WHEN clause, expected none (ADR-0007 Addendum 8 D69): possible WHEN (false) neutering", want.identity, trig.name), nil
			case !tgnargsOK:
				return fmt.Sprintf("%s: trigger %s's tgnargs does not match the declared %d (ADR-0007 Addendum 8 D69)", want.identity, trig.name, trig.tgnargs), nil
			case !tgattrOK:
				return fmt.Sprintf("%s: trigger %s's column list does not match the declared set (ADR-0007 Addendum 8 D69): possible UPDATE OF <column> narrowing", want.identity, trig.name), nil
			}
		}
	}
	return "", nil
}

// anyColumnPrivilege is ADR-0007 Addendum 4 D39: true iff role holds
// priv on any live (non-system, non-dropped) column of table. bool_or
// over zero rows is NULL, not false -- COALESCE guards a table with no
// qualifying columns (never true in this schema, but the query should
// not panic on Scan if it ever were) so a real false is never confused
// with "no columns to check."
func (p *PostgresSink) anyColumnPrivilege(ctx context.Context, role, table, priv string) (bool, error) {
	var has bool
	err := p.conn.QueryRow(ctx, `
		SELECT COALESCE(bool_or(has_column_privilege($1, $2::regclass, a.attnum, $3)), false)
		FROM pg_attribute a
		WHERE a.attrelid = $2::regclass AND a.attnum > 0 AND NOT a.attisdropped
	`, role, table, priv).Scan(&has)
	return has, err
}

// predefinedRoleStructuralPrivilege is ADR-0007 Addendum 8 D72's
// allowlist principle: PostgreSQL's own predefined roles that
// structurally carry a privilege on every table with no ACL entry
// naming them at all, keyed by the exact privilege kind they carry --
// measured against the shipped baseline during this addendum's
// implementation, not assumed. pg_maintain (oid 6337) is the one
// predefined role reporting MAINTAIN=true; pg_read_all_data reports
// SELECT=true; pg_write_all_data reports DELETE/INSERT/UPDATE=true.
// None of the sixteen predefined roles report REFERENCES, TRIGGER or
// TRUNCATE=true, so those three keys are correctly absent -- an entry
// here is a measured fact about one specific (role, privilege) pair, not
// a blanket "predefined roles are exempt" the way D59 point 3's
// oid >= 16384 range was. A privilege range would have excluded every
// predefined role from every privilege kind regardless of which one, if
// any, is actually theirs; D72's own finding is that doing so silently
// hid a GRANT MAINTAIN ... TO pg_read_all_data, because pg_read_all_data
// (oid 6181) is a predefined role too and the range does not
// distinguish "structurally carries this privilege" from "is a
// predefined role."
var predefinedRoleStructuralPrivilege = map[string][]string{
	"MAINTAIN": {"pg_maintain"},
	"SELECT":   {"pg_read_all_data"},
	"DELETE":   {"pg_write_all_data"},
	"INSERT":   {"pg_write_all_data"},
	"UPDATE":   {"pg_write_all_data"},
}

// quoteSQLStringLiteral is a minimal single-quote SQL literal quoter for
// composing privilegeHolderRoleFilterSQLTemplate's %s slot, filled only
// from this package's own fixed privilege-kind literals
// (requiredTablePrivilegeKinds, "MAINTAIN") -- never from caller- or
// database-supplied input. Doubling an embedded quote is defence in
// depth here, not the actual safety boundary (the boundary is that the
// input set is closed and internal).
func quoteSQLStringLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// privilegeHolderRoleFilterSQLTemplate is ADR-0007 Addendum 8 D72/D73's
// replacement for D59 point 3's nonSuperuserUserCreatedRoleFilter
// (oid >= 16384): "NOT rolsuper" is unchanged (the bootstrap superuser
// is outside the adversary set R12/R17 name); the oid range is replaced
// by an explicit, per-privilege allowlist of the predefined roles that
// structurally carry exactly this privilege (D72) bound as $2, and the
// enumeration itself asks the pg_has_role(..., 'MEMBER') question (D73)
// rather than has_table_privilege(r.rolname, ...) directly -- confirmed
// by execution to be transitive and to cover both NOINHERIT and
// per-grant WITH INHERIT FALSE, over 1058 (role, role, table)
// combinations with no exception. A role is always a MEMBER of itself,
// so this subsumes the pre-D73 direct check as the s = r case; it is not
// a narrower replacement. %s is holderClause, a privilege-specific
// predicate against pg_roles s -- substituted with fmt.Sprintf on a
// fixed Go string literal from each call site below, never on any value
// that reaches this function from outside the package.
const privilegeHolderRoleFilterSQLTemplate = `
	SELECT COALESCE(array_agg(DISTINCT r.rolname::text ORDER BY r.rolname::text), ARRAY[]::text[])
	FROM pg_roles r
	WHERE NOT r.rolsuper AND NOT (r.rolname = ANY($2::text[]))
	  AND EXISTS (
		SELECT 1 FROM pg_roles s
		WHERE pg_has_role(r.oid, s.oid, 'MEMBER')
		  AND %s
	  )
`

// privilegeHolders is ADR-0007 Addendum 8 D73: the two independent
// limbs D39's rejected aclexplode scan and D60/D61's has_table_privilege
// enumeration each become, neither subsuming the other (D73's own
// argument: the holder-side limb cannot see a grant to a role with no
// current members, and D39's own transcript is exactly the case the
// grantee-side limb closes -- a member reaching the privilege through a
// role the ACL never names literally). holderClause is the
// privilege-specific EXISTS predicate against pg_roles s (table-level
// has_table_privilege or D39's anyColumnPrivilege-shaped column check),
// referencing s.rolname and $1 (table); allowlist is
// predefinedRoleStructuralPrivilege[priv] or nil. Grantee-side is
// deliberately scoped to relacl (table-level ACL) only -- every grant
// this repository's provisioning issues is table-level (never
// column-level), so this matches what D73's own MAINTAIN example scans
// and does not need pg_attribute.attacl.
func (p *PostgresSink) privilegeHolders(ctx context.Context, table, priv string, holderClause string, allowlist []string) (holderSide, granteeSide []string, err error) {
	if allowlist == nil {
		allowlist = []string{}
	}
	err = p.conn.QueryRow(ctx,
		fmt.Sprintf(privilegeHolderRoleFilterSQLTemplate, holderClause),
		table, allowlist,
	).Scan(&holderSide)
	if err != nil {
		return nil, nil, fmt.Errorf("holder-side (pg_has_role MEMBER) enumeration: %w", err)
	}
	err = p.conn.QueryRow(ctx, `
		SELECT COALESCE(array_agg(DISTINCT grantee_name ORDER BY grantee_name), ARRAY[]::text[])
		FROM (
			SELECT (CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END) AS grantee_name
			FROM pg_class c, aclexplode(c.relacl) a
			WHERE c.oid = $1::regclass AND a.privilege_type = $2
		) granted
	`, table, priv).Scan(&granteeSide)
	if err != nil {
		return nil, nil, fmt.Errorf("grantee-side (aclexplode) scan: %w", err)
	}
	return holderSide, granteeSide, nil
}

// maintainHoldersReason is ADR-0007 Addendum 7 D60 (K-A, HIGH), extended
// by Addendum 8 D72/D73: the set of roles holding MAINTAIN on a
// protected table must be empty in BOTH the holder-side (pg_has_role
// MEMBER, D72's allowlist) and grantee-side (aclexplode) senses --
// asserted empty outright rather than against a declared literal,
// because nothing in this system has any legitimate need to hold
// MAINTAIN on either protected table (Addendum 6 D51), and an empty-set
// assertion has no literal to drift out of sync with. MAINTAIN has no
// column form (confirmed by execution: has_column_privilege raises
// "unrecognized privilege type" for it), so has_table_privilege is the
// right question here, not anyColumnPrivilege.
func (p *PostgresSink) maintainHoldersReason(ctx context.Context) (string, error) {
	for _, table := range requiredDDLOwnedTables {
		holderSide, granteeSide, err := p.privilegeHolders(ctx, table, "MAINTAIN",
			`has_table_privilege(s.rolname, $1::regclass, 'MAINTAIN')`,
			predefinedRoleStructuralPrivilege["MAINTAIN"],
		)
		if err != nil {
			return "", fmt.Errorf("checking MAINTAIN holders on %s: %w", table, err)
		}
		if len(holderSide) > 0 {
			return fmt.Sprintf("MAINTAIN on %s is held by %s (ADR-0007 Addendum 7 D60 / Addendum 8 D73 holder-side): the owner can GRANT this to any role, or a role can reach it via SET ROLE through a NOINHERIT membership, and only this live enumeration notices -- this does not by itself mean the transfer is prevented (R27), only that it is now observed", table, strings.Join(holderSide, ", ")), nil
		}
		if len(granteeSide) > 0 {
			return fmt.Sprintf("MAINTAIN on %s is granted to %s (ADR-0007 Addendum 8 D73 grantee-side, aclexplode): a literal ACL grantee the holder-side limb's membership traversal did not independently confirm", table, strings.Join(granteeSide, ", ")), nil
		}
	}
	return "", nil
}

// tablePrivilegesWithColumnForm is the subset of PostgreSQL's table
// privilege kinds has_column_privilege actually accepts -- confirmed by
// execution during this addendum's design pass: DELETE, TRUNCATE and
// TRIGGER all raise "unrecognized privilege type" from
// has_column_privilege, because PostgreSQL has no column-level form of
// them (MAINTAIN is the fourth such kind, and it is D60's own empty-set
// assertion, not part of this matrix). D39's anyColumnPrivilege is
// reachable only for the four kinds below; the other three fall back to
// has_table_privilege, which is the only question with meaning for a
// privilege that has no column grain.
var tablePrivilegesWithColumnForm = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "REFERENCES": true,
}

// requiredTablePrivilegeKinds is the seven non-MAINTAIN table privilege
// kinds ADR-0007 Addendum 7 D61's matrix quantifies, alphabetically
// ordered to match the matrix's own comma-joined rendering in the
// addendum's transcripts.
var requiredTablePrivilegeKinds = []string{"DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"}

// tablePrivilegeGrant is one row of D61's declared five-row matrix: role
// holds every privilege in privileges on table, and -- because the
// assertion is set equality, not a one-directional negative -- no role
// outside this matrix may hold any of these privileges on that table.
type tablePrivilegeGrant struct {
	table      string
	role       string
	privileges []string
}

// requiredTablePrivilegeHolders is D61's declared literal, measured
// against the shipped baseline rather than transcribed from D17's table
// (ADR-0007 Addendum 7 D61): owl_ledger_ddl's rows are the table owner's
// implicit privileges (every kind except MAINTAIN, which Addendum 6
// D51's REVOKE removes and D60 asserts empty separately -- not
// duplicated here). Written out literally, not derived by scanning
// scripts/ci/provision_test_roles.sh's own grants -- CLAUDE.md's "never
// enumerate targets by inference" applies to a generated list as much as
// a hand-picked one.
var requiredTablePrivilegeHolders = []tablePrivilegeGrant{
	{"screening_ledger_anchor", "owl_ledger_anchor", []string{"INSERT"}},
	{"screening_ledger_anchor", "owl_ledger_ddl", []string{"DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"}},
	{"screening_ledger_anchor", "owl_migrator", []string{"SELECT"}},
	{"screening_ledger_retention_tombstone", "owl_ledger_ddl", []string{"DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"}},
	{"screening_ledger_retention_tombstone", "owl_migrator", []string{"SELECT"}},
}

// requiredTablePrivilegeHolderRoles returns, sorted, the declared
// holders of priv on table per requiredTablePrivilegeHolders -- the
// empty slice (never nil) when no row declares it, so a direct
// comparison against a live-enumerated []string is exact rather than
// nil-vs-empty ambiguous.
func requiredTablePrivilegeHolderRoles(table, priv string) []string {
	roles := []string{}
	for _, grant := range requiredTablePrivilegeHolders {
		if grant.table != table {
			continue
		}
		for _, p := range grant.privileges {
			if p == priv {
				roles = append(roles, grant.role)
				break
			}
		}
	}
	sort.Strings(roles)
	return roles
}

// tablePrivilegeHoldersReason is ADR-0007 Addendum 7 D61, extended by
// Addendum 8 D72/D73: D39's per-role negative probes (H-C) are
// re-quantified over the live role population -- for every protected
// table and every one of the seven non-MAINTAIN table privilege kinds,
// BOTH the holder-side (pg_has_role MEMBER, D72's per-privilege
// allowlist) and grantee-side (aclexplode) sets of roles holding that
// privilege must equal exactly requiredTablePrivilegeHolders's declared
// set. An extra live holder (either side) and a missing declared holder
// are both named failures -- set equality, not a one-directional
// negative, which is what closes the coverage gap D39 never had (a
// privilege the design requires a role to hold was never independently
// checked before this), and CAP #7 confirmed this matrix has the same
// NOINHERIT/no-current-member hole D73 closes for D60.
func (p *PostgresSink) tablePrivilegeHoldersReason(ctx context.Context) (string, error) {
	for _, table := range requiredDDLOwnedTables {
		for _, priv := range requiredTablePrivilegeKinds {
			var holderClause string
			if tablePrivilegesWithColumnForm[priv] {
				holderClause = fmt.Sprintf(`EXISTS (
					SELECT 1 FROM pg_attribute a
					WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
					  AND has_column_privilege(s.rolname, $1::regclass, a.attnum, %s)
				)`, quoteSQLStringLiteral(priv))
			} else {
				holderClause = fmt.Sprintf(`has_table_privilege(s.rolname, $1::regclass, %s)`, quoteSQLStringLiteral(priv))
			}
			holderSide, granteeSide, err := p.privilegeHolders(ctx, table, priv, holderClause, predefinedRoleStructuralPrivilege[priv])
			if err != nil {
				return "", fmt.Errorf("checking %s holders on %s: %w", priv, table, err)
			}
			want := requiredTablePrivilegeHolderRoles(table, priv)
			describe := func(roles []string) string {
				if len(roles) == 0 {
					return "<none>"
				}
				return strings.Join(roles, ", ")
			}
			if !stringSlicesEqual(holderSide, want) {
				return fmt.Sprintf("live %s privilege holders (holder-side, pg_has_role MEMBER) on %s are {%s}, expected exactly {%s} (ADR-0007 Addendum 7 D61 / Addendum 8 D73): a role holds this privilege the declared matrix does not name, or a declared holder is missing it", priv, table, describe(holderSide), describe(want)), nil
			}
			if !stringSlicesEqual(granteeSide, want) {
				return fmt.Sprintf("live %s privilege grantees (grantee-side, aclexplode) on %s are {%s}, expected exactly {%s} (ADR-0007 Addendum 8 D73): a literal ACL grantee the declared matrix does not name, or a declared holder has no literal grant", priv, table, describe(granteeSide), describe(want)), nil
			}
		}
	}
	return "", nil
}

// stringSlicesEqual compares two already-sorted string slices for exact
// equality.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// CheckProvisioningState is checkProvisioningState's exported entry
// point, satisfying ProvisioningStateReader (anchor.go) so
// VerifyAnchored can require it without a package-internal type leaking
// into that interface's contract.
func (p *PostgresSink) CheckProvisioningState(ctx context.Context) (ProvisioningState, error) {
	return p.checkProvisioningState(ctx)
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
		immutableOK, err := p.triggerEnabled(ctx, obj.table, obj.immutableTrigger)
		if err != nil {
			return fmt.Errorf("ADR-0007 D21: checking trigger %s on %s: %w", obj.immutableTrigger, obj.table, err)
		}
		if !immutableOK {
			return fmt.Errorf("schema incomplete (ADR-0007 D21): %s is missing its row-immutability trigger %s (installed by %s) -- Migrate() will not report success on a table whose protections are not actually present", obj.table, obj.immutableTrigger, obj.immutableInstalledBy)
		}
		noTruncateOK, err := p.triggerEnabled(ctx, obj.table, obj.noTruncateTrigger)
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

// triggerEnabled is ADR-0007 Addendum 3 D33 (G-A): renamed from
// triggerExists, which matched only tgname/tgrelid and never read
// tgenabled -- so a trigger CAP #2 §7.5 left DISABLE'd via ALTER TABLE
// still read back as "present." No legitimate state has a disabled guard
// trigger, so this is a strict tightening with no new configuration:
// every existing caller (checkRequiredSchemaObjects) gets the stronger
// check automatically.
func (p *PostgresSink) triggerEnabled(ctx context.Context, table, trigger string) (bool, error) {
	var enabled string
	err := p.conn.QueryRow(ctx,
		`SELECT tgenabled FROM pg_trigger WHERE tgname=$1 AND tgrelid=$2::regclass AND NOT tgisinternal`,
		trigger, table,
	).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return enabled == "O", nil
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
	// ADR-0007 Addendum 7 D65: ORDER BY sequence DESC alone has no
	// tiebreaker -- unreachable while screening_ledger_anchor_pkey (ledger_id,
	// sequence) is valid and ready (K-F's own state disables exactly
	// that), so a duplicate sequence for one ledger_id becomes possible
	// only once the index is no longer enforcing, at which point this
	// query's own row order is otherwise unspecified. anchor_mac DESC as
	// a secondary key adds a total order at no cost on the normal path
	// (a real duplicate never occurs there) and turns K-F from
	// selection non-determinism into a stable choice on the degraded one.
	row := p.conn.QueryRow(ctx,
		`SELECT sequence, event_sha256, audit_sha256, audit_sequence, policy_sha256, anchored_at, anchor_mac
		 FROM screening_ledger_anchor WHERE ledger_id=$1 ORDER BY sequence DESC, anchor_mac DESC LIMIT 1`,
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

// PurgeRecord implements PurgeChecker (ADR-0007 D13/F8, extended by
// Addendum 8 D70): the tombstone row for a snapshot the caller found
// marked purged in its own envelope, rather than trusting that
// self-reported field, and rather than merely asking whether a row
// exists -- D70's forward comparison needs operator/reason/purged_at,
// not just presence. screening_ledger_retention_tombstone is written
// server-side by screening_ledger_purge_snapshots, not by the envelope
// being checked. Returns (nil, nil) when no row exists.
func (p *PostgresSink) PurgeRecord(ctx context.Context, snapshotSHA256 string) (*TombstoneRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	var record TombstoneRecord
	err := p.conn.QueryRow(ctx,
		`SELECT snapshot_sha256, purged_at, operator, reason FROM screening_ledger_retention_tombstone WHERE snapshot_sha256=$1`,
		snapshotSHA256,
	).Scan(&record.SnapshotSHA256, &record.PurgedAt, &record.Operator, &record.Reason)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &record, nil
}

// AllPurgeRecords implements PurgeChecker (ADR-0007 Addendum 8 D70's
// reverse direction): every tombstone row whose snapshot_sha256 is in
// knownSHA256 -- the set the calling ledger's own chain references
// (VerifyReport.KnownSnapshotSHA256), never the whole table, so another
// ledger's rows in the same shared Postgres schema are never named as
// this ledger's forgery. An empty knownSHA256 returns no rows rather
// than every row: ANY($1) over an empty array matches nothing, which is
// the correct answer for a ledger with no events yet.
func (p *PostgresSink) AllPurgeRecords(ctx context.Context, knownSHA256 []string) ([]TombstoneRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	rows, err := p.conn.Query(ctx,
		`SELECT snapshot_sha256, purged_at, operator, reason FROM screening_ledger_retention_tombstone WHERE snapshot_sha256 = ANY($1)`,
		knownSHA256,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []TombstoneRecord{}
	for rows.Next() {
		var record TombstoneRecord
		if err := rows.Scan(&record.SnapshotSHA256, &record.PurgedAt, &record.Operator, &record.Reason); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
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
-- ADR-0007 Addendum 3 D34/G-D: screening_ledger_reject_mutation() is now
-- a protected object (scripts/ci/provision_test_roles.sh
-- grant-ddl-ownership registers it in sec7_protected_object once
-- provisioning has run), so an unconditional CREATE OR REPLACE FUNCTION
-- here -- executed as owl_migrator on every Migrate() call -- would trip
-- D34's own event trigger on every invocation after provisioning. Guarded
-- on to_regprocedure(...) IS NULL, D21's general form applied to a third
-- object: create once, on true first bootstrap; never re-touch once it
-- exists, because once it exists its protections either already are, or
-- are about to be, in place. This also retires the self-heal CAP #2
-- credited ("Migrate() re-issues this unconditionally, so a neutered body
-- does not survive a migrate/sync") in favor of D34's stronger
-- prevention -- owl_migrator can no longer replace this function at all
-- once provisioned, so there is nothing left to heal.
DO $$
BEGIN
  IF to_regprocedure('screening_ledger_reject_mutation()') IS NULL THEN
    EXECUTE $exec$CREATE FUNCTION screening_ledger_reject_mutation()RETURNS trigger LANGUAGE plpgsql AS $func$ BEGIN RAISE EXCEPTION 'screening ledger rows are append-only';END $func$ $exec$;
  END IF;
END $$;
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
-- ADR-0007 Addendum 3 D34/G-D: same reasoning and same guard shape as
-- screening_ledger_reject_mutation() above -- owl_reject_truncate() is
-- also a protected object once provisioned.
DO $$
BEGIN
  IF to_regprocedure('owl_reject_truncate()') IS NULL THEN
    EXECUTE $exec$CREATE FUNCTION owl_reject_truncate()RETURNS trigger LANGUAGE plpgsql AS $func$ BEGIN RAISE EXCEPTION 'relation % is append-only; TRUNCATE is prohibited', TG_TABLE_NAME;END $func$ $exec$;
  END IF;
END $$;
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
    EXECUTE $exec$CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_before timestamptz,p_operator text,p_reason text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $func$ DECLARE affected bigint; BEGIN INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT s.snapshot_sha256,clock_timestamp(),p_operator,p_reason FROM screening_ledger_snapshot s WHERE s.purged_at IS NULL AND EXISTS (SELECT 1 FROM screening_ledger_event e WHERE (e.request_snapshot_sha256=s.snapshot_sha256 OR e.response_snapshot_sha256=s.snapshot_sha256) AND e.expires_at<clock_timestamp()) ON CONFLICT(snapshot_sha256) DO NOTHING; UPDATE screening_ledger_snapshot s SET purged_at=clock_timestamp(),purge_reason=p_reason,envelope_json=(envelope_json-'nonce_base64'-'ciphertext_base64')||jsonb_build_object('purged_at',clock_timestamp(),'purge_reason',p_reason) WHERE s.purged_at IS NULL AND EXISTS (SELECT 1 FROM screening_ledger_event e WHERE (e.request_snapshot_sha256=s.snapshot_sha256 OR e.response_snapshot_sha256=s.snapshot_sha256) AND e.expires_at<clock_timestamp()); GET DIAGNOSTICS affected=ROW_COUNT; RETURN affected; END $func$ $exec$;
    EXECUTE $exec$CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots(p_snapshot_sha256 text[],p_before timestamptz,p_operator text,p_reason text) RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $func$ DECLARE recorded text[]; BEGIN WITH eligible AS (SELECT s.snapshot_sha256 FROM screening_ledger_snapshot s WHERE s.snapshot_sha256=ANY(p_snapshot_sha256) AND s.purged_at IS NULL AND EXISTS (SELECT 1 FROM screening_ledger_event e WHERE (e.request_snapshot_sha256=s.snapshot_sha256 OR e.response_snapshot_sha256=s.snapshot_sha256) AND e.expires_at<clock_timestamp())), inserted AS (INSERT INTO screening_ledger_retention_tombstone(snapshot_sha256,purged_at,operator,reason) SELECT snapshot_sha256,clock_timestamp(),p_operator,p_reason FROM eligible ON CONFLICT(snapshot_sha256) DO NOTHING), updated AS (UPDATE screening_ledger_snapshot SET purged_at=clock_timestamp(),purge_reason=p_reason,envelope_json=(envelope_json-'nonce_base64'-'ciphertext_base64')||jsonb_build_object('purged_at',clock_timestamp(),'purge_reason',p_reason) WHERE snapshot_sha256 IN (SELECT snapshot_sha256 FROM eligible) RETURNING snapshot_sha256) SELECT array_agg(snapshot_sha256) INTO recorded FROM updated; RETURN COALESCE(recorded,ARRAY[]::text[]); END $func$ $exec$;
  END IF;
END $$;
COMMIT;
`
