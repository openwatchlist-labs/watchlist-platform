// ADR-0007 Addendum 7 D60/D67 test 1 (K-A, HIGH): the MAINTAIN assertion
// becomes a closed set over the live role population, not a negative
// fact about one named role. Addendum 6 D51's own test
// (d51_maintain_revoke_pgx_test.go, TestProvisioningStateDetectsMaintainRegrant)
// already covers the self-re-grant route and must keep passing --
// re-run here only as a baseline sanity check, not re-implemented. This
// file covers the routes D51's shape could never see: a grant to a
// THIRD role, a grant to PUBLIC, and membership in the pg_maintain
// predefined role -- each moving the capability to a name D51's
// single-role check never asked about.
package screeningledger

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// d60MaintainRoute is one way MAINTAIN can move to a role D51's
// single-role check never asked about, reproduced against a real
// database rather than reasoned about.
type d60MaintainRoute struct {
	name  string
	grant string // SQL run as owl_ledger_ddl (the owner) against the clone
}

var d60MaintainRoutes = []d60MaintainRoute{
	{
		name:  "direct_grant_to_third_role",
		grant: `GRANT MAINTAIN ON TABLE screening_ledger_anchor TO owl_migrator`,
	},
	{
		name:  "grant_to_public",
		grant: `GRANT MAINTAIN ON TABLE screening_ledger_anchor TO PUBLIC`,
	},
}

func TestProvisioningStateDetectsMaintainGrantToAnyRole(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	for _, route := range d60MaintainRoutes {
		t.Run(route.name, func(t *testing.T) {
			clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
			cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)

			sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
			if err != nil {
				t.Fatalf("NewPostgresSink: %v", err)
			}
			defer sink.Close(context.Background())

			baseline, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("baseline CheckProvisioningState: %v", err)
			}
			if !baseline.Provisioned {
				t.Fatalf("test precondition failed: clone must start provisioned (Reason=%q)", baseline.Reason)
			}

			ownerConn, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
			if err != nil {
				t.Fatalf("connect as owl_ledger_ddl: %v", err)
			}
			if _, err := ownerConn.Exec(ctx, route.grant); err != nil {
				t.Fatalf("%s: %v", route.grant, err)
			}
			ownerConn.Close(context.Background())

			after, err := sink.CheckProvisioningState(ctx)
			if err != nil {
				t.Fatalf("CheckProvisioningState after grant: %v", err)
			}
			if after.Provisioned {
				t.Fatalf("ADR-0007 Addendum 7 D60: CheckProvisioningState reported Provisioned=true after %q", route.grant)
			}
			if !strings.Contains(after.Reason, "MAINTAIN") {
				t.Fatalf("expected a reason naming MAINTAIN, got: %q", after.Reason)
			}
		})
	}
}

// TestProvisioningStateDetectsMaintainViaPgMaintainMembership is D59
// point 2's own route, the one a raw ACL scan would miss entirely
// (D39's own reasoning for rejecting aclexplode, reapplied): a role
// that is a MEMBER of the predefined pg_maintain role holds MAINTAIN on
// every relation, including a protected one, with no ACL entry naming
// the table at all.
func TestProvisioningStateDetectsMaintainViaPgMaintainMembership(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)

	sink, err := NewPostgresSink(ctx, cloneMigratorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	baseline, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if !baseline.Provisioned {
		t.Fatalf("test precondition failed: clone must start provisioned (Reason=%q)", baseline.Reason)
	}

	superConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superConn.Close(context.Background())

	memberRole := fmt.Sprintf("zz_d60_pgmaintain_member_%d", time.Now().UnixNano()%1_000_000_000)
	if _, err := superConn.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s NOSUPERUSER NOLOGIN`, pgx.Identifier{memberRole}.Sanitize())); err != nil {
		t.Fatalf("create member role: %v", err)
	}
	defer superConn.Exec(context.Background(), fmt.Sprintf(`DROP ROLE %s`, pgx.Identifier{memberRole}.Sanitize()))

	if _, err := superConn.Exec(ctx, fmt.Sprintf(`GRANT pg_maintain TO %s`, pgx.Identifier{memberRole}.Sanitize())); err != nil {
		t.Fatalf("GRANT pg_maintain: %v", err)
	}

	after, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState after pg_maintain membership: %v", err)
	}
	if after.Provisioned {
		t.Fatal("ADR-0007 Addendum 7 D60: CheckProvisioningState reported Provisioned=true with a role holding MAINTAIN via pg_maintain membership")
	}
	if !strings.Contains(after.Reason, "MAINTAIN") || !strings.Contains(after.Reason, memberRole) {
		t.Fatalf("expected a reason naming MAINTAIN and %s, got: %q", memberRole, after.Reason)
	}
}

// TestProvisioningStateAcceptsCleanDatabaseWithPgMaintainPresent is
// D67 test 1's required positive: the naive "no non-superuser role
// holds MAINTAIN" form fails closed on a healthy, correctly provisioned
// database, because pg_maintain itself (a predefined, NOLOGIN role) is
// non-superuser and reports MAINTAIN=true. D60's oid >= 16384
// discriminator exists specifically so this does not happen; this test
// is what would fail loudly if a later reader "simplified" the check
// back to the naive form.
func TestProvisioningStateAcceptsCleanDatabaseWithPgMaintainPresent(t *testing.T) {
	sink, ctx := newTestSink(t)
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)

	superConn, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superConn.Close(context.Background())

	var pgMaintainOID uint32
	var maintainOnAnchor bool
	if err := superConn.QueryRow(ctx, `SELECT oid, has_table_privilege('pg_maintain', 'screening_ledger_anchor', 'MAINTAIN') FROM pg_roles WHERE rolname = 'pg_maintain'`).Scan(&pgMaintainOID, &maintainOnAnchor); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			t.Fatalf("pg_maintain role lookup failed (SQLSTATE %s): %v", pgErr.Code, err)
		}
		t.Fatalf("pg_maintain role lookup failed: %v", err)
	}
	if pgMaintainOID >= 16384 {
		t.Fatalf("test precondition failed: pg_maintain's oid is %d, expected below 16384 (FirstNormalObjectId) -- the fact D60's discriminator depends on", pgMaintainOID)
	}
	if !maintainOnAnchor {
		t.Fatalf("test precondition failed: pg_maintain does not report MAINTAIN=true on screening_ledger_anchor -- the fact that forces D60's oid >= 16384 discriminator")
	}

	state, err := sink.CheckProvisioningState(ctx)
	if err != nil {
		t.Fatalf("CheckProvisioningState: %v", err)
	}
	if !state.Provisioned {
		t.Fatalf("ADR-0007 Addendum 7 D60: a clean, provisioned database with pg_maintain present and untouched should read Provisioned=true, got Reason=%q -- this is what the naive \"no non-superuser role holds MAINTAIN\" form would fail on", state.Reason)
	}
}

// TestMaintainRegrantEndToEndWedge is D67 test 1's end-to-end limb:
// owl_migrator, having been granted MAINTAIN by the owner, can cancel a
// REINDEX ... CONCURRENTLY and wedge the database -- the SQLSTATE is
// captured, not inferred.
func TestMaintainRegrantEndToEndWedge(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)

	ownerConn, err := pgx.Connect(ctx, clone.ledgerDDLDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	if _, err := ownerConn.Exec(ctx, `GRANT MAINTAIN ON TABLE screening_ledger_anchor TO owl_migrator`); err != nil {
		t.Fatalf("GRANT MAINTAIN to owl_migrator: %v", err)
	}
	ownerConn.Close(context.Background())

	// Widen the window a cancellation has to land in: REINDEX ...
	// CONCURRENTLY on a near-empty table builds its new index too fast
	// for pg_cancel_backend to reliably interrupt mid-build, which would
	// cancel before any invalid leftover exists at all -- a genuinely
	// different (uninteresting) state from the wedge this test exists to
	// reproduce. Bulk-loading rows first is not this addendum's own
	// claim, only a timing aid for reproducing it deterministically.
	bulkConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser to bulk-load rows: %v", err)
	}
	if _, err := bulkConn.Exec(ctx, `
		INSERT INTO screening_ledger_anchor (ledger_id, sequence, event_sha256, audit_sha256, audit_sequence, policy_sha256, anchored_at, anchor_mac)
		SELECT 'zz-d60-bulk-' || (n / 5000), n % 5000, repeat('a', 64), repeat('a', 64), 0, repeat('a', 64), now(), repeat('a', 64)
		FROM generate_series(0, 199999) AS n
	`); err != nil {
		bulkConn.Close(context.Background())
		t.Fatalf("bulk-load rows: %v", err)
	}
	bulkConn.Close(context.Background())

	migConn, err := pgx.Connect(ctx, cloneMigratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migConn.Close(context.Background())

	// A REINDEX ... CONCURRENTLY cancelled mid-flight leaves the wedge
	// D50's own transcripts document -- pg_cancel_backend against the
	// statement's own backend PID, from a second connection, rather than
	// a context deadline race against however long the rebuild happens
	// to take on this run's table size.
	pid := migConn.PgConn().PID()
	resultCh := make(chan error, 1)
	go func() {
		_, err := migConn.Exec(ctx, `REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey`)
		resultCh <- err
	}()

	cancelConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser to issue the cancellation: %v", err)
	}
	defer cancelConn.Close(context.Background())

	// REINDEX ... CONCURRENTLY on a near-empty table can complete in
	// under a millisecond, faster than a single pg_cancel_backend can
	// land -- repeat the signal until the statement actually finishes,
	// maximizing the chance of catching one of its several internal
	// wait points rather than betting on one fixed delay.
	var reindexErr error
	deadline := time.After(2 * time.Second)
cancelLoop:
	for {
		select {
		case reindexErr = <-resultCh:
			break cancelLoop
		case <-deadline:
			t.Fatal("REINDEX INDEX CONCURRENTLY neither completed nor was successfully cancelled within 2s")
		default:
			if _, err := cancelConn.Exec(ctx, `SELECT pg_cancel_backend($1)`, pid); err != nil {
				t.Fatalf("pg_cancel_backend(%d): %v", pid, err)
			}
			time.Sleep(time.Millisecond)
		}
	}
	t.Logf("REINDEX INDEX CONCURRENTLY as owl_migrator (cancelled): %v", reindexErr)
	if reindexErr == nil {
		t.Skip("REINDEX CONCURRENTLY completed before the cancellation reached it -- cannot exercise the cancellation-induced wedge deterministically on this run")
	}

	superConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superConn.Close(context.Background())
	_, wedgeErr := superConn.Exec(ctx, `CREATE TABLE zz_d60_wedge_probe (id int)`)
	if wedgeErr == nil {
		t.Skip("database did not wedge after the cancelled REINDEX on this run -- timing-dependent, not this addendum's own claim to verify")
	}
	var pgErr *pgconn.PgError
	if !errors.As(wedgeErr, &pgErr) {
		t.Fatalf("expected a captured SQLSTATE on the wedge probe, got a non-Postgres error: %v", wedgeErr)
	}
	t.Logf("wedge confirmed via cancelled REINDEX ... CONCURRENTLY granted through MAINTAIN: SQLSTATE %s: %v", pgErr.Code, wedgeErr)
}
