// ADR-0001 SEC-1 §8 two-tenant integration suite for the migration PR
// (db/migrations/014_tenant_isolation.sql). Gated on OWL_TEST_DATABASE_URL
// and OWL_MIGRATOR_DATABASE_URL -- skips cleanly when either is unset,
// matching scripts/ci/check_sql_invariants.sh's own gating -- and runs
// under -race with the rest of this package.
//
// Every DB interaction here shells out to psql, the same fork+exec shape
// every sink in this repo already uses (internal/screeningledger/
// postgres.go and its siblings): no new dependency, since pgx (REL-2)
// has not landed (ADR §5/§10, D1's accepted interim).
//
// Reused-connection case, decided explicitly per the task that asked for
// this suite: pgx is not landed, so there is no application-level
// connection pool to test yet -- every sink still spawns one psql process
// per write, and ADR §8 already documents that this case is inert under
// fork+exec ("today it proves nothing... it becomes the load-bearing test
// the moment pgx lands"). That specific claim -- a pooled connection
// leaking a prior tenant's binding to the next borrower -- stays a
// documented no-op until REL-2t re-arms it. What TestNoLeakAcrossReusedSession
// below tests instead, and what IS load-bearing today, is the underlying
// mechanism that will make the pooled case safe once it exists:
// set_config(..., is_local=true) resets at transaction end, so a second
// transaction on the SAME physical session/connection does not inherit
// the first transaction's tenant binding. One psql invocation running two
// sequential transactions is one physical backend connection, which is
// what makes this a real (if narrower) test of the mechanism rather than
// nothing at all.
package integrationtest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
)

const (
	sec1TenantX = "sec1-it-tenant-x"
	sec1TenantY = "sec1-it-tenant-y"
)

// sec1TenantScopedRelations is the literal 16-relation list from
// db/tenant_scoped_tables.txt (ADR-0001 SEC-1 §3/§4), transcribed
// directly rather than derived -- a heuristic would silently exclude a
// newly added relation that was never wired in.
var sec1TenantScopedRelations = []string{
	"alert_record", "alert_case", "case_assistance_record", "vendor_adapter_record", "review_security_audit_event",
	"alert_case_membership", "alert_case_event", "alert_case_idempotency", "alert_case_audit",
	"case_assistance_review", "case_assistance_idempotency", "case_assistance_audit",
	"vendor_adapter_idempotency", "vendor_adapter_audit",
	"operational_outbox_event", "operational_outbox_message",
}

func requireSEC1TestDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("OWL_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("OWL_TEST_DATABASE_URL not set; SEC-1 two-tenant suite requires a live Postgres (see scripts/ci/run-ci.sh)")
	}
	return url
}

func requireSEC1MigratorDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("OWL_MIGRATOR_DATABASE_URL")
	if url == "" {
		t.Skip("OWL_MIGRATOR_DATABASE_URL not set; SEC-1 two-tenant suite needs owl_migrator to seed fixture data")
	}
	return url
}

// runSEC1SQL executes sql against url via psql, returning combined stdout
// (tuples-only, unaligned) and an error carrying psql's stderr text when
// the script fails -- ON_ERROR_STOP=1 means a RAISE EXCEPTION or a
// constraint violation aborts the whole script, matching every migration
// in db/migrations/.
func runSEC1SQL(t *testing.T, url, sql string) (string, error) {
	t.Helper()
	cmd := exec.Command("psql", url, "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s", text)
	}
	return text, nil
}

func mustRunSEC1SQL(t *testing.T, url, sql string) string {
	t.Helper()
	out, err := runSEC1SQL(t, url, sql)
	if err != nil {
		t.Fatalf("seed/setup SQL failed: %v\nSQL: %s", err, sql)
	}
	return out
}

// lastSEC1Line returns the last non-empty line of psql -t -A output --
// used after a script that begins with "SELECT set_config(...)" (which
// itself prints a line) followed by the query under test.
func lastSEC1Line(out string) string {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return strings.TrimSpace(lines[i])
		}
	}
	return ""
}

// seedSEC1Tenant inserts one row into every Class A/B relation for
// tenant, keyed by suffix so repeated runs against a shared database
// don't collide. Seeded as owl_migrator with the tenant GUC bound
// explicitly per statement: owl_migrator owns these tables (it ran their
// CREATE TABLE statements) and is just as subject to FORCE ROW LEVEL
// SECURITY as owl_app once a GUC is bound -- migration 014 hit this
// itself and had to bind the operator wildcard for its own backfill (see
// that file's header comment).
func seedSEC1Tenant(t *testing.T, migratorURL, tenant, suffix string) {
	t.Helper()
	sql := fmt.Sprintf(`
SELECT set_config('openwatchlist.tenant_id','%[1]s',false);
INSERT INTO alert_record(alert_id,tenant_id,source_type,source_identity,record_sha256,policy_route,created_at,alert_json)
VALUES ('alert_%[2]s','%[1]s','external_alert','src','sha_%[2]s','clear',now(),'{}'::jsonb);
INSERT INTO alert_case(case_id,tenant_id,state,revision,created_at,updated_at,projection_json)
VALUES ('case_%[2]s','%[1]s','open',1,now(),now(),'{}'::jsonb);
INSERT INTO alert_case_membership(tenant_id,case_id,alert_id,joined_at)
VALUES ('%[1]s','case_%[2]s','alert_%[2]s',now());
INSERT INTO alert_case_event(tenant_id,case_id,sequence,revision,event_sha256,previous_event_sha256,occurred_at,action,actor,event_json)
VALUES ('%[1]s','case_%[2]s',1,1,'evt_%[2]s','',now(),'case_created','system','{}'::jsonb);
INSERT INTO alert_case_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[1]s','create-alert','key_%[2]s','req_%[2]s','resp_%[2]s','alert','alert_%[2]s',now(),'{}'::jsonb);
INSERT INTO alert_case_audit(tenant_id,stream_id,sequence,audit_sha256,previous_audit_sha256,occurred_at,action,actor,object_type,object_id,audit_json)
VALUES ('%[1]s','stream_%[2]s','1','audit_%[2]s','',now(),'alert_created','system','alert','alert_%[2]s','{}'::jsonb);
INSERT INTO rag_corpus_snapshot(snapshot_sha256,corpus_id,corpus_version,built_at,passage_count,snapshot_json)
VALUES ('snap_%[2]s','corpus','v1',now(),0,'{}'::jsonb) ON CONFLICT DO NOTHING;
INSERT INTO case_assistance_record(assistance_id,case_id,tenant_id,task,status,record_sha256,snapshot_sha256,generation_model_id,guardian_model_id,occurred_at,record_json)
VALUES ('assistance_%[2]s','case_%[2]s','%[1]s','summarize','completed','recsha_%[2]s','snap_%[2]s','model','guardian',now(),'{}'::jsonb);
INSERT INTO case_assistance_review(tenant_id,assistance_id,case_id,sequence,event_sha256,previous_event_sha256,action,actor,reason,occurred_at,event_json)
VALUES ('%[1]s','assistance_%[2]s','case_%[2]s',1,'review_%[2]s','','accept','analyst','ok',now(),'{}'::jsonb);
INSERT INTO case_assistance_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[1]s','assist:case_%[2]s','key_assist_%[2]s','req_a_%[2]s','resp_a_%[2]s','assistance','assistance_%[2]s',now(),'{}'::jsonb);
INSERT INTO case_assistance_audit(tenant_id,stream_id,sequence,audit_sha256,previous_audit_sha256,occurred_at,action,actor,object_type,object_id,audit_json)
VALUES ('%[1]s','cstream_%[2]s','1','caudit_%[2]s','',now(),'assistance_recorded','system','assistance','assistance_%[2]s','{}'::jsonb);
INSERT INTO vendor_adapter_record(record_id,adapter_id,adapter_version,profile_sha256,source_sha256,envelope_sha256,tenant_id,source_alert_id,occurred_at,envelope_json)
VALUES ('vrecord_%[2]s','adapter','v1',rpad('p_%[2]s',64,'0'),rpad('s_%[2]s',64,'0'),rpad('e_%[2]s',64,'0'),'%[1]s','ext_%[2]s',now(),'{}'::jsonb);
INSERT INTO vendor_adapter_idempotency(tenant_id,scope,idempotency_key,source_sha256,record_id,receipt_json)
VALUES ('%[1]s','vendor','videm_%[2]s',rpad('s_%[2]s',64,'0'),'vrecord_%[2]s','{}'::jsonb);
INSERT INTO vendor_adapter_audit(tenant_id,stream_id,sequence,previous_audit_sha256,audit_sha256,occurred_at,action,object_type,object_id,details)
VALUES ('%[1]s','vstream_%[2]s',1,'',rpad('vaudit_%[2]s',64,'0'),now(),'vendor_alert_ingested','vendor_adapter_record','vrecord_%[2]s','{}'::jsonb);
INSERT INTO operational_outbox_message(message_id,topic,tenant_id,idempotency_key,payload_sha256,message_sha256,max_attempts,created_at,message_json)
VALUES ('msg_%[2]s','alerts','%[1]s','idemmsg_%[2]s',rpad('pay_%[2]s',64,'0'),rpad('msgsha_%[2]s',64,'0'),5,now(),'{}'::jsonb);
INSERT INTO operational_outbox_event(tenant_id,stream_id,sequence,event_sha256,previous_event_sha256,message_id,occurred_at,action,attempt,event_json)
VALUES ('%[1]s','ostream_%[2]s',1,rpad('oevt_%[2]s',64,'0'),'','msg_%[2]s',now(),'enqueued',0,'{}'::jsonb);
INSERT INTO review_security_audit_event(stream_id,sequence,previous_event_sha256,event_sha256,occurred_at,request_id,tenant_id,method,path,outcome,status_code)
VALUES ('rstream_%[2]s',1,'',rpad('revt_%[2]s',64,'0'),now(),'req_%[2]s','%[1]s','GET','/v1/alerts','allowed',200);
`, tenant, suffix)
	mustRunSEC1SQL(t, migratorURL, sql)
}

func TestSEC1TwoTenantIsolation(t *testing.T) {
	testURL := requireSEC1TestDatabaseURL(t)
	migratorURL := requireSEC1MigratorDatabaseURL(t)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	suffixX := suffix + "x"
	suffixY := suffix + "y"
	seedSEC1Tenant(t, migratorURL, sec1TenantX, suffixX)
	seedSEC1Tenant(t, migratorURL, sec1TenantY, suffixY)

	t.Run("ReadIsolation", func(t *testing.T) {
		for _, rel := range sec1TenantScopedRelations {
			rel := rel
			t.Run(rel, func(t *testing.T) {
				sql := fmt.Sprintf("SELECT set_config('openwatchlist.tenant_id','%s',false); SELECT count(*) FROM %s WHERE tenant_id='%s';",
					sec1TenantX, rel, sec1TenantY)
				out := mustRunSEC1SQL(t, testURL, sql)
				if got := lastSEC1Line(out); got != "0" {
					t.Fatalf("tenant %s could see %d row(s) in %s belonging to tenant %s", sec1TenantX, mustAtoi(t, got), rel, sec1TenantY)
				}
			})
		}
	})

	t.Run("WriteIsolationInsertRejected", func(t *testing.T) {
		sql := fmt.Sprintf(`SELECT set_config('openwatchlist.tenant_id','%s',false);
INSERT INTO alert_record(alert_id,tenant_id,source_type,source_identity,record_sha256,policy_route,created_at,alert_json)
VALUES ('alert_forged_%s','%s','external_alert','src','sha_forged_%s','clear',now(),'{}'::jsonb);`,
			sec1TenantX, suffix, sec1TenantY, suffix)
		_, err := runSEC1SQL(t, testURL, sql)
		if err == nil {
			t.Fatal("expected tenant X's INSERT labelled tenant Y to be rejected by WITH CHECK, but it succeeded")
		}
		if !strings.Contains(err.Error(), "row-level security") {
			t.Fatalf("expected a row-level security rejection, got: %v", err)
		}
	})

	t.Run("WriteIsolationUpdateOtherTenantNoOp", func(t *testing.T) {
		// alert_case is the one mutable tenant-scoped relation (no
		// immutability trigger, ADR §4). Bound as tenant X, an UPDATE
		// targeting tenant Y's row must affect zero rows -- USING hides
		// the row entirely rather than raising an error, matching
		// Postgres RLS's normal "not visible" semantics for UPDATE/DELETE.
		update := fmt.Sprintf(`SELECT set_config('openwatchlist.tenant_id','%s',false);
UPDATE alert_case SET state='closed' WHERE case_id='case_%s';`, sec1TenantX, suffixY)
		mustRunSEC1SQL(t, testURL, update)
		verify := fmt.Sprintf(`SELECT set_config('openwatchlist.tenant_id','%s',false); SELECT state FROM alert_case WHERE case_id='case_%s';`, sec1TenantY, suffixY)
		if got := lastSEC1Line(mustRunSEC1SQL(t, testURL, verify)); got != "open" {
			t.Fatalf("tenant %s's UPDATE against tenant %s's alert_case row was not blocked: state=%q, want %q", sec1TenantX, sec1TenantY, got, "open")
		}
	})

	t.Run("WriteIsolationDeleteOtherTenantNoOp", func(t *testing.T) {
		del := fmt.Sprintf(`SELECT set_config('openwatchlist.tenant_id','%s',false);
DELETE FROM alert_case WHERE case_id='case_%s';`, sec1TenantX, suffixY)
		mustRunSEC1SQL(t, testURL, del)
		verify := fmt.Sprintf(`SELECT set_config('openwatchlist.tenant_id','%s',false); SELECT count(*) FROM alert_case WHERE case_id='case_%s';`, sec1TenantY, suffixY)
		if got := lastSEC1Line(mustRunSEC1SQL(t, testURL, verify)); got != "1" {
			t.Fatalf("tenant %s's DELETE against tenant %s's alert_case row was not blocked: row count=%s, want 1", sec1TenantX, sec1TenantY, got)
		}
	})

	t.Run("FailClosedNoGUCBound", func(t *testing.T) {
		// A brand-new session/statement with no set_config call at all.
		if got := lastSEC1Line(mustRunSEC1SQL(t, testURL, "SELECT count(*) FROM alert_record;")); got != "0" {
			t.Fatalf("expected zero rows visible with no tenant GUC bound, got %s -- fail-closed means zero rows, never full visibility", got)
		}
		sql := fmt.Sprintf(`INSERT INTO alert_record(alert_id,tenant_id,source_type,source_identity,record_sha256,policy_route,created_at,alert_json)
VALUES ('alert_unbound_%s','%s','external_alert','src','sha_unbound_%s','clear',now(),'{}'::jsonb);`, suffix, sec1TenantX, suffix)
		if _, err := runSEC1SQL(t, testURL, sql); err == nil {
			t.Fatal("expected an INSERT with no tenant GUC bound to be rejected, but it succeeded")
		}
	})

	t.Run("NoLeakAcrossReusedSession", func(t *testing.T) {
		sql := fmt.Sprintf(`
BEGIN;
SELECT set_config('openwatchlist.tenant_id','%[1]s',true);
SELECT count(*) FROM alert_record WHERE tenant_id='%[2]s';
COMMIT;
BEGIN;
SELECT set_config('openwatchlist.tenant_id','%[2]s',true);
SELECT count(*) FROM alert_record WHERE tenant_id='%[1]s';
COMMIT;
`, sec1TenantX, sec1TenantY)
		out := mustRunSEC1SQL(t, testURL, sql)
		var counts []string
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "0" || line == "1" {
				counts = append(counts, line)
			}
		}
		if len(counts) != 2 {
			t.Fatalf("expected exactly 2 count results in this session's output, got %v (full output: %q)", counts, out)
		}
		if counts[0] != "0" {
			t.Fatalf("first transaction (bound tenant X) saw %s row(s) of tenant Y's data", counts[0])
		}
		if counts[1] != "0" {
			t.Fatalf("second transaction on the SAME session (bound tenant Y) saw %s row(s) of tenant X's data -- is_local=true binding leaked across transactions", counts[1])
		}
	})

	t.Run("IdempotencySameKeySameBodyAcrossTenantsBothSucceed", func(t *testing.T) {
		key := "idem_shared_" + suffix
		sql := fmt.Sprintf(`
SELECT set_config('openwatchlist.tenant_id','%[1]s',false);
INSERT INTO alert_case_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[1]s','shared-scope','%[3]s','reqX','respX','alert','alert_%[4]s',now(),'{}'::jsonb);
SELECT set_config('openwatchlist.tenant_id','%[2]s',false);
INSERT INTO alert_case_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[2]s','shared-scope','%[3]s','reqY','respY','alert','alert_%[5]s',now(),'{}'::jsonb);
`, sec1TenantX, sec1TenantY, key, suffixX, suffixY)
		if _, err := runSEC1SQL(t, testURL, sql); err != nil {
			t.Fatalf("the same (scope,key_sha256) under two different tenants should both succeed independently -- tenant_id is part of the primary key now: %v", err)
		}
	})

	t.Run("IdempotencySameKeyDifferentBodySameTenantSurfaces23505", func(t *testing.T) {
		key := "idem_conflict_" + suffix
		first := fmt.Sprintf(`SELECT set_config('openwatchlist.tenant_id','%[1]s',false);
INSERT INTO alert_case_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[1]s','conflict-scope','%[2]s','reqA','respA','alert','alert_%[3]s',now(),'{}'::jsonb);`, sec1TenantX, key, suffixX)
		mustRunSEC1SQL(t, testURL, first)
		second := fmt.Sprintf(`SELECT set_config('openwatchlist.tenant_id','%[1]s',false);
INSERT INTO alert_case_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[1]s','conflict-scope','%[2]s','reqB','respB','alert','alert_%[3]s',now(),'{}'::jsonb);`, sec1TenantX, key, suffixX)
		_, err := runSEC1SQL(t, testURL, second)
		if err == nil {
			t.Fatal("expected the second insert with the same (tenant_id,scope,key_sha256) to be rejected, not silently accepted -- ON CONFLICT DO NOTHING must not be swallowing this")
		}
		if !strings.Contains(err.Error(), "duplicate key") {
			t.Fatalf("expected a duplicate-key (23505) rejection, got: %v", err)
		}
	})

	// FKCrossing: Postgres foreign-key/referential-integrity checks
	// bypass row security by design (documented Postgres behavior -- an
	// RI check must see the referenced row regardless of the querying
	// session's row visibility, or it could not enforce integrity at
	// all). Confirmed empirically while building migration 014: bound as
	// one tenant, a plain INSERT into alert_case_membership referencing
	// another tenant's real alert_record row succeeded, because the row's
	// own WITH CHECK passed (its own tenant_id matched the GUC) and the
	// FK check to alert_record ignored RLS entirely. Migration 014
	// closes this with an explicit EXISTS subquery in WITH CHECK for
	// every Class B relation that references another Class A/B relation
	// (an EXISTS subquery, unlike an FK check, is an ordinary query and
	// IS subject to RLS) -- ten of the eleven; operational_outbox_message
	// has no incoming reference to verify. Each one gets its own subtest
	// here rather than one generic case, because a subquery correct for
	// one relation's column names and object_type values does not prove
	// the pattern was applied correctly to the other nine.
	t.Run("FKCrossing", func(t *testing.T) {
		cases := []struct {
			name string
			sql  string
		}{
			{
				"alert_case_membership_alert_leg",
				fmt.Sprintf(`INSERT INTO alert_case_membership(tenant_id,case_id,alert_id,joined_at) VALUES ('%[1]s','case_%[2]s','alert_%[3]s',now());`,
					sec1TenantX, suffixX, suffixY),
			},
			{
				"alert_case_event",
				fmt.Sprintf(`INSERT INTO alert_case_event(tenant_id,case_id,sequence,revision,event_sha256,previous_event_sha256,occurred_at,action,actor,event_json)
VALUES ('%[1]s','case_%[2]s',999,1,'forged_evt_%[2]s','',now(),'case_created','system','{}'::jsonb);`, sec1TenantX, suffixY),
			},
			{
				"alert_case_idempotency_case_branch",
				fmt.Sprintf(`INSERT INTO alert_case_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[1]s','forged-scope-%[2]s','forged_key_%[2]s','r','r','case','case_%[2]s',now(),'{}'::jsonb);`, sec1TenantX, suffixY),
			},
			{
				"alert_case_audit_alert_branch",
				fmt.Sprintf(`INSERT INTO alert_case_audit(tenant_id,stream_id,sequence,audit_sha256,previous_audit_sha256,occurred_at,action,actor,object_type,object_id,audit_json)
VALUES ('%[1]s','forged-stream-%[2]s','999','forged_audit_%[2]s','',now(),'alert_created','system','alert','alert_%[2]s','{}'::jsonb);`, sec1TenantX, suffixY),
			},
			{
				"case_assistance_review",
				fmt.Sprintf(`INSERT INTO case_assistance_review(tenant_id,assistance_id,case_id,sequence,event_sha256,previous_event_sha256,action,actor,reason,occurred_at,event_json)
VALUES ('%[1]s','assistance_%[2]s','case_%[3]s',999,'forged_review_%[2]s','','accept','analyst','x',now(),'{}'::jsonb);`, sec1TenantX, suffixY, suffixX),
			},
			{
				"case_assistance_idempotency_assistance_branch",
				fmt.Sprintf(`INSERT INTO case_assistance_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[1]s','forged-assist-scope-%[2]s','forged_key2_%[2]s','r','r','assistance','assistance_%[2]s',now(),'{}'::jsonb);`, sec1TenantX, suffixY),
			},
			{
				"case_assistance_idempotency_review_event_branch_via_scope",
				fmt.Sprintf(`INSERT INTO case_assistance_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[1]s','review:assistance_%[2]s','forged_key3_%[2]s','r','r','review_event','1',now(),'{}'::jsonb);`, sec1TenantX, suffixY),
			},
			{
				"case_assistance_audit",
				fmt.Sprintf(`INSERT INTO case_assistance_audit(tenant_id,stream_id,sequence,audit_sha256,previous_audit_sha256,occurred_at,action,actor,object_type,object_id,audit_json)
VALUES ('%[1]s','forged-cstream-%[2]s','999','forged_caudit_%[2]s','',now(),'assistance_recorded','system','assistance','assistance_%[2]s','{}'::jsonb);`, sec1TenantX, suffixY),
			},
			{
				"vendor_adapter_idempotency",
				fmt.Sprintf(`INSERT INTO vendor_adapter_idempotency(tenant_id,scope,idempotency_key,source_sha256,record_id,receipt_json)
VALUES ('%[1]s','forged-vendor-%[2]s','forged_videm_%[2]s',rpad('x',64,'0'),'vrecord_%[2]s','{}'::jsonb);`, sec1TenantX, suffixY),
			},
			{
				"vendor_adapter_audit",
				fmt.Sprintf(`INSERT INTO vendor_adapter_audit(tenant_id,stream_id,sequence,previous_audit_sha256,audit_sha256,occurred_at,action,object_type,object_id,details)
VALUES ('%[1]s','forged-vstream-%[2]s',999,'',rpad('forged_vaudit_%[2]s',64,'0'),now(),'vendor_alert_ingested','vendor_adapter_record','vrecord_%[2]s','{}'::jsonb);`, sec1TenantX, suffixY),
			},
			{
				"operational_outbox_event",
				fmt.Sprintf(`INSERT INTO operational_outbox_event(tenant_id,stream_id,sequence,event_sha256,previous_event_sha256,message_id,occurred_at,action,attempt,event_json)
VALUES ('%[1]s','forged-ostream-%[2]s',999,rpad('forged_oevt_%[2]s',64,'0'),'','msg_%[2]s',now(),'enqueued',0,'{}'::jsonb);`, sec1TenantX, suffixY),
			},
		}
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				sql := fmt.Sprintf("SELECT set_config('openwatchlist.tenant_id','%s',false);\n%s", sec1TenantX, c.sql)
				_, err := runSEC1SQL(t, testURL, sql)
				if err == nil {
					t.Fatalf("expected tenant X's %s row referencing tenant Y's parent to be rejected, but it succeeded", c.name)
				}
				if !strings.Contains(err.Error(), "row-level security") && !strings.Contains(err.Error(), "violates check") {
					t.Fatalf("expected a row-level security rejection, got: %v", err)
				}
			})
		}

		// Same-tenant writes through the exact same WITH CHECK subqueries
		// must still succeed -- proving the checks are correctly
		// restrictive, not just restrictive.
		t.Run("SameTenantStillSucceeds", func(t *testing.T) {
			sql := fmt.Sprintf(`SELECT set_config('openwatchlist.tenant_id','%[1]s',false);
INSERT INTO case_assistance_idempotency(tenant_id,scope,key_sha256,request_sha256,response_sha256,object_type,object_id,created_at,receipt_json)
VALUES ('%[1]s','legit-scope-%[2]s','legit_key_%[2]s','r','r','assistance','assistance_%[2]s',now(),'{}'::jsonb);
INSERT INTO vendor_adapter_idempotency(tenant_id,scope,idempotency_key,source_sha256,record_id,receipt_json)
VALUES ('%[1]s','legit-vendor-%[2]s','legit_videm_%[2]s',rpad('x',64,'0'),'vrecord_%[2]s','{}'::jsonb);
INSERT INTO operational_outbox_event(tenant_id,stream_id,sequence,event_sha256,previous_event_sha256,message_id,occurred_at,action,attempt,event_json)
VALUES ('%[1]s','legit-ostream-%[2]s',999,rpad('legit_oevt_%[2]s',64,'0'),'','msg_%[2]s',now(),'enqueued',0,'{}'::jsonb);
`, sec1TenantX, suffixX)
			if _, err := runSEC1SQL(t, testURL, sql); err != nil {
				t.Fatalf("expected same-tenant writes through the new WITH CHECK subqueries to succeed, got: %v", err)
			}
		})
	})

	t.Run("ProvenanceMismatchedBodyTenantRejected", func(t *testing.T) {
		sink, err := alertcase.NewPostgresSink(testURL, "psql", nil, 10*time.Second)
		if err != nil {
			t.Fatalf("construct alertcase.PostgresSink: %v", err)
		}
		boundTenant, err := tenantctx.Resolve(reviewauth.Claims{TenantID: sec1TenantX})
		if err != nil {
			t.Fatalf("resolve bound tenant: %v", err)
		}
		ctx := tenantctx.NewContext(context.Background(), boundTenant)
		alertID := "alert_provenance_" + suffix
		alert := alertcase.AlertRecord{
			SchemaVersion:  alertcase.AlertSchemaV1,
			AlertID:        alertID,
			TenantID:       sec1TenantY, // body asserts a DIFFERENT tenant than ctx is bound to
			SourceType:     "external_alert",
			SourceIdentity: "src",
			RecordSHA256:   "sha_provenance_" + suffix,
			CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		}
		receipt := alertcase.IdempotencyReceipt{
			Scope: "create-alert", KeySHA256: "key_provenance_" + suffix,
			ObjectType: "alert", ObjectID: alertID, CreatedAt: alert.CreatedAt,
		}
		err = sink.PersistAlert(ctx, alert, receipt)
		if !errors.Is(err, tenantctx.ErrTenantMismatch) {
			t.Fatalf("expected PersistAlert to reject a body tenant_id disagreeing with the ctx-bound tenant via tenantctx.ErrTenantMismatch, got: %v", err)
		}
		// Confirm no row was written by any sink -- not just that Go
		// returned an error before reaching Postgres, but that Postgres
		// itself holds nothing under this alert_id, for any tenant.
		verify := fmt.Sprintf(`SELECT set_config('openwatchlist.tenant_id','*',false); SELECT count(*) FROM alert_record WHERE alert_id='%s';`, alertID)
		if got := lastSEC1Line(mustRunSEC1SQL(t, migratorURL, verify)); got != "0" {
			t.Fatalf("expected no alert_record row to exist after a rejected provenance mismatch, found %s", got)
		}
	})
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}
