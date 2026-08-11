-- SEC-1: tenant isolation migration (ADR-0001, §5/§6). The migration PR in
-- the ADR's explicit sequencing (gate PR #68 -> seam PR #70 -> this).
--
-- Adds tenant_id to the 10 Class B relations that lack it, backfills every
-- value from a join to the owning Class A record (no defaults, no
-- sentinels -- an unresolvable row aborts the migration), forces RLS on
-- every Class A and Class B relation, and re-scopes three idempotency-key
-- primary keys to include tenant_id (ADR §6).
--
-- screening_idempotency_receipt is deliberately NOT touched here, unlike
-- what an earlier draft of ADR §6 assumed. internal/screeningapi has no
-- tenant concept anywhere in the Go tree to backfill from or write going
-- forward (confirmed by inspection: no TenantID field on screeningledger's
-- Event/SnapshotEnvelope, no tenant string in internal/screeningapi at
-- all) -- unlike alertcaseapi/assistanceapi/vendoradapterapi, whose sinks
-- already assert a bound tenant via tenantctx.Assert (seam PR #70). Per
-- ADR §9, Class C's historical-attribution question is explicitly SEC-1c,
-- not this migration; screening_idempotency_receipt stays in that
-- deferral rather than getting a column this PR cannot honestly populate.
-- See the ADR addendum for the corrected §6/§9 text.
--
-- Ordering is load-bearing (ADR §5): the seam (#70) is already live and
-- inert until policy exists; this migration creates that policy; FORCE
-- lands as part of this same migration for Class A (already forced by
-- #69/013) and, newly, for Class B. Landing FORCE before the seam was
-- deployed would take every write path to zero rows; that ordering
-- constraint is already satisfied on this branch.
BEGIN;
SELECT pg_advisory_xact_lock(hashtext('openwatchlist-sec1-migration-014'));

-- owl_migrator ran the CREATE TABLE statements for every Class A relation
-- (009ab/009c/009e/009f), so it owns them -- and alert_record, alert_case,
-- case_assistance_record and vendor_adapter_record already carry FORCE
-- ROW LEVEL SECURITY (013_force_rls.sql, already merged). FORCE applies
-- to the owner too, so without a bound GUC every join below against a
-- Class A table -- the cross-tenant pre-check in section (e), and every
-- backfill UPDATE in section (d) -- would silently see zero rows: not
-- because no row matches, but because RLS hides all of them. That is a
-- looks-installed-does-nothing failure this migration would not have
-- caught against an empty database (nothing to hide), and did not catch
-- until tested against seeded data with a real cross-tenant row present.
-- '*' is the operator escape hatch openwatchlist_tenant_visible() already
-- defines (009g:84-85); binding it here, for owl_migrator only, for the
-- lifetime of this transaction (is_local=true, so it cannot leak past
-- COMMIT/ROLLBACK), is what makes this role's own reads see every
-- tenant's rows during backfill. This does not touch invariant 6
-- (test/sql/security_invariants.sql): that invariant is about the
-- wildcard being unreachable from owl_app, a distinct, less-privileged
-- role that never runs a migration file.
SELECT set_config('openwatchlist.tenant_id', '*', true);

-- ---------------------------------------------------------------------
-- (a) Fail-closed preamble. Aborts if any of the 16 tenant-scoped
-- relations (db/tenant_scoped_tables.txt) is absent, in the idiom of
-- 012_truncate_guards.sql / 013_force_rls.sql -- not 009g's
-- "IF to_regclass(t) IS NOT NULL THEN" pattern, which is why 009g shipped
-- controls that silently skipped absent tables.
-- ---------------------------------------------------------------------
DO $$
DECLARE
  t text;
  relations text[] := ARRAY[
    'alert_record','alert_case','case_assistance_record','vendor_adapter_record','review_security_audit_event',
    'alert_case_membership','alert_case_event','alert_case_idempotency','alert_case_audit',
    'case_assistance_review','case_assistance_idempotency','case_assistance_audit',
    'vendor_adapter_idempotency','vendor_adapter_audit',
    'operational_outbox_event','operational_outbox_message'
  ];
BEGIN
  FOREACH t IN ARRAY relations LOOP
    IF to_regclass(t) IS NULL THEN
      RAISE EXCEPTION 'SEC-1 migration 014: relation % does not exist; all 16 relations in db/tenant_scoped_tables.txt must be present', t;
    END IF;
  END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- (b) ADD COLUMN, nullable, on the 10 Class B relations that need a
-- backfill. operational_outbox_message already carries tenant_id NOT
-- NULL since 009g:22 and needs no column change -- it only needs policy
-- and FORCE, applied in section (f) below.
-- ---------------------------------------------------------------------
ALTER TABLE alert_case_membership ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE alert_case_event ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE alert_case_idempotency ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE alert_case_audit ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE case_assistance_review ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE case_assistance_idempotency ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE case_assistance_audit ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE vendor_adapter_idempotency ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE vendor_adapter_audit ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE operational_outbox_event ADD COLUMN IF NOT EXISTS tenant_id text;

-- ---------------------------------------------------------------------
-- (e) alert_case_membership cross-tenant pre-check. Runs before any
-- backfill proceeds: a membership row joining one tenant's case to
-- another tenant's alert is a pre-existing isolation violation, and the
-- migration must abort on finding one rather than picking a side (ADR
-- §5). This is independent of the tenant_id column just added -- it
-- checks alert_case.tenant_id against alert_record.tenant_id, both of
-- which are already populated (Class A).
-- ---------------------------------------------------------------------
DO $$
DECLARE
  violation_count bigint;
BEGIN
  SELECT count(*) INTO violation_count
    FROM alert_case_membership m
    JOIN alert_case c ON c.case_id = m.case_id
    JOIN alert_record a ON a.alert_id = m.alert_id
   WHERE c.tenant_id <> a.tenant_id;
  IF violation_count > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: % alert_case_membership row(s) join a case and an alert with different tenant_id -- pre-existing cross-tenant violation; aborting rather than picking a side. Query: SELECT m.case_id, m.alert_id FROM alert_case_membership m JOIN alert_case c ON c.case_id = m.case_id JOIN alert_record a ON a.alert_id = m.alert_id WHERE c.tenant_id <> a.tenant_id;', violation_count;
  END IF;
END $$;

-- ---------------------------------------------------------------------
-- (c)/(d) Immutability-trigger workaround and per-table backfill
-- derivation. DISABLE TRIGGER USER / backfill / ENABLE TRIGGER USER
-- around each relation's UPDATE, rather than
-- SET session_replication_role = 'replica' -- ADR §5 explicitly rejects
-- that alternative, because it also disables foreign-key enforcement
-- session-wide, exactly during the window these joins depend on FKs
-- being sound. DISABLE TRIGGER USER disables both the row-level
-- immutability trigger and the statement-level TRUNCATE guard (012); both
-- are re-enabled immediately after each table's backfill, and verified
-- re-enabled for every listed relation at the end of this section.
--
-- Each backfill is followed immediately by a check that every row
-- resolved -- no COALESCE, no fallback value: a row whose owner cannot be
-- derived is a data-integrity finding that aborts the migration with the
-- relation name and count, per ADR §5.
-- ---------------------------------------------------------------------

-- alert_case_event <- alert_case via case_id.
ALTER TABLE alert_case_event DISABLE TRIGGER USER;
UPDATE alert_case_event e SET tenant_id = c.tenant_id
  FROM alert_case c WHERE c.case_id = e.case_id;
ALTER TABLE alert_case_event ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM alert_case_event WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: alert_case_event has % row(s) with no derivable tenant_id (case_id not found in alert_case)', unresolved;
  END IF;
END $$;

-- alert_case_membership <- alert_case via case_id. (Already cross-checked
-- above against alert_record via alert_id; both give the same value by
-- construction now that the check passed.)
ALTER TABLE alert_case_membership DISABLE TRIGGER USER;
UPDATE alert_case_membership m SET tenant_id = c.tenant_id
  FROM alert_case c WHERE c.case_id = m.case_id;
ALTER TABLE alert_case_membership ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM alert_case_membership WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: alert_case_membership has % row(s) with no derivable tenant_id (case_id not found in alert_case)', unresolved;
  END IF;
END $$;

-- alert_case_idempotency <- object_type + object_id join to alert_case or
-- alert_record. object_type is always 'alert' or 'case' for rows that
-- reach Postgres: internal/alertcase/store.go's saveReceipt call sites are
-- "alert" (create-alert, object_id=alert_id) and "case" (create-case and
-- case mutations, object_id=case_id). A third scope, "alert_batch"
-- (create-alert-batch), exists only in the file-based store -- the batch
-- HTTP handler persists each constituent alert individually under the
-- "alert" scope (internal/alertcaseapi/server.go's createAlertBatch), so
-- PostgresSink never writes an "alert_batch" row; confirmed by inspection,
-- not assumed. The ELSE branch exists so a row that somehow doesn't match
-- either known type aborts via the unresolved-count check below rather
-- than silently passing through.
ALTER TABLE alert_case_idempotency DISABLE TRIGGER USER;
UPDATE alert_case_idempotency i SET tenant_id = (
  CASE
    WHEN i.object_type = 'alert' THEN (SELECT a.tenant_id FROM alert_record a WHERE a.alert_id = i.object_id)
    WHEN i.object_type = 'case' THEN (SELECT c.tenant_id FROM alert_case c WHERE c.case_id = i.object_id)
    ELSE NULL
  END
);
ALTER TABLE alert_case_idempotency ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM alert_case_idempotency WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: alert_case_idempotency has % row(s) with no derivable tenant_id (object_type/object_id not found in alert_case or alert_record)', unresolved;
  END IF;
END $$;

-- alert_case_audit <- object_type + object_id join to alert_case or
-- alert_record. object_type is always 'alert' or 'case'
-- (internal/alertcase/store.go's appendAuditUnlocked call sites: alert
-- creation uses "alert"/alert_id, case creation and case mutations use
-- "case"/case_id -- confirmed by inspection, no third variant here).
ALTER TABLE alert_case_audit DISABLE TRIGGER USER;
UPDATE alert_case_audit d SET tenant_id = (
  CASE
    WHEN d.object_type = 'alert' THEN (SELECT a.tenant_id FROM alert_record a WHERE a.alert_id = d.object_id)
    WHEN d.object_type = 'case' THEN (SELECT c.tenant_id FROM alert_case c WHERE c.case_id = d.object_id)
    ELSE NULL
  END
);
ALTER TABLE alert_case_audit ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM alert_case_audit WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: alert_case_audit has % row(s) with no derivable tenant_id (object_type/object_id not found in alert_case or alert_record)', unresolved;
  END IF;
END $$;

-- case_assistance_review <- case_assistance_record via assistance_id.
ALTER TABLE case_assistance_review DISABLE TRIGGER USER;
UPDATE case_assistance_review v SET tenant_id = c.tenant_id
  FROM case_assistance_record c WHERE c.assistance_id = v.assistance_id;
ALTER TABLE case_assistance_review ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM case_assistance_review WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: case_assistance_review has % row(s) with no derivable tenant_id (assistance_id not found in case_assistance_record)', unresolved;
  END IF;
END $$;

-- case_assistance_idempotency <- object_id join to case_assistance_record,
-- EXCEPT: this table carries two distinct object_type shapes, confirmed
-- by inspection of internal/assistancerag/store.go, not assumed from ADR
-- §5's summary alone --
--   "assistance" (Assist(): object_id = assistance_id, directly joinable)
--   "review_event" (Review(): object_id = a per-assistance sequence
--     number, e.g. "1", "2" -- NOT an assistance_id). The real owner is
--     still derivable: Review() always saves this receipt under scope
--     "review:"+assistance_id (store.go:369), so the assistance_id is
--     recovered from the scope column instead of object_id. This is a
--     join on a different column than §5's shorthand implied, not a
--     fallback value -- the scope string deterministically encodes the
--     assistance_id by construction of every call site that writes it.
ALTER TABLE case_assistance_idempotency DISABLE TRIGGER USER;
UPDATE case_assistance_idempotency i SET tenant_id = (
  CASE
    WHEN i.object_type = 'assistance' THEN
      (SELECT c.tenant_id FROM case_assistance_record c WHERE c.assistance_id = i.object_id)
    WHEN i.object_type = 'review_event' AND i.scope LIKE 'review:%' THEN
      (SELECT c.tenant_id FROM case_assistance_record c WHERE c.assistance_id = substring(i.scope FROM length('review:') + 1))
    ELSE NULL
  END
);
ALTER TABLE case_assistance_idempotency ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM case_assistance_idempotency WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: case_assistance_idempotency has % row(s) with no derivable tenant_id (object_type/object_id/scope did not resolve to a case_assistance_record)', unresolved;
  END IF;
END $$;

-- case_assistance_audit <- object_id join to case_assistance_record.
-- object_type is always "assistance" here (both appendAudit call sites in
-- internal/assistancerag/store.go use "assistance"/assistance_id; the
-- review_event ambiguity above is specific to the idempotency receipt's
-- saveReceipt call, not the audit append) -- confirmed by inspection.
ALTER TABLE case_assistance_audit DISABLE TRIGGER USER;
UPDATE case_assistance_audit d SET tenant_id = c.tenant_id
  FROM case_assistance_record c WHERE c.assistance_id = d.object_id AND d.object_type = 'assistance';
ALTER TABLE case_assistance_audit ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM case_assistance_audit WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: case_assistance_audit has % row(s) with no derivable tenant_id (object_type/object_id not found in case_assistance_record)', unresolved;
  END IF;
END $$;

-- vendor_adapter_idempotency <- record_id join to vendor_adapter_record.
-- record_id already carries a NOT NULL FK to vendor_adapter_record
-- (009e_vendor_adapter_ingress.sql:11), so this join is guaranteed to
-- resolve for every existing row.
ALTER TABLE vendor_adapter_idempotency DISABLE TRIGGER USER;
UPDATE vendor_adapter_idempotency i SET tenant_id = r.tenant_id
  FROM vendor_adapter_record r WHERE r.record_id = i.record_id;
ALTER TABLE vendor_adapter_idempotency ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM vendor_adapter_idempotency WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: vendor_adapter_idempotency has % row(s) with no derivable tenant_id (record_id not found in vendor_adapter_record)', unresolved;
  END IF;
END $$;

-- vendor_adapter_audit <- object_id join to vendor_adapter_record.
-- record_id. object_type is always "vendor_adapter_record"
-- (internal/vendoradapter/store.go's sole appendAudit call site) --
-- confirmed by inspection, single call site, no ambiguity.
ALTER TABLE vendor_adapter_audit DISABLE TRIGGER USER;
UPDATE vendor_adapter_audit d SET tenant_id = r.tenant_id
  FROM vendor_adapter_record r WHERE r.record_id = d.object_id AND d.object_type = 'vendor_adapter_record';
ALTER TABLE vendor_adapter_audit ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM vendor_adapter_audit WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: vendor_adapter_audit has % row(s) with no derivable tenant_id (object_type/object_id not found in vendor_adapter_record)', unresolved;
  END IF;
END $$;

-- operational_outbox_event <- message_id join to operational_outbox_message.
-- message_id already carries a NOT NULL FK to operational_outbox_message
-- (009g_production_hardening.sql:37), so this join is guaranteed to
-- resolve for every existing row.
ALTER TABLE operational_outbox_event DISABLE TRIGGER USER;
UPDATE operational_outbox_event e SET tenant_id = m.tenant_id
  FROM operational_outbox_message m WHERE m.message_id = e.message_id;
ALTER TABLE operational_outbox_event ENABLE TRIGGER USER;
DO $$
DECLARE unresolved bigint;
BEGIN
  SELECT count(*) INTO unresolved FROM operational_outbox_event WHERE tenant_id IS NULL;
  IF unresolved > 0 THEN
    RAISE EXCEPTION 'SEC-1 migration 014: operational_outbox_event has % row(s) with no derivable tenant_id (message_id not found in operational_outbox_message)', unresolved;
  END IF;
END $$;

-- ---------------------------------------------------------------------
-- Verify no user trigger was left disabled by the workaround above. A
-- migration that half-completes and leaves immutability off is a worse
-- outcome than one that fails (ADR §5).
-- ---------------------------------------------------------------------
DO $$
DECLARE
  t text;
  disabled_count bigint;
  relations text[] := ARRAY[
    'alert_case_event','alert_case_membership','alert_case_idempotency','alert_case_audit',
    'case_assistance_review','case_assistance_idempotency','case_assistance_audit',
    'vendor_adapter_idempotency','vendor_adapter_audit','operational_outbox_event'
  ];
BEGIN
  FOREACH t IN ARRAY relations LOOP
    SELECT count(*) INTO disabled_count
      FROM pg_trigger
     WHERE tgrelid = t::regclass AND NOT tgisinternal AND tgenabled = 'D';
    IF disabled_count > 0 THEN
      RAISE EXCEPTION 'SEC-1 migration 014: relation % has % user trigger(s) left disabled after backfill; aborting rather than leaving immutability off', t, disabled_count;
    END IF;
  END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- (f) Seal: SET NOT NULL now that every Class B relation's tenant_id is
-- fully backfilled (checked above), then ENABLE + FORCE for all of
-- Class A and Class B, then policy.
--
-- review_security_audit_event (Class A) gets the same bare predicate as
-- every other relation, not special-cased: 009g's policy admitted NULL
-- tenant_id to every caller via an explicit "tenant_id IS NULL OR ..."
-- clause. openwatchlist_tenant_visible(row_tenant) alone already
-- evaluates NULL = current_setting(...) to NULL (excluded) unless the GUC
-- is the operator wildcard '*', in which case the OR's first branch
-- admits it -- i.e. bare openwatchlist_tenant_visible(tenant_id) already
-- means "NULL-tenant rows visible to the operator role only," which is
-- exactly ADR §4's tightened requirement. The fix is deleting the extra
-- clause, not adding a new one.
-- ---------------------------------------------------------------------
ALTER TABLE alert_case_membership ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE alert_case_event ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE alert_case_idempotency ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE alert_case_audit ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE case_assistance_review ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE case_assistance_idempotency ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE case_assistance_audit ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE vendor_adapter_idempotency ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE vendor_adapter_audit ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE operational_outbox_event ALTER COLUMN tenant_id SET NOT NULL;

DO $$
DECLARE
  t text;
  relations text[] := ARRAY[
    'alert_record','alert_case','case_assistance_record','vendor_adapter_record','review_security_audit_event',
    'alert_case_membership','alert_case_event','alert_case_idempotency','alert_case_audit',
    'case_assistance_review','case_assistance_idempotency','case_assistance_audit',
    'vendor_adapter_idempotency','vendor_adapter_audit',
    'operational_outbox_event','operational_outbox_message'
  ];
BEGIN
  FOREACH t IN ARRAY relations LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;

-- A bare "openwatchlist_tenant_visible(tenant_id)" WITH CHECK is not
-- enough for a relation whose row references another tenant-scoped
-- relation: Postgres foreign-key checks bypass row security by design
-- (documented Postgres behavior -- RI checks must see the referenced row
-- regardless of the querying session's row visibility, or referential
-- integrity itself could not be enforced), which means a tenant-bound
-- caller could otherwise INSERT a row whose OWN tenant_id column is
-- correct while its reference points at another tenant's parent row.
-- Confirmed empirically while building this migration: a session bound
-- to one tenant successfully inserted an alert_case_membership row
-- linking its own case to a different tenant's real, existing alert --
-- the FK to alert_record did not block it.
--
-- The fix is a WITH CHECK that also verifies the referenced parent row
-- belongs to the same tenant as the row being written, via an ordinary
-- EXISTS subquery -- unlike the FK check itself, an EXISTS subquery is a
-- normal query and IS subject to the querying session's RLS, so the
-- subquery only finds the parent when it is visible under the current
-- binding. This is not needed on the read side (USING stays the bare
-- predicate): every existing row was already verified against its parent
-- at backfill time above (or, going forward, at the INSERT this same
-- WITH CHECK gates), and every listed table is either append-only
-- (immutability trigger) or, for alert_case, has no incoming reference
-- from another Class A/B relation to misdirect.
--
-- Comparing the parent's tenant_id to the child row's OWN tenant_id
-- column (not directly to current_setting('openwatchlist.tenant_id')) is
-- deliberate: for any concrete (non-wildcard) GUC the two are
-- equivalent, since the bare openwatchlist_tenant_visible(tenant_id)
-- check above already forces the child's own tenant_id to equal the GUC.
-- They diverge only under the operator wildcard ('*'), where comparing
-- directly to current_setting would require the parent to literally have
-- tenant_id='*' -- which no real row ever has -- and so would wrongly
-- reject every operator-authored write. Comparing to the child's own
-- tenant_id keeps the integrity check meaningful (parent and child must
-- agree on a real tenant) without depending on which GUC mode wrote it.
--
-- Ten of the eleven Class B relations have a reference to another Class
-- A/B relation and need this; operational_outbox_message does not (it is
-- the referenced side of operational_outbox_event, not a referencer).
DROP POLICY IF EXISTS openwatchlist_tenant_scope ON alert_case_membership;
CREATE POLICY openwatchlist_tenant_scope ON alert_case_membership
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND EXISTS (SELECT 1 FROM alert_case c WHERE c.case_id = alert_case_membership.case_id AND c.tenant_id = alert_case_membership.tenant_id)
  AND EXISTS (SELECT 1 FROM alert_record a WHERE a.alert_id = alert_case_membership.alert_id AND a.tenant_id = alert_case_membership.tenant_id)
);

DROP POLICY IF EXISTS openwatchlist_tenant_scope ON alert_case_event;
CREATE POLICY openwatchlist_tenant_scope ON alert_case_event
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND EXISTS (SELECT 1 FROM alert_case c WHERE c.case_id = alert_case_event.case_id AND c.tenant_id = alert_case_event.tenant_id)
);

-- object_type is always 'alert' or 'case' for rows that reach Postgres
-- (see the backfill section above); anything else falls through both
-- branches and is rejected, matching "no defaults, no sentinels."
DROP POLICY IF EXISTS openwatchlist_tenant_scope ON alert_case_idempotency;
CREATE POLICY openwatchlist_tenant_scope ON alert_case_idempotency
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND (
    (object_type = 'alert' AND EXISTS (SELECT 1 FROM alert_record a WHERE a.alert_id = alert_case_idempotency.object_id AND a.tenant_id = alert_case_idempotency.tenant_id))
    OR (object_type = 'case' AND EXISTS (SELECT 1 FROM alert_case c WHERE c.case_id = alert_case_idempotency.object_id AND c.tenant_id = alert_case_idempotency.tenant_id))
  )
);

DROP POLICY IF EXISTS openwatchlist_tenant_scope ON alert_case_audit;
CREATE POLICY openwatchlist_tenant_scope ON alert_case_audit
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND (
    (object_type = 'alert' AND EXISTS (SELECT 1 FROM alert_record a WHERE a.alert_id = alert_case_audit.object_id AND a.tenant_id = alert_case_audit.tenant_id))
    OR (object_type = 'case' AND EXISTS (SELECT 1 FROM alert_case c WHERE c.case_id = alert_case_audit.object_id AND c.tenant_id = alert_case_audit.tenant_id))
  )
);

DROP POLICY IF EXISTS openwatchlist_tenant_scope ON case_assistance_review;
CREATE POLICY openwatchlist_tenant_scope ON case_assistance_review
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND EXISTS (SELECT 1 FROM case_assistance_record r WHERE r.assistance_id = case_assistance_review.assistance_id AND r.tenant_id = case_assistance_review.tenant_id)
);

-- object_type is 'assistance' (object_id = assistance_id directly) or
-- 'review_event' (object_id is a per-assistance sequence number, not an
-- assistance_id -- the real owner is parsed from scope, "review:"+
-- assistance_id, the same derivation the backfill section above uses).
DROP POLICY IF EXISTS openwatchlist_tenant_scope ON case_assistance_idempotency;
CREATE POLICY openwatchlist_tenant_scope ON case_assistance_idempotency
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND (
    (object_type = 'assistance' AND EXISTS (SELECT 1 FROM case_assistance_record r WHERE r.assistance_id = case_assistance_idempotency.object_id AND r.tenant_id = case_assistance_idempotency.tenant_id))
    OR (object_type = 'review_event' AND scope LIKE 'review:%' AND EXISTS (SELECT 1 FROM case_assistance_record r WHERE r.assistance_id = substring(case_assistance_idempotency.scope FROM length('review:') + 1) AND r.tenant_id = case_assistance_idempotency.tenant_id))
  )
);

-- object_type is always 'assistance' here (unlike the idempotency table
-- above, the review_event ambiguity is specific to saveReceipt's call
-- site, not the audit append -- confirmed by inspection, see the backfill
-- section above).
DROP POLICY IF EXISTS openwatchlist_tenant_scope ON case_assistance_audit;
CREATE POLICY openwatchlist_tenant_scope ON case_assistance_audit
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND object_type = 'assistance'
  AND EXISTS (SELECT 1 FROM case_assistance_record r WHERE r.assistance_id = case_assistance_audit.object_id AND r.tenant_id = case_assistance_audit.tenant_id)
);

DROP POLICY IF EXISTS openwatchlist_tenant_scope ON vendor_adapter_idempotency;
CREATE POLICY openwatchlist_tenant_scope ON vendor_adapter_idempotency
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND EXISTS (SELECT 1 FROM vendor_adapter_record r WHERE r.record_id = vendor_adapter_idempotency.record_id AND r.tenant_id = vendor_adapter_idempotency.tenant_id)
);

-- object_type is always 'vendor_adapter_record' (internal/vendoradapter
-- /store.go's sole appendAudit call site -- confirmed by inspection).
DROP POLICY IF EXISTS openwatchlist_tenant_scope ON vendor_adapter_audit;
CREATE POLICY openwatchlist_tenant_scope ON vendor_adapter_audit
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND object_type = 'vendor_adapter_record'
  AND EXISTS (SELECT 1 FROM vendor_adapter_record r WHERE r.record_id = vendor_adapter_audit.object_id AND r.tenant_id = vendor_adapter_audit.tenant_id)
);

DROP POLICY IF EXISTS openwatchlist_tenant_scope ON operational_outbox_event;
CREATE POLICY openwatchlist_tenant_scope ON operational_outbox_event
USING (openwatchlist_tenant_visible(tenant_id))
WITH CHECK (
  openwatchlist_tenant_visible(tenant_id)
  AND EXISTS (SELECT 1 FROM operational_outbox_message m WHERE m.message_id = operational_outbox_event.message_id AND m.tenant_id = operational_outbox_event.tenant_id)
);

-- The six relations left: Class A (5, no incoming reference from another
-- Class A/B relation) plus operational_outbox_message (Class B, but
-- nothing else Class A/B references INTO it in the wrong direction --
-- operational_outbox_event references it, not the other way around).
-- These get the bare predicate on both USING and WITH CHECK -- no
-- cross-reference to verify.
DO $$
DECLARE
  t text;
  relations text[] := ARRAY[
    'alert_record','alert_case','case_assistance_record','vendor_adapter_record','review_security_audit_event',
    'operational_outbox_message'
  ];
BEGIN
  FOREACH t IN ARRAY relations LOOP
    EXECUTE format('DROP POLICY IF EXISTS openwatchlist_tenant_scope ON %I', t);
    EXECUTE format('CREATE POLICY openwatchlist_tenant_scope ON %I USING (openwatchlist_tenant_visible(tenant_id)) WITH CHECK (openwatchlist_tenant_visible(tenant_id))', t);
  END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- (g) Idempotency-key scoping (ADR §6). Exactly three relations: every
-- writer for these three already asserts a bound tenant via
-- tenantctx.Assert before this migration runs (internal/alertcase/
-- postgres.go, internal/assistancerag/postgres.go, internal/vendoradapter
-- /postgres.go -- seam PR #70), confirmed by inspection before writing
-- this migration. screening_idempotency_receipt is NOT included -- see
-- the file header and the ADR addendum.
--
-- ON CONFLICT ... DO NOTHING comes off these writes in the same PR as
-- this schema change (internal/alertcase/postgres.go,
-- internal/assistancerag/postgres.go, internal/vendoradapter/postgres.go);
-- a swallowed conflict on an idempotency write hides real divergence.
-- ---------------------------------------------------------------------
ALTER TABLE alert_case_idempotency DROP CONSTRAINT alert_case_idempotency_pkey;
ALTER TABLE alert_case_idempotency ADD PRIMARY KEY (tenant_id, scope, key_sha256);

ALTER TABLE case_assistance_idempotency DROP CONSTRAINT case_assistance_idempotency_pkey;
ALTER TABLE case_assistance_idempotency ADD PRIMARY KEY (tenant_id, scope, key_sha256);

ALTER TABLE vendor_adapter_idempotency DROP CONSTRAINT vendor_adapter_idempotency_pkey;
ALTER TABLE vendor_adapter_idempotency ADD PRIMARY KEY (tenant_id, scope, idempotency_key);

-- ---------------------------------------------------------------------
-- Rollback support (ADR §7). security_control_suspension is the lever
-- db/rollback/014_tenant_isolation_down.sql inserts into: a suspension
-- (NO FORCE ROW LEVEL SECURITY on the listed relations) must be loud --
-- invariant 5 in test/sql/security_invariants.sql fails while any row
-- here has closed_at IS NULL, holding CI red until someone closes it
-- deliberately. Deliberately not immutable like the audit tables above:
-- closing a suspension is an UPDATE by design (setting closed_at), not a
-- new row.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_control_suspension(
  suspension_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  control_id text NOT NULL,
  relations text[] NOT NULL,
  operator text NOT NULL,
  reason text NOT NULL,
  opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  closed_at timestamptz
);
DROP TRIGGER IF EXISTS security_control_suspension_no_truncate ON security_control_suspension;
CREATE TRIGGER security_control_suspension_no_truncate BEFORE TRUNCATE ON security_control_suspension FOR EACH STATEMENT EXECUTE FUNCTION owl_reject_truncate();

COMMIT;
