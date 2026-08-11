-- Emergency rollback lever for ADR-0001 SEC-1 migration 014 (§7).
--
-- NOT a schema revert. Policies are not dropped and the tenant_id backfill
-- is not reverted -- those are the expensive, hard-to-redo parts, and
-- neither one causes the outage this lever exists to stop. What actually
-- causes that outage is FORCE ROW LEVEL SECURITY rejecting every read and
-- write on a mis-bound or unbound GUC (fail-closed: zero rows and
-- rejected writes, per ADR §7), so this lever does exactly one thing:
-- ALTER TABLE ... NO FORCE ROW LEVEL SECURITY over the same explicit
-- 16-relation list migration 014 forced.
--
-- The lever is loud by design. It inserts a row into
-- security_control_suspension with closed_at left NULL, and invariant 5
-- in test/sql/security_invariants.sql fails while any such row is open --
-- CI stays red until an operator closes the suspension deliberately:
--
--   UPDATE security_control_suspension SET closed_at = clock_timestamp()
--    WHERE suspension_id = <id>;
--
-- A quiet rollback of a security control is how a repository ends up
-- believing it has a protection it does not have, which is the situation
-- this ADR exists to prevent -- so this script refuses to run without an
-- operator identity and a reason, rather than recording an anonymous or
-- reasonless suspension.
--
-- Usage (run as owl_migrator; never as an ad-hoc SET in an interactive
-- psql session, per ADR §7):
--
--   psql "$OWL_MIGRATOR_DATABASE_URL" -v ON_ERROR_STOP=1 \
--     -v operator='jane.doe@openwatchlist.example' \
--     -v reason='FORCE RLS on alert_case_event rejecting all writes after 014; rolling back while root cause is found' \
--     -f db/rollback/014_tenant_isolation_down.sql

-- \quit does not reliably signal a nonzero exit status in every psql
-- version (verified empirically: \quit 1 prints "extra argument ignored"
-- and still exits 0 here), so the guard below uses RAISE EXCEPTION inside
-- a DO block instead -- the same pattern db/migrations/014_tenant_isolation
-- .sql already relies on, and confirmed under -v ON_ERROR_STOP=1 to abort
-- the script with a nonzero exit.
\set QUIET 1
\if :{?operator}
\else
  DO $$ BEGIN RAISE EXCEPTION 'db/rollback/014_tenant_isolation_down.sql: operator variable is not set -- pass -v operator=<identity>'; END $$;
\endif
\if :{?reason}
\else
  DO $$ BEGIN RAISE EXCEPTION 'db/rollback/014_tenant_isolation_down.sql: reason variable is not set -- pass -v reason=<why>'; END $$;
\endif
\unset QUIET

BEGIN;

ALTER TABLE alert_record NO FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_case NO FORCE ROW LEVEL SECURITY;
ALTER TABLE case_assistance_record NO FORCE ROW LEVEL SECURITY;
ALTER TABLE vendor_adapter_record NO FORCE ROW LEVEL SECURITY;
ALTER TABLE review_security_audit_event NO FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_case_membership NO FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_case_event NO FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_case_idempotency NO FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_case_audit NO FORCE ROW LEVEL SECURITY;
ALTER TABLE case_assistance_review NO FORCE ROW LEVEL SECURITY;
ALTER TABLE case_assistance_idempotency NO FORCE ROW LEVEL SECURITY;
ALTER TABLE case_assistance_audit NO FORCE ROW LEVEL SECURITY;
ALTER TABLE vendor_adapter_idempotency NO FORCE ROW LEVEL SECURITY;
ALTER TABLE vendor_adapter_audit NO FORCE ROW LEVEL SECURITY;
ALTER TABLE operational_outbox_event NO FORCE ROW LEVEL SECURITY;
ALTER TABLE operational_outbox_message NO FORCE ROW LEVEL SECURITY;

INSERT INTO security_control_suspension(control_id, relations, operator, reason)
VALUES (
  'SEC-1-force-rls',
  ARRAY[
    'alert_record','alert_case','case_assistance_record','vendor_adapter_record','review_security_audit_event',
    'alert_case_membership','alert_case_event','alert_case_idempotency','alert_case_audit',
    'case_assistance_review','case_assistance_idempotency','case_assistance_audit',
    'vendor_adapter_idempotency','vendor_adapter_audit',
    'operational_outbox_event','operational_outbox_message'
  ],
  :'operator',
  :'reason'
);

COMMIT;
