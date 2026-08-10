-- SEC-1a: force row-level security on the 5 relations where 009g already
-- enabled it but never forced it. ENABLE ROW LEVEL SECURITY alone is
-- bypassed for the table owner, which is the role the application
-- connects as, so RLS on these tables has been a no-op since 009g
-- landed. Confirmed live via test/sql/security_invariants.sql (S0-4).
--
-- This closes only the FORCE gap. Policy definitions, tenant_id backfill,
-- and the openwatchlist.tenant_id GUC-setting problem remain SEC-1
-- proper (Sprint 1) and are not touched here.
BEGIN;

DO $$
DECLARE
  t text;
  relations text[] := ARRAY[
    'alert_record',
    'alert_case',
    'case_assistance_record',
    'vendor_adapter_record',
    'review_security_audit_event'
  ];
BEGIN
  FOREACH t IN ARRAY relations LOOP
    IF to_regclass(t) IS NULL THEN
      RAISE EXCEPTION 'SEC-1a force-RLS guard: relation % does not exist; migration 013 requires all 5 listed relations to be present', t;
    END IF;
  END LOOP;
END $$;

ALTER TABLE alert_record FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_case FORCE ROW LEVEL SECURITY;
ALTER TABLE case_assistance_record FORCE ROW LEVEL SECURITY;
ALTER TABLE vendor_adapter_record FORCE ROW LEVEL SECURITY;
ALTER TABLE review_security_audit_event FORCE ROW LEVEL SECURITY;

COMMIT;
