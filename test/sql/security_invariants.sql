-- SEC/S0-4: SQL security-invariant test harness.
--
-- Each query below must return zero rows when the invariant it checks
-- holds. A non-empty result names the relation(s) where the invariant is
-- violated. Run via scripts/ci/check_sql_invariants.sh against a live
-- schema — reviewing migration files does not catch a control that looks
-- installed but silently does nothing, which is the dominant defect class
-- in this repository.
--
-- Each block below is: a `-- INVARIANT:` comment describing the failure
-- the query detects, followed by exactly one query, followed by a blank
-- line. scripts/ci/check_sql_invariants.sh parses on that structure, so
-- keep new invariants in the same shape.

-- INVARIANT: every relation with a row-level INSERT/DELETE/UPDATE trigger
-- (i.e. an immutability or mutation-guard control) must also carry a
-- statement-level BEFORE TRUNCATE trigger. Row-level triggers never fire
-- on TRUNCATE, so a relation that has one guard but not the other is
-- silently truncatable despite looking protected.
SELECT c.relname AS missing_truncate_guard
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public'
   AND EXISTS (SELECT 1 FROM pg_trigger t
                WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
                  AND (t.tgtype & 28) <> 0)          -- has UPDATE/DELETE/INSERT row trigger
   AND NOT EXISTS (SELECT 1 FROM pg_trigger t
                    WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
                      AND (t.tgtype & 32) <> 0);     -- lacks TRUNCATE trigger

-- INVARIANT: every relation with row-level security enabled must also have
-- it forced. ENABLE ROW LEVEL SECURITY alone is bypassed for the table
-- owner, which is exactly the role the application connects as, so RLS
-- without FORCE provides no real tenant isolation.
SELECT c.relname AS rls_enabled_but_not_forced
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relrowsecurity AND NOT c.relforcerowsecurity;

-- ADR-0001 SEC-1 §8: the seven invariants below gate the migration PR
-- (db/migrations/014_tenant_isolation.sql). Each uses the literal
-- 16-relation list from db/tenant_scoped_tables.txt, transcribed directly
-- rather than derived from an information_schema/LIKE heuristic -- a
-- heuristic would silently exclude a newly added relation that was never
-- wired in, which is the failure mode the literal list exists to prevent.

-- INVARIANT: every relation in the declared tenant-scoped set has a
-- tenant_id column that is NOT NULL, with one deliberate exception:
-- review_security_audit_event, whose tenant_id stays nullable by design
-- (ADR §4 -- a NULL tenant_id marks a platform-level event, visible only
-- to the operator role once policy applies, per migration 014's use of
-- the bare openwatchlist_tenant_visible(tenant_id) predicate for it).
SELECT t.relation AS tenant_id_missing_or_wrongly_nullable
  FROM unnest(ARRAY[
    'alert_record','alert_case','case_assistance_record','vendor_adapter_record','review_security_audit_event',
    'alert_case_membership','alert_case_event','alert_case_idempotency','alert_case_audit',
    'case_assistance_review','case_assistance_idempotency','case_assistance_audit',
    'vendor_adapter_idempotency','vendor_adapter_audit',
    'operational_outbox_event','operational_outbox_message'
  ]) AS t(relation)
  LEFT JOIN information_schema.columns c
    ON c.table_schema = 'public' AND c.table_name = t.relation AND c.column_name = 'tenant_id'
 WHERE c.column_name IS NULL
    OR (c.is_nullable = 'YES' AND t.relation <> 'review_security_audit_event');

-- INVARIANT: every relation with row-level security enabled has at least
-- one policy. Catches the rollback path that drops policies instead of
-- using the documented lever (db/rollback/014_tenant_isolation_down.sql,
-- which only lifts FORCE and never drops a policy) -- RLS enabled with
-- zero policies is a different, undocumented state this invariant exists
-- to catch on its own, independent of invariant 5 below.
SELECT c.relname AS rls_enabled_without_any_policy
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relrowsecurity
   AND NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname);

-- INVARIANT: every relation in the declared tenant-scoped set has RLS
-- enabled, forced, and a policy with both USING and WITH CHECK non-null.
-- A USING-only policy permits a tenant to write rows labelled with
-- another tenant's id -- WITH CHECK is what closes that, so its absence
-- is exactly the gap this invariant exists to catch.
SELECT t.relation AS rls_not_fully_enforced
  FROM unnest(ARRAY[
    'alert_record','alert_case','case_assistance_record','vendor_adapter_record','review_security_audit_event',
    'alert_case_membership','alert_case_event','alert_case_idempotency','alert_case_audit',
    'case_assistance_review','case_assistance_idempotency','case_assistance_audit',
    'vendor_adapter_idempotency','vendor_adapter_audit',
    'operational_outbox_event','operational_outbox_message'
  ]) AS t(relation)
  LEFT JOIN pg_class c ON c.relname = t.relation AND c.relnamespace = 'public'::regnamespace
  LEFT JOIN pg_policies p ON p.schemaname = 'public' AND p.tablename = t.relation
 WHERE c.oid IS NULL
    OR NOT c.relrowsecurity
    OR NOT c.relforcerowsecurity
    OR p.tablename IS NULL
    OR p.qual IS NULL
    OR p.with_check IS NULL;

-- INVARIANT: no relation whose name ends _idempotency or _receipt has a
-- primary key or unique constraint that omits tenant_id -- except
-- screening_idempotency_receipt, deliberately excluded by the corrected
-- ADR §6/§9 (Class C, deferred to SEC-1c: internal/screeningapi has no
-- tenant concept anywhere to backfill from or write going forward, unlike
-- the three relations this invariant does cover, whose writers already
-- assert a bound tenant per the seam, PR #70).
SELECT c.relname AS idempotency_or_receipt_table_missing_tenant_scoped_key
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public'
   AND (c.relname LIKE '%\_idempotency' ESCAPE '\' OR c.relname LIKE '%\_receipt' ESCAPE '\')
   AND c.relname <> 'screening_idempotency_receipt'
   AND EXISTS (
     SELECT 1 FROM pg_constraint con
      WHERE con.conrelid = c.oid AND con.contype IN ('p','u')
        AND NOT EXISTS (
          SELECT 1 FROM pg_attribute a
           WHERE a.attrelid = con.conrelid AND a.attnum = ANY(con.conkey) AND a.attname = 'tenant_id'
        )
   );

-- INVARIANT: no open row in security_control_suspension. A rollback via
-- db/rollback/014_tenant_isolation_down.sql holds CI red until an
-- operator closes the suspension deliberately -- a quiet rollback of a
-- security control is how a repository ends up believing it has a
-- protection it does not have, which is the situation ADR-0001 exists to
-- prevent.
SELECT suspension_id AS open_security_control_suspension
  FROM security_control_suspension
 WHERE closed_at IS NULL;

-- INVARIANT: no policy reachable by owl_app -- the role every sink
-- connects as, and a member of PUBLIC, which every policy below applies
-- to by default -- contains a literal '*' wildcard check in its own
-- USING/WITH CHECK text. Every policy in this schema goes through
-- openwatchlist_tenant_visible() (db/migrations/009g_production_hardening
-- .sql:84-85), which centralizes the wildcard branch in one function
-- reserved for an operator identity that never authenticates as owl_app;
-- tenantctx.Resolve also refuses to construct a '*' Tenant
-- (internal/tenantctx/tenantctx.go), so owl_app cannot reach it through
-- the seam either. This invariant fails if a future policy inlines the
-- wildcard check directly instead of going through that function, which
-- would make the escape hatch reachable from exactly the role it must
-- never be reachable from.
SELECT schemaname || '.' || tablename || ':' || policyname AS wildcard_reachable_policy
  FROM pg_policies
 WHERE schemaname = 'public'
   AND (roles = '{public}' OR 'owl_app' = ANY(roles))
   AND (qual LIKE '%''*''%' OR with_check LIKE '%''*''%');

-- INVARIANT: owl_app does not have rolbypassrls. Granting BYPASSRLS to
-- owl_app would silently void every policy in this ADR, which is why this
-- is asserted directly rather than relying on deployment discipline
-- (ADR §3 "Roles and DSNs").
SELECT rolname AS owl_app_has_bypassrls
  FROM pg_roles
 WHERE rolname = 'owl_app' AND rolbypassrls;
