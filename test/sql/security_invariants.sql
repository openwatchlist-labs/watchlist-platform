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
