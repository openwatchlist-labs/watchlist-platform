# ADR-0001: Tenant isolation

- **Status:** Accepted
- **Date:** 2026-08-10
- **Issue:** SEC-1 (P0)
- **Related:** SEC-1a (#62, merged), SEC-1b and SEC-1c (opened by this ADR), SEC-3, SEC-5, SEC-6,
  REL-2, REL-7, REL-10, GHSA-vhj8-986g-vjf4
- **Supersedes:** nothing. This is the first ADR in `docs/adr/` and sets the format for later ones.

## Context

The platform has no working tenant isolation. Migration `009g` installed row-level security on four
relations and a policy function that reads a session GUC, and SEC-1a
(`db/migrations/013_force_rls.sql`) added the missing `FORCE` on five. Neither made isolation real.
The specifics matter, because each gap has a different fix:

**1. The GUC is never set.** `openwatchlist_tenant_visible()`
(`db/migrations/009g_production_hardening.sql:84-85`) reads
`current_setting('openwatchlist.tenant_id', true)`. Nothing in the Go tree ever sets it. The
predicate therefore evaluates against `NULL` on every row, and `row_tenant = NULL` is `NULL`, not
`true`.

This fails closed, which is worth stating precisely: forced RLS with an unset GUC yields zero rows
and rejected writes, not cross-tenant reads. Today's five forced relations are not leaking. They are
protected only because no read path queries them — the review console reads from the filesystem state
directory (`internal/reviewconsole`, called from `internal/reviewconsoleapi/server.go:230`), and the
Postgres sinks are write-only mirrors. Isolation is untested rather than defeated, and the moment a
read path is added it becomes one or the other depending on work this ADR specifies.

**2. RLS coverage is partial.** Eleven tenant-bearing relations have no policy, and ten of those have
no `tenant_id` column at all — including `alert_case_event`, `alert_case_membership`,
`case_assistance_review`, `case_assistance_idempotency`, and both alert-case and assistance audit
streams. `operational_outbox_message` has carried a `tenant_id` since `009g:22` and never received a
policy.

**3. Idempotency keys are not tenant-scoped.** `screening_idempotency_receipt` is keyed
`PRIMARY KEY(scope, idempotency_key_sha256)` (`db/migrations/008g_screening_ledger.sql:6`). Two
tenants presenting the same key collide: with identical bodies, the second tenant inherits the
first's stored decision; with differing bodies, the conflict guard reveals that the key exists. Three
sibling tables share the defect (`009ab:32`, `009c:24`, `009e:12`). Logged as
GHSA-vhj8-986g-vjf4 and SEC-6.

Three further facts about the current code are load-bearing for the design below, and are why SEC-1
needs an ADR rather than a migration:

- **There is no long-lived connection to bind a GUC to.** Every Postgres write is `fork`+`exec psql`
  (`internal/screeningledger/postgres.go:52-57`, and the same shape in `internal/alertcase`,
  `internal/assistancerag`, `internal/vendoradapter`, `internal/productionops`), one process per
  write, with SQL assembled by string concatenation over hex-encoded literals. REL-2 will replace
  this with `jackc/pgx/v5`. But each invocation already *is* a single session running a single
  transaction, which is enough to bind against today — see §3.
- **Tenant identity is currently chosen by the caller.** `internal/alertcaseapi/server.go:103`
  authenticates nothing and reads `tenant_id` from the request body
  (`internal/alertcase/policy.go:83`). `internal/screeningapi` has no tenant concept at all — the
  string does not appear in the package. Only `internal/reviewconsoleapi` derives tenant from a
  verified token, and it does so per handler, after fetching the row
  (`internal/reviewconsoleapi/server.go:209`).
- **A `tenant_id` backfill by `UPDATE` will be rejected.** Every relation needing a backfill except
  `alert_case` and `operational_outbox_event` carries a `BEFORE UPDATE OR DELETE ... FOR EACH ROW`
  immutability trigger (`009ab:42-51`, `009c:32-41`, `009e:19-25`). A naive backfill aborts with
  `rows are append-only`.

## Decision

Bind an authenticated tenant to a transaction-local GUC through a single seam, extend RLS to every
tenant-scoped relation, fold `tenant_id` into every idempotency key, and gate the whole thing on a
two-tenant integration test plus SQL invariants that fail when any part of it is absent.

Three decisions frame the rest of this document.

| # | Decision | Consequence |
|---|---|---|
| **D1** | The binding is implemented **now**, against the current `psql`-script sinks, behind a `WithTenant` seam and a CI check. SEC-1 does **not** wait for REL-2. | Isolation lands this sprint. Two binding implementations exist over time; §10 makes retiring the first a named, tested REL-2 subtask rather than a side effect. |
| **D2** | The screening-ledger family stays **out of RLS scope** in this ADR. | Smallest viable migration. But per-tenant screening evidence stays cross-tenant readable — an accepted risk with a re-entry condition, recorded in §9, not omitted. |
| **D3** | Authenticated tenant provenance is a **hard prerequisite** for closing SEC-1. | Binding a GUC to a caller-asserted tenant is theatre. Body-supplied `tenant_id` is demoted to an assertion that must match the bound tenant. |

D2 and the idempotency fix interact, and the interaction is deliberate rather than an oversight, though
which relations §6 actually touches was corrected during the migration PR (see §4 Class C and §6):
GHSA-vhj8-986g-vjf4 is closed for `alert_case_idempotency`, `case_assistance_idempotency`, and
`vendor_adapter_idempotency` by a tenant-scoped uniqueness key with **no RLS policy** on any of the
three. `screening_idempotency_receipt` carries the same defect but stays fully inside the Class C
deferral — no authenticated tenant exists anywhere upstream of it to key on — so GHSA-vhj8-986g-vjf4
remains open for that one table specifically, tracked under the same SEC-1c re-entry condition as the
rest of Class C rather than silently narrowed.

## 1. Scope

In scope: tenant resolution and binding, RLS policy coverage for Class A and Class B relations (§4),
the `tenant_id` backfill, idempotency-key scoping across three tables (`screening_idempotency_receipt`
deferred to Class C — see §4, §6), rollback, and the test bar that defines "closed".

Out of scope, each with a pointer: the ledger family (§9, SEC-1c), the idempotency TOCTOU (§6,
SEC-5), audit-chain forgery (§9, SEC-7), DSN exposure via `argv` (§3, SEC-3).

## 2. Tenant provenance (D3)

A GUC bound to a value the caller supplied proves nothing. Before binding can mean anything, the
tenant must come from a verified token.

**Single authority.** A new package `internal/tenantctx` is the only place a bound tenant is
constructed. It exposes one resolver, which derives the tenant from verified
`reviewauth.Claims.TenantID` (`internal/reviewauth/types.go:57`, populated by `Tokens.Parse` at
`internal/reviewauth/token.go:136`), plus a context setter and getter. No other package may construct
the bound-tenant value; §3 makes that structural rather than advisory.

**Body-supplied `tenant_id` is demoted to an assertion.** `alertcase.CreateAlertRequest.TenantID`
stays in the wire format — it is load-bearing for vendor adapters
(`internal/vendoradapter/profile.go:13`) and for the alert identity hash
(`internal/alertcase/policy.go:224-230`). Its meaning changes: if present and unequal to the bound
tenant, the request is rejected with `403`. It is never silently overwritten with the bound value and
never silently accepted. Both alternatives destroy evidence — the first rewrites what the caller
claimed, the second records a claim nobody checked.

**The `*` wildcard must not be reachable from a request binding.** `openwatchlist_tenant_visible()`
treats `'*'` as "see everything" (`009g:85`), and wildcard claims exist today
(`internal/reviewconsoleapi/server.go:212`). `tenantctx` refuses to bind `'*'`: a caller holding a
wildcard claim must name a concrete tenant — the pattern
`internal/reviewconsoleapi/server.go:210-216` already implements — or be rejected. The `'*'` branch
of the policy predicate survives only for the operator role (§3, roles), and invariant 6 in §8 fails
if it becomes reachable from `owl_app`.

**Closure condition.** SEC-1 is not closed while any writer can name its own tenant. The
authentication gap on `internal/alertcaseapi` and `internal/screeningapi` is tracked as **SEC-1b**
and blocks SEC-1 closure. This ADR specifies the mechanism; SEC-1b supplies the identity it binds.

## 3. Binding: where, how, and who owns it (D1)

### Ownership

Two packages, one seam:

- `internal/tenantctx` — **resolution only.** Verified claims in, opaque bound-tenant value out (§2).
- `internal/tenantsql` — **binding only.** Owns the transaction envelope and is the only code
  permitted to hand SQL touching a tenant-scoped relation to a command runner. Shared by all sinks.

### The seam

The sinks currently emit their own transaction envelopes
(`internal/screeningledger/postgres.go:68-72`, `internal/alertcase/postgres.go:67-90`,
`internal/vendoradapter/postgres.go:40-45`). The seam takes that envelope away from them: callers
pass the statement body only, and `tenantsql.WithTenant` emits

```sql
BEGIN;
SELECT set_config('openwatchlist.tenant_id', <hex-encoded tenant literal>, true);
-- caller-supplied body
COMMIT;
```

Three properties of that snippet are decisions, not incidental:

**`set_config(..., is_local => true)` rather than `SET LOCAL`.** `SET LOCAL` accepts only a literal
or identifier, so the tenant would have to be interpolated into statement text — a new injection
surface in a codebase that has deliberately avoided one. `set_config` has identical
transaction-local semantics and accepts an *expression*, so the tenant reuses the existing
`sqlText()` hex-encoding idiom (`internal/screeningledger/postgres.go:90-92`) unchanged. This is the
one place the interim departs from the textbook pattern, and this is why.

**Transaction-local, not session-level.** Under `fork`+`exec` the distinction is currently
invisible: the process exits after one script, so a session-level `SET` would behave identically.
It is specified as local anyway so that the pgx port (§10) inherits correct semantics rather than a
habit that only worked because the process was short-lived. The failure this prevents once pooling
exists: a session-level `SET` leaves the tenant bound on a connection returned to the pool, and the
next borrower inherits it.

**Statements that currently run outside any transaction are wrapped by the same seam**, which fixes
a latent hazard for free. `PersistAudit`, `PersistExternalAudit` and `PurgeExpired`
(`internal/screeningledger/postgres.go:75-86`) issue bare statements today. A local `set_config` in
that position is silently a no-op — precisely the looks-installed-does-nothing class this ADR exists
to eliminate.

`Migrate` and `Ping` stay unbound and are classified global: `Migrate` runs DDL as `owl_migrator`,
`Ping` is `SELECT 1`. They are named individually in the allowlist below, never matched by pattern.

### CI enforcement: `scripts/ci/check_tenant_binding.py`

Code review does not reliably catch a call that *should have* gone through a wrapper, so the
prohibition is mechanical. The check fails the build when Go source outside the seam hands SQL naming
a tenant-scoped relation to a runner.

1. **One list, three consumers.** The tenant-scoped relation list lives in
   `db/tenant_scoped_tables.txt` and is read by this check, by the migration (§5), and by the SQL
   invariants (§8). A relation added to the schema but not the list is caught by invariant 1; a list
   that diverges from §4 fails this check outright.
2. **Detection.** Scan Go string literals for `INSERT INTO` / `UPDATE` / `DELETE FROM` / `FROM` /
   `JOIN` followed by any listed relation.
3. **Structural enforcement, grep as backstop.** Rather than attempt dataflow analysis, each sink's
   raw `run()` becomes unexported and takes a named type that only `internal/tenantsql` can
   construct. The check then reduces to "no direct `Runner.Run(` or `p.run(` call site outside
   `internal/tenantsql` and the allowlist". The type constraint is the real control; the grep is what
   survives a refactor that reintroduces an exported path.
4. **Allowlist, in two classes.** Every entry carries a one-line justification, and the check fails
   on an entry that no longer resolves to real code. **Permanent** entries: `Migrate`, `Ping`, the
   `db/migrations/` path (§5). **Transitional** entries: the pre-seam sink call sites. The check
   fails if any transitional entry survives the seam PR, so the allowlist is a shrinking list with a
   CI-enforced end state rather than somewhere an omission can quietly settle.

Per the boundaries in `CLAUDE.md`, wiring this script into `scripts/ci/run-ci.sh` is its own reviewed
gate PR, not part of the implementation PR, and it follows the ordering in §8: **gate PR** (Postgres
provisioning plus this check, landing with every current sink call site seeded as a transitional
allowlist entry so CI is green on merge), then the **seam PR** (which empties the transitional list as
it adopts `WithTenant`), then the **migration PR**. The seeding is not ceremony: the check cannot land
enforcing before the seam it guards exists, because every sink today issues tenant-table SQL directly
and CI would be red on arrival.

### Roles and DSNs

No migration contains `CREATE ROLE` or `GRANT`; every sink connects as the table owner using the DSN
it was constructed with. This ADR defines two roles:

- **`owl_app`** — the identity in every sink DSN. Never granted `BYPASSRLS`. Subject to `FORCE`.
- **`owl_migrator`** — DDL and backfill only. Used by `Migrate` and by `db/migrations/`.

Granting `BYPASSRLS` to `owl_app` silently voids every policy in this ADR, which is why invariant 7
(§8) asserts against it rather than relying on deployment discipline.

SEC-3 — the DSN passed as `argv[1]` to `psql` (`internal/screeningledger/postgres.go:55`,
`internal/vendoradapter/postgres.go:33`) — is untouched here and remains open. It is worth noting
explicitly that D1 keeps that call shape alive longer than a pgx-first sequencing would have; §9
records the trade.

### Applies to all five screening-api variants

Per hard rule 4, the seam must be adopted by `cmd/screening-api` and `-v8d` / `-v8e` / `-v8f` / `-v8g`
together with their backing packages (`internal/screeningapi`, `internal/screeningapiv8d` … `v8g`).
Adopting it in one leaves four unprotected, and a partially adopted control is indistinguishable from
an absent one at runtime. The CI check above is what makes shipping that by accident impossible; if
REL-10 collapses the variants first, the work shrinks accordingly but the requirement does not
change.

## 4. Relation classification

Per the "never enumerate targets by inference" trap in `CLAUDE.md`, every relation created under
`db/migrations/` appears below exactly once. All 35 are listed. A relation absent from this table is a
bug in this ADR, not an implicit "global".

### Class A — tenant-scoped, `tenant_id` present, RLS already forced (5)

| Relation | Note |
|---|---|
| `alert_record` | Forced by `013:30`. Policy from `009g:94`. |
| `alert_case` | The **only mutable** tenant-scoped relation — no immutability trigger, and absent from `012`'s list. It is therefore the one place `UPDATE`/`DELETE` policy semantics and `WITH CHECK` genuinely bite, via the `ON CONFLICT ... DO UPDATE` at `internal/alertcase/postgres.go:85`. |
| `case_assistance_record` | Forced by `013:32`. |
| `vendor_adapter_record` | Forced by `013:33`. |
| `review_security_audit_event` | Forced by `013:34`, but its policy admits `tenant_id IS NULL OR ...` (`009g:100`), which makes every platform-level audit row — subject, path, permission, outcome — visible to **all** tenants. Tightened by this ADR: NULL-tenant rows become visible to the operator role only. |

### Class B — tenant-scoped, work required (11)

Ten need column, backfill, policy and `FORCE`:

`alert_case_membership`, `alert_case_event`, `alert_case_idempotency`, `alert_case_audit`,
`case_assistance_review`, `case_assistance_idempotency`, `case_assistance_audit`,
`vendor_adapter_idempotency`, `vendor_adapter_audit`, `operational_outbox_event`.

One needs policy and `FORCE` only:

`operational_outbox_message` — already carries `tenant_id` (`009g:22`) and a tenant-aware uniqueness
constraint (`009g:30`), but never received a policy.

### Class C — deferred by D2 (7)

`screening_ledger_event`, `screening_ledger_snapshot`, `screening_ledger_replication`,
`screening_ledger_audit`, `screening_ledger_retention_tombstone`, `screening_idempotency_receipt`,
`watchlist_operational_audit`.

These are tenant-scoped in principle and receive no RLS in this ADR. `screening_idempotency_receipt`
was originally planned as an exception that would still get a `tenant_id` column and a tenant-scoped
key in §6, on the theory that its defect is key collision rather than policy absence — **corrected
during the migration PR**: `internal/screeningapi` has no tenant concept anywhere in the Go tree to
backfill from or write going forward (confirmed by inspection: no `TenantID` field on
`screeningledger.Event`/`SnapshotEnvelope`, no tenant string in `internal/screeningapi` at all), unlike
`alertcaseapi`/`assistanceapi`/`vendoradapterapi`, whose sinks assert a bound tenant via
`tenantctx.Assert` (seam PR #70) before this migration runs. Populating either a historical backfill
or a going-forward write for this table would mean inventing a tenant value with no evidence behind
it — exactly what §5's "no defaults, no sentinels" rule and this section's own D2 reasoning already
forbid for the rest of Class C. `screening_idempotency_receipt` therefore stays untouched, fully inside
the Class C deferral, alongside its six siblings. Re-entry condition and risk: §9, SEC-1c.

### Class D — platform-global by design (12)

"Global" is a claim defended per relation, not a default for anything left over.

| Relation | Why it has no tenant dimension |
|---|---|
| `rag_corpus_snapshot` | Content-addressed corpus shared across tenants; per-tenant use is recorded on `case_assistance_record`. |
| `review_identity_registry_snapshot` | The identity registry itself; tenancy is a field *inside* it. |
| `operational_runtime_config_snapshot` | Deployment-wide runtime config. |
| `tenant_quota_registry_snapshot` | A registry *of* tenants, not per-tenant rows. Splitting it by tenant would make the registry unreadable by the process that enforces it. |
| `operational_backup_catalog` | Backup manifests span all tenants by construction. |
| `operational_recovery_audit` | Records operator recovery actions, which are cross-tenant events. |
| `release_qualification_report` | Release-gate evidence, per build. |
| `release_qualification_gate` | Child of the report. |
| `release_qualification_audit` | Audit of the release gate. |
| `release_artifact_record` | Published artifact identity. |
| `release_qualification_evidence` | Release evidence, per build. |
| `release_deployment_audit` | Deployment events, per environment. |

## 5. Migration plan — `db/migrations/014_tenant_isolation.sql`

**Fail closed at the top.** A `DO` block that `RAISE EXCEPTION`s if any listed relation is absent,
in the idiom of `012_truncate_guards.sql:54-60` and `013_force_rls.sql:22-28`. Explicitly **not** the
`IF to_regclass(t) IS NOT NULL THEN` style of `009g:91` — that pattern is why `009g` shipped controls
that silently skipped absent tables, and it must not be copied here.

**Add the column.** `ALTER TABLE ... ADD COLUMN tenant_id text`, nullable at first. DDL does not fire
row triggers, so this step is safe on immutable relations.

**Work around the immutability triggers.** This is the sharpest constraint in the migration and the
main reason SEC-1 needed a design gate. A backfill `UPDATE` on Class B raises
`rows are append-only` from the triggers at `009ab:42-51`, `009c:32-41` and `009e:19-25`. Resolution,
inside the single migration transaction:

```sql
ALTER TABLE <relation> DISABLE TRIGGER USER;
-- backfill
ALTER TABLE <relation> ENABLE TRIGGER USER;
```

followed by a `DO` block that re-queries `pg_trigger` for every listed relation and `RAISE
EXCEPTION`s if any user trigger is left disabled. A migration that half-completes and leaves
immutability off is a worse outcome than one that fails.

Rejected alternative, recorded so it is not revisited: `SET session_replication_role = 'replica'`,
which disables the triggers but also disables foreign-key enforcement session-wide — exactly during
the window when the backfill depends on FK-derived joins being sound.

**Derive every value from a join. No defaults, no sentinels.**

| Relation | Source of `tenant_id` |
|---|---|
| `alert_case_event` | `alert_case` via `case_id` |
| `alert_case_membership` | `alert_case` via `case_id`, **cross-checked** against `alert_record` via `alert_id` |
| `alert_case_idempotency`, `alert_case_audit` | `object_type` + `object_id` join to `alert_case` or `alert_record` |
| `case_assistance_review` | `case_assistance_record` via `assistance_id` |
| `case_assistance_idempotency`, `case_assistance_audit` | `object_id` join to `case_assistance_record` |
| `vendor_adapter_idempotency` | `vendor_adapter_record` via `record_id` |
| `vendor_adapter_audit` | `object_id` join to `vendor_adapter_record.record_id` |
| `operational_outbox_event` | `operational_outbox_message` via `message_id` |

The `alert_case_membership` cross-check is not defensive padding. A membership row joining one
tenant's case to another tenant's alert is a pre-existing isolation violation, and the migration must
**abort** on finding one rather than picking a side:

```sql
-- must return zero rows before the backfill is allowed to proceed
SELECT m.case_id, m.alert_id
  FROM alert_case_membership m
  JOIN alert_case c ON c.case_id = m.case_id
  JOIN alert_record a ON a.alert_id = m.alert_id
 WHERE c.tenant_id <> a.tenant_id;
```

Any row that does not resolve to a tenant aborts the migration with the relation name and the count.
There is no `COALESCE` and no fallback value anywhere in Class B: every row here has a derivable
owner, and one that does not is a data-integrity finding that deserves a human, not a default.

**Seal.** `SET NOT NULL`, then policy plus `ENABLE` plus `FORCE` for all of Class A and Class B,
reusing `openwatchlist_tenant_visible()` with both `USING` and `WITH CHECK`. A policy with `USING`
alone permits a tenant to write rows labelled with another tenant's id.

**The migration deliberately does not go through the seam.** The backfill is a cross-tenant operation
by definition and must complete before any policy exists; it runs as `owl_migrator` via
`db/migrations/`. This is why `db/migrations/` is a permanent allowlist entry in §3 — a stated
decision, not a gap.

**Ordering is load-bearing.** Seam adoption (§3) merges and deploys first, inert until policies
exist; then this migration; then `FORCE`. Landing `FORCE` before the seam is deployed takes every
write path to zero rows — fail-closed, but a full outage.

**REL-7 note.** DDL, backfill and policy creation in one transaction holds `ACCESS EXCLUSIVE` locks
and blocks writes for its duration. Accepted for this migration: splitting it would leave a window
where the column exists, the policy exists, and the backfill has not finished — during which the
policy evaluates against NULL and rejects live writes. The write-outage window must be measured on a
production-sized restore and stated in the deployment plan before this runs.

## 6. Idempotency-key scoping (GHSA-vhj8-986g-vjf4 / SEC-6)

Four relations were originally identified as carrying the same defect. Three are fixed together in
this migration; the fourth, `screening_idempotency_receipt`, is corrected out of this section and
into the Class C deferral (§4) — internal/screeningapi has no tenant concept anywhere upstream to key
on, so there is nothing honest to backfill or write, and inventing one would be exactly the
data-integrity-finding-not-a-default problem §5 refuses to paper over elsewhere. Left here as a
record of the correction, not silently dropped from the table:

| Relation | Current key | Becomes |
|---|---|---|
| `screening_idempotency_receipt` | `(scope, idempotency_key_sha256)` (`008g:6`) | **unchanged** — deferred to Class C / SEC-1c (§4, §9); no tenant source exists to key on |
| `alert_case_idempotency` | `(scope, key_sha256)` (`009ab:32`) | `(tenant_id, scope, key_sha256)` |
| `case_assistance_idempotency` | `(scope, key_sha256)` (`009c:24`) | `(tenant_id, scope, key_sha256)` |
| `vendor_adapter_idempotency` | `(scope, idempotency_key)` (`009e:12`) | `(tenant_id, scope, idempotency_key)` |

**Schema and writers change in one PR.** A key that includes `tenant_id` is wrong until every writer
supplies one. Writers: `internal/alertcase/postgres.go:67-90`,
`internal/assistancerag/postgres.go:67-78`, `internal/vendoradapter/postgres.go:43` — each already
asserts a bound tenant via `tenantctx.Assert` (seam PR #70) before the migration PR runs, confirmed by
inspection before writing `db/migrations/014_tenant_isolation.sql` — and the duplicated `SchemaSQL`
constants that mirror two of these tables (`internal/alertcase/postgres.go:173`,
`internal/assistancerag/postgres.go:127`; `internal/vendoradapter/postgres.go` has no `SchemaSQL`
const to update) must move in lockstep or REL-9's schema duplication becomes a live divergence.
`internal/screeningledger/postgres.go:72` is not a writer for this section, per the correction above.

**`ON CONFLICT ... DO NOTHING` comes off these writes.** Per the repo trap, a swallowed conflict on
an idempotency write hides real divergence. Catch `23505` and surface it.

**This does not fix SEC-5.** The read-then-write guard at
`internal/screeningledger/postgres.go:66` remains a TOCTOU: it checks for a conflicting receipt in a
statement that precedes the insert. Adding `tenant_id` to the key narrows the race to a single tenant
rather than closing it. Stating this plainly matters, because a reader who sees "idempotency,
tenant-scoped, conflicts surfaced" could reasonably conclude the whole idempotency story is now sound.
It is not.

## 7. Rollback

The design goal is that rollback cannot be silent. A reverted control that CI still reports green is
the same defect class as a control that never worked.

**What a bad binding actually looks like.** An unset or mis-set GUC is fail-closed: zero rows and
rejected writes. The symptom is loud and immediate, not a silent cross-tenant read. That determines
the shape of the lever — the emergency action is a capability switch, never a data fix, and never an
ad-hoc `SET` in a psql session.

**The lever.** `db/rollback/014_tenant_isolation_down.sql` issues `ALTER TABLE ... NO FORCE ROW LEVEL
SECURITY` over the same explicit relation list. Policies and columns are **not** dropped and the
backfill is **not** reverted; those are the expensive, hard-to-redo parts, and none of them cause the
outage the lever exists to stop.

**The lever is loud.** It must insert a row into a new `security_control_suspension` relation
(control id, relations, operator, reason, `opened_at`, `closed_at`), and invariant 5 in §8 fails
while any suspension is open. A rollback therefore holds CI red until someone closes it deliberately.
A quiet rollback of a security control is how a repository ends up believing it has a protection it
does not have — which is the situation this ADR is unwinding.

**Staged rollout so the lever is rarely needed.** These are deployment states, each spanning the PRs
ordered in §8 — not a second, competing ordering:

1. **Seam adopted** across all five variants, CI check enforcing, transitional allowlist empty (gate
   PR, then seam PR). No policy change; revertible as an ordinary code revert.
2. **Shadow.** An `openwatchlist_tenant_bound()` assertion records unbound transactions to a counter
   relation without rejecting them. Soak for a defined period; the expected value is zero. This is
   what proves the seam actually covers every write path before anything is forced.
3. **Enforce.** Migration, Class B policies, `FORCE`. Stage 2's counter is the go/no-go.

**Not a rollback option:** dropping the policies. The existing invariant only checks *enabled implies
forced* (`test/sql/security_invariants.sql:35-38`), so a dropped policy passes CI today. Invariant 2
in §8 exists to close exactly that hole.

## 8. Test strategy — the bar for calling SEC-1 closed

### SQL invariants

Added to `test/sql/security_invariants.sql` in its existing shape — a `-- INVARIANT:` comment, one
query, a blank line — because `scripts/ci/check_sql_invariants.sh:24-35` parses on that structure.
Each returns zero rows when the invariant holds.

1. Every relation in the declared tenant-scoped set has a `tenant_id` column that is `NOT NULL`.
2. Every relation with `relrowsecurity` has at least one policy. (Catches the drop-the-policy
   rollback.)
3. Every relation in the declared set has RLS enabled, forced, and a policy with both `qual` and
   `with_check` non-null in `pg_policies`. (Catches a `USING`-only policy, which permits
   cross-tenant writes.)
4. No relation whose name ends `_idempotency` or `_receipt` has a primary key or unique constraint
   that omits `tenant_id`.
5. No open row in `security_control_suspension`.
6. No policy reachable by `owl_app` admits the `'*'` wildcard.
7. `owl_app` does not have `rolbypassrls`.

The declared set is the literal list from `db/tenant_scoped_tables.txt` (§3), not an
`information_schema` or `LIKE` heuristic. A heuristic would silently exclude a newly added relation,
which is the failure mode the list exists to prevent.

### Two-tenant integration test

Lives in `internal/integrationtest`, runs under `-race`, gated on `OWL_TEST_DATABASE_URL`. Every
obligation below must pass before SEC-1 is closed:

- **Read isolation.** Tenant A cannot `SELECT` tenant B's rows, on **every** Class A and Class B
  relation — table-driven over the literal list, because a relation omitted from the test is an
  invisible hole.
- **Write isolation.** Tenant A cannot `INSERT` a row labelled tenant B (`WITH CHECK`), and cannot
  `UPDATE` or `DELETE` B's rows on the mutable `alert_case`.
- **Fail-closed.** With no GUC bound: zero rows and rejected writes, not full visibility. This is the
  test that distinguishes "isolation works" from "the query happened to return nothing".
- **No leak across a reused connection.** Bind A, run, release, bind B on the *same* physical
  connection, assert B sees nothing of A's. Under `fork`+`exec` this case is inert — one process per
  write means there is no connection to reuse — so today it proves nothing. It is written now because
  it becomes the load-bearing test the moment pgx lands, and §10 step 2 makes re-running it a gate on
  that cutover. A green result here before REL-2 must not be read as coverage.
- **Idempotency.** Same key with the same body across two tenants yields two independent receipts and
  neither inherits the other's response. Same key with a different body within one tenant surfaces
  `23505` rather than swallowing it. Tenant A reusing a key tenant B already used is not
  distinguishable from a fresh key in the response — no existence oracle.
- **FK crossing.** An `alert_case_membership` joining A's case to B's alert cannot be created.
- **Provenance (D3).** A request whose body asserts a `tenant_id` different from the bound claim is
  rejected with `403`, and no row is written by any sink.

### CI wiring — the part that decides whether any of this is real

`scripts/ci/run-ci.sh:60-63` prints `SKIP` when `OWL_TEST_DATABASE_URL` is unset, so on an ordinary
run the entire tenant-isolation suite never executes. A control that runs only when an optional
environment variable happens to be set is the same silent-absence bug this ADR exists to fix, one
level up.

CI must provision a Postgres service and make these checks non-skippable. Per the boundaries in
`CLAUDE.md`, both gate changes — provisioning Postgres, and wiring `check_tenant_binding.py` from §3
— land in a single reviewed gate PR, separate from the implementation PRs. The full sequence is:
**gate PR → seam PR → migration PR**.

## 9. Accepted risks and non-goals

**D2 — the ledger family stays unprotected.** Class C relations receive no RLS in this ADR. Per-tenant
screening evidence — ledger events, request and response snapshots, retention tombstones — remains
readable across tenants by any principal with database access. This is the single largest residual
risk in this document, and it is accepted here on the grounds that the screening path has no
authenticated tenant to bind (§2) and that inventing one for a backfill would attribute historical
evidence on a guess. **Re-entry condition:** once `internal/screeningapi` carries an authenticated
tenant under SEC-1b, Class C gets its own ADR and migration under **SEC-1c**, including how
historical ledger rows are attributed. Owner and issue exist so this is a scheduled debt, not a
silence.

**SEC-5 is not fixed.** §6 states the residual TOCTOU precisely.

**SEC-7 is orthogonal.** RLS constrains which rows a principal sees; it does not stop a principal
with write access from forging an audit chain.

**Application-layer checks stay.** `tenantOK` (`internal/reviewconsoleapi/server.go:209`) remains as
defence in depth. RLS does not replace it — RLS protects the rows, the handler check protects against
a handler that queries with the wrong binding — and neither is sufficient alone.

**D1 prolongs SEC-3.** Binding against the `psql` sinks keeps the `fork`+`exec` call shape, and with
it the DSN-in-`argv` exposure, alive longer than a pgx-first sequencing would have. Accepted: an
unenforced tenant boundary is the larger exposure of the two, and §10 bounds how long the interim
lives.

## 10. Handover to REL-2

The interim binding exists because isolation cannot wait for the persistence rewrite. It is a
security control, not scaffolding — and REL-2 is a persistence change, whose author has no particular
reason to treat it as one.

**REL-2 may not remove, bypass, or weaken the binding as a side effect of a persistence change.**
Removal is a named subtask, **REL-2t**. The specific hazard: `scripts/ci/check_tenant_binding.py` keys
on the seam, so a pgx port that deletes `tenantsql.WithTenant` *and* its call sites together removes
both the control and the check that would have caught it, and CI goes green.

`REL-2t` closes only when all of the following hold, in this order:

1. `internal/tenantsql` grows a pgx binding that issues the tenant `set_config(..., true)` as the
   first statement inside `BeginTx`, behind the **same exported seam**, so call sites do not change.
2. The §8 two-tenant suite is re-run **against pgx**, unmodified, and passes — including the reused
   connection case, which is inert under `fork`+`exec` and only becomes a real test once connections
   are pooled.
3. `check_tenant_binding.py` is retargeted to the pgx call sites and still fails on a deliberately
   unbound query, verified by a negative test rather than by inspection.
4. The §7 stage-2 shadow counter is re-armed across the cutover and reads zero.
5. Only then are the `psql`-script envelope and the sink `run()` helpers removed, in a PR citing both
   REL-2 and SEC-1. No allowlist entry is deleted by this step. The transitional entries are already
   empty by this point (§3), and the three permanent entries — `Migrate`, `Ping`, `db/migrations/` —
   are **re-pointed** at their pgx equivalents rather than removed. They are global by design, not by
   deferral, so they outlive the binding implementation they were written against.

If REL-2 is descoped or deferred indefinitely, nothing in this ADR regresses. The interim is complete
on its own terms; it is not a stopgap waiting to become correct.

## Consequences

**Positive.** Tenant isolation becomes a property the database enforces rather than one each handler
remembers to check. The seam gives a single place to change binding semantics, and the CI check makes
partial adoption — across five screening-api variants and five sinks — impossible to ship quietly.
The invariants convert three controls that currently exist only as intent into things CI can fail on.

**Negative.** A write-outage window during the migration (§5). Two binding implementations until
REL-2t closes. A CI check that will reject legitimate new query sites until their author routes them
through the seam, which is the intended friction. And an ADR-sized amount of process attached to what
looks, from the outside, like adding a `WHERE` clause.

**Neutral but worth stating.** Nothing here improves matching, scoring, or throughput. SEC-1 closing
does not move the platform closer to production capability on the DOM-* axis; it removes one of the
reasons a pilot could not be run at all.

## Addendum: seam PR findings

Recorded during implementation of §2/§3 (`internal/tenantctx`, `internal/tenantsql`, and the retrofit
of `internal/alertcase`, `internal/assistancerag`, `internal/vendoradapter`, `internal/productionops`,
`internal/screeningledger`). This section documents what the design above missed and how it was
actually resolved — it is not a redesign, and none of it changes §2–§9's decisions.

### 1. §3 assumed a DB-side lookup could resolve tenant for `SyncAudit`; it cannot

§3 specifies that `internal/tenantsql` "owns the transaction envelope" for SQL touching a
tenant-scoped relation, and §5's migration derives `alert_case_audit`/`case_assistance_audit`
tenant_id via a join on `object_type`/`object_id` to the owning Class A record. Read together, the
implicit assumption was that `SyncAudit`'s Go-level sweep of the on-disk audit-event backlog could
resolve each event's tenant the same way: query the owning record.

That assumption is wrong, and not as a corner case. `alert_record`, `alert_case`, and
`case_assistance_record` already carry `FORCE ROW LEVEL SECURITY` (`db/migrations/013_force_rls.sql:30-32`,
landed by SEC-1a before this PR), with policy
`USING (openwatchlist_tenant_visible(tenant_id))` (`db/migrations/009g_production_hardening.sql:94`),
where `openwatchlist_tenant_visible` reads `current_setting('openwatchlist.tenant_id', true)`
(`db/migrations/009g_production_hardening.sql:84-85`). With no GUC bound, that reads `NULL`, and
`row_tenant = NULL` is never `true` — so a `SELECT tenant_id FROM alert_case WHERE case_id = ...`
issued over the seam's own `owl_app` connection returns **zero rows, unconditionally**, before a
tenant is known. This is the same fail-closed behavior the ADR's Context section already documents
for reads in general; it was not previously connected to the resolver `SyncAudit` would need.

The policy's only escape hatch is `current_setting('openwatchlist.tenant_id', true) = '*'`
(`db/migrations/009g_production_hardening.sql:85`), reserved for the operator role. `tenantctx.Resolve`
refuses to construct a `'*'` tenant (`internal/tenantctx/tenantctx.go:39-41`,
`ErrWildcardTenant`), which is exactly what invariant 6 in §8 requires ("No policy reachable by
`owl_app` admits the `'*'` wildcard") — so there is no code path by which the seam could grant itself
the bypass. A live Postgres join for this resolver, run over `owl_app`, is a structural dead end, not
a missing index or a performance concern.

**Resolution.** `SyncAudit` resolves tenant from the on-disk sibling record instead of a query —
`internal/alertcase/postgres.go:239` (`lookupAuditTenant`) reads `alerts/<id>.json` or
`cases/<id>/projection.json` under the same `stateDirectory` the function already receives, using the
package's existing path-confinement helpers (`internal/alertcase/state_path.go:39,85,92`);
`internal/assistancerag/postgres.go:215` (`resolveAuditTenant`) reads `assistance/<id>.json` the same
way (`internal/assistancerag/state_path.go:31,77`). This is the same `object_type`/`object_id` join §5
specifies for the Postgres backfill, sourced from disk instead of SQL — the on-disk state directory is
already the authoritative read source per this ADR's own Context section ("the review console reads
from the filesystem state directory... the Postgres sinks are write-only mirrors"). An event whose
`object_id` doesn't resolve — missing file, unreadable, empty `tenant_id` — is logged with its
`stream_id`/`sequence`/`object_type`/`object_id`/attempted path and skipped; it is never fatal to the
rest of the sweep and never defaulted to a guessed tenant (`internal/alertcase/postgres.go:229-237`,
`internal/assistancerag/postgres.go:215-232`). Resolved events are grouped by tenant so each Postgres
transaction still binds exactly one (`internal/alertcase/postgres.go:174-198`,
`internal/assistancerag/postgres.go:167-193`).

### 2. `productionops` has no per-ID on-disk index; tenant is resolved in-batch instead

Unlike `alertcase`/`assistancerag`, `internal/productionops` has no `Store` type and no per-ID lookup
path into the state directory — `SyncVendorAdapterState` and `SyncOutbox` are pure glob-and-read
sweeps (`internal/productionops/postgres.go:110`, `:209`). Applying the same disk-resolver pattern as
§1 above would mean re-reading an arbitrary file by ID with no existing helper to do it safely.

**Resolution.** Both functions build the object_id → tenant_id join in memory from the same batch
already being read, rather than from a persistent index: `SyncVendorAdapterState` records each
`vendor_adapter_record`'s `RecordID → TenantID` while processing the `records` glob, then looks that
map up for the `receipts` and `audit` globs processed in the same call
(`internal/productionops/postgres.go:110-198`); `SyncOutbox` does the same for `MessageID → TenantID`
across `messages` and `events` (`internal/productionops/postgres.go:209-273`). This matches §5's join
semantics (`record_id`/`object_id` → owning record, `message_id` → owning message) but there is **no
cross-run persistent index** — a receipt, audit event, or outbox event whose owning record/message is
not present in *that run's* batch is logged with its identifying fields and skipped
(`internal/productionops/postgres.go:159`, `:182`, `:255`), not guessed at. Under normal operation this
is a non-issue because nothing in either sync path deletes or archives processed files (verified by
inspection — no `os.Remove`/`os.Rename` touches `records`/`receipts`/`audit`/`messages`/`events`), so
an owning record present in one run is present in every subsequent run too.

### 3. Transaction granularity in `productionops` changed from one commit per run to one per tenant group

Before this PR, `SyncVendorAdapterState` and `SyncOutbox` each built one `BEGIN;...COMMIT;` string
spanning every file in the batch and issued it as a single `psql` invocation — one transaction per
run, regardless of how many tenants' data it carried. `tenantsql.WithTenant` binds exactly one tenant
per transaction (§3), and a sync run spans every tenant with pending state, so this PR necessarily
changed the unit of atomicity from "the whole run" to "one tenant's slice of the run": resolved rows
are grouped by tenant (`tenantBatch`, `internal/productionops/postgres.go:72-97`) and each group is
committed as its own `WithTenant` call (`internal/productionops/postgres.go:198`, `:271`).

**Why partial completion on crash/retry is still safe.** A crash between two tenant groups (A
committed, B not yet started) is a new observable state that did not exist before this PR — the
question is whether re-running the sync after such a crash is safe, and it is, for reasons checked
against the actual schema and code rather than assumed:

- **The retry path is "re-derive from unchanged source," not "resume from a cursor."** Neither
  function's source directories are ever mutated by these code paths (confirmed by inspection, §2
  above), so a retry re-globs the identical files and rebuilds byte-identical tenant groups. There was
  no offset or watermark before this PR either — full-batch re-scan was already the retry mechanism.
- **Every `ON CONFLICT` target is a real constraint keyed on content, not on when the row was
  written**, and none of the five statements is `DO UPDATE`:

  | Table | Conflict target (`internal/productionops/postgres.go`) | Backing constraint |
  |---|---|---|
  | `vendor_adapter_record` | `record_id` (`:145`) | `record_id text PRIMARY KEY` (`db/migrations/009e_vendor_adapter_ingress.sql:3`) |
  | `vendor_adapter_idempotency` | `scope,idempotency_key` (`:168`) | `PRIMARY KEY(scope,idempotency_key)` (`db/migrations/009e_vendor_adapter_ingress.sql:12`) |
  | `vendor_adapter_audit` | `audit_sha256` (`:195`) | `UNIQUE(audit_sha256)` (`db/migrations/009e_vendor_adapter_ingress.sql:18`) |
  | `operational_outbox_message` | `message_id` (`:241`) | `message_id text PRIMARY KEY` (`db/migrations/009g_production_hardening.sql:20`) |
  | `operational_outbox_event` | `event_sha256` (`:268`) | `event_sha256 text PRIMARY KEY` (`db/migrations/009g_production_hardening.sql:35`) |

  Every one of these values is read out of the static JSON file, computed once by the producer, not
  regenerated per sync attempt — so a retry issues a byte-identical statement against an
  already-satisfied constraint and Postgres no-ops it. There is no path to a double-write.
- **Each tenant's transaction is still atomic.** `p.run`/`p.Run` sends the full
  `"BEGIN;\n...\nCOMMIT;\n"` text to one `psql` session; a process killed before `COMMIT;` leaves
  Postgres to roll that session back. Partial completion only ever happens *between* tenant
  transactions, never *within* one.
- **FK ordering survives the split.** Within one tenant's accumulated statement string, records are
  always appended before the receipts/audits/events that reference them (`internal/productionops/postgres.go:110-198`,
  `:209-273`), and a referencing row is always grouped into the *same* tenant bucket as the record it
  references, since both are resolved from the same `RecordID`/`MessageID` map. A row's FK dependency
  is therefore always satisfied inside its own single-tenant transaction — there is no cross-transaction
  FK dependency for a partial run to break.
- **The skip path (§2) is unaffected by retry.** "Owning record not in this batch" is deterministic
  given unchanged source files: a row that resolved on one run resolves identically on the next
  (re-processed as a no-op), and one that didn't resolve logs and skips identically both times.

**Checked consequence: advisory-lock scope narrowed from run-level to tenant-group-level.** Before
this PR, `SyncVendorAdapterState`/`SyncOutbox` acquired `pg_advisory_xact_lock` once
(`hashtext('openwatchlist-phase9g-vendor-sync')` / `hashtext('openwatchlist-phase9g-outbox-sync')`)
inside the single run-spanning transaction, so two concurrent invocations were fully serialized against
each other for the whole run. After this PR, the same lock key is acquired and released inside each
per-tenant transaction (`internal/productionops/postgres.go:198`, `:271`) — so two concurrent
invocations can now interleave at tenant-group granularity: one process's tenant-A transaction can
commit and release the lock while another process's tenant-A transaction (from a separate, concurrent
run) proceeds next, interleaved with the first process's tenant-B transaction. This is a real
narrowing of the mutual-exclusion guarantee, not a hypothetical one, and it is stated here as a
checked consequence rather than asserted safe by omission: it remains safe only because of the same
idempotency argument above (every statement either tenant-group's transaction could issue is
`ON CONFLICT ... DO NOTHING` on a content-derived key), not because serialization still holds — it
does not, at sub-run granularity.

## Addendum: migration PR findings

Recorded during implementation of §5/§6/§7/§8 (`db/migrations/014_tenant_isolation.sql`,
`db/rollback/014_tenant_isolation_down.sql`, the seven new invariants in
`test/sql/security_invariants.sql`, and the two-tenant suite in
`internal/integrationtest/tenant_isolation_test.go`), verified against a real local Postgres 17
instance provisioned identically to CI (`scripts/ci/provision_test_roles.sh`), not asserted from
inspection alone. This section documents what §5's design missed and how it was actually resolved —
it is not a redesign.

### 1. `owl_migrator` needed the operator wildcard bound for its own backfill

§5 does not say what identity the migration's own JOINs read Class A tables as, beyond "runs as
`owl_migrator`." That identity turned out to matter: `owl_migrator` ran the `CREATE TABLE` statements
for every Class A relation (`009ab`/`009c`/`009e`/`009f`), so it *owns* them, and `alert_record`,
`alert_case`, `case_assistance_record`, `vendor_adapter_record` already carry
`FORCE ROW LEVEL SECURITY` (`013_force_rls.sql`, merged before this migration). `FORCE` applies to the
owner too — so without a bound tenant GUC, every JOIN in this migration against a Class A table,
*including the alert_case_membership cross-tenant pre-check itself* (§5 point (e)), silently saw zero
rows: not because nothing matched, but because RLS hid everything. Confirmed empirically: seeded a
real cross-tenant `alert_case_membership` violation, ran the migration, and it committed successfully
— the pre-check had found "0 violations" for the wrong reason. This is exactly the class of bug this
ADR exists to eliminate, and it was invisible against CI's empty-database migration run, which has no
data for RLS to hide.

**Resolution.** The migration binds the operator wildcard for the lifetime of its own transaction
before any Class A read (`db/migrations/014_tenant_isolation.sql:50`,
`SELECT set_config('openwatchlist.tenant_id', '*', true)`), `is_local=true` so it cannot leak past
`COMMIT`/`ROLLBACK`. This does not touch invariant 6 (no wildcard reachable from `owl_app`): the
invariant is about `owl_app`, a distinct, less-privileged role that never runs a migration file.

### 2. Foreign-key checks bypass row security — ten policies needed a cross-reference `WITH CHECK`

§5's uniform `openwatchlist_tenant_visible(tenant_id)` policy (same predicate on `USING` and
`WITH CHECK`, applied identically to all 16 relations) verifies a row's *own* `tenant_id` column. It
does not verify that a row's *reference* to another tenant-scoped relation agrees. Postgres
referential-integrity checks bypass row security by design — documented Postgres behavior, since an RI
check must see the referenced row regardless of the querying session's visibility, or it could not
enforce integrity at all. Confirmed empirically: bound as one tenant, a plain `INSERT` into
`alert_case_membership` referencing another tenant's real, existing `alert_record` row succeeded — the
row's own `WITH CHECK` passed (its own `tenant_id` matched the GUC) and the FK check to `alert_record`
ignored RLS entirely. A normal tenant-bound caller could create a **new** cross-tenant link at any
time going forward; §5's pre-check only ever screens for pre-existing violations, once, at migration
time.

**Resolution.** Ten of the eleven Class B relations reference another Class A/B relation and gained an
explicit `EXISTS` subquery in `WITH CHECK` verifying the referenced parent belongs to the same tenant
as the row being written (`db/migrations/014_tenant_isolation.sql:444-548`) — an `EXISTS` subquery,
unlike an FK check, is an ordinary query and *is* subject to the querying session's RLS, so it only
finds the parent when visible under the current binding. `operational_outbox_message` is the one
Class B relation with no incoming reference to verify and keeps the bare predicate. The comparison is
against the child row's own `tenant_id` column, not directly against
`current_setting('openwatchlist.tenant_id')`: for any concrete tenant the two are equivalent (the bare
predicate already forces the child's `tenant_id` to equal the GUC), but they diverge under the
operator wildcard, where comparing directly to the GUC would require the parent to literally have
`tenant_id='*'` — which no real row has — wrongly rejecting every operator-authored write. `USING`
keeps the bare predicate: every row already reaching a table was verified against its parent either at
backfill time (§5) or by this same `WITH CHECK` at insert time, so re-verifying on every read is
redundant work, not a coverage gap. Every one of the ten new subqueries has its own empirical
regression case in `internal/integrationtest/tenant_isolation_test.go`'s `FKCrossing` subtests — one
relation's correct subquery does not imply another's is, and two were caught wrong during development
(a naming mismatch between seeded fixture IDs and the test's own forged rows initially made two of the
ten "pass" for referencing a row that did not exist under either tenant, not for correctly detecting
the cross-tenant case).

### 3. `case_assistance_idempotency`'s `review_event` rows need scope-parsing in the policy, not just the backfill

Documented already as a backfill-derivation correction (§5's file header), but it applies equally to
the new `WITH CHECK`: `object_id` for a `review_event`-scoped row is a per-assistance sequence number
(`"1"`, `"2"`, …), not an `assistance_id` — the real owner is recoverable only by parsing it out of
`scope` (`"review:"+assistance_id`, per `internal/assistancerag/store.go:369`). The policy's `EXISTS`
subquery for this branch repeats the identical `substring(scope FROM length('review:') + 1)`
derivation the backfill uses (`db/migrations/014_tenant_isolation.sql:504`), and has its own dedicated
integration-suite case (`FKCrossing/case_assistance_idempotency_review_event_branch_via_scope`) rather
than relying on the `assistance`-branch case to stand in for it.

### 4. `screening_idempotency_receipt` correction

§6 originally listed `screening_idempotency_receipt` as receiving the tenant-scoped key change in this
migration. Corrected in §4/§6/§9 directly (not just here): `internal/screeningapi` has no tenant
concept anywhere to backfill from or write going forward, so the table stays fully inside the Class C
deferral. See §4 Class C and §6 for the corrected text and reasoning; noted here only so this
addendum's own list of migration-PR corrections is complete.
### 5. Class D's `rag_corpus_snapshot` classification did not extend to `internal/rag`

§4's Class D table classifies the Postgres relation `rag_corpus_snapshot`
(`db/migrations/009c_governed_rag_ai_assistance.sql:2`) as platform-global: "Content-addressed corpus
shared across tenants; per-tenant use is recorded on `case_assistance_record`" (line 273). That
relation is owned by `internal/assistancerag` (`internal/assistancerag/postgres.go`), one of the
packages this addendum's §1 and §2 already retrofit through `tenantsql.WithTenant`.

Two unrelated systems share the name. `internal/rag` — a second, independent retrieval
implementation used by `cmd/rag-query`, `cmd/rag-index`, `cmd/review-run`, and
`internal/revieworchestrator` — defines its own `CorpusSnapshot` type (`internal/rag/types.go:65`)
under schema string `rag-corpus-snapshot/v1alpha1` (`internal/rag/types.go:5`). It is file-based:
`rag.LoadSnapshot` reads a JSON file from disk, and no Postgres relation backs it at all.
`cmd/rag-index/main_test.go:1-13` documents this collision directly — it records that the repo has
"TWO separate, parallel RAG implementations," `internal/rag` and `internal/assistancerag`,
distinguished only by actually running the binary against the fixtures and diffing output, because
the two packages' schemas are otherwise easy to conflate.

Because `internal/rag` creates no relation under `db/migrations/`, it cannot appear in §4's table —
the table's own governing rule is that every relation created under `db/migrations/` appears exactly
once (lines 230-232) — and Class D's stated rationale for `rag_corpus_snapshot` ("per-tenant use is
recorded on `case_assistance_record`") was never about, and does not extend to, `internal/rag`'s
document set.

`internal/rag`'s `DocumentSpec` carries a real per-document `TenantID` (`internal/rag/types.go:33`),
and the retriever does filter on it: `documentAllowed` excludes a document whose `Spec.TenantID` is
non-empty and unequal to `query.TenantID`, incrementing `ExcludedTenantOrScope`
(`internal/rag/retrieve.go:122-124`). That filter runs; it is not theatre. What is unverified is
`query.TenantID` itself. `cmd/rag-query` and `cmd/review-run` — the entry points that build a
`RetrievalQuery` — take tenant identity from a plain `--tenant-id` flag, defaulted to `"tenant-a"`
and checked against nothing (`cmd/rag-query/main.go:20`, `cmd/review-run/main.go:30`).
`revieworchestrator.Run` passes it straight through into `rag.QueryFromDecision`
(`internal/revieworchestrator/orchestrate.go:38`, `:87`) with no intervening check. There is no
`reviewauth.Claims`, no token, nothing upstream of `internal/rag` resembling the verified-claims
input `tenantctx.Resolve` requires (`internal/tenantctx/tenantctx.go:35-44`) — the caller asserts a
tenant and the retriever trusts the assertion.

**Out of scope for the 014 migration; tracked separately as SEC-1d.**
`db/migrations/014_tenant_isolation.sql` operates on Postgres relations only (§5); `internal/rag` has
no database relation to seal, so there is nothing for that migration to touch. Closing this gap means
giving `cmd/rag-query`, `cmd/review-run`, and any future service wrapping them an authentication
mechanism to derive `TenantID` from, following the same pattern §2 established via
`tenantctx.Resolve` (`internal/tenantctx/tenantctx.go:35-44`): a verified-claims input in, a bound
tenant out, with the same wildcard and empty-tenant refusals `Resolve` already implements. Until that
identity exists, this is the same "tenant identity is currently chosen by the caller" hazard the
Context section names for `internal/alertcaseapi` (line 52), on a code path the Context section does
not cover. The draft security advisory "Tenant isolation is not enforced"
(`scripts/create-advisories.sh:36-39`, currently `Status: partially addressed`) is written broadly
enough to cover this gap; its description should be understood to include `internal/rag`'s
CLI/future-service callers, not only the Postgres-bound paths this ADR closes.

**Distinct, separately-tracked bug: `AccessScope` is validated but never enforced (SEC-14).**
`DocumentSpec.AccessScope` (`internal/rag/types.go:34`) is required to be non-empty at manifest
validation — `ValidateManifest` rejects a document with `len(doc.AccessScope) == 0`
(`internal/rag/validate.go:24`) — but nothing downstream ever reads it. `documentAllowed`
(`internal/rag/retrieve.go:117-141`) checks source tier, approval status, `TenantID`, and the
effective-date window; it does not reference `AccessScope`. `RetrievalQuery`
(`internal/rag/types.go:96-112`) has no scope field to compare it against, and a repo-wide search
confirms `AccessScope` appears at exactly the two sites above and nowhere else in the module. The
counter its name implies it drives, `ExcludedTenantOrScope` (`internal/rag/types.go:145`), is
incremented from exactly one branch — the `TenantID` check (`internal/rag/retrieve.go:123`) — and no
branch increments it for scope. The name promises an enforcement the code does not perform. This is
independent of SEC-1d above: even a fully authenticated `TenantID` would not stop a document from
being retrieved outside its declared `AccessScope`, because nothing checks `AccessScope` at all.

## Addendum: citation corrections

Two line-number citations in §2 were inaccurate in the original text and are corrected here:

1. **Claims.TenantID location.** §2 cites `internal/reviewauth/types.go:57` as the definition of
   `Claims.TenantID`. The correct location is `types.go:40`. Line 57 defines `SecurityAuditEvent.TenantID`,
   an adjacent but distinct field in the same file.

2. **TenantID decode location.** §2 cites `internal/reviewauth/token.go:136` as where `Parse` decodes
   `TenantID`. The correct location is `token.go:105`, where `d.Decode(&c)` unmarshals the JWT claims
   payload into the `Claims` struct. Line 136 is where the already-decoded `c.TenantID` is consumed as
   an argument to `s.Registry.RolesFor(u, c.TenantID)` to re-derive roles.
