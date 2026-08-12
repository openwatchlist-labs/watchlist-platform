# ADR-0005: Persistence connection pooling

- **Status:** Proposed
- **Date:** 2026-08-12
- **Issue:** REL-2 (P1)
- **Related:** SEC-1 (ADR-0001, accepted), SEC-3, SEC-1c, SEC-5, REL-10 (ADR-0002), SEC-1b
  (ADR-0003), INFRA-4, GHSA-vhj8-986g-vjf4
- **Supersedes:** nothing. Discharges the handover ADR-0001 §10 records as `REL-2t`. ADR-0001 is
  **not** modified by this document; two corrections to its §10 are recorded here in §10 instead.

## Context

Every Postgres write in this platform is `fork`+`exec psql`, one process per statement, with SQL
assembled by string concatenation over hex-encoded literals and the DSN passed as `argv[1]`. ADR-0001
§3 built the tenant-binding seam (`internal/tenantsql`) against that call shape deliberately — D1 in
that document — so that isolation would not wait for the persistence rewrite, and §10 makes retiring
the interim a named, tested subtask rather than a side effect of a persistence change.

This ADR is that subtask's design. Four facts about the current tree are load-bearing, and each was
verified against the working tree rather than inherited from ADR-0001, which was written before
REL-10, SEC-1b and DOM-3 landed.

### The seam is intact, and the four-sink list is still accurate

`tenantsql.WithTenant` (`internal/tenantsql/tenantsql.go:47`) emits `BEGIN`, a
`set_config('openwatchlist.tenant_id', …, true)`, the caller's body, and `COMMIT`, and hands the
result to a `Runner` (`:33`) along with a `Bound` proof value (`:25-29`) that only `tenantsql` can
construct. Four sinks hold a `runBound` adapter and route every tenant-scoped write through it:

| Sink | `runBound` | `WithTenant` call sites |
|---|---|---|
| `internal/alertcase` | `postgres.go:72` | `:107`, `:158`, `:220` |
| `internal/assistancerag` | `postgres.go:69` | `:116`, `:155`, `:210` |
| `internal/vendoradapter` | `postgres.go:47` | `:79` |
| `internal/productionops` | `postgres.go:60` | `:94` (via `tenantBatch.commit`) |

`db/tenant_scoped_tables.txt` still carries exactly the sixteen Class A and Class B relations from
ADR-0001 §4. One of them, `review_security_audit_event`, has **no Go writer at all** — the only
`INSERT` naming it anywhere in the tree is the test fixture at
`internal/integrationtest/tenant_isolation_test.go:162`. That is not a REL-2 problem, but it means the
four sinks above cover fifteen relations, not sixteen, and a reader checking coverage should not go
looking for a fifth sink that does not exist.

### `internal/screeningledger` is structurally different, and stays that way

It imports neither `tenantctx` nor `tenantsql`. Its four write paths — `PostgresSink.Persist`
(`internal/screeningledger/postgres.go:60-74`), `PersistAudit` (`:83-89`), `PurgeExpired` (`:93-98`)
and `PersistExternalAudit` (`:102-107`) — each emit a bare `BEGIN;` / `COMMIT;` envelope with **no**
tenant GUC. That disposition is recorded in the package's own doc comments (`:76-82`, `:91-92`,
`:100-101`): its relations are Class C, deferred by ADR-0001 D2, and absent from
`db/tenant_scoped_tables.txt` by design.

Confirmed as a direct consequence: **ADR-0001 §10 items 1 through 4 do not apply to this sink.**
They are re-verification obligations for a tenant binding this sink does not have and is not supposed
to acquire under REL-2. §4 below scopes it as a separate, simpler migration rather than forcing it
into the tenant-bound pattern.

### The `fork`+`exec` inventory is six sites, not five

ADR-0001 §3 names five sinks. A sixth site exists, in a long-running service, and no ADR names it:

| Site | Shape | Process shape |
|---|---|---|
| `internal/screeningledger/postgres.go:21`, DSN at `:55` | stdin script | CLI |
| `internal/alertcase/postgres.go:29`, DSN at `:64` | stdin script | service and CLI |
| `internal/assistancerag/postgres.go:28`, DSN at `:61` | stdin script | service |
| `internal/vendoradapter/postgres.go:36` | `-c <sql>`, DSN `argv[1]` | service |
| `internal/productionops/postgres.go:42` | stdin script | CLI |
| `internal/productionops/runtime.go:81` | `-c "SELECT 1"`, DSN `argv[1]` | **service, per request** |

The last is `CheckRuntime`'s PostgreSQL readiness probe (`internal/productionops/runtime.go:73-87`),
reached from `internal/platformapi/server.go:155` and routed at `:178-179` on `/readyz`, served by
`cmd/platform-api` (`main.go:58`). Every readiness probe forks a psql process. §11 migrates it.

### Process shape does not follow the sink list

REL-2's framing question — where does a connection *pool* help — is answered per constructed object,
not per package, because the same package is constructed in both shapes.

Long-running HTTP servers: `cmd/alert-case-api/main.go:47`, `cmd/case-assistance-api/main.go:33`,
`cmd/vendor-adapter-api/main.go:40`, `cmd/platform-api/main.go:58`. The three sink-holding services
construct their sinks at `internal/alertcaseapi/server.go:30`, `internal/assistanceapi/server.go:44`
and `internal/vendoradapterapi/server.go:32`.

`internal/productionops` is **CLI-only for writes**: `PSQLRunner` is constructed at
`cmd/platform-ops/main.go:220` and `:231` and nowhere else, and neither entry point serves HTTP. So
the real split is three tenant-bound service sinks, one tenant-bound CLI sink, one unbound CLI sink,
and one service-side readiness probe — not "four services and one CLI".

## Decision

Replace `fork`+`exec psql` with `jackc/pgx/v5`, keeping SQL-text authorship inside `internal/tenantsql`
so the CI control that guards the tenant binding survives the rewrite unchanged; pool for
long-running services, use a single connection for CLIs; migrate `internal/screeningledger` first and
separately because it carries none of ADR-0001 §10's verification burden; and construct the cutover
assertion §10 assumes already exists.

| # | Decision | Consequence |
|---|---|---|
| **D1** | SQL-text authorship **stays inside `tenantsql`**. Sinks keep passing column data; `tenantsql` keeps writing the verb text, now with `$n` placeholders. | `scripts/ci/check_tenant_binding.py` needs no change to its detection at all. The idiomatic-pgx alternative — SQL literals at every call site — would force a wave of new allowlist entries and silently retire the control. See §2 and §10 item 3. |
| **D2** | The seam's **exported function keeps its name and its first three parameters**; what changes is the `Runner` contract and each sink's four-line `runBound` helper. | ADR-0001 §10 item 1's "same exported seam so call sites do not change" is satisfied as far as it can be: the body-construction logic is byte-identical and **one argument per call site changes**. Stated as a partial fit rather than claimed as none. |
| **D3** | `tenantsql.Bound` is **deleted** and replaced by a structural control the compiler enforces: `tenantsql.DB` holds the pool in an unexported field and exposes no executor. | A control may only be removed by naming its replacement. The replacement is stronger — under the seam today a sink still owns a runner it could call directly; after this it owns nothing that can execute SQL. |
| **D4** | **Pool for services, single connection for CLIs.** `pgxpool.Pool` for the three service sinks and the readiness probe; one `pgx.Conn` per invocation for `screeningledger` and `productionops`. | A pool amortizes connection setup across concurrent requests. `cmd/screening-ledger`'s sync loop is strictly sequential, so a pool would never hold more than one connection in use while adding a health-check goroutine and lifecycle configuration that buy nothing. See §3. |
| **D5** | ADR-0001 §10 item 2 is **split in two**: re-run the existing suite unmodified *and* add a pgx-only sibling that pins `MaxConns=1`. | The named test is not a pool test and cannot become one by being re-run. §10 item 2 records why. |
| **D6** | §7 stage 2's shadow counter is **constructed, not re-armed**, and it moves from SQL to Go. | The mechanism ADR-0001 describes was never built. Post-enforcement, a SQL-side counter downstream of an RLS rejection would structurally always read zero. See §7. |
| **D7** | Pool sizing, timeouts and `statement_timeout` / `idle_in_transaction_session_timeout` are **set explicitly**, never left to library defaults. | pgxpool's `max(4, NumCPU)` default couples the Postgres connection budget to a container CPU limit. And `fork`+`exec` was silently supplying a transaction-abandonment backstop that a pooled connection does not. See §3. |
| **D8** | **No automatic retry** in the first cutover. | The idempotency writes deliberately raise on `23505`, and `productionops`' advisory-lock scope is already narrowed to tenant-group granularity. A silent retry hides divergence in precisely the places this repository has decided not to hide it. |
| **D9** | Six staged PRs, `screeningledger` **first and independent**, the four tenant-bound sinks **together**. | It is the largest fork-count reduction, it proves the dependency before any security-control code depends on it, and it carries none of §10 items 1–4. The four tenant-bound sinks cannot be half-migrated without maintaining two seams at once. See §5. |
| **D10** | The three dormant `database/sql` shims are **resolved in REL-2**, not left dormant-but-newly-possible. | REL-2's own dependency addition is what makes them constructible. See §11. |
| **D11** | **SEC-3 closes in full under REL-2 — both halves.** | Removing psql closes the child-process half automatically and closes none of the CLI-`argv` half, whose last visible marker REL-2's own diff deletes. See §11. |
| **D12** | The `/readyz` psql fork is migrated in the same PR, closing the **last `fork`+`exec psql` call site in non-test code**. | The two-tenant suite keeps shelling out to psql deliberately and permanently; the claim carries that carve-out or it is false. See §11. |

## 1. Scope

In scope: the pgx binding shape (§2); pool and connection lifecycle, sizing, timeout and retry
semantics (§3); `screeningledger`'s separate migration path (§4); migration order and the dependency
obligation (§5); rollback (§6); the cutover assertion (§7); the test bar (§8); the `REL-2t` closure
checklist executed item by item against ADR-0001 §10 (§10); and SEC-3 closure, `/readyz`, and the
dormant shims (§11).

Out of scope, each with a pointer:

- **Whether `screeningapi` should write to the ledger on the request path** — undesigned, belongs to
  SEC-1c's own ADR. §9 records it as a forward-compatibility constraint on this design, not as a
  call site this document designs for.
- **RLS coverage for Class C** (ADR-0001 §9, SEC-1c). REL-2 changes the driver, never the policy set.
- **The idempotency TOCTOU** at `internal/screeningledger/postgres.go:66` (ADR-0001 §6, SEC-5).
- **`ON CONFLICT ... DO NOTHING` on the ledger writes** (`postgres.go:69`, `:71`, `:72`) — a live
  instance of the repository's own "do not swallow conflicts" trap. §4 preserves it verbatim across
  the driver change and says so, rather than either fixing it under a persistence label or copying it
  forward silently.
- **Normalization, catalog format, matching, scoring.** Untouched.

This ADR documents a decision. Implementation is six separate PRs (§5), per hard rule 7.

## 2. The pgx binding

### 2.1 Why the SQL text stays inside `tenantsql`

`scripts/ci/check_tenant_binding.py` is **runner-agnostic**, and that is the leverage point for this
whole migration. It scans Go string literals for a SQL verb followed by a relation named in
`db/tenant_scoped_tables.txt` (`:126-151`) and fails on any hit outside `internal/tenantsql/` and the
two-class allowlist. It knows nothing about psql, about `Runner.Run`, or about pgx. ADR-0001 §3
point 3 also described a "no direct `Runner.Run(` call site" grep as a backstop; that was never
implemented, and the literal scan is the entire check.

So the check's real invariant is the one `tenantsql`'s own package comment states
(`internal/tenantsql/tenantsql.go:1-9`): after the seam exists, the literal text
`INSERT INTO <tenant-table>` cannot appear anywhere else in the tree.

The idiomatic pgx shape would destroy that invariant on contact:

```go
// REJECTED. This is what "port the sinks to pgx" looks like if written naturally.
_, err := tx.Exec(ctx, "INSERT INTO alert_record(alert_id,tenant_id,...) VALUES ($1,$2,...)", ...)
```

Every sink call site would then spell a tenant-scoped relation, `check_tenant_binding.py` would fail
on all of them, and the fix a hurried author reaches for is an allowlist entry per site. That converts
a CI-enforced shrinking transitional list — currently **empty**, with the end state enforced
(`db/tenant_binding_allowlist.txt:21-25`) — into a permanent one, and retires the control while CI
stays green. This is the same shape as the hazard ADR-0001 §10 already names for deleting
`WithTenant` and its call sites together, arrived at from a different direction.

**Decision (D1):** sinks continue to pass column data; `tenantsql` continues to write the verb text.
The check is unchanged, and §10 item 3 reduces to adding one negative case rather than retargeting a
detection strategy.

### 2.2 Statements become parameterized; the hex-encoding idiom is retired

`tenantsql.Col` today carries pre-encoded SQL text (`internal/tenantsql/tenantsql.go:59-62`), because
psql has no parameter binding — which is also why five separate copies of a hex-encoding helper exist
(`internal/alertcase/postgres.go:278-283`, `internal/assistancerag/postgres.go:245-250`,
`internal/screeningledger/postgres.go:111-122`, `internal/productionops/postgres.go:49-54`) plus a
sixth, differently-shaped quote-escaper (`internal/vendoradapter/postgres.go:81`). All six are deleted
by this migration.

```go
// Col carries a value, not pre-encoded SQL text. Cast is an optional
// type name rendered as "$n::<cast>" -- the only remaining reason a
// caller needs to say anything about SQL syntax at all.
type Col struct {
    Name  string
    Value any
    Cast  string // e.g. "timestamptz", "jsonb"; empty for none
}

// Stmt is SQL written by this package plus the arguments it binds.
// Sinks accumulate []Stmt instead of concatenating strings.
type Stmt struct {
    sql  string
    args []any
}

func Insert(table string, cols []Col, conflict string) Stmt
func InsertCatchConflict(table string, cols []Col) Stmt
```

Two consequences worth stating rather than discovering during implementation. First,
`fmt.Sprint(event.Sequence)` and friends at the sink call sites become plain values. Second, the
`::timestamptz` and `::jsonb` suffixes currently appended to encoded text move onto `Col.Cast`, so no
sink spells a SQL fragment at all.

### 2.3 `tenantsql.DB` owns the pool; `Bound` is deleted

```go
// DB is the only handle a sink holds. The pool is unexported: there is
// no method on this type that executes caller-supplied SQL outside a
// tenant binding except Unbound, which names its reason from a closed set.
type DB struct {
    pool *pgxpool.Pool
    c    counters // see §7
}

const setTenantSQL = `SELECT set_config('openwatchlist.tenant_id', $1, true)`

func (db *DB) WithTenant(ctx context.Context, tenant tenantctx.Tenant, body []Stmt) error {
    tx, err := db.pool.Begin(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx)
    db.c.opened.Add(1)
    if _, err := tx.Exec(ctx, setTenantSQL, tenant.String()); err != nil {
        return err
    }
    db.c.bound.Add(1)
    for _, s := range body {
        if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
            return err
        }
    }
    return tx.Commit(ctx)
}
```

`set_config(..., true)` remains the mechanism rather than `SET LOCAL`, and pgx strengthens ADR-0001
§3's reasoning rather than weakening it. `SET LOCAL` is a utility statement and accepts no bind
parameter under any driver, so it would still require interpolating the tenant into statement text —
now for no reason at all, since `set_config` takes `$1` as a genuine parameter. The tenant value stops
being encoded into SQL entirely.

**`Bound` is deleted (D3).** Its purpose was to make a sink's raw runner uncallable except through
`WithTenant`. Under this shape a sink has no runner: it holds a `*tenantsql.DB` whose pool is
unexported, so there is nothing to call. The compiler enforces what the proof token enforced by
convention. Removing a control demands naming its replacement, and this is the naming.

`Unbound` exists for the writes that legitimately have no tenant, and it is deliberately awkward:

```go
// Reason values are a closed set. Unbound counts per reason (§7), so the
// soak reads a breakdown rather than a bare number.
const (
    ReasonMigrate      = "migrate"       // DDL as owl_migrator (ADR-0001 §3, permanent allowlist)
    ReasonClassDGlobal = "class-d-global" // e.g. rag_corpus_snapshot (ADR-0001 §4 Class D)
)

func (db *DB) Unbound(ctx context.Context, reason string, body []Stmt) error
```

This is not an escape hatch that defeats D3, and the reason is worth being precise about: `Unbound`
executes whatever `[]Stmt` it is given, but a `Stmt` naming a tenant-scoped relation can only be
produced by `tenantsql.Insert` — or by a caller spelling the relation name itself, at which point
`check_tenant_binding.py`'s lexical scan catches it. The two controls compose: the compiler stops a
sink from reaching an executor, and the lexical check stops a sink from authoring tenant-scoped SQL.

Its current users are `Migrate` and `Ping` (permanent allowlist entries,
`db/tenant_binding_allowlist.txt:17-18`) and `assistancerag.PersistSnapshot`
(`internal/assistancerag/postgres.go:79-83`), which writes `rag_corpus_snapshot` — Class D,
platform-global by design, and already deliberately outside the seam. `Ping` becomes `pool.Ping` and
opens no user transaction, so it leaves the §7 counters alone.

### 2.4 What a call site actually looks like after the change (D2)

ADR-0001 §10 item 1 requires the binding to sit "behind the **same exported seam**, so call sites do
not change." That is achievable for the business logic and not quite achievable for the last argument,
and this document states the partial fit rather than overclaiming:

```go
// internal/vendoradapter/postgres.go:79 -- before
return tenantsql.WithTenant(ctx, tenant, body, p.runBound)

// after
return p.db.WithTenant(ctx, tenant, body)
```

The `body` expression above it — the `tenantsql.Insert(...) + tenantsql.InsertCatchConflict(...)`
construction that is the actual business logic — changes only in that `+` becomes `append`, because
`Stmt` replaces string concatenation (§2.2). Every sink's four-line `runBound` helper
(`internal/alertcase/postgres.go:72`, `internal/assistancerag/postgres.go:69`,
`internal/vendoradapter/postgres.go:47`, `internal/productionops/postgres.go:60`) is deleted, along
with its `run` helper — which is exactly what ADR-0001 §10 item 5 calls "the sink `run()` helpers"
and schedules for removal.

## 3. Pool and connection lifecycle

### 3.1 Pool for services, one connection for CLIs (D4)

A pool amortizes connection setup across many concurrent operations in a long-running process. Two of
the five write paths are not that, and giving them a pool would be cargo cult rather than design.

**`cmd/screening-ledger` (unbound CLI).** Its `sync` loop (`main.go:53-67`) is strictly sequential:
for each unreplicated event it calls `sink.Persist` (`:61`) and `sink.PersistAudit` (`:65`), plus one
`sink.Migrate` per run (`:49`). That is `2N+1` psql processes for `N` events, and it is *never*
concurrent — there is no second goroutine anywhere in the command. A pool would hold exactly one
connection in use for the entire run while adding a background health-check goroutine, reconnect
logic, and five lifecycle knobs that can only be wrong.

**Recommendation for this sink specifically: a single `*pgx.Conn`, opened once per invocation and
closed at exit.** That captures the entire benefit available here — `2N+1` connection setups collapse
to one — with none of the pool's machinery. `import-audit` (`main.go:105-110`, one
`PersistExternalAudit` per record via `external_audit.go:86-90`) benefits identically.

The obvious objection is that a long-lived single connection over a large backlog can be killed
mid-run, and a pool would transparently reconnect. It does not need to: the loop is already resumable
by construction. `store.IsReplicated` (`main.go:54`) skips events already replicated, so a killed run
is re-derived from unchanged source on the next invocation — the same "re-derive, do not resume from a
cursor" property ADR-0001's seam addendum §3 establishes for `productionops`. Failing the run loudly
and letting the operator re-invoke is the correct behavior, not a gap.

**`cmd/platform-ops` (tenant-bound CLI).** Same shape, same recommendation: one connection per
invocation. It differs from `screening-ledger` only in that it *is* tenant-bound, so it takes a
`*tenantsql.DB` constructed over a single connection rather than a pool. `tenantsql.DB` therefore has
two constructors — `Open` (pool) and `OpenConn` (single connection) — behind one type, so no call site
learns which it holds.

**The three service sinks and the readiness probe:** `pgxpool.Pool`.

### 3.2 Sizing and timeouts for the service sinks (D7)

Concrete values, with the reasoning attached, because a table of numbers with no rationale is
re-tuned by the next reader on instinct:

| Setting | Value | Why |
|---|---|---|
| `MaxConns` | `10` | Explicit, **not** pgxpool's `max(4, NumCPU)` default. A CPU-derived pool size means changing a container's CPU limit silently changes the Postgres connection budget — an implicit coupling between two unrelated deployment knobs. |
| `MinConns` | `2` | Keeps warm connections so the first request after an idle period does not pay TCP plus authentication inside its request budget. |
| `MaxConnLifetime` | `30m`, `MaxConnLifetimeJitter` `5m` | Bounded lifetime lets a rolling Postgres upgrade or a credential rotation take effect. The jitter is not decoration: without it every connection in every replica expires in the same second. |
| `MaxConnIdleTime` | `5m` | Releases connections held by a service that has gone quiet. |
| `HealthCheckPeriod` | `1m` | pgxpool's default; no reason to deviate. |
| `ConnConfig.ConnectTimeout` | `5s` | Bounds a single connection attempt independently of the operation budget. |

**The operation budget is unchanged and now covers more.** Each sink already wraps its work in
`context.WithTimeout` using its configured `Timeout` — `alertcase` 20s
(`internal/alertcase/postgres.go:56`, `:62`), `assistancerag` 30s
(`internal/assistancerag/postgres.go:54`, `:59`), `vendoradapter` 10s
(`internal/vendoradapter/postgres.go:29`, `:34`). Those values are kept, and the same ctx now covers
acquire plus begin plus exec plus commit rather than one psql exec. pgxpool honors ctx cancellation on
`Acquire`, so a saturated pool surfaces as a deadline error at the same budget the sink already
declared — no separate acquire timeout is introduced, because a second budget is a second thing to get
wrong.

**`fork`+`exec` was silently providing a transaction-abandonment backstop.** A psql process that hung
mid-transaction was killed by `exec.CommandContext` when the ctx expired, and its backend died with it,
releasing every lock it held. A pooled connection has no such property: the ctx deadline cancels the
Go-side operation, but a server-side statement can keep running and a transaction can stay open. Two
`RuntimeParams` restore it, set on the connection rather than left to server defaults:

- `statement_timeout` = the sink's operation budget.
- `idle_in_transaction_session_timeout` = `30s`.

This is not defensive padding. Without it, the first bug that returns a connection to the pool with an
open transaction holds locks indefinitely on relations that already carry `ACCESS EXCLUSIVE`-taking
migrations, and the symptom is a platform-wide write stall with no error anywhere.

**Connection budget arithmetic.** Postgres' default `max_connections` is 100.
`scripts/ci/provision_test_roles.sh` provisions two roles, and the three sink-holding services each
hold one pool: `3 services × R replicas × 10` connections, plus `owl_migrator` for migrations, plus
`cmd/platform-api`'s readiness pool (§11, `MaxConns` 2). At `R = 2` that is 66 connections, which
fits; at `R = 3` it is 96, which does not leave room for a migration or an operator session. The
deployment plan must state `R` and either raise `max_connections` or lower `MaxConns` before this
runs — the same obligation ADR-0001 §5 places on the migration's write-outage window, for the same
reason: a number that only works at the scale it was tested at is not a design.

### 3.3 Retry (D8)

**No automatic retry in the first cutover.** Surface every error.

pgx already retries connection *acquisition* internally by handing out a different connection when one
is found dead, which is the retry that is unambiguously safe. Application-level retry of a failed
*transaction* is not, here, for reasons specific to this repository:

- The idempotency writes deliberately raise on `23505` rather than swallowing it
  (`tenantsql.InsertCatchConflict`, `internal/tenantsql/tenantsql.go:83-89`), per the repository's own
  "do not swallow conflicts" rule. A retry loop that treats a re-raised unique violation as transient
  reintroduces exactly the swallowing that helper exists to prevent.
- `productionops`' advisory-lock scope is already narrowed from run-level to tenant-group-level
  (ADR-0001 seam addendum §3), and its safety argument rests on every statement being
  `ON CONFLICT DO NOTHING` on a content-derived key — not on serialization, which no longer holds at
  sub-run granularity. Adding a retry on top of a guarantee that was already narrowed once, without
  metrics, is how the third narrowing goes unnoticed.

`40001` and `40P01` (serialization failure, deadlock) are the conventional retry candidates and are
deliberately excluded too: neither is expected on these write paths today, so the first occurrence is
information, and a retry would consume it. Retry is a follow-up with its own ADR once §7's counters
and error metrics have run in production.

## 4. `internal/screeningledger`: a separate, simpler migration

This sink does not participate in the tenant binding and must not be made to. Its migration is
therefore a driver swap and nothing else.

**What it is not.** ADR-0001 §10 items 1–4 are re-verification obligations for a tenant binding.
`screeningledger` has none: its relations (`screening_ledger_event`, `screening_ledger_snapshot`,
`screening_ledger_replication`, `screening_ledger_audit`, `screening_ledger_retention_tombstone`,
`screening_idempotency_receipt`, `watchlist_operational_audit`) are all Class C per ADR-0001 §4,
absent from `db/tenant_scoped_tables.txt`, and carry no RLS policy. There is no GUC to bind, no
two-tenant property to re-prove, no `check_tenant_binding.py` call site to retarget, and nothing for
the §7 counters to count. Recording that as a scoping decision matters as much as recording the work:
an implementer who assumes uniformity across "the five sinks" will either invent a tenant for this one
— which ADR-0001 §4 and §5 both explicitly forbid — or will mark items 1–4 done against a sink they
never applied to.

**What changes.**

- `PostgresSink` holds a `*pgx.Conn` instead of `DSN`/`PSQLPath`/`CommandRunner`
  (`internal/screeningledger/postgres.go:30-35`). `CommandRunner` and `ExecRunner` (`:15-28`) are
  deleted; the interface exists solely to make the fork injectable in tests, and pgx against a real
  Postgres replaces that (§8.2).
- The four write paths keep their transaction envelopes exactly as they are, now as
  `conn.Begin`/`tx.Commit`: `Persist` (`:60-74`), `PersistAudit` (`:83-89`), `PurgeExpired`
  (`:93-98`), `PersistExternalAudit` (`:102-107`). ADR-0001 §3's fix — wrapping the three
  formerly-bare statements so a future local `set_config` could not be a silent no-op — is preserved,
  not undone, even though no `set_config` is issued here.
- Statements become parameterized. `sqlText`, `sqlNullableText` and `sqlJSON` (`:111-122`) are
  deleted; `sqlNullableText`'s empty-string-to-`NULL` behavior becomes a `nil` argument.
- `SchemaSQL` (`:124-143`) is unchanged and still executed by `Migrate` as one multi-statement script.

**What is deliberately preserved, and is a known defect.** The `ON CONFLICT ... DO NOTHING` clauses at
`:69`, `:71` and `:72` are a live instance of this repository's own trap — "`ON CONFLICT DO NOTHING`
on ledger and idempotency writes hides real divergence." REL-2 preserves them verbatim. Changing them
is a behavior change to evidence integrity, it belongs to SEC-5 and SEC-1c, and smuggling it into a
persistence PR is precisely the pattern hard rule 7 exists to prevent. It is named here so the next
reader knows it was seen and left, not missed.

**Role identity, which is currently unstated.** `cmd/screening-ledger` calls `sink.Migrate` — DDL — on
every `sync` (`main.go:49`) and every `import-audit` (`:107`). Its DSN therefore cannot be an
`owl_app` identity, and in fact `scripts/ci/provision_test_roles.sh:78-93` grants `owl_app` nothing on
any Class C relation at all. ADR-0001 §3 says "the identity in every sink DSN" is `owl_app`; that is
not true of this sink and never was. REL-2 states it rather than inheriting it silently: this CLI runs
as an identity with DDL rights on the ledger schema, and any move to split that (DDL at deploy time,
`owl_app` at sync time) is a separate change with its own reasoning.

**Expected effect.** A `sync` over `N` events goes from `2N+1` processes to one connection and `2N+1`
round trips. That is the largest single reliability improvement in REL-2 and it lands first (§5).

## 5. Migration order and the dependency obligation

### 5.1 Stage 0 — dependency only

`go.mod` currently declares **zero** dependencies and there is no `go.sum`. `jackc/pgx/v5` is the one
authorized exception under hard rule 1, and under the persistence ADR — this one.

Stage 0 adds the dependency and no call sites. Its entire purpose is that the following obligations
are discharged in a PR where nothing else is happening:

- **Record the exact transitive closure.** `pgx/v5` is authorized by name; the modules it pulls in
  transitively are named nowhere in this repository's rules. The PR must paste `go mod graph` output
  for the closure and get it explicitly acknowledged against hard rule 1. This ADR deliberately does
  not guess the list — asserting a dependency set from memory in a document whose whole subject is
  verified citation would be self-defeating.
- **`go mod verify` starts doing something.** `scripts/ci/run-ci.sh:21` runs it on every build and has
  been vacuous with an empty module graph.
- **`govulncheck` and `staticcheck` gain a real surface** (`run-ci.sh:31-32`). Both already run; both
  have had nothing third-party to analyze.

Note that `pgxpool` is `github.com/jackc/pgx/v5/pgxpool`, a package inside the authorized module, not
a separate dependency.

### 5.2 Stages

| Stage | Content | ADR-0001 §10 |
|---|---|---|
| 0 | Dependency only (§5.1). No call sites. | — |
| 1 | `internal/screeningledger` to pgx (§4). Independent. | none apply |
| 2 | `tenantsql` grows the pgx binding (§2). No sink adopts it; covered by unit tests and the §8 pool tests against a real Postgres. | item 1 |
| 3 | The §7 counters, and the negative test for `check_tenant_binding.py`. | items 3, 4 (mechanism) |
| 4 | The four tenant-bound sinks, **together**. Soak. | items 2, 4 (reading) |
| 5 | Remove the psql envelope and the sink `run()` helpers; re-point the three permanent allowlist entries; §11's three closures. | item 5 |

**Why `screeningledger` goes first.** It carries none of §10's verification burden (§4), it is the
largest fork-count reduction, and it exercises the new dependency in production before any
security-control code depends on it. If pgx turns out to have an operational problem in this
environment, discovering it here costs a revert of one CLI rather than a revert of the tenant binding.

**Why the four tenant-bound sinks go together.** D2 changes the `Runner` contract. A half-migrated
state means `tenantsql` maintains both a script runner and a pooled binding simultaneously — the
two-implementations condition ADR-0001 §10 exists to end, reintroduced inside the PR meant to end it.
The four sinks' call sites are seven lines total (§1's table); there is no meaningful risk reduction
in splitting them, and there is a real cost.

**Why stage 3 precedes stage 4.** A cutover assertion built after the cutover measures nothing about
the cutover.

## 6. Rollback

**What a bad pgx binding looks like.** Every failure mode is loud, and the shapes differ enough to be
worth naming:

- `set_config` fails or the tenant is wrong → the transaction aborts, or RLS rejects the write. Both
  surface as errors, not as silent cross-tenant writes. Fail-closed, exactly as ADR-0001 §7 describes.
- `is_local` is wrong, so a binding survives `COMMIT` and leaks to the next borrower → **silent**, and
  the only genuinely dangerous mode. This is what §8.1's `MaxConns=1` test exists to catch, and it is
  why that test is a gate rather than a nice-to-have.
- The pool saturates → the operation budget expires and the sink returns a deadline error.
- A connection is abandoned mid-transaction → `idle_in_transaction_session_timeout` (§3.2) reaps it.

**The lever, per stage.** Stages 0 through 4 are ordinary code reverts. That is a deliberate property
of the ordering: **the psql envelope still exists through stage 4**, so reverting the sink cutover
restores a working write path with no database change and no data migration. Nothing in stages 0–4
alters schema, policy, or data.

**Stage 5 is the point of no easy return**, which is why it is last and why the soak sits before it.
After stage 5 a rollback means reverting the removal PR, not flipping a switch.

**Do not reach for `security_control_suspension`.** That lever (`db/migrations/014_tenant_isolation.sql:601`,
`db/rollback/014_tenant_isolation_down.sql:70`, invariant 5 at `test/sql/security_invariants.sql:122-129`)
suspends `FORCE ROW LEVEL SECURITY` and holds CI red until closed. REL-2 does not touch RLS, and a pgx
regression is not a security-control suspension. Using it here would open a suspension nobody can close
by fixing the actual problem, and would train the next operator to treat the loudest lever in the
repository as a generic rollback. If a REL-2 regression genuinely requires suspending RLS, that is a
separate, deliberate decision with its own record.

## 7. The cutover assertion (D6)

### 7.1 ADR-0001 §7 stage 2's counter does not exist

ADR-0001 §7 describes a shadow stage: "an `openwatchlist_tenant_bound()` assertion records unbound
transactions to a counter relation without rejecting them." §10 item 4 requires that counter to be
"re-armed across the cutover" and to read zero.

**It was never built.** `openwatchlist_tenant_bound` appears nowhere in the tree. Greps across `db/`,
`test/sql/`, `scripts/ci/` and all Go source return nothing for it, for any tenancy-related shadow
mechanism, or for a counter relation. `db/migrations/014_tenant_isolation.sql` creates exactly one
table — `security_control_suspension` (`:601`), the §7 rollback lever, which does exist and is wired
to invariant 5 and to `scripts/ci/provision_test_roles.sh:93`.

There is nothing to re-arm. REL-2 constructs the mechanism, and this section says what it is —
otherwise item 4 is a checklist line dischargeable by inspecting nothing, which is the silent-absence
bug class one level up.

### 7.2 Why the replacement is a Go-side counter, not the SQL one

This **replaces** ADR-0001's design rather than approximating it, and the reason is a change in the
world since §7 was written.

§7 staged its counter **before** `FORCE` landed. In that window an unbound write could still succeed,
so recording it was the only way to learn that a write path had escaped the seam. Post-enforcement
that is no longer true: `FORCE ROW LEVEL SECURITY` rejects an unbound write loudly and immediately. A
SQL-side shadow counter sitting downstream of that rejection would structurally always read zero — not
because the seam is sound, but because the rejection happened first. It would prove nothing about the
pgx migration specifically, while looking exactly like a passing check.

The Go-side counter instead proves that **the seam itself is being used**, which is a hazard RLS
cannot detect on its own.

### 7.3 The mechanism

`tenantsql.DB` carries three counters (§2.3), incremented on the paths shown there:

- `opened` — transactions begun on this handle.
- `bound` — transactions where `set_config` succeeded.
- `unbound[reason]` — transactions opened via `Unbound`, broken down by its closed reason set.

**Soak conditions across the cutover, all three required:**

1. `opened == bound + sum(unbound)`. Any inequality means a transaction was opened and neither bound
   nor declared unbound — a path that escaped both, which is the exact hazard.
2. The `unbound` breakdown matches the classified-global writes and nothing else: `migrate` at
   startup, `class-d-global` from `assistancerag.PersistSnapshot`. A reason appearing that is not in
   the closed set will not compile; a count appearing where none was expected is a finding.
3. **Zero RLS-rejection errors** observed from any pgx sink in the same window. This is the condition
   that proves nothing is silently falling back to an unbound path that RLS is quietly catching
   *instead of* the counter — without it, conditions 1 and 2 could hold while a bypassing path is
   being absorbed by the database.

### 7.4 What this does not prove

Stated explicitly so ADR-0001 §10 item 4 is not read as covering more than it does.

These counters prove every transaction was **wrapped** by `WithTenant`, and condition 3 proves nothing
reached Postgres unbound. They do **not** prove the **correct** tenant was bound for a given request.
RLS verifies that *some* tenant is bound and that rows match it; it cannot know which tenant the
request was entitled to.

That property comes from elsewhere and is unchanged by REL-2: `tenantctx.Resolve` derives the tenant
from verified claims only and refuses the wildcard (`internal/tenantctx/tenantctx.go:35-45`),
`tenantctx.Assert` rejects a body-supplied tenant that disagrees (`:81-90`), and ADR-0003's handler
mapping turns that into a 403 (`internal/alertcaseapi/server.go:125-128`, `:161-164`, `:207-210`,
`:256-259`). REL-2 changes the driver beneath all of it and none of the logic. Recorded here as
unchanged-by-REL-2, not as covered-by-item-4.

## 8. Test strategy

The two process shapes have different load profiles and get separate bars.

### 8.1 Service sinks

All under `-race`, in `internal/integrationtest`, gated the way the existing suite is and therefore
non-skippable in CI, which already provisions a `postgres:17` service and both role DSNs
(`.github/workflows/ci.yml`).

**Pooled tenant-binding leak — the gate.** `TestREL2PooledTenantBindingNoLeak`: construct a
`tenantsql.DB` with **`MaxConns=1`**, so "the same physical connection" is deterministic rather than
probabilistic. Run `WithTenant(A)`, then `WithTenant(B)`, and assert B sees nothing of A's. Then
acquire outside any `WithTenant` and assert `current_setting('openwatchlist.tenant_id', true)` is
empty. This is the test ADR-0001 §8 describes as "the load-bearing test the moment pgx lands", and
§10 item 2 explains why it has to be new.

**Concurrent tenant interleaving.** Two tenants, many goroutines, `MaxConns=2`, writes interleaved
across the pool; assert no row lands under the wrong tenant. This is the `-race` concurrency test the
repository requires for a concurrency change, and the two-tenant test the repository requires for a
tenancy change, in one.

**Connection exhaustion under load.** `MaxConns=2`, 50 concurrent `PersistAlert` calls: assert all
succeed — queued, not rejected — and that `pool.Stat().TotalConns()` never exceeds `MaxConns`. The
`TotalConns` assertion is the one that actually proves pooling is in effect, and unlike a wall-clock
assertion it is not flaky.

**Pool timeout behavior.** Hold every connection in a deliberately blocked transaction, then issue one
more call with a short ctx deadline; assert it returns a deadline error at roughly its deadline rather
than hanging, and that the error is distinguishable from a query failure. This proves acquire is
covered by the operation budget (§3.2), which is the claim that would otherwise be untested.

**The reliability property itself.** Assert zero process spawns across the concurrent-load test. The
cheapest honest form is to run it with a `PATH` containing no `psql` binary: if any fork+exec path
survives, the test fails rather than silently succeeding via a shell-out.

### 8.2 The CLI sink

Different profile: sequential, one long-lived connection, potentially large backlog.

- **Backlog over one connection.** Sync `N` events (`N` large enough to matter, e.g. 500) and assert
  all `N` land, that `store.IsReplicated` agrees for every event, and that exactly **one** connection
  was opened. The last assertion is the one that distinguishes this from the pre-REL-2 behavior.
- **Resumability after a killed connection.** Terminate the backend mid-run (`pg_terminate_backend`),
  assert the run fails loudly rather than silently skipping events, then re-invoke and assert the
  remainder completes and no event is double-written. This exercises the "re-derive from unchanged
  source" property (§3.1) rather than assuming it.
- **`statement_timeout` is in effect**, asserted directly rather than by configuration inspection.
- **No process spawn**, same `PATH` technique as §8.1.

### 8.3 CI-gate work this ADR specifies but does not perform

Per `CLAUDE.md`'s Boundaries, gate changes are their own reviewed PR. This ADR specifies two:

1. A new negative case in `scripts/ci/tests/test_tenant_binding.py`, alongside the existing
   `test_unbound_query_against_listed_relation_is_rejected` (`:41`), whose fixture is a **pgx-shaped**
   call site — `tx.Exec(ctx, "INSERT INTO alert_record(...) VALUES ($1)")` outside `internal/tenantsql`
   — asserting the check still fails. That is §10 item 3's "verified by a negative test rather than by
   inspection", made concrete.
2. Reading the §7 counters in the soak. Whether that is a metrics endpoint or a log line is an
   implementation choice; the three conditions in §7.3 are not.

## 9. Accepted risks and non-goals

**SEC-1c is not designed for here.** Whether `internal/screeningapi` should synchronously write to the
ledger on the request path is undesigned and belongs to SEC-1c's own ADR. REL-2 migrates
`screeningledger`'s **current** write pattern — disk-event-driven CLI sync — exactly as it exists.

Stated as a forward-compatibility constraint rather than a design: if SEC-1c later introduces a
live request-path write to the ledger, that call site will need tenant binding, and nothing in §2's
or §3's design precludes it. `screeningledger` receives a bare `pgx.Conn` **because its relations are
Class C today**, not because ledger writes are structurally exempt; a future tenant-bound ledger writer
would take a `*tenantsql.DB` and route through `WithTenant` like every other tenant-bound sink, and
§2.3's `Unbound` reason set would gain nothing. That is the whole of the forward compatibility this
ADR owes SEC-1c, and building further for a call site that does not exist would be designing against a
decision that has not been made.

**ADR-0001 §4's Class C rationale is now stale, and REL-2 is not the place to fix it.** That section
argues Class C stays deferred because "`internal/screeningapi` has no tenant concept anywhere in the
Go tree to backfill from or write going forward." SEC-1b changed that:
`internal/screeningapi/http.go:91` derives a bound tenant via `tenantctx.FromContext` and rejects the
request when absent (`:93`), and the idempotency store is tenant-scoped
(`internal/screeningapi/idempotency.go:29-34`). ADR-0001 §9's re-entry condition for SEC-1c has
therefore been met. Recorded here because a reader comparing §4's reasoning to today's tree will
notice the divergence; acting on it is SEC-1c's, and neither ADR-0001 nor the issue register is edited
by this document.

**Two binding implementations exist between stages 2 and 5.** Shorter than the interim ADR-0001 D1
accepted, and bounded by §5's ordering, but real.

**`ON CONFLICT DO NOTHING` on the ledger writes survives REL-2** (§4). Named, not fixed.

**The idempotency TOCTOU survives REL-2.** `internal/screeningledger/postgres.go:66` checks for a
conflicting receipt in a statement preceding the insert. pgx does not change that; SEC-5 owns it.

**Nothing here improves matching, scoring, or correctness of results.** REL-2 removes a reliability
and credential-exposure problem. It does not move the platform closer to production capability on the
`DOM-*` axis.

## 10. `REL-2t` closure checklist, item by item

ADR-0001 §10 lists five conditions, in order. Two of them cannot be discharged as literally written,
for reasons that are facts about the tree rather than disagreements with the design. Both corrections
are recorded here; **ADR-0001 is not edited.**

### Item 1 — pgx binding behind the same exported seam

**Executable as written, with one qualification.** §2.3 issues
`SELECT set_config('openwatchlist.tenant_id', $1, true)` as the first statement inside the transaction
opened by `pool.Begin`, before any body statement, in `internal/tenantsql`. The tenant travels as a
bind parameter rather than as statement text, which strengthens ADR-0001 §3's `set_config`-over-`SET
LOCAL` reasoning rather than superseding it.

Qualification (D2): the seam's exported function, its name, and its first three parameters are
unchanged, and the body-construction logic at every sink is unchanged in substance. **One argument per
call site changes** — `p.runBound` becomes `p.db` — and each sink's `runBound` and `run` helpers are
deleted, which item 5 already schedules. "Call sites do not change" is true of the business logic and
not of the last argument; claiming otherwise would be the kind of near-miss this repository's review
culture exists to catch.

### Item 2 — the two-tenant suite re-run against pgx, including the reused-connection case

**Correction: the named test is not a pool test, and re-running it proves nothing about pooling.**

The case is `TestSEC1TwoTenantIsolation/NoLeakAcrossReusedSession`,
`internal/integrationtest/tenant_isolation_test.go:243-271`. Two facts about it:

1. It executes through `exec.Command("psql", ...)` (`:87`), like every other case in the file, and it
   is covered by a **permanent** allowlist entry (`db/tenant_binding_allowlist.txt:20`) precisely
   because the property under test is the database's own enforcement, which must not route through the
   seam. Re-running it "against pgx" is not meaningful: it does not use the sinks.
2. What it actually asserts is two sequential transactions **in one psql session** — that
   `is_local=true` resets at `COMMIT`. The file header says so directly (`:12-27`): the pooled-borrow
   claim "stays a documented no-op until REL-2t re-arms it", and "a green result here before REL-2
   must not be read as coverage."

**Resolution (D5), both parts required:**

- **(a)** Re-run the existing suite unmodified and green. It tests Postgres' own RLS enforcement,
  which is invariant across drivers, and it must not regress. It stays psql-based and stays a
  permanent allowlist entry. **This alone does not discharge item 2.**
- **(b)** Add `TestREL2PooledTenantBindingNoLeak` (§8.1), which pins `MaxConns=1` so the pooled-borrow
  case is deterministic rather than probabilistic. This is the test item 2 was reserving a slot for.

### Item 3 — `check_tenant_binding.py` retargeted, verified by a negative test

**Executable, and smaller than it looks — because of D1.** The check's detection is a lexical scan of
Go string literals for a SQL verb followed by a listed relation (`scripts/ci/check_tenant_binding.py:126-151`).
It is runner-agnostic: it never referenced psql, and the `Runner.Run(` grep ADR-0001 §3 point 3
described was never implemented. Because D1 keeps SQL-text authorship inside `tenantsql`, the check's
invariant survives the driver change **verbatim** and needs no retargeting of its detection.

What item 3 still requires is proof, not inspection: the new negative case in §8.3, whose fixture is a
pgx-shaped call site rather than a psql-shaped one. If that case passes — i.e. the check fails the
build — the control demonstrably still covers the new call shape.

### Item 4 — the §7 stage-2 shadow counter re-armed and reading zero

**Correction: the mechanism was never built.** `openwatchlist_tenant_bound()` and its counter relation
do not exist anywhere in the tree (§7.1). "Re-armed" has no referent.

**Resolution (D6):** REL-2 constructs the assertion, in Go rather than SQL, and §7.2 states why that
replaces rather than approximates the original — post-`FORCE`, a SQL-side counter downstream of an RLS
rejection would structurally always read zero and prove nothing about this migration. The three soak
conditions are §7.3; the boundary of what they prove is §7.4, and item 4 must be read as covering that
boundary and no more.

### Item 5 — remove the psql envelope, in a PR citing REL-2 and SEC-1

**Executable as written.** Stage 5 (§5.2) removes `tenantsql`'s psql script envelope, each sink's
`run()` and `runBound()` helpers, the `CommandRunner`/`ExecRunner` interfaces, and the six hex-encoding
and quoting helpers.

Per item 5's own text, **no allowlist entry is deleted**. The transitional list is already empty
(`db/tenant_binding_allowlist.txt:21-25`). The three permanent entries are **re-pointed**, not removed:
`Migrate` and `Ping` to their pgx equivalents, `db/migrations/` unchanged — it never went through a Go
seam at all. The fourth permanent entry, the two-tenant suite (`:20`), is unchanged and stays
psql-based by design (item 2(a)).

## 11. SEC-3, `/readyz`, and the dormant `database/sql` shims

### 11.1 SEC-3 closes in full — both halves (D11)

SEC-3 is the DSN passed as `argv[1]` to psql. ADR-0001 §3 cites two sites and §9 records that D1
prolonged the exposure. There are two distinct halves, and only one of them closes by itself.

**The psql-child half closes automatically and completely.** All six sites in §Context disappear with
the psql invocation. The three API services never put a DSN on their own argv — they read
`postgres_dsn` from a JSON config file (`internal/alertcaseapi/config.go:21`,
`internal/assistanceapi/config.go:29`, `internal/vendoradapterapi/config.go:16`) — so for them the
exposure ends entirely.

**The CLI-`argv` half does not close by itself, and REL-2's own diff deletes its last visible
marker.** Three CLIs put the DSN on their own command line, where `ps` can read it, independent of
psql:

| Call site | Current |
|---|---|
| `cmd/alert-case/main.go:113` | `fs.String("postgres-dsn", …)` |
| `cmd/platform-ops/main.go:216` | `fs.String("dsn", …)` — `sync-vendor-adapter` |
| `cmd/platform-ops/main.go:227` | `fs.String("dsn", …)` — `sync-outbox` |
| `cmd/screening-ledger/main.go:124` | `opts["--postgres-dsn"]` — survives *alongside* the env form at `:125-127` |

**Decision:** REL-2 closes both, in stage 5. `cmd/screening-ledger` already carries the pattern —
`--postgres-dsn-env` reads the DSN from a named environment variable (`main.go:125-127`) — and it is
applied to the other three declarations, with the plain flag removed in all four. That fourth row
matters: leaving `--postgres-dsn` accepted next to `--postgres-dsn-env` means SEC-3 does not close in
full, only becomes avoidable.

The reason for doing this inside REL-2 rather than deferring it is not convenience. Once no psql call
site remains, nothing in the tree points at the surviving exposure, and the change that removed the
signpost would be the change that left the exposure open — structurally the same hazard ADR-0001 §10
names for a pgx port that deletes both the binding and the check that guards it.

**SEC-3 therefore closes as a consequence of REL-2, both halves, not just the psql-removal half.**
The advisory and the issue register are not edited by this ADR; the closure claim is recorded here and
the stage-5 PR cites it.

### 11.2 The `/readyz` psql fork (D12)

`internal/productionops/runtime.go:73-87` reads the DSN from an environment variable and forks
`psql -c "SELECT 1"` (`:81`) on every readiness probe, via `internal/platformapi/server.go:155` and
`/readyz` at `:178-179`. It is the one psql site neither migration track in this ADR would pick up by
default: it lives in `internal/productionops`, a named sink package, but it is not a sink write and is
not tenant-bound.

**It is not fixed by reusing a service sink's pool.** `platformapi.Server`
(`internal/platformapi/server.go:20-34`) holds no Postgres sink, and `cmd/platform-api` is a separate
process from the three sink-holding services. There is no pool to reach. The actual shape:

- `productionops.CheckRuntime` (`runtime.go:27`) takes a pinger parameter instead of reading
  `os.Getenv(c.Readiness.PostgreSQLDSNEnv)` and forking (`:74-85`).
- Its two callers have different process shapes and each supplies its own:
  `internal/platformapi/server.go:155` (service, per probe) passes a small pool — `MaxConns` 2 —
  constructed once at startup, conditional on `c.Readiness.PostgreSQLRequired`;
  `cmd/platform-ops/main.go:114` (CLI, one-shot) passes a single connection, or nil when PostgreSQL is
  not required.
- **No behavior is lost** by moving the DSN read from check time to startup: process environment is
  fixed at `exec`, so `os.Getenv` at `:74` could never have observed a rotation. Stated so this does
  not read as an unnoticed regression.

**The closure claim, with its carve-out.** This removes the last `fork`+`exec psql` call site in
**non-test** code. `internal/integrationtest/tenant_isolation_test.go:87` continues to shell out to
psql deliberately and permanently (item 2(a), `db/tenant_binding_allowlist.txt:20`). Claiming "the last
psql call site in the tree" without that carve-out would be false.

### 11.3 Three dormant `database/sql` shims (D10)

Three packages hold a `*sql.DB` and issue parameterized writes against twelve relations:
`internal/catalogregistry/postgres.go` (`PostgresStore`, `:19-21`),
`internal/alertlistmapping/postgres.go` (`PostgresStore`, `:18-21`),
`internal/providerrefresh/postgres.go` (`PostgresRepository`, `:16`). Their schemas live in embedded
migrations under `internal/*/migrations/` — **outside `db/migrations/`** — so those twelve relations
fall outside ADR-0001 §4's classification (whose governing rule is that every relation created under
`db/migrations/` appears exactly once), outside `db/tenant_scoped_tables.txt`, and outside both
`check_tenant_binding.py` and the SQL invariants. None of the three carries a tenant column.

They are unreachable today, and the evidence is specific rather than an absence of grep hits: there is
no `sql.Open` anywhere in the tree, `go.mod` declares no driver so none could be registered, and the
only callers of these packages' exported Postgres surface are three CLIs that print the schema string —
`cmd/catalog-registry/main.go:35`, `cmd/alert-list-mapping/main.go:34`,
`cmd/provider-refresh/main.go:37`. No constructor supplies a non-nil `DB`.

**REL-2's own dependency addition is what makes this relevant.** `pgx/v5` ships `pgx/v5/stdlib`, a
`database/sql` driver. After stage 0, these three shims become constructible in one import line, and
anything wired through them would bypass `tenantsql` entirely against relations no gate covers and no
ADR classifies. This is a **consequence of this PR**, not an unrelated finding REL-2 happens to be
well positioned to fix — and that distinction is why it is in scope rather than filed away.

**Decision, in this order:**

1. **Verify by deletion**, using ADR-0002 §3.1's method rather than reading: remove `PostgresStore` and
   `PostgresRepository`, and confirm the build and the full test suite stand. `PostgresMigration()` is
   an independent string function and survives, so the three live CLI callers are unaffected.
2. **If a live caller turns up**, classify all twelve relations against ADR-0001 §4's Class A/B/C/D
   scheme instead, so the surface is visible to a reader and a gate.

Do **not** leave them dormant-but-newly-constructible with no gate and no classification. That is the
same shape as INFRA-4 — the finding that CI's bootstrap superuser bypasses row security regardless of
`FORCE` (`.github/workflows/ci.yml:39`): a control absent rather than defeated, invisible until
something makes it reachable.

## Consequences

**Positive.** One process per write becomes one pooled connection per service, and `2N+1` processes per
ledger sync become one connection. The DSN leaves every `argv` in the system (§11.1). The
hex-encoding-into-SQL-text idiom — six copies of it — is replaced by real parameter binding, removing
an injection surface class rather than continuing to avoid it by discipline. `set_config` finally takes
the tenant as a parameter instead of as encoded text. Two gaps in ADR-0001's handover that would
otherwise have been discharged by inspection are named and given executable substitutes (§10 items 2
and 4). And `go mod verify`, `govulncheck` and `staticcheck` start doing work they have been doing
vacuously.

**Negative.** A new dependency, with a transitive closure that is not enumerated by hard rule 1 and
must be acknowledged explicitly (§5.1). Two binding implementations between stages 2 and 5. A
connection budget that now has to be reasoned about at deploy time (§3.2) where forked processes made
it self-limiting and self-cleaning. Six PRs for what is, from outside, "use a connection pool."

**Neutral but worth stating.** REL-2 changes no policy, no schema, and no evidence semantics. The
Class C deferral, the ledger's swallowed conflicts, and the idempotency TOCTOU all survive it exactly
as they are. Closing REL-2 removes a reliability problem and a credential exposure; it does not make
the matching or persistence layers production-capable, and the two remaining defects in §9 are
unchanged in both severity and ownership.
