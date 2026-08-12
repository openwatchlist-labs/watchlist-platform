# ADR-0006: Vendor adapter tenant provenance

- **Status:** Proposed
- **Date:** 2026-08-12
- **Issue:** SEC-1e (P0)
- **Related:** SEC-1 (ADR-0001, accepted), SEC-1b (ADR-0003), REL-10 (ADR-0002), REL-2 (ADR-0005),
  SEC-1c, SEC-1d, SEC-3, SEC-6, GHSA-vhj8-986g-vjf4, GHSA-wv2h-hrq2-932p, PR #92 (merged hotfix)
- **Supersedes:** nothing. Closes the one scope ADR-0003 §10 deferred and the one call site ADR-0003
  §6's fallback removal reached outside its own two surfaces. Neither ADR-0001 nor ADR-0003 is
  modified by this document.

## Context

`internal/vendoradapterapi` is the last write surface in the platform whose tenant boundary rests on
a value no verified identity stands behind. ADR-0003 §10 deferred it to SEC-1e on a stated premise:

> `internal/vendoradapterapi` is untouched (SEC-1e). Its tenant arrives from a config-loaded adapter
> profile rather than a request body, so the shape of the fix differs — there is no bearer token on
> the path that matters.

**That premise does not describe the current tree, and this ADR exists because of the difference.**
The tenant does not arrive from a config-loaded profile. It arrives from the vendor's own JSON
payload, by a path the profile names. The gap is not a data-integrity question about which static
value to bind; it is the same caller-asserted-identity problem SEC-1b fixed for `alertcaseapi` and
`screeningapi`, displaced one hop outward — the "caller" is whatever system posts to
`/v1/vendor-alerts/{adapter}`, and the "assertion" is a field inside the document it sends.

Every fact below was verified against the working tree at `f845721` (the merge of PR #92), not
carried over from ADR-0001 or ADR-0003.

### 1. The tenant is vendor-asserted

`Profile` supports two sources for a canonical field: `Mappings map[string]string`, a JSON path into
the vendor payload (`internal/vendoradapter/types.go:34`), and `Constants map[string]any`, a fixed
operator-declared value (`:36`). `Convert` resolves the mapping first
(`internal/vendoradapter/convert.go:54-62`) and then lets a constant overwrite it unconditionally
(`:63-66`), so a profile declaring both silently discards the payload value. `ValidateProfile`
accepts either as satisfying the required-field rule (`internal/vendoradapter/profile.go:87-93`).

All three shipped profiles use `Mappings` for `tenant_id`, and none uses `Constants`:

| Profile | `mappings.tenant_id` | `constants` |
|---|---|---|
| `configs/vendor-adapters/generic-json-v1.json` | `tenant_id` (`:19`) | `{}` (`:39`) |
| `configs/vendor-adapters/fircosoft-reference-json-v1.json` | `message.customer` (`:19`) | `{}` (`:39`) |
| `configs/vendor-adapters/actimize-reference-json-v1.json` | `caseAlert.tenant` (`:19`) | `{}` (`:39`) |

The resolved value becomes `CreateAlertRequest.TenantID` (`convert.go:68`, `:135`) and is written
to `vendor_adapter_record.tenant_id` (`internal/vendoradapter/postgres.go:92`). Nothing cross-checks
it against anything.

Two of the three paths are worth reading closely, because they are not tenant identifiers that
happen to live in a payload — they are vendor business fields pressed into service as tenancy.
`message.customer` is a customer on a Fircosoft message; `caseAlert.tenant` is an Actimize case
field. The platform's tenant namespace and the vendor's are different namespaces that these
profiles assert are the same one.

### 2. Nothing authenticates the caller

`Handler()` registers four routes on a bare `http.ServeMux` and returns it unwrapped
(`internal/vendoradapterapi/server.go:52-58`); `cmd/vendor-adapter-api/main.go:38` serves it
directly. There is no bearer token, no `internal/httpauth`, no credential check of any kind, and
`Config` (`internal/vendoradapterapi/config.go:11-21`) carries no signing-key or registry path to
build one from.

ADR-0001 D3 states the consequence in its own words: "Binding a GUC to a caller-asserted tenant is
theatre." §2 of this document argues that the same judgment applies here, and what follows from it.

### 3. PR #92's interim is in the tree, and named this ADR as its removal condition

SEC-1b deleted `tenantctx.Assert`'s body fallback (`internal/tenantctx/tenantctx.go:81-85`), which
is correct for the two surfaces that gained authentication and wrong for this one, which did not.
Every write through this sink began failing closed with `ErrNoBoundTenant`, and because `ingest`
inspected the error only when `Config.PostgresRequired` was true — `false` in the shipped example
config — the failure was swallowed and the handler still returned `201`.

PR #92 restored writes with `assertTenant` (`internal/vendoradapter/postgres.go:54-76`), which
defers to `tenantctx.Assert` when ctx carries a bound tenant (`:72-74`) and otherwise resolves the
body-supplied value directly (`:75`). Its doc comment names the exact condition for its own
deletion:

> Delete this function and call `tenantctx.Assert` directly once SEC-1e gives vendoradapterapi a
> bound tenant of its own.

That is this ADR's job, and §6 executes it as a checklist item rather than leaving it to be
inferred. PR #92 also made `ingest` surface `ErrTenantMismatch` as 403 and `ErrNoBoundTenant` as
500 regardless of `PostgresRequired` (`internal/vendoradapterapi/server.go:100-113`); that part is
kept.

## Decision

Authenticate the surface with the existing `internal/httpauth` guard, make `tenant_id` an
operator-declared profile constant that the payload cannot supply, assert that constant against the
authenticated tenant *before* anything is written, and delete the PR #92 interim.

| # | Decision | Consequence |
|---|---|---|
| **D1** | **Authentication is in scope for this ADR**, reusing `internal/httpauth` unchanged. | Argued in §2 on mechanism, not preference: the hotfix's removal condition is unreachable without it. No new auth system, no new dependency. |
| **D2** | `tenant_id` becomes **Constants-only**. `ValidateProfile` rejects a profile declaring `mappings.tenant_id`. | The vendor payload loses the ability to name a tenant. Migrates three profiles and changes three content-addressed `ProfileSHA256` values (§4). |
| **D3** | The tenant assertion moves **ahead of `Store.Process`**. | Today's 403 fires after the filesystem write it is supposed to prevent (§5). Constants-only is what makes the check orderable at all. |
| **D4** | Mismatch between the profile-declared tenant and the bound tenant is **403**, per ADR-0001 §2. | The profile constant plays the role the request body plays elsewhere: an assertion checked against the bound tenant, never silently overwritten, never silently accepted. |
| **D5** | **Hard cutover**, no `auth_required` flag, conditional on the same operator confirmation ADR-0002 D3 and ADR-0003 §8 required. | §7 states the zero-traffic evidence for *this* surface, verified rather than inherited. |
| **D6** | `assertTenant` and its body-trust fallback are **deleted**; `Persist` calls `tenantctx.Assert` directly like every other sink. | §6. The condition PR #92 wrote for itself, executed. |

D1 and D2 are the two judgment calls this ADR exists to make. §2 and §4 argue them.

## 1. Scope

In scope: why a configuration-only fix cannot close this gap (§2), authentication and the route
policy table (§3), the Constants-only rule and the profile migration with its checksum consequences
(§4), assertion ordering relative to the filesystem write (§5), deletion of the PR #92 interim (§6),
rollout (§7), the test bar for calling SEC-1e closed (§8), accepted risks (§9), follow-ups (§10).

Out of scope, each with a pointer: route-level authorization and the permission vocabulary
(§3, §9 — the same follow-up ADR-0003 §11 opened); tenant filtering on the adapter-listing route
(§9); the filesystem store's tenant-blind receipt scope (§9); `screening_idempotency_receipt`
(SEC-1c); `internal/rag`'s CLI callers (SEC-1d); the `fork`+`exec` call shape and DSN-in-`argv`
(SEC-3, ADR-0005).

This ADR documents a decision. The implementation is a separate PR, per `CLAUDE.md` hard rule 7.
§6 and §8 enumerate that PR's scope so nothing in it is discovered rather than designed.

## 2. Why a configuration-only fix is insufficient (D1)

The question this ADR was asked to settle is whether SEC-1e can be closed by configuration alone —
migrating the three profiles to `Constants` — with authentication left to a later issue. The
tempting answer is yes: a constant is operator-declared, so the vendor stops choosing the tenant,
and ADR-0001 §2's closure condition ("SEC-1 is not closed while any writer can name its own tenant")
appears satisfied.

**It is not sufficient, and the decisive argument is mechanical rather than a matter of security
appetite.**

### The hotfix removal condition cannot be met by configuration

`tenantctx` is the single authority for constructing a bound tenant — its package doc says so
directly (`internal/tenantctx/tenantctx.go:1-7`, "No other package may construct a Tenant"), and
ADR-0001 §2 made that structural rather than advisory. There are exactly two constructors:
`Resolve`, which takes a `reviewauth.Claims` (`:35-45`), and `Assert`, which requires a tenant
already bound on ctx and returns `ErrNoBoundTenant` otherwise (`:81-85`).

So "give `vendoradapterapi` a bound tenant of its own" has exactly two possible implementations:

1. Authenticate, and bind from verified claims — what `internal/httpauth` does.
2. Fabricate a `reviewauth.Claims{TenantID: <profile constant>}` and hand it to `Resolve`.

Option 2 is not a hypothetical; it is character-for-character what `assertTenant` already does today
(`internal/vendoradapter/postgres.go:75`). A configuration-only fix would change *where the string
comes from* — profile instead of payload — while leaving the same unverified-claims construction in
place. `assertTenant` would survive under a new name, and PR #92's removal condition would be
unmet. The comment would still be true.

That settles D1 without needing to argue about how much residual risk is tolerable: **this ADR is
required to delete the interim, and only a verified caller produces a bound tenant that lets it be
deleted.**

### What each half would provide on its own, stated honestly

Because ADR-0003 §10's under-scoping of exactly this gap came from an unexamined "the shape of the
fix differs," the two halves are separated here rather than merged into a single claim.

**Constants-only, without authentication, would provide:** the tenant written to
`vendor_adapter_record.tenant_id` is an operator declaration carried in a checksummed profile, not a
value the sender chose. Provenance of the *label* becomes real and auditable. An attacker reaching
the endpoint could no longer write under an arbitrary tenant string of their choosing.

**It would not provide:** any control over who writes. An unauthenticated attacker who can reach
the endpoint could still inject forged alerts into any tenant that has a profile, simply by posting
to that adapter — the tenant is fixed per adapter, and the adapter is chosen by URL path. The
resulting rows would be indistinguishable from genuine ingestion, and they would carry a tenant
label with better provenance than before, which arguably makes the forgery more credible rather than
less. The GUC bound underneath would still be bound on the authority of nothing.

**Authentication, without Constants-only, would provide:** the security property in full. A payload
value disagreeing with the bound tenant is rejected by `tenantctx.Assert` (`:86-88`), so the vendor
axis is closed by the same demotion-to-assertion ADR-0001 §2 specifies for request bodies.

**It would not provide** a workable system, for the reason in §4: two of the three profiles map
`tenant_id` to a vendor business field, so legitimate traffic would 403 on a value the vendor has no
reason to keep equal to a platform tenant id. Nor would it allow the check to run before the write
(§5). Authentication alone is sound and unusable; Constants-only alone is usable and unsound. This
ADR takes both.

## 3. Authentication (D1)

### Mechanism

`internal/httpauth`, unchanged, exactly as ADR-0003 §2 and §3 specify it. This surface needs nothing
that package does not already have, and the fit is closer than for either SEC-1b surface:

- `httpauth.MuxMatcher` (`internal/httpauth/httpauth.go:210`) builds a `Matcher` from an
  `*http.ServeMux` by reusing the mux's own pattern match, and `Handler()`
  (`internal/vendoradapterapi/server.go:52-58`) is already an `http.ServeMux` — no route-table
  migration, no second routing implementation.
- `httpauth.New` (`:72`) fails at construction when a registered route has no policy entry (`:88-90`),
  which is ADR-0003 §4's structural guarantee against a route shipping with an undecided policy.
- `Guard.Wrap` (`:101`) authenticates via `reviewauth.TokenService.Parse` and binds the resolved
  tenant onto the request context before the handler runs (`:117-130`).

The adoption pattern is `internal/alertcaseapi/auth.go` transposed: `Routes` (`:18`), `RoutePolicy`
(`:35`), `AuthenticatedHandler` (`:51`) and `LoadTokenService` (`:65`), with `Config` gaining
`auth_registry_path`, `signing_key_path` and `max_token_ttl_minutes`
(`internal/alertcaseapi/config.go:31-33`, resolved at `:57-58`), and the `serve` branch wiring the
authenticated handler (`cmd/alert-case-api/main.go:33-37`).

Because that template is merged, tested code, "there is no bearer token on the path that matters"
(ADR-0003 §10) is no longer an argument about mechanism cost. There is a bearer token on the path;
it simply has not been put there.

### Route policy table

State **(A)** is inherited from ADR-0003 D3 and not re-decided here: until the route-level
authorization follow-up lands, any validly authenticated, tenant-bound request is permitted. The
table is filled in so that is a decision on the record rather than a default.

| Route | Method | Policy |
|---|---|---|
| `/healthz` (`internal/vendoradapterapi/server.go:54`) | GET | `Public` |
| `/readyz` (`:55`) | GET | `Public` |
| `/v1/vendor-adapters` (`:56`) | GET | `AuthenticatedTenant` |
| `/v1/vendor-alerts/{adapter}` (`:57`) | POST | `AuthenticatedTenant` |

Health and readiness stay unauthenticated, matching ADR-0003 §2 and
`internal/reviewconsoleapi/server.go:113-116`. Neither reads tenant-scoped data: `ready`
(`:60-66`) reports store status and profile count.

`/v1/vendor-adapters` is authenticated but **not** tenant-filtered: `list` (`:67-69`) returns
`ProfileSummary` for every loaded profile — `adapter_id`, `version`, `vendor`, `profile_sha256`
(`internal/vendoradapter/profile.go:135-147`). Under D2 the profile set becomes a per-tenant
partition, so this discloses the existence and checksum of other tenants' adapters to any
authenticated caller. This is the same shape ADR-0003 §10 records for `alertcaseapi`'s unfiltered
read routes, it is a real residual, and §9 carries it rather than letting "tenant is bound" imply
"reads are filtered."

The wildcard refusal applies here as everywhere: `tenantctx.Resolve` rejects `'*'`
(`internal/tenantctx/tenantctx.go:40-41`), so a `platform-admin` token bound to `'*'` in
`configs/review-console/identity-registry-r1.json` is rejected on this surface. §8 gives it a named
test, for the reason ADR-0003 §9 case 4 gives: correct, and surprising enough that its absence would
read as a bug.

## 4. Constants-only `tenant_id` (D2)

**Decision: a profile may declare `tenant_id` only in `constants`. `ValidateProfile` rejects a
profile declaring `mappings.tenant_id`, so a non-conforming profile fails to load and the server
fails to construct.**

Three reasons, in the order of how much they decide.

**1. Under authentication, a mapped value can only be redundant or wrong.** `tenantctx.Assert`
compares the asserted value to the bound tenant and rejects disagreement
(`internal/tenantctx/tenantctx.go:86-88`). A mapped `tenant_id` that equals the bound tenant adds
nothing the token did not already carry; one that differs is a 403. There is no third case in which
the vendor's value contributes correct information. Keeping the pathway keeps a way to fail and no
way to succeed differently.

**2. The mapped values are not tenant identifiers.** `message.customer` and `caseAlert.tenant`
(§1) are vendor business fields. Requiring them to equal a platform tenant id makes legitimate
Fircosoft and Actimize traffic 403 on the contents of a field the vendor maintains for its own
purposes — and, read the other way, hands the vendor a denial-of-service lever over ingestion by
editing that field.

**3. Constants-only is what makes §5's ordering fix possible.** A constant is readable from the
profile before the payload is parsed (`p.Constants["tenant_id"]`). A mapping is only resolvable
after `Convert`, which runs inside `Store.Process`, which writes. This is not a stylistic
preference: it is the difference between a check that can precede every write and one that
structurally cannot.

### The mixed state is eliminated, not resolved

ADR-0001 §2's precedent governs disagreement between a supplied value and a bound value: 403, never
silently overwritten, never silently accepted. This ADR follows it for the axis that survives — the
profile constant versus the authenticated tenant (D4, §5).

For the axis the task of this ADR was to decide — a payload-mapped `tenant_id` disagreeing with a
`Constants`-declared one in a mixed or transitional profile — the answer is that **the state is
unreachable by construction**. `ValidateProfile` rejects the combination, so `LoadProfile` fails,
`LoadProfiles` fails, `New` fails (`internal/vendoradapterapi/server.go:22-25`), and
`cmd/vendor-adapter-api/main.go:25-28` exits non-zero. There is no request-time behavior to specify
because no such profile can be serving.

This is deliberate, and it is the strongest available answer rather than an evasion. Were the
combination permitted, `convert.go:63-66` would resolve it by letting the constant silently
overwrite the mapped value — precisely the "silently overwritten" outcome ADR-0001 §2 forbids, in
the one place in this package where it is already implemented. Refusing the profile at load is what
keeps that code path from ever governing a tenant. It also matches the failure mode `httpauth`
already uses for an undeclared route (§3): a startup error, not a runtime surprise.

### Deviation from ADR-0001 §2, and why

After migration, a vendor payload that still contains its old `tenant_id` field has that field
**not read at all**, rather than read and checked as an assertion. This deviates from ADR-0001 §2's
treatment of body-supplied `tenant_id`, and the reason is specific to this surface's shape:

`alertcaseapi`'s caller and the authenticated principal are the same party, so a disagreement is
that party contradicting itself and 403 is the honest resolution. Here they are different parties:
the authenticated principal is the integration, and the payload author is the vendor. Granting the
vendor document standing to disagree with an operator declaration means the only sound resolution
of a disagreement is rejecting an otherwise valid alert — which makes a missed sanctions match
reachable by a vendor-side field edit. In a screening platform that trade is the wrong way round.

The vendor's value is not discarded as evidence, however. The migration moves each profile's old
`tenant_id` source path into `additional_evidence`, so `message.customer` and `caseAlert.tenant` are
still captured on the record (`convert.go:109-125`) — retained as what they are, vendor fields,
without governing tenancy.

### Profile migration and the checksum consequences

`profileHash` hashes the whole `Profile` struct with `ProfileSHA256` zeroed
(`internal/vendoradapter/canonical.go:14-21`), so moving `tenant_id` from `mappings` to `constants`
changes all three declared checksums. That value is not decorative, and every place it reaches was
checked:

| Consumer | Effect of the change |
|---|---|
| `ValidateProfile` (`profile.go:122-130`) | Recomputes and errors on a declared/computed mismatch. Each JSON's `profile_sha256` must be updated in the same commit. |
| `RecordID` (`convert.go:143-144`) | `ProfileSHA256` is an input to `recordBase`, so every record id for the same source alert changes. |
| `EnvelopeSHA256` (`convert.go:145-149`) | Covers `ProfileSHA256`; changes accordingly. |
| Alert evidence (`convert.go:107`) | `alert_list_resolution.adapter_profile_sha256` is embedded in the alert, so the alert's `RecordSHA256` changes (`internal/alertcase/policy.go:230-233`). The `AlertID` does not: its identity hash is tenant, source type, source identity and decision id (`:223-229`). |
| `vendor_adapter_record.profile_sha256` (`postgres.go:89`) | New rows carry the new value. Correct by construction — the column records which profile produced the record. |
| `test/golden/vendor-adapters/generic-envelope.json` | Pins `profile_sha256`, `record_id` and `envelope_sha256`. **No test reads this file**; its only references in the tree are the `.clean-restart/` import manifests. Regenerate it so it does not become misleading. |

**There is no rekey or dual-read cost**, for the same reason ADR-0003 §7 gives for the screening
idempotency store: no records exist to migrate. The only config for this surface
(`configs/vendor-adapters/phase9e-api-example.json`) names a `state_directory` of
`test/fixtures/vendor-adapters/runtime-state`, which is not in the tree, and `postgres_dsn: ""`.

**Editing the profiles and the golden file is permitted by the clean-restart gates**, checked rather
than assumed: `legacy_exclusion_gate.py` byte-compares working-tree files against import hashes only
under `--verify-bootstrap-bytes` (`:165-188`), its own comment states that post-bootstrap CI must not
compare current files to initial hashes "or future development would be impossible" (`:154-157`), and
`CLEAN_RESTART_BOOTSTRAP_VERIFY` (`scripts/ci/run-ci.sh:6`) is set nowhere in the repository. No
control file is edited by any part of this work, per `CLAUDE.md` rule 2.

## 5. Assertion ordering (D3)

**The tenant check must run before `Store.Process`, not after it.**

Today it runs after. `ingest` calls `s.Store.Process` (`internal/vendoradapterapi/server.go:86`),
which writes the record (`internal/vendoradapter/store.go:66`), the idempotency receipt (`:70`) and
an audit-chain entry (`:74`, appended and hash-linked at `:111-134`) to the filesystem. Only then
does `ingest` reach `s.Postgres.Persist` (`server.go:98`), which is where the assertion lives
(`internal/vendoradapter/postgres.go:79`). A 403 from PR #92's mismatch branch (`server.go:106-109`)
therefore leaves a durable, audit-chained record on disk, written under a tenant the request was not
entitled to.

Two things make this more than an aesthetic ordering point:

- ADR-0001 §8's provenance obligation is "rejected with `403`, and no row is written by any sink."
  One sink currently writes.
- The filesystem is not a cache. ADR-0001's Context establishes it as the authoritative read source
  — "the review console reads from the filesystem state directory... the Postgres sinks are
  write-only mirrors." The check as it stands guards the mirror and not the original. And when
  `s.Postgres` is nil — the shipped example config, with `postgres_dsn: ""` — the branch containing
  the only tenant check in the request path does not execute at all (`server.go:96`).

**Resolution.** `ingest` resolves the profile's declared tenant from `p.Constants["tenant_id"]` and
asserts it against the ctx-bound tenant immediately after profile lookup (`server.go:71-75`) and
before `Store.Process`. `tenantctx.Assert` is the same call the sink makes; on mismatch the handler
returns 403 having written nothing. The sink's own `Assert` call stays as the fail-closed backstop
underneath — ADR-0003 §3's point that a structural guarantee at the edge does not remove the need
for the sink to refuse an unbound write.

PR #92's error mapping in `ingest` (`server.go:100-113`) is retained: `ErrTenantMismatch` to 403 and
`ErrNoBoundTenant` to 500 regardless of `PostgresRequired`, since both are integrity failures rather
than the Postgres-unreachable case that flag exists to degrade through, and the degradation path for
generic infrastructure errors (`:114-117`) is unchanged.

## 6. Deleting the PR #92 interim (D6)

Implementation-PR scope, stated here so it is designed rather than discovered, and enumerated as an
obligation rather than assumed to follow from D1.

**Delete `assertTenant` in full** — the function and its doc comment,
`internal/vendoradapter/postgres.go:54-76` — together with the `internal/reviewauth` import it
alone requires (`:12`). **`Persist` calls `tenantctx.Assert` directly** (`:79`), the same as
`internal/alertcase/postgres.go`, `internal/assistancerag/postgres.go` and every other sink. After
this, no package outside `internal/httpauth` constructs a bound tenant from claims it invented,
which is the property ADR-0001 §2 asked for and SEC-1b delivered everywhere except here.

**The two tests PR #92 added must be revisited, not left to pass:**

- `TestPersistWithoutBoundTenantIsNotUnconditionallyRejected`
  (`internal/vendoradapter/postgres_test.go:64`) asserts that an unbound `Persist` does **not**
  return `ErrNoBoundTenant`. It encodes the interim and must invert: after this ADR, an unbound
  `Persist` must return `ErrNoBoundTenant`. Leaving it passing would mean the fallback was not
  actually removed.
- `TestPersistWithBoundTenantStillEnforcesMismatch` (`:81`) survives unchanged and should be kept —
  it is the same obligation D4 restates, and it already exercises `tenantctx.Assert`'s real path.

`internal/vendoradapterapi/persist_error_test.go:54` binds a tenant on the request context directly
to work around the absence of middleware; once middleware exists it should mint a real token
instead, for the reason ADR-0003 §6 gives against stubbing the verification path out of the tests
that exist to protect it.

**Interaction with ADR-0005 (REL-2).** ADR-0005's sink inventory cites this file at `postgres.go:47`
(`runBound`) and `:79` (`WithTenant`), which are its pre-hotfix positions; the current positions are
`:48` and `:105`, and deleting `assertTenant` moves them again. Nothing in ADR-0005's design depends
on the line numbers, and ADR-0005 is not edited by this document — noted so that whoever executes
REL-2t is not surprised to find the citations off by the size of a function this ADR removes.

## 7. Rollout: hard cutover (D5)

Same decision and same reasoning as ADR-0003 D4, with the evidence re-verified for this surface
rather than inherited, because ADR-0002's and ADR-0003's traffic findings were about other binaries.

- No reference to `vendor-adapter-api` or `vendoradapterapi` exists anywhere in the tree outside
  `cmd/vendor-adapter-api/` and `internal/vendoradapterapi/` themselves — nothing in `scripts/`,
  `.github/`, `deploy/`, `runtime/` or any config.
- **Positive evidence, not just absence:** the only deployment harness in the repository declares
  `runtime_executables` of `platform-api`, `platform-ops`, `container-healthcheck` and `catalog-mmap`
  (`scripts/deployment/r2-4/harness/config/policy.json:150-155`). This binary is not among them, and
  `platformapi` imports only `productionops` and `reviewconsoleapi`
  (`internal/platformapi/server.go:19-20`), so it is not reachable from the deployed entrypoint
  either. (ADR-0003 §8 cites `scripts/deployment/r2-4/remote_runtime_control.py` for the launch
  path; the file is at `scripts/deployment/r2-4/harness/scripts/remote_runtime_control.py:198`.)
- The only config for the surface is a fixture config: `postgres_dsn: ""` and a `state_directory`
  that does not exist in the tree (`configs/vendor-adapters/phase9e-api-example.json`).

With no client to keep working, a staged rollout buys nothing, and a config-gated `auth_required`
is itself the silent-absence bug class this repository keeps producing — ADR-0001 §8's "a control
that runs only when an optional environment variable happens to be set." There is no flag.

**Precondition, carried over from ADR-0002 D3 and ADR-0003 §8.** Repo evidence cannot prove the
absence of a deployment it cannot observe. Before the implementation PR merges, obtain operator
confirmation that no deployed environment, runbook or external integration posts to this surface. If
confirmation comes back positive, this surface reverts to a staged rollout — an
unauthenticated-but-logged soak with a counter that must read zero before enforcement, on the model
of ADR-0001 §7 stage 2, with a dated end state and an issue tracking it.

**A second, unusual confirmation is required here**, because D2 changes what a valid vendor payload
is: any real integration would have been sending `tenant_id` (or `message.customer`, or
`caseAlert.tenant`) as the tenant, and after migration that field stops being read. The operator
confirmation must therefore cover the profiles as well as the endpoint — specifically, which tenant
each of the three adapters should be bound to. **The implementation PR cannot invent those values**;
a profile constant is an operator declaration, and guessing one would be precisely the
"no defaults, no sentinels" violation ADR-0001 §5 refuses elsewhere. Absent a real answer, the
shipped profiles are fixtures and should be migrated to the fixture tenant already used throughout
the test corpus (`tenant-a`), with that stated in the profile `description` so no reader mistakes a
fixture for a deployment binding.

**Rollback lever.** Reverting the implementation PR restores unauthenticated access. As in ADR-0003
§8 this needs no suspension record — no schema change, no data written, nothing left behind — with
the same asymmetry stated: a revert re-opens SEC-1e and restores a body-trusting write path, so it
is a re-opening rather than a neutral rollback and should be recorded as one. Note that a revert
also restores `assertTenant`, without which the surface fails closed on every write; a partial
revert that removes the middleware but keeps §6's deletion would take the surface to a hard outage.

## 8. Test strategy — the bar for calling SEC-1e closed

Per `CLAUDE.md` rule 5, each case must fail before the change. These are ordinary Go tests with no
database dependency, so unlike ADR-0001 §8's suite they run under `go test -race -count=1 ./...` on
every CI run, and nothing here may be gated on `OWL_TEST_DATABASE_URL`.

**The two cases that define the decision (D2/D3/D4):**

1. **Constants-bound tenant enforced.** A token issued for `tenant-a` posting to an adapter whose
   profile declares `constants.tenant_id = "tenant-a"` reaches the handler with
   `tenantctx.FromContext` returning `tenant-a`, the write proceeds, and the persisted
   `CreateAlertRequest.TenantID` is `tenant-a`.
2. **Mismatch rejected, with nothing written.** A token for `tenant-a` posting to an adapter whose
   profile declares `tenant-b` is rejected with 403 **and leaves no record, no receipt and no audit
   entry in the state directory**. The filesystem assertion is the point of the case: it fails
   against today's ordering (§5) even with authentication present, which is what makes it the test
   that proves D3 rather than restating D4.

**Cases that prove the mechanism is real:**

3. **Unauthenticated rejected** — 401 on: no `Authorization` header, a header without the `Bearer `
   prefix, a valid-shaped token with an invalid signature, and a valid signature over tampered
   claims. No handler runs and nothing is written in any of them.
4. **Wildcard claim rejected.** A valid `platform-admin` token bound to `'*'` is rejected
   (`ErrWildcardTenant`, `internal/tenantctx/tenantctx.go:40-41`).
5. **Route table completeness.** Every route `Handler()` registers has an entry in the policy table,
   and constructing the guard with a route missing from the table fails — the check that keeps state
   (A) from decaying into an unstated default (ADR-0003 §4).

**Regression cases for the profile rule and the deletion:**

6. **A profile declaring `mappings.tenant_id` fails to load**, and a `Server` configured with a
   profiles directory containing one fails to construct. This is what makes the mixed state
   unreachable rather than merely undocumented (§4).
7. **`Persist` with no bound tenant returns `ErrNoBoundTenant`** — the inversion of
   `internal/vendoradapter/postgres_test.go:64` (§6). Without this, the interim's removal is
   unverified.
8. **All three shipped profiles load and convert**, with `profile_sha256` recomputing to the
   declared value — `internal/vendoradapter/convert_test.go:20` already covers the shape and will
   fail on a stale declared checksum, which is the intended tripwire for a half-done migration.

## 9. Accepted risks and non-goals

**Route-level authorization does not exist after this ADR.** State (A), §3: within a tenant, any
authenticated subject may ingest vendor alerts. This is the same residual ADR-0003 §10 records for
its two surfaces, and it closes with the same follow-up (§10).

**`GET /v1/vendor-adapters` is not tenant-filtered.** Any authenticated caller sees every adapter's
`adapter_id`, `version`, `vendor` and `profile_sha256` (§3). Under D2 the profile set partitions by
tenant, so this discloses the existence and configuration checksum of other tenants' integrations.
Stated plainly because "the tenant is bound" invites the opposite inference; the fix belongs with
the read-filtering work in the authorization follow-up.

**The filesystem store's idempotency scope stays tenant-blind.** `Store.Process` keys receipts on
`"ingest:" + AdapterID` (`internal/vendoradapter/store.go:47-48`) with no tenant, while the Postgres
relation is keyed `(tenant_id, scope, idempotency_key)` per ADR-0001 §6. This is safe **only because
D2 makes `adapter_id` a per-tenant partition** — a profile serves exactly one tenant, so two tenants
cannot collide in one scope. It is recorded as an accepted risk with an explicit re-entry condition
rather than as a solved problem: **if `Mappings` for `tenant_id` were ever re-permitted, one profile
would again serve many tenants, and a shared idempotency key across two of them would surface a 409
"idempotency conflict" — the cross-tenant existence oracle ADR-0001 §8 names ("no existence
oracle"). Re-permitting mappings therefore requires folding the tenant into the receipt scope first.**

**A compromised integration can still write under its own tenant.** Authentication establishes which
tenant is writing, not that the alerts are genuine. An attacker holding a valid token for `tenant-a`,
or an integration whose credentials leak, can inject forged vendor alerts into that tenant. This is
the boundary this ADR draws and it should not be read as broader: SEC-1e closes cross-tenant
provenance, not alert authenticity.

**Token issuance and key distribution are not designed here**, identical to ADR-0003 §10. A fourth
service now depends on `reviewauth`, so signing-key rotation becomes a four-service operation.

**SEC-3 is untouched.** This sink still passes the DSN as `argv[1]` to `psql`
(`internal/vendoradapter/postgres.go:37`); ADR-0005 owns that change.

## 10. Follow-ups

None of these are edited by this ADR or its implementation PR. They are recorded so the conditions
are written down rather than remembered.

**GHSA-wv2h-hrq2-932p** — update once the implementation PR merges, to record that
`internal/vendoradapterapi` derives tenant from a verified token and an operator-declared profile
constant. With SEC-1e closed, ADR-0001 §2's closure condition — "SEC-1 is not closed while any
writer can name its own tenant" — holds on every HTTP write surface in the tree. The advisory should
still not be closed on this PR alone: §9's authorization, read-filtering and alert-authenticity
residuals remain, as do SEC-1c and SEC-1d.

**GHSA-vhj8-986g-vjf4** — unchanged by this ADR. `vendor_adapter_idempotency` was already
tenant-scoped by ADR-0001 §6; the filesystem residual in §9 is a distinct shape and is recorded
there, not folded into this advisory.

**`docs/backlog/issue-register.md`** — the register is excluded from version control, so this is a
note to its owner rather than a change:

- **SEC-1e** closes when §8's bar passes.
- **SEC-1** — the last of ADR-0001 D3's prerequisites is satisfied when SEC-1e closes. Whether SEC-1
  itself closes depends on ADR-0001 §9's other conditions, which this ADR does not touch.
- **The route-level authorization follow-up** opened by ADR-0003 §11 gains a third surface: this
  one's two `AuthenticatedTenant` routes, and the tenant filter on `/v1/vendor-adapters` (§9). Its
  registry-rotation cost is unchanged and now spans four services.

## Consequences

**Positive.** The last caller-asserted tenant on an HTTP write path is gone, and with it the last
reason `tenantctx.Assert`'s fail-closed contract had an exception. `assertTenant` — a body-trusting
fallback living in a sink, exactly the shape SEC-1b removed from the shared package — is deleted
rather than left with a comment describing when it should have been. The tenant on a vendor-adapter
record becomes an operator declaration carried in a checksummed profile and checked against a
verified caller, which is stronger provenance than any other write path in the platform currently
has. And the 403 finally precedes the write it exists to prevent.

**Negative.** Three content-addressed profiles change checksum, and with them every future
`RecordID` and `EnvelopeSHA256` for the same source alert (§4) — free today because no records
exist, and not free ever again. Constants-only means one profile per tenant, so an operator running
one vendor across ten tenants maintains ten near-identical profiles; that cost is real and is the
price of making the tenant an operator declaration rather than a payload field. A fourth service
depends on `reviewauth`. And the surface stops accepting the payload shape its own fixtures use,
which is an API break with no clients to break.

**Neutral but worth stating.** Nothing here makes this service deployed or deployable. Its only
config still names a state directory that is not in the tree, its `postgres_dsn` is still empty, and
the deployment harness still runs four binaries none of which is this one. SEC-1e removes a reason a
pilot could not be run; it does not run one — the same closing caveat ADR-0002 and ADR-0003 both end
on, and for the same reason.
