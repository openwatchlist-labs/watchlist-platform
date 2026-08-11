# ADR-0003: Authenticated tenant provenance for alertcaseapi and screeningapi

- **Status:** Proposed
- **Date:** 2026-08-11
- **Issue:** SEC-1b (P0)
- **Related:** SEC-1 (ADR-0001, accepted), REL-10 (ADR-0002), SEC-1c, SEC-1e, SEC-6,
  GHSA-vhj8-986g-vjf4, GHSA-wv2h-hrq2-932p
- **Supersedes:** nothing. Completes the prerequisite ADR-0001 D3 declared and ADR-0002 §11 handed
  over. Neither of those documents is modified by this one.

## Context

ADR-0001 built a complete tenant-isolation enforcement stack: forced RLS across sixteen relations,
a resolution/binding seam (`internal/tenantctx`, `internal/tenantsql`), cross-reference `WITH
CHECK` subqueries closing the FK-crossing hole, tenant-scoped idempotency keys on three tables, and
a two-tenant integration suite. All of it rests on one input — a tenant that arrives already
verified.

On two surfaces it does not arrive verified, and ADR-0001 said so at the time (§2, "closure
condition"): the authentication gap on `internal/alertcaseapi` and `internal/screeningapi` is
tracked as SEC-1b and blocks SEC-1 closure. That ADR specified the mechanism a verified tenant
flows through. This one supplies the identity.

The current state of each surface, verified against the tree rather than carried over from either
prior document:

**`internal/alertcaseapi` authenticates nothing and takes the tenant from the request body.**
`createAlert` decodes an `alertcase.CreateAlertRequest` (`internal/alertcaseapi/server.go:103-104`)
and does no credential check of any kind; a grep for tenant, authenticat, authoriz, bearer,
Authorization, claims or token across `internal/alertcaseapi/*.go` returns nothing outside tests.
The body's `tenant_id` is consumed downstream — required non-empty by
`internal/alertcase/policy.go:83`, and folded into the alert identity hash at
`internal/alertcase/policy.go:224-230`, so it is load-bearing evidence, not a routing hint. Whoever
sends the request chooses which tenant's data they are writing.

**`internal/screeningapi` has no tenant concept at all.** The string does not appear in the
package. `validateToken` (`internal/screeningapi/service.go:286`) is a charset-and-length check on
`X-Correlation-ID` and `Idempotency-Key`, not authentication, despite the name — ADR-0002 §11
flagged this and it remains true.

**The enforcement stack below them is already fully built and already inert on this axis.**
`tenantctx.Assert` (`internal/tenantctx/tenantctx.go:75-83`) implements ADR-0001 §2's demotion of
body-supplied `tenant_id` to an assertion: when ctx carries a tenant bound by a verified caller, a
disagreeing body value is rejected with `ErrTenantMismatch` (`:77-79`). When ctx carries no bound
tenant it falls through to `Resolve` on the body value alone (`:82`) — trusting the caller
outright. Its own doc comment (`:69-74`) names this the accepted interim and points at SEC-1b.
**Every sink call takes that fallback branch today**, because no API package binds a tenant on ctx:
the five `Assert` call sites are `internal/alertcase/postgres.go:80`, `:111`,
`internal/assistancerag/postgres.go:86`, `:126`, and `internal/vendoradapter/postgres.go:53`, and
none of their callers construct a bound context.

So the situation is precisely inverted from the usual one: the control is built, tested, and
merged, and the thing it constrains is a value the attacker supplies. Closing SEC-1b is what makes
the rest of ADR-0001 mean anything.

Two facts about the surrounding code are load-bearing for the design below.

- **The verification mechanism already exists and is complete.** `reviewauth.TokenService.Parse`
  (`internal/reviewauth/token.go:85-147`) is a finished verifier — §2 enumerates it. This ADR
  reuses it and adds nothing to it.
- **REL-10 already delivered the single integration point.** ADR-0002's Stage 2 deletion has
  executed. `cmd/screening-api` is the only screening entrypoint, `internal/screeningapi` the only
  backing package, and `scripts/ci/check_screening_variants.py` (wired at
  `scripts/ci/run-ci.sh:17`) fails the build if a variant path reappears. The five-way rollout
  ADR-0001 §3 specified has collapsed to one, exactly as ADR-0002 §11 promised.

## Decision

Authenticate both surfaces with the existing `reviewauth` token mechanism at the HTTP edge, bind
the verified tenant onto the request context through `tenantctx` before any handler runs, delete
the `tenantctx.Assert` fallback that currently trusts the body, and cut over hard rather than in
stages.

Five decisions frame the rest of this document.

| # | Decision | Consequence |
|---|---|---|
| **D1** | Reuse `reviewauth.TokenService.Parse` **unchanged**. No second auth system, no new dependency. | The claims schema, registry-SHA lineage, session-epoch revocation and role re-derivation that `reviewconsoleapi` already relies on apply identically here. `tenantctx.Resolve`'s contract is untouched — it already accepts exactly a `reviewauth.Claims` (§2). |
| **D2** | Add a new package `internal/httpauth` for the HTTP edge adapter. **Not** an extraction from `reviewauth`, which needs nothing extracted. | One import-cycle-free place where authenticating and tenant-binding happen together, so "authenticated but forgot to bind" cannot compile. `platformapi`'s reach through `reviewconsoleapi` is retired as a side effect (§3). |
| **D3** | SEC-1b delivers **authentication and tenant binding only**. Between this cutover and the permission-vocabulary follow-up, every route is in state **(A)**: any validly authenticated, tenant-bound request is permitted. | Stated as a decision with a per-route table (§4), never an unstated default. The alternative — reject everything pending authorization — is rejected in §4 with reasons, chiefly that it makes this ADR's own test bar vacuous. |
| **D4** | **Hard cutover.** Auth is unconditional; there is no `auth_required` flag and no unauthenticated transition mode. | Justified in §8 against the live-traffic evidence, which is the specific thing that distinguishes this from an ordinary API-breaking change. Conditional on the same operator confirmation ADR-0002 D3 required. |
| **D5** | Body-supplied `tenant_id` behavior is **inherited from ADR-0001 §2, not re-decided**. | 403 on mismatch, never silently overwritten, never silently accepted. The mechanism is already written and already tested; this ADR supplies the bound tenant that makes the check reachable. |

D2 and D3 are the two judgment calls this ADR exists to make, and §3 and §4 argue them rather than
listing options.

## 1. Scope

In scope: the authentication mechanism and its position in the request pipeline (§2), the
`internal/httpauth` package and the adoption boundary (§3), the route policy table and the (A)/(B)
decision (§4), the inherited body-`tenant_id` assertion (§5), removal of the `tenantctx.Assert`
fallback and the test breakage it causes (§6), the screening idempotency key (§7), rollout (§8),
the test bar for calling SEC-1b closed (§9), accepted risks (§10), and follow-up update conditions
(§11).

Out of scope, each with a pointer: route-level authorization and the permission vocabulary it needs
(§4, §11); `internal/vendoradapterapi`, whose tenant arrives from a config-loaded adapter profile
rather than a request body and is a different shape of gap (§10, SEC-1e); the
`screening_idempotency_receipt` relation (§7, ADR-0001 Class C, SEC-1c); `internal/rag`'s CLI
callers (ADR-0001 seam addendum §5, SEC-1d); migrating `internal/reviewconsoleapi` onto the new
package (§3); `rateIdentity`'s fail-open behavior (§3, §10).

This ADR documents a decision. The implementation is a separate PR, per `CLAUDE.md` hard rule 7.
§6 and §9 enumerate that PR's scope so nothing in it is discovered rather than designed.

## 2. The mechanism

### What verifies the caller

`reviewauth.TokenService.Parse` (`internal/reviewauth/token.go:85-147`), unchanged. It is a
complete verifier, and the enumeration matters because reusing something incomplete would be worse
than writing something new:

| Check | Location |
|---|---|
| Format and `owat1` prefix, three segments | `token.go:88` |
| Constant-time HMAC-SHA256 over the signed portion | `token.go:96`, via `sign` at `token.go:148-152` |
| Strict claims decode, unknown fields rejected | `token.go:103-107` |
| Claims schema version and registry-SHA lineage | `token.go:108-110` |
| Issued-at with 30s skew tolerance | `token.go:120-122` |
| Expiry | `token.go:123-125` |
| TTL against `MaxTTL` policy | `token.go:126-128` |
| Subject exists and is active | `token.go:129-132` |
| Session-epoch revocation | `token.go:133-135` |
| Roles re-derived from the registry, stale binding rejected | `token.go:136-145` |

Two properties of that list are worth drawing out because they do security work this ADR then
relies on and does not repeat.

**Role re-derivation is a tenant check, not only a role check.** `Parse` calls
`s.Registry.RolesFor(u, c.TenantID)` (`token.go:136`), and `RolesFor`
(`internal/reviewauth/registry.go:105`) returns an error when the subject has no binding for that
tenant (`registry.go:114-116`). A token naming a tenant its subject is not bound to therefore fails
to parse at all. That is coarse — it does not distinguish an analyst from an auditor within a
tenant — but it is a real cross-tenant control that exists before any authorization work lands, and
§4 leans on it.

**Registry-SHA lineage binds tokens to a registry version.** `Parse` rejects any token whose
`registry_sha256` does not equal the loaded registry's (`token.go:108-110`). This is what makes the
authorization follow-up in §11 a coordinated rotation rather than an additive change.

### Where it sits

A middleware wrapping the whole handler, ahead of every route, on both surfaces. The scheme is a
bearer token in the `Authorization` header, identical to the one `internal/reviewconsoleapi`
already uses (`server.go:169-175`).

Both surfaces are already wrappable and neither needs a route-table migration first:

- `cmd/screening-api/main.go:37` constructs a single `screeningapi.Handler` and `:40` passes it to
  `http.Server`. Its routing is a hand-rolled `switch` on `request.URL.Path`
  (`internal/screeningapi/http.go:23-54`) and stays exactly as it is.
- `cmd/alert-case-api/main.go:33` passes `server.Handler()` to `http.Server`.
  `alertcaseapi.Handler()` (`internal/alertcaseapi/server.go:52-64`) is already an
  `http.ServeMux` with nine routes.

This confirms ADR-0002 §11's inheritance claim post-deletion: one entry point, one config path, one
key-derivation site, and a populated seam is all that was missing.

### How it produces a tenant

The middleware verifies, then binds, in one place:

```go
claims, err := tokens.Parse(bearer, time.Now().UTC())   // reviewauth
tenant, err := tenantctx.Resolve(claims)                 // unchanged contract
ctx := tenantctx.NewContext(r.Context(), tenant)
```

**`tenantctx.Resolve`'s contract is consumed exactly as written and is not modified.** It takes a
`reviewauth.Claims` and reads `claims.TenantID` (`internal/tenantctx/tenantctx.go:35-36`, field
defined at `internal/reviewauth/types.go:40`), trims surrounding whitespace, and refuses two
values outright: empty, with `ErrNoTenantClaim` (`tenantctx.go:38-39`), and the `'*'` wildcard,
with `ErrWildcardTenant` (`tenantctx.go:40-41`). Both refusals are already correct for this use and
neither needs relaxing.

The wildcard refusal has a visible consequence that deserves naming rather than discovering: the
shipped registry binds `platform-admin` to tenant `'*'`
(`configs/review-console/identity-registry-r1.json`). A valid, correctly signed platform-admin
token presented to either of these surfaces is **rejected**. That is ADR-0001 §2 working as
specified — "the `*` wildcard must not be reachable from a request binding" — and §9 gives it a
named test. A caller holding a wildcard claim must obtain a concrete-tenant token; the
query-parameter substitution `reviewconsoleapi` performs (`server.go:210-216`) is a review-console
affordance and is deliberately not reproduced here (§3).

`/healthz` and `/readyz` remain unauthenticated on both surfaces, matching
`reviewconsoleapi/server.go:113-116`, where health, readiness and console assets sit outside the
`sec` wrapper. Deployment probes must not need credentials, and neither endpoint reads
tenant-scoped data — `screeningapi`'s readiness is `Service.Ready()` (`http.go:35`) and
`alertcaseapi`'s is `Server.Check` (`server.go:69-75`). §4's table records this per route rather
than leaving it to the middleware's construction.

## 3. `internal/httpauth`, and why it is a new package rather than an extraction (D2)

The question this ADR was asked to settle: should it extract a standalone auth package from
`reviewauth`'s existing pieces, so `alertcaseapi`/`screeningapi` — and `platformapi`,
retroactively — do not each reach through `reviewconsoleapi` the way `platformapi` does today?

**Recommendation: add `internal/httpauth`. But "extract from `reviewauth`" is the wrong framing,
and correcting it is most of the answer.**

### Nothing needs extracting

`internal/reviewauth` already *is* the standalone auth package. Everything a consumer needs is
exported and importable today with no refactor: `TokenService` (`token.go:18`), `Claims`
(`types.go:35-46`), `Registry` (`types.go:27-34`), `LoadRegistry` (`registry.go:13`),
`VerifyRegistry` (`registry.go:26`), `LoadSigningKey` (`token.go:24`), `NewTokenService`
(`token.go:39`), `Permissions` (`registry.go:124`) and `PermissionAllowed` (`registry.go:140`). It
imports nothing from elsewhere in the tree.

What does not exist standalone is roughly thirty lines of HTTP edge adapter — read the
`Authorization` header, call `Parse`, put the result on the request context, reject with 401 on
failure. That exists exactly once, as `reviewconsoleapi`'s unexported `sec`
(`internal/reviewconsoleapi/server.go:162-194`), behind an unexported context key and accessor
(`server.go:199`). It is unreachable by any other package by construction.

This reframing also disposes of the premise about `platformapi`. `rateIdentity`
(`internal/platformapi/server.go:253-268`) reaches through `s.Review.Tokens` (`:257`) not because
`reviewconsoleapi` holds something unique, but because it needs a `*TokenService` and nobody wrote
the three lines that construct one from `reviewauth` directly. That coupling is incidental and
fixable today without any new package at all. **A new package is therefore not justified by
"stop the reach-throughs."** It is justified by the next point.

### Why not put the middleware in `reviewauth`

Because it cannot bind a tenant there. Binding means calling `tenantctx.Resolve`, and
`internal/tenantctx` imports `internal/reviewauth` (`tenantctx.go:15`). Middleware living inside
`reviewauth` would create a cycle, so it could only stash claims and leave each handler to call
`Resolve` itself.

That split is the exact silent-absence shape this repository keeps producing. A handler that
authenticates but forgets to bind compiles, passes review, serves traffic, and — until the §6
fallback removal lands — writes rows under a body-supplied tenant while looking authenticated.
`CLAUDE.md` rule 5 names this class ("a control that looks installed and does nothing") and
ADR-0001 §3 built a CI check specifically because "code review does not reliably catch a call that
*should have* gone through a wrapper."

A package importing both `reviewauth` and `tenantctx` has no cycle and makes the bound tenant a
structural consequence of having passed authentication: there is no ordering for a handler to get
wrong, because the handler is not involved. `tenantctx.Assert`'s post-§6 behavior — error when no
tenant is bound — becomes the fail-closed backstop underneath it rather than the primary control.

### Adoption boundary, deliberately narrow

- **`alertcaseapi` and `screeningapi`** adopt it in the implementation PR. This is the SEC-1b
  deliverable.
- **`platformapi`** is retrofitted to construct its own `TokenService` from `reviewauth`, retiring
  the `s.Review.Tokens` reach (`server.go:257`). This is a coupling fix only. **`rateIdentity`'s
  fail-open to `"anonymous"` (`server.go:268`) is not changed**, because for a rate-limit bucket
  identity, falling back to a per-IP bucket on an unparseable token is defensible, and altering
  rate-limiting behavior inside an authentication ADR is scope creep of exactly the kind ADR-0002
  D4 refused. It is recorded in §10 as a known shape, not fixed here.
- **`reviewconsoleapi` is not migrated.** Its `sec` does two things `httpauth` deliberately will
  not: it appends a security-audit event per request including the outcome and status
  (`server.go:192`), and its `tenant()` (`server.go:210-216`) supports wildcard-claim operators
  substituting a concrete tenant from a query parameter — which `httpauth` must refuse, since
  `Resolve` rejects `'*'` (§2). Folding those differences into a shared middleware would either
  weaken the wildcard refusal or force review-console semantics onto two APIs that have no
  four-eyes or review structure. Migrating it is an optional later cleanup, not a SEC-1b
  prerequisite.

That answers the sub-question of whether `alertcaseapi`/`screeningapi` should adopt
`reviewconsoleapi`'s exact middleware-plus-per-handler-derivation split: **no.** The middleware half
is right and is what `httpauth` generalizes. The per-handler half exists because the review console
has wildcard operators and per-resource tenant comparisons against rows it has already fetched
(`tenantOK`, `server.go:209`, called at `:242`, `:298`, `:334`, `:367`, `:383`, `:415`, `:426`).
Neither new surface has that structure — both write rows whose tenant is the caller's — so binding
once at the edge is both simpler and stronger than deriving per handler.

### Security-audit events

`reviewconsoleapi`'s middleware emits a `reviewauth.SecurityAuditEvent` per request
(`server.go:192`, and for rejected requests `:195-198`). `httpauth` should expose the same
capability as an optional dependency rather than requiring it, since `screeningapi` has no audit
store configured today and requiring one would make audit-store provisioning a blocker for
authentication. Whether both new surfaces enable it at cutover is an implementation-PR call; the
ADR's position is that the hook must exist in the package from the start, because retrofitting an
audit seam through a middleware after adoption is how it ends up never being added.

## 4. Route policy, and the (A) versus (B) decision (D3)

SEC-1b delivers authentication and tenant binding. It does not deliver route-level authorization.
That leaves a question which must not be answered by default: between this cutover and the
authorization follow-up, what does a route do with a validly authenticated, tenant-bound request?

- **(A)** Permit it. A coarse, explicit "authenticated and tenant-bound is sufficient for now" gate.
- **(B)** Reject it. Fail closed on every data route until real authorization exists.

**Decision: (A), declared structurally per route rather than left implicit.**

### Why not (B)

**(B) makes this ADR's own test bar vacuous.** §9 requires that a valid token produce the correct
bound tenant and that a body `tenant_id` disagreeing with the bound claim be rejected with 403 and
write no row. Under (B) every data route returns 403 regardless, so both tests pass without
exercising anything. A security test that passes for the wrong reason is not a hypothetical concern
in this repository — ADR-0001's migration-PR addendum §1 records exactly that outcome, where the
cross-tenant pre-check "found '0 violations' for the wrong reason" because RLS had hidden the rows
it was supposed to be examining, and the migration committed successfully against a seeded
violation.

**(B) leaves the §6 fallback removal unvalidated.** The point of deleting the `Assert` fallback is
that sinks now *require* a ctx-bound tenant. If no request ever reaches a sink, nothing demonstrates
that the binding path works end to end — only that rejection works. The first real execution of the
bound-tenant path would then happen whenever the authorization follow-up flips routes on, in
whatever environment that lands in. That is the same class of deferred-first-execution risk
ADR-0001 §7 built a shadow stage to avoid.

**(A)'s residual is a different issue class from the one SEC-1 blocks on.** Under (A), an
unauthenticated request is rejected, a token with an invalid signature or stale registry lineage or
revoked session epoch is rejected (§2), a `'*'` wildcard claim is rejected, a body `tenant_id`
disagreeing with the bound claim is rejected (§5), and a token naming a tenant its subject has no
binding for cannot parse at all (`registry.go:114-116`). What (A) does *not* do is distinguish an
analyst from an auditor *within* one tenant. That is intra-tenant privilege separation. It is a
real gap and §11 tracks it — but it is not the tenant boundary ADR-0001 D3 makes a hard
prerequisite for closing SEC-1.

**The zero-traffic finding argues for (A) at least as strongly as against it.** The reasoning that
(B) costs little because nothing depends on these surfaces working is sound as far as it goes — but
the same premise makes (A) *safe*, because the population of callers who would be over-permitted
under (A) is empty. Absent traffic retires (A)'s risk and (B)'s cost at the same rate; what breaks
the tie is that (A)'s benefit — the binding gets exercised, in CI, from the first day — is
concrete, while (B)'s benefit is a gap that is theoretical while nothing calls these services.

### How (A) avoids becoming a forgotten placeholder

The legitimate worry about (A) is that a coarse gate installed as a temporary state is exactly the
kind of thing that is still there in a year with nobody remembering it was provisional. This is
handled structurally, using the move ADR-0001 §3 already used for its transitional allowlist — a
list CI forces to empty rather than a convention reviewers are asked to remember.

`httpauth` takes an explicit route-to-policy table. Every route must name a policy. The only policy
value that exists today is `AuthenticatedTenant`. A route present in the mux but absent from the
table fails at **construction**, not at request time — a startup error, not a 500 on the first
request that happens to hit it.

Two consequences follow. Adding a route without deciding its policy becomes impossible to ship
quietly. And the authorization follow-up becomes "add values to an enum that already exists and
change table entries," not "find every place a decision was silently deferred."

The table is filled in here, so state (A) is a decision on the record rather than a default nobody
wrote down:

| Surface | Route | Method | Policy |
|---|---|---|---|
| `screeningapi` | `/healthz` (`http.go:24`) | GET | `Public` |
| `screeningapi` | `/readyz` (`http.go:30`) | GET | `Public` |
| `screeningapi` | `/v1/screenings` (`http.go:40`) | POST | `AuthenticatedTenant` |
| `screeningapi` | `/v1/screenings/batch` (`http.go:46`) | POST | `AuthenticatedTenant` |
| `alertcaseapi` | `/healthz` (`server.go:54`) | GET | `Public` |
| `alertcaseapi` | `/readyz` (`server.go:55`) | GET | `Public` |
| `alertcaseapi` | `/v1/alerts` (`server.go:56`) | POST | `AuthenticatedTenant` |
| `alertcaseapi` | `/v1/alerts/batch` (`server.go:57`) | POST | `AuthenticatedTenant` |
| `alertcaseapi` | `/v1/alerts/{id}` (`server.go:58`) | GET | `AuthenticatedTenant` |
| `alertcaseapi` | `/v1/cases` (`server.go:59`) | POST | `AuthenticatedTenant` |
| `alertcaseapi` | `/v1/cases/{id}` (`server.go:60`) | GET | `AuthenticatedTenant` |
| `alertcaseapi` | `/v1/cases/{id}/events` (`server.go:61`) | POST | `AuthenticatedTenant` |
| `alertcaseapi` | `/v1/cases/{id}/verify` (`server.go:62`) | POST | `AuthenticatedTenant` |

Note that `alertcaseapi`'s two read routes (`/v1/alerts/{id}`, `/v1/cases/{id}`) currently perform
no tenant comparison against the record they return — unlike `reviewconsoleapi`, which checks
`tenantOK` on every fetched row (`server.go:242`, `:298`). Binding a tenant does not by itself add
that check. §10 records it as a distinct residual, because a reader could otherwise reasonably
conclude that "tenant is bound" means "reads are filtered."

## 5. Body-supplied `tenant_id` (D5)

ADR-0001 §2 already decided this and this ADR does not reopen it: a body `tenant_id` that is
present and unequal to the bound tenant causes rejection with 403. It is never silently overwritten
with the bound value and never silently accepted, because the first rewrites what the caller
claimed and the second records a claim nobody checked.

The mechanism is written and tested. `tenantctx.Assert` (`tenantctx.go:75-83`) compares the body
value against a ctx-bound tenant and returns `ErrTenantMismatch` on disagreement (`:77-79`), and
`internal/integrationtest/tenant_isolation_test.go:421-442` already asserts exactly that, binding a
tenant on ctx at `:421-425` and requiring `PersistAlert` to reject a disagreeing body tenant at
`:440-442`.

What has been missing is a bound tenant for it to compare against, on any request path. This ADR
supplies it. The field stays in the wire format — ADR-0001 §2 established it is load-bearing for
vendor adapters (`internal/vendoradapter/profile.go:13`) and for the alert identity hash
(`internal/alertcase/policy.go:224-230`) — and changes meaning from an instruction to an assertion.

## 6. Removing the `tenantctx.Assert` fallback, and what it breaks

This is implementation-PR scope, stated here so it is designed rather than discovered.

**The change.** Delete the fallback at `internal/tenantctx/tenantctx.go:82`, so `Assert` returns an
error when ctx carries no bound tenant instead of resolving the body value. Rewrite the doc comment
at `:69-74`, which currently documents the fallback as the accepted interim and names SEC-1b as the
work that ends it. That comment is the marker for this change; leaving it in place after removing
the behavior it describes would be worse than either state.

**What this does not touch.** Direct `tenantctx.Resolve` callers are unaffected and must stay:
`internal/productionops/postgres.go:90`, `:129`, `:227`, and the `SyncAudit` disk resolvers at
`internal/alertcase/postgres.go:216` and `internal/assistancerag/postgres.go:206`. These construct
`reviewauth.Claims{TenantID: ...}` from tenant values read out of *persisted records*, not from a
request — the resolution pattern ADR-0001's seam addendum §1 and §2 specified after establishing
that a live Postgres lookup was a structural dead end. A reviewer scanning for "caller names its
own tenant" will find these; they are legitimate and this section exists partly so that finding
does not stall the PR.

### Test breakage — measured, not estimated

The scoping premise for this work was that removing the fallback would break every existing sink
test. **Measured against the current tree, it does not**, and the real cost is somewhere else. Both
halves are stated because an implementer planning for the wrong one will mis-size the PR.

**Sink tests are not affected.** None of the five `Assert` call sites is reached by any unit test in
its own package: `internal/alertcase`, `internal/assistancerag` and `internal/vendoradapter` have
tests (`store_test.go`, `state_path_test.go`, `convert_test.go`) that never call the `Persist*`
functions. `alertcaseapi`'s handler test constructs a `Config` with no `PostgresDSN`
(`internal/alertcaseapi/server_test.go:22`), so `Server.Postgres` stays nil
(`internal/alertcaseapi/server.go:28-33`) and no sink is entered. The only test that calls a sink is
`internal/integrationtest/tenant_isolation_test.go:440`, which already binds a tenant on ctx
(`:421-425`) and therefore takes the bound branch — it survives the removal unchanged.

**Exactly two tests break, both direct unit tests of the fallback**, in
`internal/tenantctx/tenantctx_test.go`:

- `:59` `TestAssertResolvesFromBodyWhenNoBoundTenant` — inverts. It currently asserts that
  `Assert(context.Background(), "tenant-acme")` succeeds; it must assert that it now fails.
- `:69` `TestAssertRejectsWildcardOrEmptyBodyWhenNoBoundTenant` — keeps passing, but for a
  different reason (no bound tenant, rather than a bad body value). Rewrite it to assert the new
  reason, or it silently stops testing what its name claims.

**The larger cost is the handler tests, which will 401 once middleware lands.** These are in scope
for the same PR and need a minted-token helper:

- `internal/alertcaseapi/server_test.go` — `TestHTTPAlertCaseLifecycle` (`:16`) issues four
  unauthenticated requests (`:33`, `:46`, `:57`, `:62`) and `TestStrictUnknownField` (`:68`) one
  more (`:72`).
- `internal/screeningapi/service_test.go` — `TestHandlerIdempotencyReplayAndConflict` (`:76`)
  issues three (`:85`, `:93`, `:110`).

**The helper should mint real tokens, not stub the middleware.** `TokenService.Issue`
(`internal/reviewauth/token.go:51`) produces a token `Parse` accepts, and the fixtures already
exist: `test/fixtures/review-console/signing-key.hex` and
`configs/review-console/identity-registry-r1.json`, whose users include `alice` bound to `tenant-a`
and `mallory` bound to `tenant-b` — a two-tenant pair usable directly for §9's cross-tenant cases.
`cmd/review-console/main.go:32-42` (`issue-token`) is the worked reference. Stubbing the middleware
out in tests would leave the verification path itself untested at exactly the surfaces this ADR
exists to protect.

## 7. The screening idempotency key (GHSA-vhj8-986g-vjf4)

ADR-0002 §11 handed SEC-1b a tenant-blind idempotency key and left open whether this ADR feeds a
tenant into it. **It does, for one of the two stores that carry the defect.** Those two are
routinely conflated and are separated here.

**`internal/screeningapi`'s filesystem store is fixed in this ADR's implementation PR.** The record
path is derived from endpoint and key only — `recordPath` digests a two-field struct of
`{endpoint, key}` (`internal/screeningapi/idempotency.go:108-113`), called from
`internal/screeningapi/http.go:91` and `:149` with the endpoint taken from `request.URL.Path`
(`http.go:89`). Once §2's middleware binds a verified tenant, adding it to that digest struct is a
small, local change at the single derivation site REL-10 consolidated down to. Two reasons to do it
now rather than defer:

- The tenant that makes the fix possible arrives in this PR. Shipping the authentication and then
  not making the one-site change it enables leaves the defect open for no reason anyone would be
  able to reconstruct later.
- There is no migration cost. No records exist to rekey: `var/` is absent from the tree and
  gitignored (`.gitignore:9`), and the configured root is `var/screening-api/idempotency`
  (`configs/screening-api/example.json:7`). A key-derivation change that would ordinarily require a
  rekey or a dual-read window requires neither here.

**The `screening_idempotency_receipt` relation stays deferred to SEC-1c.** It is written by
`internal/screeningledger`, not by `internal/screeningapi`, and closing it means a migration plus
the Class C RLS decision ADR-0001 §4, §6 and §9 explicitly own — including how historical ledger
rows are attributed. ADR-0001's own re-entry condition for Class C is "once `internal/screeningapi`
carries an authenticated tenant under SEC-1b" (§9), which this ADR satisfies. **SEC-1c's
precondition is met by this ADR; its work is not done by this ADR.**

So GHSA-vhj8-986g-vjf4 narrows here rather than closing: the filesystem store is fixed, the relation
is not. §11 states the advisory update condition.

## 8. Rollout: hard cutover (D4)

ADR-0001 chose a three-stage rollout with a shadow counter because its change was a migration whose
failure mode was a full write outage. This change is different in a way that normally argues for
*more* caution, not less: these are HTTP API surfaces, and requiring authentication breaks every
existing client at the moment it lands. The default answer for a live API would be a staged rollout
— accept unauthenticated requests while logging them, then enforce.

**Rejected, because the premise is false for these two surfaces specifically.**

ADR-0002 §5 and §10 found no live traffic to any screening-api tier on all repo-visible evidence.
That finding still holds after Stage 2's deletion, and it now extends to `alertcaseapi` with
evidence stronger than the absence-of-reference argument ADR-0002 had available:

- `grep -rn "alert-case-api\|screening-api"` across `scripts/`, `.github/`, `runtime/` and
  `deploy/` returns nothing except `scripts/ci/check_screening_variants.py`'s own docstring.
- `configs/screening-api/local.json` — the survivor's `--config` default
  (`cmd/screening-api/main.go:33`, `:62`) — still does not exist. Only `example.json` remains, and
  it carries placeholder catalog identifiers and an all-zero package checksum.
  `configs/alert-case/phase9ab-example.json` names a `state_directory` of
  `test/fixtures/alert-case/runtime-state`, which does not exist either, and a `psql_path` of
  `test/fixtures/alert-case/fake-psql.sh` — it is a fixture config, not a deployment.
- **Positive evidence, not just absence:** the only deployment harness in the repository
  (`scripts/deployment/r2-4/`) runs exactly one binary. Its policy declares
  `runtime_executables: platform-api` (`scripts/deployment/r2-4/harness/config/policy.json`), and
  `remote_runtime_control.py:230` launches `bin/platform-api serve` and nothing else. That binary's
  handler wraps only the review console — `platformapi.Handler()` calls `s.Review.Handler()`
  (`internal/platformapi/server.go:168-169`) — and the package imports just `productionops` and
  `reviewconsoleapi` (`server.go:19-20`). Neither `alertcaseapi` nor `screeningapi` is reachable
  from the sole deployed entrypoint.

With no client to keep working, a staged rollout buys nothing and costs something real. A
config-gated `auth_required: false` is *itself* the silent-absence bug class this repository keeps
producing, and ADR-0001 §8 says so directly about a different flag: "a control that runs only when
an optional environment variable happens to be set is the same silent-absence bug this ADR exists
to fix, one level up." Authentication that a config key can switch off is a control whose presence
cannot be read off the code. There is no flag.

**Precondition, carried over from ADR-0002 D3.** Repo evidence cannot prove the absence of a
deployment it cannot observe: `/var/` is gitignored and there is no telemetry in either package to
consult. Before the implementation PR merges, obtain the same operator confirmation ADR-0002 Stage 0
required — that no deployed environment, runbook, or external integration calls either surface. If
confirmation comes back positive for either one, **that surface reverts to a staged rollout**: an
unauthenticated-but-logged soak with a counter that must read zero before enforcement, on the model
of ADR-0001 §7 stage 2, with a dated end state and an issue tracking it. This is a conditional in
the design, not a decision left to whoever runs into it.

**Rollback lever.** Reverting the implementation PR restores unauthenticated access. Unlike
ADR-0001 §7's lever this needs no suspension record, because the change writes no data, alters no
schema, and leaves no state behind — the same reasoning ADR-0002 §7 applied to a pure deletion. The
one asymmetry worth stating: reverting also restores the `tenantctx.Assert` fallback, and with it
the body-trusting behavior on every sink. A revert is therefore a re-opening of SEC-1b, not a
neutral rollback, and should be recorded as such.

## 9. Test strategy — the bar for calling SEC-1b closed

Per `CLAUDE.md` rule 5, each case must fail before the change. Cases run **per API surface** —
`internal/alertcaseapi` and `internal/screeningapi` — because a control adopted on one and not the
other is indistinguishable from an absent one, which is the argument ADR-0001 §3 made for the
five-variant rollout and which survives the collapse to two surfaces.

**The three required cases, per surface:**

1. **Unauthenticated request rejected.** 401, on: no `Authorization` header, a header without the
   `Bearer ` prefix, a well-formed token with an invalid signature, and a token with a valid
   signature over tampered claims. No handler runs and no row is written in any of them.
2. **Valid token produces the correct bound tenant.** A token issued for `tenant-a` reaches the
   handler with `tenantctx.FromContext` returning `tenant-a`, and the write proceeds. This is the
   case (B) in §4 would have made impossible to write.
3. **Mismatched body tenant rejected.** A token for `tenant-a` with a body asserting `tenant-b` is
   rejected with 403 and **writes no row through any sink** — ADR-0001 §8's provenance obligation,
   exercisable over HTTP for the first time.

**Three further cases the investigation showed are required**, because `Parse` is the only thing
standing behind the binding and a partial reuse of it would be invisible:

4. **Wildcard claim rejected.** A valid `platform-admin` token, bound to tenant `'*'` in
   `configs/review-console/identity-registry-r1.json`, is rejected — `ErrWildcardTenant`,
   `tenantctx.go:40-41`. Correct per ADR-0001 §2 and surprising enough that its absence would read
   as a bug.
5. **Expired, stale-lineage, and revoked-epoch tokens rejected**, one case each, against
   `token.go:123-125`, `:108-110` and `:133-135`. These verify the middleware actually calls
   `Parse` rather than a subset of it.
6. **Cross-tenant token rejected at parse.** A token naming a tenant its subject has no binding for
   fails, per `registry.go:114-116`. This is the coarse cross-tenant control §4 leans on when
   arguing state (A) is not fail-open, so it must be tested rather than assumed.

**Route table completeness.** A test asserting that every route registered on each surface has an
entry in §4's policy table, and that constructing the server with a route missing from the table
fails. This is what keeps state (A) from decaying into an unstated default (§4).

**Regression cases for §6 and §7:**

- `tenantctx.Assert` with no bound tenant returns an error rather than resolving the body value,
  replacing `tenantctx_test.go:59`.
- Two tenants presenting the same idempotency key to `/v1/screenings` receive independent records,
  and neither inherits the other's response — the `screeningapi` half of GHSA-vhj8-986g-vjf4 (§7).

**Non-skippable.** These are ordinary Go tests with no database dependency, so unlike ADR-0001 §8's
suite they run under `go test -race -count=1 ./...` on every CI run without provisioning. Nothing
here is gated on `OWL_TEST_DATABASE_URL`, and nothing here should be.

## 10. Accepted risks and non-goals

**Route-level authorization does not exist after this ADR.** State (A), §4: within a tenant, any
authenticated subject may call any route on either surface. An auditor-role token can create an
alert. The cross-tenant boundary holds; the intra-tenant one does not. This is the largest residual
in this document and §11 carries its update condition.

**`alertcaseapi`'s read routes do not filter by bound tenant.** `getAlert`
(`internal/alertcaseapi/server.go:169`) and `getCase` (`:213`) return a record by ID with no
comparison against the caller's tenant — unlike `reviewconsoleapi`, which checks `tenantOK` on
every fetched row (`server.go:242`, `:298`). This ADR binds a tenant; it does not add those checks.
Until they exist, a caller authenticated for one tenant can read another tenant's alert or case by
guessing an ID over HTTP, notwithstanding that the Postgres RLS policies would stop the equivalent
SQL read. Stated plainly because "tenant is now bound" invites the opposite inference. Tracked with
the authorization follow-up in §11.

**`platformapi.rateIdentity` still fails open.** It returns `"anonymous"` plus a per-IP bucket for
a missing or invalid token (`internal/platformapi/server.go:268`). §3 retires the reach through
`reviewconsoleapi` but deliberately does not change this. For a rate-limit bucket it is defensible;
it is recorded here so that the retrofit is not later read as having fixed it.

**`internal/vendoradapterapi` is untouched (SEC-1e).** Its tenant arrives from a config-loaded
adapter profile rather than a request body, so the shape of the fix differs — there is no bearer
token on the path that matters. Folding it in would mean designing a second mechanism inside an ADR
whose argument is that there should be one, and its `Assert` call site
(`internal/vendoradapter/postgres.go:53`) is affected by §6's removal, so SEC-1e is a **sequencing
dependency**, not merely a sibling: the fallback removal lands before that surface has a bound
tenant to supply. The implementation PR must confirm that no `vendoradapterapi` path regresses to an
error, or scope the removal to leave that call site working until SEC-1e closes. This is the one
place where §6's change reaches outside this ADR's two surfaces.

**`internal/rag`'s CLI callers remain unauthenticated (SEC-1d).** ADR-0001's seam addendum §5
documented `cmd/rag-query` and `cmd/review-run` taking tenant from a `--tenant-id` flag defaulted to
`"tenant-a"`. Unaffected by this ADR either way.

**Token issuance and key distribution are not designed here.** Both surfaces gain a signing-key path
and a registry path in config, and how those are provisioned in a real deployment is a deployment
concern this ADR does not address — consistent with `reviewconsoleapi`, which has the same shape
today (`internal/reviewconsoleapi/config.go:28-32`). The residual is that a shared signing key
across services means a token minted for the review console is accepted by these surfaces. That is
intended — it is one identity system — but it means key rotation is now a three-service operation.

## 11. Follow-ups

None of these are edited by this ADR or its implementation PR. They are recorded so the conditions
are written down rather than remembered.

**GHSA-wv2h-hrq2-932p** — update once the implementation PR merges, to record that
`internal/alertcaseapi` and `internal/screeningapi` now derive tenant from a verified token, and
that the residuals are the ones in §10 rather than "no authentication exists." The advisory should
not be closed on this PR alone: §10's authorization and read-filtering gaps remain, and SEC-1e is
open.

**GHSA-vhj8-986g-vjf4** — narrow, do not close (§7). The `internal/screeningapi` filesystem
idempotency store is fixed; `screening_idempotency_receipt` remains open under SEC-1c.

**`docs/backlog/issue-register.md`** — the register is deliberately excluded from version control
(`.gitignore`), so this is a note to its owner rather than a change:

- **SEC-1b** closes when §9's bar passes on both surfaces.
- **SEC-1** unblocks on the D3 prerequisite. ADR-0001 §2's closure condition — "SEC-1 is not closed
  while any writer can name its own tenant" — is satisfied for these two surfaces and not for
  `vendoradapterapi` (SEC-1e).
- **SEC-1c** — its stated re-entry condition ("once `internal/screeningapi` carries an
  authenticated tenant under SEC-1b", ADR-0001 §9) is **met** by this ADR. The Class C ledger
  relations can now be scoped.
- **A new issue for route-level authorization**, ID to be assigned by the register's owner rather
  than invented here. Scope: permission identifiers covering screening and alert ingestion, the
  route-to-permission mapping replacing §4's `AuthenticatedTenant` entries, the tenant checks on
  `alertcaseapi`'s read routes (§10), and the registry rotation. **Its cost, stated now so it is not
  discovered later:** new permission identifiers change `Registry.RegistrySHA256`, and `Parse`
  rejects any token whose `registry_sha256` does not match the loaded registry
  (`internal/reviewauth/token.go:108-110`). The vocabulary change therefore invalidates every
  outstanding token the moment it lands, across the review console and both new surfaces
  simultaneously. That is a coordinated rotation, and it is the concrete reason the work does not
  ride along inside SEC-1b.

## Consequences

**Positive.** ADR-0001's enforcement stack stops resting on a caller-supplied value. The
body-`tenant_id`-as-assertion mechanism, written and tested since the seam PR, becomes reachable for
the first time. `tenantctx.Assert` stops trusting the body and starts failing closed, so a future
sink whose caller forgets to authenticate errors rather than writing under a guessed tenant. The
authentication mechanism is the one already in the tree, so there is one identity system rather than
two, and `platformapi` stops reaching through `reviewconsoleapi` to get at it. SEC-1c's stated
re-entry condition is met.

**Negative.** State (A) leaves intra-tenant authorization absent on both surfaces, and
`alertcaseapi`'s read routes remain unfiltered by tenant (§10) — the two residuals most likely to
be misread as closed by someone who sees "authentication landed." A third package now depends on
`reviewauth`, so signing-key rotation becomes a three-service operation. `internal/httpauth` is a
new package in a repository that has good reason to be suspicious of new abstractions, and §3 argues
its existence rather than assuming it. And §6's fallback removal reaches one call site outside this
ADR's two surfaces, in `vendoradapterapi`, which SEC-1e has not yet reached.

**Neutral but worth stating.** Nothing here makes either service deployed or deployable.
`configs/screening-api/local.json` still does not exist, `configs/alert-case/phase9ab-example.json`
still points at a state directory that is not in the tree, and the only binary the deployment
harness runs is `platform-api`. SEC-1b removes a reason a pilot could not be run; it does not run
one. Anyone reading this ADR as evidence that these APIs are live in production has misread it, for
the same reason ADR-0002's closing paragraph gives.
