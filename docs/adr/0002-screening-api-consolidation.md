# ADR-0002: Screening API consolidation

- **Status:** Proposed
- **Date:** 2026-08-11
- **Issue:** REL-10 (P1)
- **Related:** SEC-1 (ADR-0001, accepted), SEC-1b (blocked on this ADR), DOM-3, #14, #15,
  SAL-5/SAL-6/SAL-9
- **Supersedes:** nothing. Corrects the record in `docs/design/phase8-runtime-operations.md` (§2) and
  `docs/RETIRED_SERVICE_VERSIONS.md` (§2), and one false doc comment in
  `internal/screeningapi/phase8c_scoring.go` (§6).

## Context

REL-10 is filed as "five parallel, non-shared implementations of the screening API" and has been
flagged since the original audit as the single biggest source of technical debt in the repo, on the
reasoning that a fix landing in one variant leaves four unprotected. ADR-0001 adopted that framing
directly (`docs/adr/0001-tenant-isolation.md:222-229`): the tenant seam must be adopted by
`cmd/screening-api` and `-v8d`/`-v8e`/`-v8f`/`-v8g` together, because "a partially adopted control is
indistinguishable from an absent one at runtime."

The debt is real. The stated shape of it is wrong in three ways that change what this ADR can decide,
and two documents in this repository make contradictory claims about which implementation is
authoritative. This ADR establishes the facts before deciding, because a consolidation that picks the
wrong survivor is not recoverable by review — it is recoverable only by re-deriving everything below.

**1. They are not five implementations of the same thing.** Only `internal/screeningapi` performs
screening. It starts the Rust catalog-mmap workers (`cmd/screening-api/main.go:97`) and has no
upstream. The other four are HTTP proxies that forward to an upstream and add one capability each.
`internal/screeningapiv8d/upstream.go:26-46` POSTs to `{base}/v1/screenings`, and its error strings
name the target explicitly — "call Phase 8B screening API" (`upstream.go:38`), "read Phase 8B
response" (`upstream.go:43`). The five example configs realize a port ladder that matches:

| Tier | Config | Listens | Upstream |
|---|---|---|---|
| 8B `screening-api` | `configs/screening-api/example.json:3` | `8090` | none — owns the Rust runtime |
| 8D `-v8d` | `configs/screening-api/phase8d-example.json:2-3` | `18091` | `18090` |
| 8E `-v8e` | `configs/scoring-activation/phase8e-example.json:2-3` | `18091` | `18090` |
| 8F `-v8f` | `configs/activation-promotion/phase8f-example.json:2-4` | `18093` | `18091` + `18092` |
| 8G `-v8g` | `configs/screening-ledger/phase8g-example.json:2-3` | `18094` | `18093` |

**2. They are not non-shared.** `cmd/screening-api-v8d/main.go:17` imports `internal/screeningapi`,
not `internal/screeningapiv8d`, reaching v8d only through a type-alias shim
(`internal/screeningapi/phase8d_frontdoor.go:6-30`). `internal/screeningapiv8e/server.go:11` and
`upstream.go:8` import v8d, and v8e embeds a v8d server **in-process** as a delegate
(`server.go:77-83`) rather than proxying to it. Only v8f and v8g are standalone. A deletion plan that
assumes independence breaks the build.

**3. None of them is deployed, `cmd/screening-api` included.** §5 gives the inventory. This matters
because "which variant is authoritative" has no traffic-based answer, and the two documents that offer
an answer disagree.

Two further facts are load-bearing and are why REL-10 needs an ADR rather than a delete commit:

- **The capabilities are not in the code this ADR deletes.** Each proxy tier is a thin HTTP wrapper
  over an engine package that has its own CLI and survives untouched (§6). Deleting the wrappers
  deletes packaging, not capability.
- **There is exactly one exception, and it is already tracked as DOM-3.** No surviving HTTP path
  returns scored results, because `screeningapi`'s scoring bridge has no caller (§6). This ADR does
  not fix that, and §10 states why.

## Decision

Delete `cmd/screening-api-v8d` through `-v8g` and `internal/screeningapiv8d` through `v8g`. Retain
`cmd/screening-api` / `internal/screeningapi` as the sole screening implementation and
`docs/api/screening-api.openapi.yaml` as its sole contract. Prove capability custody rather than
response parity before deleting, gate regrowth in CI, and hand SEC-1b exactly one auth integration
point.

Four decisions frame the rest of this document.

| # | Decision | Consequence |
|---|---|---|
| **D1** | The survivor is **`internal/screeningapi`**, chosen on capability and contract, not on recency, completeness, or deployment. | It is the only tier that can screen at all. The choice is forced, not preferred — see §4. This is **not** a synthesis: nothing is ported out of v8d–v8g, because the capabilities do not live there (§6). |
| **D2** | `docs/design/phase8-runtime-operations.md:27` is **stale by construction** and is corrected here, not silently overridden. | Its instruction to "target `screening-api-v8g` as the public boundary" is a restored pre-restart artifact (§2). Left unaddressed, the next reader re-opens this decision on the strength of a document with a newer commit date than the one that supersedes it. |
| **D3** | Deletion is gated on **operator confirmation**, not on this ADR's own evidence alone. | §5 and §9 show no repo-visible caller. Repo evidence cannot prove the absence of a deployment it cannot see, and `docs/RETIRED_SERVICE_VERSIONS.md:71-77` already named this exact missing input. §7 makes it a precondition rather than an assumption. |
| **D4** | Scoring is **not** wired into `screeningapi` by this ADR or its implementation PR. | That is DOM-3's scope. REL-10 makes DOM-3 materially worse (§10) and that is recorded as an accepted risk with a sequencing constraint — not quietly absorbed into a consolidation PR, where a response-schema change would ride in under a cleanup label. |

## 1. Scope

In scope: the survivor decision, the record corrections in §2 and §6, the caller/reference inventory
(§5), the deletion and rollback plan (§7), the endpoint contract (§8), the test bar (§9), the accepted
risks (§10), and the SEC-1b handover (§11).

Out of scope, each with a pointer: wiring scoring into the surviving HTTP path (§10, DOM-3);
authentication and tenant binding (§11, SEC-1b, ADR-0001 §2); the tenant-blindness of the surviving
idempotency key (§11, ADR-0001 Class C and GHSA-vhj8-986g-vjf4); replacing `fork`+`exec psql` in
`internal/screeningledger` (ADR-0001 §10, REL-2).

This ADR documents a decision. The deletion itself is a separate PR — see §7.

## 2. Record correction: which document is authoritative

Two documents make incompatible claims:

- `docs/RETIRED_SERVICE_VERSIONS.md:3-5` — v8d/e/f/g are "earlier iterations of the current
  `internal/screeningapi` / `cmd/screening-api`", with a recorded decision to "keep, not archive or
  delete" (`:50`).
- `docs/design/phase8-runtime-operations.md:27` — "New deployment work should target
  `screening-api-v8g` as the public boundary unless a lower-level component is being tested
  deliberately."

Both cannot be true. Git history resolves it, and resolves it against the more recently committed
file:

| File | History |
|---|---|
| `docs/design/phase8-runtime-operations.md` | one commit — `86350b7`, 2026-08-10 |
| `docs/RETIRED_SERVICE_VERSIONS.md` | `f9ca8c5` 2026-08-01 (authored), `f0bbbeb` 2026-08-09 (updated) |

`86350b7` is titled "SAL-5, SAL-6, SAL-9: restore remaining legacy design/testing/migration docs". It
restored 67 files from the frozen pre-restart repository `watchlist-platform-legacy` at commit
`31aa23f516018f7577f4dcec95142f981142a6f8`, "byte-identical to the legacy source except trailing
double-space Markdown hard-line-breaks stripped." Its 2026-08-10 date records **when the file was
copied back into the tree, not when its claim was true**.

The index those files were restored under is explicit about their standing
(`docs/design/README.md:1-30`):

> **Status:** historical record — not living documentation. […] **Read these as intent, not as fact.**
> […] Do not use these documents to answer "does the system currently do X" — use the issue register
> […] and the current source tree for that. […] Nothing else here was rewritten, re-wrapped, or
> fact-checked against the current codebase.

No commit message in the repository promotes v8g to a public boundary, retires v8d–v8f, or otherwise
explains the claim at `phase8-runtime-operations.md:27`.

**Correction:** `phase8-runtime-operations.md:27` describes pre-restart design intent and must not be
read as a current deployment instruction. `docs/RETIRED_SERVICE_VERSIONS.md` is the live record. Its
substantive claims hold up under re-checking, with two exceptions worth correcting so the next reader
does not inherit them:

- `:45-48` pleads that "a shallow clone doesn't preserve enough history to establish a reliable
  chronology." The repository is not shallow (`git rev-parse --is-shallow-repository` → `false`, 122
  commits). Chronology is still unrecoverable, but for a different reason: v8e, v8f and v8g all arrive
  in a single squashed baseline commit, `03c0f04` ("chore: establish sanitized public OpenWatchlist
  baseline", 2026-07-27). No amount of history depth recovers what a squash discarded.
- `:23-25` describes v8e as having "no idempotency". v8e has no `idempotency.go`, but it has the
  behavior — it hands `IdempotencyDirectory` to the v8d server it embeds
  (`internal/screeningapiv8e/server.go:71`). The file-listing difference is not a behavioral one.

## 3. Topology and the sharing edges

The import graph, verified by grep over actual import statements rather than inferred from package
names:

```text
cmd/screening-api      -> internal/screeningapi                      (main.go:14)
cmd/screening-api-v8d  -> internal/screeningapi -> ...v8d            (main.go:17, phase8d_frontdoor.go:6)
cmd/screening-api-v8e  -> internal/screeningapiv8e -> ...v8d         (main.go:14, server.go:11)
cmd/screening-api-v8f  -> internal/screeningapiv8f                   (main.go:14)
cmd/screening-api-v8g  -> internal/screeningapiv8g                   (main.go:14)
```

Two consequences for the deletion order:

- `internal/screeningapi/phase8d_frontdoor.go` is a pure re-export shim — six type aliases and three
  constructors over `screeningapiv8d` (`:10-30`), with no logic of its own. It must be deleted in the
  same change as `cmd/screening-api-v8d`, or the survivor stops compiling.
- v8e cannot be deleted after v8d. It embeds a v8d `Server` and serves through `delegate.Handler()`
  (`internal/screeningapiv8e/server.go:77-83`), decorating responses with an activation tuple
  (`:145`). Both go together.

Routing genuinely differs across the five, which is worth recording because it was previously assumed
identical:

| Tier | Routing | Shape |
|---|---|---|
| 8B | `internal/screeningapi/http.go:23-54` | hand-rolled `switch` on `request.URL.Path` |
| 8D | `internal/screeningapiv8d/server.go:53-57` | real `http.ServeMux` |
| 8E | `internal/screeningapiv8e/server.go:90-106` | `/readyz` exact, then `strings.HasPrefix(path, "/v1/screenings")`, else delegate |
| 8F | `internal/screeningapiv8f/server.go:68-81` | `switch`, `/v1/screenings` and `/batch` sharing one arm |
| 8G | `internal/screeningapiv8g/server.go:54-67` | `switch`, same shape as 8F |

Only 8E prefix-matches; the other four are exact. All four proxy tiers expose a
`Handler() http.Handler` (`v8d:52`, `v8e:87`, `v8f:65`, `v8g:52`), and the survivor is an
`http.Handler` passed whole to `http.Server` (`cmd/screening-api/main.go:37-39`) — so a wrappable seam
exists everywhere today, contrary to earlier assessment. What does not exist anywhere is a *populated*
one: §11.

## 4. Why `internal/screeningapi` is the survivor

The four candidate selection criteria REL-10 proposes, evaluated:

| Criterion | Result |
|---|---|
| Most recently modified | Inconclusive. `screeningapi` and `v8d` were both last touched by `5ddc03c` (2026-08-10), a mechanical staticcheck sweep under INFRA-2. v8e/f/g are untouched since the `03c0f04` baseline. Lint recency is not authority. |
| Most complete feature set | **No single tier wins.** Each proxy has a capability the others lack (§6). By file count the survivor is largest (10 non-test files vs 7/3/4/3), but file count is not feature coverage. |
| Referenced by current deployment/config | **None of them.** §5. |
| Genuinely none is ahead | **Not the case, on one axis that overrides the rest.** |

That overriding axis: `internal/screeningapi` is the only tier that *terminates* a request. Every
other tier requires an upstream to answer — v8d and v8g via `UpstreamBaseURL`
(`v8d/upstream.go:22-23`, `v8g/server.go:145`), v8f via two (`v8f/server.go:60`), v8e via the v8d
delegate it embeds. Retaining any proxy and deleting `screeningapi` leaves a chain with nothing at the
bottom. The choice is forced by the dependency direction, not preferred on quality.

It is also the only tier with a published contract: `docs/api/screening-api.openapi.yaml`, whose
header states it "was written directly from internal/screeningapi/http.go, types.go, and config.go —
every path, header, status code, and error code below is what the code actually does." And it is the
tier `docs/ARCHITECTURE.md:20` and `internal/integrationtest/integration_test.go:31` both name as
production.

**This is not a synthesis.** Nothing needs porting out of the deleted trees, because the capabilities
are not implemented there (§6). That is the finding that makes REL-10 a deletion rather than a merge,
and it is the single most consequential result of this investigation.

## 5. Caller and reference inventory

`grep -rn "screening-api"` across `scripts/`, `runtime/`, and `.github/` returns **zero matches**.
Specifically:

- **CI**: `.github/workflows/ci.yml:82` runs only `./scripts/ci/run-ci.sh`. That script compiles and
  unit-tests the whole module (`run-ci.sh:29` `go vet ./...`, `:32` `go test -race -count=1 ./...`)
  but never starts a binary as a service. All five are built and tested; none is run.
- **Deployment**: `scripts/deployment/r2-4/` — the only deployment harness in the repo, 16 scripts
  plus a validation/rollback/repair runbook set — never mentions screening-api.
- **Release**: `scripts/release/` (7 scripts) never mentions it.
- **Configs**: all five are examples. `configs/screening-api/example.json:10-12` carries placeholders
  (`catalog_component_REPLACE_ME`, `catalog_version_REPLACE_ME`, an all-zero `package_sha256`). The
  survivor's own `--config` default is `configs/screening-api/local.json`
  (`cmd/screening-api/main.go:33,62`), which **does not exist in the repository**.

Remaining references, all of which are documentation, fixtures, or tests:

| Reference | Kind | Disposition on deletion |
|---|---|---|
| `docs/design/phase8{,d,e,f,g}-*.md` | restored legacy records | Leave. Historical by declaration (§2); rewriting them would falsify an archive. |
| `docs/RETIRED_SERVICE_VERSIONS.md` | live decision record | Replace with a pointer to this ADR (§7). |
| `docs/CMD_TESTING_PATTERN.md` | live testing doc | Prune the v8d–v8g sections. |
| `docs/TEST_DATA.md`, `docs/TEST_COVERAGE.md` | live test docs | Prune v8d–v8g rows. |
| `configs/screening-api/phase8d-example.json`, `configs/scoring-activation/phase8e-example.json`, `configs/activation-promotion/phase8f-example.json`, `configs/screening-ledger/phase8g-example.json` | example configs | Delete `phase8d-example.json`. The other three name state directories still owned by surviving CLIs — see §7. |
| `test/fixtures/screening-api-v8d/`, `test/fixtures/screening-ledger/`, `test/golden/screening-ledger/` | fixtures | `-v8d` deleted with its package; screening-ledger fixtures retained by `cmd/screening-ledger`. |

**Nothing breaks if a variant's endpoint disappears, because no endpoint is exposed today.**

## 6. Capability custody

Each proxy tier's distinguishing capability, and where it actually lives:

| Capability | Tier | Engine package | Own CLI | Depends on a v8* package? |
|---|---|---|---|---|
| Candidate scoring | 8D | `internal/candidatescoring` | `cmd/candidate-score` | no |
| Bounded projections | 8D | `internal/projectionpackage` | `cmd/projection-package` | no |
| Activation-tuple fencing | 8E | `internal/scoringactivation` | `cmd/scoring-activation` | no |
| Promotion / canary / shadow | 8F | `internal/activationpromotion` | `cmd/activation-promotion` | no |
| Durable ledger + Postgres audit | 8G | `internal/screeningledger` | `cmd/screening-ledger` | no |

Verified by import inversion: no engine package imports any `screeningapiv8*` package. The dependency
runs one way only — the servers import the engines. `internal/screeningledger` additionally owns the
Postgres footprint (`db/migrations/008g_screening_ledger.sql`, see ADR-0001:37-41) and is driven by
`cmd/screening-ledger`, not by v8g.

So deleting v8d–v8g removes HTTP packaging around engines that remain fully present, fully tested, and
independently reachable. **With one exception.**

### The exception: scoring has no reachable HTTP path after this change

`internal/screeningapi/phase8c_scoring.go:5-7` carries this doc comment:

```go
// Phase8CCandidateScorer is the typed bridge used by the Phase 8B real-time
// and batch service. Both paths call the same immutable engine, preventing
// route-specific score drift.
```

That is false, and it is the only claim in this investigation that survived into the code rather than
into a document. `Phase8CCandidateScorer` has **zero non-test callers repo-wide**. `Service` has no
scorer field (`internal/screeningapi/service.go:16-21`). `ScreeningResponse` has no score field
(`internal/screeningapi/types.go:108-122`). The substring "score" appears nowhere in `service.go` or
`types.go`. The surviving API returns unscored retrieval candidates.

v8d is therefore the only wired HTTP scoring path in the repository, and this ADR deletes it. §10
records the consequence. **Correcting that doc comment is in scope for the implementation PR**; wiring
the bridge is not (D4).

## 7. Migration and deprecation plan

Staged, not a hard cutover — though "cutover" overstates it, since no traffic moves (§5). The stages
exist to make the precondition and the rollback explicit.

**Stage 0 — precondition (D3).** Obtain operator confirmation that no deployed environment, rollback
runbook, or external integration references v8d–v8g. This is the exact confirmation
`docs/RETIRED_SERVICE_VERSIONS.md:71-77` identified as missing and never obtained. §9's evidence is
necessary but not sufficient: `/var/` is gitignored (`.gitignore:9`) and there is no telemetry in any
tier, so repo evidence cannot rule out a deployment it cannot observe. **If confirmation is not
obtained, this ADR does not authorize deletion.** If it comes back positive for any tier, §10's
sequencing constraint applies.

**Stage 1 — this PR.** Land this ADR. No code deleted.

**Stage 2 — deletion PR.** In one commit, because §3's import edges forbid splitting it:

- delete `cmd/screening-api-v8d`, `-v8e`, `-v8f`, `-v8g`
- delete `internal/screeningapiv8d`, `v8e`, `v8f`, `v8g`
- delete `internal/screeningapi/phase8d_frontdoor.go` (§3 — the survivor will not compile otherwise)
- delete `configs/screening-api/phase8d-example.json` and `test/fixtures/screening-api-v8d/`
- correct the false doc comment at `internal/screeningapi/phase8c_scoring.go:5-7` (§6)
- replace `docs/RETIRED_SERVICE_VERSIONS.md` with a short pointer to this ADR, and add a note at
  `docs/design/phase8-runtime-operations.md`'s topology section recording that it is superseded — or,
  if amending a restored archive is judged unacceptable, record the supersession only in
  `docs/design/README.md`. The archive's integrity claim (§2) argues for the latter.
- prune the v8d–v8g sections of `docs/CMD_TESTING_PATTERN.md`, `docs/TEST_DATA.md`,
  `docs/TEST_COVERAGE.md`

**Config disposition.** `configs/scoring-activation/phase8e-example.json`,
`configs/activation-promotion/phase8f-example.json` and `configs/screening-ledger/phase8g-example.json`
are named for the deleted binaries but point at state directories owned by surviving CLIs
(`cmd/scoring-activation`, `cmd/activation-promotion`, `cmd/screening-ledger`). Do not delete them
blind. Each key that only the deleted server consumed (`listen_address`, `upstream_base_url`,
`current_base_url`, `candidate_base_url`, `idempotency_directory`) should be stripped, and the file
kept for its surviving CLI, or the file deleted only if its CLI has its own example. Deciding this
per-file is deletion-PR work; deleting them wholesale is a silent capability regression of the kind
this ADR exists to prevent.

**Rollback lever.** `git revert` of the deletion commit. This is sufficient here in a way it usually
is not: the change is pure deletion, touches no schema, writes no data, and changes no surviving
endpoint's behavior (§8). There is no state to reconcile on the way back. If a missing capability is
discovered post-deletion, the revert restores byte-identical code, and its tests were green at
deletion time by §9's bar.

## 8. Endpoint and version contract

**Clean replacement. No transitional multi-version serving.**

There is nothing to transition: no deployed instance serves any of the five today (§5), so there is no
client to keep working across a cutover. The surviving binary continues to serve exactly the four
routes it serves now — `/healthz`, `/readyz`, `/v1/screenings`, `/v1/screenings/batch`
(`internal/screeningapi/http.go:23-54`) — with unchanged request and response schemas.

`docs/api/screening-api.openapi.yaml` becomes the single contract, and already documents precisely
those four paths. `APIVersion` stays `screening-api/v0.1.0`
(`internal/screeningapi/types.go:18`); no version bump is warranted, because no surviving behavior
changes.

The deleted tiers' response decorations — v8d's scored candidates, v8e's `activation_tuple`
(`v8e/server.go:145`), v8f's `promotion` block (`v8f/server.go:196,252-263`), v8g's
`X-Screening-Ledger-*` headers (`v8g/server.go:131-137`) — disappear with them. No documented contract
covers any of these; none appears in the OpenAPI spec. They are undocumented decorations on
undeployed endpoints, with the scoring exception carved out in §6 and §10.

## 9. Test strategy — the bar for calling REL-10 closed

ADR-0001 §8 set a "prove it before you trust it" bar, and this ADR holds the same bar — but aimed at
the claim that actually needs proving.

**Why not golden-response differential parity.** The obvious bar would be to capture each tier's HTTP
responses against shared fixtures and assert byte-parity before deletion. That bar is ceremony here.
It would prove that endpoints with no callers, no live config, and no deployment produce the same
bytes as before — while proving nothing about the only thing at risk, which is whether a *capability*
survives the deletion of its wrapper. The proposition to test is custody, not parity.

**The bar: capability-custody proof.** Before the Stage 2 deletion merges, for each of the five
engines in §6:

1. The engine package and its `cmd/` entrypoint are present and untouched by the deletion diff.
2. The engine's own test suite is green after deletion, not merely before.
3. `go build ./...` and `go test -race -count=1 ./...` are clean on the post-deletion tree — which
   `run-ci.sh:29,32` already enforces, so this is a gate that exists rather than one to build.
4. No config, doc, fixture, or script in the post-deletion tree references a deleted binary. A single
   `grep -rn "screening-api-v8"` returning only matches inside `docs/design/` (the declared archive,
   §2) is the check.

Item 2 is the one with teeth: it is what distinguishes "the engine still exists" from "the engine
still works without the server that was exercising it."

**Documented deliberate non-parity.** The deletion PR must state, and this ADR states here, that these
behaviors are removed rather than preserved: scored HTTP responses (§6, §10 — DOM-3), activation-tuple
fencing over HTTP, promotion/canary/shadow routing over HTTP, and ledger-backed durable delivery over
HTTP. In every case the engine remains and the CLI remains; what is removed is the HTTP surface. This
is non-parity by decision, itemized in advance — not discovered afterwards.

**Regrowth gate.** Add `scripts/ci/check_screening_variants.py`, wired into `run-ci.sh` alongside
`check_tenant_binding.py` (`run-ci.sh:15`), failing when a `cmd/screening-api-v8*` or
`internal/screeningapiv8*` path reappears in `git ls-files`. ADR-0001:222-229 is the argument for it:
this debt already grew back once, and the ADR that noticed had to specify a five-way rollout of a
control that should have needed one. A gate makes the sixth variant a CI failure rather than a review
catch.

## 10. Accepted risks and non-goals

### DOM-3 gets materially worse, and that is this ADR's largest cost

This is not a new risk. It is DOM-3 — that the platform's primary screening service returns unscored
results — degrading in severity as a direct consequence of REL-10.

**Before REL-10:** the primary service is unscored (`internal/screeningapi/types.go:108-122` has no
score field; the bridge at `phase8c_scoring.go` has no caller), but a scored HTTP path exists via
`cmd/screening-api-v8d`, which calls `candidatescoring` through
`internal/screeningapiv8d/server.go:163` and returns scored candidates.

**After REL-10:** there is **zero reachable scoring path over HTTP, anywhere in the platform**, until
DOM-3 closes. `internal/candidatescoring` remains fully present and `cmd/candidate-score` still scores
from the command line, so the capability is not lost — but nothing serves it.

DOM-3 is tracked privately (`docs/backlog/README.md`: "Engineering issues for this platform are
tracked privately, not in this directory"), so this ADR cross-references it by ID and does not restate
its contents or status. The `DOM-*` namespace is corroborated by `docs/design/README.md:28`.

**Sequencing.** On all repo-visible evidence (§9's traffic finding below), no caller depends on scored
responses today, so this is a deferrable accepted risk rather than a production regression, and DOM-3
may land after REL-10. **This is conditional on Stage 0.** If operator confirmation establishes that
any real caller consumes v8d's scored responses, then deleting v8d is a production regression, and
**DOM-3 must land before or atomically with the consolidation, not after** — a hard sequencing
constraint, not a preference.

**Re-entry condition.** REL-10 is not closed while `docs/api/screening-api.openapi.yaml` documents an
unscored response and DOM-3 remains open. The fix is small — the engine
(`internal/candidatescoring`), the typed bridge (`internal/screeningapi/phase8c_scoring.go:12-37`),
and a worked reference implementation (`internal/screeningapiv8d/server.go:145-165`) all exist today,
and the bridge's `Score`/`ScoreBatch`/`PolicyReference` surface is already shaped for the job. That
smallness is an argument for prioritizing DOM-3 **immediately after REL-10 lands** — it is not an
argument for absorbing it into the consolidation PR. Wiring a scorer changes
`ScreeningResponse` and therefore the published OpenAPI contract; a response-schema change riding
inside a deletion PR is exactly the kind of unreviewed scope creep an ADR is supposed to prevent
(D4).

### Live-traffic finding for v8d

Checked against the same sources as the consolidation question, with the limits stated rather than
elided:

- **No runtime state exists.** There is no `var/` directory. All four configured idempotency
  directories are absent (`var/screening-api/idempotency`, `var/screening-api-v8d/idempotency` per
  `configs/screening-api/phase8d-example.json:5`, and the v8e/v8f equivalents). A served request
  writes a record (`internal/screeningapiv8d/idempotency.go:42,63-67`), so this tree has served none.
- **That is not conclusive.** `/var/` is gitignored (`.gitignore:9`); its absence in a clone says
  nothing about another host.
- **No telemetry exists to consult.** Zero matches for prometheus/metrics/telemetry/otel/statsd across
  all five packages. No logs anywhere in the tree. There is no instrumentation that could answer this
  question from inside the repository, on any host.
- **The only ledger state is fixture data.** `test/fixtures/screening-ledger/state/head.json` records
  `ledger_id: "screening-api-v8g-example"` at sequence 1 — the example config's own `instance_id`
  (`configs/screening-ledger/phase8g-example.json:6`).
- **v8d could not serve scored responses even if started.** Its upstream is `127.0.0.1:18090`
  (`phase8d-example.json:3`), which is `screeningapi` — whose only config is an example with
  placeholder catalog identifiers and an all-zero package checksum
  (`configs/screening-api/example.json:10-12`), and whose `--config` default points at a nonexistent
  file (`cmd/screening-api/main.go:33`). There is no runnable Phase 8B in this repository for v8d to
  proxy to.

**Finding: no live traffic, on all repo-visible evidence.** The residual uncertainty is exactly what
D3 and Stage 0 exist to close, and it is not closed by this document.

### Other accepted risks

- **The restored design archive keeps a superseded instruction.** If Stage 2 leaves
  `phase8-runtime-operations.md:27` untouched to preserve archive integrity (§7), a reader who finds
  that file without `docs/design/README.md` gets stale guidance. Mitigated by the supersession note in
  the index; not eliminated.
- **Undocumented decorations are removed without deprecation notice.** §8. Accepted because no
  contract documents them and no client consumes them.
- **`cmd/screening-api` is itself undeployed.** This ADR retains a binary with no live config
  (`configs/screening-api/local.json` does not exist). REL-10 does not make the platform served; it
  makes it single-implementation. Producing a runnable config is out of scope and belongs with DOM-3
  or a deployment issue.

## 11. What SEC-1b inherits

SEC-1b — authentication for `alertcaseapi` and `screeningapi` — is blocked today because a control
designed against five diverging codebases must be implemented five times, and ADR-0001:222-229 makes
partial adoption unacceptable. This section states precisely what SEC-1b gets once REL-10 lands.

**Confirmed absent today, across all five (grep for tenant/authenticat/authoriz/bearer/Authorization/
jwt/apikey/reviewauth across all ten directories returns zero matches):** any authentication, any
tenant concept, any authorization. `validateToken`
(`internal/screeningapi/service.go:286-297`) is a lexical charset-and-length check on
`X-Correlation-ID` and `Idempotency-Key` — not authentication, despite the name.

**After REL-10, SEC-1b gets exactly one of each:**

| Seam | Location after REL-10 | Count before |
|---|---|---|
| Request entry point | `Handler.ServeHTTP` (`internal/screeningapi/http.go:21`) | 5 |
| Route table | the `switch` at `http.go:23-54` | 5, in 3 different shapes (§3) |
| Config load | `screeningapi.LoadConfig` (`internal/screeningapi/config.go:14`), called once from `cmd/screening-api/main.go:88` | 5 |
| Idempotency key derivation | `http.go:89-91` | 4 |
| Server construction | `cmd/screening-api/main.go:37-39` | 5 |

**One entry point, one config path, one key-derivation site.** That is what this ADR guarantees, and
it is the specific guarantee SEC-1b's design should rely on.

Three further inheritances SEC-1b should not have to rediscover:

- **The handler is already wrappable.** `main.go:37-39` passes a single `http.Handler` to
  `http.Server`. Auth middleware wraps it without touching the route table — no ServeMux migration is
  a prerequisite, though `http.ServeMux` (as v8d used, `v8d/server.go:53-57`) remains available if
  per-route policy is wanted later.
- **The idempotency key is tenant-blind, and stays that way until SEC-1b supplies a tenant.** The
  record path is derived from endpoint and key only (`http.go:89-91`, `idempotency.go:108-112`). This
  is the surviving instance of the defect ADR-0001 deferred to Class C for
  `screening_idempotency_receipt` (ADR-0001:36-41, :80-84, GHSA-vhj8-986g-vjf4). REL-10 does not fix
  it and does not make it worse; it reduces it from four filesystem stores to one.
- **The chain's removal eliminates a trap SEC-1b would otherwise have hit.** The proxy tiers forward
  only `Content-Type`, `X-Correlation-ID` and `Idempotency-Key` upstream
  (`v8d/upstream.go:31-35`, `v8g/server.go:149-153`) — no `Authorization` header, no credential of any
  kind. Any auth terminating above 8B would have lost the caller's identity before it reached the code
  that needs to bind it. With one tier, the question does not arise.

Per ADR-0001's D3, authenticated tenant provenance remains a hard prerequisite for closing SEC-1;
this ADR supplies the single surface, and SEC-1b supplies the identity.

## Consequences

**Positive.** The repository stops carrying five HTTP front doors for one screening engine. SEC-1b
proceeds against one codebase with one seam, and the five-way rollout ADR-0001:222-229 specified
collapses to one. 2,833 lines of non-test code and 1,722 lines of tests leave the tree, along
with four near-duplicate idempotency stores — `v8d/idempotency.go` and `v8f/idempotency.go` differ
only in package name, identifier export, and error wrapping — which is the concrete form of REL-10's
"a fix in one leaves four unprotected." The record corrections in §2 and §6 stop the next
investigation from re-deriving all of this.

**Negative.** DOM-3 worsens from "primary service unscored" to "no scored HTTP path anywhere" until it
closes (§10) — the real cost of this ADR, and the reason §10 is the longest risk section. Four
capabilities lose their HTTP surface while retaining their engines and CLIs (§6, §9). A restored
design document keeps a superseded instruction unless amended (§7).

**Neutral but worth stating.** REL-10 does not make the platform deployable. All five variants are
undeployed today, the survivor included; consolidation makes the codebase single-implementation, not
running. Anyone reading this ADR as evidence that screening is live in production has misread it —
`configs/screening-api/local.json` still does not exist.
