# ADR-0004: Screening scoring integration

- **Status:** Proposed
- **Date:** 2026-08-11
- **Issue:** DOM-3 (P1)
- **Related:** REL-10 (ADR-0002, accepted), SEC-1b (ADR-0003), SEC-1 (ADR-0001, accepted), DOM-2,
  GHSA-wv2h-hrq2-932p
- **Supersedes:** nothing. Discharges the follow-up ADR-0002 §10 recorded as urgent. Neither
  ADR-0001, ADR-0002, nor ADR-0003 is modified by this one.

## Context

`internal/screeningapi` — the sole screening implementation after REL-10 (`CLAUDE.md:43-45`) —
returns unscored retrieval candidates. A caller gets a list of records the Rust catalog runtime
matched by exact name, prefix, or typed identifier, with no confidence, no evidence, and no
indication of which candidate is worth an analyst's attention first.

ADR-0002 §10 deleted the only HTTP path that did return scored results and stated the consequence in
terms this ADR is written to close: "there is **zero reachable scoring path over HTTP, anywhere in
the platform**, until DOM-3 closes" (`docs/adr/0002-screening-api-consolidation.md:466-467`).

ADR-0002 called the fix small, on the grounds that the engine, the typed bridge, and a worked
reference implementation all existed (`:490-500`). Two of those three hold. This ADR confirms what
survives that claim, corrects the third, and documents two gaps ADR-0002 did not reach — a join key
that nothing in the tree establishes, and an operational precondition that is unfulfilled in exactly
the way ADR-0002's own Stage 0 and ADR-0003's D3 were unfulfilled.

## Decision

Wire `internal/candidatescoring` into `screenAt()` through a **scoring binding held once at
startup**, sourced from `internal/scoringactivation`'s checksum-fenced activation tuple, joining
retrieval to projection on `record_id`. Scored responses become the contract; the unscored response
is replaced outright, not versioned alongside. Scoring is **not optional at runtime**: the service
either starts with a verified binding or does not start.

---

## 1. Scope

**In scope.** Making a scored candidate reachable over HTTP on `POST /v1/screenings` and
`POST /v1/screenings/batch`; the response-schema change that implies; the failure posture when
scoring cannot be performed; the test bar that proves scoring is wired rather than merely compiled.

**Out of scope, named so they are not assumed.**

- **Matching.** `internal/matcherbaseline` stays off the production path (`CLAUDE.md:96`). This ADR
  scores what retrieval already returns; it does not change what retrieval returns.
- **Catalog format.** No change to `normalize_ascii` or the compiled package layout. §8 shows why
  none is needed — that is a finding, not an omission.
- **Route authorization.** ADR-0003 §11 left this to a new issue with an owner-assigned ID. Scoring
  does not touch it.
- **Per-tenant scoring policy.** §7 states this as a non-goal explicitly rather than leaving it as
  an unstated default.
- **Producing a deployable service.** ADR-0002 §10 recorded that `cmd/screening-api` is itself
  undeployed. §10 records that this ADR does not change that.

## 2. Confirming ADR-0002 §6 and §10

ADR-0002 did real investigation here. Each of its findings was re-verified against the post-REL-10,
post-SEC-1b tree rather than transcribed. Three hold; one is closed; one is materially incomplete.

### The engine is intact — holds

`internal/candidatescoring` is fully present and independent: `engine.go`, `policy.go`, `types.go`,
`normalize.go`, with `engine_test.go` and a CLI at `cmd/candidate-score`. Its policy is a real,
loadable artifact (`configs/scoring/candidate-scoring-r1.json`), checksum-addressed on parse
(`internal/candidatescoring/policy.go:29-52`) and re-verified against its own content at engine
construction (`engine.go:20-36`). Nothing about REL-10 touched it.

### The bridge has no caller — holds

`Phase8CCandidateScorer` (`internal/screeningapi/phase8c_scoring.go:8-38`) wraps
`*candidatescoring.Engine` and exposes `Score`, `ScoreBatch`, and `PolicyReference` (`:28-38`). It
still has zero non-test callers. `Service` still has no scorer field
(`internal/screeningapi/service.go:16-21`). `ScreeningResponse` still has no score field
(`internal/screeningapi/types.go:116-130`).

### The false doc comment — closed, no action

ADR-0002 §6 quoted a doc comment claiming "Both paths call the same immutable engine, preventing
route-specific score drift," found it false, and put correcting it in scope for the Stage 2
implementation PR. **That correction landed.** `phase8c_scoring.go:5-7` now reads:

```go
// Phase8CCandidateScorer is a typed bridge to the candidatescoring engine.
// It has no caller in the current screening HTTP path; Service returns
// unscored retrieval candidates. See DOM-3.
```

Verified in the deletion commit itself (`git log -p --follow -- internal/screeningapi/phase8c_scoring.go`,
commit `ae43880`, "REL-10: delete screening-api-v8d through v8g"). This ADR records the item as
discharged so no reader re-opens it. §9 keeps the underlying property — one engine, both routes —
as a *tested* claim rather than a commented one.

### The "worked reference implementation" — does not survive scrutiny

ADR-0002 §10 cited `internal/screeningapiv8d/server.go:145-165` as a worked reference for the
wiring. Recovered from history (`git show ae43880^:internal/screeningapiv8d/server.go`), it is a
worked reference for the wrong thing.

v8d scored against a `default_lineage` block supplied entirely by its own config file
(`configs/screening-api/phase8d-example.json` at `ae43880^`):

```json
"default_lineage": {
  "provider": "ofac-direct",
  "catalog_id": "ofac-production",
  "component_id": "sdn",
  "activation_id": "activation-phase8d-fixture",
  "normalization_profile": "unicode-upper-alnum-space-v1"
}
```

None of those values matched the Phase 8B service v8d proxied. That service serves catalog
`ofac-sdn-direct` under component `catalog_component_ed835720fdb2b3a505927488`
(`test/fixtures/screening-api/config.json`, `test/golden/catalog-registry/registry.json`), compiled
under normalization profile `openwatchlist-runtime-normalization/ascii-v1`
(`test/golden/runtime-mmap/ofac-fixture.info.json:12`).

v8d's startup consistency check compared `config.DefaultLineage.NormalizationProfile` against the
policy's — that is, config against config. The lineage stamped onto every scored response it
produced was a constant that had never been read from, or checked against, the catalog that
actually served the candidates.

This is precisely the failure mode `CLAUDE.md:47-50` names as the dominant bug class in this
repository: a control that looks installed and does nothing. **v8d is cited in this ADR as an
anti-pattern, not as a reference.** §4's binding derives every lineage field from verified artifact
content, and §9 requires a test that fails if it ever stops doing so.

## 3. The engine is reachable; the join is what is missing

ADR-0002 §6 established that no engine package depends on a deleted server. Reachability in the
import sense was never the problem. The problem is that retrieval and scoring describe candidates in
two different vocabularies, and nothing in the tree connects them.

### What retrieval produces

`runtimemmapclient.Candidate` (`internal/runtimemmapclient/types.go:21-28`) carries six fields:

```go
RecordID, EntityType, PrimaryName, MatchKind, MatchedValue, NormalizedQuery
```

`screenAt()` copies these verbatim into its own `Candidate`
(`internal/screeningapi/types.go:82-90`, populated at `service.go:110-117`).

### What scoring consumes

`candidatescoring.Candidate` (`internal/candidatescoring/types.go:72-79`) carries
`CandidateID`, `Names`, `Identifiers`, `Countries`, `DatesOfBirth`, `EntityType`. Three of those —
identifiers, countries, dates of birth — are the corroborating evidence the policy's weights are
built around (`configs/scoring/candidate-scoring-r1.json`: `typed_identifier_exact` 550,
`date_of_birth_exact` 120, `country_exact` 60, plus the negative conflict weights). **Retrieval
supplies none of them.**

### Where they come from: the activation tuple

`internal/scoringactivation` already owns a verified binding of catalog, projection package, and
policy. Its shape was read directly rather than inferred from method names, and it half lines up.

**The field shape lines up exactly.** `LoadActive()` returns `(Snapshot, error)`
(`internal/scoringactivation/manager.go:125-131`). `Snapshot.ProjectionPackage`
(`scoringactivation/types.go:48-52`) is a `projectionpackage.Package`
(`projectionpackage/types.go:73-80`), whose `Projections` is a `ProjectionDocument` whose
`Candidates` field is **literally `[]candidatescoring.Candidate`**
(`projectionpackage/types.go:67-71`). There is no adapter, no projection layer, no field mapping:
the projection package stores exactly the type the engine consumes.

**The key does not line up.** `LookupActiveCandidate` matches on `candidate.CandidateID`
(`manager.go:198-210`) — the projection's `candidate_id`, sourced from `SourceRecord.CandidateID`
in the canonical input (`projectionpackage/types.go:40-48`). The screening service's
`Candidate.CandidateID` is something else entirely: a per-request content digest computed from the
request ID, component, version, and candidate body (`service.go:118-123`). It is not a catalog key
and it is not stable across requests. The only field that can join the two worlds is
`runtimemmapclient.Candidate.RecordID`.

**That join is a new contract, and this ADR creates it.** Nothing in the tree currently establishes
`record_id == candidate_id`. The two fixture families use disjoint vocabularies: the compiled
catalog holds `ofac:sdn:1001`, `ofac:sdn:2002`, `ofac:sdn:3003`
(`test/golden/runtime-mmap/ofac-fixture.owmmap`); the projection package holds `a-tie`,
`candidate-exact-lei`, `candidate-exact-name`, `candidate-weak`, `z-tie`
(`test/fixtures/projection-package/packages/b652a63f…/projections.json`). Stating the join
explicitly — rather than discovering it by writing code that happens to compile — is the point of
this section.

> **Contract.** A projection package bound to catalog C **must** key its candidates by the same
> record identifiers C's compiled runtime returns as `record_id`. A projection whose candidate IDs
> do not cover the catalog's retrievable records is a mis-built artifact, and §6 specifies what a
> miss does at request time rather than letting it pass silently.

### `LookupActiveCandidate` is the wrong entry point

It calls `LoadActive()` internally on every invocation (`manager.go:199`), and `LoadActive` reaches
`validateActivation` (`manager.go:212-240`), which re-reads the projection package from disk via
`projectionpackage.LoadPackage` (`manager.go:216`) and re-verifies its manifest, payload, file, and
package checksums plus the directory's checksum-addressed name (`projectionpackage/package.go:198-274`).
Calling it once per candidate would re-read and re-checksum the entire package N times per request,
then linear-scan it.

§4 therefore holds one `Snapshot` from startup and builds its own index. `LookupActiveCandidate`
stays as the CLI-shaped accessor it is; the screening path does not use it.

## 4. What `screenAt()` changes

### The binding, constructed once

`Service` (`service.go:16-21`) gains one field — a scoring binding, not four loose ones — resolved
at startup in `cmd/screening-api/main.go`'s `load()` (`:96-113`), beside `StartRuntimeManager`
(`:105`) and before the `Service` literal (`:109`). Illustrative shape only:

```go
type scoringBinding struct {
    engine  *screeningapi.Phase8CCandidateScorer   // phase8c_scoring.go:24-26
    lineage candidatescoring.Lineage               // from Snapshot.Activation
    index   map[string]candidatescoring.Candidate  // keyed by record_id (§3)
    policy  candidatescoring.PolicyReference       // phase8c_scoring.go:36-38
}
```

Built from one `scoringactivation.Snapshot`:

- `engine` — `NewPhase8CCandidateScorer` over an engine constructed from `Snapshot.Policy`. The
  existing bridge is used as-is; this ADR adds no parallel wrapper.
- `lineage` — every field from `Snapshot.Activation` (`scoringactivation/types.go:14-21`):
  `Provider`, `CatalogID`, `ComponentID`, `ComponentVersion` from `Activation.Catalog`;
  `ActivationID` from `Activation.ActivationID`; `NormalizationProfile` from
  `Activation.Catalog.NormalizationProfile`. The engine requires all six non-empty
  (`candidatescoring/engine.go:243-247`). **None is config-declared** — that is the §2 correction
  made structural.
- `index` — built once by iterating `Snapshot.ProjectionPackage.Projections.Candidates`, keyed by
  `CandidateID` per §3's join contract. Read-only for the process lifetime.
- `policy` — `PolicyReference()` off the bridge, carried into every response per §5.

`Config` (`types.go:29-49`) gains one path field, `scoring_activation_state_directory`. It follows
ADR-0003's precedent exactly (`:41-48`): resolved relative to the config file in `LoadConfig`, not
validated by `check` — which needs no scoring binding to validate catalog and runtime wiring — and
required by `serve`.

### Where scoring happens in the request flow

Inside `screenAt()` (`service.go:38-134`), scoring sits **after** the entity-type filter loop
(`:103-125`) and **before** the count and status assignment (`:126-131`):

```
validate → load state → resolve list       (:39-49)
  ├─ unavailable → blocked, return          (:61-67)
active pointer + version                    (:68-75)
runtime lookup                              (:76-87)
runtime lineage stamp                       (:88-102)
entity-type filter, candidate IDs           (:103-125)
▶ SCORE HERE  ── project, score, reorder, attach
candidate_count + status                    (:126-131)
screening_id                                (:132)
```

Three reasons for that position. The filter has already run, so the engine is not asked to score
candidates the caller excluded. `response.CandidateCount` and `Status` (`:126-131`) then describe
the scored set rather than the pre-scoring one. And the engine already sorts by score descending
with deterministic tie-breaks (`engine.go:65-76`), so `response.Candidates` can adopt that ordering
directly — the response becomes ranked, which is most of the point of scoring at all.

`screening_id` is computed last (`:132`), over the scored response, so a scored result and an
unscored one over identical inputs get different screening IDs. That is correct: they are different
evidence.

### The subject, and what it provably cannot score

`candidatescoring.Subject` (`candidatescoring/types.go:63-69`) wants names, identifiers, countries,
and dates of birth. `ScreeningRequest` carries a single `Query` (`types.go:51-58`, `:60-67`) — one
value, one kind, an optional identifier type. The mapping is therefore total but narrow:

| `Query.Kind` | `Subject` |
|---|---|
| `name` | `Names: []string{Query.Value}` |
| `identifier` | `Identifiers: []Identifier{{Type: Query.IdentifierType, Value: Query.Value}}` |
| `record_id` | neither; scoring is skipped, see §6 |

`Subject.EntityType` is set only when `Query.TargetEntityTypes` has exactly one element; the field
is singular and any other count has no honest answer. Entity-type vocabulary reconciles without a
translation table — `normalizeEntityType` (`candidatescoring/normalize.go:39-52`) already folds
`individual`→`PERSON` and `organization`→`ORGANIZATION`, covering the two most common values in
`validEntityType` (`service.go:279`).

**The limitation, stated rather than left implicit:** the subject side can never supply a country or
a date of birth, so `country_exact`, `country_conflict`, `date_of_birth_exact`,
`date_of_birth_year`, and `date_of_birth_conflict` **cannot fire from a screening HTTP request**,
however rich the projection package is. Roughly half the policy's weight vocabulary is unreachable
over HTTP after this ADR lands. Scores will be driven by name shape and typed identifier only.

This is a real gap, not a rounding error, and it is deliberately not closed here: adding a subject
block to `ScreeningRequest` is a second contract change, and riding it inside the response change is
the scope creep ADR-0002 §10 objected to on exactly these grounds. It is recorded in §11 as its own
follow-up with its own decision to make.

### Batch

`ScreenBatch` (`service.go:136-169`) already loops over `screenAt` (`:151`). It keeps doing so.
`ScoreBatch` (`phase8c_scoring.go:32-34`) is deliberately **not** called: routing batch through a
second engine entry point is how single and batch acquire divergent behavior, which is the drift
v8d's deleted doc comment falsely claimed to prevent. One code path, asserted by test (§9.5).

### Startup, fail-closed

`serve` refuses to start unless, in order: the activation state directory loads and validates
(`LoadActive`, which enforces the whole tuple — `manager.go:212-240`, `validateTuple` at `:243-268`);
and the runtime package's normalization profile equals the policy's. See §6 for why there is no flag
to make this optional.

## 5. The OpenAPI contract

`docs/api/screening-api.openapi.yaml` currently documents an unscored response — `Candidate` at
`:283-292` has no score field, and `ScreeningResponse` at `:327-349` has no policy block.

### Clean replacement, not a versioned transition

**This is a breaking change to a contract nothing calls, and it is treated as a clean replacement.**
ADR-0002 §8 reached this conclusion for the same endpoints on the same evidence, and that evidence
has not changed: no deployed instance serves this API, `configs/screening-api/local.json` does not
exist, and `cmd/screening-api/main.go:33` defaults `--config` to that nonexistent path. There is no
client to keep working across a cutover, so there is no transition to stage. No `v2` path, no
content negotiation, no dual-shape response.

Where this ADR **departs** from ADR-0002 §8: that ADR held `APIVersion` at `screening-api/v0.1.0`
(`types.go:18`) because no surviving behavior changed. Here it does. Both
`ResponseSchemaVersion` (`types.go:13`, `screening-response/v1alpha1`) and `APIVersion` bump. A
consumer that pins a schema version must fail loudly against a response whose candidate shape
changed, and the version string is the only mechanism that makes that possible.

### The shape

`Candidate` gains, drawn field-for-field from `candidatescoring.CandidateResult`
(`candidatescoring/types.go:144-155`) so the HTTP contract and the engine's output do not drift:

| Field | Type | Presence |
|---|---|---|
| `score` | integer | always, when `status` is `matched` |
| `strength_band` | string | always, when `status` is `matched` |
| `exact_identifier_matched` | boolean | always, when `status` is `matched` |
| `exact_name_matched` | boolean | always, when `status` is `matched` |
| `reason_codes` | array of string | always (may be empty) |
| `components` | array of `ScoreComponent` | always (may be empty) |
| `evidence` | array of `EvidenceItem` | always (may be empty), bounded by `max_evidence_items` |

`ScoreComponent` (`component`, `points`, `reason_code`) and `EvidenceItem` (`kind`, `outcome`,
`subject_value`, `candidate_value`, `points`, `reason_code`) become named schemas, mirroring
`candidatescoring/types.go:126-140`.

`ScreeningResponse` gains a top-level `policy` object mirroring `candidatescoring.PolicyReference`
(`:166-171`): `policy_id`, `policy_version`, `policy_sha256`, `normalization_profile`. A scored
response that cannot say which policy produced it is not audit evidence, and `policy_sha256` is what
makes a score replayable against immutable content.

**`score` is never `omitempty`.** In Go terms the field is a plain `int` on a struct that is only
populated on the scored path. A caller reading `score` and finding it absent cannot distinguish "not
scored" from "scored zero," and in a sanctions platform that is the difference between "no evidence
of a match" and "a control silently did not run." Absence is not an acceptable encoding of either.
Where scoring did not happen, the response says so through `status` and `review_blockers` (§6), in
the response body, loudly.

### Noted, not fixed

The spec's `RuntimeLineage` (`:294-310`) already omits three fields present in Go —
`catalog_mode`, `package_sha256`, `runtime_record_count` (`types.go:92-106`). Pre-existing drift,
unrelated to DOM-3, recorded here because this ADR touched the neighbouring schema and a future
reader deserves to know it was seen and left alone rather than missed.

## 6. Failure posture

The requested tradeoff, decided rather than deferred. **Recommendation: fail closed at startup, and
at request time distinguish a data gap from a defect from an unavailability — never degrade silently
to an unscored 200.**

### Why not "degrade to unscored with a flag"

It is the more available design, and it is wrong here. A response carrying candidates but no scores,
distinguished only by a flag, is indistinguishable at a glance from a working response — and the
consumer of a sanctions screening result is frequently an analyst queue that sorts by score. A
degraded response silently reorders itself into arbitrary order and keeps looking healthy. That is
`CLAUDE.md:47-50`'s silent-absence class, delivered by design rather than by accident.

The alternative is not "fail everything." The repository already has vocabulary for "we have a
result, and a human must adjudicate it": `StatusBlocked` (`types.go:113`) plus `ReviewBlockers`
(`types.go:129`), used today when list resolution is unavailable (`service.go:61-67`). A blocked
response preserves the retrieval evidence — which remains regulator-meaningful — while making it
impossible to mistake for a scored one.

### The matrix

| Condition | Behavior | Reasoning |
|---|---|---|
| Activation state directory missing, unloadable, or failing `validateActivation` at startup | `serve` exits non-zero | Matches ADR-0003 D4's hard cutover for auth paths (`docs/adr/0003-authenticated-tenant-provenance.md:477-529`). A service that starts without scoring is a service that serves unscored results forever without anyone noticing. |
| Runtime package profile ≠ policy profile at startup | `serve` exits non-zero | The check that v8d only pretended to perform (§2). **This is the check that fails against today's fixtures** — the existing tuple loads cleanly and the row above does not fire. See §10. |
| Retrieved `record_id` absent from the projection index | HTTP 200, `status: "blocked"`, blocker `candidate_projection_unavailable` | A data gap in an artifact, not a service fault. The retrieval hit is real evidence and must not be discarded; the blocker names exactly which candidate could not be scored. |
| `Query.Kind` is `record_id` | HTTP 200, `status: "blocked"`, blocker `scoring_subject_unavailable` | §4: a record-ID lookup has no subject to compare against. Returning it with an unpopulated score would be the silent degradation this section rejects. |
| `engine.Score` returns an error | HTTP 500 | The engine validates the request we constructed (`engine.go:225-252`). An error means *our* request was malformed — a defect in this service. Dressing a defect as a blocked 200 hides it. |
| Active catalog pointer moved off the snapshot's binding mid-request | HTTP 503, `ErrRuntimeUnavailable` | Matches the existing posture for the same class of race (`service.go:68-75`). |

### No `scoring_enabled` flag

Deliberate, and worth stating because the flag is the obvious accommodation for §10's unfulfilled
precondition. A boolean that turns a regulatory control off is indistinguishable, at runtime and in
a config review, from a control that is broken. ADR-0003 reached the same conclusion for
authentication and said so in `Config`'s own doc comment ("hard cutover, no auth_required flag to
make them optional there", `types.go:41-45`). Scoring gets the same treatment: the binding is
configured and verified, or the process does not run.

The honest consequence is that until §10's precondition is met, `serve` cannot start against the
current fixtures. §10 owns that rather than hiding it behind a flag.

## 7. Interaction with SEC-1b

ADR-0003 landed authenticated, tenant-bound requests on both API surfaces. Checked directly rather
than assumed: **ADR-0003 mentions neither DOM-3 nor scoring anywhere in its 679 lines.** The
interaction was therefore analyzed here rather than inherited.

**Scoring has no tenant dimension of its own.** `screenAt()` takes no tenant parameter and never
has; tenant is resolved in the handler (`http.go:91-96`) and flows only to the idempotency store
(`:98`, `:156`). Nothing in §4's binding is tenant-derived: the policy is a single
checksum-addressed file, and the projection package is compiled from catalog content. Both are
properties of the catalog being screened against, not of who is asking.

**Per-tenant scoring policy is an explicit non-goal**, stated rather than left as the unexamined
default. It is a coherent thing to want — different institutions calibrate risk appetite
differently. It is not a thing to add by extending §4's binding to a map keyed by tenant, because
scoring policy is part of the activation tuple's identity (`scoringactivation/types.go:31-37`
binds policy ID, version, SHA256, and normalization profile into the activation record). Per-tenant
policy means per-tenant activations, which is an activation-lifecycle change, not a wiring change.
§11 records it as its own issue.

**One real coupling, and it is not orthogonal.** Scored responses are cached and replayed under the
tenant-scoped idempotency key ADR-0003 §7 introduced (`:445-475`, `http.go:98`, `:156`). A replayed
response returns bytes produced under whatever policy was active when the original request ran. If
the activation pointer moves, replay silently serves scores from the previous policy. This ADR does
not invalidate the idempotency store on activation change — that would be a data-lifecycle decision
of its own — but §5's `policy_sha256` in the response body is what makes the divergence
**detectable** by an auditor comparing two replays. Recording the mechanism is the point; a reader
should not have to rediscover that replay and activation can disagree.

## 8. DOM-2: the corroborating-evidence gap needs no catalog format change

DOM-2 concerns the absence of corroborating evidence — identifiers, dates of birth, jurisdiction —
in match adjudication. The natural assumption is that closing it requires the compiled catalog to
carry those attributes, and therefore a format change.

**It does not, and the evidence is in the tree.** Corroborating attributes already live in a
*separate* checksum-addressed artifact: `projectionpackage.SourceRecord`
(`internal/projectionpackage/types.go:40-48`) carries `Identifiers`, `Countries`, `DatesOfBirth`,
and `EntityType`, compiled into a `ProjectionDocument` (`:67-71`) whose payload is bound to one
exact catalog package by SHA256 through the manifest (`:51-64`) and enforced by `validateTuple`
(`scoringactivation/manager.go:243-268`). The mmap catalog supplies retrieval keys; the projection
package supplies scoring attributes; the activation tuple proves they describe the same catalog.

Consequently, closing the corroborating-evidence gap over HTTP requires **no `PACKAGE_SCHEMA_VERSION`
bump, no full catalog recompile, and no re-qualification of every runtime binding**. `CLAUDE.md:52-56`'s
rule 6 is not engaged by this ADR. The one Go-side change §10 needs — surfacing
`normalization_profile` on `runtimemmapclient.PackageInfo` (`runtimemmapclient/types.go:10-19`) — is
additive to a Go struct and reads a value the mmap header already stores
(`runtime/catalog-mmap/src/format.rs:462`); it changes no on-disk layout.

This is the same class of finding as ADR-0002 §3.1's "not a synthesis" discovery: an assumed
architectural obstacle that dissolves on inspection, worth writing down because the assumption is
more expensive than the fact.

**Stated limit.** DOM-2's original framing could not be verified from this repository.
`docs/backlog/issue-register.md` is deliberately excluded from version control (`.gitignore:24-28`),
and a repo-wide grep for `DOM-2` returns zero matches. This section therefore cross-references DOM-2
by ID and asserts only the technical finding, which stands on repo evidence alone — exactly the
posture ADR-0002 §10 took toward DOM-3. Whether this closes DOM-2, narrows it, or merely corrects
its framing is a judgment for the register's owner (§11).

## 9. Test strategy — the bar for calling DOM-3 closed

The bar is **a real end-to-end HTTP request that returns a populated score**. Not that the bridge
compiles; not that the engine is unit-tested — it already is
(`internal/candidatescoring/engine_test.go`). DOM-3 is a wiring bug, so only an exercised wire
closes it.

1. **Scored request over HTTP.** Authenticated `POST /v1/screenings` through
   `NewAuthenticatedHandler`, following the existing pattern in `service_test.go`
   (`TestHandlerIdempotencyReplayAndConflict` issues a token and sets `Authorization: Bearer`).
   Asserts, on the decoded JSON body: `candidates[0].score > 0`, a non-empty `strength_band`, a
   non-empty `reason_codes`, and `policy.policy_sha256` equal to the loaded policy's digest.

2. **A test that fails before the change.** Required by `CLAUDE.md:47-50`, and the before-state is
   recorded here so a reviewer can check it: `ScreeningResponse` today has no score field
   (`types.go:116-130`), so assertion 1 does not compile against the current struct, and against
   the current *JSON* the field is absent. The failing-first artifact is the JSON-level assertion —
   it must be shown red on the pre-change tree.

3. **Projection miss is loud.** A retrieved `record_id` absent from the index yields HTTP 200 with
   `status: "blocked"` and blocker `candidate_projection_unavailable` — explicitly *not* a 200 with
   a zero or absent score. This is the test that would catch §6's posture silently regressing to
   degradation.

4. **The profile check reads the runtime, not the config.** A policy whose `normalization_profile`
   differs from the runtime package header makes startup fail. The assertion must be that the value
   compared came from `PackageInfo.NormalizationProfile` — construct the case so a config-declared
   value would pass and the real header fails. This is the regression test for §2's v8d
   anti-pattern; without it, the same bug reappears wearing different names.

5. **Single/batch parity.** The same subject through `/v1/screenings` and `/v1/screenings/batch`
   produces identical scores, bands, and reason codes. This makes the property v8d's deleted doc
   comment merely *asserted* into one that is *proven*.

6. **Lineage completeness.** Every field of the request lineage traces to `Snapshot.Activation`
   content; no scored response carries a lineage value that appears only in a config file.

7. **`-race` on the shared binding.** Concurrent requests share one read-only snapshot, engine, and
   index. `CLAUDE.md:47-50` requires a `-race` test for concurrency claims, and "read-only after
   startup" is a concurrency claim.

## 10. Accepted risks and unfulfilled preconditions

### The activated tuple that exists is not bound to a catalog this service serves

This is the operational precondition DOM-3 inherits, and it is unfulfilled in the same way
ADR-0002's Stage 0 and ADR-0003's D3 were. Checked by execution, not inspection, and stated
precisely because the obvious summary — "the fixture is broken" — is wrong:

**An activated tuple exists and it loads cleanly.** `test/fixtures/scoring-activation/state/active.json`
is a well-formed, fully populated activation record: it declares a complete catalog descriptor
inline, a projection binding, and a policy binding, with `unicode-upper-alnum-space-v1` consistently
in both its `catalog` and `policy` sections. Verified by running it, not by reading it:

```
$ go run ./cmd/scoring-activation status --state-dir test/fixtures/scoring-activation/state
{"activation_id":"activation-phase8e-fixture", ... ,"status":"ok"}    # exit 0
```

That path is `LoadActive` → `validateActivation` → `validateTuple`
(`scoringactivation/manager.go:125-131`, `:212-240`, `:243-268`), so every checksum in the tuple is
verified. Two of its three artifacts are genuinely real:

- **The projection package is real.** `test/fixtures/projection-package/packages/b652a63f…` carries
  all four required files, its `manifest.json` and `projections.json` digests match `FILES.sha256`,
  `PACKAGE.sha256` matches the digest of `FILES.sha256`, the directory is correctly
  checksum-addressed, and `projections.json` holds five real projections with names, identifiers,
  countries, and entity types.
- **The policy is real.** `configs/scoring/candidate-scoring-r1.json` is a complete policy — twelve
  weights, three ordered thresholds — whose canonical digest `b71fadc6…` matches the tuple's
  declaration.

**Exactly one artifact in the chain is a placeholder, and it is the catalog.** The tuple's
`catalog.catalog_package_path` resolves to `test/fixtures/projection-package/catalog-fixture.mmap`,
which is **41 bytes containing the literal text `openwatchlist-phase8e-catalog-fixture-v1`**. It is
not a compiled catalog and not in the `OWMMAP01` format the real runtime packages use
(`test/golden/runtime-mmap/ofac-fixture.owmmap`). Its SHA256 `e872179e…` does genuinely match the
declared `catalog_package_sha256`, which is exactly why the tuple validates:
`ValidateCatalogPackageFile` (`projectionpackage/package.go:311-320`) verifies a digest and nothing
else, so a stub whose digest matches its descriptor is indistinguishable from a catalog.

**Finding: the tuple is valid; it is simply not about a catalog `cmd/screening-api` can serve.**
Three independent reasons, none of them a defect in the activation record:

1. **The catalog is not loadable.** Its catalog package is the 41-byte stub above. There is no
   compiled catalog for the Rust runtime to serve, so this tuple's catalog cannot be pointed at
   `cmd/screening-api` at all.
2. **Different catalog, different profile.** The tuple describes `ofac-direct` / `ofac-production` /
   `sdn` at `unicode-upper-alnum-space-v1`. The screening API's runtime binding serves
   `ofac-sdn-direct` under component `catalog_component_ed835720fdb2b3a505927488` at
   `openwatchlist-runtime-normalization/ascii-v1` (`test/fixtures/screening-api/config.json`,
   `test/golden/runtime-mmap/ofac-fixture.info.json:12`).
3. **No candidate coverage.** Its five candidate IDs (`a-tie`, `candidate-exact-lei`,
   `candidate-exact-name`, `candidate-weak`, `z-tie`) are scoring unit-test names. §3's join would
   miss on every one of the served catalog's records (`ofac:sdn:1001` / `2002` / `3003`) even if the
   profiles agreed.

Corollary, stated because it is easy to misread: **the check that fails at startup is §4's
runtime-profile equality check, not `LoadActive`.** Loading this tuple succeeds. Comparing its
policy profile against the runtime package the screening API actually serves is what fails. Pairing
this policy with the screening catalog's descriptor would additionally fail `validateTuple`'s
policy/descriptor profile check (`manager.go:264-266`) and `validateRequest`'s lineage/policy check
(`candidatescoring/engine.go:248-250`) — but neither of those rejects the fixture as it stands
today.

The tuple's remaining property is that nothing consumes it: no Go code reads that state directory;
the only references are `configs/scoring-activation/phase8e-example.json:2` and
`configs/activation-promotion/phase8f-example.json:2`, both example configs for CLIs.

**What the implementation PR must therefore produce**, or DOM-3 lands as wiring with nothing to
exercise it:

1. A catalog descriptor for the **real** screening runtime package —
   `test/golden/runtime-mmap/ofac-fixture.owmmap`, which unlike `catalog-fixture.mmap` is an actual
   compiled 1552-byte `OWMMAP01` catalog — declaring profile
   `openwatchlist-runtime-normalization/ascii-v1`.
2. A canonical projection input and compiled projection package (via `cmd/projection-package`)
   derived from that catalog, keyed by `ofac:sdn:1001` / `2002` / `3003` per §3's join contract.
3. A scoring policy declaring `openwatchlist-runtime-normalization/ascii-v1`. This is a new config
   file, not a modification of `candidate-scoring-r1.json`, which other tests pin
   (`cmd/candidate-score/main_test.go:53`, `cmd/scoring-activation/main_test.go:55`) and which the
   existing tuple's binding checksums.
4. An activation record binding the three, produced by `cmd/scoring-activation activate`.
5. `normalization_profile` surfaced on `runtimemmapclient.PackageInfo` (§8), so §9.4's check is real.

None of these requires a Rust change (§8). All are additive artifacts, and none modifies the
existing Phase 8E fixture tuple, which stays valid for the tests that already depend on it.

**This ADR does not authorize skipping them.** If the implementation PR cannot produce a working
tuple, the correct outcome is that §9's bar does not pass and DOM-3 stays open — not a
`scoring_enabled` flag (§6), and not a stub catalog standing in for a compiled one.

### Other accepted risks

- **Half the policy vocabulary is unreachable over HTTP.** §4: country and date-of-birth weights
  cannot fire, because the request has no subject block. Accepted for this ADR; §11 owns the fix.
- **The screening path gains a dependency on `internal/scoringactivation`.** ADR-0002 §6 catalogued
  that package as an independent engine with its own CLI. It stays that; it now also has a library
  consumer. The alternative — re-implementing the tuple verification `validateTuple` already
  performs — is worse, and hand-rolled checksum verification in a second place is how the two
  drift.
- **`cmd/screening-api` remains undeployed.** ADR-0002 §10 recorded this and it is unchanged.
  `configs/screening-api/local.json` still does not exist. This ADR makes the platform *capable* of
  serving scored results; it does not make it serve anything. Reading this ADR as evidence that
  scored screening is live in production is a misreading, for the same reason ADR-0002 and ADR-0003
  both had to say so.
- **Scored replay can disagree with the active policy.** §7. Detectable via `policy_sha256`, not
  prevented.

## 11. Follow-ups

None of these is edited by this ADR or its implementation PR. They are written down so the
conditions are recorded rather than remembered.

**GHSA-wv2h-hrq2-932p** — assess after the implementation PR merges. Scored responses do not change
the advisory's authentication residuals, but they do change what an authenticated caller receives,
and §7's replay/activation divergence is a new detail its residual list should account for. **Do not
close on this PR.**

**`docs/backlog/issue-register.md`** — deliberately excluded from version control
(`.gitignore:24-28`), so this is a note to its owner rather than a change:

- **DOM-3** closes when §9's bar passes end to end, *including* §10's artifacts. Wiring that cannot
  be exercised does not close it.
- **DOM-2** — §8 corrects the assumption that a Rust catalog format change is required. Whether that
  narrows DOM-2, closes part of it, or only re-scopes it is the owner's call; this ADR asserts the
  technical finding, not the issue's status.
- **REL-10 / ADR-0002's re-entry condition** — "REL-10 is not closed while
  `docs/api/screening-api.openapi.yaml` documents an unscored response and DOM-3 remains open"
  (`docs/adr/0002-screening-api-consolidation.md:490-500`) — is satisfied when §5 lands.
- **A new issue for subject-side corroborating attributes.** Scope: an optional `subject` block on
  `ScreeningRequest` carrying countries, dates of birth, and additional identifiers, unlocking the
  five policy weights §4 shows are currently unreachable. Additive and backward-compatible, but a
  request-schema change deserving its own decision.
- **A new issue for per-tenant scoring policy**, if wanted. §7: it is an activation-lifecycle
  change, not a wiring change.

## Consequences

**Positive.** The platform's primary screening service returns scored, ranked, evidence-bearing
candidates over HTTP for the first time since REL-10 — and, given §2's finding about v8d's fabricated
lineage, arguably for the first time with lineage that means anything. `internal/candidatescoring`
stops being a fully-tested engine with no reachable caller. The response carries its own policy
checksum, so a score is replayable against immutable content. Single and batch demonstrably share
one engine, as a tested property rather than a comment. And §8 removes a believed blocker from
DOM-2's path at no cost.

**Negative.** The response contract breaks, deliberately and without deprecation, on the reasoning
that there is nothing to deprecate. `serve` acquires a new way to refuse to start, and until §10's
artifacts exist it will refuse to start against the current fixtures — a real cost, accepted in
preference to a flag that would let scoring be silently off. The screening path depends on a third
engine package. And roughly half the scoring policy's weights remain unreachable over HTTP, which is
a limitation a reader could easily mistake for a bug if §4 did not name it.

**Neutral but worth stating.** This ADR does not make the screening API deployed or deployable, does
not change what retrieval matches, and does not make `internal/matcherbaseline` live. It closes the
gap between a retrieval hit and a scored candidate. Every other gap ADR-0002 and ADR-0003 recorded
is still exactly where they left it.
