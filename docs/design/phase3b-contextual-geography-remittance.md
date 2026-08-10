# Phase 3B — Contextual geography and remittance matching

Phase 3B completes the deterministic Phase 3 matcher baseline for the ISO 20022 routes that cannot be handled safely by whole-field exact or fuzzy-name comparison alone:

- `jurisdiction_policy` for governed country and embargo-style policy matching; and
- `contextual_phrase_window` for names, aliases, vessels, and jurisdictions embedded in remittance narrative.

The implementation remains deterministic. It does not make a compliance disposition, invoke an LLM, or infer sanctions policy from raw country names.

## Provider composition

`ofac-context` composes three independently governed inputs:

1. the accepted `.owpcat` direct-list runtime package;
2. the Phase 3A checksum-protected name matcher profile set; and
3. checksum-protected context and jurisdiction-policy sets.

The runtime package remains the active catalog generation. Context profile and policy checksums are carried in candidate evidence and candidate identity so a replay can prove the exact non-catalog configuration used.

## Jurisdiction policy boundary

OFAC direct-list records do not by themselves constitute a complete embargo-country policy. Phase 3B therefore requires an explicit jurisdiction policy artifact rather than hard-coding a country list into the matcher.

A policy entry contains canonical alpha-2/alpha-3 codes, a canonical name, aliases, status, programs, and source metadata. The reference repository ships only a clearly labeled synthetic fixture. Deployments must supply a reviewed and versioned institution-specific or authority-derived policy set.

Country matching is exact after deterministic folding. Substring matching is prohibited. `CU` and `CUBA` can resolve to the same policy entry; `SCUBA` cannot.

## Remittance phrase windows

Narrative matching uses whole folded tokens. A candidate phrase may be:

- a contiguous phrase; or
- an ordered phrase within a bounded number of extra tokens.

The score is integer basis points derived from:

- boundary-safe phrase match;
- window compactness; and
- source quality for primary name, alias, transliteration, or jurisdiction policy.

Single-token direct-list names must meet a configurable minimum length. Jurisdiction names and codes remain boundary-safe but are not subject to the direct-list single-token length gate.

## Denial context

Configured denial markers are evaluated in a bounded token window around the matched phrase. A strong phrase such as `JORDAN EXAMPLE` inside `NO BUSINESS RELATIONSHIP WITH JORDAN EXAMPLE` is not returned as a candidate. It is emitted as a `narrative_denial_context` diagnostic with:

- the matched source record;
- the phrase span;
- the surrounding token evidence;
- detected denial markers;
- preconfigured penalty and final score; and
- source assertions.

This is evidence for the later false-positive classifier. Phase 3B does not auto-release the alert.

## Context evidence contract

`matcher-context-evidence/v1alpha1` is an optional extension of the existing matcher feature evidence. It records:

- folded query and matched tokens;
- token-window start, end, and text;
- detected denial markers; and
- jurisdiction policy-set and entry identity where applicable.

Legacy exact and Phase 3A outputs omit this extension and remain byte-stable.

## CLI

```bash
go run ./cmd/matcher-run \
  --provider ofac-context \
  --catalog test/golden/ofac/ofac-sdn-fixture.runtime.owpcat \
  --matcher-profiles configs/matcher-profiles/ofac-name-baseline-r1.json \
  --context-profiles configs/matcher-profiles/ofac-context-baseline-r1.json \
  --jurisdiction-policy test/fixtures/matcher-context/jurisdiction-policy-synthetic-r1.json \
  --input requests \
  --output results \
  test/golden/matcher-context/pacs008-contextual.matcher-requests.json
```

The jurisdiction fixture is synthetic and must not be treated as a current production embargo list.

## Acceptance behavior

The regression fixture proves:

- `CU` matches the governed `CUBA` policy entry;
- `CUBA` in remittance matches as a jurisdiction phrase;
- `SCUBA` does not match `CUBA`;
- `Acme Imports LLC` is found as a primary-name phrase;
- `MV EXAMPLE` is found as a vessel alias;
- denial language suppresses `Jordan Example` into a diagnostic;
- name fuzzy matching and exact identifier/address routes remain available through the composite provider; and
- request-batch and replay execution are byte-identical.
