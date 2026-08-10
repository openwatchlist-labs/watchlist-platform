# Homelab real-source binding candidate and review gate

This gate binds each of the 35 false-positive archetypes to a real record from the finalized OFAC Advanced XML snapshot and to an exact OpenSanctions `us_ofac_sdn` entity from the same frozen source pair.

## Candidate quality boundary

Legacy `openwatchlist.homelab.binding-candidates.v1` packs are not review-eligible. The accepted generator emits `openwatchlist.homelab.binding-candidates.v2` and must pass the local candidate auditor before any review command runs.

A v2 candidate must:

- satisfy hard archetype-specific eligibility;
- use an exact, unambiguous OFAC UID crosswalk;
- keep official OFAC and OpenSanctions evidence source-separated;
- retain typed identifiers, programs, dates, countries, locations and gender;
- name the exact real-source collision feature;
- include a synthetic collision seed without inventing watchlist data;
- disclose score components, quality rank and tie-group size;
- use an immutable `candidate_id` as the selection key.

Display order is advisory. A reviewer must never select by rank alone, especially within a tie group.

## Safety and integrity rules

- The generator emits bounded candidates only. It never accepts a candidate.
- OFAC records are addressed by `DistinctParty@FixedRef`.
- OpenSanctions crosswalks must be exact source identifiers, normally `referents=ofac-<FixedRef>` or an exact source record property.
- Ambiguous exact crosswalks block candidate quality.
- Official OFAC projections and exact OpenSanctions NDJSON lines are independently SHA-256 hashed.
- Names, aliases, programs, dates, countries, locations and identifiers are copied from frozen sources; no watchlist identity data may be invented.
- A named reviewer and written rationale are required for every selection.
- Selected entries remain `reviewed_pending_set`, which the planner treats as unbound.
- Only explicit all-35 finalization changes entries to `bound`.
- The process provides no regulatory disposition.

## Workflow

1. Stage the v2 generator to OptiPlex-2 with `h1-stage.sh`.
2. Run `h1-generate-binding-candidates.sh`.
3. Confirm the output says `quality_gate=review_eligible` and inspect the candidate audit.
4. Review the v2 Markdown workbook and use `h1-binding-review.sh show fp-NNN`.
5. Select by candidate ID, not rank:

   ```bash
   ./scripts/homelab/h1-binding-review.sh select fp-001 ofac-123__provider-id \
     --reviewer "Reviewer Name" \
     --rationale "Concrete source-supported rationale of at least forty characters."
   ```

6. Check progress with `h1-binding-review.sh status`.
7. After all 35 are reviewed, run `h1-binding-review.sh finalize --finalizer "Reviewer Name"`.
8. Regenerate the execution plan. All 315 executions become eligible together.

A low or absent candidate count requires a revised real-record selection rule or a blocked archetype. It must never be filled with fabricated watchlist data.
