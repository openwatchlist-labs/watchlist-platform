# H1 r1.13.11 complete-v2 binding rematerialization and planner closure

## Purpose

H1 r1.13.11 repairs the promoted `real-ofac-bindings.v1.json` representation after the governed r1.13 selection and acceptance lifecycle. The accepted candidate identities are unchanged. The repair completes each bound row with the immutable v2 candidate and review evidence required by `h1-binding-review.py`.

The repair also replaces the planner's historical v1-only candidate discovery with governed-v2 resolution and removes the unconditional message claiming that executions remain unbound when the generated plan reports zero blocked executions.

## Pinned live artifacts

- Candidate set: `binding_candidates_v2_1bc7a328177b167ffd77_20260722T171954Z`
- Candidate pack SHA-256: `d042921d1e28dd91da86078c221d7ccda585f837f37c5c20cb72cdc896694cf9`
- Governed state SHA-256: `7312b82c8adde4773568e9567a758d0dcc430f8bf66033492c5e42ff6bff0425`
- Pre-repair promoted binding SHA-256: `b53468614297becd0aaf43f33255177aca3df64a5e0b967b2913a3b119d77beb`
- Complete-v2 promoted binding SHA-256: `879ea3221325ab66d2e94cd236119c526d1a5753420aad1e336bbf28c0b81cb1`
- Governed selection digest: `97ef55525f7c4f11c5bac6545661aaad2ae68a252c16cd0940ac985a8c8642aa`

## Binding fields completed

Each of the 35 rows is reconstructed from its governed `candidate_snapshot` and the pinned candidate pack. This includes:

- OFAC source record ID, entity type, record projection hash, official aliases, and typed evidence;
- OpenSanctions entity schema, OFAC source crosswalk ID, entity hash, names, and typed evidence;
- candidate set and candidate ID;
- candidate evidence and quality-gate hashes;
- selected exact mechanic feature and mechanic-evidence hash;
- governed reviewer, rationale, lower-rank rejection, and selection digest lineage.

## Atomic gates

Before replacing repository files, the installer requires the proposed workfile to pass:

- `Bound: 35`
- `Validation errors: 0`
- `Executions: 315`
- `Ready: 315`
- `Blocked: 0`

After replacement, the same gates are run again without environment overrides. Any failure restores the previous promoted binding, planner, and installed r1.13.11 files.

## Governance preservation

The installer does not rewrite:

- governed selections;
- complete-set review;
- governed acceptance state;
- the pinned candidate pack;
- original acceptance evidence.

A separate checksummed rematerialization evidence directory records before/proposed/after files, planner before/after files, status and planner logs, and immutable-artifact verification.
