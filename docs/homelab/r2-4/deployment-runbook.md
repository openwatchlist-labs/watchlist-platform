# R2.4 deployment runbook

## Public harness

The sanitized reference harness is under
`scripts/deployment/r2-4/harness/`. Its committed policy is intentionally
non-operational and points only to `.example.invalid` hosts.

Create an environment-specific policy outside the repository:

```bash
cp scripts/deployment/r2-4/harness/config/policy.example.json \
  "$HOME/.config/openwatchlist/r2-4-policy.json"
chmod 600 "$HOME/.config/openwatchlist/r2-4-policy.json"
export R183_POLICY_OVERRIDE="$HOME/.config/openwatchlist/r2-4-policy.json"
```

Set `public_template` to `false` only after replacing every placeholder with the
intended private host, path, model, and resource values. Never commit the
resulting file.

## Required starting state

- Exact `v0.1.0-rc.4` staged payloads are present on all four roles.
- Neither runtime role has an active R2.4 runtime.
- Opt1 API and owned PostgreSQL ports are free.
- The protected PostgreSQL service remains outside the activation scope.
- Required Opt1 secrets exist outside the repository.
- G732 and P50 capability services are already running.
- The operator has the accepted no-start staging evidence directory.

## Readiness

```bash
cd scripts/deployment/r2-4/harness

./scripts/run-activation-readiness.sh \
  --staging-evidence "$R2_4_STAGING_EVIDENCE" \
  --output "$R2_4_READINESS_EVIDENCE"
```

Required status:

```text
READY_FOR_GOVERNED_R2_4_CONTROLLED_ACTIVATION
```

Readiness is read-only. Review the source lock, corpus checksums, role
preflights, protected workload snapshots, and deterministic archive identities
before authorizing activation.

## Controlled activation

```bash
./scripts/activate-smoke-rollback-reactivate.sh \
  --readiness-evidence "$R2_4_READINESS_EVIDENCE" \
  --staging-evidence "$R2_4_STAGING_EVIDENCE" \
  --output "$R2_4_DEPLOYMENT_EVIDENCE" \
  --approval ACTIVATE_OPENWATCHLIST_R2_4_CONTROLLED_ROLLBACK_QUALIFIED_RUNTIME
```

Required final status:

```text
DEPLOYED_AND_ROLLBACK_QUALIFIED_R2_4_CONTROLLED_RUNTIME
```

Do not rerun automatically after a nonzero result. Preserve the complete
evidence directory and review the original failure phase plus per-role rollback
results.

## Evidence handling

Generated evidence is private operational data. Store it outside the repository.
Public documentation may record sanitized status, hashes, counts, and role
outcomes, but not private addresses, usernames, container IDs, secrets, or
absolute workstation paths.
