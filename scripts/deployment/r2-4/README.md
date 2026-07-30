# R2.4 sanitized homelab harness

The `harness/` directory is the public, sanitized reference implementation of
the accepted R2.4 r1.8.3.4 readiness, activation, smoke, rollback, and
reactivation workflow.

## Safety model

- The committed policy uses `.example.invalid` hosts and is marked
  `public_template: true`.
- Operational entrypoints fail closed with the public template.
- An operational policy must be stored outside the repository and supplied with
  `R183_POLICY_OVERRIDE`.
- Secrets, private addresses, generated evidence, and runtime data are not part
  of this tree.
- G732 and P50 remain capability-only roles.
- Opt1 and Opt2 are the only roles eligible for runtime activation or rollback.

## Offline validation

```bash
./scripts/ci/verify-homelab-r2-4-publication.sh
```

The gate verifies sanitized publication boundaries, exact fixture identities,
corpus passage checksums, source-lock metadata, shell/Python syntax, policy
contracts, lifecycle safety, qualification-first ordering, and automatic
rollback evidence.

## Preparing a private policy

```bash
cp scripts/deployment/r2-4/harness/config/policy.example.json \
  "$HOME/.config/openwatchlist/r2-4-policy.json"
chmod 600 "$HOME/.config/openwatchlist/r2-4-policy.json"
export R183_POLICY_OVERRIDE="$HOME/.config/openwatchlist/r2-4-policy.json"
```

Replace all placeholders and set `public_template` to `false`. Do not commit the
private copy.

See `docs/homelab/r2-4/deployment-runbook.md` and
`docs/homelab/r2-4/rollback-and-recovery.md`.
