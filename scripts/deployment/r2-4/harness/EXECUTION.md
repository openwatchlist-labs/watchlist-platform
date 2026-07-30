# Sanitized harness execution

The public template is intentionally non-operational. Create a private policy
outside the repository, replace every placeholder, set `public_template` to
`false`, and export its path:

```bash
cp config/policy.example.json "$HOME/.config/openwatchlist/r2-4-policy.json"
chmod 600 "$HOME/.config/openwatchlist/r2-4-policy.json"
export R183_POLICY_OVERRIDE="$HOME/.config/openwatchlist/r2-4-policy.json"
```

Readiness:

```bash
./scripts/run-activation-readiness.sh   --staging-evidence "$R2_4_STAGING_EVIDENCE"   --output "$R2_4_READINESS_EVIDENCE"
```

Controlled activation:

```bash
./scripts/activate-smoke-rollback-reactivate.sh   --readiness-evidence "$R2_4_READINESS_EVIDENCE"   --staging-evidence "$R2_4_STAGING_EVIDENCE"   --output "$R2_4_DEPLOYMENT_EVIDENCE"   --approval ACTIVATE_OPENWATCHLIST_R2_4_CONTROLLED_ROLLBACK_QUALIFIED_RUNTIME
```

Generated evidence must remain outside the repository.
