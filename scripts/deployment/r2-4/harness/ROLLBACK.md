# Sanitized rollback reference

Manual rollback is bounded to the two runtime roles:

```bash
./scripts/rollback-r2-4-controlled-runtime.sh   --output "$R2_4_ROLLBACK_EVIDENCE"   --approval ROLLBACK_OPENWATCHLIST_R2_4_CONTROLLED_RUNTIME
```

The public template cannot run this command. Supply a private operational policy
through `R183_POLICY_OVERRIDE`.

Rollback must preserve the accepted stage, leave capability-only roles
untouched, and record separate per-role rollback and archive-cleanup outcomes.
