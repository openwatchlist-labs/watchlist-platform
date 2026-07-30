# R2.4 rollback and recovery

## Automatic rollback

Any failure after remote mutation triggers a bounded global rollback of Opt1 and
Opt2. The controller records separate return codes and structured results for:

- Opt1 rollback
- Opt2 rollback
- Opt1 temporary-archive cleanup
- Opt2 temporary-archive cleanup

The original failure phase is preserved. Rollback attempted and rollback
succeeded are distinct fields; success is never inferred merely because the
rollback path ran.

## Manual rollback

Use the manual rollback entrypoint only when the deployment evidence requires
recovery or an operator intentionally stops the controlled runtime:

```bash
cd scripts/deployment/r2-4/harness

./scripts/rollback-r2-4-controlled-runtime.sh \
  --output "$R2_4_ROLLBACK_EVIDENCE" \
  --approval ROLLBACK_OPENWATCHLIST_R2_4_CONTROLLED_RUNTIME
```

The manual path is limited to Opt1 and Opt2. It must not activate, stop, or
reconfigure G732 or P50 capability services.

## Required rollback outcomes

- No R2.4 runtime remains active on Opt1 or Opt2.
- The accepted staged payload remains byte-preserved.
- Opt1-owned PostgreSQL resources are removed only when their ownership labels
  match the governed policy.
- Existing protected containers and services remain unchanged.
- No compiler, package installation, image pull/build, or systemd mutation
  occurs.

## Failure review order

1. Verify the evidence checksum manifest.
2. Read `failure.json` and `phase.json`.
3. Inspect the failing role's structured result and SSH stderr.
4. Inspect `automatic-rollback/summary.json`.
5. Confirm both runtime roles report `runtime_active: false`.
6. Confirm temporary archives were removed.
7. Repair the exact invariant before producing new readiness evidence.
