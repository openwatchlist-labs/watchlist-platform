# OpenWatchlist R2.4 controlled homelab deployment

R2.4 rebuilt the deployment path after the clean-repository restart and
qualified the published `v0.1.0-rc.4` Linux AMD64 runtime in a controlled
four-role homelab.

Final governed status:

```text
DEPLOYED_AND_ROLLBACK_QUALIFIED_R2_4_CONTROLLED_RUNTIME
```

## Public release boundary

- Release: `v0.1.0-rc.4`
- Release ID: `361927608`
- Main commit: `210dc3c00d43f4f4e9ceae6905c24c9c9ea99584`
- Main tree: `51b93dd4a4e27b5607c2a460580829490e9742d1`
- Linux AMD64 runtime SHA-256:
  `1cf61dce31fad81d8511bac76c5a29aef3c0375a3a26d0c92f58a70a3494a29f`

## Documentation map

- [`architecture.md`](architecture.md) — role topology and isolation boundaries
- [`deployment-runbook.md`](deployment-runbook.md) — readiness and controlled activation
- [`rollback-and-recovery.md`](rollback-and-recovery.md) — automatic and manual rollback
- [`qualification-results.md`](qualification-results.md) — accepted closure results
- [`qualification-results.json`](qualification-results.json) — machine-readable sanitized result
- [`defect-closure.md`](defect-closure.md) — failures found and controls added
- [`publication-boundary.md`](publication-boundary.md) — what may and may not be public

## Important limitation

The Opt2 catalog runtime was qualified with the committed synthetic
three-record conformance fixture. The result proves binary, package, lookup,
smoke, rollback, and reactivation mechanics. It does not claim full production
OFAC coverage or regulatory disposition.
