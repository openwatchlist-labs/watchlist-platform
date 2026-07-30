# OpenWatchlist R2.4 r1.8.3.4 sanitized reference harness

This directory preserves the accepted controlled deployment logic without
publishing environment-specific infrastructure identity.

The committed `config/policy.json` and `config/policy.example.json` are
non-operational templates. Their hosts use `.example.invalid`, their runtime
paths are generic, and `public_template` is `true`.

Operational entrypoints require `R183_POLICY_OVERRIDE` to name a private policy
stored outside the repository with `public_template` set to `false`.

The harness retains:

- exact synthetic activation inputs and source-lock metadata;
- corpus passage and deterministic recompilation validation;
- role-aware four-host preflight logic;
- complete temporary-root config rebinding and declared seal regeneration;
- qualification-first Opt2 archive transfer ordering;
- controlled activation, smoke, full rollback, and reactivation;
- structured automatic rollback evidence.

Run offline validation with:

```bash
./scripts/validate-package.sh
./scripts/self-test.sh
```

See the repository documentation under `docs/homelab/r2-4/`.
