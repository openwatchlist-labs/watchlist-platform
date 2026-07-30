# R2.4 qualification results

## Final status

```text
DEPLOYED_AND_ROLLBACK_QUALIFIED_R2_4_CONTROLLED_RUNTIME
```

## Opt1 final smoke

- API bound: yes
- Owned PostgreSQL bound: yes
- `/livez`: HTTP 200
- `/healthz`: HTTP 200
- `/readyz`: HTTP 200
- `/metrics`: HTTP 200
- PostgreSQL readiness: `ok`
- Review-console readiness: `ok`
- Policy, corpus, and identity-registry paths: `ok`
- Runtime, outbox, and backup paths: writable
- Outbox integrity and disk-space checks: `ok`
- Final runtime configuration SHA-256:
  `37ad8b256ec763cf8e13d3ea4e9bf9ba726e5746dfdb79157bea538417785ac9`

## Opt2 final smoke

- Governed input SHA-256:
  `17559b75fef7e34c1c37dca7192113fb5632b5248255cbb20a9e0ea35803bb21`
- Governed package SHA-256:
  `8c5e581ad36807c15a2ae00c5cb4e8b7f9154e208b369ff3227617294a473367`
- Record count: 3
- Name count: 8
- Identifier count: 3
- Exact name lookup: passed
- Exact identifier lookup: passed
- Exact record-ID lookup: passed
- Resident daemon started: no

## Capability-only roles

G732 passed initial and final model/API checks without starting a new process.
P50 passed initial and final Qdrant and Neo4j connectivity checks without
starting a new process.

## Deployment controls

- Complete temporary-root rebinding: performed
- Declared seal regeneration: performed
- Persistent-path residue: none
- Opt1 qualification before Opt2 archive transfer: enforced
- Initial activation and smoke: passed
- Full rollback qualification: passed
- Controlled reactivation: passed
- Compiler toolchain invocation on hosts: none
- Image pull/build: none
- Package installation: none
- systemd mutation: none

## Scope limitation

The catalog fixture is synthetic nonproduction conformance data. This result is
not a production watchlist deployment, regulatory certification, or customer
readiness statement.
