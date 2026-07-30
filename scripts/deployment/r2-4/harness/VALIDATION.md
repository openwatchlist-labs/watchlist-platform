# Sanitized harness validation

Construction and repository CI require:

```bash
./scripts/validate-package.sh
./scripts/self-test.sh
```

The tests are offline and standard-library only. They validate exact public
fixture identities, corpus passage checksums, deterministic compilation,
source-lock behavior with a fake GitHub API client, role restrictions,
configuration rebinding, seal regeneration, qualification-first transfer,
smoke contracts, and rollback evidence.

The public policy must contain no private infrastructure identity and must remain
non-operational.
