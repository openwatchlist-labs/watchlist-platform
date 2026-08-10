# H1 r2.3.4 historical Go-evidence quarantine repair

## Observed r2.3.3 failure

The r2.3.3 generated selector itself compiled in the authentic `internal/screeningapi` package. Repository-wide `go test ./...` nevertheless failed because an older r2.3.2 evidence directory still contained a generated `.go` file under:

```text
var/homelab/evidence/provider-activation-r232-*/materialized/selector/internal/screeningapi
```

Because `var/homelab` was inside the root Go module, that retained evidence was treated as a live package and failed with `undefined: ScreeningRequest`.

The verified rollback journal established:

```text
PASS|local_selector_restored
PASS|remote_mutation_not_started
PASS|rollback_complete
```

No runtime image, source transfer, remote backup, credential rotation, lineage mutation, service mutation, capability probe, or qualification attempt occurred.

## r2.3.4 correction

r2.3.4 does not delete, rename, or rewrite historical evidence. Before repository-wide Go testing it:

1. inventories every `.go` file below `var/homelab`;
2. writes a nonsecret quarantine evidence record;
3. creates a temporary nested module boundary at `var/homelab/go.mod` when one does not already exist;
4. runs root `go list ./...` and fails if any `/var/homelab/` package remains visible;
5. runs `go test ./...` and the Docker image build with the boundary active;
6. restores the pre-existing boundary or removes the temporary boundary after the image is saved;
7. performs the same restoration from the verified rollback path on any failure.

This isolates generated and retained evidence from the production module while preserving the evidence bytes.

## Retained activation contract

- Frozen native OFAC and OpenSanctions source digests must be valid.
- Production catalog tables remain read-only.
- Governed lineage is materialized in `public.h1_provider_lineage_v1`.
- The provider selector preserves legacy `raw_list_name` requests when `provider_mode` is absent.
- Exactly three positive provider-mode probes and one invalid-mode negative probe are allowed.
- Qualification attempts remain zero.

## Guarded lifecycle

1. Install the non-mutating overlay.
2. Run the read-only live plan.
3. Confirm `activation_ready: true`, no blockers, zero screening requests, and zero qualification attempts.
4. Activate with `ROTATE-ACTIVATE-R23-4`.
5. Promote capability closure only after all four bounded probes pass.
