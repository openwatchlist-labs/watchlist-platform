# CLAUDE.md

Project guidance for Claude Code sessions in `openwatchlist-labs/watchlist-platform`.

## What this is

A sanctions and watchlist screening platform. A missed match or a corrupted audit record has
regulatory consequences, so correctness and evidence integrity outrank speed and elegance here.

Current honest status: the governance layer (lineage, four-eyes, immutable ledger, checksum-addressed
policy) is solid. The matching and persistence layers are not yet production-capable. Work is tracked
in the consolidated issue register; every task should reference an issue ID (`DOM-*`, `SEC-*`,
`REL-*`, `SAL-*`, `DOC-*`).

## Commands

```bash
scripts/ci/run-ci.sh                        # full gate: vet, test, cargo test, clippy
go test -race -count=1 ./...                # required before any PR touching Go
cargo test --locked --workspace --all-targets
python scripts/ci/legacy_exclusion_gate.py  # MUST pass on every PR
python scripts/ci/verify-legacy-lineage.py
```

## Hard rules

1. **No new dependencies.** `go.mod` and the Rust workspace are intentionally dependency-free.
   The only authorized exception is `jackc/pgx/v5`, and only under the persistence ADR (REL-2).
   Need a UUID? Use `crypto/rand`. Need a hash? It is already in stdlib.

2. **Never edit the clean-restart control files.** `.clean-restart/**` and
   `docs/governance/legacy-qualification-lineage.json` are the evidence that this repository was
   rebuilt clean after a credential-exposure incident. If `legacy_exclusion_gate.py` or
   `verify-legacy-lineage.py` fails, the *code placement* is wrong — fix that. Editing a baseline
   hash or the frozen commit/tree to make a check pass voids the guarantee the check exists to prove.

3. **Salvaged legacy material goes to new paths.** The gate blocks `testdata/homelab/`,
   `cmd/homelab*/`, `deploy/homelab/`, `scripts/homelab/`, `var/`, `target/`, and any
   `*/evidence/` or `*/materialized/` segment. Port archetype corpora to `test/corpus/`, the
   validator to `cmd/corpus-validate/`, design docs to `docs/design/`.
   **Never** migrate `*.key`, `*.pem`, `*.crt`, or `.env*` from the legacy archive.

4. **There is one screening-api implementation.** `cmd/screening-api` (+ `internal/screeningapi`)
   is the sole screening implementation; REL-10 deleted the four `-v8d`/`-v8e`/`-v8f`/`-v8g` proxy
   tiers (see ADR-0002).

5. **Write the failing test first.** The dominant bug class in this repo is *silent absence* —
   a control that looks installed and does nothing. A fix without a test that fails before it is
   unverifiable for exactly these bugs. Concurrency fixes need a `-race` test; tenancy fixes need
   a two-tenant test; schema guards need a SQL invariant query returning zero rows.

6. **Normalization and catalog-format changes are release events, not patches.**
   `normalize_ascii` (`runtime/catalog-mmap/src/format.rs`) determines every index key, and the
   compiled package layout is pinned by `PackageSHA256` in each runtime binding. Changing either
   requires a `PACKAGE_SCHEMA_VERSION` bump, a full catalog recompile, and re-qualification of every
   binding. Do not make these changes as part of an unrelated task.

7. **Do not invent a format or contract and implement it in the same pass.** On-disk formats,
   protocol frames, threat models, and irreversible migrations get a written ADR in `docs/adr/`,
   reviewed and merged first. Implementation PRs reference the ADR.

## Repo-specific traps

- **Fail-open migrations.** `009g` uses `IF to_regclass(t) IS NOT NULL THEN` and silently skips
  security controls for absent tables. New migrations must `RAISE EXCEPTION` instead. Do not copy
  the surrounding style.
- **Row triggers do not fire on `TRUNCATE`.** Immutability requires a
  `BEFORE TRUNCATE ... FOR EACH STATEMENT` trigger in addition to the row trigger.
- **RLS needs `FORCE`.** `ENABLE ROW LEVEL SECURITY` alone is bypassed for the table owner.
  It also needs `SET LOCAL openwatchlist.tenant_id` — not `SET` — inside every transaction.
- **Never enumerate targets by inference.** When a task supplies a list of tables, packages, or
  files, use exactly that list. A silently omitted table is an invisible security hole.
- **`select` with `default` does not protect a closed channel.** Sending on a closed channel panics
  regardless. See `internal/runtimemmapclient/pool.go`.
- **Do not swallow conflicts.** `ON CONFLICT DO NOTHING` on ledger and idempotency writes hides real
  divergence. Catch `23505` and surface it.
- **Do not discard errors from `json.Marshal`** on anything bound for the ledger. There are three
  existing `_ =` instances in `screeningledger`; do not add a fourth.
- **Markdown hard-line-breaks trip the whitespace gate on new content.** `scripts/ci/check_whitespace.py`
  grandfathers whitespace already present at import (`.clean-restart/inherited-whitespace-baseline.txt`,
  hash-bound to the original source, not editable per rule 2) but rejects any *new* trailing-whitespace
  warning. A Markdown hard-break (`  ` two trailing spaces, forcing a mid-paragraph line break) is
  exactly this pattern and will fail the gate the moment it appears in a file the gate didn't already
  know about it in. When porting or writing Markdown: strip trailing double-spaces used as hard-breaks
  and let the blank-line paragraph break do the work instead, or use an explicit `<br>` if the mid-paragraph
  break is load-bearing. Do not edit the whitespace baseline to grandfather new occurrences. Note any
  such strip in the PR description — it is a formatting change, not a byte-preserving copy, and reviewers
  should be able to see it changed rendered output only where a hard-break was genuinely mid-paragraph.

## Layout

```
cmd/                  Service and CLI entrypoints (single screening-api entrypoint — see rule 4)
internal/             56 packages; business logic
  candidatescoring/     Evidence scoring; NOT currently wired into the live screening path
  matcherbaseline/      Real fuzzy matcher; intentionally OFF the production path today
  runtimemmapclient/    Go client for the Rust worker pool (stdio TSV protocol)
  reviewauth/          Tokens, RBAC, audit chain
runtime/catalog-mmap/ Rust: catalog compiler + mmap retrieval runtime (dependency-free)
db/migrations/        Postgres schema; append-only ledger, RLS, immutability triggers
docs/adr/             Architecture decision records (design gate — see rule 7)
test/fixtures/, test/golden/, test/corpus/
.clean-restart/       Import control files — READ ONLY (see rule 2)
```

## Definition of done

- `scripts/ci/run-ci.sh` passes
- `go test -race` passes
- `python scripts/ci/legacy_exclusion_gate.py` passes
- A test exists that failed before the change
- No new dependency, or the authorizing ADR is cited
- The PR names the issue ID and, if applicable, which screening-api variant it targets

## Boundaries

Open PRs; do not merge. Do not push to `main`. Do not modify CI gate scripts as part of a feature
task — gate changes are their own reviewed PR.
