# ADR-0007: Audit chain integrity

- **Status:** Proposed
- **Date:** 2026-08-13
- **Issue:** SEC-7 (P1)
- **Related:** SEC-1 (ADR-0001, accepted), REL-10 (ADR-0002), SEC-1b (ADR-0003), DOM-3 (ADR-0004),
  REL-2 (ADR-0005), SEC-1e (ADR-0006), SEC-10 (PR #100, PR #101, merged), SEC-11 (PR #102, merged),
  REL-5, REL-8
- **Supersedes:** nothing. This is the first document in the repository to specify a tamper-evidence
  mechanism. No prior ADR is modified — ADR-0001 §9 is *cited* for the scope it declined, not
  amended.

## Context

`internal/screeningledger` keeps two append-only hash chains. Their integrity guarantee is
`sha256(json(record))` with no secret input and no commitment to anything outside the directory the
records live in. The verifier checks that each entry's recorded predecessor digest equals the
previous entry's digest, that sequence numbers are contiguous, that each entry's self-digest
recomputes, and that the last entry matches a head file — a head file written by the same function,
at the same permissions, into the same directory as the entries it attests.

Every input to that check is public and every output is rewritable by whoever can write the
directory. A party with filesystem or database write access can alter or delete entries, recompute
each downstream digest with the published algorithm, rewrite the head, and obtain a chain the
system's own verifier reports as `"status":"ok"`. There is no value anywhere in the system that a
forged history cannot reproduce.

This is the last unaddressed finding from the Phase 2 adversarial audit. It is routed to a design
document rather than a patch because the deliverable named in the register is "threat model, key
custody, anchoring, and an **honest** statement of the residual" (`docs/backlog/issue-register.md:249`)
— and because CLAUDE.md rule 7 requires a merged ADR before a threat model is implemented.

Every claim below was verified against the working tree at `61ca62a`. Where a premise this ADR
inherited turned out to be wrong, §3 says so explicitly rather than quietly designing around it.

## 1. What the chain actually is

Two chains share one store directory, and one verifier entry point covers both.

| | Event chain | Audit chain |
|---|---|---|
| Record type | `Event`, 21 fields (`internal/screeningledger/types.go:30-51`) | `AuditEvent`, 10 fields (`types.go:79-91`) |
| Digest function | `hashEvent` (`store.go:374-381`) | `hashAudit` (`audit.go:101-108`) |
| Construction | blank the self field, `json.Marshal`, `digestHex` | identical |
| Predecessor field | `PreviousEventSHA256` ← prior `EventSHA256` (`store.go:115`) | `PreviousAuditSHA256` ← prior `AuditSHA256` (`audit.go:28`) |
| Entry path | `events/<event_id>.json` (`store.go:331`) | `audit/<seq>-<sha>.json` (`audit.go:34`) |
| Head file | `head.json` (`store.go:135`) | `audit-head.json` (`audit.go:38`) |
| Verifier | `Store.Verify` (`store.go:173-239`) | `Store.VerifyAudit` (`audit.go:44-88`) |

Four properties of that table carry the whole finding.

**The digest is unkeyed.** `digestHex` is `sha256.Sum256` over its argument and nothing else
(`crypto.go:91`). Neither `hashEvent` nor `hashAudit` accepts or consults a secret. `Store` holds a
32-byte key (`store.go:18`), but it reaches only the snapshot cipher (`store.go:78`, `:82`) and the
redaction MAC (`replay.go:92`, `:96`) — never the chain.

**The digest input is Go struct-field order, not canonical JSON.** Both functions call
`json.Marshal` on the struct directly. The package *has* a `canonicalJSON` helper
(`crypto.go:92-100`), but it is applied only to request and response bodies before snapshotting
(`store.go:66`, `:70`). This is not a defect on its own — Go's encoder emits struct fields in
declaration order deterministically — but it means the chain's wire format is pinned to a Go type
declaration, which §6 has to account for.

**The head files do catch plain truncation, and they are not an anchor.** `VerifyAudit` compares its
walk against `audit-head.json` (`audit.go:80-86`) and `Verify` against `head.json`
(`store.go:228-234`), so deleting the newest entries without touching the head is detected. That is
strictly stronger than the register's description of this bug class. It changes nothing about the
finding: both heads are written by the same `marshalAndWrite` → `atomicWrite` path at the same
`0o640` into the same directory as the entries (`audit.go:38`, `store.go:135`). An adversary who can
delete an entry can rewrite the head in the same breath. The head is an internal-consistency check
against accident, not a commitment against intent.

**One entry point covers both chains.** `Store.Verify` calls `s.VerifyAudit()` before returning
(`store.go:235`), so anything that runs `Verify` runs both.

### 1.1 Nothing runs verification

`screening-ledger status|verify` (`cmd/screening-ledger/main.go:34-46`) is the only path that calls
`Store.Verify` in the whole system. It runs when an operator types it.

- `grep -rn "screening-ledger" scripts/ .github/ deploy/` returns zero matches.
- `scripts/ci/run-ci.sh` builds and unit-tests the module but never runs the binary.
- The deployment harness declares `runtime_executables` as `platform-api`, `platform-ops`,
  `container-healthcheck`, `catalog-mmap`
  (`scripts/deployment/r2-4/harness/config/policy.json:150-155`). `screening-ledger` is not among
  them.

The single automated execution anywhere in the repository is `TestHappyPath_Verify`
(`cmd/screening-ledger/main_test.go:99-108`), which runs `verify` against a committed one-event
fixture. There is no scheduled job, no verification on read, and no CI gate. A verifier that runs
only when someone chooses to run it is the weaker half of this finding, and §8 treats it as such.

### 1.2 Every writer

**Event chain:** `Store.Append` (`store.go:48`) and nothing else. `AppendInput{}` is constructed at
exactly one site in the entire tree — `store_test.go:22`. There is no production writer of the event
chain today.

**Audit chain:** `Store.AppendAudit` (`audit.go:14`), four call sites:

| Site | Action |
|---|---|
| `cmd/screening-ledger/main.go:65` | `postgres_replicated` |
| `internal/screeningledger/replay.go:52` | `replay` |
| `internal/screeningledger/replay.go:160` | `export_bundle` |
| `internal/screeningledger/replay.go:207` | `purge_expired` |

No package outside `screeningledger` writes either chain. The sibling packages own their own,
separate chains; §7 triages them.

## 2. The threat model

**In scope.** A party that can write the ledger directory, or write the Postgres mirror, and wants
past history to read differently than it happened. Three concrete acts: altering the content of an
entry, deleting entries from the middle, and truncating the tail. In every case the party recomputes
whatever the public algorithm requires so that the system's own verifier agrees with the result.

**In scope, and the reason a MAC alone is insufficient.** The same party, additionally holding the
chain key. §5 states this residual rather than designing as if it were closed.

**Out of scope.** Confidentiality of ledger contents — that is snapshot encryption (`crypto.go:40-61`)
and, for cross-tenant read exposure, ADR-0001 §9's accepted D2 risk. Availability. An adversary who
deletes the entire ledger directory and admits nothing was ever there; detecting that requires
knowing a ledger was supposed to exist, which is §6's genesis record and §8's automation, not a
property of the chain.

**Explicitly not assumed.** That the system has live traffic. It does not: ADR-0002 §5 found zero
callers of any screening-api tier, ADR-0003 §8:485-506 re-confirmed it with positive evidence from
the deployment harness, and §1.2 above shows the event chain has no production writer at all. This
ADR designs for the threat the system *states* while sizing the mechanism to the deployment the
system *has*. §5.3 rejects two stronger designs on exactly that basis.

## 3. Three inherited premises that did not survive verification

Recording these because each would have produced a real design error, and because a later reader
will otherwise re-derive them.

### 3.1 ADR-0001 contains no keyed-HMAC recommendation

It is natural to assume SEC-1's ledger work left a keyed-chain design to be picked up here. It did
not. `grep -ni "hmac\|keyed\|anchor\|worm\|kms" docs/adr/0001-tenant-isolation.md` returns nothing.
ADR-0001 names SEC-7 exactly twice, both times to push it away:

- `docs/adr/0001-tenant-isolation.md:92-93` lists "audit-chain forgery (§9, SEC-7)" among the items
  explicitly out of scope.
- `:522-523` — "**SEC-7 is orthogonal.** RLS constrains which rows a principal sees; it does not stop
  a principal with write access from forging an audit chain."

The "HMAC-via-KMS chain + signed WORM anchors + anchor-aware `Verify()`" phrasing lives in
`docs/backlog/issue-register.md:215`, a sprint line, not an ADR. **This ADR must not cite ADR-0001
for a design ADR-0001 does not contain**, and does not.

### 3.2 The file chain and the Postgres ledger are one chain, not two

The question of whether `screening_ledger_event` needs a separate design from the file-based chain
has a definite answer: no, because the Postgres table is downstream of the file.
`cmd/screening-ledger/main.go:63` calls `sink.Persist` with the `Event` value read from the file
store, and `postgres.go:135-141` inserts that value's fields plus `event_json`. `PersistAudit`
(`main.go:67` → `postgres.go:198-201`) does the same for `AuditEvent`. The file chain is
authoritative; Postgres mirrors it. One mechanism covers both.

Two consequences follow, and both are independent defects this ADR must carry into its design
because they sit on the same attack path:

**The immutability triggers do not fire on `TRUNCATE`.** Every trigger in `SchemaSQL` is
`BEFORE UPDATE OR DELETE ... FOR EACH ROW` (`postgres.go:281-286`). There is no
`BEFORE TRUNCATE ... FOR EACH STATEMENT` trigger on any of the six protected tables. This is the
trap CLAUDE.md names by name. A party with DB write access empties the entire mirror — event, audit,
replication, receipts, tombstones — without firing a single trigger, and `Migrate`'s
`CREATE TABLE IF NOT EXISTS` (`postgres.go:273-279`) then re-creates nothing because the tables still
exist. The mirror is silently gone.

**Audit-mirror conflicts are swallowed.** `PersistAudit` inserts with
`ON CONFLICT (audit_sha256) DO NOTHING` (`postgres.go:200`). If the same audit digest arrives with
different content the row is dropped without a word — the second CLAUDE.md trap, on the integrity
table itself.

### 3.3 SEC-7's register row names a different primary target

`docs/backlog/issue-register.md:102` scopes SEC-7 to `internal/reviewauth/audit.go` + 13 sibling
stores, and its symptom list describes `reviewauth`, not `screeningledger`:

| Register symptom | `reviewauth` | `screeningledger` |
|---|---|---|
| `Verify()` validates a prefix, tail truncation returns `ok` | **True** — no head file exists at all (`reviewauth/audit.go:85-113`); a truncated chain returns `AuditStatus{"ok", n, prev}` with a smaller `n` (`:112`) | False — head compared at `store.go:232`, `audit.go:84` |
| No `fsync` | **True** — `writeJSONAtomic` is `os.WriteFile` + `os.Rename`, no `Sync` (`reviewauth/audit.go:143-154`) | False — `atomicWrite` syncs file and directory (`store.go:405-407`, `:420`) |
| `mkdir` spinlock, no PID/TTL | **True** — `withLock`, 10s deadline, 10ms poll (`reviewauth/audit.go:29-44`) | False — `sync.Mutex` (`store.go:20`, `:49`) |
| Unkeyed chain, forgeable by a writer | **True** (`reviewauth/canonical.go:12-18`) | **True** (`crypto.go:91`) |

Only the fourth row is common to both. **The unkeyed-chain finding is the one this ADR specifies**;
the other three are `reviewauth`-specific and belong to that store's own pass (§7). This ADR takes
`screeningledger` as its implementable target on the grounds that it is the chain with a real
persistence path, a Postgres mirror, and an existing key-custody mechanism to build on — and names
every sibling, with triage, so the choice does not silently orphan the register's stated targets.

### 3.4 Corrections found implementing D3 (Stage 2)

Recorded here rather than silently worked around, in the same spirit as §3.1–3.3: both were checked
against the tree at implementation time, not assumed from this ADR's own text.

**§3.2 and §5.3 point 3's "all six existing protected tables lack a `BEFORE TRUNCATE` trigger" was
already false when this ADR was drafted.** `db/migrations/012_truncate_guards.sql` (commit `c9a89d4`,
2026-08-10) added a `BEFORE TRUNCATE ... FOR EACH STATEMENT` trigger, via `owl_reject_truncate()`, to
exactly the six tables named there: `screening_ledger_event`, `screening_ledger_audit`,
`screening_ledger_replication`, `screening_ledger_retention_tombstone`, `screening_ledger_snapshot`,
`screening_idempotency_receipt`. `c9a89d4` is an ancestor of `61ca62a`, the commit this ADR states it
verified every claim against (Context, above) — so this was not drift introduced by a later PR, the
premise did not hold at the moment it was written. D3's actual remaining scope, once this is
corrected, is the trigger on the *new* `screening_ledger_anchor` table only.

A related, separately-tracked gap surfaced by the same check: `internal/screeningledger/postgres.go`'s
`SchemaSQL` constant independently bootstraps those same six tables (called from every
`cmd/screening-ledger` CLI invocation and from this package's own pgx test suite, with no dependency
on `db/migrations/` having run first) and never carried the `BEFORE TRUNCATE` trigger `012` added —
this is REL-9's tracked schema-duplication finding (`docs/backlog/issue-register.md:129`), shown here
to have a real consequence rather than only a maintenance one. The Stage 2 implementation PR closes
this one property gap in `SchemaSQL` directly; it does not attempt REL-9's broader unification of the
two schema sources, which remains its own, larger, separate problem.

**This ADR did not reconcile the new `owl_ledger_anchor` role with the existing rule in
`docs/adr/0001-tenant-isolation.md:208`: "No migration contains `CREATE ROLE` or `GRANT`; every sink
connects as the table owner using the DSN it was constructed with."** §5.3 point 2 specifies the role
must exist and be distinct from the ledger writer, but says nothing about where it is provisioned, and
the natural reading of "`owl_migrator` ... transfers ownership ... then drops its own membership" (the
phrasing this ADR's implementation was kicked off with) describes exactly the `CREATE ROLE`/`GRANT`
shape ADR-0001 keeps out of `db/migrations/`. Resolved, not left silent: `owl_ledger_anchor`'s
creation, the `ALTER TABLE screening_ledger_anchor OWNER TO owl_ledger_anchor` ownership transfer, and
`owl_migrator`'s membership-drop `REVOKE` all live in `scripts/ci/provision_test_roles.sh`, run by the
same bootstrap superuser that provisions `owl_migrator` and `owl_app` — following ADR-0001's existing
pattern rather than creating a new exception to it. The anchor table's own `CREATE TABLE` stays in
`db/migrations/015_screening_ledger_anchor.sql`, run by `owl_migrator`, unchanged from how every other
relation in this schema is created.

## 4. Decisions

| ID | Decision | Rationale |
|---|---|---|
| **D1** | **One root secret, never used directly; three subkeys via HKDF-SHA256 with distinct `info` strings.** Fixes `redact.go`'s raw-key reuse in the same change. | §5.1. Without it the chain key inherits the snapshot key's distribution and the custody boundary is fictional. |
| **D2** | **`hashEvent`/`hashAudit` become HMAC-SHA256 under a derived chain key.** | §5.2. Defeats a filesystem- or DB-write adversary who does not hold the key. |
| **D3** | **Periodic head anchoring to `screening_ledger_anchor`, written by a distinct DB role under an independent key, plus the missing `TRUNCATE` triggers. `Verify()` becomes anchor-aware.** | §5.3. Defeats an adversary who *does* hold the chain key. The MAC alone does not. |
| **D4** | **Fresh `v2` chain at a genesis anchor; the `v1` prefix is frozen and preserved under its original, weaker guarantee.** | §6. Retroactive keying attests only to the present, so it would manufacture false assurance. |
| **D5** | **Adoption is proved by a forgery test that passes against the old verifier and fails against the new one.** | §7. The REL-8 standard: a fix for a silent-absence bug is unverifiable without a test that fails first. |
| **D6** | **The mechanism is specified here; the CI gate that runs it is a separate, named gate PR.** | §8 and CLAUDE.md Boundaries. |
| **D7** | **Siblings are enumerated and triaged as adopt-as-is or own-design-pass; none is implemented here.** | §7. |

## 5. The mechanism

### 5.1 Key hierarchy (D1)

Today a single 32-byte value loaded by `LoadKey` (`crypto.go:18-39`) from `--key-file` or `--key-env`
(`cmd/screening-ledger/main.go:121`) is used directly for two different primitives:

- **AES-256-GCM**, encrypting every request and response snapshot (`crypto.go:44-59`).
- **HMAC-SHA256**, producing redaction pseudonyms in exported bundles (`redact.go:55-59`, called from
  `replay.go:92`, `:96`).

Under this ADR the loaded value becomes a **root secret `R` that is never used directly for any
primitive.** Three subkeys derive from it with `crypto/hkdf` — stdlib as of Go 1.24, and `go.mod:3`
pins `go 1.26.5`, so **no new dependency** (CLAUDE.md rule 1 satisfied without an exception):

| Subkey | `info` | Consumer |
|---|---|---|
| `K_snap` | `openwatchlist/screening-ledger/snapshot-aead/v2` | `encryptSnapshot` / `decryptSnapshot` (`crypto.go:40-90`) |
| `K_redact` | `openwatchlist/screening-ledger/redaction-pseudonym/v2` | `hmacHex` (`redact.go:55-59`) |
| `K_chain` | `openwatchlist/screening-ledger/chain-mac/v2` | `hashEvent`, `hashAudit` |

Illustrative only — the implementation PR owns the real code:

```go
// salt binds a derivation to the ledger it serves, so two ledgers sharing a
// root secret do not share subkeys.
sub, err := hkdf.Key(sha256.New, root, []byte(ledgerID), info, 32)
```

**`K_anchor` is deliberately not in that table.** It is an independent secret, generated separately,
held by the anchoring identity, and not derivable from `R`. §5.3 explains why the entire defense
rests on that.

#### Why the `redact.go` key reuse is fixed here and not deferred

This was checked rather than assumed. Leaving it is a real gap, not an inelegance, on three counts.

**It is an outward-facing chosen-message oracle.** `hmacHex` MACs values taken from the
caller-supplied request body: `HashKeys` defaults to `name,address,original_value`
(`cmd/screening-ledger/main.go:85`, matching `configs/screening-ledger/phase8g-example.json:12`), and
`RedactJSON` is invoked only from `ExportBundle`'s `redacted` mode (`replay.go:91-100`) — the mode
whose entire purpose is producing an artifact for someone outside the trust boundary. The design
therefore hands an external recipient MAC outputs, over partly attacker-chosen messages, keyed by the
exact secret that decrypts every snapshot in the ledger. Nothing about that is breakable against
HMAC-SHA256 today, which is precisely why it is a structural weakness to close rather than an
incident to report.

**It would become a fourth use of the same bytes.** HKDF-Extract is itself `HMAC(salt, IKM)`
(RFC 5869 §2.2). Deriving over the raw `s.key` while that same value remains a live AES key and a
live HMAC key makes one 32-byte secret simultaneously an AES key, a MAC key over attacker-influenced
input, and key-derivation input material.

**Decisively: it would make this ADR's own custody claim false.** If `K_redact` stays `R` while
`K_chain = HKDF(R, …)`, then every holder of `R` still derives `K_chain`. `R` must be present in the
appending process to encrypt snapshots, is handed to anyone who needs to decrypt evidence, and one
instance is committed to this repository at `test/fixtures/screening-ledger/snapshot-key.hex`. A
chain key rooted in a secret distributed like that adds a step to forgery; it does not prevent it.
§5.2's boundary only means something if `R`'s holders are a *smaller* set than the ledger
directory's writers, and it can only stay smaller if `R` stops being the value that gets handed
around for decryption.

**Cost of doing it now: two call sites** (`replay.go:92`, `:96`) pass a derived subkey instead of
`s.key`. `grep -rn "hmac" --include="*_test.go"` finds no test anywhere that pins a redaction
pseudonym value, so nothing breaks. The one genuine consequence is **pseudonym linkability across
the cutover**: a `name` exported before the change produces a different token than the same `name`
exported after, so an auditor holding bundles from both sides cannot correlate them. Recorded here
as a decided, accepted consequence rather than left to surface during implementation. It is free
today — the fixture ledger holds one event and there is no production writer — and it is not free
after the first real export.

**Snapshot re-encryption under `K_snap` is transparent to both chains.** `SnapshotSHA256` is computed
over *plaintext*, not ciphertext (`crypto.go:56-57`), and `AAD` derives from that digest
(`crypto.go:58`). Re-encrypting therefore yields an identical `SnapshotSHA256`, identical `AAD`, and
identical `PlaintextSHA256`; only `NonceBase64` and `CiphertextBase64` change. Every digest the event
chain references (`store.go:115`) is unchanged, snapshot filenames (`store.go:332`) are unchanged,
and `verifySnapshot` (`store.go:311-330`) passes before and after. The migration is an in-place
envelope rewrite, not a re-chaining.

### 5.2 Keyed chain (D2)

`hashEvent` and `hashAudit` become `HMAC-SHA256(K_chain, canonical(record))`, with the self-digest
field blanked before serialization exactly as today. `Verify` and `VerifyAudit` recompute under the
same key and reject on mismatch.

**Custody requirement, stated concretely enough to audit:** the file holding `R` lives outside
`--ledger-dir`; it is mode `0400`; it is owned by a principal that does not own the ledger directory
and is not the principal the ledger's writing process runs as when that process is doing anything
other than appending. The CLI already refuses to accept a DSN on `argv` for a directly analogous
reason (`cmd/screening-ledger/main.go:128-139`, ADR-0005 §11.1 D11); key custody gets the same
treatment.

**Why this stops the stated attack.** The forgery in §2 requires producing a valid digest for a
record the adversary chose. Under an unkeyed SHA-256 that requires nothing but the algorithm. Under
HMAC it requires `K_chain`, which the ledger directory does not contain and write access to it does
not confer.

**Honest residual, which is why §5.3 exists.** The appending process must hold `K_chain` to append.
An adversary who compromises that process, or reads the key file, forges freely and undetectably at
this layer. A keyed chain moves the attack from "anyone who can write the directory" to "anyone who
holds the key" — a real and large reduction, and not a closure. Any statement that the keyed chain
alone makes the ledger tamper-proof would be false, and §10 keeps it out of `SECURITY.md`.

### 5.3 External anchor (D3)

The anchor is what a key-holding adversary cannot defeat, because it puts a commitment to the
history *outside* the domain that adversary controls, at a time they cannot revisit.

**Mechanism.** A new relation, written through the ADR-0005 pgx sink:

```sql
CREATE TABLE IF NOT EXISTS screening_ledger_anchor (
  ledger_id text NOT NULL, sequence bigint NOT NULL,
  event_sha256 text NOT NULL, audit_sha256 text NOT NULL,
  anchored_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  anchor_mac text NOT NULL,
  PRIMARY KEY (ledger_id, sequence));
```

`anchor_mac` is `HMAC-SHA256(K_anchor, ledger_id ‖ sequence ‖ event_sha256 ‖ audit_sha256)`.

Four properties make it load-bearing, and each is a requirement on the implementation PR, not a
nicety:

1. **`K_anchor` is not derived from `R`** (§5.1). If it were, holding the appending key would confer
   the anchoring key and the anchor would prove nothing beyond the chain MAC.
2. **The anchoring identity is a different DB role than the ledger writer.** The sink's doc comment
   already establishes that this repository distinguishes `owl_app` from a DDL-capable identity
   (`postgres.go:23-34`), so the role vocabulary exists; the anchor writer is a third identity with
   `INSERT` on this table and nothing else.
3. **The table carries the `TRUNCATE` trigger the rest of the schema is missing** — a
   `BEFORE TRUNCATE ... FOR EACH STATEMENT` trigger in addition to the row trigger, per CLAUDE.md.
   §3.2 shows all six existing protected tables lack this; the implementation PR adds it to the
   anchor table and to those six, since an anchor whose siblings can be truncated is only half a
   control.
4. **`Verify()` becomes anchor-aware.** It fails if the chain at an anchored sequence disagrees with
   the anchored digests, and fails if the current head is *behind* the newest anchor — which is what
   catches tail truncation even when the head file was rewritten consistently.

**What it costs the adversary.** With `K_chain` they can still produce a self-consistent chain. They
cannot produce one that agrees with a row committed before they arrived, under a key they do not
hold, in a table they cannot truncate, written by a role they are not. Rewriting history now
requires compromising the anchoring identity *as well*, and doing so before the next anchor is
written — which is a materially different and much narrower proposition than "can write the ledger
directory."

**What it still does not cost them.** An adversary who holds `K_anchor` *and* `K_chain` and controls
both roles rewrites everything. There is no cryptographic answer to a fully compromised operator;
there is only making the compromise require more than one custody domain. §10 says exactly this.

#### Rejected alternatives

**RFC 3161 timestamping or a public transparency log.** Strongest guarantee — it removes the
operator from the trust base entirely. Rejected: it requires network egress from a process that
currently has none, and almost certainly a new module dependency, which CLAUDE.md rule 1 forbids
without an authorizing ADR. Against a system with zero live traffic (§2), no deployed screening path
(ADR-0002 §5), and one event of real ledger data (§6), this is designing for a threat model the
system does not yet have while the one it *does* state goes unaddressed. Re-entry condition: the
first production deployment that screens real traffic for an external counterparty.

**WORM object storage.** Rejected on availability of the target, not on merit. There is no such
target: the deployment harness runs four binaries (§1.1) and no object store appears anywhere in
`scripts/deployment/r2-4/`. Specifying an anchor to storage that does not exist would produce the
exact silent-absence failure this ADR is about — a control that looks installed and does nothing.

**Keyed chain only, anchor deferred.** Rejected because §5.2's residual is not a corner case. The
register's own deliverable names anchoring (`docs/backlog/issue-register.md:215`), and shipping the
MAC alone would let the project describe the chain as tamper-evident while the stated threat actor —
a party with write access, who in this deployment is very often the same operator who holds the key —
remains able to forge.

## 6. Migration (D4)

**Retroactive keying is rejected on principle, not on cost.** A MAC computed today over entries
written last month attests that those bytes exist today and nothing more. Applying `K_chain` to the
existing chain would produce a chain that *looks* as though it had been protected all along, which is
a stronger claim than the evidence supports — the same class of error as presenting a hardcoded
literal as a rule trace. This ADR will not manufacture assurance retroactively.

**Therefore: a fresh chain at a genesis anchor, with the old chain preserved.**

1. `SchemaVersion` constants (`types.go:5-11`) gain `v2` values for event, audit, and head records.
2. Snapshots are re-encrypted in place under `K_snap` (§5.1) — every referenced digest unchanged.
3. A genesis record is appended: the first `v2` entry, whose predecessor field carries the final
   `v1` digest, so the `v1` prefix remains cryptographically referenced rather than discarded.
4. The genesis is anchored immediately. That anchor is what makes the `v1`/`v2` boundary a fact
   rather than a claim.
5. `Verify()` accepts `v1` entries **only** as a frozen prefix terminating at genesis, and reports
   them under the weaker guarantee explicitly in its output — an operator reading `verify` must be
   able to see which portion of their history is anchored and which is merely self-consistent.
6. Any `v1` entry appearing *after* genesis is a hard failure, not a downgrade.

**Existing data is one event.** `test/fixtures/screening-ledger/state/` holds a single event, its
`head.json`, `ledger-id`, and two snapshots — and **no `audit/` directory and no `audit-head.json`**.
There are zero audit-chain entries anywhere in the repository. With no production writer (§1.2) and
no live traffic (§2), the migration's real-world scope is that one fixture. This is the cheapest
this change will ever be.

**The fixture is the tripwire.** `TestHappyPath_Verify` (`cmd/screening-ledger/main_test.go:99-108`)
runs `verify` against that fixture and asserts `"status":"ok"`. It will fail the moment the chain
format changes, which is the intended behavior: the fixture is regenerated under `v2`, the `v1` copy
is retained beside it as the frozen-prefix test case, and a green run after regeneration is evidence
the migration executed rather than evidence it was skipped.

## 7. Test strategy (D5) and sibling triage (D7)

### 7.1 Prove it by breaking it

CLAUDE.md rule 5 and the standard REL-8's flake-reproduction work set (`0033ede`): each case must
fail before the change. The first case is the ADR's whole argument expressed as code.

1. **Forgery detection — the load-bearing test.** Build a multi-entry chain. Tamper one entry's
   content. Recompute *every* downstream digest and both head files using the published algorithm,
   exactly as an adversary would. Assert that the `v1` verifier returns success on the result, and
   that the `v2` verifier returns an error. A test that only shows `v2` rejecting a naively corrupted
   chain proves nothing about this bug — the forged chain must be internally perfect.
2. **Tail truncation against the anchor.** Delete the newest *k* entries, rewrite the head
   consistently, assert `v2` detects the shortfall by comparison with the newest anchor.
3. **Wrong key.** A chain MACed under a different `K_chain` fails verification.
4. **Anchor divergence.** A chain that is fully valid and correctly MACed but disagrees with a stored
   anchor row fails.
5. **Key separation.** Assert `K_snap`, `K_redact`, and `K_chain` are pairwise distinct for a given
   root and ledger ID, and that changing only `info` changes the output — the test that would catch
   a copy-paste leaving two derivations sharing an `info` string.
6. **Frozen-prefix acceptance.** The retained `v1` fixture verifies as a frozen prefix and is
   reported as unanchored; a `v1` entry after genesis fails.
7. **`TRUNCATE` rejection.** A SQL invariant test asserting `TRUNCATE` on each protected table
   raises, per CLAUDE.md's requirement that schema guards be proved by a query. This one runs under
   the existing `OWL_TEST_DATABASE_URL` path (`scripts/ci/run-ci.sh:63-67`) — see §8 on why that
   gating is itself a problem.

### 7.2 Sibling chains

Nine other packages carry their own chains. None is in this ADR's implementation scope; each fix is
a future PR citing this ADR. The triage column is here so nobody re-derives it.

| Package | Chain evidence | Triage |
|---|---|---|
| `screeningledger` | `types.go:35`, `:83` | **Specified here.** The implementable target. |
| `activationpromotion` | `types.go:70`; fixture `test/fixtures/activation-promotion/state/audit/` + `audit-head.json` | **Adopt as-is.** Same head-file design and same `<seq>-<sha>.json` entry layout as `screeningledger`'s audit chain; the mechanism ports with a key-source decision and no structural redesign. |
| `reviewauth` | `types.go:59`, `audit.go:85-113` | **Own design pass — highest severity.** No head file, no `fsync`, `mkdir` spinlock (§3.3). It needs the three REL-5-class defects fixed *before* a MAC is meaningful; a keyed chain with no head still truncates silently. |
| `alertcase` | `types.go:140`, `:181`, `store.go:548-565` | **Own design pass.** Hashes via `HashObject`/`CanonicalJSON` (`alertcase/canonical.go:36-42`), and its head is an ad-hoc `map[string]any` (`store.go:565`) rather than a typed record. Also tenant-scoped, so key custody interacts with ADR-0001. |
| `assistancerag` | `types.go:179`, `:191`, `store.go:451` | **Own design pass.** Same `CanonicalJSON` divergence as `alertcase`; two chains per store. |
| `vendoradapter` | `types.go:100`, `store.go:73` | **Own design pass.** Tenant provenance was only just settled by ADR-0006; sequencing after that work, not alongside it. |
| `revieworchestrator` | `types.go:68` (`PreviousHash`), `audit.go` | **Own design pass.** Different field naming and record shape; needs its own canonical-form decision. |
| `updatemanager` | `types.go:183`, `audit.go:22-46` | **Own design pass.** `sha256JSON`, and `EventID` is derived from the digest prefix (`audit.go:46`), so changing the digest changes identifiers — a migration concern the others do not have. |
| `productionops` | `types.go:91`, `postgres.go` | **Own design pass.** Deployed (`policy.json:150-155` lists `platform-ops`), so it is the only sibling with a live write path and should be sequenced first among them. |
| `screeningledger` (external) | `external_audit.go:37-74` | **Rides on `activationpromotion`.** `LoadExternalAuditDirectory` verifies *that* package's chain shape (`phase8fAuditEvent`, `:23-35`); it adopts whatever `activationpromotion` adopts. |

**Count reconciliation.** The register says "`audit.go` + 13 sibling stores"
(`docs/backlog/issue-register.md:102`). Ten distinct chain-bearing packages are enumerable by
`grep -rln "previous_event_sha256\|previous_audit_sha256\|previous_hash"`; the register's 13 counts
individual stores, several packages carrying two chains each (`screeningledger`, `alertcase`,
`assistancerag`). The discrepancy is one of counting granularity, not a missing package. Per
CLAUDE.md — never enumerate targets by inference — an adopting PR must work from the table above,
not from a re-derived grep.

## 8. Automation (D6)

A verification mechanism nobody runs is the silent-absence bug this ADR exists to remove, one level
up. ADR-0001 §8 made exactly this argument (`docs/adr/0001-tenant-isolation.md:499-501`) about
`run-ci.sh` printing `SKIP` when `OWL_TEST_DATABASE_URL` is unset: "A control that runs only when an
optional environment variable happens to be set is the same silent-absence bug this ADR exists to
fix, one level up." That skip is still there, now at `scripts/ci/run-ci.sh:63-67` — ADR-0001 cited it
at `:60-63` and the lines have since drifted, which is itself a small argument for gates that fail
rather than print. §1.1 shows
`screening-ledger verify` is in a weaker position still — it runs only when a human types it.

**This ADR specifies the mechanism. It does not wire the gate**, because CLAUDE.md Boundaries put
gate-script changes in their own reviewed PR. The obligation is named here so it cannot be dropped:

1. **Gate PR** — makes anchor verification runnable and non-skippable in CI, and provisions whatever
   it needs. The §7.1 case 7 `TRUNCATE` test must not land behind the existing
   `OWL_TEST_DATABASE_URL` skip, or it inherits the defect ADR-0001 §8 already identified.
2. **Implementation PR** — D1 key hierarchy, D2 keyed chain, D3 anchor and triggers, D4 migration,
   §7.1 tests. Cites this ADR.
3. **Adoption PRs** — one per sibling, per §7.2's triage.

SEC-7 does not close until a deliberately forged chain fails a CI run that nobody chose to invoke.

## 9. Discarded-error disposition

Explicit, because silence here is how the SEC-10 follow-ups got missed twice.

**`external_audit.go:62` — in scope for the implementation PR.** It sits on a chain *verification*
path: `LoadExternalAuditDirectory` re-marshals a `phase8fAuditEvent` to recompute its digest
(`:60-66`). It cannot fail in practice — the struct's only `any` values (`Payload map[string]any`,
`:32`) came from `json.Unmarshal` at `:57`, so they are JSON-native by construction — and it fails
closed if it ever did, since a nil `canonical` produces a digest that will not match `expected`. The
defect is diagnostic: a marshal failure would be reported as `"%s checksum mismatch"` (`:65`),
misattributing a code fault to evidence tampering, which on this particular code path is precisely
the wrong answer to give an operator. Folded into the implementation PR because that PR touches this
verifier anyway.

**`redact.go:56` — out of scope as an error fix, in scope as a key fix.** The discarded error is
SEC-10 cleanup on the export path, not the chain, and the same "cannot fail in practice" reasoning
applies (`value` is decoded from JSON at `redact.go:13-17`). Its *key* handling is a
different matter and is fixed here by D1 (§5.1). Splitting it this way is deliberate: the error
discard is cosmetic, the key reuse is not, and bundling them would obscure which one mattered.

**Newly identified, not previously tracked — `replay.go:52` and `replay.go:160` discard the entire
`AppendAudit` error.** Both are `_, _ = s.AppendAudit(...)`. A `replay` or an `export_bundle`
operation can therefore fail to append its audit entry and still report success to the operator —
the audit chain silently misses an event that did happen. This is omission-from-the-chain by
non-adversarial means: the same class of harm SEC-7 addresses, reached without an attacker. It is
**named here as a SEC-7-adjacent follow-up and deliberately not swept into this ADR's scope**, since
it is an error-handling fix in SEC-10's family and deserves its own issue rather than being smuggled
into a design change. `replay.go:207` correctly returns its error (`:208`), which shows the
discarding at `:52` and `:160` is an inconsistency rather than a considered choice.

**No action — six sites that marshal types which cannot fail:** `store.go:165` (`Head`), `:289`
(`map[string]string`), `:308` (`SnapshotEnvelope`), `:439` (values from `json.Unmarshal`);
`replay.go:72` (`map[string]any` of `[]string`), `:201` (`SnapshotEnvelope`). Listed so a future
sweep does not have to re-establish that they are benign.

## 10. Accepted risks and non-goals

**R1 — a fully compromised operator still forges.** An adversary holding both `R` and `K_anchor`,
able to act as both the appending and the anchoring role, rewrites history completely and no
mechanism in this ADR detects it. This is the residual the register asked to be stated honestly
(`docs/backlog/issue-register.md:249`), and it is inherent: without an external timestamping
authority (§5.3, rejected with a re-entry condition) the operator is in the trust base. What this
ADR buys is that forgery now requires two custody domains instead of one filesystem write.

**R2 — the anchor is only as frequent as its invocation.** History between the newest anchor and the
present is protected by the MAC alone, so a key-holding adversary can rewrite that window. Anchor
cadence is therefore a security parameter, not an operational preference, and §8's automation is what
keeps the window bounded. Until the gate PR lands, the window is unbounded.

**R3 — `SECURITY.md` must not overclaim.** `SECURITY.md:5` currently lists "audit integrity" among
priority report categories and makes no tamper-proofing claim, so nothing there is false today. The
register names revised `SECURITY.md` language as part of this deliverable
(`docs/backlog/issue-register.md:249`); the language that becomes warranted after implementation is
that the ledger is *tamper-evident against a party with storage write access*, with R1 stated. It
must not say tamper-proof, and it must not say anything at all until the mechanism actually ships —
a security policy describing a control that is still only proposed is itself a silent-absence bug.
The edit belongs to the implementation PR.

**R4 — this ADR does not touch `reviewauth`, which the register lists first.** §3.3 and §7.2 give
the reasoning and the triage. `reviewauth`'s store is the more broken one on three of four axes and
is deployed behind `platform-api`; its own pass should be sequenced next, not left to inference.

**R5 — no permission model is introduced.** `internal/reviewauth`'s `resourcePermissions`
(`registry.go:189-205`) is the repository's closed-set permission table, and SEC-11 (PR #102) has
just established the maintenance obligation attached to it. It is deliberately **not** extended
here: `screeningledger` is an operator-invoked CLI with no reviewauth dependency
(`grep -rn "reviewauth" internal/screeningledger/ cmd/screening-ledger/` returns nothing), so a
`ledger.verify` or `ledger.anchor` permission would have no enforcement point and would be a control
that looks installed and does nothing. The access boundary in §5 is OS-level file ownership and
Postgres role identity, which are the boundaries that actually exist on this path. **Re-entry
condition:** if chain verification or anchoring is ever exposed through the review console, it gains
entries in `resourcePermissions` — the existing table, not a parallel authorization concept — and
that table's documented maintenance obligation applies.

**R6 — §3.2's two defects are inherited, not introduced.** The missing `TRUNCATE` triggers and the
swallowed audit conflict exist today and are not caused by this change. D3 fixes the triggers because
an anchor whose sibling tables can be truncated is half a control. The `ON CONFLICT DO NOTHING` on
`PersistAudit` (`postgres.go:200`) is **not** fixed here — it belongs with SEC-5's idempotency
conflict work, which already owns the "catch `23505` and surface it" pattern for this schema.

## Consequences

**Positive.** The ledger stops being forgeable by anyone who can write its directory, which is the
first time any chain in this repository has had a guarantee that survives an adversary rather than
an accident. The key hierarchy retires a raw-key reuse that had a caller-supplied MAC oracle on an
externally-shared artifact — a weakness that existed independently of SEC-7 and would have survived
it. The Postgres mirror gains the `TRUNCATE` protection its immutability triggers have always
implied and never had. And the repository gets a written triage of ten sibling chains, so the next
nine passes start from a decision instead of a survey.

**Negative.** A second key enters custody, and `K_anchor` has no rotation story in this document —
one more secret to lose. Redaction pseudonyms break linkability across the cutover (§5.1), free today
and never free again. The chain format changes, so the committed fixture and any `v1` ledger become
frozen historical records verifiable only under the weaker guarantee — this is the honest outcome,
but it does mean the system will carry two verification paths permanently. Anchoring introduces a
Postgres dependency on a code path that is currently pure filesystem, so `verify` on a host with no
database becomes a partial check that must say so rather than returning `ok`. And nine sibling
chains remain unkeyed after this lands, which means "the audit chain is tamper-evident" will be true
of exactly one package and must be said that precisely.

**Neutral but worth stating.** Nothing here makes `screening-ledger` deployed, scheduled, or reached
by live traffic. It is not in `runtime_executables` (`policy.json:150-155`), its event chain has no
production writer (§1.2), and the entire body of real chain data in this repository is one fixture
event. SEC-7 closes the gap between what the ledger claims about its own history and what it can
prove — it does not put any history into it. That is the same closing caveat ADR-0002, ADR-0003, and
ADR-0006 all end on, and for the same reason.
