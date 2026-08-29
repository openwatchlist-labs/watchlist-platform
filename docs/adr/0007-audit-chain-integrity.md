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

Two chains share one store directory, and one verifier entry point checks both. (Stage 3 note: after
D3/D4 landed, "checks both" no longer implies "protects both equally" — see the reworded closing
paragraph of this section, and R7 in §10.)

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

**One entry point checks both chains, with materially different guarantees.** `Store.Verify` calls
`s.VerifyAudit()` (now `verifyAuditLocked`) before returning, so anything that runs `Verify` runs
both — that part was true when this ADR was drafted and remains true. What changed once D3's anchor
cross-check landed (Stage 3, `Store.VerifyAnchored`) is that the two chains stopped being checked
*equally*: the event chain is verified against the anchor, the audit chain is not (§10 R7). One
function call, two different guarantees — the original phrasing here ("covers both") read as parity
that no longer exists and, for the audit chain specifically, never will under this design.

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

### 6.1 Correction found implementing D4 (Stage 3)

Recorded here rather than silently worked around, in the same spirit as §3.4: checked against the
tree and git history at implementation time, not assumed from this ADR's own text.

**The premise above — "the `v1` copy is retained beside it" — was already false by the time Stage 3
began.** Stage 1 (PR #106, commit `9661a5a`) regenerated `test/fixtures/screening-ledger/state/`'s
sole event and `head.json` **in place** under the new D2 HMAC scheme, while leaving `schema_version`
at `openwatchlist.screening-ledger-event.v1`. Stage 1's own commit message says so plainly: "D4 (the
v1/v2 genesis-anchor bridge) is next stage, so this PR regenerates the one committed fixture ... in
place under the new scheme rather than attempting a migration bridge here." The practical effect:
by the time Stage 3 read the fixture, its one `v1`-labeled event already carried an HMAC digest
(`event_sha256: a029ec78d93f...`), not the genuine pre-D2 plain-SHA256 digest
(`855cf134fb8eb40d...`) the label claimed. Strong data was sitting under a weak-guarantee label —
the opposite error from the one this ADR's Migration section warns against (§6's opening: retroactive
keying "would produce a chain that *looks* as though it had been protected all along"), but still an
inaccuracy this ADR's own honesty standard does not permit leaving uncorrected.

**Resolution, decided with the operator rather than assumed:** the fixture's one event is relabeled
`v2` (its digest recomputed under the new label, since `schema_version` is itself part of the hashed
JSON) rather than left mislabeled `v1` — strong data does not get called weak. A genuine,
historically-sourced frozen-`v1` fixture was built instead from git history: commit `03c0f04` (this
repository's clean-restart baseline import, an ancestor of `9661a5a`) holds the real pre-D2 digest,
copied byte-for-byte into `test/fixtures/screening-ledger/frozen-v1-synthetic/` (see that directory's
own `README.md`) rather than hand-computed, so `Verify`'s frozen-prefix code path (§6 points 5–6) has
real coverage against an actual unkeyed digest, not only data fabricated inline in a test. That
fixture is explicitly labeled synthetic test data, not a claim of preserved production history —
this repository has never had live traffic (§2), so no real production data was ever at stake in
either Stage 1's regeneration or this correction. A real `v2` genesis record was then appended after
the relabeled event via the ordinary, unmodified `Append` path (§6 point 3's predecessor-linkage
happens automatically, since genesis is simply the next entry), followed by an audit-chain entry
documenting the migration and a genesis anchor. **This repository's real ledger therefore has an
event-chain frozen-prefix length of zero** — there is no genuine weaker-guarantee history left to
report, only the relabel-and-continue-forward path above. The general frozen-prefix mechanism (D4
points 5–6) is still built and tested, for the benefit of any future ledger — or ADR-0007 §7.2
sibling — that has genuine pre-D2 history to bridge; it is simply not exercised by this ledger's own
data, only by the synthetic fixture built for that purpose.

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

**R7 — the audit chain has no anchor-level protection against an adversary holding `K_chain`; only
the event chain does.** `screening_ledger_anchor.sequence` is the event chain's sequence (§5.3,
migration `016`'s schema comment); `audit_sha256` is captured once, at anchor time, as supplementary
evidence, not cross-checked against the live audit chain by `Store.VerifyAnchored`. The practical
consequence: the exact adversary §5.2/§5.3 name as the residual the anchor exists to close — a party
who holds `K_chain` but not `K_anchor` — can rewrite any audit entry (`postgres_replicated`, `replay`,
`export_bundle`, `purge_expired`) and re-MAC everything downstream under the real key, and
`VerifyAnchored` will report `"anchor_status":"verified"` regardless, because it only ever compares
the anchor's `event_sha256` against the file chain. This is the same exposure the audit chain had
before D3's anchor mechanism existed at all — D2's HMAC is the entirety of its protection, then and
now. This is not fixed here: extending the anchor to cover a specific audit sequence would reopen the
`sequence`-column schema decision this stage made, which is disproportionate to what a three-stage
implementation should still be revising. Instead, `AnchorVerifyResult.AuditAnchorCoverage` (Go) and
`"audit_anchor_coverage":"supplementary_only"` (the CLI's `verify`/`status` JSON) carry this fact into
the same output an operator reads `"anchor_status":"verified"` from, found and required by a security
review of this stage rather than assumed acceptable to leave in code comments alone.

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

## Addendum 1: SEC-7 reopened -- the schema-version downgrade break and the externally-authenticated verification design (2026-08-19)

- **Status:** Proposed
- **Trigger:** two independently-produced audits -- different methodology (one against a local
  clone, one against GitHub-hosted read access) -- each found that the shipped SEC-7
  implementation's security claim does not hold, and reached the same verdict by different
  evidence paths. **SEC-7 is reopened.** This addendum is the repair design; it does not
  re-litigate whether the break is real, and it does not re-prove it. The public claim is already
  contained: `README.md:93-97` states that "external anchor enforcement is currently undergoing
  security requalification" and that "the previously stated anchored-integrity guarantee should
  not be relied on until requalification completes" (PR #130).
- **Scope:** a pure addition. Nothing above this section is edited -- not D1-D7, not §3.4, not
  §6.1, not R1-R6. R7 is the single prior decision whose *disposition* changes, and AR7 below
  states the new one explicitly rather than editing §10 in place. Decision numbering continues
  this ADR's own convention at **D8**; risk numbering at **R8**.
- **Verification basis:** every claim below was checked against the working tree at
  `f135210f8bf4f466a8ad22976a0087efd78c5a07` (tip of `main` after PR #130 merged), the same
  standard §Context and every prior correction note set for their own claims. Where an audit's own
  account of a finding turned out to be imprecise or incomplete, this addendum says so and
  restates it from the code rather than repeating it. Findings retain the labels the reopening
  brief assigned them (F1, F1b, F3, F4, F5, F6); F7, F8 and F9 are new and were found while
  verifying the others. There is no F2 in this addendum's brief and none is invented here.
- **A note on drift, since this document has now been wrong about a line number twice.**
  §8 cites the `run-ci.sh` skip at `:63-67`; it is at `:65-69` at this commit. §5.1 cites
  `go.mod:3` as `go 1.26.5`; it is `go 1.26.6`. Neither changes any argument, and neither is
  edited above. They are recorded because §8's own remark -- that a drifting citation "is itself a
  small argument for gates that fail rather than print" -- has now been demonstrated a third time.

### Addendum 1 context: what actually broke, and why the shipped test did not catch it

D2 made the chain digest a keyed MAC. D4 made `v1` (pre-D2, unkeyed) entries verifiable as a
frozen prefix so genuine pre-D2 history would not have to be retroactively re-keyed -- a decision
this ADR argued for on integrity grounds and still stands behind (§6, opening paragraph). The
defect is not in either decision. It is that the implementation lets the **verified data choose
which of the two algorithms verifies it**.

`verifyLocked` selects the digest function by switching on `p.event.SchemaVersion`
(`internal/screeningledger/store.go:257-274`) -- a plain JSON field inside the ledger directory,
which §2's threat model already grants the adversary write access to. `EventSchemaV1` routes to
`legacyHashEvent` (`store.go:481-488`): `event.EventSHA256 = ""`, `json.Marshal`, `digestHex` --
plain `sha256.Sum256`, no key, publicly recomputable by anyone holding the source.

The guard that was supposed to prevent exactly this is `if sawV2` (`store.go:264`), and `sawV2` is
set only inside the `EventSchemaV2` branch (`store.go:270`). It therefore detects a **transition**
from v2 to v1 and nothing else. A chain in which *every* entry is labelled `v1` never sets `sawV2`,
never trips the guard, and verifies end to end under the unkeyed algorithm. `verifyAuditLocked`
has the identical structure -- `sawV2` declared at `audit.go:86`, set only at `:109`, checked only
at `:103`.

The head files do not help. `verifyLocked` compares `head.Sequence` and `head.EventSHA256`
(`store.go:294`) and never `head.SchemaVersion`; `verifyAuditLocked` compares the same two fields
(`audit.go:127`). `headSchemaFor` (`store.go:307-312`) derives the head's label *from the entry*,
so a uniformly-relabelled chain produces a `HeadSchemaV1` head that matches by construction.

**Why the shipped D5 proof passed anyway, which is the part worth carrying forward.**
`TestForgeAndDetect_SEC7D5LoadBearingProof` (`internal/screeningledger/forge_test.go:77`) does
everything §7.1 case 1 asked: it builds a chain under the pre-D2 formula, tampers the middle entry,
recomputes every downstream digest, rewrites the head, confirms the result is internally perfect
under the old scheme, and asserts the real `Store.Verify` rejects it. It sets
`SchemaVersion: EventSchemaV2` on every forged entry (`forge_test.go:89`) and `HeadSchemaV2` on the
head (`forge_test.go:152`). That forces the HMAC branch, so `Verify` rejects, so the test passes.

One field's value is the entire distance between the shipped test and the exploit. The test proves
that *the v2 branch* is keyed. It says nothing about **who chooses the branch**, and the answer is:
the attacker. This is the silent-absence class CLAUDE.md rule 5 names -- a control that looks
installed and does nothing -- reached through a test that was written carefully and still missed it,
which is why D20 below specifies the replacement test's shape rather than leaving it to judgment.

### F1, restated precisely: what the adversary can and cannot do today

The reopening brief asked for the remaining capability to be stated precisely rather than
totalised. Doing that turned up more capability than the brief credited.

**Confirmed, no key of any kind required.** Relabel every event to `EventSchemaV1`, every audit
entry to `AuditSchemaV1`, both head files to `HeadSchemaV1`; rewrite any field of any entry; delete
entries; renumber; re-link `previous_event_sha256`/`previous_audit_sha256`; recompute every digest
with `legacyHashEvent`/`legacyHashAudit`. `Verify` returns success. The audit chain is the softer
target of the two: `verifyAuditLocked` (`audit.go:72-131`) performs no snapshot check at all, so
nothing key-dependent is reachable on that chain under any labelling.

**The one check that survives on the event chain, and F8, which removes it.** `verifyLocked` calls
`verifySnapshot` for both snapshot digests of every entry (`store.go:281`, `:284`), and
`verifySnapshot` decrypts under `s.keys.snap` (`store.go:422`). That is the sole key-dependent
operation reachable on a fully-`v1` event chain, and it is why the brief characterised the
remaining capability as bounded: without `K_snap` the adversary cannot fabricate snapshot
*content*.

**F8 (new).** `verifySnapshot` returns `nil` immediately when `env.PurgedAt != ""`
(`store.go:419-421`). `PurgedAt` is `purged_at` in the snapshot envelope JSON
(`types.go:74`) -- another plain field, in `<ledger-dir>/snapshots/`, in the same directory the
threat model grants write access to. Setting it on every envelope makes `verifySnapshot` return
success without decrypting anything, which removes the last key-dependent check from the event
chain's verification path. `decryptSnapshot` is never reached (`crypto.go:63-65` would reject a
purged envelope anyway, which is the correct behaviour for the retention path this field exists
for -- the defect is that a verification path treats "purged" as "checked").

The honest statement, therefore, is stronger than the brief's: **under F1 alone the adversary's
remaining capability is bounded but real** -- deletion, renumbering, re-linking and rewriting of
every non-snapshot field all pass, orphaned snapshots are never detected, and only snapshot content
resists. **Under F1 combined with F8 the bound is gone**, because the adversary marks every
snapshot purged and the verifier stops asking. Both must be closed; closing F1 alone leaves a
verification path whose only cryptographic content is optional at the adversary's discretion.

**Empirical status.** The audits confirmed against the real committed fixture that the legacy
digest is publicly recomputable without the chain key. That is not re-derived here. What is
verified here is that the code structure producing it is unchanged at `f135210`:
`store.go:257-274`, `store.go:481-488`, `audit.go:100-113`.

### The other confirmed findings, verified against this commit

**F1b -- the anchor has no operational write path.** `AnchorSink` (`anchor.go:90-93`) and
`WriteAnchor` (`anchor.go:130-141`) exist and are correct. Every caller in the tree is a test:
`anchor_pgx_test.go:73` and `:85`; `verify_anchor_pgx_test.go:88`, `:93`, `:152`, `:157`, `:216`,
`:221`. Non-test callers: zero. The CLI's subcommand set is
`migrate|status|verify|sync|replay|export|purge|import-audit` (`cmd/screening-ledger/main.go:20`,
switch at `:28`) and contains no anchor subcommand. This is acknowledged in-code
(`anchor.go:127-129`) and by §8's deferral of cadence to a gate PR. The consequence for the
reopening is specific: the mechanism §5.3 designed to catch precisely the F1 forgery cannot catch
it, because in a shipped system there are no anchor rows for it to disagree with. D3 is not
partially wired. On the write side it is not wired.

**F3 -- `SchemaSQL` never creates the anchor table.** `SchemaSQL` (`postgres.go:301-333`) creates
seven tables (`:302-308`) and installs their row-immutability triggers (`:310-315`) and TRUNCATE
guards (`:326-333`). `screening_ledger_anchor` is not among them. `Migrate` executes only
`SchemaSQL` (`postgres.go:89`) and is called from `migrate` (`main.go:31`), `sync` (`main.go:85`)
and `import-audit` (`main.go:145`) -- a bootstrap path explicitly documented as independent of
`db/migrations/` ever having run (`postgres.go:319-325`). A database provisioned by
`screening-ledger migrate` alone therefore has zero anchor protection, silently. The guard test
that exists to catch exactly this divergence enumerates the same seven tables and omits the anchor
table (`postgres_schema_test.go:25-33`), so the gap is invisible to CI. `LatestAnchor`
(`postgres.go:219-228`) on such a database fails with an undefined-relation error rather than
reporting `absent` -- which is accidentally fail-closed today and must be made deliberately so.

**F4, refined -- the coupling is unenforced, and the local runner is silent.** The brief's
refinement is correct and confirmed. GitHub Actions genuinely does provision the anchor role and
run the negative tests: `ci.yml:40`, `:41` and `:47` set `OWL_TEST_DATABASE_URL`,
`OWL_MIGRATOR_DATABASE_URL` and `OWL_LEDGER_ANCHOR_DATABASE_URL` at job level, and `ci.yml:87-92`
invokes `provision_test_roles.sh grant-anchor-ownership` before `ci.yml:93-95` runs `run-ci.sh`.
The gap is that none of this is enforced. `run-ci.sh` -- what a developer runs locally -- names
none of the three variables; it gates only `check_sql_invariants.sh` on `OWL_TEST_DATABASE_URL`
(`run-ci.sh:65-69`), printing `SKIP: SQL security invariants (OWL_TEST_DATABASE_URL not set)` and
falling through to `PASS: OpenWatchlist clean-restart CI` (`run-ci.sh:71`) at exit 0. The SEC-7
anchor suite reaches CI only incidentally through `go test ./...` (`run-ci.sh:35`) and self-skips
via `t.Skip` (`anchor_pgx_test.go:49`, `postgres_pgx_test.go:34`). Nothing asserts `ci.yml` still
sets the variables: `verify-clean-restart.sh:31` checks only that the file exists, and
`legacy_exclusion_gate.py:247-254` checks only for `pull_request_target` and `persist-credentials`.

**One thing the brief did not name, found while checking it, and worse than the skip itself.** The
single most load-bearing negative test -- `TestSEC7LedgerWriterCannotInsertAnchor`
(`anchor_pgx_test.go:109`), whose own doc comment says that "if this test ever passes with
`err == nil`, the anchor proves nothing" (`anchor_pgx_test.go:103-108`; the phrase wraps across
`:107-108`, so it does not match a single-line grep) -- is gated on `requireMigratorDSN(t)`
(`anchor_pgx_test.go:110`), **not** on the `requireAnchorDatabaseURL` its siblings use
(`anchor_pgx_test.go:45-52`, reading `OWL_LEDGER_ANCHOR_DATABASE_URL` at `:47` and skipping at
`:49`; used at `:70` and `:142`).

**The gate is invisible to a grep of this file, which is part of why it survived review.**
`requireMigratorDSN` is declared in a *different file of the same package* --
`postgres_pgx_test.go:30-36` -- where it reads `OWL_MIGRATOR_DATABASE_URL` (`:32`) and calls
`t.Skip` (`:34`). The string `OWL_MIGRATOR_DATABASE_URL` therefore does not appear anywhere in
`anchor_pgx_test.go`; only the anchor variable does. Grepping the test's own file for the variable
that actually gates it returns nothing, and the file reads as correctly gated.

The consequence: an environment that sets only `OWL_LEDGER_ANCHOR_DATABASE_URL` runs the positive
test (`anchor_pgx_test.go:69`) green and silently skips the proof of separation. Both files are
byte-identical between `f135210` and this branch's tip, so this is not drift.

**F5 -- `sync` mirrors without verifying.** `sync` (`main.go:81-104`) runs
`ListEvents` (`:86`) -> `LoadSnapshot` (`:93`, `:95`) -> `Persist` (`:97`) -> `MarkReplicated`
(`:98`) -> `AppendAudit` (`:99`) -> `PersistAudit` (`:101`), then reports `"status":"ok"`
unconditionally (`:104`). No `Verify`, `VerifyDetail`, `VerifyAudit` or `VerifyAnchored` appears
anywhere on the path. `NewStore`'s `Recover` (`store.go:42`, `store.go:153-179`) replays a pending
write and performs no chain check. `ListEvents` (`store.go:350-368`) does no digest checking and
silently swallows per-file read and unmarshal failures (`store.go:361-365`). The consequence is
specific to this schema: forged rows land in tables carrying `BEFORE UPDATE OR DELETE` immutability
triggers (`postgres.go:310-315`), so once mirrored they cannot be corrected, annotated or removed
by the same identity that wrote them. `import-audit` (`main.go:142-148`) has the same shape.

**F6 -- the anchor writer is the anchor table's owner.** `provision_test_roles.sh:130-132` runs
`GRANT owl_ledger_anchor TO owl_migrator`, `ALTER TABLE screening_ledger_anchor OWNER TO
owl_ledger_anchor`, `REVOKE owl_ledger_anchor FROM owl_migrator`. The ownership transfer makes the
anchor-writing role the table owner, which contradicts §5.3 point 2's requirement that it hold
"`INSERT` on this table and nothing else" (`0007:378-381`) and the code's own restatement of that
as fact (`anchor.go:83-85`, "write-only in privilege (INSERT only -- no SELECT/UPDATE/DELETE)"; and
`postgres.go:213-215`). As owner it holds implicit full DML plus DDL -- including
`ALTER TABLE ... DISABLE TRIGGER` and `DROP TRIGGER screening_ledger_anchor_no_truncate`, i.e. the
power to remove the very guard `015` installs. The script's postconditions (`:148-167`) prove that
`owl_migrator` cannot INSERT and that `owl_migrator` has SELECT; they contain no assertion about
what `owl_ledger_anchor` cannot do, and structurally cannot, having just granted it everything.
The test suite demonstrates the read half incidentally: `anchor_pgx_test.go:91-96` connects on the
anchor DSN and successfully runs `SELECT anchor_mac FROM screening_ledger_anchor`.

**F7 (new) -- the anchor table has no row-immutability trigger.**
`015_screening_ledger_anchor.sql` installs the TRUNCATE guard (`015:48-49`) and only that. There is
no `BEFORE UPDATE OR DELETE ... FOR EACH ROW` trigger on `screening_ledger_anchor` in `015`, in
`016`, or in `SchemaSQL` -- while all six other protected tables have had one since before this ADR
was drafted (`postgres.go:310-315`). Combined with F6 this is not a theoretical gap: the role that
writes anchors can `UPDATE` an existing anchor row to agree with a forged chain, or `DELETE` it and
write a new one, without touching TRUNCATE and without dropping a trigger. An external commitment
whose own writer can rewrite it in place is not a commitment.

**F9 (new) -- `ledger-id` is the HKDF salt, and its default makes the salt a shared constant.**
`ensureLedgerID` (`store.go:447-473`) reads `<ledger-dir>/ledger-id` (`:452`), errors if a
configured value disagrees with the durable file (`:454-456`), and otherwise writes the requested
value or a directory-derived fallback (`:461-470`). `NewStore` passes the resolved value to
`deriveChainKeys` (`store.go:34`), where it becomes the HKDF salt for all three subkeys
(`chainkey.go:26`, applied at `:27`, `:31`, `:35`). The CLI supplies the bare literal
`"screening-ledger-cli"` as the default (`main.go:157`), which `ensureLedgerID` then writes durably
into the ledger directory on first use. Two consequences:

1. **Chain identity is not external today.** The only tie between a ledger and its identity is a
   file inside the ledger directory plus a flag value the operator has to already know. The
   mismatch guard at `store.go:454-456` is real (`main_test.go:171-174` proves it), but it can only
   catch a rewritten `ledger-id` file if the operator passes a `--ledger-id` they remember; the
   default silently accepts the literal. This is the gap D14 below closes rather than letting
   disappear.
2. **`chainkey.go`'s stated salt property is false on the default path.** Its comment
   (`chainkey.go:9-11`) and §5.1's identical claim (`0007:277-278`) say the salt "binds a
   derivation to the ledger it serves, so two ledgers sharing a root secret do not share subkeys."
   Every CLI-bootstrapped ledger that does not pass `--ledger-id` pins the same salt, so two such
   ledgers under one root secret derive **identical** `K_snap`, `K_redact` and `K_chain`. The
   committed fixture avoids this only because it carries an explicit id
   (`test/fixtures/screening-ledger/state/ledger-id` is `screening-api-v8g-example`) and the tests
   pass it (`main_test.go:90`, `:107`).

**The fail-open reporting that lets all of this stay quiet.** `AnchorStatusUnavailable`
(`anchor.go:214`) and `AnchorStatusAbsent` (`anchor.go:221`) both return a `nil` error. The CLI
maps anything other than `verified` to `"status":"partial"` (`main.go:64-67`) and still exits 0 --
`output` (`main.go:238-242`) writes JSON and returns; `os.Exit(1)` is reachable only through `must`
(`main.go:248-251`). When `--postgres-dsn-env` is absent the CLI does not call `VerifyAnchored` at
all; it hand-builds an `AnchorStatusUnavailable` result at `main.go:55`. The committed expectation
for the happy path is exactly this: `"status":"partial"` with `"anchor_status":"unavailable"` at
exit 0 (`main_test.go:107-122`). A scripted caller checking the exit code cannot distinguish "fully
anchored and verified" from "no anchor was checked at all." Note also that there is no
`AnchorStatusFailed`: a genuine tamper detection and a connection failure are both bare `error`
returns from `VerifyAnchored` (`anchor.go:210-242`), distinguishable only by error string.

**Deployment shape, re-confirmed rather than assumed.** §2's "explicitly not assumed" still holds
at this commit: `screening-ledger` is absent from `runtime_executables`
(`scripts/deployment/r2-4/harness/config/policy.json:150-155`, which lists `platform-api`,
`platform-ops`, `container-healthcheck`, `catalog-mmap`). The event chain still has no production
writer. There are no anchor rows anywhere in any environment, because nothing writes them (F1b).
**Every schema change, MAC-input change and key-material change this addendum proposes is therefore
free at this moment and never free again** -- the same argument §6 made about the migration, and
the reason this design does not contort itself to preserve compatibility with data that does not
exist.

### D8. The externally-authenticated invariant, stated as facts the ledger cannot supply

The structural error behind F1 is that `Verify` derives its own acceptance criteria from the
artifact it is checking. Every parameter of the check -- which algorithm, where the genesis
boundary sits, which ledger this is, how long the chain should be -- is read out of the same
directory the threat model gives the adversary. Fixing the `sawV2` guard alone would not fix that;
it would fix one instance of it.

Verification must consume the following facts from outside the ledger directory. They are numbered
EA1-EA5 so implementation and tests can refer to them individually.

| | Fact | What replaces today's inference |
|---|---|---|
| **EA1** | **Minimum accepted schema version, per chain** (`min_event_schema`, `min_audit_schema`, `min_head_schema`) | Today the entry names its own algorithm (`store.go:257`, `audit.go:101`). Under EA1 an entry below the floor is rejected outright, whatever it calls itself. |
| **EA2** | **Genesis boundary as a sequence number** (`genesis_event_sequence`, `genesis_audit_sequence`; `1` means "no v1 prefix is permitted at all") | Today the boundary is inferred from `sawV2` (`store.go:264`, `audit.go:103`) -- i.e. from the data under test. Under EA2 an entry below the genesis sequence **must** be `v1`, an entry at or above it **must** meet the EA1 floor. Neither branch is reachable by relabelling, because the label is no longer what selects the branch. |
| **EA3** | **Chain identity** (`ledger_id`) | Today it is a file inside the ledger directory (`store.go:451`) whose default is a shared literal (`main.go:157`) -- F9. Under EA3 the authenticated value is the one the verifier trusts, and the on-disk file must agree with it or verification fails. |
| **EA4** | **Expected anchored head** (sequence and digest, committed before the fact by an identity the appending process is not) | Today nothing writes one -- F1b. This is the only one of the five that D3 already designed a home for. |
| **EA5** | **Trust-root identity** -- the fingerprint of the key that authenticates EA1-EA3 | Nothing today. Named explicitly because a chain of "externally authenticated" facts has to terminate somewhere, and naming where it terminates is this ADR's own standard (§10 R1). |

EA1 and EA2 together are the F1 fix. EA1 alone is not sufficient: a floor with no boundary fact
cannot express a legitimate frozen `v1` prefix, and D4 is not being withdrawn. EA2 alone is not
sufficient either: without a floor, a future `v3` regression would be a downgrade the boundary
check would not see. They are one decision with two fields.

EA5 is not decoration. Without it the verifier has an authenticated policy and no way to say
*whose* policy, which is the same category of gap as F9 -- an identity that looks external and is
not.

### D9. Where the facts live: investigated, and layered (option (c)), not either alone

The reopening brief asked for this to be investigated and argued rather than assumed. All three
options were checked against this system's actual deployment shape, which was re-confirmed above
(`policy.json:150-155`; no production writer; zero anchor rows).

**Option (a) -- the existing anchor table alone, now actually wired up.** Genuinely attractive: it
reuses `015_screening_ledger_anchor.sql`, `AnchorSink` (`anchor.go:90`), `LatestAnchor`
(`postgres.go:219`), `VerifyAnchored` (`anchor.go:208`) and a role-separation design that is
already written down; and `anchor_mac` already covers `ledger_id` (`anchor.go:31-34`), so it
authenticates EA3 with no new machinery. **Rejected as the sole mechanism**, on three grounds that
are specific to this repository rather than general:

1. **It couples the F1 fix to Postgres reachability.** F1 is a defect in the pure-filesystem
   verification path, and the pure-filesystem path is the one this repository actually exercises:
   the committed happy-path test runs `verify` with no DSN (`main_test.go:107`), `run-ci.sh` names
   no ledger DSN at all, and the CLI's no-DSN branch skips `VerifyAnchored` entirely
   (`main.go:52-56`). Putting the schema floor behind a database means the check that matters most
   is absent from every environment that does not have one.
2. **F3 means the table may not exist even when Postgres is reachable.** A database bootstrapped
   through `screening-ledger migrate` has no `screening_ledger_anchor` (`postgres.go:301-333`).
3. **It places the F1 defence inside the adversary's stated reach.** §2 puts "a party that can
   write the Postgres mirror" in scope (`0007:120-121`). The only barrier between that party and
   the anchor table is role separation -- which F6 and F7 show is not currently real, and which
   D17 and D16 below have to rebuild before the anchor can carry weight it does not carry today.

**Option (b) -- a separate external artifact alone.** Also attractive: no database dependency, no
secret required to check the most important property, and it fits a binary that is not deployed and
has no network egress (§5.3's rejected-alternatives reasoning still applies unchanged).
**Rejected as the sole mechanism** because EA4 is not the same kind of fact as EA1-EA3. The
anchored head changes on every append; a file that must be rewritten at that cadence, by the
appending process, reintroduces exactly the custody problem it exists to solve, and it cannot
provide the property EA4 actually needs -- a commitment written **before the fact**, by a
**different identity**, into storage the appending identity **cannot rewrite**. A file cannot be
append-only against its own writer. A role-isolated table with an immutability trigger can.

**Option (c) -- both, layered. Chosen.** The five facts separate cleanly by cadence, and the
separation is not an accommodation, it is the actual structure of the problem:

- **EA1, EA2, EA3, EA5 change once in a ledger's lifetime.** They belong in a signed
  **verification policy** file, stored outside `--ledger-dir`, supplied to the verifier by path.
- **EA4 changes on every anchor.** It belongs in `screening_ledger_anchor`, which already exists
  and finally gets a writer (D12, D19).

Neither substitutes for the other, and stating which attack each stops is the point:

- The **policy alone** stops F1 -- with no database, no network, and no secret in the verifying
  process.
- The **anchor alone** stops truncation, rollback and post-hoc divergence by a `K_chain`-holder --
  which the policy cannot, because a key-holding adversary can produce a chain that satisfies every
  policy fact.

The decisive practical consequence, and the reason this is not over-engineering: **the F1 defence
becomes runnable in `run-ci.sh` unconditionally**, with no Postgres service and no credential.
That is what makes D18's fail-closed local gate achievable by construction rather than by
exhortation. An option-(a)-only design would leave the most important check gated on exactly the
environment variable F4 is about.

### D10. Key custody for the policy artifact: Ed25519 signature, not a MAC

The policy file is **signed with Ed25519** (`crypto/ed25519` -- Go standard library; `go.mod:3` is
`go 1.26.6`, so **no new dependency** and CLAUDE.md rule 1 is satisfied without an exception, the
same basis §5.1 used for `crypto/hkdf`). The verifier holds only the public key.

**Why not a MAC under `K_anchor`, which would be simpler and add no key at all.** Because a MAC
makes every verifier a secret-holder. If checking the schema floor requires `K_anchor`, then
`verify` cannot run without a secret, so CI cannot run it without a secret, so the check ends up
gated on whether a secret happens to be present -- which is F4, reintroduced by the fix for F1. A
signature inverts that: the public half can be committed, distributed, printed and compared freely,
so the EA1/EA2/EA3 check has no precondition at all. The private half never enters the appending
process, the verifying process, or CI.

Custody accounting, stated plainly because §Consequences already charged this design for one extra
secret: this adds a **keypair**, not a secret in any running binary. `R` and `K_anchor` remain the
only values a running process holds. The Ed25519 private key is used at ledger-provisioning time
and at policy-change time, both of which are deliberate, rare, operator-initiated events.

**EA5 in practice.** `verify` prints the SHA-256 fingerprint of the public key it verified the
policy under, in the same JSON an operator reads the status from. The trust root terminates at a
public key the operator supplies out of band; printing its fingerprint is what makes that
termination auditable rather than assumed. R8 states this residual.

Illustrative only -- the implementation PR owns the real shape:

```json
{"schema_version":"openwatchlist.screening-ledger-verification-policy.v1",
 "ledger_id":"screening-api-v8g-example",
 "min_event_schema":"openwatchlist.screening-ledger-event.v2",
 "min_audit_schema":"openwatchlist.screening-ledger-audit.v2",
 "genesis_event_sequence":1,"genesis_audit_sequence":1,
 "allow_unanchored":false}
```

signed over `canonicalJSON` of that object (`crypto.go:102-110`, the helper this package already
has and applies only to snapshot bodies today), with the signature and public key carried in a
sibling field or file. Canonicalisation matters here in a way it does not for the chain digests
(§1's third property): unlike `Event`, this document is authored by hand and by tooling, so its
byte form cannot be pinned to a Go struct declaration.

### D11. Binding the policy to the anchor, and closing R7 in the same schema change

An authenticated policy and an authenticated anchor that do not reference each other can be
recombined: an adversary pairs a stale policy (permissive floor) with a current anchor. Therefore:

- `screening_ledger_anchor` gains **`policy_sha256`** -- the digest of the canonical policy the
  anchor was written under -- and it enters `anchorMAC`'s input (`anchor.go:31-34`, today
  `ledger_id ‖ sequence ‖ event_sha256 ‖ audit_sha256`).
- Verification fails if the anchor's `policy_sha256` does not match the digest of the policy the
  verifier is using. A policy change is therefore a re-anchoring event, which is correct: it is a
  change to what the ledger claims about itself.
- The table also gains **`audit_sequence`**, alongside `audit_sha256`. See AR7 below.

New migration `db/migrations/017_screening_ledger_anchor_policy_binding.sql`, following `015`'s
fail-closed `DO $$ ... RAISE EXCEPTION` preamble style (`015:36-44`) rather than `009g`'s
silently-skipping `IF to_regclass(t) IS NOT NULL THEN` style, per CLAUDE.md.

**This changes `anchor_mac`'s input and therefore invalidates every existing anchor row.** There
are none, in any environment, because nothing writes them (F1b). §6 made this argument about the
fixture migration -- "this is the cheapest this change will ever be" -- and it applies with more
force here, because the count is zero rather than one.

### D12. Fail-closed verification semantics, and the end of silent "partial"

Today `unavailable` and `absent` are both `nil`-error outcomes (`anchor.go:214`, `:221`) that the
CLI reports as `"status":"partial"` at exit 0 (`main.go:64-67`, `main.go:238-242`), and the absence
of a DSN skips the anchor check without ever calling `VerifyAnchored` (`main.go:52-56`). All three
of those are removed.

**Mode `anchored` -- the default, and the only mode reachable without an explicit flag.**
Verification succeeds only when, in order: the policy file is present, its signature verifies under
the configured public key, its `ledger_id` matches the durable `ledger-id` file, every entry
satisfies EA1/EA2, an anchor row exists for this `ledger_id`, its `anchor_mac` verifies under
`K_anchor`, its `policy_sha256` matches, and its committed digests agree with the chain. Result:
`"status":"ok"`, exit 0. **Every other outcome is a verification failure: exit 1.** That
explicitly includes today's `unavailable` (no database configured) and `absent` (database reachable,
no anchor row). "I could not check" and "I checked and it was fine" stop being the same exit code.

**Mode `historical-unanchored` -- explicit, doubly gated, never inferred.** It requires **both**
`--verification-mode historical-unanchored` on the command line **and** `"allow_unanchored": true`
inside the signed policy. Either alone is insufficient. The command-line half means an operator
cannot get the weaker check by omitting a flag; the policy half means an operator cannot
unilaterally downgrade a ledger whose policy owner declared it anchored. EA1 and EA2 are still
enforced in this mode -- it relaxes EA4 only. Output carries `"verification_mode"` on every run,
in both modes, so the field's presence is not itself a signal.

**Supporting changes this requires:**

- Add `AnchorStatusFailed` to `AnchorVerifyStatus` (`anchor.go:156-173`), so a tamper detection is
  distinguishable in the result type from a plumbing error. Today both are bare `error` returns
  from `VerifyAnchored` (`anchor.go:210-242`) separable only by string matching.
- Retire `Store.Verify() (Head, error)` (`store.go:197-205`) as the package's public entry point.
  It discards the report by construction, which is the shape that makes the weaker check easy to
  reach by accident. It has **no non-test callers** at this commit, so this costs nothing now.
- Fix the misattributed error: `main.go:48` loads `K_anchor` via `LoadKey`, which reports
  `"snapshot encryption key is required"` (`crypto.go:31`) when the *anchor* key is missing.
- `LatestAnchor` against a database with no anchor table (F3) must produce a named failure, not an
  undefined-relation error that reads like a connection problem.
- `main_test.go:107-122`'s committed expectation of `"status":"partial"` at exit 0 becomes an
  expectation of failure, and is the smallest visible proof that this decision landed.

### D13. F8: a purged snapshot is not a verified snapshot

`verifySnapshot`'s early `return nil` on `env.PurgedAt != ""` (`store.go:419-421`) is correct for
the retention path and wrong for the verification path. Under this design:

- The set of legitimately purged snapshots is not read from the envelope being checked. A purge is
  already recorded independently in `screening_ledger_retention_tombstone` (`postgres.go:306`,
  written by `screening_ledger_purge_snapshots`, `postgres.go:318`) and locally by `PurgeExpired`
  (`replay.go:194-201`); verification consults that record, not the field the adversary can set.
- Where no independent purge record is available (a filesystem-only verification with no database),
  a purged envelope on an entry the policy expects to be verifiable is a failure in `anchored` mode
  and a counted, reported condition in `historical-unanchored` mode. It is never silent.
- The count of snapshot checks actually performed appears in the verify output, so "every snapshot
  was skipped" cannot look like "every snapshot passed."

This is in scope by the standard §5.1 already set for the `redact.go` key reuse: an existing
weakness that would make the new guarantee false is not adjacent cleanup. EA1 restores the keyed
digest; F8 is the path by which an adversary avoids ever exercising a key at all.

### D14. F9 / EA3: chain identity becomes external, and the shared-salt default is retired

- The authenticated `ledger_id` is the policy's. `<ledger-dir>/ledger-id` must agree with it;
  disagreement is a verification failure, not a silent adoption of the file's value.
- `main.go:157`'s `opts.value("--ledger-id", "screening-ledger-cli")` default is **removed**, not
  changed to a different literal. `--ledger-id` becomes required for a new ledger, or is taken from
  the policy. A default that silently becomes the durable identity **and** the HKDF salt
  (`chainkey.go:26`) is the mechanism by which two unrelated ledgers under one root secret derive
  identical `K_chain`.
- `ensureLedgerID`'s directory-derived fallback (`store.go:464-467`) stays for the library path but
  is no longer reachable from the CLI.
- Existing ledgers that already wrote `"screening-ledger-cli"` durably must be re-identified. R10
  states the cost; at this commit no such ledger exists outside a developer's scratch directory.
- `chainkey.go:9-11`'s comment and §5.1's claim (`0007:277-278`) become true once the default is
  gone. They are not edited here; the implementation PR corrects the comment, and this addendum
  records that they were false on the default path at `f135210` so the correction is traceable.

### D15. F3: `SchemaSQL` reaches parity on the anchor table

`SchemaSQL` (`postgres.go:301-333`) gains `screening_ledger_anchor` -- the `015` table plus `017`'s
columns, the row-immutability trigger from D16, and the TRUNCATE guard -- so a database bootstrapped
through `Migrate` alone (`postgres.go:89`; `main.go:31`, `:85`, `:145`) is not silently
anchor-less. `postgres_schema_test.go:25-33`'s `protectedTables` list gains the anchor table, and
the same test asserts the row-immutability trigger, not only the TRUNCATE guard.

Scope is deliberately the one property, matching the boundary §3.4 already drew (`0007:218-225`):
this is not REL-9's unification of the two schema sources, which remains its own larger problem.
The difference from §3.4's case is that there the divergence was a maintenance finding with a real
consequence; here the divergence removes the entire mechanism.

### D16. F7: the anchor table becomes actually immutable

`screening_ledger_anchor` gains a `BEFORE UPDATE OR DELETE ... FOR EACH ROW` trigger using the
existing `screening_ledger_reject_mutation()` function (`postgres.go:309`), in `017` and in
`SchemaSQL`. It has had only the TRUNCATE guard since it was created (`015:48-49`), while every
other protected table has had both since `012`.

The SQL invariant test must prove it by query, per CLAUDE.md: `UPDATE` and `DELETE` against
`screening_ledger_anchor` each raise, asserted as the specific SQLSTATE, in the style
`anchor_pgx_test.go:141-164` already uses for TRUNCATE (`P0001`).

### D17. F6: three-way role separation, with the assertion the current script cannot make

The current arrangement has two roles where the design needs three, and gives the wrong one
ownership (`provision_test_roles.sh:130-132`). Corrected:

| Role | On `screening_ledger_anchor` | Used at runtime by |
|---|---|---|
| **`owl_ledger_ddl`** (new) | **OWNER**; DDL only | nothing -- bootstrap/migration identity only |
| **`owl_ledger_anchor`** | `INSERT` only. Not owner. No `SELECT`, `UPDATE`, `DELETE`, `TRUNCATE`, no DDL | the anchor writer (D19) |
| **`owl_migrator`** | `SELECT` only | `PostgresSink`, for `LatestAnchor` (`postgres.go:219`) |
| **`owl_app`** | nothing | -- unchanged, and deliberately so (`provision_test_roles.sh:136-141`) |

The point of separating owner from writer is narrow and load-bearing: **a table's owner can drop
the table's triggers.** With the writer as owner, D16's immutability trigger and `015`'s TRUNCATE
guard are protections the protected party can remove. That is the same silent-absence shape as F1
-- a control present in the schema and revocable by the party it constrains.

Provisioning stays in `scripts/ci/provision_test_roles.sh` rather than moving into a migration,
following ADR-0001's rule (`0001:208`) exactly as §3.4 already reconciled it (`0007:227-239`).
The script gains the postconditions it currently cannot express -- that `owl_ledger_anchor` has no
`UPDATE`, no `DELETE`, and is not `relowner` -- alongside the ones it already proves
(`provision_test_roles.sh:148-167`).

`owl_ledger_ddl` is a fourth named role in the cluster but not a fourth *runtime* identity: nothing
connects as it outside provisioning and migration. R9 records the operational cost.

### D18. F4: local verification fails closed; the CI coupling is not the mechanism

Three changes, and one explicit non-change.

1. **`run-ci.sh` fails closed on missing database gates.** The `SKIP: ... (OWL_TEST_DATABASE_URL
   not set)` path that falls through to `PASS` (`run-ci.sh:65-71`) exits non-zero instead. An
   operator who genuinely has no database sets an explicit opt-out
   (`OWL_ALLOW_UNPROVEN_DB_GATES=1`), which still runs everything else but prints a named
   fail-open banner and marks the run as not constituting a security gate. Silence is removed;
   the ability to work without Postgres is not.
2. **The anchor gates are named in `run-ci.sh` at all.** `OWL_MIGRATOR_DATABASE_URL` and
   `OWL_LEDGER_ANCHOR_DATABASE_URL` appear nowhere in it today; the SEC-7 suite reaches CI only
   through `go test ./...` (`run-ci.sh:35`) and self-skips (`anchor_pgx_test.go:49`,
   `postgres_pgx_test.go:34`). They become gates the script knows about and reports on.
3. **`TestSEC7LedgerWriterCannotInsertAnchor` requires both DSNs.** Its gate moves from
   `requireMigratorDSN` alone (`anchor_pgx_test.go:110`) to requiring both, so no environment can
   run the positive test green while skipping the separation proof.

**The explicit non-change.** This design deliberately does **not** add a gate that greps
`.github/workflows/ci.yml` for the environment variables. `ci.yml:40`, `:41` and `:47` do set them
today and `ci.yml:87-92` does provision the roles -- that is confirmed, not assumed -- but making
correctness depend on a check that one named file still contains three named lines replaces one
unenforced coupling with another, more brittle one. The property worth having is that **a
verification run which did not prove the property says so and exits non-zero**, wherever it runs.
Get that right locally and CI inherits it.

Per CLAUDE.md Boundaries this is a separate, reviewed gate PR -- the same obligation §8 already
recorded and which is still open. §8's closing sentence stands unchanged and is now also the
closing condition for the reopening: SEC-7 does not close until a deliberately forged chain fails a
CI run that nobody chose to invoke.

### D19. F5: verify before mirroring; mark, never assume, when unverified

- The anchor gets an operational write path: a `screening-ledger anchor` subcommand
  (`main.go:20`, `:28`), connecting as `owl_ledger_anchor` through `AnchorSink`
  (`anchor.go:95-141`), which verifies the chain in `anchored` mode and then commits the head. This
  is D3's missing half (F1b). Cadence remains §8/D6's separate concern -- R2's bounded-window
  argument is unchanged -- but a mechanism with no caller is not a deferred cadence, it is an
  absent control.
- `sync` (`main.go:81-104`) runs full `anchored`-mode verification **before** the first `Persist`
  (`main.go:97`) and aborts on failure. Same for `import-audit` (`main.go:142-148`).
- Under explicitly-selected `historical-unanchored`, `sync` must record the unverified state **in
  the mirror**: `verified_at` and `verification_mode` columns on `screening_ledger_replication`
  (`postgres.go:304`), written in the same transaction as the row they describe. This is not
  belt-and-braces. The immutability triggers (`postgres.go:310-315`) mean a row mirrored without
  verification can never afterwards be corrected, annotated or removed by the identity that wrote
  it, so the fact must be recorded at write time or it is unrecordable.
- `ListEvents` (`store.go:350-368`) must stop swallowing per-file read and unmarshal failures
  (`store.go:361-365`). A file that cannot be parsed is a chain the caller has not seen all of.

### D19 correction note: "Same for `import-audit`" was a stale generalization (found implementing the repair)

Checked against the tree rather than transcribed, in the same spirit as §3.4 and §6.1. D19's
"Same for `import-audit`" does not describe `import-audit`'s actual shape, and no code change was
needed there.

`import-audit` (`main.go:142-148`) never constructs a local `Store` and never calls `Persist` on
this package's own event/audit chains -- it calls `sink.Migrate` and then `ImportExternalAudit`,
which writes only to `watchlist_operational_audit` via `PersistExternalAudit`. There is no local
chain here for `anchored`-mode verification (D8-D12's mechanism) to apply to.

What `import-audit` does have is `LoadExternalAuditDirectory` (`external_audit.go:46-84`), which
reads every file in the source directory, recomputes each record's checksum
(`phase8fEventChecksum`) and its sequence/`PreviousEventSHA256` linkage against the running
`previous`, for the **entire** directory, before returning the validated `records` slice.
`ImportExternalAudit` (`external_audit.go:85-102`) does not begin its `PersistExternalAudit` loop
(`:96-99`) until that full, validated slice is in hand. So the whole external chain is verified
before any persist call -- the identical shape `sync` is missing (F5) and D19 fixes there -- just
under the phase8f/`activationpromotion` sibling chain's own algorithm (§7.2: "rides on
`activationpromotion`"), not this package's D8-D12 mechanism, which is correct: `import-audit`
imports a different chain than the one this ADR specifies.

`sync`'s actual gap is structural and has no counterpart here: it calls `Persist` (`main.go:97`)
inside a per-event loop with no verification call anywhere on the path (confirmed absent at
implementation time). `import-audit`'s verify-before-persist property already existed by
construction. D19's parenthetical was written by analogy to `sync` without checking that
`import-audit`'s call shape actually matches, and it does not.

### D20. Test ownership: the reproduction's required shape, specified so nothing weaker satisfies it

**Ownership is decided and is not this session's work.** The end-to-end downgrade-exploit
regression belongs to the **implementation** session, consistent with how D5's original test landed
in the Stage 1 implementation PR (#106) rather than the design PR (#103), and with CLAUDE.md rule 7.
Stating this explicitly rather than leaving it implicit, because the shipped D5 test shows that a
carefully written test can satisfy a loosely specified requirement and still miss the bug.

The specification below is normative. An implementation PR that satisfies fewer than all nine
points has not discharged it.

1. **The starting chain is built by the real, unmodified `Store.Append`** (`store.go:52`) --
   multi-entry, with genuine encrypted snapshots on disk. Not hand-constructed `Event` literals.
   The shipped test's synthetic events (`forge_test.go:88-103`) carry empty
   `RequestSnapshotSHA256`/`ResponseSnapshotSHA256`, so `verifySnapshot` (`store.go:281`) would
   fail for a reason unrelated to the finding and would make either outcome uninterpretable.
2. **The relabel is uniform.** Every event to `EventSchemaV1`, every audit entry to
   `AuditSchemaV1`, `head.json` and `audit-head.json` to `HeadSchemaV1`. Leaving any single entry
   at `v2` sets `sawV2` (`store.go:270`, `audit.go:109`) and tests the already-working transition
   guard instead of the finding.
3. **Both chains, not one.** The audit chain has no snapshot check at all (`audit.go:72-131`), so
   an event-chain-only reproduction understates the exposure.
4. **Every legacy field is recomputed** with `legacyHashEvent` (`store.go:481`) and
   `legacyHashAudit`, including the predecessor linkage and both head files, so the result is
   internally perfect under the weak scheme. This is the negative control and it must be asserted,
   not assumed.
5. **The adversary holds no key** -- not `K_chain`, not `K_snap`, not `K_anchor`. The test must be
   constructible from the ledger directory and the published algorithm alone.
6. **It invokes the real, current verifier** for the "new" half -- `Store.VerifyDetail` or its
   successor, not a reimplementation. `forge_test.go:22-51`'s `verifyEventChainUnderFormula`
   stand-in is acceptable for the *old* half only, where no compiled old verifier survives.
7. **Two assertions, both required.** The verifier as it stands at
   `f135210f8bf4f466a8ad22976a0087efd78c5a07` **accepts** the relabelled chain -- run against that
   tree, this is the proof the break was real rather than an assertion that it was. The redesigned
   verifier **rejects** it, with an error naming the schema floor or the genesis boundary, not a
   digest mismatch reached by accident.
8. **Content tampering is included, not only relabelling.** A test that shows only "labels were
   changed and rejected" proves the label check and not the property.
9. **A companion case covers F8**: `purged_at` set on every snapshot envelope
   (`store.go:419-421`), demonstrating that under the current verifier this removes the last
   key-dependent check, and that under the redesign it no longer does.

The corresponding negative-control obligation for D12: a test asserting that `verify` with no
database **exits non-zero** in `anchored` mode, replacing `main_test.go:107-122`'s current
expectation of `"status":"partial"` at exit 0.

### AR7. R7's disposition, decided fresh: reopened, and closed rather than re-accepted

R7 (`0007:650-665`) accepted that the audit chain has no anchor-level protection against an
adversary holding `K_chain`, on the reasoning that D2's HMAC is the entirety of its protection and
that extending the anchor "would reopen the `sequence`-column schema decision this stage made,
which is disproportionate to what a three-stage implementation should still be revising."

Both halves of that rationale have failed, for different reasons:

- **The premise failed.** R7 rested on the HMAC being real protection for the audit chain even
  without an anchor. F1 shows it is bypassable by a keyless adversary via schema downgrade, and F8
  shows the audit chain never had even the snapshot-decryption backstop that bounded the event
  chain. Between F1 and this addendum, R7 was not an accepted residual against a key-holder -- it
  was an open hole against anyone with write access.
- **The deferral reason is void.** D11 reopens the anchor schema regardless, to add
  `policy_sha256`. The stated cost of fixing R7 -- reopening a schema decision -- is a cost this
  addendum is paying anyway, and there are zero anchor rows to migrate.

**Decision: R7 is closed, not re-accepted.** `screening_ledger_anchor` gains `audit_sequence`
alongside `audit_sha256` in `017`, both enter `anchorMAC`'s input, and `VerifyAnchored`
(`anchor.go:208-244`) cross-checks the audit chain at that sequence exactly as it cross-checks the
event chain at `sequence` (`anchor.go:232-242`). `AuditAnchorCoverage` and the
`"audit_anchor_coverage":"supplementary_only"` output field (`anchor.go:175-194`,
`main.go:77`) are retired rather than carried forward, and `016`'s schema comments are superseded
by `017`'s. §1's closing paragraph -- "one function call, two different guarantees" -- stops being
true, which was the right outcome all along and was deferred for a reason that no longer holds.

### New accepted risks

**R8 -- the trust root terminates at an operator-supplied public key.** D10 removes the need for a
secret in the verifier; it does not make the verifier self-authenticating. An adversary who can
replace both the policy file and the public key the verifier is configured with defeats EA1-EA3.
Mitigation is disclosure, not cryptography: the fingerprint is printed on every run (EA5) so it can
be compared against an out-of-band record. This is the same shape as R1 and is stated for the same
reason -- the alternative is an external timestamping authority, which §5.3 rejected with a
re-entry condition that has not been met.

**R9 -- two new artifacts to lose, and losing them fails closed.** The policy file and the Ed25519
private key are both operator-held, and a lost policy file means verification fails until it is
reconstructed and re-signed. That is the correct direction of failure and it is still a real
operational cost. Related: `owl_ledger_ddl` is a fourth named role to provision. Neither has a
rotation story in this document, which is the same gap §Consequences already recorded for
`K_anchor`.

**R10 -- F9's shared salt is a latent re-identification cost.** Any ledger that durably wrote
`"screening-ledger-cli"` as its `ledger-id` (`main.go:157` -> `store.go:469`) has a chain key
derived under a salt shared with every other such ledger. Changing the identity changes the salt,
which changes `K_chain`, which invalidates every existing digest -- i.e. re-identification is a
D4-class migration, not a rename. At `f135210` no such ledger exists outside developer scratch
directories, so the cost is zero now and unbounded later. This is a reason to remove the default
in the same change, not after it.

**R11 -- the anchor's protection is still bounded by anchor cadence, and cadence is still unwired.**
R2 said this and remains true: history between the newest anchor and the present is protected by the
MAC alone. D19 adds a writer, which closes F1b, but scheduling remains §8's gate PR. Until that
lands the window is operator-discipline-bounded rather than mechanism-bounded, and `verify` should
report the age of the newest anchor so the window is visible rather than assumed.

### Staging

Same shape as the original three stages, and for the same reason -- each stage must be independently
reviewable and independently provable.

1. **This addendum**, merged before any code (CLAUDE.md rule 7).
2. **Stage R1 -- the F1 fix, filesystem-only.** D8 (EA1/EA2/EA3), D10 (policy artifact and
   signature), D13 (F8), D14 (F9), D12's mode selection and exit codes for the no-database path,
   and D20's reproduction. Deliberately first and deliberately DB-free: it is the whole of the
   confirmed break, and it is provable with no Postgres.
3. **Stage R2 -- the anchor made real.** D11 (`017`, MAC input, policy binding), D15 (F3), D16
   (F7), D17 (F6), D19 (F5 and the `anchor` subcommand), AR7's audit-sequence cross-check, and
   D12's anchored-mode exit codes end to end.
4. **Gate PR -- D18 (F4)**, separate and reviewed on its own, per CLAUDE.md Boundaries.
5. **`SECURITY.md` and `README.md` language.** R3's rule is unchanged and now has a second
   instance behind it: nothing is said until the mechanism ships and its reproduction passes.
   `README.md:93-97`'s requalification notice stays until then, and is revised -- not deleted -- by
   the PR that closes stage R2.

### Addendum 1 summary

- **F1 is confirmed against `f135210` and is not re-litigated.** `store.go:257-274` and
  `audit.go:100-113` let the verified data select its own verifying algorithm; `sawV2`
  (`store.go:264`, `audit.go:103`) detects only a v2->v1 transition, so a uniform relabel passes.
  The shipped D5 test (`forge_test.go:77`) missed it by labelling its forgery `v2`
  (`forge_test.go:89`).
- **Three findings are new here:** F7 (the anchor table has no row-immutability trigger --
  `015:48-49` installs only the TRUNCATE guard), F8 (`verifySnapshot`'s `purged_at` short-circuit,
  `store.go:419-421`, removes the last key-dependent check and makes F1's residual unbounded), and
  F9 (`ledger-id` is the HKDF salt, `chainkey.go:26`, and the CLI default `main.go:157` makes it a
  shared constant, falsifying §5.1's salt claim on the default path).
- **The design is D8-D20.** Five externally-authenticated facts (EA1-EA5); a layered home for them
  -- an Ed25519-signed verification policy outside the ledger directory for the slow-moving four,
  the existing anchor table for the head -- chosen over either alone with the tradeoffs stated;
  fail-closed semantics that end `"partial"` at exit 0; and explicit dispositions for F3, F4, F5,
  F6, F7, F8 and F9.
- **R7 is reopened and closed rather than re-accepted**, because its premise failed and its
  deferral reason is void once D11 reopens the anchor schema anyway.
- **The reproduction is the implementation session's job**, and D20 specifies its required shape in
  nine normative points so that no weaker artifact discharges it.
- **This addendum revises no prior decision.** D1-D7 stand. §3.4 and §6.1 stand. R1-R6 stand. R7's
  disposition changes, and AR7 records the new one rather than editing §10.

**Audit basis commit:** `f135210f8bf4f466a8ad22976a0087efd78c5a07`

Every file:line citation in this addendum was verified against that tree. For a CAP record's
"Audit basis commit" field, use `f135210f8bf4f466a8ad22976a0087efd78c5a07` (branch `main`, tip
after PR #130).

## Addendum 2: SEC-7 still not closed -- the CAP's four demonstrated bypasses, and the remediation design (2026-08-20)

- **Status:** Proposed
- **Trigger:** a Composition Audit Program record produced against the repaired system
  (`docs/backlog/sec-7-cap-record-2d7ded3.md`, Part 2 format, adversarial posture, audit basis
  commit `2d7ded3b199f6abcc67c1892ec242c92c170b28a`) returned **QUALIFIED, not PASS**: the
  invariant Addendum 1 rebuilt holds only under five preconditions the system neither checks nor
  asserts anywhere, and for four of them the audit executed a working bypass against a live
  PostgreSQL 17.11 cluster with SQLSTATEs and transcripts recorded. **SEC-7 is not closed.** This
  addendum is the remediation design for exactly those findings. It does not re-litigate whether
  they are real -- they were proven by execution, not inspection -- and it does not re-prove them.
- **What the CAP also found, and which this addendum does not disturb:** the cryptographic core of
  the repair is sound. F1's downgrade break and F8's purge short-circuit are genuinely closed,
  proven by a reproduction that builds and runs the real pre-repair `f135210` binary from a
  `git worktree`. D17's role separation is real -- 19 of 19 escalation attempts rejected, including
  every DDL form F6 named. AR7 is correct. The policy layer's exact-equality schema pin
  (`policy.go:112`) is the right choice and closes F1's structural analogue one layer up. None of
  that is reopened here.
- **Scope:** a pure addition. Nothing above this section is edited -- not D1-D7, not D8-D20, not
  AR7, not §3.4, §6.1 or the D19 correction note, not R1-R11. Decision numbering continues this
  ADR's own convention at **D21**; risk numbering at **R12**. Where a prior decision's
  *disposition* changes, the new decision says so explicitly rather than editing the old text --
  the convention AR7 established for R7.
- **Verification basis:** every claim below was checked against the working tree at
  `2d7ded3b199f6abcc67c1892ec242c92c170b28a` -- the same commit the CAP audited, so `main` has not
  moved between the audit and this design. That does not make transcription safe, and every
  `file:line` here was re-derived from the tree rather than copied from the CAP record. Findings
  retain the labels the CAP assigned them (F-A through F-G).
- **Drift found in the CAP record's own citations.** Recorded rather than silently corrected, the
  same convention §3.4, §6.1 and Addendum 1's own drift note (`0007:717-720`) set:
  1. CAP §7.0 step 2 says "All 14 `db/migrations/*.sql` applied." There are **15** at this commit
     (`008g` through `018`). `018_screening_ledger_replication_verification.sql` is off the anchor
     path, so no finding is affected; the method note is off by one.
  2. CAP §7.2 cites the provisioning postconditions at `provision_test_roles.sh:148-167`. At this
     commit that block is `:165-216`, with the `has_table_privilege` lookups at `:181-210`.
     `:148-167` is Addendum 1's citation against `f135210` (pre-D17), carried forward. The CAP's
     *claim* -- that the postconditions say nothing about DDL -- still holds, and in one respect
     understates the current script: `:211-215` is a `pg_class.relowner` check, not a
     `has_table_privilege` lookup, so non-ownership **is** now asserted. DDL capability still is
     not, which is the substance.
  3. CAP §7.7 quotes D13's citation of "locally by `PurgeExpired` (`replay.go:194-201`)". The
     envelope mutation is at `replay.go:197-201` at this commit. This is pre-existing drift in this
     ADR's own text (`0007:1136-1137`), not CAP drift. Not edited above; recorded here.

  Everything else the CAP cites was checked and is accurate at this commit.

### Addendum 2 context: why these are one design and not four patches

Addendum 1 diagnosed the original's structural error as fixing instances rather than causes: the
`sawV2` guard was one instance of "the verified data chooses its own acceptance criteria," and D8
replaced the class rather than the instance. The CAP's findings have the same relationship to each
other, and naming it is what keeps this addendum from repeating the error one more time.

**The class is: a control whose installation is asserted rather than checked, by the party the
control constrains.**

- **F-E** -- `SchemaSQL`'s anchor guard asserts "if the table exists its protections are in place"
  (`postgres.go:392-398`) and never checks. `Migrate()` reports success on a schema that never
  reached the state it claims.
- **F-D** -- `IsPurgeRecorded` asserts a tombstone row is independent evidence
  (`postgres.go:262-266`) and never checks who could have written it. The answer is: the role the
  record exists to constrain.
- **F-F** -- D17 asserts that separating owner from writer protects the table's triggers. It
  protects them from the *writer*. Nothing protects them from the *owner*, and the owner is a real
  login credential with a real password in CI (`.github/workflows/ci.yml:57`).
- **F-C** -- `--allow-genesis` asserts an operator's belief that no anchor has ever been written,
  and the verifier treats the assertion as evidence.
- **F-A** -- D10 asserts a custody mechanism ("exposed as a package function for whatever
  out-of-band tooling an operator runs it from", `policy.go:69-74`) that cannot be built at all,
  because `internal/screeningledger` is a Go `internal` package.

Five instances, one shape. The design below answers each instance, and states the general form once
where it recurs (D21's closing paragraph, which D27 then depends on).

### The findings, verified against this commit

Restated from the code, not transcribed. Severities are the CAP's, calibrated against Addendum 1's
F1-F9 so the two sets are comparable.

**F-E (CRITICAL) -- `Migrate()` succeeds on a partial migration and leaves the anchor table
mutable.** `SchemaSQL`'s anchor block is guarded by
`IF to_regclass('screening_ledger_anchor') IS NULL THEN` (`postgres.go:399-406`). That predicate
distinguishes *absent* from *present* and never *stale* from *current*, so on a database migrated
through `015` but not `017` it skips entirely -- leaving `audit_sequence`, `policy_sha256` and
D16's `screening_ledger_anchor_immutable` trigger absent -- while `Migrate()` (`postgres.go:88-93`)
returns `nil`. The six unconditional tables are re-installed on every run by
`DROP TRIGGER IF EXISTS ... CREATE TRIGGER` (`postgres.go:350-355`, `:367-373`); the anchor table
alone is not, so a dropped trigger there is never restored either. On such a database `owl_migrator`
-- explicitly inside §2's threat model (`0007:120-121`) -- owns the table and the CAP executed an
in-place `UPDATE` forging `event_sha256`. That is limb **(b)** of the invariant being false through
an ordinary deployment path, after a migration that reported success.

The guard tests that exist to catch schema divergence cannot see it: both are `strings.Contains`
checks against the `SchemaSQL` Go constant (`postgres_schema_test.go:38`, `:60`). They assert that
text is present in a string literal. Neither asserts that a trigger exists on a live database after
`Migrate()` runs, and no live-database assertion of the D15/D16 parity claim exists anywhere in the
repository.

**F-A (HIGH) -- D10's custody mechanism is unbuildable as specified.** Confirmed at this commit:
`SignVerificationPolicy` (`policy.go:75`) has exactly one caller in the tree,
`cmd/screening-ledger/main_test.go:121`. `LoadEd25519PrivateKey` (`crypto.go:62`) has zero callers
anywhere, tests included. There is no policy-signing subcommand
(`main.go:20` lists `migrate|status|verify|sync|anchor|replay|export|purge|import-audit`). No policy
artifact is committed -- `test/fixtures/screening-ledger/` holds `snapshot-key.hex`, `state/`,
`frozen-v1-synthetic/`, `request.json`, `response.json` and `fake-psql.sh`, and no policy or public
key. The strings `--policy-file`, `policy-public-key` and "verification policy" appear nowhere in
`docs/`, `README.md`, `SECURITY.md` or `scripts/` outside this ADR and the CAP record. Meanwhile
`--policy-file` is `opts.required` for every verification path (`main.go:248`). With no way for any
operator to produce a policy, verification is unreachable in any operational sense.

**F-F (HIGH) -- `owl_ledger_ddl` has unrestricted authority over the anchor table.** D17 separated
the anchor *writer* from the *owner* and that separation is real (CAP §7.2, 19 of 19). Nothing
separates the owner from the table's own protections. The CAP executed, as `owl_ledger_ddl`:
`DROP TRIGGER screening_ledger_anchor_immutable`, then `DELETE FROM screening_ledger_anchor`, then
`CREATE TRIGGER` restoring it -- leaving zero anchor rows and a schema indistinguishable from an
untouched one, which any later schema audit or `grant-anchor-ownership` re-run would report as
correctly protected. `GRANT INSERT ... TO owl_migrator` also succeeded. The triggers do fire for
the owner while installed, which is correct and is worth crediting to D16; the defect is that the
owner removes them first. `owl_ledger_ddl` appears in no threat model: §2 excludes `K_anchor`, the
`owl_ledger_anchor` role and the policy signing key, and R9 records `owl_ledger_ddl` only as an
*operational* cost ("a fourth named role to provision", `0007:1379-1380`).

**F-C (MEDIUM, composing to HIGH with F-F) -- `--allow-genesis` masks the wipe.**
`verificationSettings` (`main.go:259-263`) is shared verbatim by `status`/`verify` (`main.go:37`),
`sync` (`:91`) and `anchor` (`:143`). On `anchor` the flag is a legitimate bootstrap
acknowledgment. On `verify` it converts `AnchorStatusAbsent` -- the exact and only signature of an
anchor-table wipe -- into a nil-error return (`anchor.go:281-284`) at exit 0. Compounding it,
`"status"` is hard-coded `"ok"` at `main.go:70` for every nil-error outcome, so a genesis-allowed
run and a fully anchor-verified run share both the exit code and the top-level status field,
separable only by reading the sibling `anchor_status`. That is a narrower re-introduction of the
"I could not check" versus "I checked and it was fine" conflation D12 exists to remove.

**F-D (MEDIUM) -- tombstone forgery.** `screening_ledger_retention_tombstone` is created by
`owl_migrator` (`db/migrations/008g_screening_ledger.sql:7`, and independently by `SchemaSQL` at
`postgres.go:346`), carries a `BEFORE UPDATE OR DELETE ... FOR EACH ROW` trigger
(`postgres.go:355`) and a TRUNCATE guard (`:371`), and has **no INSERT constraint of any kind**.
`IsPurgeRecorded` (`postgres.go:267-276`) trusts a bare `EXISTS`. So the mirror-writing adversary
§2 admits by name sets `purged_at` on every local envelope, inserts matching tombstones, and
`verifySnapshotChecked` (`store.go:576-585`) returns `(false, nil)` for all of them: every
key-dependent snapshot check skipped, in anchored mode, with a database configured. That is F8's
effect restored through the very record D13 chose to replace it.

Second half, and it is not a smaller problem: `Store.PurgeExpired` (`replay.go:163-209`) sets
`env.PurgedAt` at `:199` and writes **no independent record at all** -- its `AppendAudit` at `:207`
is a chain entry, not a tombstone. `screening_ledger_purge_snapshots` (`postgres.go:358`) tombstones
only snapshots present in the PostgreSQL mirror. A snapshot purged locally and never `sync`ed
therefore has no tombstone, and anchored-mode verification fails permanently at `store.go:583` with
no remediation path: legitimate retention renders the ledger unverifiable. The two paths also
disagree on legal holds -- `replay.go:177` honours `holds/`, the SQL function does not.

Related and unenforced: `SnapshotChecksPerformed` (`store.go:264`) is reported in the CLI output
(`main.go:76`) and no caller, gate or test asserts anything about it. "Every snapshot was skipped"
still exits 0 with `"status":"ok"` -- the counter D13 introduced to prevent exactly that confusion
is reporting-only.

**F-B (LOW) -- AR7 is correct and has no regression guard.** The CAP probed AR7's cross-check
(`anchor.go:317-334`) directly against a live database and found all three cases detected. This was
the finding most likely to be a latent break and it is not one. It has zero committed coverage: the
only `VerifyAnchored` negative tests are `verify_anchor_pgx_test.go:154` (event-chain tail
truncation) and `:220` (event-chain re-MACed tamper), and neither reaches the historical-lookup
branch, because both anchor at the current head. Grepping every `*_test.go` in the package for
`AuditSequence`, `eventAtSequence` and `auditEntryAtSequence` returns no test usage at all.

**F-G (LOW) -- the D18 gate's own regression test is invoked by nothing.**
`grep -rn "test_check_db_gates"` across the tree returns nothing outside the file itself. Its three
siblings all run from `run-ci.sh` (`:14`, `:16`, `:18`); it is the only one that does not. The
regression guard for D18's fail-closed behaviour never runs.

### D21. F-E: `Migrate()` verifies the schema it claims to have produced, and refuses rather than repairs

**Decision: assert the postcondition; fail loudly on any shortfall; do not attempt repair.**

Repair is not merely undesirable here, it is structurally impossible for the one object that
matters. After `provision_test_roles.sh grant-anchor-ownership` (`:146`) the anchor table is owned
by `owl_ledger_ddl`, and `Migrate()` runs as `owl_migrator` on every CLI invocation (`main.go:32`,
`:89`, `:200`). A `DROP TRIGGER`/`CREATE TRIGGER` attempt against a table it does not own fails
with a permission error that reads to an operator like a plumbing fault -- which is exactly the
diagnostic confusion D15 was written to remove. Refusal is also the direction CLAUDE.md's
fail-open-migration rule points: `RAISE EXCEPTION` rather than silently skip.

**Mechanism.**

1. **A literal required-object list.** A single declaration in `postgres.go` --
   `requiredSchemaObjects` -- enumerating, for all eight protected tables, the relation name, its
   row-immutability trigger name, and its TRUNCATE-guard trigger name; plus, for
   `screening_ledger_anchor`, the columns `017` adds (`audit_sequence`, `policy_sha256`). Written
   out literally, never derived by scanning `SchemaSQL` or by inference, per CLAUDE.md's "never
   enumerate targets by inference." It is the same eight-table set
   `postgres_schema_test.go:28-37` already lists, and both must read the one declaration so they
   cannot drift.
2. **`Migrate()` checks it.** After executing `SchemaSQL`, `Migrate()` runs one postcondition query
   against `pg_class`, `pg_trigger` and `pg_attribute` for that list, in the same call, before
   returning. Any missing relation, trigger or column produces a named error identifying **which**
   object is absent and **which** migration installs it -- not a generic "schema incomplete."
   `main.go:32`, `:89` and `:200` all route the result through `must()`, so the CLI exits 1.
3. **Ownership is reported, not enforced.** A `SchemaSQL`-only bootstrap legitimately leaves the
   anchor table owned by `owl_migrator`; a fully provisioned database has it owned by
   `owl_ledger_ddl`. Both are valid states, so the check reports the owner rather than failing on
   it. This is stated explicitly so it reads as a decision rather than an omission -- and it is the
   hook D27 depends on.

**Where the schema version is recorded: nowhere, deliberately.** This repository has no
`schema_migrations` relation and no version-tracking table of any kind -- confirmed by grep, not
assumed. Migrations are applied by a shell loop (`.github/workflows/ci.yml:88-92`, and the same
loop in `release-qualification.yml:85`). This addendum decides **not** to introduce one. A recorded
version number states what the schema is supposed to be; the postcondition query observes what it
actually is. Recording a version and trusting it would reproduce F-E's own error one level up: a
value that looks like evidence and is only a claim, writable by the same role that writes
everything else in the mirror. The postcondition query is strictly stronger and needs no new
storage.

**The general form, stated once because D27 relies on it.** `SchemaSQL` is a bootstrap that must
remain idempotent across an ownership boundary it does not control. There are exactly two safe
shapes for such a statement: unconditionally re-apply it (correct while the running role still owns
the object), or assert its presence and fail (correct once ownership has moved). The shape that is
never safe is the third one, present today: skip on the assumption that presence implies
correctness. Every future guard in `SchemaSQL` picks one of the first two.

**Tests, each of which fails before the change.**

- `TestMigrateFailsOnStaleAnchorTable` (new, pgx, gated on `OWL_MIGRATOR_DATABASE_URL`): provision
  a database with `008g` through `016` only, run `Migrate()`, assert a non-nil error naming
  `screening_ledger_anchor_immutable`. Fails today, because `Migrate()` returns `nil` -- this is
  the CAP's §7.6 state reproduced as a committed regression.
- `TestMigrateInstallsEveryProtectedTrigger` (new, pgx): against a fresh database, run `Migrate()`,
  then query `pg_trigger` for every entry in `requiredSchemaObjects`. This is the live-database
  assertion the D15/D16 parity claim has never had. The two `strings.Contains` tests
  (`postgres_schema_test.go:38`, `:60`) stay -- they are DB-free and cheap -- but stop being the
  only evidence.

### D22. F-E, second half: `42703` gets its own explicit, named failure

`LatestAnchor`'s error handling matches `42P01` only (`postgres.go:253-256`). Against a
`015`-but-not-`017` table, its SELECT (`postgres.go:240-242`) requests `audit_sequence` and
`policy_sha256` and raises SQLSTATE `42703` (`column "audit_sequence" does not exist`), which falls
through to the bare `return Anchor{}, false, err` at `:257` and surfaces as unnamed plumbing.

`LatestAnchor` gains an explicit `42703` arm returning a distinct named error: the anchor table
exists but lacks columns `017` adds, i.e. this database's schema is incomplete and this deployment
is in F-E's state. Kept as its own decision rather than folded into D21 because the two do different
jobs: D21 prevents the state being reached through `Migrate()`; D22 is the diagnostic backstop for a
database that reached it some other way (a partially applied `db/migrations/` run, a restore from an
older dump). Neither substitutes for the other. Exercised by the same fixture
`TestMigrateFailsOnStaleAnchorTable` builds.

### D23. F-A: the signer becomes a real binary, and custody moves from structural to operational

D10's premise cannot be satisfied. `internal/screeningledger` is a Go `internal` package; no module
outside this one can import it, now or ever, so the "out-of-band tooling" `policy.go:69-74`
describes cannot exist. This is F1b's shape one level up -- Addendum 1 established that "a mechanism
with no caller is not a deferred cadence, it is an absent control" and did not apply the same test
to the artifact carrying EA1-EA3.

**Decision: a separate binary, `cmd/screening-ledger-policy`.** Not a `screening-ledger` subcommand,
and not a promotion of the policy types out of `internal/`.

- **Why not a subcommand.** It would put code that reads an Ed25519 *private* key into the same
  binary an operator runs to verify and to anchor, on the ledger host. The property D10 actually
  wanted -- "the private half never enters the appending process, the verifying process, or CI"
  (`0007:1038-1039`) -- is preserved by a separate executable and lost by a subcommand. The
  distinction is not cosmetic: a subcommand makes it possible to run the signer by accident in the
  place it must never run.
- **Why not promoting the types out of `internal/`.** It would create a public API surface for a
  package this repository deliberately keeps internal, and it buys nothing toward custody: the
  private key lives wherever the operator puts it either way. The `internal` boundary is not what
  protects the key.
- **Shape.** Three subcommands -- `keygen` (writes a keypair; private key mode `0400`), `sign`
  (policy document plus private key, emits the signed envelope), `fingerprint` (public key, emits
  the same SHA-256 `PolicyPublicKeyFingerprint` already prints at `main.go:81`, so an operator can
  compare EA5's printed value against an out-of-band record without running a verification).
  All three reuse code that already exists and has no production caller today:
  `SignVerificationPolicy` (`policy.go:75`), `LoadEd25519PrivateKey` (`crypto.go:62`),
  `LoadEd25519PublicKey` (`crypto.go:41`).
- **Deliberately absent from `runtime_executables`**
  (`scripts/deployment/r2-4/harness/config/policy.json:150-155`). Recorded here so a later reader
  does not add it on the reasoning that it is a `cmd/` binary like the others.

**The tradeoff against what custody separation is supposed to achieve, stated rather than glossed.**
Custody separation for this artifact becomes **operational rather than structural**: it now rests on
where the binary is run and where the private key file lives, not on the signing code being
unreachable from the ledger host. That is a genuine reduction against the *text* of D10 and no
reduction at all against what D10 could ever have delivered, because D10's structural version
presumed an external importer of an `internal` package and was therefore never available. What is
genuinely preserved and is the whole of the property worth having: the private key never enters
`screening-ledger`, never enters the appending or verifying process, never enters CI, and is used
only at ledger-provisioning and policy-change time. An operator who wants stronger separation gets
it the way this repository already gets it for `R` (§5.2's custody requirement, `0007:337-342`) --
by where the key file lives and who owns it, not by which module the code sits in.

**Three things D23 also requires, none of which exists today:**

- **A committed example policy.** A signed policy and its trust-root public key under
  `test/fixtures/screening-ledger/policy/`, labelled example material rather than operator key
  material, so the CLI's documented happy path is exercisable without
  `cmd/screening-ledger/main_test.go:106`'s in-test generation being the only source in existence.
- **An operator procedure in `docs/`.** Generating the keypair; where the private key lives (an
  offline host, mode `0400`, outside `--ledger-dir`, owned by a principal that is not the ledger
  directory's owner -- the same custody language §5.2 already sets for `R`); how to re-sign on a
  policy change; and that a policy change is a re-anchoring event, because `policy_sha256` enters
  `anchorMAC` (D11, `anchor.go:33-36`).
- **No `SECURITY.md` change yet.** R3's rule is unchanged and now has a third instance behind it:
  nothing is said until the mechanism ships and its reproduction passes.

### D24. F-C: `--allow-genesis` is scoped to the subcommand it was designed for

`--allow-genesis` has a legitimate meaning on `anchor`: an operator acknowledging that this ledger
genuinely has no anchor row and that they are about to write its first. It has no legitimate meaning
on `status`, `verify` or `sync`, where its only effect is to convert the sole observable signature
of an anchor-table wipe into success.

- `status`/`verify`/`sync` stop reading `--allow-genesis`. Passing it becomes an **error**, not a
  silently ignored flag. Silently ignoring it would leave a monitoring job holding a flag that looks
  load-bearing and does nothing -- the silent-absence shape this whole ADR exists to remove.
- `anchor` keeps it, with D25's additional constraint below.
- `main.go:70` stops hard-coding `"status": "ok"`. The top-level status is derived from
  `report.AnchorStatus`, so an operator or a scripted caller reading only the exit code and the
  top-level field can distinguish "anchor verified" from "no anchor was found." Today
  `anchor_status` is the only field that separates them, and it is the field a script is least
  likely to read.

This half is straightforward and closes the CAP's §7.4 transcript directly. It does not close F-F.

### D25. F-C/F-F: the signed policy commits a minimum anchor sequence -- adopted, with its limit stated

The CAP's flagged candidate, evaluated on its merits rather than defaulted to.

**It works, for the attack it addresses.** `VerificationPolicy` (`policy.go:21-29`) is Ed25519-signed
under a key `owl_ledger_ddl` does not hold and cannot forge. Adding `min_anchor_sequence` and
refusing `AnchorStatusAbsent` whenever `min_anchor_sequence >= 1` makes a **full anchor-table wipe
detectable** -- zero rows is below the signed floor -- and D24 has already removed the flag that
masked it on the verification paths. It requires no new storage, no new relation and no new key
material, exactly as the CAP said.

**Both halves of the check are normative, not only the absent one.** `VerifyAnchored`
(`anchor.go:244`) enforces two conditions against `min_anchor_sequence`, and an implementation that
adds only the first has not discharged D25:

1. `AnchorStatusAbsent` (`anchor.go:276-286`) is a failure whenever `min_anchor_sequence >= 1`, and
   `--allow-genesis` cannot override it -- the signed policy already contradicts the assertion the
   flag makes.
2. A *present* anchor whose sequence is below the floor is equally a failure. `LatestAnchor` returns
   the highest-sequence row (`postgres.go:240-242`, `ORDER BY sequence DESC LIMIT 1`), so
   `latest.Sequence < policy.MinAnchorSequence` means the newest surviving anchor predates what the
   policy committed to. That is `AnchorStatusFailed`, with an error naming the floor and the
   sequence found -- not `AnchorStatusAbsent`, because something was found and it was wrong.

**It does not do what a first reading suggests, and the gap must be stated.** An adversary who can
wipe can also wipe *selectively*. Deleting every anchor above sequence `N` -- or deleting all of
them and re-inserting a copy of the row at `N` they saved first, which the immutability trigger does
not prevent once it has been dropped -- satisfies a floor of `N`. What they cannot do is fabricate a
row that never existed, at any sequence, because `anchor_mac` requires `K_anchor`
(`anchor.go:142-153`), which §2 excludes them from holding. Rollback is therefore limited to
sequences this ledger genuinely reached, and the floor limits how far back among those they may go.
So the mechanism **bounds rollback to the policy's committed floor; it does not prevent rollback to
it.** And because the policy is by design a rarely-changed artifact (D9, `0007:1008-1011`: EA1-EA3
and EA5 "change once in a ledger's lifetime"), the floor ratchets only when an operator re-signs and
re-anchors. The exposed window is `[floor, head]`, which is structurally the same shape as R2/R11's
anchor-cadence window one layer up, and R14 records it as such.

**Cost, which is real but is paid at its cheapest moment.** `policy.go:112` is an exact-equality
schema pin, not a floor -- correctly, as the CAP credited. Adding a field is therefore a schema
change: the document becomes
`openwatchlist.screening-ledger-verification-policy.v2`, `canonicalPolicyBytes` output changes,
`PolicySHA256` (`policy.go:61`) changes, and every anchor row's D11 `policy_sha256` binding is
invalidated. There are zero anchor rows in any environment -- `screening-ledger` remains absent from
`runtime_executables` (`policy.json:150-155`), re-confirmed at this commit -- so the migration cost
is zero now and unbounded later, the same argument D11 made for `017` and §6 made for the fixture.

**Bootstrap ordering, decided rather than left to surface during implementation.** A ledger's first
policy necessarily carries `min_anchor_sequence: 0`, since no anchor exists yet; at that value
`--allow-genesis` on `anchor` is permitted and `AnchorStatusAbsent` is the honest state. Raising the
floor is a policy re-issue, which by D11 is a re-anchoring event, so the new floor is always
satisfiable by construction at the moment it is signed. Once the floor is above zero,
`--allow-genesis` is refused on `anchor` as well -- it is asserting something the signed policy
already contradicts.

**Verdict: adopted as a layer, not as the answer.** It closes the demonstrated §7.4 bypass and makes
policy re-issue cadence an explicit security parameter rather than an operational preference. F-F
remains open after it, which is why D26 exists.

### D26. F-F: a superuser-provisioned DDL event trigger binds the table's owner

**This decision goes beyond the CAP's own framing, and says so.** CAP §9 states the residual as:
"A table owner can always drop that table's triggers; PostgreSQL provides no ownership model in
which the owner is bound by them." The first clause is true. The second is true *about ownership*
and incomplete about PostgreSQL. **Event triggers are not owner-scoped.** `CREATE EVENT TRIGGER`
requires superuser; the resulting trigger fires for every non-superuser role including a table's own
owner; and no non-superuser can disable it. Every role in this cluster is created
`NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS` (`provision_test_roles.sh:53`, `:55`), including
`owl_ledger_ddl` (`:64`).

**Mechanism**, provisioned by the bootstrap superuser in `scripts/ci/provision_test_roles.sh` -- the
same identity and the same file that already performs `grant-anchor-ownership` (`:119-217`), so this
follows ADR-0001:208's "no migration contains `CREATE ROLE` or `GRANT`" rule exactly as §3.4
reconciled the anchor role, rather than creating a new exception to it:

- An event trigger on `sql_drop` whose function inspects `pg_event_trigger_dropped_objects()` and
  raises if any dropped object is `screening_ledger_anchor`,
  `screening_ledger_anchor_immutable`, `screening_ledger_anchor_no_truncate`, or (per D27)
  `screening_ledger_retention_tombstone` and its own two triggers. `sql_drop` fires inside the
  dropping transaction, so the exception rolls the drop back.
- An event trigger on `ddl_command_end` for tag `ALTER TABLE` that raises when the target is one of
  those relations. This is what blocks `ALTER TABLE ... DISABLE TRIGGER ALL`, which is not a drop
  and which the CAP confirmed the owner can currently execute.
- **Created after `db/migrations/` has run**, so `017`'s own `ALTER TABLE` and
  `DROP TRIGGER IF EXISTS` statements (`017:28-42`) are unaffected, and narrowly scoped by object
  identity so that no other migration, no `db/rollback/` script, and no `SchemaSQL` run is caught.
- `ALTER EVENT TRIGGER ... ENABLE ALWAYS`, so it also fires under
  `session_replication_role = 'replica'`. That GUC is `SUSET` and therefore already unreachable to
  these roles; the clause is one word and removes the question rather than leaving it to be
  re-derived.

**Costs, stated with the same specificity as the benefit.**

- **No precedent in this repository.** Confirmed: `EVENT TRIGGER` appears nowhere in `db/`,
  `scripts/` or `internal/`. This is a new database-level mechanism, and it is the first control
  here that a migration cannot install.
- **Database-wide blast radius.** Event triggers are not per-relation. A defect in the trigger
  function breaks unrelated DDL across the whole database, including SEC-1's RLS migrations and
  `db/rollback/014_tenant_isolation_down.sql`. Identity-scoping the function body and creating it
  last are the mitigations; the risk is real and is not eliminated by them.
- **It relocates the residual rather than deleting it.** A superuser can drop the event trigger.
  That is the correct place for the residual to terminate and is the honest statement of what this
  buys: the party who must be trusted moves from `owl_ledger_ddl` -- a role the deployment hands out
  with a real password in CI (`.github/workflows/ci.yml:57`) and which §2 never excluded -- to the
  bootstrap superuser, which §2 never granted the adversary and which INFRA-3 already treats as the
  one identity allowed to be a superuser (`provision_test_roles.sh:20-22`).

**Empirical proof obligation. This design does not get to assert D26 works.** The behaviour above
was reasoned from PostgreSQL's documented event-trigger semantics and from this repository's role
attributes; it was **not** executed against a live cluster, because this is a design pass and
CLAUDE.md rule 7 puts implementation in its own PR. The implementation PR discharges D26 only by
reproducing the CAP's §7.3 sequence as a committed test and showing every row now blocked, with its
SQLSTATE captured rather than inferred: `DROP TRIGGER screening_ledger_anchor_immutable`; the
drop-then-`DELETE` transaction; the drop-both-then-`TRUNCATE` transaction;
`ALTER TABLE ... DISABLE TRIGGER ALL`; and `DROP TABLE` -- each as `owl_ledger_ddl` over
`OWL_LEDGER_DDL_DATABASE_URL`, alongside the 19 escalation attempts `anchor_pgx_test.go` already
covers. **If that proof fails, D26 is withdrawn**, and R12/R13 below carry the residual explicitly
and unchanged. Stating both outcomes in advance is deliberate: it is what stops the disposition
being decided after the fact by whichever result arrived.

### D27. F-D: the tombstone write path becomes a definer function the constrained role cannot alter

EA1 established the pattern this finding needs: an independent, write-restricted record the party
being constrained cannot forge. Here the constrained party is `owl_migrator`, which today both owns
`screening_ledger_retention_tombstone` and holds unrestricted INSERT on it.

**Does this need D17's full three-way role split? No, and the reason is structural rather than
economical.** The anchor needed three roles because it has a separate runtime *writer process*
holding a separate key -- `owl_ledger_anchor` plus `K_anchor` -- so owner, writer and reader are
genuinely three identities with three different jobs. The tombstone has no separate writer: it is
written as a side effect of a retention purge `owl_migrator` legitimately performs. Adding a fourth
login role would mean the CLI carries a second DSN for `purge` and would not change who is asking
for the write. What must be true is narrower and sharper: the **predicate** deciding which rows may
be tombstoned has to be enforced by code the migrator cannot alter.

- `screening_ledger_purge_snapshots` (`postgres.go:358`, `db/migrations/008g_screening_ledger.sql:19`
  -- today `SECURITY INVOKER` by omission) becomes **`SECURITY DEFINER`** with an explicit
  `SET search_path`, owned by **`owl_ledger_ddl`** -- the role D17 already introduced. No fifth
  role. The `SET search_path` is not boilerplate: without it a definer function resolves unqualified
  names against the caller's `search_path`, which hands the caller the very control the definer
  boundary exists to take away.
- `screening_ledger_retention_tombstone`'s ownership moves to `owl_ledger_ddl` in the same
  provisioning step, which is renamed from `grant-anchor-ownership` to reflect that it now covers
  two relations rather than one.
- `owl_migrator` keeps `SELECT` (which `IsPurgeRecorded` needs, `postgres.go:271-274`) and gains
  `EXECUTE` on the function. It loses `INSERT`, `UPDATE`, `DELETE` and ownership. The forged INSERT
  the CAP executed becomes `42501`.
- The function validates every snapshot it tombstones against `screening_ledger_snapshot`'s
  `expires_at`, so even through the sanctioned path the migrator cannot record a purge for a
  snapshot that is not actually expired. The record stops being "a row `owl_migrator` wrote" and
  becomes "a row the server agreed to write, under a predicate `owl_migrator` cannot change."
- Provisioning postconditions in the style `:181-215` already uses: assert
  `has_table_privilege('owl_migrator', 'screening_ledger_retention_tombstone', 'INSERT')` is false;
  assert `relowner` is `owl_ledger_ddl`; assert `prosecdef` is true and `proowner` is
  `owl_ledger_ddl` on the function. Prove it, do not assume the statements did what they say.

**Why this is one design with D21 and not a separable change.** Once ownership moves, `SchemaSQL`'s
unconditional `CREATE OR REPLACE FUNCTION screening_ledger_purge_snapshots` (`postgres.go:358`), run
as `owl_migrator` on every CLI invocation, would fail -- the identical situation that produced
F-E's fail-open guard for the anchor table. The answer is D21's general form: guard on current
state, and let the postcondition check verify rather than assume. Without D21 in the same stage,
D27 would recreate F-E on a second object.

If D26 survives its proof, the tombstone relation and its triggers join the event trigger's identity
list, so the owner cannot drop these protections either.

### D28. F-D, second half: local purge fails closed, and the two purge paths stop disagreeing

Taken as one decision with D27, because what each path may consult depends on what the other
guarantees.

- **`Store.PurgeExpired` gains a recorder and refuses without one.** It takes a `PurgeRecorder`
  and, when none is supplied, mutates no envelope and returns an error. Fail closed, matching D13's
  direction: a purge whose independence cannot be recorded must not happen, rather than happening
  and silently rendering the ledger permanently unverifiable at `store.go:583`.
- **`cmd/screening-ledger purge` requires `--postgres-dsn-env`** (`main.go:180-196`, where it is
  optional today at `:190`). The local-only purge path that produces the unrecoverable state ceases
  to exist rather than being documented around.
- **Eligibility is decided in exactly one place, and it is not the SQL function.** The local path
  already knows about legal holds (`replay.go:177`); the SQL function does not and should not learn
  about a filesystem directory. So the definer function gains a form taking an explicit
  `snapshot_sha256[]` -- the set the local path determined is eligible -- and still validates each
  against `expires_at` server-side. The local side **narrows** (holds, and only holds); the server
  side **floors** (expiry, non-negotiable). That is what keeps the record independent of the caller
  while leaving legal holds authoritative where they actually live. It also resolves the divergence
  the CAP found, rather than leaving two functions with two answers.
- **`SnapshotChecksPerformed` stops being reporting-only.** In `anchored` mode,
  `SnapshotChecksPerformed == 0 && SnapshotChecksTotal > 0` becomes a verification failure. The
  counter D13 introduced to stop "every snapshot was skipped" looking like "every snapshot passed"
  (`0007:1141-1142`) currently gates nothing, which is the same silent-absence shape one more time.

### D29. F-B: the three regression tests AR7 has never had

Coverage closure, specified here so it is not lost, and explicitly **not** a design question -- the
mechanism was probed live and is correct. All three go in `verify_anchor_pgx_test.go`, gated on
`requireAnchorDatabaseURL` (`anchor_pgx_test.go:45`) and `requireMigratorDSN`
(`postgres_pgx_test.go:30`) like their siblings, and each must assert **both** halves the existing
tests assert: that `VerifyPolicy` alone accepts the manipulated chain (the shape at
`verify_anchor_pgx_test.go:193-195` and `:268-270`), and that `VerifyAnchored` rejects it. A test
that only shows rejection does not show that the anchor is what caught it.

1. **`TestVerifyAnchoredDetectsAuditTailTruncation`** -- anchor at the current head; delete the
   newest audit entry; rewrite `audit-head.json` consistently; assert the error matches
   `"possible tail truncation (AR7)"` (`anchor.go:321`). The audit-chain counterpart of `:154`.
2. **`TestVerifyAnchoredDetectsAuditDivergence`** -- anchor at the current head; tamper an audit
   entry and re-MAC it under the real `K_chain`, modelling the `K_chain`-holder-without-`K_anchor`
   adversary exactly as `:220` does for the event chain; assert the error matches
   `"disagrees with the anchor's committed audit digest"` (`anchor.go:333`).
3. **`TestVerifyAnchoredDetectsHistoricalTamperBelowAnchor`** -- anchor at sequence `N`, append
   further legitimate entries so the head advances past `N`, then tamper the entry **at** `N` and
   the audit entry at the anchored `audit_sequence`, re-MACing both. This is the only case that
   drives `latest.Sequence != report.Head.Sequence` (`anchor.go:305`, `:324`), and therefore the
   first execution by anything of `eventAtSequence` (`store.go:424`) and `auditEntryAtSequence`
   (`store.go:450`). Both branches must be asserted; covering only one leaves half the historical
   lookup still dead.

### D30. F-G: wire the D18 gate's own regression test

`scripts/ci/tests/test_check_db_gates.sh` is invoked by nothing. One line in `run-ci.sh`, placed
next to the gate it guards (`run-ci.sh:25`) rather than with its siblings at `:14`/`:16`/`:18`, so
the test and the script it tests read together:

```sh
./scripts/ci/tests/test_check_db_gates.sh
```

Per CLAUDE.md Boundaries gate-script changes are normally their own reviewed PR. This is a one-line
invocation of an already-committed, already-reviewed test that adds no gate and changes no
pass/fail semantics for any environment that was passing before, so it rides with the
implementation rather than becoming a fourth PR -- and the PR description names the `run-ci.sh`
change explicitly so a reviewer sees the file was touched and why.

### New accepted risks

**R12 -- `owl_ledger_ddl` is named in the threat model, not left as an operational cost in R9.**
§2 gains an explicit exclusion for `owl_ledger_ddl`: a role the design assumes the adversary does
**not** hold. §2 today has no such list -- its "Out of scope" paragraph (`0007:128-132`) covers
confidentiality and availability, and its "Explicitly not assumed" paragraph (`0007:134-138`) is
about live traffic. The role and key exclusions this design actually rests on are stated in §5.3
points 1-2 (`0007:376-381`) and R1 (`0007:607-613`), and were first consolidated into one list by
the CAP record's §2. That list is where `owl_ledger_ddl` belongs, and §2 is where it should be
readable.

Today `owl_ledger_ddl` appears only in R9 as "a fourth named role to provision" (`0007:1379-1380`), while holding
a real login credential with a real password in CI (`.github/workflows/ci.yml:57`), and CAP §7.3
demonstrates what holding it is worth: a full anchor-table wipe with the triggers restored and the
schema indistinguishable from an untouched one. R9's sentence is not edited; R12 records the new
disposition, the same way AR7 recorded R7's rather than editing §10 in place. With D26 the
assumption is enforced by the database; without D26 it is an assumption only, and either way it is
now stated where a reader looks for the threat model rather than where they look for provisioning
costs.

**R13 -- `--allow-genesis`'s actual guarantee, restated honestly.** After D24 it can no longer mask
a wipe on any verification path, and after D25 a full wipe is detectable against the signed floor.
What it still is, and what must not be overstated: on `anchor`, `--allow-genesis` records that *this
operator believes* this is a first anchor. It is an acknowledgment, not evidence. Without D26 it
cannot distinguish a genuine genesis from a wipe-and-recreate performed by the table's own owner,
because at the moment it is evaluated both states are byte-identical -- zero rows, both triggers
present, schema correct. With D26 it can, down to a superuser. The flag's name should be read as
"the operator asserts genesis," never as "genesis was verified."

**R14 -- the rollback window between policy re-issues.** D25's floor bounds how far history can be
rolled back; it does not prevent rollback to the floor, and the floor advances only when an operator
re-signs the policy and re-anchors. Policy re-issue cadence therefore joins anchor cadence (R2, R11)
as a security parameter rather than an operational preference, and it is the second such parameter
this design leaves unscheduled. `verify` already reports `anchor_age_seconds` (`main.go:79`, R11);
the same reasoning says it should report the distance between the policy's committed floor and the
current anchor sequence, so the window is visible rather than assumed. Recorded here rather than
designed, because scheduling remains §8/D6/D18's separate gate concern and this addendum does not
reopen it.

### Staging

Same shape and the same reason as §8 and Addendum 1's staging (`0007:1397-1414`): each stage must be
independently reviewable and independently provable.

1. **This addendum**, merged before any code (CLAUDE.md rule 7).
2. **Stage C1 -- schema truth.** D21, D22, D27, D28, and D30 riding along. One stage rather than
   two, because D27's ownership move is only safe once D21's postcondition check exists; splitting
   them would recreate F-E on the tombstone relation in the interval.
3. **Stage C2 -- genesis, wipes, and the owner.** D24, D25 (policy schema `v2`, re-signing,
   re-anchoring), D26 with its empirical proof obligation, and D29 riding along. If D26's proof
   fails, this stage lands D24 and D25 and R12/R13 carry the residual explicitly -- that outcome is
   pre-declared here, not decided afterwards.
4. **Stage C3 -- the operator can actually use this.** D23: `cmd/screening-ledger-policy`, the
   committed example policy fixture, and the operator procedure. Sequenced last only because it
   blocks nothing else; it is the finding that makes the whole mechanism unreachable in practice,
   and it must not be dropped for that reason.
5. **`SECURITY.md` and `README.md` language.** R3's rule unchanged. `README.md:93-97`'s
   requalification notice stays until every stage above has landed and its reproduction passes --
   Addendum 1's staging item 5 and CAP §8's "public claim containment holds" both require it, and
   the CAP verified nothing in PR #135, #136 or #137 re-asserted the guarantee.

**SEC-7 does not close on this addendum.** §8's closing condition -- "a deliberately forged chain
fails a CI run that nobody chose to invoke" -- is met in the CI sense by `d20_exploit_test.go`. It
is not met while no operator can produce the policy verification requires (F-A), and it is
contradicted outright while a forged anchor is writable on a database `Migrate()` called
successfully migrated (F-E). The closing sentence stands and now has a second addendum behind it.

### Addendum 2 summary

- **The CAP's verdict is QUALIFIED, not PASS**, on one CRITICAL and three HIGH findings, four of
  them with bypasses executed against a live database. This addendum designs the remediation; it
  does not re-litigate the findings.
- **The class behind all five substantive findings is one shape:** a control whose installation is
  asserted rather than checked, by the party the control constrains. F-E asserts a schema state,
  F-D asserts a record's independence, F-F asserts that owner/writer separation protects triggers,
  F-C asserts an operator's belief as evidence, F-A asserts a custody mechanism that cannot be
  built.
- **The design is D21-D30.** Postcondition verification in `Migrate()` that refuses rather than
  repairs (D21) and its diagnostic backstop (D22); a real signing binary with the custody tradeoff
  stated (D23); `--allow-genesis` scoped to `anchor` (D24) plus a policy-committed anchor floor
  (D25); a superuser-provisioned event trigger that binds the table owner, carrying an explicit
  empirical proof obligation and a pre-declared withdrawal condition (D26); a `SECURITY DEFINER`
  tombstone write path with a narrower-than-D17 justification (D27) and a fail-closed local purge
  that resolves the legal-holds divergence (D28); AR7's three missing regression tests (D29); and
  the one-line gate wiring (D30).
- **D26 departs from the CAP's own framing and says so.** CAP §9 framed the F-F residual as
  possibly unclosable on the grounds that a table owner can always drop that table's triggers. That
  is true about ownership and incomplete about PostgreSQL: event triggers are superuser-only and
  bind every non-superuser role, the owner included. The claim is reasoned, not executed, and the
  implementation PR discharges it only by reproducing CAP §7.3 with every attempt blocked.
- **Three risks are recorded** rather than designed away: `owl_ledger_ddl` moves into the threat
  model (R12), `--allow-genesis`'s guarantee is restated as an acknowledgment rather than evidence
  (R13), and policy re-issue cadence joins anchor cadence as an unscheduled security parameter
  (R14).
- **This addendum revises no prior decision.** D1-D7 stand. D8-D20 and AR7 stand. §3.4, §6.1 and the
  D19 correction note stand. R1-R11 stand; R9's `owl_ledger_ddl` sentence is not edited, and R12
  records the changed disposition instead.

**Audit basis commit:** `2d7ded3b199f6abcc67c1892ec242c92c170b28a`

Every file:line citation in this addendum was verified against that tree -- the same commit the CAP
record was produced against, so no drift separates the audit from this design. For a CAP record's
"Audit basis commit" field covering the implementation of this addendum, use the tip of whichever
stage PR is under audit, not this value.

## Addendum 3: the scoping principle -- why six of ten Addendum 2 mechanisms were defeated by one shape, and the remediation design (2026-08-20)

- **Status:** Proposed
- **Trigger:** a second Composition Audit Program record produced against the implemented Addendum 2
  (`docs/backlog/sec-7-cap-record-b2fe831.md`, Part 2 format, adversarial posture, audit basis
  commit `b2fe831e8e556b324e28a3af05aef98240d00f83`) returned **QUALIFIED, not PASS** for the second
  time: seven findings, one CRITICAL and four HIGH, six of them demonstrated live against a
  PostgreSQL 17.11 cluster provisioned by `scripts/ci/provision_test_roles.sh` exactly as
  `.github/workflows/ci.yml:80-120` does it. **SEC-7 is not closed.**
- **What CAP #2 confirmed and this addendum does not disturb.** F-C is closed outright: the prior
  record's §7.4 transcript cannot be reproduced, `--allow-genesis` is refused rather than ignored on
  the verification paths (`main.go:297-302`), and the top-level status is derived
  (`main.go:320-325`). F-A, F-B and F-G are closed. F-E's *stated* form is closed and the check
  generalises -- three of five deliberately constructed degraded schema states were refused with
  errors naming both the missing object and the migration that installs it. D26 blocks all five
  attack forms it was written against, and blocks four of them on
  `screening_ledger_retention_tombstone` as well, which no committed test covers. None of that is
  reopened here.
- **Scope:** a pure addition. Nothing above this section is edited -- not D1-D7, not D8-D20, not
  AR7, not D21-D30, not §3.4, §6.1 or the D19 correction note, not R1-R14. Decision numbering
  continues at **D31**, risk numbering at **R15**. Where a prior decision's *disposition* changes,
  the new decision says so explicitly rather than editing the old text -- the convention AR7
  established for R7 and Addendum 2 followed for R9.
- **Verification basis:** every `file:line` below was re-derived from the working tree at
  `b2fe831e8e556b324e28a3af05aef98240d00f83` rather than copied from the CAP record.
- **This design pass executed against a live cluster, and that is a deliberate departure.** Addendum
  2 deferred all execution to implementation, on the correct general principle that CLAUDE.md rule 7
  puts implementation in its own PR -- and D26 was shipped on behaviour "reasoned from PostgreSQL's
  documented event-trigger semantics" (`0007:1874-1877`). Three of CAP #2's five HIGH/CRITICAL
  findings are reasoning errors in that deferral: `DROP OWNED` is not in a tag list nobody tested,
  `pg_event_trigger_ddl_commands()` reports a renamed object's *new* identity, and
  `CREATE OR REPLACE FUNCTION` is not `ALTER TABLE`. Each is a twenty-minute lab question. So this
  addendum separates two things that Addendum 2 fused: **mechanism availability** (does PostgreSQL
  do the thing this design assumes? -- established here, by execution, before the decision is
  written) and **implementation correctness** (does this repository's code do it? -- still the
  implementation PR's job, D37). The transcripts are in the sections that rely on them.

### Drift found while writing this addendum

Recorded rather than silently corrected, the convention §3.4, §6.1, `0007:717-720` and
`0007:1474-1490` set.

1. **`0007:1584` cites `verifySnapshotChecked` at `store.go:576-585`.** At this commit the function
   is `store.go:594-624`, with the tombstone branch at `:601-611`. Carried from the design pass
   against `2d7ded3`; the substance is unchanged.
2. **`0007:1526` cites `SchemaSQL`'s anchor guard at `postgres.go:399-406`.** At this commit it is
   `postgres.go:680-687`, and PR #139 added a second guard of the identical shape for the tombstone
   table at `postgres.go:707-716`. D27 predicted that second guard would be needed
   (`0007:1923-1928`) and justified it by D21's postcondition check. D33 below is what that
   justification actually requires in order to hold.
3. **CAP #2 corrects two severity ratings in the first CAP record, in opposite directions**, and
   this addendum adopts both. F-E's CRITICAL overstated it: an in-place anchor rewrite is rejected
   on the MAC at `anchor.go:305`, executed and confirmed, so limb (b) held through the exact attack
   F-E was rated on. F-D's MEDIUM understated it: run end to end through the shipped CLI it is a
   `verify` that prints `"status":"ok"` at exit 0 on a tampered snapshot. G-C inherits the second
   correction and is the CRITICAL of this addendum.

---

### Addendum 3 context: one shape, six mechanisms

Addendum 1 diagnosed the original's structural error as fixing instances rather than causes
(`0007:1494-1497`). Addendum 2 diagnosed its own findings as one class -- "a control whose
installation is asserted rather than checked, by the party the control constrains"
(`0007:1499-1500`) -- and then, per CAP #2 §11, reproduced that class one level up. This addendum
has to name the shape more precisely than "asserted rather than checked," because that phrasing did
not stop it from recurring.

**The shape is: a control that decides what to protect, or what to protect against, by listing
members of an open set.**

Every one of CAP #2's six mechanism findings is a list that did not contain the adversary's move:

| Mechanism | The list | The form outside it | Finding |
|---|---|---|---|
| D26 `sql_drop` trigger | `WHEN TAG IN ('DROP TABLE', 'DROP TRIGGER')` (`provision_test_roles.sh:376`) | `DROP OWNED` | G-B |
| D26 `ddl_command_end` trigger | `WHEN TAG IN ('ALTER TABLE')` (`:377`) | `CREATE FUNCTION` (`CREATE OR REPLACE`) | G-D |
| D26 function body | `protected_tables` / `protected_trigger_identities`, matched on `object_identity` (`:341-347`) | `ALTER TABLE ... RENAME TO`, which changes the identity | G-G |
| D26 function body, again | the same two arrays | the guard *functions* the triggers call, which are on neither list | G-D |
| D21 `requiredSchemaObjects` | relations, trigger *names*, columns (`postgres.go:178-233`) | a trigger that exists and is `DISABLE`d; provisioning that never ran | G-A |
| D27 predicate | `expires_at < p_before` (`019:46`, `:78`) | a `p_before` the caller chooses, over an `expires_at` the caller writes | G-C |

Two of these lists are lists of *actions* (tags). Three are lists of *objects* (names). One is a
list of *facts* (which schema objects count as complete). In every case the enumeration is the
allow/deny boundary, and in every case the adversary picked a member of the complement.

**The general principle this addendum adopts, stated once and applied six times:**

> **Scope a control by the thing it protects, identified in a way the adversary cannot change, and
> let it see every action. Never scope it by the actions you expect.**

The set of objects to protect is closed, small, and known at provisioning time. The set of DDL
statements PostgreSQL supports is open, grows every major release, and includes forms
(`DROP OWNED`, `DROP SCHEMA ... CASCADE`, `ALTER TABLE ... RENAME`) whose relationship to a
protected object is not obvious from their name. Enumerating the first is tractable. Enumerating the
second is what failed, twice, in the same mechanism.

This is the same move D26 itself made one level down, and CAP #2 gave D26 credit for it: CAP #1 §9
framed F-F as possibly unclosable because "a table owner can always drop that table's triggers,"
and D26 answered by changing *which authority decides*, not by enumerating what the owner might do.
D31 applies that reasoning to D26's own scoping.

---

### D31. The scoping principle, and where PostgreSQL actually supports it

**Decision: where a control can be scoped by protected-object identity rather than by expected
action, it must be. Where it cannot, the addendum says so and states what carries the residual.**

Three sub-decisions follow, each verified by execution against PostgreSQL 17.11 during this design
pass rather than reasoned from the manual.

**1. Object identity means OID, not name.** `pg_event_trigger_ddl_commands()` returns both `objid`
and `object_identity`. D26 compares `object_identity` (`provision_test_roles.sh:351-358`). Executed:

```
-- probe event trigger reporting everything it can see
ALTER TABLE prot RENAME TO prot_renamed;
NOTICE:  ddl_end   tag=ALTER TABLE type=table objid=16387 identity=public.prot_renamed
                                              ^^^^^^^^^^^ the ORIGINAL oid, unchanged
```

The OID is stable across `RENAME TO` and `SET SCHEMA`; the identity string is not. Comparing `objid`
closes G-G by construction rather than by adding `ALTER TABLE ... RENAME` to a list -- which would
have been the enumerative fix, and would have missed `SET SCHEMA` the same way.

**2. The OIDs must be resolved at provisioning time and stored, not resolved by name inside the
trigger.** This is not a stylistic preference; the obvious implementation does not work. A first
lab attempt wrote `IF o.objid = 'screening_ledger_anchor'::regclass::oid` directly in the function
body and failed:

```
DROP OWNED BY ddl;
ERROR:  42P01: relation "prot" does not exist
```

By the time `sql_drop` fires, the object is already gone from the catalog, so a `regclass` cast
inside the trigger cannot resolve it. The protected set therefore has to be a **relation**, written
once when the objects are known to exist.

**3. Remove the `WHEN TAG` filters entirely.** With an object-keyed check, the tag filter buys
nothing and costs exactly the two findings it caused. An unfiltered `sql_drop` trigger does see
`DROP OWNED`'s cascaded drops -- the question the audit brief asked to be confirmed, answered by
execution:

```
DROP OWNED BY ddl;
NOTICE:  sql_drop  tag=DROP OWNED type=table   objid=16387 identity=public.prot            orig=t
NOTICE:  sql_drop  tag=DROP OWNED type=trigger objid=16394 identity=prot_immutable on public.prot orig=f
NOTICE:  sql_drop  tag=DROP OWNED type=table   objid=16390 identity=public.other           orig=t
```

`pg_event_trigger_dropped_objects()` reports the cascaded drops with real OIDs, real identities, and
`original` distinguishing directly-named objects from cascade victims. **G-B does not need a
structurally different detection approach.** It needs the tag filter gone. That is worth stating
plainly because the brief allowed for the opposite answer.

**What this principle does not reach, stated rather than left to be discovered.** Three limits were
looked for and found:

- **It is a DDL control only.** Nothing here constrains DML. The row-immutability and TRUNCATE
  triggers remain the DML control, and D34 protects the functions they call -- but a role with
  `UPDATE` on a protected table and a neutered guard is a DML problem, not an event-trigger one.
- **PostgreSQL offers no ownership model where the owner is bound by the object's own protections**
  -- CAP #1 §9's statement, still true. Event triggers work because they are a *different*
  authority, not a stronger form of ownership. Extension membership (`ALTER EXTENSION ... ADD`)
  would give dependency-level protection, but requires a `.control` file on the server filesystem
  and a packaging story this repository does not have; rejected as out of proportion, and recorded
  so a later reader does not re-derive it.
- **A superuser can still drop the event triggers.** That residual is R12's and stays exactly where
  D26 put it, which is the correct place for it to terminate.

---

### D32. G-C (CRITICAL): retention becomes an externally-authenticated fact, not a server-side predicate

**The finding, restated from the code.** D27 claims (`0007:1914-1917`) that the definer function
"validates every snapshot it tombstones against `screening_ledger_snapshot`'s `expires_at`, so even
through the sanctioned path the migrator cannot record a purge for a snapshot that is not actually
expired." Both overloads gate on `expires_at < p_before`
(`db/migrations/019_screening_ledger_purge_definer.sql:46`, `:78`). `p_before` is a caller argument
(`postgres.go:542`, `:570`). `expires_at` lives in `screening_ledger_snapshot`, a table
`owl_migrator` owns and inserts into -- as `tombstone_forgery_pgx_test.go:75-78` does itself. CAP #2
§7.3 executed both halves: `p_before => 'infinity'` tombstoned two snapshots expiring in ten years,
and a fabricated snapshot row with a past `expires_at` was tombstoned under a perfectly sane
`p_before`. Then, end to end through the shipped CLI, `verify` returned `"status":"ok"` with
`"anchor_status":"verified"` at exit 0 on a ledger whose snapshot content had been tampered with.

**Why this is F1's shape and not a bug in the predicate.** D8 named the class exactly
(`0007:941-968`): the verified data must not choose its own acceptance criteria. F1 was a chain that
selected its own digest algorithm. G-C is a *retention claim* that supplies its own evidence of
expiry. Tightening the predicate -- clamping `p_before`, reading `expires_at` from a different table
-- is the `sawV2` fix all over again: it removes the instance and leaves the class, because every
candidate source inside the mirror is writable by the role the record exists to constrain. D8's
answer was to move the fact outside the adversary's reach and authenticate it. D32 does the same.

**Decision: a purge is legitimate if and only if it is attested by an audit-chain entry at or below
the anchored `audit_sequence`.**

The audit chain is already the right instrument and it is already built:

- `AppendAudit` (`audit.go:14`) marshals `details` into `AuditEvent.Details`
  (`types.go:99`), and `hashAudit` (`audit.go:151`) MACs the entire marshalled event under
  `K_chain` -- so `Details` is inside the chain digest, verified today, with no format change.
- `Store.PurgeExpired` already writes such an entry (`replay.go:251`), but its `details` payload is
  `map[string]int{"snapshot_count": purged}` -- a count. It must carry the sorted, deduplicated
  `snapshot_sha256` set instead.
- The anchor already commits the audit chain: `anchor_mac` covers `audit_sequence` and
  `audit_sha256` (D11, AR7), and `VerifyAnchored` cross-checks both (`anchor.go:344-359`). An
  adversary holding `K_chain` can forge a purge attestation; they cannot get it *anchored*, because
  that needs `K_anchor`, which §2 excludes. That is limb (b)'s argument, applied to retention.

**The adjudication rule.** A snapshot `S` whose local envelope is marked purged is accepted as
legitimately purged if and only if **all** of:

1. a verified audit entry `A` exists with `A.Action == "purge_expired"` and
   `S ∈ A.Details.snapshot_sha256`; and
2. `A.Sequence <= latest.AuditSequence` -- the attestation is at or below what the anchor committed;
   and
3. a tombstone row exists for `S` (`IsPurgeRecorded`, `postgres.go:511`).

Condition 3 is retained deliberately, and its status changes: **the tombstone stops being the
authority and becomes corroboration.** It is not load-bearing after D32 -- an adversary who can
forge it gains nothing, because conditions 1 and 2 are the gate -- but the two records disagree only
when something is wrong, so requiring both costs nothing and detects mirror/ledger divergence for
free. Stating this explicitly matters: a later reader must not remove condition 3 on the reasoning
that D32 made it redundant, nor re-strengthen it on the reasoning that it is still the evidence.

**An ordering problem this design has to solve rather than discover.** `verifySnapshotChecked` is
called from inside `VerifyPolicy`'s event loop (`store.go:393`), which runs *before*
`verifyAuditPolicyLocked` has verified the audit chain (`store.go:411`) and long before
`VerifyAnchored` reads the anchor at all (`anchor.go:272`, after its own call to `VerifyPolicy` at
`:245`). Condition 2 is not evaluable where the decision is currently made.

**Decision: `VerifyPolicy` collects, `VerifyAnchored` adjudicates.**

- `verifySnapshotChecked` stops deciding. On a purged envelope it records a **claim** --
  the snapshot sha and the event sequence that referenced it -- and returns `performed = false`
  with the claim appended to the report.
- `VerifyReport` gains `PurgeClaims []PurgeClaim`. `VerifyPolicy` returning claims is not
  acceptance: a caller that uses `VerifyPolicy` directly and ignores them would recreate the gap, so
  **`VerifyPolicy` fails closed on any unadjudicated claim unless the caller opts into deferral**
  through an explicit field on `VerifyOptions` that only `VerifyAnchored` sets. "I collected this
  for someone else to judge" and "I judged it" must not share a return value -- D12's rule, applied
  to a new boundary.
- `VerifyAnchored` adjudicates every claim after the anchor cross-check succeeds, and only then
  computes the final `SnapshotChecksPerformed`. D28's zero-checks gate (`store.go:424`) moves with
  it, and is strengthened: see below.
- In `historical-unanchored` mode there is no anchor, so condition 2 cannot hold. That mode already
  tolerates skipped snapshot checks by explicit double gate (`store.go:604-611`,
  policy `allow_unanchored`), and continues to -- unchanged, and now the only mode that does.

**D28's counter gate is strengthened in the same decision, because G-C walked straight past it.**
CAP #2 §7.3 hid exactly one snapshot of four; `SnapshotChecksPerformed == 0 && SnapshotChecksTotal > 0`
(`store.go:424`) never fired. After D32 the gate is not the defence -- adjudication is -- but the
counter should still say something true, so in anchored mode **every** claim must adjudicate
successfully or verification fails. There is no partial-skip budget. A ledger with legitimately
purged snapshots verifies because each purge is anchored, not because few enough were skipped.

**Hardening that rides along, explicitly labelled as hardening and not as the fix.** Neither of
these closes G-C on its own and neither should be cited as if it did:

- `screening_ledger_purge_snapshots` drops the caller-supplied `p_before` and uses
  `clock_timestamp()` server-side. A caller cannot choose the present.
- The expiry floor reads `screening_ledger_event.expires_at` (`008g:3` -- a column on a relation
  carrying a row-immutability trigger, and one whose value is inside the chain-MACed `Event`) joined
  through `request_snapshot_sha256` / `response_snapshot_sha256`, rather than
  `screening_ledger_snapshot.expires_at`. `owl_migrator` still owns that table too, so this raises
  the cost of the forgery without eliminating it -- which is precisely why it is not the fix.

**The transitional state, named rather than left as a default.** Ledgers that purged snapshots
before D32 ships have `purged_at` set locally and a tombstone row, but no audit attestation carrying
a sha set, so they would fail adjudication. There are **zero anchor rows in any environment** and
`screening-ledger` remains absent from `runtime_executables`
(`scripts/deployment/r2-4/harness/config/policy.json:150-155`, re-confirmed at this commit), so no
such ledger exists anywhere. The migration cost is zero now and unbounded later -- the same argument
D11 made for `017`, D25 made for policy `v2`, and §6 made for the fixture. **No backward
compatibility path is provided, and that is the decision, not an omission.**

### D33. G-A (HIGH): migration and provisioning are two completion conditions, and `Migrate()` proves one

**The finding.** `checkRequiredSchemaObjects` (`postgres.go:249-283`) proves that
`db/migrations/*.sql` produced its objects. It does not prove that
`provision_test_roles.sh grant-ddl-ownership` ever ran. CAP #2 §7.5 built a database with all
sixteen migrations applied and provisioning skipped: `migrate` printed
`{"operation":"migrate","screening_ledger_anchor_owner":"owl_migrator","status":"ok"}` at exit 0,
`owl_migrator` owned both protected tables, no event trigger existed, the CAP §7.7 tombstone forgery
succeeded, `ALTER TABLE ... DISABLE TRIGGER` on the anchor's own guard succeeded, `Migrate()` still
reported success and **did not re-enable the trigger**, and the in-place anchor rewrite went through.

Three distinct gaps compose there, and all three are the enumeration shape:

1. `triggerExists` (`postgres.go:291-298`) matches `tgname` and `NOT tgisinternal`. It never reads
   `tgenabled`. A `DISABLE`d trigger is a present trigger.
2. Nothing in any runtime path queries `pg_event_trigger`. D26's installation is unobserved outside
   `ddl_event_trigger_pgx_test.go:97-116`, which is a CI test against the CI database, not something
   an operator runs against a deployment.
3. Ownership is "reported, not enforced" by D21 point 3 (`0007:1641-1645`). `SchemaObjectOwner`
   (`postgres.go:318`) returns it and `main.go:38-39` prints it; nothing compares it to anything.

**D21 point 3's reasoning was sound and is not reversed.** A `SchemaSQL`-only bootstrap legitimately
leaves `owl_migrator` owning these tables, and a fully provisioned deployment does not; both are
valid *post-`Migrate`* states. The error was concluding from that that nothing may ever assert the
difference. The two states are not equally valid for *verification*.

**Decision: name the second completion condition, assert it where it is load-bearing, and report it
everywhere else.**

- **A literal `requiredProvisioningState` declaration**, written out in `postgres.go` beside
  `requiredSchemaObjects` (`postgres.go:178`), never derived by inference per CLAUDE.md's
  "never enumerate targets by inference". Note that this is an enumeration of *protected objects*,
  which D31 permits, not of expected actions. Its members:
  - both event triggers by name, each with `evtenabled = 'A'`;
  - `relowner` of `screening_ledger_anchor` and `screening_ledger_retention_tombstone` = `owl_ledger_ddl`;
  - `prosecdef` true and `proowner` = `owl_ledger_ddl` for both `screening_ledger_purge_snapshots` overloads;
  - `has_table_privilege('owl_migrator', 'screening_ledger_retention_tombstone', 'INSERT')` false;
  - `has_table_privilege('owl_migrator', 'screening_ledger_anchor', 'INSERT')` false;
  - `has_table_privilege('owl_ledger_anchor', 'screening_ledger_anchor', 'SELECT')` false.
- **Every one of those facts is readable by `owl_migrator`**, which is not obvious and was checked
  by execution rather than assumed -- a non-superuser can read `pg_event_trigger.evtenabled`,
  `pg_trigger.tgenabled`, `pg_class.relowner`, `pg_proc.prosecdef`/`proowner`, and
  `has_table_privilege` for other roles. No new role, DSN or grant is required to run this check.
- **`tgenabled` joins the existing schema check unconditionally.** No legitimate state has a
  disabled guard trigger, so this is not a mode question: `triggerExists` becomes
  `triggerEnabled`, asserting `tgenabled = 'O'`. This is a strict tightening of D21 with no
  new configuration.
- **Where each condition bites.** `Migrate()` continues to assert the schema condition and now
  **reports** the provisioning condition; it does not fail on it, because the bootstrap path is
  real. **`VerifyAnchored` requires it** whenever a database is supplied. A verification run against
  a database whose protections were never installed is exactly the "I could not check" outcome D12
  exists to remove (`0007:1090-1128`), and it must not share an exit code with "I checked and it was
  fine."
- **Interface cost, stated because it is not free.** `AnchorReader` (or `AnchorOptions`) gains a
  provisioning-state reader. `opts.Anchors` is an interface specifically so a nil is a checked nil
  (`anchor.go:240-243`); adding a method means every in-package test fake gains it too. That is the
  price of making the check unavoidable rather than optional, and it is the right price -- an
  optional check is the shape F1 and G-A both have.

### D34. G-B, G-D, G-G (HIGH, HIGH, LOW): D26 becomes object-scoped -- one mechanism, three findings

These three are one decision because they are one mechanism and one root cause: D26 scopes by action
and by name. Splitting them would produce three enumerative patches.

**Decision: replace D26's two tag-filtered, identity-matching event triggers with two unfiltered,
OID-matching ones backed by a provisioning-populated registry.**

- **`sec7_protected_object`** -- a new relation, created and populated by
  `provision_test_roles.sh grant-ddl-ownership` (which becomes `grant-ddl-ownership` proper, since
  it now provisions three things), owned by the bootstrap superuser, `REVOKE ALL ... FROM PUBLIC`,
  with `SELECT` granted to `owl_migrator` so D33's check can read it. It holds one row per protected
  object: `objid`, plus a human-readable note for diagnostics. Its members:
  - `screening_ledger_anchor`, `screening_ledger_retention_tombstone`;
  - `screening_ledger_anchor_immutable`, `screening_ledger_anchor_no_truncate`,
    `screening_ledger_retention_tombstone_immutable`,
    `screening_ledger_retention_tombstone_no_truncate` (by `pg_trigger.oid`);
  - **`screening_ledger_reject_mutation()` and `owl_reject_truncate()`** -- G-D. These are the
    functions all eight guard triggers call, they are created by `008g:10` and
    `012_truncate_guards.sql:9` respectively, and again by `SchemaSQL` (`postgres.go:633`,
    `:648`) -- every one of those statements runs as `owl_migrator`, which therefore owns them. CAP #2
    §7.4 replaced the first with `BEGIN RETURN NEW; END` and rewrote an anchor row in place with no
    DDL D26 inspects, then neutered the second and `TRUNCATE`d the anchor table to zero rows with
    both triggers still present and enabled;
  - both `screening_ledger_purge_snapshots` overloads -- D27 explicitly left these out
    (`provision_test_roles.sh:335-340`) on the reasoning that they stay "within `owl_ledger_ddl`'s
    own authority to alter." After D32 the definer function is part of the retention control, and
    after G-B showed the owner can destroy it wholesale, that reasoning no longer holds;
  - `sec7_protected_object` itself, so the registry cannot be dropped without tripping the trigger
    that reads it.
- **`sec7_protect_ddl_objects()` becomes `SECURITY DEFINER`** with `SET search_path = pg_catalog, public`,
  owned by the bootstrap superuser. **This is load-bearing, not hygiene**, and it was found by
  execution: a first lab build left the function `SECURITY INVOKER` (the current default at
  `provision_test_roles.sh:332`), so its `SELECT` on the registry ran as the invoking role and every
  DDL statement in the database failed with `permission denied for table sec7_protected` --
  including unrelated `CREATE TABLE`. That is D26's own "database-wide blast radius" risk
  (`0007:1863-1866`) realised, and it would have shipped.
- **Both event triggers lose their `WHEN TAG` clause.** `ON sql_drop` and `ON ddl_command_end`,
  unfiltered, `ENABLE ALWAYS` as now. The function returns immediately on a registry miss.
- **The comparison is `objid`, never `object_identity`.** Identity strings are kept in the raised
  error text, for diagnostics only.

**Executed, in full, during this design pass.** Against a lab table owned by a `ddl` role, a guard
function owned by a `mig` role, and the registry design above:

| Attempt | Result |
|---|---|
| `DROP OWNED BY ddl` (G-B) | `ERROR: SEC7 BLOCKED drop: tag=DROP OWNED type=table identity=public.prot` |
| `ALTER TABLE prot RENAME TO x` (G-G) | `ERROR: SEC7 BLOCKED ddl: tag=ALTER TABLE type=table identity=public.x` |
| `ALTER TABLE prot SET SCHEMA ...` | `ERROR: SEC7 BLOCKED ddl: ... identity=public.prot` |
| `CREATE OR REPLACE FUNCTION guard()` as `mig` (G-D) | `ERROR: SEC7 BLOCKED ddl: tag=CREATE FUNCTION type=function identity=public.guard()` |
| `DROP TRIGGER prot_immutable` (D26 form 1) | blocked |
| drop-then-`DELETE` (D26 form 2) | blocked |
| `ALTER TABLE ... DISABLE TRIGGER ALL` (D26 form 4) | blocked |
| `DROP TABLE prot` (D26 form 5) | blocked |
| unrelated `CREATE TABLE` / `DROP TABLE` / `CREATE OR REPLACE FUNCTION` / superuser DDL | **all succeed** |
| `DROP OWNED BY mig` where `mig` owns only unprotected objects | succeeds, or fails on an ordinary dependency error |

All four CAP #2 escapes closed, all five original D26 forms still closed, no collateral damage. That
this is a design pass does not make the transcript optional -- D26's proof obligation
(`0007:1874-1885`) exists because a design that asserts its own mechanism is how F1 shipped.

**The event trigger's own self-protection was confirmed too**, since the audit brief raised it and
D34 changes the object: as a non-superuser, `DROP EVENT TRIGGER`, `ALTER EVENT TRIGGER ... DISABLE`,
`CREATE OR REPLACE FUNCTION sec7_protect_ddl_objects`, `DROP FUNCTION` and
`ALTER FUNCTION ... OWNER TO` all fail with `must be owner of ...`. The residual terminates at the
superuser, exactly as R12 says.

### D35. G-E (HIGH): the membership window is deleted, not narrowed

**The finding.** `provision_test_roles.sh` runs `GRANT owl_ledger_ddl TO owl_migrator` (`:160`),
`ALTER TABLE screening_ledger_anchor OWNER TO owl_ledger_ddl` (`:161`), and only afterwards the
`REVOKE` at `:169`, whose comment (`:163-168`) claims it "runs unconditionally ... this is what
makes a partially-completed prior run ... self-heal on retry." It runs unconditionally *in source
order*; the script is `set -euo pipefail` (`:23`), so a failure of the `ALTER TABLE` -- or a SIGINT,
or a cancelled CI step -- aborts before `:169`. **Role membership is cluster-wide.** CAP #2 §7.9
reproduced it: a failed provisioning run against one database left `owl_migrator` a member of
`owl_ledger_ddl`, and on a *separate, correctly provisioned* database the failed run never touched,
`owl_migrator` gained `INSERT` on both protected tables and the CAP §7.7 forgery succeeded. The only
membership check in the tree is the script's own postcondition at `:198-202`, after the `REVOKE`,
unreachable on exactly the path that creates the leak.

**Decision: the `GRANT`/`REVOKE` pair is removed. The window does not exist because the grant does
not happen.**

The membership is unnecessary. `ALTER TABLE ... OWNER TO` requires the executing role to be able to
`SET ROLE` to the new owner **only when that role is not a superuser**. This script connects as
`psql_super` (`:44-46`), the bootstrap superuser INFRA-3 provisions (`:20-22`). Executed:

```
owl_ci member of ddl: false
ALTER TABLE own_probe OWNER TO ddl;      -- as superuser owl_ci: SUCCEEDS
                                          owner now: ddl
ALTER TABLE mig_probe OWNER TO ddl;      -- as non-superuser mig: ERROR: must be able to SET ROLE "ddl"
```

The `GRANT` at `:160` was addressing a constraint that does not apply to the identity actually
running it. Deleting it is strictly better than any cleanup: a trap can be defeated by `SIGKILL`, a
retry only helps if a retry happens, and both leave a window. This is the principle from D31 in its
strongest form -- do not close the hole, remove the thing that opens it.

**Two supporting changes, both belt-and-braces rather than the fix:**

- **The ownership-transfer step runs in one transaction.** `GRANT`/`REVOKE` of role membership *is*
  transactional, verified: inside a transaction the membership is visible, after `ROLLBACK` it is
  gone, and an error mid-transaction rolls it back. So even if a future change reintroduces a
  membership grant, a single `BEGIN ... COMMIT` around the step makes the window atomic. Recorded
  because the next person to need a membership should not have to rediscover this.
- **A non-membership precondition runs first, not last.** The script asserts
  `owl_migrator` is not a member of `owl_ledger_ddl` **before** doing anything, so a dangling
  membership left by an older script version, an interrupted run, or a manual grant is detected and
  refused rather than silently inherited. The existing assertion at `:198-202` stays where it is;
  this is an addition, and the two together mean the property is checked on both edges.

**And it becomes observable outside the script.** D33's `requiredProvisioningState` already asserts
`has_table_privilege('owl_migrator', 'screening_ledger_retention_tombstone', 'INSERT')` is false,
which is true if and only if the membership is absent -- so the leak CAP #2 found becomes a
verification failure on the next `verify`, not something only a full `go test` run against that
database can see.

### D36. G-F (MEDIUM): the signer decides what "valid" means, and both ends enforce it

**The finding.** `runSign` (`cmd/screening-ledger-policy/main.go:72-98`) is `os.ReadFile` →
`json.Unmarshal` → `SignVerificationPolicy`. No field is examined. CAP #2 §7.8 signed: a document
with `min_anchor_seqence` (one transposed letter), which produced a signed artifact with
`min_anchor_sequence = 0`; a document omitting the field, same result; a `v1`-labelled document with
an empty `ledger_id`, empty schema floors, zero genesis boundaries and `allow_unanchored: true`; and
`{"hello":"world"}`, which produced a signed, all-zero policy.

The silent zero is the operationally dangerous one. `min_anchor_sequence` is the only mechanism
bounding anchor rollback (D25, R14), `uint64` zero-fills on both a typo and an omission, and every
artifact this repository ships carries `0`: the committed fixture
(`test/fixtures/screening-ledger/policy/example-policy.signed.json`), the operator procedure's
template (`docs/operations/screening-ledger-policy-signing.md:56`), and the in-test helper
(`cmd/screening-ledger/main_test.go:106-124`, whose `VerificationPolicy` literal omits the field).

**Decision: define validity as a property of the artifact, enforce it in one function, and call that
function from both the producer and the consumer.**

- **`VerificationPolicy.Validate() error`**, in `policy.go` beside the types it validates:
  - `SchemaVersion` exactly `VerificationPolicySchemaV2` (`policy.go:29`) -- the same equality the
    load path already applies at `:135`, moved into the shared function so the signer applies it too;
  - `LedgerID` non-empty after trimming;
  - `MinEventSchema` and `MinAuditSchema` recognised by the existing ordinal lookups
    (`eventSchemaOrdinal`/`auditSchemaOrdinal`, `store.go:75`), not merely non-empty -- an unrecognised floor is a policy that can never
    accept anything;
  - `GenesisEventSequence >= 1` and `GenesisAuditSequence >= 1` -- sequence numbering in this ledger
    starts at 1 (`store.go:352`), so 0 is not a boundary, it is an unset field.
- **Strict decoding, which is what actually catches the typo.** `json.Decoder` with
  `DisallowUnknownFields()`, so `min_anchor_seqence` is an error rather than a silently ignored key.
  This is established practice in this repository, not a new idea: `cmd/policy-evaluate/main.go:46`,
  `cmd/release-config/main.go:52`, `cmd/catalog-registry/main.go:187`, `cmd/matcher-project/main.go:33`
  and three others already do it, and `cmd/policy-evaluate/main_test.go:145` shows the test shape
  that proves it fired. It is also D31's principle at the JSON layer: accept the closed set of known
  fields, reject the open set of everything else.
- **Presence, not just validity, for `min_anchor_sequence`.** Strict decoding catches a misspelling
  but not an omission, and an omitted floor is the exact failure that matters. The unsigned input
  document is therefore decoded through a shadow struct whose fields are pointers, and every field
  must be present. An operator who genuinely wants no floor writes `"min_anchor_sequence": 0` and
  means it. Silence stops being a value.
- **Both ends call it.** `SignVerificationPolicy` (`policy.go:98`) refuses to sign an invalid
  policy, and `LoadSignedVerificationPolicy` (`policy.go:123`) refuses to load one, after the
  signature check and before returning. A policy that cannot be validated can be neither produced
  nor consumed. Enforcing at one end only would leave the other as the gap -- which is what
  `policy.go:135` being the sole check produced.
- **`keygen` and `fingerprint` are unchanged.** They were correct: `keygen` writes mode `0400`
  (`cmd/screening-ledger-policy/main.go:61`, confirmed by CAP #2), and `fingerprint` reproduces
  `PolicyPublicKeyFingerprint` (`policy.go:156`).

**What this does not claim.** D36 does not make the signer trustworthy against an operator who is
handed a hostile-but-valid policy document; nothing can, since a valid policy is exactly what the
operator is authorising. It closes the gap between "what the operator wrote" and "what got signed,"
which is where the silent zero lived. R8's operator-discipline residual is unchanged.

**The committed example private key was re-examined and needs no change.**
`test/fixtures/screening-ledger/policy/example-signing-key.hex` is real signing material for the
example public key; its README labels it as throwaway example material in its first sentence, the
operator procedure directs the reader to `keygen` on an offline host, and CAP #2 §7.8 confirmed
nothing in `docs/`, CI or `scripts/` routes it into a trust-root position. Recorded because a
committed private key deserves an explicit verdict rather than silence.

### D37. Test ownership and pre-declared withdrawal conditions

The specific shape the implementation must satisfy, so nothing weaker can be claimed to discharge
this addendum -- the standard D20 (`0007:1293-1338`) and D26 (`0007:1874-1885`) set.

**Every test below must fail before its change.** Where a CAP #2 transcript exists, the test
reproduces that transcript, not a paraphrase of it.

1. **D32.** `TestPurgeRequiresAnchoredAttestation` (pgx): reproduce CAP #2 §7.3's chain end to end --
   tamper one snapshot of four, mark it purged, tombstone it through the definer function, and
   assert `VerifyAnchored` **fails**. Today this sequence exits 0 with `"status":"ok"`.
   `TestPurgeSnapshotsIgnoresCallerTimestamp`: assert the `'infinity'` call tombstones nothing.
   `TestVerifyPolicyFailsClosedOnUnadjudicatedClaims`: a direct `VerifyPolicy` caller that does not
   opt into deferral gets an error, not a report.
2. **D33.** `TestVerifyAnchoredRefusesUnprovisionedDatabase` (pgx, against a database migrated in
   full with `grant-ddl-ownership` skipped -- the `owl_p4` state CAP #2 §7.5 built).
   `TestMigrateFailsOnDisabledGuardTrigger`: `ALTER TABLE ... DISABLE TRIGGER`, then `Migrate()`
   must fail. Today it returns nil and leaves the trigger disabled.
3. **D34.** `TestD34EventTriggerBlocksEveryCAPTwoEscape`: the four escapes above, each as its own
   attempt with the SQLSTATE captured, **plus** the five original D26 forms unchanged, **plus** the
   four tombstone-relation forms CAP #2 §7.1 added, **plus** a collateral-damage case asserting that
   unrelated `CREATE TABLE`, `DROP TABLE` and `CREATE OR REPLACE FUNCTION` still succeed. A suite
   that proves only the blocks has not proven D34 is safe to install.
4. **D35.** `TestProvisioningLeavesNoDanglingMembership`: assert `pg_auth_members` holds no
   `owl_migrator`→`owl_ledger_ddl` edge after a successful run **and** after a deliberately failed
   one. This is the test whose absence let G-E ship.
5. **D36.** Table-driven over CAP #2 §7.8's four inputs, each asserting a specific refusal, and one
   asserting the committed example fixture still signs and loads.

**Withdrawal conditions, declared now rather than decided after the fact:**

- **If D34's collateral-damage cases fail** -- if an unfiltered event trigger breaks unrelated DDL in
  this schema in a way the lab did not reproduce, most plausibly around SEC-1's RLS migrations or
  `db/rollback/014_tenant_isolation_down.sql` -- D34 falls back to `WHEN TAG` filters restored
  *plus* OID matching, which still closes G-G and G-D but leaves G-B open behind a longer tag list.
  That fallback is strictly worse and must be recorded as such, not presented as equivalent.
- **If D32's adjudication cannot be implemented without restructuring `VerifyPolicy`'s return
  contract beyond what this addendum describes**, the implementation stops and the design is
  amended. It does not ship a partial adjudication that accepts some claims -- a purge check that
  runs sometimes is the shape of every finding in this document.

### New accepted risks

**R15 -- the protected-object registry is a new trust object, and a stale registry fails open.**
`sec7_protected_object` holds OIDs, and an OID is only meaningful while the object it names exists.
If a protected object is legitimately dropped and recreated -- which after D34 requires a superuser
to remove the event triggers first -- the registry silently protects an OID nothing uses, and the
new object is unprotected. This is a fail-open shape and it is accepted only because D33 closes it:
`requiredProvisioningState` asserts that every registry row's OID resolves to the object it claims,
so a stale registry is a verification failure rather than a silent gap. The registry and the check
that validates it must ship together; either alone is worse than neither. Recorded so that a later
change to one is understood to require the other.

**R16 -- purge attestation is anchor-cadence bound.** After D32 a snapshot purged since the last
anchor cannot be verified as legitimately purged until the next anchor is written. Retention
therefore becomes a third consumer of anchor cadence, alongside R2/R11's tamper-detection window and
R14's rollback window -- and anchor cadence is still unwired (`policy.json:150-155`). The failure
mode is fail-closed and recoverable (write an anchor), which is the correct direction, but it means
an operator who purges and then verifies before anchoring sees a failure that is not a compromise.
`verify` should say which claims are unattested and at what audit sequence, so the distinction is
readable rather than inferred. Recorded here rather than designed, because scheduling remains
§8/D6/D18's separate concern and this addendum does not reopen it.

**R17 -- the event trigger's blast radius widens from four tags to every DDL statement.** D26 named
this risk while filtering to four tags (`0007:1863-1866`); D34 removes the filter, so the trigger
function now runs on every DDL statement in the database. The mitigations are that the function is
`SECURITY DEFINER` (so it cannot fail on privilege), that its body is a single indexed lookup with
an early return, and that the collateral-damage cases in D37 are a shipping requirement rather than a
nicety. The residual is that a future defect in that function breaks all DDL rather than some.
Accepted, because the alternative -- a tag list -- is the thing that failed twice.

### Staging

Same shape and reason as §8, Addendum 1 (`0007:1397-1414`) and Addendum 2 (`0007:2038-2058`): each
stage independently reviewable and independently provable.

1. **This addendum**, merged before any code (CLAUDE.md rule 7).
2. **Stage E1 -- the DDL boundary.** D34 and D35 together, plus D33's `tgenabled` tightening. One
   stage because D34's registry is created by the same provisioning step D35 rewrites, and because
   D34 without D35 leaves the membership leak able to hand `owl_ledger_ddl` to `owl_migrator`
   anyway. D31's principle is discharged or withdrawn here.
3. **Stage E2 -- provisioning as a verified fact.** D33 in full, which depends on E1 having created
   the registry and the event triggers whose presence it asserts.
4. **Stage E3 -- retention becomes anchored.** D32, the CRITICAL. Sequenced after E2 because its
   adjudication runs inside `VerifyAnchored`, which E2 has just given a provisioning precondition,
   and because D32's `VerifyReport` change is the largest single change to the verification contract
   since D12. Not sequenced first despite its severity, and that is a deliberate call: G-C's
   exploitation requires a database whose protections are otherwise intact, so E1 and E2 do not
   widen the window while E3 is pending.
5. **Stage E4 -- the signer.** D36. Blocks nothing else.
6. **`SECURITY.md` and `README.md` language.** R3's rule unchanged. `README.md:93-97`'s
   requalification notice stays until every stage above has landed and its reproduction passes. CAP
   #2 re-confirmed that nothing in PR #138 or #139 re-asserted the guarantee; that must remain true
   through this addendum as well.

**SEC-7 does not close on this addendum.** §8's closing condition -- "a deliberately forged chain
fails a CI run that nobody chose to invoke" -- is met in the CI sense by `d20_exploit_test.go`, and
since D23 it is met in the operational sense too. It is contradicted by CAP #2 §7.3 for as long as
`verify` prints `"status":"ok"` at exit 0 on a tampered snapshot. The closing sentence stands and now
has a third addendum behind it.

### Addendum 3 summary

- **CAP #2's verdict is QUALIFIED, not PASS**, for the second consecutive audit: one CRITICAL, four
  HIGH, six of seven findings demonstrated live. This addendum designs the remediation.
- **The class is sharper than Addendum 2's phrasing of it.** Not "asserted rather than checked" but
  **"scoped by listing members of an open set."** Six of ten Addendum 2 mechanisms are such a list;
  each was defeated by a member of its complement. D31 states the replacement principle: scope by
  the protected object, identified by something the adversary cannot change, and see every action.
- **The design is D31-D37.** The scoping principle with its PostgreSQL support established by
  execution (D31); retention as an anchored, externally-authenticated fact rather than a server-side
  predicate over caller-owned data (D32); provisioning named as a second completion condition,
  asserted where it is load-bearing (D33); D26 rebuilt as an OID-keyed, unfiltered, `SECURITY
  DEFINER` control covering the tables, the triggers, the guard functions and the registry itself
  (D34); the membership window deleted rather than narrowed (D35); a validity contract enforced at
  both the producing and consuming end of the policy artifact (D36); and the proof obligations with
  pre-declared withdrawal conditions (D37).
- **This design pass executed its mechanism assumptions**, which is a departure from Addendum 2 and
  the direct lesson of three of CAP #2's findings. `DROP OWNED`'s cascaded drops **are** visible to
  `pg_event_trigger_dropped_objects()`; a renamed object keeps its `objid`; `CREATE OR REPLACE
  FUNCTION` reports the existing function's `objid`; a superuser needs no membership to transfer
  ownership; role-membership grants are transactional; and an invoker-rights event trigger reading a
  registry table breaks every DDL statement in the database. The last of those would have shipped.
- **Three risks are recorded** rather than designed away: the registry is a new trust object whose
  staleness fails open and is closed only by D33 (R15), purge attestation joins anchor cadence as a
  security parameter (R16), and the event trigger's blast radius widens to all DDL (R17).
- **This addendum revises no prior decision.** D1-D7, D8-D20, AR7 and D21-D30 stand. R1-R14 stand;
  D21 point 3's "ownership is reported, not enforced" is not reversed -- D33 adds a second,
  differently-scoped assertion beside it and says why both are correct.

**Audit basis commit:** `b2fe831e8e556b324e28a3af05aef98240d00f83`

Every file:line citation in this addendum was verified against that tree -- the same commit CAP #2
was produced against, so no drift separates the audit from this design. For a CAP record covering
the implementation of this addendum, use the tip of whichever stage PR is under audit, not this
value.

## Addendum 4: the referent principle -- what a control compares, and the third CAP's six findings (2026-08-20)

- **Status:** Proposed
- **Trigger:** a third Composition Audit Program record produced against the implemented Addendum 3
  (`docs/backlog/sec-7-cap-record-3c7e5be.md`, adversarial posture, audit basis commit
  `3c7e5be6dd5e893b7704aebd54a81afd4d89d44a`) returned **QUALIFIED, not PASS** for the third
  consecutive audit: six findings, one CRITICAL, three HIGH and two MEDIUM, five of them demonstrated
  live against a PostgreSQL 17.11 cluster provisioned by `scripts/ci/provision_test_roles.sh` exactly
  as `.github/workflows/ci.yml:97-140` does it. The CRITICAL was demonstrated end to end from an
  adversary holding **no keys at all** through to a `VerifyAnchored` returning
  `anchor_status=verified` with `snapshot_checks=6/6` on a chain whose content was tampered and whose
  every digest was recomputed under an unkeyed formula. **SEC-7 is not closed.**
- **What CAP #3 confirmed and this addendum does not disturb.** D31's principle is correct and, where
  it was applied, held against everything the audit threw at it: eight `ALTER TABLE` forms,
  `DROP OWNED`, `RENAME TO`, `SET SCHEMA`, `SET TABLESPACE`, `DISABLE TRIGGER`,
  `DISABLE ROW LEVEL SECURITY`, `ALTER TRIGGER ... RENAME`, `CREATE OR REPLACE FUNCTION` on the shared
  guards, every attempt against the event triggers themselves, and direct catalog writes -- all
  blocked. G-B, G-D and G-G are closed. **D32 is closed and is the strongest thing in Addendum 3**:
  the collect/adjudicate split is airtight, the three-condition rule is exact at every boundary
  tested, and no caller anywhere in the module can read `PurgeClaims` without adjudication. G-E is
  closed: the membership window is deleted, and the regression test that should have existed now
  does. D11's policy binding defeated two independent attacks in that audit that were not aimed at
  it. None of that is reopened here.
- **Scope:** a pure addition. Nothing above this section is edited -- not D1-D7, not D8-D20, not AR7,
  not D21-D30, not D31-D37, not R1-R17. Decision numbering continues at **D38**, risk numbering at
  **R18**. Where a prior decision's *text* is wrong rather than merely superseded -- D35's
  biconditional, which CAP #3 found false as written -- the new decision says so in its own words and
  states what the old claim actually rests on afterwards. That is the convention AR7 established for
  R7 and Addendum 3 followed for D21 point 3, and it applies to a false claim as much as to a changed
  disposition: **a silently patched implementation under a standing false sentence is worse than
  either alone**, because the next reader reasons from the sentence.
- **Verification basis:** every `file:line` below was re-derived from the working tree at
  `3c7e5be6dd5e893b7704aebd54a81afd4d89d44a` rather than copied from the CAP record.
- **This design pass executed its mechanism assumptions, as Addendum 3 established and CAP #3 itself
  held to.** Every PostgreSQL, Go `encoding/json` and chain-digest behavioural claim this addendum
  depends on was run against a purpose-built disposable PostgreSQL 17.11 cluster and against real
  builds of this repository's own code at this commit, before the decision that relies on it was
  written. The transcripts are in the sections that rely on them. Two of them changed the design:
  `pg_depend` turned out **not** to be a sound structural resolver for D40 (a benign `CREATE VIEW`
  over a protected table is indistinguishable from an inheritance attachment by dependency type
  alone), and a pure length bound on the genesis boundary turned out **not** to close H-A. Both are
  recorded below with the transcript that refuted them, because a design that asserts its own
  mechanism is how F1 shipped.

### Drift found while writing this addendum

Recorded rather than silently corrected, the convention §3.4, §6.1, `0007:717-720`, `0007:1474-1490`
and `0007:2141-2160` set.

1. **Addendum 3's `file:line` citations resolve against `b2fe831`, not against this tree.** PR #141
   moved most of them -- `store.go:393` became `:395` for the genesis branch, `postgres.go:511`
   became `:666` for `IsPurgeRecorded`, `policy.go:98` became `:211` for `SignVerificationPolicy`.
   Addendum 3 says as much at `0007:2755-2758`, and CAP #3 §12 re-confirmed it. This is expected and
   is not a defect. Citations *into Addendum 3's own prose* (`0007:NNNN`) are unaffected and are used
   below where the claim is about the text rather than about the code.
2. **`0007:2323` cites `IsPurgeRecorded` at `postgres.go:511`.** At this commit it is
   `postgres.go:666`. Substance unchanged.
3. **CAP #3 revises one of CAP #2's severity ratings, and this addendum adopts the revision.** G-F
   (the signer validates nothing) was rated MEDIUM, and D36 was designed against that rating. The
   *residual* left after D36 is CRITICAL, not MEDIUM -- not because D36 failed at what it set out to
   do (it refuses both of CAP #2 §7.8's inputs; re-confirmed by execution below) but because G-F was
   rated on `min_anchor_sequence` silently becoming `0`, an anchor-rollback bound, while the same
   signed artifact also carries `genesis_event_sequence`, and that field selects **which digest
   formula verifies the entire chain** (`store.go:395`). A policy field that chooses between a keyed
   HMAC and an unkeyed SHA-256 is an F1-class control surface. H-A inherits the correction and is the
   CRITICAL of this addendum.

---

### Addendum 4 context: the enumeration was fixed and the referent drifted

Addendum 1 diagnosed the original's structural error as fixing instances rather than causes
(`0007:1494-1497`). Addendum 2 named its findings as one class -- "a control whose installation is
asserted rather than checked, by the party the control constrains" (`0007:1499-1500`) -- and then
reproduced that class one level up. Addendum 3 sharpened it to **"a control that decides what to
protect, or what to protect against, by listing members of an open set"** (`0007:2172-2173`), and
that sharpening was right: it produced D31, and D31 produced controls that held.

CAP #3 §11 records what recurred anyway, and it is one more turn of the same screw:

> **the question to ask of each new control is not only "what does it enumerate?" but "what does it
> compare, and is the thing being compared the thing that matters?"**

Every finding in this addendum is that question answered wrongly:

| Mechanism | What it compares | Why the referent is wrong | Finding |
|---|---|---|---|
| D34 event trigger | `obj.objid` from `pg_event_trigger_ddl_commands()` against the registry (`provision_test_roles.sh:446`) | for `CREATE RULE` the reported OID is the *rule*; for inheritance attachment it is the *child* | H-D, H-F |
| D33 negative privilege probes | `has_table_privilege(role, table, priv)` (`postgres.go:240`, `:248`) | PostgreSQL grants privileges at table *and column* granularity; the table-level probe reads `false` while the privilege is present and usable | H-C |
| D33 / R15 registry staleness | `objid` resolves in `pg_class` **or** `pg_proc` **or** `pg_trigger` (`postgres.go:272-277`) | R15 promised the OID resolves to *the object it claims*; the `note` column carrying the claim is never compared to anything | H-E |
| D36 policy decode | the decoded `VerificationPolicy` struct (`policy.go:116-165`) | not the bytes the operator read; a repeated key makes the document say one thing and sign another | H-B |
| D8 / `Validate()` genesis boundary | `GenesisEventSequence >= 1` (`policy.go:77`) | a *claim about the ledger*, compared against nothing in that ledger | H-A |

**The principle this addendum adopts, stated once and applied five times:**

> **A control's comparison must terminate on the thing being protected, not on whatever the platform
> happened to hand it. Where the platform's report is about something else, do not classify the
> report -- re-assert the protected thing's own state.**

That last clause is the substantive move, and it is D31 applied one level further in. D31 replaced an
open set of *actions* with a closed set of *objects*. D40 replaces an open set of *ways an action can
refer to an object* with a closed set of **properties of the object**. The set of DDL forms
PostgreSQL supports grows every major release, and the set of ways a form's reported OID can be a
dependent object rather than the target grows with it. The set of facts that must be true of
`screening_ledger_anchor` for it to still be protected does not grow at all -- it is written down at
provisioning time and checked afterwards.

---

### D38. H-A (CRITICAL) and H-B (HIGH): the document's bytes, and the boundary's referent

These are **one decision**, not two, and CAP #3 §11.1 gives the reason: neither half closes the
attack. Validating the genesis boundary while leaving duplicate-key decoding in place still leaves
`min_anchor_sequence` -- the only mechanism bounding anchor rollback (D25, R14) -- exploitable by the
identical trick. Fixing duplicate-key decoding while leaving the boundary unvalidated still leaves a
`K_policy` holder able to disable keyed verification for an entire chain.

**And it leaves an honest operator's typo able to do the same thing, with no adversary anywhere.**
This addendum designs for both cases explicitly, and states plainly that the second is the more
urgent of the two, not the less. An attack requires an attacker; a fat-fingered
`genesis_event_sequence` requires only a Tuesday. `Validate()` accepts it, the signer signs it, the
bootstrap verify prints no error, and every subsequent `verify` reports `anchor_status=verified` on a
chain nothing keyed is checking. There is no error message anywhere in that sequence. A control whose
failure mode is silent under honest operation is not a control that is merely incomplete -- it is one
whose success output is not evidence of anything, which is D12's whole subject (`0007:1090-1128`).

#### The finding, restated from the code

`VerifyPolicy`'s per-entry branch (`store.go:395`) selects the digest formula by the entry's position
against the boundary:

```go
if p.event.Sequence < policy.GenesisEventSequence {
    if p.event.SchemaVersion != EventSchemaV1 { return ... }
    eventSHA, err = legacyHashEvent(p.event)      // store.go:719 -- NO key parameter
    frozenPrefixLength = i + 1
} else {
    ... hashEvent(p.event, s.keys.chain)          // HMAC under K_chain
}
```

The comment above that branch (`store.go:386-393`) states the design intent exactly, and it is
correct as far as it goes: *"which formula applies ... is chosen by this entry's POSITION against the
externally-supplied genesis boundary -- never by the entry's own SchemaVersion field. That field is
the adversary's to set (§2's threat model); the boundary is not."*

The boundary is not the adversary's to set. **It is nobody's to check.** `Validate()` accepts any
value `>= 1` (`policy.go:77`) with no reference to the ledger the policy governs, and no other code
path compares it to the chain's actual length. `legacyHashEvent` continues to exist for a legitimate
reason -- D4/D14's frozen-prefix design needs it for genuinely historical v1 entries -- and H-A is
not a case for deleting it. It is a case for authenticating the boundary that selects it.

#### Executed: H-A and H-B against the real shipped code at this commit

Against a fresh keypair from the real `screening-ledger-policy keygen` (mode `0400` confirmed), using
the real `sign` subcommand -- the only non-test caller `SignVerificationPolicy` has ever had:

```
H-B  CAP #3 §7.5's review-bait document (duplicate keys, honest first occurrence)
     document as an operator reads it:  genesis_event_sequence=1  genesis_audit_sequence=1  min_anchor_sequence=500
     screening-ledger-policy sign    -> exit 0
     what it actually signed:           genesis_event_sequence=999999999
                                        genesis_audit_sequence=999999999
                                        min_anchor_sequence=0

H-A  genesis_event_sequence: 1000000000000 against any ledger
     screening-ledger-policy sign    -> exit 0, SIGNED genesis=1000000000000

CONTROL -- D36 has not regressed, both CAP #2 §7.8 inputs still refused:
     "min_anchor_seqence" (transposed) -> exit 1  json: unknown field "min_anchor_seqence"
     min_anchor_sequence omitted       -> exit 1  missing required field(s): min_anchor_sequence
```

And the CRITICAL end to end, run against a real build of `internal/screeningledger` at this commit,
using **this repository's own D20-certified forgery machinery** (`buildGenuineMultiEntryChain`,
`downgradeAndForge{tamperContent: true}` and `assertGenuinelyForgedUnderLegacyFormula`, all defined in
`internal/screeningledger/d20_exploit_test.go` -- three cross-file helpers, named here so a reader's
grep finds them) rather than a paraphrase of it:

```
genuine chain length=3  head_sha=bfc006150be24de6...
forged  chain length=3  head_sha=977d40d081a6a6bf...   (every entry relabelled v1, every digest unkeyed)

bait policy Validate()                    -> nil            <-- accepted today
VerifyPolicy under the bait policy        -> err=nil  frozen_prefix=3/3  snapshot_checks=6/6
CONTROL, same forged chain, genesis=1     -> err=entry at sequence 1 (schema "...event.v1") is at or
                                             after the policy genesis boundary (1) and does not meet
                                             the minimum accepted schema version "...event.v2"
```

#### (a) Duplicate keys are rejected, on the bytes, before anything is decoded

**Go's `encoding/json` has no built-in mechanism for this, and the alternatives were checked rather
than assumed.** Executed against the repository's own toolchain (`go 1.26.6`, `go.mod:3`):

```
json.Decoder + DisallowUnknownFields, real unsignedPolicyInput shape, duplicate known keys
   -> Decode err=<nil>   genesis=999999999  min_anchor=0        (last occurrence silently wins)
json.Unmarshal, same input
   -> err=<nil>          genesis=999999999                       (same)

encoding/json/v2 (Go 1.26 stdlib)
   -> DOES reject: "jsontext: duplicate object member name \"a\""
   -> but every file in .../src/encoding/json/v2/ carries //go:build goexperiment.jsonv2, and a
      default build fails with "build constraints exclude all Go files in .../encoding/json/v2"
   -> and with GOEXPERIMENT=jsonv2 set, encoding/json (v1) STILL accepts duplicates, last-wins
```

`encoding/json/v2` is therefore **rejected, with its reason recorded** so it is not re-derived: it
would require a `GOEXPERIMENT` on every build of this module -- a toolchain-wide build-mode change,
which under CLAUDE.md rule 6's reasoning is a release event and not a patch -- *and* it would change
nothing until the call sites moved to the v2 API, since the experiment does not alter v1 semantics.
This is worth stating precisely because "Go 1.26 rejects duplicate keys now" is true of one package
in the standard library and false of the one this code calls.

**Decision: a token-level duplicate-key scan over the raw bytes, in `policy.go`, stdlib only, run
before decoding.** `json.Decoder.Token()` driven by `More()`, with each value consumed into a
`json.RawMessage`, enumerates every member name in source order including repeats; the scan recurses
into nested objects and array elements, and rejects trailing content after the top-level value.
Executed:

```
CAP #3 §7.5 bait document       -> repeated JSON key(s): [genesis_audit_sequence genesis_event_sequence min_anchor_sequence]
committed example fixture       -> nil            (test/fixtures/screening-ledger/policy/example-policy.signed.json)
legitimate flat policy          -> nil
nested object, no duplicates    -> nil
duplicate in a NESTED object    -> repeated JSON key(s): [a.b]
duplicate inside an array elem  -> repeated JSON key(s): [a.[].b]
trailing second document        -> trailing content after the top-level JSON value
duplicate, differing whitespace -> repeated JSON key(s): [a]
```

Both ends call it, for D36's own reason -- enforcing at one end leaves the other as the gap:
`DecodeUnsignedPolicy` (`policy.go:116`), which is the sole path the signer's input takes, and
`LoadSignedVerificationPolicy` (`policy.go:244`), on the envelope bytes, after the signature check and
before `Validate()`. A policy document whose bytes do not say what they appear to say can be neither
produced nor consumed.

**What this does and does not claim.** It closes the gap between the bytes an operator read and the
values that got signed. It does not make an operator safe against a hostile-but-unambiguous document;
nothing can, and D36 already said so (`0007:2611-2614`). CAP #3 §10.5 notes that an automated
pipeline canonicalising documents before signing would close the review-evasion without touching the
decoder -- true, and not adopted, because no such pipeline exists and a decoder that accepts an
ambiguous document is a defect regardless of who reads it first.

#### (b) The genesis boundary commits to the prefix it declares

This is the real design question the brief asks -- what "validate against reality" means precisely --
and it has a precise answer.

**First, what does not work, established by execution rather than reasoned about.** The obvious fix is
a length bound: require `genesis_event_sequence - 1 <= len(chain)`. That does reject H-A's
`999999999` against a three-entry ledger. It does **not** close the finding:

```
proposed length bound only, forged 3-entry chain, genesis=4 (== head+1, the maximum the bound allows)
   -> every entry is below the boundary
   -> every entry verifies under legacyHashEvent
   -> ACCEPTED
```

`genesis = head + 1` means "the entire ledger is frozen v1 prefix," which is a **legitimate** state
immediately after D4's migration and is simultaneously the maximal form of the attack. A bound that
cannot distinguish them has not distinguished anything. The length bound is necessary, and it is
implied by the decision below rather than adopted separately.

**What closes it is D8's own principle, applied to the one field D8 never applied it to.** The
genesis boundary is the only policy field that is a *claim about the ledger* rather than a
*constraint on the ledger*, and the region it declares is the region verified by an unkeyed formula.
The only thing that can authenticate an unkeyed region is a signature over its content. So:

**Decision: the policy carries the boundary and a commitment to the prefix the boundary declares, and
the verifier reconciles the two against the actual chain. `VerificationPolicySchemaV3` adds
`genesis_event_sha256` and `genesis_audit_sha256`.**

The rule, stated for the event chain and applying identically to the audit chain (`audit.go:89`,
`audit.go:171`):

- **`genesis_event_sequence == 1`.** The declared prefix is entries `1..0`, i.e. empty. The
  companion field must be the **empty-string sentinel**, and the check passes with no reference to
  the ledger at all.
- **`genesis_event_sequence == N > 1`.** An entry at sequence `N-1` must exist in the chain, and its
  `EventSHA256` must equal `genesis_event_sha256`. Otherwise: hard failure, in D12's sense -- not a
  warning, not a skipped check, not a `partial`.

**One pinned digest commits to the whole prefix, and that is a property of this chain, not an
assumption.** `Event.PreviousEventSHA256` (`types.go:44`) is an ordinary JSON field of `Event`, and
`legacyHashEvent` blanks only `EventSHA256` before marshalling (`store.go:719-726`), so each entry's
digest covers its predecessor's digest; `store.go:383` independently enforces that linkage while
walking. Executed:

```
legacyHashEvent covers PreviousEventSHA256 (mutating the link changes the digest)   -> true
genuine prefix-head digest  bfc006150be24de6...
forged  prefix-head digest  977d40d081a6a6bf...      differ -> true
```

The same holds for the audit chain via `AuditEvent.PreviousAuditSHA256` (`types.go:92`) and
`legacyHashAudit` (`audit.go:171-178`).

**The proposed check against the four cases that matter**, executed:

```
H-A bait, genesis=999999999   -> REJECT  (no entry at 999999998 exists to pin)
bootstrap,  genesis=1         -> ACCEPT  (empty prefix, empty sentinel)
max-boundary forgery, genesis=4, pin=<the genuine prefix head>
                              -> REJECT  (pin bfc00615... vs actual 977d40d0...)
honest re-issue, genesis=4, same pin against the genuine chain
                              -> ACCEPT
```

The third line is the one the length bound could not produce.

**Bootstrap versus re-issue -- the interaction the brief asks to be stated precisely, because it is a
real design question and not a mechanical detail.**

- **A bootstrap policy requires no knowledge of any ledger.** `genesis_event_sequence: 1` plus the
  empty sentinel is a complete, valid, signable document for a ledger that does not exist yet. This
  is not an edge case to be tolerated; **it is every real ledger today.** CAP #3 §7.6 re-confirmed at
  this commit, and this design pass re-confirmed again, that `screening-ledger` is absent from
  `runtime_executables` (`scripts/deployment/r2-4/harness/config/policy.json`) and that there are zero
  anchor rows in any environment. So the common case costs the operator nothing at all.
- **A policy issued against an existing chain with a real v1 prefix requires exactly one 64-character
  hex string**, read from the entry at `N-1`. It does **not** require the chain length as an
  independent fact -- the digest implies it, since a chain shorter than `N-1` has no entry to match.
- **Re-issue against an existing chain is stable, and this is what makes the scheme workable rather
  than a per-verification chore.** `Append` writes `EventSchemaV2` unconditionally (`store.go:224`)
  and `AppendAudit` writes `AuditSchemaV2` unconditionally (`audit.go:34`); no code path in this
  package produces a v1 entry. **The frozen prefix therefore never grows.** Its boundary and its
  digest are fixed at D4's migration and are constants for the life of the ledger, so every
  subsequent policy re-issue -- to raise `min_anchor_sequence`, to change `allow_unanchored`, to
  rotate anything else -- carries the same two values unchanged. An operator who is asked to re-read
  the ledger on every re-issue would eventually stop reading it; an operator asked for a constant
  will copy it correctly.
- **Where the check runs.** In `verifyPolicyLocked`, at the point the frozen prefix is walked -- not
  in `Validate()`. `Validate()` is a property of the artifact and has no ledger; making it pretend
  otherwise would be the same category error as the field it is fixing. `Validate()` gains only the
  *internal* consistency rule (`genesis == 1` implies the sentinel, `genesis > 1` implies a
  well-formed 64-hex digest), which is genuinely a property of the artifact and which the signer can
  therefore enforce at signing time.

**The schema bump is justified on the precedent that already exists in this document, not invented
here.** D11 made the argument for `db/migrations/017`, D25 made it for policy `v2`, and D32 made it
for the transitional state: a format change is free while zero anchor rows exist anywhere and never
free again. The exact-equality pin at `policy.go:65-67` means a `v2`-labelled document is rejected
outright by a `v3` verifier rather than silently narrowed to the fields the old struct knows -- the
same choice D8 made for the chain-schema check and D25 made for `v1`. **No backward compatibility
path is provided, and that is the decision, not an omission.** The committed fixture
(`test/fixtures/screening-ledger/policy/example-policy.signed.json`), the operator procedure's
template (`docs/operations/screening-ledger-policy-signing.md`) and the in-test helper
(`cmd/screening-ledger/main_test.go`) are re-issued as v3 in the same stage.

**What D38 does not close, stated rather than left to a fourth CAP.** D11 already prevents policy
substitution *after* an anchor exists, and CAP #3 confirmed it defeats exactly that. D38 closes the
pre-anchor window D11 cannot reach, which is the window every ledger is in today. It does not reach
an operator who is handed a correct-looking digest by an adversary and signs it -- that terminates at
R8's operator-discipline residual, and is recorded as R20 below rather than claimed as closed.

### D39. H-C (HIGH): the privilege probes reach column granularity, and D35's biconditional is withdrawn

**The finding.** Three of D33's six named facts are negative privilege checks, implemented at
`postgres.go:234-246` (both `INSERT` probes) and `postgres.go:247-253` (the anchor writer's `SELECT`).
All three ask `has_table_privilege`. PostgreSQL grants privileges at table **and column**
granularity, and a column-level grant is invisible to the table-level probe. CAP #3 §7.1 executed it;
this design pass reproduced it independently:

```
[owner] GRANT INSERT (snapshot_sha256,purged_at,operator,reason) ON <tombstone> TO <migrator>;  => SUCCEEDED
        has_table_privilege (migrator, tombstone, INSERT)                 = f    <-- what D33 reads
        has_column_privilege(migrator, tombstone, <any of them>, INSERT)  = t
[migrator] INSERT INTO <tombstone> (snapshot_sha256,purged_at,operator,reason) VALUES (...);    => SUCCEEDED
           forged rows present: 1
CheckProvisioningState                                                    -> Provisioned=true
```

`GRANT` is not a DDL form any event trigger can inspect -- Addendum 3 confirmed by execution that
`GRANT`/`REVOKE` report `objid=NULL`, so the `objid` membership test can never match them. That
finding is recorded in the provisioning script's own comment
(`scripts/ci/provision_test_roles.sh:459-463`) and **not** in Addendum 3's prose; CAP #3 §7.1 cites it
as `0007:2455-2459`, which at this commit is D34's registry member list, so a reader following that
citation lands on the wrong paragraph. Corrected here rather than repeated. D33 is the only mechanism
that was ever going to see a column-level grant, and it was looking at the wrong granularity.

**Decision: every negative privilege probe asks the question at column granularity, over the
relation's live columns, and the table-level probe is deleted rather than kept alongside.**

```sql
SELECT bool_or(has_column_privilege($1, $2, a.attnum, $3))
FROM pg_attribute a
WHERE a.attrelid = $2::regclass AND a.attnum > 0 AND NOT a.attisdropped
```

**Why this shape and not the obvious alternative**, established by execution because the alternative
is the one a reader will reach for. Two candidates were built and compared:

```
                                                       table-level  has_column_privilege  raw pg_attribute.attacl
                                                       probe (D33)  over live columns     + aclexplode scan
column GRANT to the role directly                          f              t                     t
table  GRANT to the role (does the column form subsume?)   t              t                     t
column GRANT to PUBLIC                                     f              t                     (n/a)
column GRANT to a role the target is a MEMBER of           f              t                     NULL  <-- misses
```

`has_column_privilege` **subsumes** the table-level check (a table grant confers the privilege on
every column, and the function says so), so replacing rather than supplementing is correct and leaves
no second thing to keep in sync. The raw-catalog approach -- scanning `pg_attribute.attacl` with
`aclexplode` -- is **strictly weaker and is rejected**: an ACL entry names a grantee literally, so it
does not expand role membership, and it returned NULL for exactly the case D35 exists to make
observable. Recorded so nobody re-derives the catalog scan as the "more direct" answer; it is more
direct and less correct.

`attnum > 0 AND NOT attisdropped` is not incidental: system columns and dropped columns are neither
grantable nor droppable targets, and passing them to `has_column_privilege` is a question with no
meaning.

**D35's text is wrong as written, and this addendum says so rather than patching around it.**
`0007:2556-2560` reads:

> *"D33's `requiredProvisioningState` already asserts
> `has_table_privilege('owl_migrator', 'screening_ledger_retention_tombstone', 'INSERT')` is false,
> **which is true if and only if the membership is absent** -- so the leak CAP #2 found becomes a
> verification failure on the next `verify`."*

**The biconditional is false in both directions of interest.** The privilege can be present, and the
`INSERT` genuinely succeed, with the probe reading `false` -- demonstrated above. Per this document's
convention the sentence at `0007:2556-2560` is not edited; it is withdrawn here, and what remains
true of D35 after the withdrawal is stated exactly:

- **G-E itself is closed and D35's substantive claim stands.** The `GRANT`/`REVOKE` pair is deleted,
  a repo-wide sweep at this commit finds the membership granted nowhere except inside the regression
  test that exists to prove it is refused, preconditions run on both edges, and CAP #3 §7.10 found no
  `owl_*` membership edges at all after a full provisioning run. **The window is genuinely gone.**
- **What was overstated is the *observability* D35 credited to D33** -- the claim that a residual
  membership would necessarily surface as a verification failure. Before D39 it would not have. After
  D39 it does, because a membership that confers `INSERT` confers it on every column and the
  column-granularity probe reads `true`. D35's conclusion is restored by D39; it was not established
  by D35.

The distinction matters because R15 and D35 both accept documented risk **on the explicit basis that
D33 closes it**. An acceptance rationale that names a closure narrower than the closure actually is
does not merely mislead a reader -- it licenses the next change to remove the wrong thing.

### D40. H-D (HIGH) and H-F (MEDIUM): D34 stops resolving referents and re-asserts the protected object's state

**The finding, and its history.** This is the **third** recurrence of one shape: G-D
(`CREATE OR REPLACE FUNCTION` reported the function, not the tables whose guards it neutered), then
H-D, then H-F. D34's function compares `obj.objid` against the registry (`provision_test_roles.sh:446`),
which is correct for every command form whose reported `objid` *is* the protected object -- and three
forms attach to a protected table while reporting something else.

`CREATE RULE` succeeds against a protected table in the **shipped configuration**, with ownership
alone and no additional privilege, because rules are named within the table rather than the schema
and so need no `CREATE` on any schema. CAP #3 §7.3 then showed the consequence, which is the
"silent absence" class CLAUDE.md rule 5 names as this repository's dominant bug: with
`DO INSTEAD NOTHING` installed, the anchor writer's `INSERT` **reports success and vanishes** --
`anchor rows before=44 after=44`, no error, no warning, no row. The anchor freezes at its current
sequence while every writer believes it is advancing, and all history after the frozen anchor becomes
rewritable with the anchor cross-check still passing. CAP #3 §7.11 adds the operational corollary,
which belongs in this document because it constrains work that has not been designed yet: **a future
anchor-cadence monitor must read the anchor's `sequence`, not the writer's exit code.**

Inheritance attachment (H-F) is the same blind spot with a different reported object: the child is
reported, the parent is not, rows injected into the child are returned by unqualified `SELECT`s
against the protected parent, and the parent's row-immutability trigger does not fire for them.

**Per CAP #3 §11.3 and this addendum's brief: no list of forms.** Adding `CREATE RULE` and the two
inheritance forms to an enumeration is the enumerative fix that would miss the fourth form the same
way the tag list missed `DROP OWNED` twice.

**Investigated: can the reported object be resolved back to the protected table structurally?** The
brief asked for a real recommendation rather than a guess, so both halves were built and run.

First, what PostgreSQL actually reports. An unfiltered `ddl_command_end` probe logging every column of
`pg_event_trigger_ddl_commands()`, against a protected table:

```
CREATE RULE r AS ON INSERT TO prot ...   classid=2618 (pg_rewrite)  objid=<the rule>    PROTECTED=f
CREATE TABLE child () INHERITS (prot)    classid=1259 (pg_class)    objid=<the child>   PROTECTED=f
ALTER TABLE child INHERIT prot           classid=1259 (pg_class)    objid=<the child>   PROTECTED=f
CREATE TRIGGER t ... ON prot             classid=2620 (pg_trigger)  objid=<the trigger> PROTECTED=f
CREATE INDEX ix ON prot(v)               classid=1259 (pg_class)    objid=<the index>   PROTECTED=f
CREATE POLICY p ON prot                  classid=3256 (pg_policy)   objid=<the policy>  PROTECTED=f
CREATE VIEW v AS SELECT * FROM prot      classid=1259 (pg_class)    objid=<the view>    PROTECTED=f
ALTER TABLE prot ADD CONSTRAINT / COMMENT ON prot / ALTER TABLE prot ADD COLUMN
                                         classid=1259 (pg_class)    objid=<prot>        PROTECTED=t
```

The last line is the set D34 already covers. The lines above it are the open set. Note that
`CREATE TRIGGER`, `CREATE INDEX` and `CREATE POLICY` on a protected table are in that same set and
**no CAP has raised any of them** -- CAP #3 found `CREATE TRIGGER` and `CREATE INDEX` blocked only by
`owl_ledger_ddl` holding `CREATE` on no schema, which is a privilege coincidence, exactly as it found
for H-F.

Second, `pg_depend`. **It is not a sound resolver, and this refuted the design this section was
expected to reach.** Executed, listing every dependency edge pointing at the protected table:

```
pg_rewrite  <rule r_ins on prot>        deptype=a   AND  deptype=n
pg_trigger  <t_noop on prot>            deptype=a
pg_class    <index i_prot>              deptype=a
pg_policy   <p_prot on prot>            deptype=a
pg_constraint <c_chk on prot>           deptype=a   AND  deptype=n
pg_class    <child1>                    deptype=n              <-- inheritance
pg_class    <child2>                    deptype=n              <-- inheritance
pg_rewrite  <"_RETURN" on view v_prot>  deptype=n              <-- a BENIGN view over the table
```

A rule filtered on "depends on a protected table" blocks `CREATE VIEW ... SELECT FROM
screening_ledger_anchor`, which is legitimate and which D37's collateral-damage requirement forbids
breaking. Narrowing to `deptype='a'` (auto -- "is a part of the referenced object") does discriminate
rule, trigger, index, policy and constraint from the view, cleanly. **But inheritance is `deptype='n'`,
identical to the view's**, so `pg_depend` alone cannot express the boundary at all. It would take two
mechanisms -- an auto-dependency rule plus an explicit `pg_inherits` check -- and it would still be
betting that every object type PostgreSQL adds in future majors lands on the side of the classifier
this repository guessed. That is a list again, one level of abstraction up.

**So the answer to the brief's question is yes: object-attachment operations do need a different
detection mechanism from direct object operations -- and the mechanism is to stop detecting
operations.**

**Decision: `sec7_protect_ddl_objects()` keeps its `objid` membership check unchanged and gains a
second phase that re-asserts, after every DDL statement, that every protected relation still matches
the state recorded for it at provisioning time.**

- The existing `objid` check is **not** replaced. It is what catches the G-D form -- replacing a
  shared guard function changes no protected relation's own catalog state, since
  `CREATE OR REPLACE FUNCTION` keeps the OID and the trigger still points at it -- and it produces the
  specific, object-naming error text CAP #3 credited. The two phases answer different questions and
  both are needed.
- A second superuser-owned registry, **`sec7_protected_relation`**, created and populated by
  `provision_test_roles.sh grant-ddl-ownership` alongside `sec7_protected_object`, with
  `REVOKE ALL ... FROM PUBLIC` and `SELECT` to `owl_migrator` so D41's check can read it, and itself
  a member of `sec7_protected_object` so it cannot be dropped without tripping the trigger that reads
  it. One row per protected relation, recording: `relowner`, `relkind`, `relrowsecurity`,
  `relforcerowsecurity`, the non-internal trigger OID set, the index OID set, and the RLS policy OID
  set.
- The invariant asserted after every DDL statement, for each recorded relation: the relation still
  exists; `relowner`, `relkind` and both RLS flags are unchanged; **no row in `pg_rewrite` has
  `ev_class` equal to it** (no rules); **no row in `pg_inherits` has `inhparent` or `inhrelid` equal
  to it** (no children attached, and it has not itself been attached as a child); its non-internal
  trigger OID set, index OID set and policy OID set are each unchanged; and every one of its triggers
  is `tgenabled = 'O'`.
- Identity strings stay in the error text for diagnostics only, as D34 already has it.

**Executed, in full, during this design pass.** Against a lab table owned by a `ddl` role, a guard
function owned by a `mig` role, and the two registries above:

| Attempt | Result |
|---|---|
| `CREATE RULE ... DO INSTEAD NOTHING` (H-D) | **BLOCKED** `a rewrite RULE exists on it` |
| `CREATE TABLE ch () INHERITS (prot)` (H-F) | **BLOCKED** `an inheritance child is attached` |
| `CREATE TEMP TABLE ch () INHERITS (prot)` (H-F, needs no grant at all) | **BLOCKED** same |
| `ALTER TABLE ch INHERIT prot` (H-F) | **BLOCKED** same |
| `CREATE TRIGGER t ... ON prot` (raised by no CAP) | **BLOCKED** `its trigger set changed` |
| `CREATE UNIQUE INDEX ix ON prot ((1))` (raised by no CAP; blocks writes) | **BLOCKED** `its index set changed` |
| `CREATE POLICY p ON prot` (raised by no CAP) | **BLOCKED** `its RLS policy set changed` |
| `ALTER TABLE prot ADD COLUMN` (existing D34 form) | **BLOCKED** by the `objid` phase, unchanged |
| `DROP TRIGGER prot_immutable ON prot` (D26 form 1) | **BLOCKED** by the `objid` phase, unchanged |
| `ALTER TABLE prot DISABLE TRIGGER ALL` (D26 form 4) | **BLOCKED** by the `objid` phase, unchanged |
| `DROP OWNED BY ddl` (G-B) | **BLOCKED** by the `objid` phase, unchanged |
| unrelated `CREATE TABLE` / `DROP TABLE` | **succeed** |
| unrelated `CREATE OR REPLACE FUNCTION` | **succeeds** |
| superuser `CREATE TABLE` / `ALTER TABLE` / `DROP TABLE` on unprotected objects | **succeed** |
| **`CREATE VIEW` and `DROP VIEW` over the protected table** | **succeed** |

Final state after the whole attack sequence: `rules_on_prot=0`, `children=0`, trigger set unchanged,
column count unchanged -- the transaction aborts, so nothing partially applies.

**Three mechanism facts this decision depends on, each executed rather than assumed:**

1. **`ddl_command_end` fires for `DROP` commands**, not only for create and alter -- observed for
   `DROP TABLE` and `DROP INDEX`. So the invariant phase covers drop-shaped attacks on a protected
   relation's attachments, which the `sql_drop` phase's `objid` check would miss for any object not
   individually registered.
2. **The cost is small enough to state.** 400 DDL statements: 79 ms with the trigger disabled, 103 ms
   enabled -- roughly 0.06 ms per statement, with two protected relations.
3. **Ordering is safe.** `.github/workflows/ci.yml` runs every `db/migrations/*.sql` **before**
   `provision_test_roles.sh grant-ddl-ownership`, so the state recorded at provisioning time is the
   final state and no legitimate later migration is fighting the record. This is the same ordering
   D34 already relies on to avoid catching its own installation DDL (`provision_test_roles.sh:464-466`).

**This closes H-F's *stated* mechanism, and D41 additionally asserts the privilege fact H-F depended
on.** CAP #3 rated H-F MEDIUM partly because the attack needs `CREATE` on a schema, which
`owl_ledger_ddl` does not hold in the shipped configuration -- "the split is the whole defence," and
D33 never asserted it. D40 removes the dependence on that coincidence; D41 asserts the coincidence
anyway, as defence in depth and not as the fix. Note also that the `CREATE TEMP TABLE ... INHERITS`
variant needs **no grant whatsoever** (`TEMP` is held by default), so a privilege assertion alone
would not have closed even the form that exists today.

**Correction found implementing D40/D41, in the same spirit as §3.4 and §6.1.** This section's own
text groups `CREATE TRIGGER` with `CREATE INDEX` as both "blocked only by `owl_ledger_ddl` holding
`CREATE` on no schema" (`0007:3249-3252`, this addendum's context section). Re-executed against a
real PostgreSQL 17.11 cluster during the implementation pass: **`CREATE INDEX` genuinely needs
schema `CREATE`** (an index is a new relation in the schema's namespace, the same rule `CREATE
TABLE` follows), confirmed by a `42501 permission denied for schema public` when attempted as
`owl_ledger_ddl` with no schema grant. **`CREATE TRIGGER` does not** -- it requires only ownership
of (or the `TRIGGER` privilege on) the target table, which `owl_ledger_ddl` already has by virtue of
owning `screening_ledger_anchor`/`screening_ledger_retention_tombstone`, and it succeeds as
`owl_ledger_ddl` with zero schema-level grant of any kind. `CREATE POLICY` and `CREATE RULE` are the
same way -- neither is a schema-namespaced object. This does not change D40's design or D41's
assertions: D40's second phase blocks `CREATE TRIGGER`/`CREATE POLICY` structurally regardless of
privilege (§ transcript above, `its trigger set changed` / `its RLS policy set changed`), exactly as
specified, and D41 part three's two `has_*_privilege` facts are still true and still asserted -- they
were simply never the reason `CREATE TRIGGER`/`CREATE POLICY` were unexploited before D40 shipped;
no CAP raised either, and the accurate reason is "no CAP tried it," not a privilege coincidence.
Recorded here rather than silently corrected because the next reader should not re-derive it, and
because a false "the privilege split already covers this" sentence is worse than the true "D40 is the
only defence for these two forms" one it replaces for these two forms specifically.

### D41. H-E (MEDIUM): the registry's identity and its population both become assertions

**The finding.** R15 accepts a documented fail-open risk on an explicit basis (`0007:2666-2674`):

> *"`requiredProvisioningState` asserts that every registry row's OID resolves to **the object it
> claims**, so a stale registry is a verification failure rather than a silent gap."*

The shipped check (`postgres.go:271-282`) asserts something weaker: that each `objid` resolves to
**some** object in `pg_class` **or** `pg_proc` **or** `pg_trigger`. The `note` column carries the
claim and is never compared to anything. Executed against a repointed and against an emptied
registry -- CAP #3 §7.2's two states -- the shipped query returns `0` in both cases, so
`CheckProvisioningState` certifies the database as provisioned while D34 is protecting the wrong
object in the first case and **is inert for every object** in the second.

**In fairness to D33, R15's own literal scenario is closed**: an object legitimately dropped and
recreated leaves an OID resolving to nothing, `staleCount > 0` fires, and
`TestCheckProvisioningStateDetectsStaleRegistryRow` covers it. What is not closed is OID reuse, a
repointed row, and an empty registry. The registry *as an object* is also genuinely well protected --
CAP #3 §7.2 found no non-superuser write path of any kind and the correct owner and ACL -- so this
decision is about the check, not the table.

**Decision, part one: define "resolves to the object it claims" and assert it.**

`sec7_protected_object` gains a **`classid`** column recording which system catalog each row's OID
belongs to, and the row's claim becomes a machine-comparable identity rather than a prose `note`. D33
then asserts, for every row:

```sql
(SELECT identity FROM pg_identify_object(r.classid, r.objid, 0)) = <the expected identity>
```

Three facts established by execution, because the failure mode of this check matters as much as its
success:

- **`pg_identify_object` is callable by `owl_migrator`** -- a non-superuser -- for `pg_class`,
  `pg_proc` and `pg_trigger` alike, returning `(type, schema, name, identity)`. No new role, DSN or
  grant is required, the same property D33's existing facts have.
- **On a dangling OID, or an OID belonging to a different catalog than `classid` claims, it returns a
  row with a NULL `identity` and does not raise.** So the comparison fails closed and the check does
  not have to guard against an exception.
- **This closes cross-catalog OID reuse, which the shipped three-way `NOT EXISTS` cannot see.** A
  `pg_class` OID sitting in a row that claims a function passes the shipped query (executed:
  `shipped_stale_count = 0`) and fails the identity comparison. OIDs are drawn from one global
  counter and are unique only within a catalog, so this is a real gap and not a hypothetical one.

**Decision, part two: assert the population against a second, independent source.**

An identity check on the rows that are present says nothing about rows that are absent, and CAP #3's
sharpest version of this finding is the empty registry: zero rows means the trigger function returns
on every miss, so **D34 is inert for every object** while the provisioning script's own
`[[ "$registry_row_count" == "11" ]]` (`provision_test_roles.sh:415-419`) is long since satisfied and
gone. That split -- the installer checks and the verifier does not -- is G-A's shape one level
deeper, and it is why this addendum treats population as an assertion rather than a count.

- **A literal `requiredProtectedObjects` declaration in `postgres.go`**, written out beside
  `requiredSchemaObjects` (`postgres.go:294-318`) and `requiredProvisioningState`'s members, never
  derived by scanning the provisioning script or by a naming-pattern guess -- CLAUDE.md's "never
  enumerate targets by inference", which applies to a generated list as much as a hand-picked one.
  Each member is a `(classid, identity)` pair.
- **D33 asserts the registry contains exactly those pairs -- no more, no fewer.** An emptied
  registry, a truncated registry, a padded registry and a repointed row are each a distinct,
  specifically-named verification failure. The provisioning script's own count assertion stays where
  it is; the two together mean the property is checked by the installer *and* by the verifier, which
  is the only arrangement that survives the installer not having run.
- **`sec7_protected_relation` (D40) gets the same treatment**, since a second registry inherits the
  first one's failure mode exactly.

**Decision, part three: D33 asserts the two privilege facts H-F depended on.** CAP #3 §7.4 found
inheritance attachment blocked in the shipped configuration only because `owl_ledger_ddl` holds
`CREATE` on no schema and no database -- load-bearing, and unasserted anywhere. Both are readable by a
non-superuser (executed), and both join `requiredProvisioningState`:

```
has_schema_privilege  ('owl_ledger_ddl', <the schema holding the protected tables>, 'CREATE')  = false
has_database_privilege('owl_ledger_ddl', current_database(),                        'CREATE')  = false
```

This is defence in depth behind D40, not the fix for H-F, and the addendum says so in both places so
that a later change cannot remove D40 on the strength of D41 or vice versa.

**What this does not close.** An adversary who can rewrite both the registry and the reality it
records passes every check in D41. Registry writes require the bootstrap superuser, so that
terminates at R12/R17 where every other residual in this document terminates. Recorded as R19 rather
than left implicit.

### D42. Test ownership and pre-declared withdrawal conditions

The specific shape the implementation must satisfy, so nothing weaker can be claimed to discharge
this addendum -- the standard D20 (`0007:1293-1338`), D26 (`0007:1874-1885`) and D37
(`0007:2623-2662`) set.

**Every test below must fail before its change, per CLAUDE.md rule 5.** Where a CAP #3 transcript
exists, the test reproduces that transcript, not a paraphrase of it. Several assertions below are
stated as "must pass today and fail after" -- that direction is deliberate: for these findings the
current behaviour is *acceptance*, so a test that only asserts the post-fix refusal cannot
distinguish a working fix from a test that never exercised the path.

1. **D38(a).** `TestDecodeUnsignedPolicyRejectsDuplicateKeys`: CAP #3 §7.5's exact bait document
   bytes, asserting it signs today through the real `DecodeUnsignedPolicy` +
   `SignVerificationPolicy` path with `genesis_event_sequence=999999999` and `min_anchor_sequence=0`,
   and is refused after with all three repeated keys named. Plus, in the same table: a duplicate in a
   nested object, a duplicate inside an array element, trailing content after the top-level value,
   the committed example fixture still signing and loading, and both CAP #2 §7.8 inputs still refused
   so D36 is proven un-regressed.
2. **D38(b).** `TestGenesisBoundaryRequiresPrefixCommitment`: build the forgery with
   `buildGenuineMultiEntryChain`, `downgradeAndForge{tamperContent: true}` and
   `assertGenuinelyForgedUnderLegacyFormula` -- all three defined in `d20_exploit_test.go`, so the
   forgery is D20's own certified-genuine one -- and assert `VerifyAnchored` **accepts** it today
   under a policy that passes `Validate()`, and fails after. Must include: the `genesis=999999999`
   case; the **`genesis = head + 1` max-boundary case**, which a length bound alone would pass and
   which is therefore the test that distinguishes this design from the obvious one; the bootstrap
   case (`genesis=1`, empty sentinel) as a **positive**; and an honest re-issue against a genuine
   chain as a second positive. A suite that proves only refusals has not proven the design is
   usable.
3. **D39.** `TestProvisioningStateDetectsColumnLevelGrant` (pgx): CAP #3 §7.1's exact
   `GRANT INSERT (cols)` on both protected tables, asserting `CheckProvisioningState` returns
   `Provisioned=true` today and a specifically-named failure after, and asserting the tombstone
   forgery the grant enables actually succeeds -- otherwise the test proves a probe changed rather
   than a hole closed. Table-driven over the direct-grant, `PUBLIC` and role-membership routes, plus
   the anchor writer's `SELECT` probe.
4. **D40.** `TestD40ProtectedRelationInvariantHoldsUnderEveryForm` (pgx): every row of D40's
   transcript table above, each as its own attempt with the SQLSTATE captured -- `CREATE RULE`, all
   three inheritance forms **including the `TEMP` variant that needs no grant**, `CREATE TRIGGER`,
   `CREATE UNIQUE INDEX`, `CREATE POLICY` -- **plus every existing D34 and D26 form unchanged**,
   **plus** the collateral-damage cases: unrelated `CREATE TABLE`, `DROP TABLE` and
   `CREATE OR REPLACE FUNCTION`, superuser DDL, and `CREATE VIEW`/`DROP VIEW` over a protected table.
   D37's rule applies verbatim: a suite that proves only the blocks has not proven D40 is safe to
   install.
5. **D41.** `TestCheckProvisioningStateDetectsRepointedAndEmptiedRegistry` (pgx): CAP #3 §7.2's exact
   repoint and its exact `DELETE`, each asserting `Provisioned=true` today and a distinct named
   failure after; plus a cross-catalog-reuse row; plus the two `CREATE`-privilege facts.

**Withdrawal conditions, declared now rather than decided after the fact:**

- **If D40's collateral-damage cases fail against the real schema** in a way the lab did not
  reproduce -- most plausibly around SEC-1's RLS migrations or `db/rollback/014_tenant_isolation_down.sql`,
  the same places D37 named -- D40 falls back to the `pg_depend` `deptype='a'` resolver **plus** an
  explicit `pg_inherits` check. That fallback closes H-D and H-F as they exist today and leaves the
  general shape open for any future object type PostgreSQL classifies differently. **It is strictly
  worse and must be recorded as such, not presented as equivalent.**
- **If D38(b) cannot be implemented without restructuring `VerifyAnchored`'s or `VerifyPolicy`'s
  return contract beyond adding two policy fields and one check in the prefix walk**, the
  implementation stops and the design is amended. It does not ship a boundary check that runs in some
  modes -- a validation that runs sometimes is the shape of every finding in this document.
- **D38(a) and D38(b) ship together or not at all.** Splitting them recreates CAP #3 §11.1's exact
  gap, in whichever direction the split falls.

**Addendum 3's own pre-declared withdrawal conditions remain correctly un-triggered, re-verified
against what *this* addendum designs rather than inherited from CAP #3's confirmation.** D34's
collateral-damage cases pass with D40's second phase installed -- unrelated `CREATE TABLE`,
`DROP TABLE`, `CREATE OR REPLACE FUNCTION`, superuser DDL, and additionally `CREATE VIEW` over a
protected table, which no prior collateral case covered -- so the `WHEN TAG` fallback is **not**
required and **must not** be adopted. D32's adjudication shipped in full, not partially, and nothing
in this addendum touches it.

### New accepted risks

**R18 -- D40 widens R17's blast radius from "a defect in the trigger function" to "any drift between
a protected relation and its recorded state," and the recovery path must be documented rather than
discovered.** R17 (`0007:2686-2692`) accepted that an unfiltered event trigger runs on every DDL
statement, so a defect in it breaks all DDL rather than some. D40 adds a second way to reach the same
outcome without any defect at all: if a protected relation's actual state ever diverges from
`sec7_protected_relation` -- a superuser legitimately adding an index, say, without re-recording --
then **every** subsequent DDL statement in the database fails, including the superuser's own and
including entirely unrelated ones. Executed, and both recovery paths verified:

```
drifted state, unrelated CREATE TABLE as superuser   -> ERROR: protected relation ... its index set changed
ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE   -> SUCCEEDS even while drifted
SET event_triggers = off; <corrective DDL>                      -> SUCCEEDS (PostgreSQL 17 GUC)
re-run provision_test_roles.sh grant-ddl-ownership              -> re-records the state; DDL healthy again
```

**`event_triggers` is not a bypass, and that was checked rather than assumed**: `pg_settings` reports
`context = superuser`, and a non-superuser -- including the protected tables' owner, the role D26/D34
exist to bind -- gets `permission denied to set parameter "event_triggers"`. This is true of D34 as
already shipped, not only of D40, and is recorded here because a reader encountering the GUC should
find its disposition in this document rather than re-derive it. The residual terminates at the
superuser, exactly where R12 puts it. Accepted, because the alternative -- an invariant that is
checked but not enforced -- is the shape of G-A.

**R19 -- `sec7_protected_relation` is a second trust object with the first one's failure mode.** D41
asserts its identity and population, and D40 puts it under `sec7_protected_object`'s protection, but
an adversary who can rewrite both the registry and the reality it records passes every check. That
requires the bootstrap superuser, the same terminus as R12/R17. **The registry and the check that
validates it must ship together; either alone is worse than neither** -- R15's rule, restated for the
new object, so that a later change to one is understood to require the other.

**R20 -- the prefix commitment is only as good as the digest the operator was handed.** D38(b)
removes the *silent* failure: a boundary that is reconciled against nothing becomes a boundary that
is reconciled against the chain, and a typo becomes a hard failure instead of a quiet downgrade to
unkeyed verification. It does not make an operator safe against an adversary who supplies both the
boundary and a matching digest for a chain they have already forged -- that is R8's
operator-discipline residual, unchanged, and it is bounded in practice by D11 once any honest anchor
exists. Recorded so the new fields are not read as a stronger claim than they are.

### Staging

Same shape and reason as §8 and the three prior addenda (`0007:1397-1414`, `0007:2038-2058`,
`0007:2694-2716`): each stage independently reviewable and independently provable.

1. **This addendum**, merged before any code (CLAUDE.md rule 7).
2. **Stage F1 -- the policy artifact.** D38 in full, both halves in one PR for the reason D42 states.
   Includes the `VerificationPolicySchemaV3` bump and the re-issued fixture, operator template and
   test helper. Sequenced first because it is the CRITICAL and because it is the only stage whose
   exploitation needs no database at all.
3. **Stage F2 -- the DDL boundary.** D40, plus the `sec7_protected_relation` registry the provisioning
   step creates. D40's collateral-damage cases are a shipping requirement, and the withdrawal
   condition is discharged or invoked here.
4. **Stage F3 -- provisioning as a verified fact, corrected.** D39 and D41, sequenced after F2
   because D41's population assertion covers the registry F2 creates. D39 could ship independently
   and is kept here because both decisions edit `requiredProvisioningState` and splitting them would
   produce two conflicting versions of the same function.
5. **`SECURITY.md` and `README.md` language.** R3's rule unchanged. `README.md:93-97`'s
   requalification notice stays until every stage above has landed and its reproduction passes. CAP
   #3 re-confirmed that nothing in PR #140 or #141 re-asserted the guarantee; that must remain true
   through this addendum as well.

**SEC-7 does not close on this addendum.** §8's closing condition -- "a deliberately forged chain
fails a CI run that nobody chose to invoke" -- is contradicted by CAP #3 §7.6 for as long as a
tampered, unkeyed-digest chain returns `anchor_status=verified` with `snapshot_checks=6/6` under a
policy that passes `Validate()`. The closing sentence stands and now has a fourth addendum behind it.

### Addendum 4 summary

- **CAP #3's verdict is QUALIFIED, not PASS**, for the third consecutive audit: one CRITICAL, three
  HIGH, two MEDIUM, five of six demonstrated live. This addendum designs the remediation and follows
  CAP #3 §11's dependency-ordered sequencing rather than raw severity.
- **The class is one turn sharper than Addendum 3's.** Not "scoped by listing members of an open set"
  but **"the enumeration was fixed and the referent drifted"**: D34 compares an OID that for three
  DDL forms is not the protected object's, D33 compares a privilege at the wrong granularity, D33/R15
  compares an OID's existence rather than its identity, and D36 compares a decoded struct rather than
  the bytes a human read. D40 states the replacement: where the platform's report is about something
  else, do not classify the report -- re-assert the protected thing's own state.
- **The design is D38-D42.** The policy document's bytes and the genesis boundary's referent, as one
  decision (D38); privilege probes at column granularity, with D35's biconditional withdrawn in text
  rather than patched in silence (D39); D34's second phase, a closed set of properties of the
  protected relation replacing an open set of ways a statement can refer to it (D40); the registry's
  identity and population as assertions against an independent literal declaration (D41); and the
  proof obligations with pre-declared withdrawal conditions (D42).
- **This design pass executed every mechanism assumption, and two of them changed the design.**
  `pg_depend` is not a sound structural resolver -- a benign `CREATE VIEW` over a protected table is
  indistinguishable from an inheritance attachment by dependency type, and `deptype='a'` misses
  inheritance entirely. A pure length bound on the genesis boundary does not close H-A, because
  `genesis = head + 1` is both a legitimate post-migration state and the maximal attack. Also
  confirmed by execution: `encoding/json` accepts duplicate keys and `encoding/json/v2` is
  `GOEXPERIMENT`-gated and does not change v1; `has_column_privilege` subsumes `has_table_privilege`
  and catches the role-membership route a raw ACL scan misses; `ddl_command_end` fires for `DROP`;
  `pg_identify_object` returns NULL rather than raising on a wrong-catalog OID; `event_triggers` is
  superuser-only and so is not a bypass; and `Append`/`AppendAudit` never write a v1 entry, which is
  what makes the prefix commitment a constant rather than a chore.
- **Three risks are recorded** rather than designed away: D40's invariant widens R17's blast radius
  to any recorded-state drift, with two verified recovery paths (R18); the second registry is a
  second trust object terminating at the superuser (R19); and the prefix commitment is bounded by
  what the operator was handed (R20).
- **This addendum revises no prior decision.** D1-D7, D8-D20, AR7, D21-D30 and D31-D37 stand.
  R1-R17 stand. One sentence of D35's supporting text (`0007:2556-2560`) is withdrawn as false,
  explicitly and in D39's own words; G-E's closure and D35's substantive decision are unaffected, and
  what D35 claimed about observability is restored by D39 rather than by D35.

**Audit basis commit:** `3c7e5be6dd5e893b7704aebd54a81afd4d89d44a`

Every file:line citation in this addendum was verified against that tree -- the same commit CAP #3
was produced against, so no drift separates the audit from this design. For a CAP record covering the
implementation of this addendum, use the tip of whichever stage PR is under audit, not this value.

## Addendum 5: the population a control is meaningful over -- I-A's scope gap, I-B's unchecked referent, and the first CAP with no bypass (2026-08-21)

- **Status:** Proposed
- **Trigger:** a fourth Composition Audit Program record produced against the implemented Addendum 4
  (`docs/backlog/sec-7-cap-record-8b36c91.md`, adversarial posture, audit basis commit
  `8b36c91f7ef58e11048116d8c7e0e45f7da18024`) returned **QUALIFIED, not PASS** for the fourth
  consecutive audit -- but on materially different grounds, and this addendum must not be read as a
  fourth repetition of the same result. **No bypass of the stated invariant was found.** An
  adversary holding everything §2 grants -- ledger filesystem write, `K_chain`, `K_snap`, the
  Postgres mirror as `owl_migrator`, and an adversarially-authored policy document -- could not
  forge a history or a retention claim the current verifier accepts. H-A, CAP #3's CRITICAL, was
  reproduced end to end through this repository's own D20-certified forgery machinery against a live
  database and is refused at the exact point D38(b) specifies. Two findings remain, one MEDIUM
  (I-A) and one LOW (I-B), and **neither is a forgery**: both concern states the system reaches
  through ordinary operation, with no adversary anywhere.
- **What CAP #4 confirmed and this addendum does not disturb.** D38 is credited as the strongest
  single decision in the four addenda: eleven ambiguity forms refused including four no prior CAP
  tried, six legitimate documents accepted as controls, and the genesis pin separating
  `genesis = head + 1`'s legitimate and malicious forms by the pin's *value* -- the distinction the
  ADR itself identified as the one a length bound cannot make. D40's second phase held against
  sixteen owner-level DDL forms including six no prior CAP attempted, and is transaction- and
  concurrency-safe. D39 catches all four column-grant routes. D41's cross-catalog identity
  comparison closes a state the shipped CAP #3 query returned clean for. Provisioning is idempotent
  and the D18 gate still fails closed on all seven DSNs. **D31's scoping principle and Addendum 4's
  referent principle compose correctly, and this addendum reopens neither.**
- **Scope:** a pure addition. Nothing above this section is edited -- not D1-D7, not D8-D20, not
  AR7, not D21-D30, not D31-D37, not D38-D42, not §3.4, §6.1 or the D19 correction note, not
  R1-R20. Decision numbering continues at **D43**, risk numbering at **R21**. Where a prior
  decision's *text* is stricter than what the code enforces -- R19's bypass precondition, which
  CAP #4 found overstated -- the new decision says so in its own words and states what the old claim
  actually rests on afterwards, the convention AR7 established for R7, Addendum 3 followed for D21
  point 3, and Addendum 4 followed for D35's biconditional.
- **Verification basis:** every `file:line` below was re-derived from the working tree at
  `8b36c91f7ef58e11048116d8c7e0e45f7da18024` rather than copied from the CAP record.
- **This design pass executed its mechanism assumptions, as Addendum 3 established and Addendum 4
  held to -- and this time three of them changed the design.** Every PostgreSQL and
  deployment-mechanism claim this addendum depends on was run against a purpose-built disposable
  PostgreSQL 17.11 cluster before the decision that relies on it was written, and **both I-A
  variants were reproduced against the real schema** (all seventeen `db/migrations/*.sql` applied as
  `owl_migrator`, then `scripts/ci/provision_test_roles.sh create-roles`, `grant-app-privileges` and
  `grant-ddl-ownership`, in CI's order per `.github/workflows/ci.yml:97-140`). The cluster was torn
  down; no repository file was modified during the investigation. The three refutations, each with
  its transcript in the section that relies on it:
  1. **A name-keyed registry -- Direction B's core proposal -- reopens G-G**, which D31 closed. The
     escape was executed: two statements, by the table's own owner, and the row-immutability trigger
     is gone (D44).
  2. **`system_identifier` alone does not detect a copy.** It is *identical* between a database and
     a `pg_dump`-based restore into another database of the same cluster -- the exact case CAP §7.6
     demonstrated. Only the database OID discriminates (D43, D45).
  3. **`CREATE DATABASE ... TEMPLATE` preserves relation OIDs**, so the controls remain live and
     enforcing while any instance-binding marker would report a mismatch. That refutes making such
     a marker a gate, and is why D45 is diagnostic-only (D45).

### Drift found while writing this addendum

Recorded rather than silently corrected, the convention §3.4, §6.1, `0007:717-720`,
`0007:1474-1490`, `0007:2141-2160` and `0007:2804-2826` set.

1. **Addendum 4's `file:line` citations resolve against `3c7e5be`, not against this tree.** PR #143
   moved several -- `store.go:395` became `:410` for the genesis branch, `store.go:719` became
   `:756` for `legacyHashEvent`, `policy.go:77` became the pin-shape helper at `:125`. Addendum 4
   says as much at `0007:3632-3634` and CAP #4 §13 re-confirmed it. This is expected and is not a
   defect. Citations *into a prior addendum's own prose* (`0007:NNNN`) are unaffected and are used
   below where the claim is about the text rather than about the code.
2. **CAP #4 §7.6's variant-1 transcript understates which control catches an ordinary restore.**
   The record dumped with `pg_dump --no-owner --no-privileges`, so `screening_ledger_anchor` arrived
   owned by the restoring superuser and D33's owner check (`postgres.go:211-219`) fired first. Under
   an ordinary `pg_dump -d <src> | psql -d <dst>` run as the superuser -- the shape an operator
   actually types -- **owners are preserved**: re-executed against the real schema, the restored
   database reported `anchor owner=owl_ledger_ddl`, and the detector is D41's identity assertion,
   with **0 of 12** `sec7_protected_object` rows resolving via `pg_identify_object`. The finding is
   unaffected and its severity is unchanged; what changes is the credit. **D41 is carrying more of
   this than the CAP record attributes to it**, which matters because D43 below rests on exactly
   that.
3. **CAP #4's I-A severity rationale rests on a document that is not living guidance.** See D48;
   recorded there rather than here because it is a decision, not a citation slip.

---

### Addendum 5 context: the referent was fixed and the population drifted

Addendum 1 diagnosed the original's structural error as fixing instances rather than causes
(`0007:1494-1497`). Addendum 2 named its findings as one class -- "a control whose installation is
asserted rather than checked, by the party the control constrains" (`0007:1499-1500`). Addendum 3
sharpened it to "a control that decides what to protect, or what to protect against, by listing
members of an open set" (`0007:2172-2173`), and produced D31. Addendum 4 sharpened it again to "the
enumeration was fixed and the referent drifted" (`0007:2853-2857`), and produced D40's replacement
of an open set of *ways a statement can refer to an object* with a closed set of *properties of the
object*.

CAP #4 §0.1 looked for a fifth turn of that screw **inside the security boundary and did not find
one**, and §12 states the honest reason: D31's and Addendum 4's principles compose. What it found
instead is the same question asked about a different axis, and CAP #4 §12 phrases it exactly:

> **A control scoped by an identifier the adversary cannot change is also scoped by an identifier
> that does not survive the operations the system legitimately performs on itself. Ask not only
> "what does it compare, and is that the thing that matters?" but "over what population of databases
> is that comparison meaningful, and what routine operation moves the schema outside it?"**

Both findings are that question answered incompletely, in two different places:

| Mechanism | What it compares | Why it is incomplete | Finding |
|---|---|---|---|
| D34/D40 registries | raw OIDs (`provision_test_roles.sh:430-456`, `:540-579`) | an OID is a fact about one running database, not about the schema; every mechanism that copies a schema carries the rows and not their meaning | **I-A** |
| D41 relation registry | `objid` resolved via `pg_identify_object` (`postgres.go:419-431`) | the *other seven columns* are what D40's second phase compares live state against, and nothing compares them to anything | **I-B** |

**The principle this addendum adopts, stated once and applied twice:**

> **A control's referent has a population over which it is meaningful, and that population is part
> of the control. State it, detect departure from it, and say which of the system's own routine
> operations leave it -- but do not weaken the referent to widen the population.**

The last clause is the substantive move and it is the one the investigation forced. The obvious
response to I-A is to replace the OID with something portable. D44 shows by execution that the only
portable identifier a relation has is its name, that a name-keyed registry reopens G-G, and that the
two properties -- adversary-immutable and dump-portable -- are in **genuine tension for a referent**
and **not in tension at all for a marker**. That distinction is what makes D43 and D45 the right
shape and D44 a rejection rather than an adoption.

---

### D43. I-A (MEDIUM): the population D34/D40/D41 are meaningful over, stated as a fact and not a caveat

**The finding, restated from the code.** `sec7_protected_object` and `sec7_protected_relation` store
raw OIDs (`provision_test_roles.sh:430-439`, `:449-456`, `:464-477`), and `sec7_protect_ddl_objects()`
compares against them by OID in both phases (`:513`, `:519`, `:540-579`). An OID identifies an object
inside one running database; it is not a property of the schema. `pg_dump` emits both registries
**and** both event triggers, so a copy always arrives with the enforcement machinery present and its
referents wrong, in one of two directions. Both were reproduced against the real schema during this
design pass:

```
variant 2 -- pg_dump --schema-only | psql (the "clone production into staging" command)
  registry rows:        obj=0/12  rel=0/2      <- a schema-only dump carries no rows
  event triggers:       both present, evtenabled='A'
  anchor owner:         owl_ledger_ddl          <- correct
  as owl_ledger_ddl, the exact role D26/D34/D40 exist to bind:
    DROP TRIGGER screening_ledger_anchor_immutable ON screening_ledger_anchor  => SUCCEEDED
    CREATE RULE ... ON INSERT TO screening_ledger_anchor DO INSTEAD NOTHING    => SUCCEEDED
    ALTER TABLE screening_ledger_anchor DISABLE TRIGGER ALL                    => SUCCEEDED

variant 1 -- pg_dump | psql, owners preserved (no --no-owner)
  registry rows:        obj=12/12 rel=2/2       <- rows carried faithfully
  identities resolving: 0 of 12                 <- and meaning carried not at all
  anchor owner:         owl_ledger_ddl          <- correct
  [superuser]    CREATE TABLE p (x int)
      => ERROR: ADR-0007 Addendum 4 D40: protected relation (objid 16665) no longer exists
  [owl_migrator] GRANT SELECT ON screening_ledger_event TO owl_app
      => ERROR: ADR-0007 Addendum 4 D40: protected relation (objid 16665) no longer exists
```

Variant 2 is G-A's shape -- a control present in the catalog and doing nothing -- reached by a
supported tool with no flags that would avoid it. Variant 1 is R18's blast radius realised without
any drift and without any superuser mistake.

**Decision: state the population, and add no new security control, because the one that is needed is
already installed.**

This is the conclusion the investigation produced and it is the opposite of what this section was
expected to reach, so it is stated with the evidence rather than asserted. **D41 is already the
correct detector, and it is exact.** The four operations that copy this schema partition cleanly:

| Operation | Relation OIDs | Registries | Controls actually enforcing? | D41's verdict |
|---|---|---|---|---|
| `pg_dump --schema-only` restore | reassigned | **empty** | **no** | `has 0 row(s), expected exactly 12` |
| `pg_dump` full restore | reassigned | rows carried, all dangling | no -- all DDL fails | `no row whose OID resolves ... to pg_class public.screening_ledger_anchor` |
| `CREATE DATABASE ... TEMPLATE` | **preserved** | rows carried and **valid** | **yes** | provisioned |
| physical basebackup / replica | **preserved** | rows carried and **valid** | **yes** | provisioned |

The third row was executed, not reasoned about, because it is the row that decides D45's shape:

```
CREATE DATABASE owl_tmpl TEMPLATE owl_ci;
  relation OIDs preserved?  prot oid here = 16387 ; registry rel row objid = 16387
  as owl_ledger_ddl in the TEMPLATE clone:
    DROP TRIGGER prot_immutable ON prot   => ERROR: D34: prot_immutable on public.prot (objid 16396) is protected
    CREATE RULE r2 ... DO INSTEAD NOTHING => ERROR: D40: protected relation (objid 16387): a rewrite RULE exists on it
```

**The load-bearing consequence: there is no state in which a copy's controls are inert and D41
accepts it, and no state in which a copy's controls are live and D41 refuses it.** In every copy
whose OIDs were reassigned, D41 fails; in every copy whose OIDs were preserved, the controls
genuinely enforce. The stated invariant is therefore not falsified by any of the four operations,
which is why I-A is MEDIUM and not HIGH, and why this addendum adds **no** new gate. What I-A
actually exposes is three absences, and D45, D46, D48 and D49 answer them one for one: nothing
**diagnoses** the state, nothing **documents** it, and nothing **tests** it.

**The population, stated so a later reader inherits it rather than re-deriving it.** D34's, D40's
and D41's guarantees hold over exactly one database: **the one whose protected relations still carry
the OIDs `grant-ddl-ownership` recorded, in the instance it recorded them in.** A database leaves
that population when and only when its relation OIDs are reassigned, which is what every *logical*
copy does and no *physical* copy does. Re-running
`scripts/ci/provision_test_roles.sh grant-ddl-ownership` re-enters it, and that was verified rather
than assumed: after re-populating a schema-only clone's registries, the same owner-level attack that
had succeeded returned `D34: prot_immutable on public.prot (objid 16583) is protected`.

**One suggestion in CAP #4 §12 is wrong as literally phrased, and correcting it here stops it being
re-derived.** §12 point 1(a) proposes that provisioning "record a database identity
(`system_identifier` from `pg_control_system()`, say) that a copy cannot carry." A copy carries it
perfectly whenever the copy lands in the same cluster, which is the case §7.6 itself demonstrated:

```
source   database  sysid=7676522240524753513  dboid=16616
restored database  sysid=7676522240524753513  dboid=17177      <- sysid IDENTICAL
```

`system_identifier` is a property of the *cluster*, not of the database. The pair
`(system_identifier, database OID)` does discriminate, both halves are readable by `owl_migrator`
with no new role, DSN or grant (executed), and neither `owl_migrator` nor `owl_ledger_ddl` can change
either (`ALTER DATABASE ... RENAME` -> `must be owner of database`, for both). D45 uses the pair.
D45 also explains why it may not gate.

---

### D44. Direction B investigated and rejected: the portable identifier is the mutable one

The remediation brief asked for both directions to be investigated with real reasoning and for the
answer to say plainly whether adversary-immutability and dump-portability are in genuine tension,
rather than proposing something that quietly gives up one to gain the other. Both halves were built
and run.

**Decision: the registries keep raw OIDs. A name-keyed -- or any dump-portable -- referent is
rejected, because it reopens G-G, which D31 closed by execution.**

**What was built.** A second lab database with the same protected table, the same guard triggers and
the same two event triggers, but with the registry keyed by `object_identity` strings rather than
`objid`, and with D40's second phase resolving each protected relation by name. Then the escape, as
`owl_ledger_ddl`, the table's own owner:

```
name-keyed registry:
  DROP TRIGGER prot_immutable ON prot                  => ERROR: BYNAME-DROP blocked  (the easy case)
  ALTER TRIGGER prot_immutable ON prot RENAME TO zzz   => ALTER TRIGGER      <-- SUCCEEDED
  DROP TRIGGER zzz ON prot                             => DROP TRIGGER       <-- SUCCEEDED
  non-internal triggers left on prot: 0

shipped OID-keyed registry, same two statements:
  ALTER TRIGGER prot_immutable ON prot RENAME TO zzz
      => ERROR: D34: zzz on public.prot (objid 16396, tag ALTER TRIGGER) is protected
  DROP TRIGGER prot_immutable ON prot
      => ERROR: D34: prot_immutable on public.prot (objid 16396) is protected
  non-internal triggers left on prot: 2
```

Two statements, no privilege the shipped configuration does not already grant, and the anchor's
row-immutability trigger is gone. The reason is the one D31 recorded at `0007:2216-2228` and this
pass re-confirmed directly:

```
t1 oid before rename                                     16505
ALTER TRIGGER t1 ON prot RENAME TO t1_renamed
NOTICE: tag=ALTER TRIGGER type=trigger objid=16505 identity=t1_renamed on public.prot
t1_renamed oid after rename                              16505
```

The OID is stable across the rename; the reported identity is the **new** name. A registry keyed by
identity therefore stops matching the moment the adversary renames, which is precisely G-G. D31's
second sub-decision compounds it: by the time `sql_drop` fires the object is already gone from the
catalog, so a name cannot be resolved there at all (`0007:2230-2243`) -- a name-keyed drop phase can
only compare the reported identity string, which is the comparison that just failed.

**So the answer to the brief's question is: yes, the two properties are in genuine tension -- for a
referent. They are not in tension at all for a marker, and conflating the two is what makes this
look like a closer call than it is.** A marker only has to be *recognised*; a referent has to be
*dereferenced* to an object. Executed:

```
COMMENT ON TABLE sec7_protected_relation IS 'SEC7-MARKER-superuser-owned';   -- superuser-owned relation
  occurrences in pg_dump --schema-only output   1        <- DUMP-PORTABLE
  occurrences in pg_dump (full) output          1
  owl_ledger_ddl, in the SOURCE database  => ERROR: must be owner of table sec7_protected_relation
  owl_migrator,   in the SOURCE database  => ERROR: must be owner of table sec7_protected_relation
  owl_ledger_ddl, in the schema-only CLONE => ERROR: must be owner of table sec7_protected_relation
  owl_migrator,   in the schema-only CLONE => ERROR: must be owner of table sec7_protected_relation
                                                        <- ADVERSARY-IMMUTABLE, in the copy too
```

A `COMMENT ON` a superuser-owned relation is both dump-portable and adversary-immutable, in the
source and in the copy. **What it cannot do is name an object in a way that survives a rename**,
because the only portable name is the mutable one. That is the whole of the tension, and stating it
this precisely is what stops the next reader adopting a portable referent on the strength of the
marker result.

Two further candidates were considered and are recorded so they are not re-derived:

- **`SECURITY LABEL`** is unavailable in this deployment: `SECURITY LABEL ON TABLE ... IS 'x'` fails
  with `no security label providers have been loaded`, confirmed by execution and consistent with
  CAP #4 §7.3, which found the same when trying it as an attack. It would in any case have the
  identity problem above.
- **Extension membership (`ALTER EXTENSION ... ADD`)** was already rejected by D31
  (`0007:2269-2272`) for requiring a `.control` file and a packaging story this repository does not
  have. A second reason applies here and is worth adding: `pg_dump` deliberately emits only
  `CREATE EXTENSION` for extension members, so making the ledger relations extension members would
  mean a dump carried **no ledger tables at all**. That is a different failure, not a fix.

**What survives from Direction B is the marker, and it is demoted from referent to diagnostic.**
D45 adopts it in that role, and D46 spends it on the failure D45 cannot prevent.

---

### D45. `sec7_instance_binding`: a copy marker that diagnoses and must never gate

D43 establishes that D41 already refuses every copy whose OIDs were reassigned. What no mechanism
does is **say why**, and I-A's variant-1 transcript is the cost: an operator running a DR exercise
gets `protected relation (objid 16665) no longer exists` -- a bare integer -- from every DDL
statement in the database, including their own unrelated ones, with no path from that message to a
cause or a fix.

**Decision: provisioning records one row binding the registries to the instance whose OIDs they
hold. It is read only on an already-failing path, and it is never a gate.**

Illustrative only -- the implementation PR owns the real shape:

```sql
CREATE TABLE IF NOT EXISTS sec7_instance_binding (
  system_identifier text        NOT NULL,
  database_oid      oid         NOT NULL,
  database_name     text        NOT NULL,
  provisioned_at    timestamptz NOT NULL);
```

- **Written by `scripts/ci/provision_test_roles.sh grant-ddl-ownership`** (`:119`), in the same step
  and by the same bootstrap superuser that creates and populates both registries, from
  `pg_control_system()` and `pg_database`. Exactly one row; the step deletes and re-inserts, as it
  already does for both registries (`:447`, `:462`), so re-provisioning is idempotent.
- **Same posture as the two registries:** superuser-owned, `REVOKE ALL ... FROM PUBLIC`, `SELECT`
  granted to `owl_migrator`, and **itself a member of `sec7_protected_object`** so it cannot be
  dropped or altered without tripping the trigger that reads it. Confirmed by execution that
  `owl_ledger_ddl` and `owl_migrator` are both refused `UPDATE` on it (`permission denied for
  table sec7_instance_binding`), matching the 24-attempt result CAP #4 §7.5 recorded for
  `sec7_protected_relation`.
- **Both fields are readable by `owl_migrator` with no new role, DSN or grant** -- executed, not
  assumed, the same property D33's and D41's existing facts have (`0007:2422-2425`,
  `0007:3404-3406`).

**Why the pair, and not `system_identifier` alone.** D43's transcript: a restore into another
database of the same cluster carries `system_identifier` unchanged. The database OID is what moves.

**Why this must never gate, which is the decision and not a hedge.** `CREATE DATABASE ... TEMPLATE`
changes the database OID while **preserving every relation OID**, so the binding reports a mismatch
on a database whose controls are demonstrably live (D43's third transcript). A blocking binding
check would refuse a correctly protected database -- a false refusal, which is exactly the class
D12 exists to remove, arriving from the other side. Executed across all three states:

```
source database                       BINDING MATCHES -- OIDs in this database were assigned here
full restore (same cluster, new db)   BINDING MISMATCH -- recorded 7676522240524753513/16384 (owl_ci)
                                                        live     7676522240524753513/16513 (owl_full2)
schema-only clone                     NO BINDING ROW (a schema-only dump carries no rows)
```

The third line is worth reading carefully: in variant 2 the binding row is absent for the same
reason the registry rows are, so **the binding adds nothing to variant 2's detection** -- D41's
population assertion already names it, and D45 simply joins that assertion so the message can name
the binding too. The binding earns its place in variant 1 and nowhere else.

**Cost, stated plainly because it is the cost CAP #4 §10.2 names as this design's real risk.**
Adding a thirteenth protected object means three coordinated edits, none of which cross-checks the
others: `provision_test_roles.sh:464-477`'s `INSERT`, `:481`'s `[[ "$registry_row_count" == "12" ]]`,
and `requiredProtectedObjects` (`internal/screeningledger/postgres.go:337-350`). The row-count
assertions fail *closed*, which is why the arrangement survives, and R23 records that the surface
grew again rather than glossing it.

---

### D46. I-A's second sub-case: the diagnostic names the relation and the instance, or says why it cannot

CAP #4 separates I-A's two variants and is right to: variant 2 is the security gap and variant 1 is
a **diagnosability problem, not a bypass**. This decision is that smaller, separate item, and it is
deliberately kept out of D43 so neither is read as the other's justification.

**Decision: `sec7_protected_relation` gains an `identity` column recorded at provisioning, used only
in the error text, and D40's existence branch resolves it to produce one of three named messages.**

- `identity` is written by `grant-ddl-ownership` from `pg_identify_object`, exactly as
  `requiredProtectedRelations` (`postgres.go:393-396`) already declares the same two strings
  independently. Two declarations of one fact, which is D41's own arrangement
  (`0007:3429-3433`), so D47's comparison covers this column too.
- D40's first check (`provision_test_roles.sh:541-543`) keeps its `objid` existence test **exactly
  as it is**. Only the `RAISE` changes.
- **The resolution must be exception-free, and `to_regclass` is not.** Executed:
  `to_regclass('public.nope')` returns NULL without raising, but `to_regclass('a.b.c.d')` raises
  `improper relation name (too many dotted names)`. A new exception path inside an event-trigger
  function that already runs on every DDL statement is precisely R17's accepted risk realised, so
  the resolver is a plain catalog join that cannot raise:

```sql
SELECT c.oid INTO live
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname || '.' || c.relname = rel.identity;
```

**The three messages**, executed end to end against a restored database during this design pass:

```
(a) name resolves to a DIFFERENT oid, and the binding mismatches -> this is a copy
    ERROR: protected relation "public.prot" (registry objid 16387) no longer exists; "public.prot"
    is present with objid 16450. This database is a copy or restore of another (registry recorded
    instance 7676522240524753513/16384 "owl_ci"; live instance 7676522240524753513/16446
    "owl_full"). The SEC-7 registries hold raw OIDs and do not survive pg_dump/pg_restore.
    Recovery: scripts/ci/provision_test_roles.sh grant-ddl-ownership -- see docs/operations/...

(b) name resolves to a DIFFERENT oid, binding MATCHES -> dropped and recreated in place
    ERROR: protected relation "public.prot" (registry objid 16387) no longer exists; "public.prot"
    is present with objid 16450 -- the relation was dropped and recreated. Re-run
    grant-ddl-ownership.

(c) the name does not resolve at all
    ERROR: protected relation "public.absent" (registry objid 16387) no longer exists and no
    relation of that name is present.
```

Case (b) is R15's own literal scenario (`0007:2666-2674`), which until now produced the same bare
integer as case (a) despite being a completely different situation with a completely different
cause.

**The structural property that makes this safe, stated because it is the only reason a diagnostic
belongs inside a security control's trigger function at all:** `identity` and the binding row are
read **only after** `NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = rel.objid)` has already
fired. The control's decision is made before either value is consulted. **A wrong, stale, or absent
`identity` can therefore change only an error message and can never widen what passes**, and there
is no steady-state cost: on the passing path neither column is touched, so D40's measured
~0.06 ms per statement (`0007:3335-3336`) is unchanged. This is deliberately the opposite
arrangement from D41's `note` column, which H-E found carrying a claim nothing checked -- `identity`
carries a claim nothing *relies on*, and D47 checks it anyway.

---

### D47. I-B (LOW): the recorded state columns get a referent of their own, and R19 is corrected forward

**The finding, restated from the code.** `sec7_protected_relation` carries eight columns
(`provision_test_roles.sh:430-439`). `objid` is asserted by D41. The other seven -- `relowner`,
`relkind`, `relrowsecurity`, `relforcerowsecurity`, `trigger_oids`, `index_oids`, `policy_oids` --
are exactly what D40's second phase compares live catalog state *against* (`:544-579`), and
`protectedRelationIdentityReason` (`internal/screeningledger/postgres.go:404-433`) reads **none of
them**: it counts rows (`:412-418`) and resolves each row's `objid` to an identity (`:419-431`), and
stops. CAP #4 §7.5 case G demonstrated the consequence, and this design pass reproduced it against
the real schema:

```
UPDATE sec7_protected_relation SET trigger_oids = <the real set> || ARRAY[999999]::oid[]
  shipped check:  rows=2  all identities resolve: 2   -> Provisioned=true
```

The registry now records a trigger set that does not exist, and the verifier certifies the database
as provisioned.

**CAP #4 §12 point 2 doubts this is worth fixing, on the reasoning that "the natural check is 'the
recorded state equals the state `grant-ddl-ownership` would record now,' which is close to
re-running provisioning and may not be worth it." That is the right question and the answer is no --
it is not close to re-running provisioning, and this was established by building the check rather
than estimating it.** All seven columns reduce to literals, and five of them to literals this
repository already declares:

| Column | Asserted against | Source of the literal |
|---|---|---|
| `relowner` | `owl_ledger_ddl` | `requiredDDLOwnedTables` (`postgres.go:165-168`) -- already declared, already asserted live by D33 (`postgres.go:211-219`) |
| `relkind` | `'r'` | new, one character |
| `relrowsecurity`, `relforcerowsecurity` | `false`, `false` | new, and true of both relations today (verified) |
| `trigger_oids` | exactly the OIDs of the two trigger names declared for that table | `requiredSchemaObjects` (`postgres.go:485`) -- already declared per table |
| `index_oids` | exactly the OID of `<table>_pkey` | new, one name per table |
| `policy_oids` | empty | new |

**Decision: `protectedRelationIdentityReason` gains a per-column comparison against a literal
declaration written beside `requiredProtectedRelations` (`postgres.go:393-396`), reconciling recorded
OIDs to declared *names* through the catalog.** This is a **name-to-OID reconciliation between two
independent literals**, not a re-execution of provisioning: it never reads the provisioning script,
never re-derives the set by scanning, and asks no question whose answer provisioning has to supply.
Illustrative shape only:

```sql
r.trigger_oids = (SELECT coalesce(array_agg(t.oid ORDER BY t.oid), ARRAY[]::oid[])
                    FROM pg_trigger t
                   WHERE t.tgrelid = r.objid AND NOT t.tgisinternal
                     AND t.tgname = ANY($1))          -- $1: the two declared trigger names
```

Executed against the real schema, both directions:

```
CAP #4 §7.5 case G state:   owner_ok=t kind_ok=t rls_ok=t triggers_ok=f indexes_ok=t policies_ok=t
                            (the shipped check returns Provisioned=true for this exact state)
clean provisioned state:    all seven columns match declared literals for both relations: true
```

Note what the reconciliation buys beyond catching the demonstrated state: because the live side
filters to the **declared** trigger names, a recorded set containing an OID that is not one of them
fails whether that OID is fabricated, stale, or belongs to a real but undeclared trigger. It is
D41's own move -- compare against an independent literal rather than against the artifact's own
account of itself -- applied to the seven columns D41 skipped. `identity` (D46) is covered by the
same comparison, so the diagnostic column is not a new unchecked claim.

**Severity is LOW and this decision does not inflate it.** Reaching the state requires the bootstrap
superuser, who can drop the event triggers outright, so it confers no capability a superuser does
not already have -- CAP #4's own reasoning, adopted unchanged. `relowner`, the one recorded fact
that maps directly to a live protection, is independently asserted by D33 already. And the
manipulations in the other direction are loud rather than silent: a recorded value that does not
match reality makes `IS DISTINCT FROM` true on every DDL statement, which breaks all DDL rather than
permitting anything. **This is a correctness-of-the-check fix, not a hole being closed**, and the
next section is the part that actually matters.

**R19's text is stricter than what the code enforces, and this addendum says so rather than patching
around it.** `0007:3551-3556` reads:

> *"D41 asserts its identity and population, and D40 puts it under `sec7_protected_object`'s
> protection, but **an adversary who can rewrite both the registry and the reality it records
> passes every check.**"*

**The conjunction is false as written.** Rewriting `trigger_oids`, `index_oids`, `policy_oids`,
`relkind` or either RLS flag **alone** neuters D40's second phase for that property with reality
untouched, and D41 is silent -- demonstrated above. Per this document's convention the sentence at
`0007:3551-3556` is **not edited**; it is withdrawn here, and what remains true of R19 after the
withdrawal is stated exactly:

- **R19's substantive decision stands.** `sec7_protected_relation` *is* a second trust object; it
  *is* a member of `sec7_protected_object`; D41 *does* assert its identity and population; and the
  residual *does* terminate at the bootstrap superuser, R12/R17's terminus. CAP #4 §7.5 confirmed by
  execution that no non-superuser write path of any kind exists -- 24 attempts across four roles.
  None of that is disturbed.
- **What was overstated is the precondition.** Before D47 the bypass required rewriting the registry
  **only**. After D47 it requires rewriting the registry **and** the reality it records, which is
  what R19 already described. **R19's sentence is made true by D47; it was not true when it was
  written.** That distinction matters for the same reason D39 gave when withdrawing D35's
  biconditional (`0007:3199-3201`): a later reader deciding what may safely be changed reasons from
  the sentence, and an acceptance rationale naming a stronger precondition than the code enforces
  licenses the next change to remove the wrong thing.

---

### D48. Where operator-facing guidance lives -- and why the legacy design document is not edited

**A premise the remediation brief inherited from CAP #4 does not survive verification, and recording
that is this document's own standard (§3, §3.4, §6.1).**

CAP #4 rates I-A partly on this basis (§7.6, §12): *"`docs/design/deployment.md:39` instructs
operators to do exactly this"*, and the remediation brief accordingly asked that the file be
corrected to stop instructing an unpaired clone pattern. Checked against the tree at this commit:

- `docs/design/README.md:3` -- **"Status: historical record -- not living documentation."**
- `:11` -- the files are **"byte-preserving copies of the frozen legacy source"**, restored under
  SAL-4, SAL-5, SAL-6 and SAL-9 from `watchlist-platform-legacy` frozen at
  `31aa23f516018f7577f4dcec95142f981142a6f8`.
- `:19-20` -- **"Nothing else here was rewritten, re-wrapped, or fact-checked against the current
  codebase."**
- `:22` -- **"Read these as intent, not as fact."**
- `git log -- docs/design/deployment.md` returns exactly one commit, `86350b7` ("SAL-5, SAL-6,
  SAL-9: restore remaining legacy design/testing/migration docs"), and the only reference to the
  file anywhere in the tree is that same README's own table row (`docs/design/README.md:53`).
- The only other `pg_dump` mention in the repository,
  `docs/governance/openwatchlist-clean-restart-r0.md:22-28` (`pg_dump -Fc`,
  `pg_restore --clean --if-exists`), is from the same SAL commit and describes the backup contract
  of the legacy homelab deployment that the same document's R0 section retires.

**So the repository does not currently instruct anyone to do this.** I-A's severity rationale is
inaccurate on that point, and the addendum says so plainly rather than inheriting it.

**I-A itself is undiminished, and the correction makes the remedy clearer rather than smaller.**
`pg_dump` is *the* PostgreSQL logical backup and clone tool; an operator performing a DR exercise or
refreshing a staging environment reaches for it without being told to. What CAP #4 found is
therefore not a wrong instruction to correct but **a warning that does not exist** -- and the
correction sharpens exactly which absence is the finding. §10.3's second risk states it precisely
and is unaffected: *"the safe operating envelope is not written down anywhere an operator would
look."*

**Decision: `docs/design/deployment.md` is not edited. The living document that does not exist is
written, in the place operator-facing guidance already lives.**

Editing a byte-preserving salvage copy to correct a claim about the *present* would break the
convention `docs/design/README.md:11` and the SAL-* work established, and would be a strange act in
any case: it would amend a historical record of what the legacy system did, to describe a control
that legacy system never had. The document is accurate as history.

- **New: `docs/operations/sec7-database-copies.md`**, the second file in a directory that currently
  holds exactly one (`screening-ledger-policy-signing.md`). Its scope is D43's population, written
  for an operator rather than a reviewer:
  - the registries hold raw OIDs and **do not survive a logical dump**, stated first;
  - D43's four-row table -- which copy operations preserve the OIDs and which reassign them;
  - **what to do before cloning for staging**: re-run
    `scripts/ci/provision_test_roles.sh grant-ddl-ownership` on the clone, and treat a clone that
    has not been re-provisioned as not representative of production for any SEC-7 purpose;
  - **how to read each of D46's three messages**, and what each one means;
  - **the recovery path for a bricked restore**, both verified branches: `ALTER EVENT TRIGGER
    sec7_protect_ddl_objects_on_alter DISABLE` (which succeeds even while drifted) or
    `SET event_triggers = off`, then re-run `grant-ddl-ownership`, then re-enable. Re-verified
    during this design pass on a genuinely bricked restore of the real schema.
  - that `event_triggers` is `SUSET` and so is not a bypass for any non-superuser
    (`permission denied to set parameter "event_triggers"`, re-confirmed) -- R18's point, repeated
    where an operator will meet it.
- **`docs/operations/screening-ledger-policy-signing.md` gains one cross-reference**, so the
  directory's two documents point at each other and neither is reachable only by knowing it exists.
- **`SECURITY.md` and `README.md` are unchanged.** R3's rule is unchanged and now has a fifth
  instance behind it. `README.md:93-97`'s requalification notice stays.

**This discharges R18's own unmet requirement.** R18 (`0007:3527-3549`) states that "the recovery
path must be documented rather than discovered" and treats that as satisfied by having written it
into a risk note at line 3536 of this document, inside a section headed "New accepted risks."
CAP #4 §7.6 point 2 is right that it is not. D48 is where it is actually discharged, and R18's text
is not edited -- this decision records the change, the convention AR7 set for R7.

---

### D49. Test ownership and pre-declared withdrawal conditions

The specific shape the implementation must satisfy, so nothing weaker can be claimed to discharge
this addendum -- the standard D20 (`0007:1293-1338`), D26 (`0007:1874-1885`), D37
(`0007:2623-2662`) and D42 (`0007:3455-3523`) set.

**Every test below must fail before its change, per CLAUDE.md rule 5.** Where a CAP #4 transcript
exists, the test reproduces that transcript, not a paraphrase of it.

1. **The copy states become permanent CI fixtures, which is CAP #4 §12 point 1(c)'s question
   answered yes.** `grep -rn "pg_dump\|pg_restore"` across `internal/`, `scripts/` and `.github/`
   returns nothing at this commit, so **no test anywhere exercises a dumped or restored database**.
   `provision_test_roles.sh` gains a **`create-restored-database`** subcommand following the
   existing degraded-state fixture pattern exactly -- `create-stale-anchor-database` (`:616`) and
   `create-unprovisioned-database` (`:640`) already exist for precisely this purpose, and
   `.github/workflows/ci.yml` already invokes both. It builds **both** variants:
   `owl_ci_sec7_restored` (full `pg_dump | psql`, owners preserved -- note the drift item above:
   **not** `--no-owner`, or the test proves D33's owner check rather than D41's identity assertion)
   and `owl_ci_sec7_cloned` (`--schema-only`).
2. **D43.** `TestVerifyAnchoredRefusesRestoredDatabase` and
   `TestVerifyAnchoredRefusesSchemaOnlyClone` (pgx, against the two new fixtures): assert
   `CheckProvisioningState` returns a **specifically named** failure for each -- the identity
   failure for the restore, the population failure for the clone -- and that `VerifyAnchored`
   refuses. Both must assert the *reason string*, not merely `Provisioned=false`: the two states
   fail for different reasons and a test that cannot tell them apart would pass if either detector
   were removed.
3. **D43, the positive that stops the check being over-tightened.**
   `TestProvisioningStateAcceptsTemplateClone` (pgx): `CREATE DATABASE ... TEMPLATE`, assert
   `Provisioned=true` and that a `CREATE RULE` against a protected table is still blocked. This is
   the collateral-damage case for this addendum, and D37's rule applies verbatim: **a suite that
   proves only the refusals has not proven the design is safe to install.**
4. **D45.** `TestInstanceBindingIsRecordedAndNeverGates`: assert the row exists and matches after
   provisioning; assert `owl_ledger_ddl` and `owl_migrator` are both refused `UPDATE`; and assert
   that a **mismatched binding with valid registries returns `Provisioned=true`** -- the test that
   would fail if anyone later made the binding a gate.
5. **D46.** `TestD40DiagnosticNamesTheRelationAndTheInstance` (pgx): all three messages, each
   asserted on its own fixture -- copy, drop-and-recreate-in-place, name-absent -- with the SQLSTATE
   captured rather than inferred. Plus the negative that makes the safety property real:
   **corrupt `identity` to a value that resolves to nothing, on an otherwise healthy database, and
   assert every DDL statement still succeeds** -- proving the diagnostic column cannot affect the
   passing path.
6. **D47.** `TestCheckProvisioningStateDetectsRewrittenRecordedState` (pgx): CAP #4 §7.5 case G's
   exact `UPDATE`, asserting `Provisioned=true` **today** and a distinct named failure after --
   that direction is deliberate, per D42's note (`0007:3461-3465`): the current behaviour is
   acceptance, so a test asserting only the post-fix refusal cannot distinguish a working fix from a
   test that never exercised the path. Table-driven over all seven columns, not only
   `trigger_oids`, plus a clean-state positive.

**Withdrawal conditions, declared now rather than decided after the fact:**

- **If the instance binding is ever made a gate, D45 is withdrawn.** The `TEMPLATE` transcript in
  D43 shows a blocking binding refuses a database whose controls are demonstrably live. A
  diagnostic that becomes a gate is not a stronger version of D45; it is a different and worse
  decision, and test 4 above exists to make the change fail loudly.
- **If D47's clean-state positive fails against the real schema** -- if any of the seven columns
  turns out not to be a stable literal for both protected relations in the shipped configuration --
  the implementation stops and this addendum is amended. It does **not** ship a comparison covering
  some columns and not others: a check that runs on part of its referent is the shape of every
  finding in this document. In particular, if a future migration adds a second index or a third
  trigger to either relation, the literal changes and the two declarations must move together.
- **D46 must not be split from D45.** Message (a) -- the one that names the situation an operator is
  actually in -- requires the binding row. Shipping the `identity` column alone yields cases (b) and
  (c) and silently degrades case (a) into (b), which would tell a DR operator their relation was
  "dropped and recreated." That is a worse message than the bare integer it replaces.

**Addendum 4's pre-declared withdrawal conditions remain correctly un-triggered**, re-verified
against what *this* addendum designs rather than inherited from CAP #4's confirmation. D40's
collateral-damage cases pass, so the `pg_depend` fallback is **not** required and **must not** be
adopted (CAP #4 §12 confirms this independently). D38(a) and D38(b) shipped together as D42
required. Nothing in this addendum touches D38, D39, D40's comparison set, or D41's `objid`
assertion.

### New accepted risks

**R21 -- the instance binding is a diagnostic, and a physical copy is undetectable by it. That is
correct, not a gap.** A `pg_basebackup`, a streaming replica, or a volume snapshot carries
`pg_control`'s `system_identifier` and `pg_database`'s OIDs byte-for-byte, so the binding matches
and no copy is reported. It should not be: such a copy also carries every relation OID, so D34, D40
and D41 are genuinely enforcing in it -- D43's fourth table row. The binding answers "were these
OIDs assigned here?", which is the question that matters, and not "is this the original database?",
which is not. Recorded so that a later reader does not add a stronger identity test to close a gap
that is not one.

**R22 -- `pg_upgrade`'s preservation of database OIDs was not verified in this pass, and is stated
as unverified rather than asserted.** `pg_upgrade` is designed to preserve relation OIDs, and
preserves database OIDs on recent majors; if that holds, a major-version upgrade stays inside D43's
population and the binding continues to match. It was not executed here, and this document does not
assert PostgreSQL behaviour it has not run -- the standard Addendum 3 set (`0007:2129-2139`). The
failure direction if it does not hold is benign and worth stating: the registries would already be
failing D41 on their own account, and the binding would add a diagnostic to an
already-failing path. It can produce a spurious *message*, never a spurious *refusal* -- which is
D45's whole design. This joins CAP #4 §11 point 1's standing condition that a different PostgreSQL
major invalidates the DDL results.

**R23 -- the coordinated-edit surface grew again, and this addendum does not pretend otherwise.**
CAP #4 §10.2 already records that adding a ninth protected relation requires coordinated edits to
`db/migrations/`, `SchemaSQL`, `provision_test_roles.sh`'s two registry populations and its two
hard-coded row-count assertions, and `postgres.go`'s four literal declarations, with nothing
cross-checking them. D45 adds a thirteenth registry member (so `:481`'s `== "12"` and
`requiredProtectedObjects` both move), D46 adds a column, and D47 adds a fifth literal declaration.
The mitigating property is unchanged and is the reason this arrangement survives: **every one of
those assertions fails closed.** The aggravating property is unchanged too: nothing cross-checks
them against each other, and §10.3's first risk -- that the controls are split across four artifacts
with no single owner -- is not addressed by this addendum and is not claimed to be.

### Staging

Same shape and reason as §8 and the four prior addenda (`0007:1397-1414`, `0007:2038-2058`,
`0007:2694-2716`, `0007:3566-3586`): each stage independently reviewable and independently provable.

1. **This addendum**, merged before any code (CLAUDE.md rule 7).
2. **Stage G1 -- the operator envelope.** D48 alone: `docs/operations/sec7-database-copies.md` and
   the cross-reference. **Sequenced first, and deliberately so.** It blocks nothing, which is
   exactly why every prior addendum's equivalent item was sequenced last and why CAP #4 §12 point 3
   predicts it "is the item most likely to be dropped because it is documentation rather than code."
   It is also the only item an operator meets *before* the dangerous action rather than after. D23
   was sequenced last on the same "blocks nothing" reasoning and CAP #2 rated the resulting gap
   HIGH; this addendum does not repeat that.
3. **Stage G2 -- the binding and the diagnostic.** D45 and D46 together, for the reason D49's third
   withdrawal condition states: D46's most important message needs D45's row. Includes the
   `create-restored-database` fixture and its CI wiring, and D43's tests, since the fixture is what
   makes them runnable. Per CLAUDE.md Boundaries the `.github/workflows/ci.yml` invocation of the
   new subcommand is named explicitly in the PR description, following D30's precedent
   (`0007:1993-1997`).
4. **Stage G3 -- the recorded-state comparison.** D47. Sequenced last because it is the LOW, because
   it depends on D46's `identity` column being present to cover it, and because it touches
   `protectedRelationIdentityReason`, which G2 does not.
5. **`SECURITY.md` and `README.md` language.** R3's rule unchanged. `README.md:93-97`'s
   requalification notice stays until every stage above has landed and its reproduction passes.
   CAP #4 §9 re-confirmed that nothing in PR #142 or #143 re-asserted the guarantee; that must
   remain true through this addendum as well.

**SEC-7 does not close on this addendum, but the reason has changed and that should be said
plainly.** §8's closing condition -- "a deliberately forged chain fails a CI run that nobody chose
to invoke" -- is met in the CI sense by `d20_exploit_test.go` and, since D23, in the operational
sense too. For the first time it is **not contradicted by a demonstrated forgery**: CAP #4 found
none. What remains open is limb (c) being reachable-false through an ordinary copy with zero test
coverage and zero operator documentation. That is a smaller and different barrier than the four that
preceded it, and D48 and D49 are the whole of it. The closing sentence stands and now has a fifth
addendum behind it.

### Addendum 5 summary

- **CAP #4's verdict is QUALIFIED, not PASS, for the fourth consecutive audit -- but for the first
  time with no forgery bypass.** The cryptographic and database-level core held against everything
  the audit attempted, including CAP #3's CRITICAL reproduced end to end. The two remaining findings
  are a scope gap (I-A, MEDIUM) and an unchecked referent (I-B, LOW), and neither is an attack.
- **The class is one axis over from Addendum 4's, not one turn deeper.** Not "the referent drifted"
  but **"the referent is correct and its population was never stated."** D43 states the population;
  the principle is that a referent's population is part of the control, and that the way to fix a
  narrow population is to state and detect it, **never to weaken the referent to widen it**.
- **The design is D43-D49.** The population D34/D40/D41 are meaningful over, with the conclusion that
  D41 is already its exact detector (D43); Direction B evaluated and rejected with the transcript
  that refutes it (D44); an instance binding that diagnoses and is pre-declared never to gate (D45);
  the three-way diagnostic that replaces an integer-only message, read only on an already-failing
  path (D46); the seven recorded state columns given a referent of their own, with R19 corrected
  forward (D47); the operator document that does not exist, and why the frozen legacy design
  document is not edited (D48); and the proof obligations with pre-declared withdrawal conditions
  (D49).
- **This design pass executed its mechanism assumptions, and three of them changed the design.** A
  name-keyed registry reopens G-G -- `ALTER TRIGGER ... RENAME` then `DROP TRIGGER`, two statements
  by the table's owner, trigger gone, while the shipped OID-keyed build blocks both.
  `system_identifier` is identical across a same-cluster restore, so CAP #4 §12's own suggestion is
  wrong as phrased and the database OID is what discriminates. `CREATE DATABASE ... TEMPLATE`
  preserves relation OIDs, which refutes making any instance marker a gate. Also confirmed by
  execution: `COMMENT ON` a superuser-owned relation is both dump-portable and adversary-immutable,
  so the tension is real for a **referent** and absent for a **marker**; `to_regclass` raises on a
  malformed name and so is unusable inside the trigger; both R18 recovery paths work on a genuinely
  bricked restore; re-running `grant-ddl-ownership` restores enforcement on a clone; and D41's
  identity assertion, not D33's owner check, is what catches an ordinary owner-preserving restore.
- **One premise inherited from CAP #4 does not survive verification.** `docs/design/deployment.md`
  is a byte-preserving restored legacy document in a directory `docs/design/README.md:3` marks
  "historical record -- not living documentation," referenced from nowhere else in the tree. The
  repository does not instruct operators to perform the dangerous copy; what is missing is a
  warning, not a corrected instruction. I-A is undiminished and the remedy is clearer for it.
- **Three risks are recorded** rather than designed away: the binding cannot and should not detect a
  physical copy (R21); `pg_upgrade`'s OID preservation is stated as unverified rather than asserted
  (R22); and the coordinated-edit surface grew again (R23).
- **This addendum revises no prior decision.** D1-D7, D8-D20, AR7, D21-D30, D31-D37 and D38-D42
  stand. R1-R18 and R20 stand. One sentence of R19 (`0007:3551-3556`) is withdrawn as stricter than
  what the code enforces, explicitly and in D47's own words; R19's substantive decision and its
  superuser terminus are unaffected, and D47 is what makes the withdrawn sentence true.

**Audit basis commit:** `8b36c91f7ef58e11048116d8c7e0e45f7da18024`

Every file:line citation in this addendum was verified against that tree -- the same commit CAP #4
was produced against, so no drift separates the audit from this design. For a CAP record covering
the implementation of this addendum, use the tip of whichever stage PR is under audit, not this
value.

## Addendum 6: atomicity -- the referent a legitimate operation rewrites, and the first finding that wedges rather than bypasses (2026-08-26)

- **Status:** Proposed
- **Trigger:** a fifth Composition Audit Program record produced against the implemented Addendum 5
  (`docs/backlog/sec-7-cap-record-71fbb42.md`, adversarial posture, audit basis commit
  `71fbb428bf8ef267f9607afc8dee9dd0bc5bc7f4`) returned **QUALIFIED, not PASS** for the fifth
  consecutive audit -- and for the **second** consecutive audit with **no forgery bypass**. Six
  findings remain, one HIGH (J-A), one MEDIUM (J-B) and four LOW (J-C, J-D, J-E, J-F). **None is a
  forgery**, and five of the six require no adversary at all. **SEC-7 is not closed.**
- **What CAP #5 confirmed and this addendum does not disturb.** D45's never-gates property held
  against six constructed states, four of them outside its own test -- the binding's *content*
  reaches no verdict in any of them, including absence and contradiction. D46's three messages were
  each reproduced verbatim against a real database in the real state each describes. D47 ships,
  works over all seven recorded columns plus `identity`, closes I-B, and turns out to be the only
  mechanism anywhere in the system that names J-A's state in words. The new `pg_dump` fixtures
  introduce nothing beyond the already-understood OID reassignment across eleven measured
  security-relevant catalog properties. The operator document works when followed literally, on both
  of its procedures. The cryptographic core is unregressed: 97 top-level PASS, 0 SKIP, 0 FAIL across
  all four pgx-gated packages. **D31's scoping principle, Addendum 4's referent principle and
  Addendum 5's population principle compose, and this addendum reopens none of them.**
- **Scope:** a pure addition. Nothing above this section is edited -- not D1-D7, not D8-D20, not
  AR7, not D21-D30, not D31-D37, not D38-D42, not D43-D49, not §3.4, §6.1 or the D19 correction
  note, not R1-R23. Decision numbering continues at **D50**; risk numbering at **R24**. Where a
  prior decision's *citation* has drifted, the drift section below records it rather than editing
  the old text -- the convention AR7 established for R7 and every addendum since has followed.
- **Verification basis:** every `file:line` below was re-derived from the working tree at
  `71fbb428bf8ef267f9607afc8dee9dd0bc5bc7f4` rather than copied from the CAP record or from a prior
  addendum.
- **This design pass executed its mechanism assumptions, as Addendum 3 established and Addenda 4
  and 5 held to -- and this time the execution refuted the fix this section was expected to
  reach.** A disposable PostgreSQL 17.11 cluster was built on port 55437 and provisioned with the
  **real** schema in `.github/workflows/ci.yml:141-235`'s exact order (all seventeen
  `db/migrations/*.sql` as `owl_migrator`, then `create-roles`, `grant-app-privileges` and
  `grant-ddl-ownership`), baseline confirmed at thirteen `sec7_protected_object` rows, two
  `sec7_protected_relation` rows, one `sec7_instance_binding` row, both event triggers
  `evtenabled='A'`, and `owl_ledger_ddl` holding `CREATE` on neither schema nor database. The
  cluster was torn down, its port confirmed not listening, and no repository file was modified. The
  three results that changed the design, each with its transcript in the section that relies on it:
  1. **An interception point for `CONCURRENTLY` DDL genuinely exists** -- `ddl_command_start` fires
     for every one of these statements and an exception there prevents the catalog change outright.
     It is nonetheless **rejected**, because that hook exposes `tg_tag` and nothing else, so
     scoping it means enumerating actions database-wide -- D31's rejected shape, restored (D50).
  2. **`REINDEX ... CONCURRENTLY` preserves the index *definition* and rewrites only its OID.** The
     wedge is not caused by the statement's non-atomicity so much as by D40 recording the one index
     property a legitimate rebuild changes (D50).
  3. **PostgreSQL 17's `MAINTAIN` privilege is revocable from a table's own owner** -- which
     removes J-A's exact one-statement vector -- **and the owner can re-grant it to itself**, which
     is why D51 is a layer with a stated limit and not the fix (D51).

### Drift found while writing this addendum

Recorded rather than silently corrected, the convention §3.4, §6.1, `0007:717-720`,
`0007:1474-1490`, `0007:2141-2160`, `0007:2804-2826` and `0007:3689-3712` set.

1. **Addendum 5's `file:line` citations resolve against `8b36c91`, not against this tree.** PR #152
   moved most of them; CAP #5 §12 records the same and gives three examples. Expected, not a
   defect. Citations *into a prior addendum's own prose* (`0007:NNNN`) are unaffected and are used
   below where the claim is about the text rather than about the code.
2. **CAP #5's own citation for the mechanism J-A breaks is approximate and is made exact here.**
   §7.4 cites D40's index comparison at `provision_test_roles.sh:~641-646`. At this commit the
   `SELECT ... INTO cur_indexes` is `:648-649`, the comparison is `:650`, and the
   `its index set changed` exception is `:651`. The CAP marked it approximate with its own `~`; the
   substance is unchanged and D50 needs the exact lines.
3. **CAP #5 §5's enforcement-point table carries three offsets.** P4 cites `anyColumnPrivilege` at
   `postgres.go:441+`; it is `:579`. P5 cites `protectedObjectIdentityReason` at `:371`; it is
   `:372`. P7 cites `protectedRelationStateReason` at `:446+`; it is `:525`, with
   `requiredProtectedRelationStates` at `:495`. No finding depends on any of them.
4. **J-F's stale-count list is one item short.** CAP #5 §7.11 point 6 names
   `internal/screeningledger/postgres.go:341` and `:367` and
   `scripts/ci/provision_test_roles.sh:740`. `docs/operations/sec7-database-copies.md:70` also
   still says `expected exactly 12`, and it is the only one of the four an operator reads. D56
   covers all four.

---

### Addendum 6 context: the referent a legitimate operation rewrites

Addendum 1 diagnosed the original's structural error as fixing instances rather than causes
(`0007:1494-1497`). Addendum 2 named its findings as one class -- "a control whose installation is
asserted rather than checked, by the party the control constrains" (`0007:1499-1500`). Addendum 3
sharpened it to "a control that decides what to protect, or what to protect against, by listing
members of an open set" (`0007:2172-2173`) and produced D31. Addendum 4 sharpened it again to "the
enumeration was fixed and the referent drifted" (`0007:2853-2857`) and produced D40. Addendum 5
moved one axis over -- "the referent is correct and its population was never stated"
(`0007:3742-3746`) -- and produced D43.

CAP #5 §0.1 looked for a sixth turn of the class screw inside the security boundary and, like
CAP #4, did not find one. It states J-A's own axis as:

> **A control that asserts an invariant over catalog state assumes the statement that violates the
> invariant is atomic with the check. PostgreSQL's `CONCURRENTLY` forms are not.**

That is true, and it is the reason the failure is a *wedge* rather than a bypass. It is not,
however, the whole diagnosis, and the difference is exactly what separates the fix this addendum
adopts from the one the framing invites. Non-atomicity explains why D40 **cannot refuse** the
statement. It does not explain why D40 **wants to** refuse it. `REINDEX ... CONCURRENTLY` is not an
attack; it is the most ordinary maintenance command PostgreSQL has, and D40 objects to it only
because D40 recorded the one property of an index that a legitimate rebuild rewrites.

**The sharper form, which is what produces D50 rather than a tag filter:**

> **A control that compares recorded state to live state must choose a referent that only an
> illegitimate change can alter. Where the platform rewrites an identifier as part of an operation
> the system legitimately performs on itself, comparing that identifier makes routine maintenance
> indistinguishable from attack -- and because such rewrites are precisely the ones the platform
> performs non-atomically, the control cannot refuse the change, only be permanently unsatisfied by
> it. Ask not only "what does it compare, over what population?" but "does anything legitimate
> rewrite the thing I compare -- and if it does, can my exception undo it?"**

The two clauses are not independent, and noticing that they are not is the load-bearing move.
PostgreSQL's non-atomic DDL forms exist *because* they are maintenance operations that must not
hold long locks. The set of statements a control cannot roll back and the set of statements that
legitimately rewrite an object's identity are, in this database, close to the same set. Fixing the
referent therefore fixes most of the atomicity problem as a side effect -- and where it does not
(D50's stated residual), what is left is genuinely rare and genuinely recoverable.

**This does not reopen G-G, and the reason is precise.** D44 rejected a dump-portable referent and
recorded the tension it found (`0007:3897-3900`): "the two properties are in genuine tension -- for
a **referent**. They are not in tension at all for a **marker** ... A marker only has to be
*recognised*; a referent has to be *dereferenced* to an object." The index set is neither. It is one
of the **properties** D40 records about a protected relation -- the same list as `relowner`,
`relkind` and the RLS flags -- and Addendum 4's own principle is that a closed set of properties is
the right thing to compare (`0007:2855-2857`). A property is compared for equality and never
dereferenced, so `ALTER TRIGGER ... RENAME`-then-`DROP`, the two statements that defeated D44's
name-keyed registry, do not apply: a rename **changes** a definition set rather than escaping it.
That is not reasoned, it is measured -- under D50 `ALTER INDEX ... RENAME` moves from *succeeds* to
*blocked* (see D50's battery). **D50 is Addendum 4's principle applied to the one column Addendum 4
wrote in the older style.**

---

### D50. J-A (HIGH): the index referent becomes the index *definition* set, and the wedge is removed rather than intercepted

**The finding, restated from the code.** D40's second phase re-derives each protected relation's
index set and compares it to `sec7_protected_relation.index_oids`
(`scripts/ci/provision_test_roles.sh:648-651`):

```sql
SELECT COALESCE(array_agg(ix.indexrelid ORDER BY ix.indexrelid), ARRAY[]::oid[]) INTO cur_indexes
  FROM pg_index ix WHERE ix.indrelid = rel.objid;
IF cur_indexes IS DISTINCT FROM rel.index_oids THEN
  RAISE EXCEPTION 'ADR-0007 Addendum 4 D40: protected relation (objid %): its index set changed', rel.objid;
```

Every *atomic* DDL form that would change that set is refused at `ddl_command_end` inside the
statement's own transaction, so nothing applies -- CAP #4 §7.10 verified exactly that for plain
`CREATE INDEX` and certified on its basis that reaching R18's drift "requires the change to be made
with the triggers disabled or via `SET event_triggers = off`, both superuser-only." **That
certification is false.** `REINDEX ... CONCURRENTLY` commits its catalog swap in an earlier internal
transaction; the exception aborts only the last one. The operator sees an error and the OID has
already changed.

#### Executed: the finding, and its family enumerated

Against a `CREATE DATABASE ... TEMPLATE` clone of the fully provisioned primary, so the starting
state is byte-identical to the shipped one. "WEDGED" means an unrelated `CREATE TABLE` by the
bootstrap superuser fails afterwards.

```
recorded index_oids for public.screening_ledger_anchor: {16920}

REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey       [owl_ledger_ddl]  {16920}->{16952}        WEDGED
REINDEX TABLE CONCURRENTLY screening_ledger_anchor            [owl_ledger_ddl]  {16920}->{16957}        WEDGED
REINDEX TABLE CONCURRENTLY screening_ledger_retention_tombstone [owl_ledger_ddl]                        WEDGED
REINDEX SCHEMA CONCURRENTLY public                            [superuser]       {16920}->{17077}        WEDGED
REINDEX DATABASE CONCURRENTLY <db>                            [superuser]                               WEDGED
CREATE INDEX CONCURRENTLY ... ON screening_ledger_anchor      [superuser]       {16920}->{16920,16978}  WEDGED

REINDEX INDEX screening_ledger_anchor_pkey                    [owl_ledger_ddl]  OID-preserving          ok
REINDEX TABLE screening_ledger_anchor                         [owl_ledger_ddl]  OID-preserving          ok
VACUUM FULL screening_ledger_anchor                           [owl_ledger_ddl]  OID-preserving          ok
CLUSTER screening_ledger_anchor USING ..._pkey                [owl_ledger_ddl]  OID-preserving          ok
```

**Two forms beyond what CAP #5 recorded:** `REINDEX SCHEMA CONCURRENTLY` and
`REINDEX DATABASE CONCURRENTLY`. Both are superuser-or-owner scoped in this configuration
(`REINDEX SCHEMA` requires ownership of the schema, refused to `owl_ledger_ddl` with
`must be owner of schema public`), but both reach the same state and neither appears in any prior
record. This is why the enumeration below is stated as a closed set with its closure argued rather
than as a list of the forms someone happened to try.

**The complete PostgreSQL 17 `CONCURRENTLY` family, and why only the index forms matter here.** The
forms are `CREATE INDEX`, `DROP INDEX`, `REINDEX {INDEX,TABLE,SCHEMA,DATABASE,SYSTEM}`,
`REFRESH MATERIALIZED VIEW` and `ALTER TABLE ... DETACH PARTITION`. Executed against both protected
relations:

```
DROP INDEX CONCURRENTLY screening_ledger_anchor_pkey    -> ERROR: cannot drop index ... because constraint ... requires it
REFRESH MATERIALIZED VIEW CONCURRENTLY screening_ledger_anchor -> ERROR: "screening_ledger_anchor" is not a materialized view
ALTER TABLE screening_ledger_anchor DETACH PARTITION x CONCURRENTLY -> ERROR: table "screening_ledger_anchor" is not partitioned
sec7_protected_relation relkind for both relations      -> r
```

Both protected relations are ordinary tables whose only index is a constraint-backed primary key,
and D40 already pins `relkind` and blocks inheritance attachment, so the matview and partition forms
are unreachable by construction rather than by coincidence. **`index_oids` is therefore the only one
of D40's seven recorded columns reachable by a non-atomic statement** -- triggers, policies,
`relowner`, `relkind` and both RLS flags have no `CONCURRENTLY` form in PostgreSQL 17. This is the
answer to CAP #5 §11 point 1(b), and it bounds the scope of this decision to one column.

#### Executed: a recoverability split, which CAP #5 does not draw and which the severity turns on

```
CREATE INDEX CONCURRENTLY zzcic ON screening_ledger_anchor (anchored_at)  [superuser]
   -> ERROR: D40 ... its index set changed ;  unrelated CREATE TABLE -> ERROR (wedged)
DROP INDEX zzcic                                                          [superuser]
   -> succeeds WHILE WEDGED ;  unrelated CREATE TABLE -> ok (healthy again)

REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey                   [owl_ledger_ddl]
   -> ERROR: D40 ... its index set changed ;  live {17112} vs recorded {16920}
REINDEX INDEX screening_ledger_anchor_pkey (plain, superuser, to undo it) -> ERROR: ... its index set changed
```

**`CREATE INDEX CONCURRENTLY`'s wedge is self-healing.** The `DROP INDEX` succeeds even while every
other DDL statement is failing, because at *that* statement's `ddl_command_end` the live set matches
the recording again. No superuser trigger-disable, no re-provisioning. **`REINDEX ... CONCURRENTLY`'s
is not**, and cannot be: the recorded OID no longer exists anywhere and no DDL statement can bring
it back. J-A's severity rests on the `REINDEX` forms specifically, and so does D50.

#### Investigated and rejected: intercept the statement before its first internal commit

The brief asked whether PostgreSQL offers **any** way to intercept a `CONCURRENTLY` operation before
its first internal commit. **It does, and the answer is still no.**

`ddl_command_start` fires for all three tags, `CONCURRENTLY` forms included, and an exception raised
there prevents the catalog change completely:

```
ddl_command_start fires:  REINDEX (plain and CONCURRENTLY) | CREATE INDEX | DROP INDEX | ALTER TABLE
                          VACUUM FULL and CLUSTER: no (they are not DDL commands)

with an exception raised at ddl_command_start:
  REINDEX INDEX CONCURRENTLY prot_pkey  -> ERROR: BLOCKED-AT-START tag=REINDEX  oids UNCHANGED
  REINDEX TABLE CONCURRENTLY prot       -> ERROR: BLOCKED-AT-START tag=REINDEX  oids UNCHANGED
  CREATE INDEX CONCURRENTLY ix9 ON prot -> ERROR: BLOCKED-AT-START tag=CREATE INDEX  oids UNCHANGED
```

So an interception point exists and works. What it cannot do is tell you *what is being operated
on*. Executed inside a `ddl_command_start` function:

```
pg_event_trigger_ddl_commands()    -> ERROR: can only be called in an event trigger function
pg_event_trigger_dropped_objects() -> ERROR: can only be called in a sql_drop event trigger function
tg_tag = REINDEX     tg_event = ddl_command_start          <- tg_tag is the ONLY thing available
```

A guard at this hook can therefore only be scoped **by command tag**, which is D31's explicitly
rejected shape (`0007:2192-2199`: "scope a control by the thing it protects ... never by the actions
you expect"), restored in the one place D31's own reasoning would forbid it. Concretely it would
refuse `REINDEX` and `CREATE INDEX` **on every relation in the database** -- forty-plus unprotected
tables, including SEC-1's tenant-scoped relations -- to protect two. And the tag list would be an
enumeration of an open set again: a future `CONCURRENTLY` form outside it reaches the same wedge,
which is precisely the complement problem that defeated D26 twice.

Two secondary variants were considered and are recorded so they are not re-derived. Parsing
`current_query()` inside `ddl_command_start` to recover the object name is text-matching against a
statement an adversary writes, and would be wrong before it was slow. Having
`ddl_command_start` record pre-statement state for `ddl_command_end` to consult buys nothing: the
change has still committed and the exception still cannot undo it.

**Recorded plainly because the brief allowed for the opposite answer: prevention at this hook is
available and is the wrong mechanism, not an unavailable one.**

#### Executed: what a legitimate rebuild actually rewrites

```
REINDEX INDEX CONCURRENTLY prot_pkey
  old_oid 17134  ->  new_oid 17160        oid_same             = f
                                          name_same            = t
                                          pg_get_indexdef_same = t
                                          indisunique/indisprimary_same = t
                                          indkey_same          = t
                                          constraint_oid_same  = t
                                          indisvalid           = t
```

**The OID is the one thing it changes.** Everything about the index that describes what the index
*does* is invariant, which is what one would expect of an operation whose entire purpose is to
rebuild an index without changing it.

#### Decision: `index_oids` is replaced by `index_defs`, the sorted set of index definitions

`sec7_protected_relation.index_oids` becomes `index_defs text[]`, populated at provisioning as the
sorted array of `pg_get_indexdef(indexrelid)` over the relation's indexes, and compared by D40's
second phase with the same `IS DISTINCT FROM` it uses today. Replaced, not supplemented: two
recordings of one property is a second thing to keep in sync, and D39 already settled that question
in the same direction when `has_column_privilege` subsumed `has_table_privilege`.

Illustrative only -- the implementation PR owns the real shape:

```sql
SELECT COALESCE(array_agg(pg_get_indexdef(ix.indexrelid) ORDER BY pg_get_indexdef(ix.indexrelid)),
                ARRAY[]::text[]) INTO cur_index_defs
  FROM pg_index ix WHERE ix.indrelid = rel.objid;
IF cur_index_defs IS DISTINCT FROM rel.index_defs THEN
  RAISE EXCEPTION '... protected relation "%" (objid %): its index set changed', rel.identity, rel.objid;
```

**What the OID column catches that the definition column does not**, stated first because it is the
only thing given up: an index object replaced by a byte-identical one. That is a rebuild, and a
rebuilt index enforces exactly what the old one enforced -- the server builds it from the table's
own rows. There is no attack in the shape "the same index, again."

**What the definition column catches that the OID column does not**, which is not nothing:
`ALTER INDEX ... RENAME` (the name is in the definition) and `ALTER INDEX ... SET (fillfactor=...)`
(`pg_get_indexdef` renders storage parameters -- executed:
`CREATE INDEX ix_v ON public.prot USING btree (v)` becomes
`... USING btree (v) WITH (fillfactor='40')`). Both report the *index's* OID at `ddl_command_end`,
so D34's membership phase never matches them and D40's OID set is unchanged by either. **D50 is
therefore a strict tightening as well as a repair**, and the rename case is measured below rather
than argued.

#### Executed, in full: the same battery against the shipped code and against the prototype

A prototype was built by adding `index_defs` to `sec7_protected_relation`, populating it, and
swapping the one comparison -- everything else in `sec7_protect_ddl_objects()` unchanged -- against
the real provisioned schema, and each attempt run from a pristine `TEMPLATE` clone. "WEDGED" again
means an unrelated `CREATE TABLE` fails afterwards.

| Attempt | role | shipped (OID) | prototype (definition) |
|---|---|---|---|
| `REINDEX INDEX CONCURRENTLY ..._pkey` | `owl_ledger_ddl` | **WEDGED** | **succeeds, healthy** |
| `REINDEX TABLE CONCURRENTLY screening_ledger_anchor` | `owl_ledger_ddl` | **WEDGED** | **succeeds, healthy** |
| `REINDEX TABLE CONCURRENTLY ..._retention_tombstone` | `owl_ledger_ddl` | **WEDGED** | **succeeds, healthy** |
| `REINDEX SCHEMA CONCURRENTLY public` | superuser | **WEDGED** | **succeeds, healthy** |
| `REINDEX DATABASE CONCURRENTLY` | superuser | **WEDGED** | **succeeds, healthy** |
| `CREATE INDEX CONCURRENTLY ... ON screening_ledger_anchor` | superuser | WEDGED | WEDGED -- see the residual below |
| `CREATE INDEX CONCURRENTLY ... ON screening_ledger_anchor` | `owl_ledger_ddl` | permission denied for schema public | permission denied for schema public |
| `REINDEX INDEX` / `REINDEX TABLE` / `VACUUM FULL` / `CLUSTER` | `owl_ledger_ddl` | ok | ok |
| `DROP TRIGGER screening_ledger_anchor_immutable` | `owl_ledger_ddl` | blocked | **blocked** |
| `ALTER TABLE ... DISABLE TRIGGER ALL` | `owl_ledger_ddl` | blocked | **blocked** |
| `ALTER TRIGGER ... RENAME TO` | `owl_ledger_ddl` | blocked | **blocked** |
| `DROP OWNED BY owl_ledger_ddl` | `owl_ledger_ddl` | blocked | **blocked** |
| `CREATE RULE ... DO INSTEAD NOTHING` | `owl_ledger_ddl` | blocked | **blocked** |
| `CREATE TABLE ... INHERITS (...)`, and the `TEMP` variant | `owl_ledger_ddl` | blocked | **blocked** |
| `CREATE TRIGGER ... ON screening_ledger_anchor` | `owl_ledger_ddl` | blocked | **blocked** |
| `CREATE UNIQUE INDEX ... ((1))` | superuser | blocked | **blocked** |
| `CREATE POLICY ... ON screening_ledger_anchor` | superuser | blocked | **blocked** |
| `ALTER TABLE ... OWNER TO owl_migrator` | superuser | blocked | **blocked** |
| `DROP TABLE screening_ledger_anchor CASCADE` | superuser | blocked | **blocked** |
| `CREATE OR REPLACE FUNCTION screening_ledger_reject_mutation()` | `owl_migrator` | blocked | **blocked** |
| **`ALTER INDEX screening_ledger_anchor_pkey RENAME TO ...`** | superuser | **succeeds** | **BLOCKED** |
| unrelated `CREATE TABLE` / `DROP TABLE` | `owl_migrator` | ok | **ok** |
| unrelated `CREATE OR REPLACE FUNCTION` | `owl_migrator` | ok | **ok** |
| `CREATE VIEW` over a protected table | superuser | ok | **ok** |
| `CREATE INDEX` / `DROP INDEX` on `screening_ledger_event` | superuser | ok | **ok** |
| **`REINDEX TABLE CONCURRENTLY screening_ledger_event`** (unprotected) | superuser | ok | **ok** |
| **`CREATE INDEX CONCURRENTLY` on `screening_ledger_event`** (unprotected) | superuser | ok | **ok** |

Every prior CAP's attack form still blocked, one strictly stronger, every collateral-damage case
still passing -- including the two `CONCURRENTLY` forms on an unprotected relation, which the
rejected `ddl_command_start` design would have broken. D37's rule applies verbatim
(`0007:2643-2645`): a suite that proves only the blocks has not proven D50 is safe to install, and
the last six rows are why this table has them.

**Copy detection is unregressed, and that was checked rather than assumed.** Index definitions
*are* dump-portable, so one might expect D50 to weaken I-A's detection. It does not: D40's relation
loop is keyed by `rel.objid`, whose `NOT EXISTS` branch fires before any index comparison is
reached. A real `pg_dump | psql` restore of the prototype database still produces D46 message (a):

```
ERROR: ADR-0007 Addendum 5 D46: protected relation "public.screening_ledger_retention_tombstone"
       (registry objid 16435) no longer exists; ... is present with objid 18158. This database is a
       copy or restore of another (registry recorded instance 7678485004407329689/16384 owl_ci; ...
```

**Steady-state cost is unchanged**, measured because D40 and D46 both stated theirs
(`0007:3336`, `0007:4058`): 200 DDL statements took 103 ms against the shipped build and 108 ms
against the prototype -- 0.513 vs 0.540 ms per statement, both dominated by the client round trip.

#### The residual D50 does not close, named rather than left to a sixth CAP

- **`CREATE INDEX CONCURRENTLY` on a protected relation still wedges.** It genuinely adds a
  definition, and refusing it is correct -- `CREATE UNIQUE INDEX ... ((1))` is one of D40's own
  attack forms. Non-atomicity means the refusal arrives after the index exists. It is
  **self-healing** by `DROP INDEX` with no superuser trigger-disable (transcript above), and it is
  **unreachable to `owl_ledger_ddl`**, which holds `CREATE` on no schema -- a fact D41 part three
  already asserts (`0007:3437-3448`), so it is a checked precondition rather than a coincidence.
- **A cancelled `REINDEX ... CONCURRENTLY` also wedges, and this route appears in no CAP.**
  Executed by cancelling a rebuild mid-flight:

  ```
  cancelled REINDEX INDEX CONCURRENTLY ix_v  ->  ix_v (valid=t)   ix_v_ccnew (valid=f)   prot_pkey (valid=t)
  ```

  The cancelled statement errors before `ddl_command_end`, so the wedge does not appear on the
  cancelling session's statement -- it appears **later**, on an unrelated DDL statement by someone
  else. Self-healing by `DROP INDEX <...>_ccnew`, and after D51 unreachable to `owl_ledger_ddl` for
  the same reason the completed form is. R24 records both.

**Two further alternatives rejected, so they are not re-derived.** Recording *both* the OID set and
the definition set and comparing only the latter keeps a second declaration nothing checks -- H-E's
exact shape -- and is adopted only as D58's withdrawal fallback, where it is worse and is labelled
worse. Having D40 *re-record* the live state when it detects index drift would let a genuine attack
launder itself into the recording, which is the one thing a recorded-state control must never do.

**The coordinated-edit surface does not grow.** `requiredProtectedRelationStates`
(`internal/screeningledger/postgres.go:495-516`) already declares `indexNames` per relation and
reconciles the recorded column against the OIDs of those declared names
(`postgres.go:537-547`); after D50 it reconciles against `pg_get_indexdef` of the same declared
names. One literal, one query, same count. R23's aggravating property is unchanged and is not made
worse here.

---

### D51. J-A defence in depth: the capability is removed at its source, and its restoration is asserted

D50 makes the completed rebuild harmless. It does not stop `owl_ledger_ddl` from reaching the two
residual routes above, and it does not answer the brief's third question -- whether these roles can
be denied `CONCURRENTLY`-class operations by a privilege PostgreSQL actually offers. **They can, and
the answer has a limit that must be stated with it.**

**Executed.** PostgreSQL 17 gates `REINDEX` (with `VACUUM`, `ANALYZE`, `CLUSTER`,
`REFRESH MATERIALIZED VIEW` and `LOCK TABLE`) on the per-table `MAINTAIN` privilege, which an owner
holds implicitly -- and which, unlike ownership itself, is **revocable**:

```
REVOKE MAINTAIN ON TABLE screening_ledger_anchor, screening_ledger_retention_tombstone FROM owl_ledger_ddl;

  has_table_privilege('owl_ledger_ddl','screening_ledger_anchor','MAINTAIN')  -> f

  REINDEX INDEX CONCURRENTLY ..._pkey    [owl_ledger_ddl] -> ERROR: permission denied for index ...   (NO wedge)
  REINDEX TABLE CONCURRENTLY <table>     [owl_ledger_ddl] -> ERROR: permission denied for table ...
  REINDEX INDEX / REINDEX TABLE (plain)  [owl_ledger_ddl] -> ERROR: permission denied
  VACUUM FULL / ANALYZE                  [owl_ledger_ddl] -> WARNING: permission denied to vacuum/analyze, skipping
  CLUSTER                                [owl_ledger_ddl] -> ERROR: permission denied for table

  ALTER TABLE ... ADD COLUMN             [owl_ledger_ddl] -> ERROR: ADR-0007 Addendum 3 D34: ... is protected
```

The last line is the check that the revoke did not over-reach: `owl_ledger_ddl` keeps every ordinary
DDL right it had, so `ALTER TABLE` is still refused **by D34** rather than by privilege. Nothing
D26/D34/D40 relies on changes.

**Decision, two parts.**

1. **`grant-ddl-ownership` revokes `MAINTAIN` on both protected tables from `owl_ledger_ddl`**, in
   the same superuser-only provisioning step that already transfers their ownership. Nothing in this
   repository runs `VACUUM`, `ANALYZE`, `CLUSTER`, `REINDEX` or `LOCK TABLE` as `owl_ledger_ddl` --
   confirmed by grep across `internal/`, `cmd/`, `scripts/` and `.github/` -- and autovacuum is a
   background worker that is unaffected by table-level grants, so nothing legitimate is lost. Manual
   maintenance on these two relations becomes a bootstrap-superuser action, which is what R12/R17
   already say about every other privileged operation on them.
2. **`requiredProvisioningState` asserts it.**
   `has_table_privilege('owl_ledger_ddl', <each protected table>, 'MAINTAIN') = false` joins D33's
   existing negative facts, beside the `anyColumnPrivilege` probes at
   `internal/screeningledger/postgres.go:248-267`. `MAINTAIN` has no column form, so D39's
   column-granularity correction does not apply and the table-level probe is the right question
   here -- stated explicitly so a later reader does not "fix" it into `has_column_privilege` and get
   an error.

**The limit, stated with the same specificity as the benefit.** Executed:

```
GRANT MAINTAIN ON TABLE screening_ledger_anchor TO owl_ledger_ddl;   [as owl_ledger_ddl]  -> SUCCEEDS
```

An owner can re-grant to itself, and `GRANT` reports `objid=NULL`, so D34 never sees it -- the
residual Addendum 3 recorded (`provision_test_roles.sh:671-673`) and CAP #4 and CAP #5 both
re-confirmed. **D51 is therefore an accident boundary, not a security boundary.** It closes J-A's
stated trigger completely -- CAP #5's own framing is "the most routine maintenance command
PostgreSQL has," and after D51 an operator who types it gets a clean permission error instead of a
bricked database -- and it makes a deliberate restoration a **named provisioning-state failure** on
the next `verify` rather than a silent capability. That is D35's principle
(`0007:2541`: "do not close the hole, remove the thing that opens it") with D39's observability
attached, and it is exactly as much as it is. R25 states it as a risk rather than letting the
decision imply more.

**Neither decision may be removed on the strength of the other**, and this addendum says so in both
places, the arrangement D41 part three set for D40 (`0007:3447-3448`). D50 without D51 leaves
`owl_ledger_ddl` holding a maintenance capability whose every use is now a harmless no-op nobody has
explained. D51 without D50 leaves the superuser and the cancelled-rebuild routes wedging, and leaves
the wedge one self-re-grant away for the owner. D58 makes them one stage.

---

### D52. J-A's residual: the drifted, non-copied database gets a diagnostic and a tested recovery

D46's three named messages are reachable **only** from D40's `NOT EXISTS` branch
(`provision_test_roles.sh:594-624`). Every other branch -- owner, relkind, RLS flags, rules,
inheritance, triggers, indexes, policies -- still raises the bare-integer form CAP #5 quotes:
`protected relation (objid 16914): its index set changed`. And
`docs/operations/sec7-database-copies.md:1` states its own scope as copies and restores, so an
operator meeting index drift on the **live** database has neither a message that names the relation
nor a document that covers the state.

**Decision, two parts.**

1. **Every D40 branch names the relation, not only the OID.** `rel.identity` is already in the row
   (D46) and already reconciled against an independent literal (D47), so this costs one substitution
   per `RAISE` and no new read. The messages also say what kind of failure this is -- the recording
   is stale, the relation is present -- so it is distinguishable at a glance from D46's copy and
   drop-and-recreate cases. D46's structural safety property is preserved unchanged: `identity` is
   still read only on an already-failing path, so a wrong or absent value can still only change an
   error message and never widen what passes (`0007:4052-4061`).
2. **`docs/operations/sec7-database-copies.md` gains a section for a drifted, non-copied database**
   -- what "its index set changed" means, that `REINDEX ... CONCURRENTLY` is its most likely cause
   before D50/D51 land and a superuser action after, and the recovery.

**The recovery is tested, not described**, to the standard D48 set for "Recovering a bricked
restore" and which the brief requires. Executed verbatim from the document, on a genuinely
`REINDEX`-wedged database built from the real provisioned schema:

```
REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey  [owl_ledger_ddl]
   -> ERROR: ADR-0007 Addendum 4 D40: protected relation (objid 16914): its index set changed
   unrelated CREATE TABLE [superuser] -> ERROR: ... its index set changed        (wedged)

step 1  ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE;   -> ALTER EVENT TRIGGER
                                                                            (succeeds while wedged)
step 2  PGDATABASE=<db> ./scripts/ci/provision_test_roles.sh grant-ddl-ownership
        -> PASS: D34 object-scoped ... installed and ENABLE ALWAYS ...      exit 0
step 3  SELECT evtname, evtenabled FROM pg_event_trigger;
        -> sec7_protect_ddl_objects_on_drop = A ;  sec7_protect_ddl_objects_on_alter = A
        CREATE TABLE ... ; DROP TABLE ... [owl_migrator]  -> ok
```

The document's existing procedure is therefore correct for this state as well as for a restore; what
is missing is only that nothing tells an operator it applies. Note that the recovery needs the
bootstrap superuser and the party who caused the outage is not one -- that is the honest cost, and
after D50 and D51 the state is not reachable by that party at all.

**D47 is credited for what it already does.** CAP #5 §7.6 observes that
`protectedRelationStateReason` (`internal/screeningledger/postgres.go:525-571`) is the only
mechanism in the system that renders this state in words --
`sec7_protected_relation's recorded index_oids for public.screening_ledger_anchor do not match its
declared primary-key index` -- while D40's runtime message is an integer. That was an unplanned
benefit of a decision written for a LOW finding and it should be recorded as such. After D50, D47
correctly reports a rebuilt index as provisioned, because the recorded definition still matches.

---

### D53. J-B (MEDIUM): the copy fixtures stop consuming themselves

**The finding, restated from the code.** `TestVerifyAnchoredRefusesSchemaOnlyClone`
(`internal/screeningledger/d43_copy_population_pgx_test.go:113`) proves CAP #4 §7.6 variant 2 by
having `owl_ledger_ddl` execute
`DROP TRIGGER screening_ledger_anchor_immutable ON screening_ledger_anchor` against
`owl_ci_sec7_cloned` and asserting it succeeds (`:145-147`). It never restores the trigger, and
`owl_ci_sec7_cloned` is a **persistent CI fixture** built once per provisioning cycle by
`provision_test_roles.sh create-restored-database`, not a per-test database. CAP #5 §7.10
demonstrated the consequence three ways; the one that matters is:

```
./scripts/ci/run-ci.sh          -> exit 0   "PASS: OpenWatchlist clean-restart CI"
go test -race -count=1 ./...    -> exit 1   --- FAIL: TestVerifyAnchoredRefusesSchemaOnlyClone
```

**CLAUDE.md's Definition of done lists both commands**, and after Addendum 5 they cannot both pass
in one provisioning cycle. It also fails in the alarming direction: the message reads
`expected the table owner's DROP TRIGGER to succeed`, so a reader is told a control the finding says
is absent appears to be present, and the plausible wrong conclusion is that a control changed.

**Decision: the test restores what it mutates, and the property is asserted rather than assumed.**

The pattern already exists in the same addendum:
`TestCheckProvisioningStateDetectsRewrittenRecordedState`
(`internal/screeningledger/d47_recorded_state_pgx_test.go:22`) is table-driven over seven mutations
and carries an explicit `restore:` statement for every one (`:86-122`). D53 is that pattern applied
to the one place Addendum 5 did not apply it.

- The trigger is recreated after the assertion, from the same definition `SchemaSQL` and
  `db/migrations/017_screening_ledger_anchor_policy_binding.sql` declare, in a `t.Cleanup` so it
  runs on a failing assertion too -- a test that leaves the fixture broken *because it failed* is
  the same defect with a worse trigger condition.
- The test asserts the trigger is back before returning. Restoring without checking is the shape of
  every finding in this document.
- **The property, stated so it is testable rather than aspirational:** `run-ci.sh` followed by an
  independent `go test -race -count=1 ./...` must both pass against one provisioned state, and two
  successive `go test -count=1` runs of the copy suite must both pass. D58 makes both a requirement.

Rated and fixed rather than waived even though GitHub CI is unaffected (one `run-ci.sh` invocation
at `.github/workflows/ci.yml:237`, none in `release-qualification.yml`, each preceded by its own
fixture build). The verification suite is the instrument by which SEC-7's closure will be judged and
§8's closing condition is stated in terms of a CI run; an instrument that is single-shot per
provisioning, and that reports its exhaustion as a control regression, is not one to leave in place.

---

### D54. J-C and J-D (LOW, LOW): D46's diagnostic is ordered by evidence, and reads its evidence safely

**One decision, because they are one branch and splitting them would produce two patches to the same
eight lines.**

**The finding, restated from the code.** D46 resolves the recorded name first and consults the
instance binding only if that resolution succeeds
(`scripts/ci/provision_test_roles.sh:605-624`):

```
SELECT c.oid INTO live_oid FROM pg_class c JOIN pg_namespace n ... WHERE n.nspname||'.'||c.relname = rel.identity;   -- :605-607
IF live_oid IS NULL THEN RAISE ... 'and no relation of that name is present';                                        -- :609-611
SELECT b.system_identifier, b.database_oid, b.database_name INTO rec_sysid, rec_dboid, rec_dbname
  FROM sec7_instance_binding b LIMIT 1;                                                                              -- :614-615
IF rec_sysid IS DISTINCT FROM live_sysid OR rec_dboid IS DISTINCT FROM live_dboid THEN ... 'is a copy or restore'
```

Three consequences, all demonstrated by CAP #5 §7.5 and each re-derived from the code here:

- **A copy whose recorded relation is absent by name reports (c)**, whose documented remedy
  (`docs/operations/sec7-database-copies.md:66-68`, *"Do not re-provision over this; find out what
  removed it first"*) is the **opposite** of the correct action, and whose text contains nothing
  telling the operator they are on a copy -- although the binding row is present and mismatched.
  CAP #5 built the state with `pg_dump --exclude-table`, a supported flag and no adversary.
- **The loop has no `ORDER BY`** (`:593`), so on a database in which one recorded relation resolves
  and another does not, which of two contradictory messages the operator sees is decided by heap
  order.
- **Zero binding rows are read as positive evidence of a copy.** `SELECT ... INTO` leaves the
  variables NULL, `NULL IS DISTINCT FROM <value>` is true, and message (a) fires naming
  `<NULL>/<NULL> <NULL>`. And if the binding **table** is absent while the registries dangle, the
  unqualified `FROM sec7_instance_binding` raises `relation "sec7_instance_binding" does not exist`
  from inside the event-trigger function -- R17's accepted risk realised by the very kind of
  reference D46 rejected `to_regclass` in order to avoid (`0007:4016-4021`).

**Decision, three parts.**

**(a) Order by evidence.** The instance comparison runs **before** the name-resolution branch. A
database whose binding mismatches is a copy whether or not the recorded relation is present under
its name, so that fact is established first and the name resolution then refines the message rather
than pre-empting it. This is the general form of what went wrong: the branch that ran first was the
one that was cheapest to compute, not the one that carries the evidence.

**(b) Determinism.** `FOR rel IN SELECT * FROM sec7_protected_relation` gains an `ORDER BY` -- on
`identity`, since it is `NOT NULL` and D47 reconciles it -- so two runs against one database state
produce one message.

**(c) Absent or unreadable evidence gets a fourth message, and the read cannot raise.** Where
today's code asserts "copy" from missing evidence, the classification becomes explicit: *the
instance binding is absent or empty, so whether this database is a copy cannot be determined.*
Message (a) requires a binding row that is present **and** mismatched. The read is guarded by
`to_regclass('sec7_instance_binding')`, and the branch is skipped when it is NULL.

**J-D's question answered directly, with the transcript, because the brief asks for the original
concern to be stated and either resolved or upheld.** D46's stated concern is real and reproduces:

```
to_regclass('a.b.c.d')                 -> ERROR: improper relation name (too many dotted names): a.b.c.d
```

But that concern is about the **provenance of the argument**, not about the function. D46 was
resolving `rel.identity` -- a column, i.e. data, which drift or a superuser can make malformed, and
avoiding `to_regclass` there was correct and stays correct: **part (c) does not reintroduce it for
`rel.identity`.** The binding-table guard passes a **literal** written in the function's own source,
which cannot be malformed. Executed:

```
to_regclass('sec7_instance_binding')    (absent, well-formed constant)  -> NULL, no raise
to_regclass('public.prot')              (present)                        -> 17118
an untaken plpgsql IF branch referencing an absent table                 -> never planned, no exception
BEGIN ... EXCEPTION WHEN undefined_table                                 -> also catches it cleanly
```

The third line is what makes the guard sufficient rather than decorative: plpgsql plans a statement
on first execution of that statement, so a guarded branch that is not taken never attempts to
resolve the table. The `EXCEPTION WHEN undefined_table` alternative works too and is **rejected**
for a specific reason rather than on taste: it opens a subtransaction on a path that runs on every
DDL statement in the database, which is R17's accepted risk paid on the passing path as well as the
failing one. **The concern D46 recorded is upheld for data and resolved for constants**, and stating
the distinction is what stops the next reader concluding either that `to_regclass` is banned here or
that it was safe all along.

---

### D55. J-E (LOW): one referent, one spelling

`sec7_protected_relation.identity` is written from
`(pg_identify_object('pg_class'::regclass, c.oid, 0)).identity`
(`scripts/ci/provision_test_roles.sh:493`), which **quotes** an identifier when SQL requires it.
D46's resolver compares against `n.nspname || '.' || c.relname` (`:607`), which **never** quotes.
Executed:

```
oid    pg_identify_object     D46 join key         agree
23065  "a.b".c                a.b.c                f
23072  a."b.c"                a.b.c                f
23068  public."Weird Name"    public.Weird Name    f

SELECT count(*) ... WHERE nspname||'.'||relname = 'a.b.c'   ->  2       (and SELECT ... INTO takes one, silently)
```

Two consequences: for any protected relation whose schema or table name requires quoting `live_oid`
is always NULL, so **every** D46 case degrades to message (c) -- J-C by another route -- and the
join key is ambiguous, so `SELECT ... INTO live_oid` can bind the wrong relation without raising.

**Decision: the resolver asks the question in `pg_identify_object`'s own spelling.** The comparison
becomes `(pg_identify_object('pg_class'::regclass, c.oid, 0)).identity = rel.identity` over
`pg_class`, so the value being matched and the value that was recorded are produced by one function
and cannot disagree by construction. Composing the key with `quote_ident` on both halves would also
work and is **not** chosen: it re-implements a rendering the server already exposes, which is the
"two spellings of one referent" shape one layer down.

**Reachability in the shipped configuration: none.** Both protected relations are unquoted lowercase
in `public` and the two spellings agree today. It is fixed anyway on the H-E standard: a claim the
code makes about its referent that is true of today's population and not of the referent as written
is the thing this document has spent five addenda learning to stop shipping.

**D47 is not affected and must not be "fixed" alongside it** -- `protectedRelationStateReason`
compares `pg_identify_object`'s spelling on both sides already
(`internal/screeningledger/postgres.go:525-571`), so it is internally consistent. It is D46's
resolver alone that diverges from the value D46 itself recorded.

**One observation recorded as a deliberate non-change.** The resolver is unfiltered by `relkind`, so
a view or sequence occupying the recorded name satisfies "is present" and yields message (a) or (b).
For a diagnostic that reports **presence** rather than identity that is correct, and adding a
`relkind` filter would make an already-failing path fail with less information. Recorded so it is
read as a decision.

---

### D56. J-F (LOW): the stale counts, the circular recovery line, and the operator document's missing preconditions

Documentation and message text only; every procedure works today when followed with ordinary
operator judgement, which is why this is LOW and why it is nonetheless not dropped.

1. **Four stale "twelve"s, one more than CAP #5 names.** `internal/screeningledger/postgres.go:341`
   ("grant-ddl-ownership's twelve-row `sec7_protected_object` population") and `:367` ("exactly
   `requiredProtectedObjects`'s twelve (classid, identity) pairs"), and
   `scripts/ci/provision_test_roles.sh:740` ("12 in `sec7_protected_object` at this commit") --
   all three correct in code, since the Go check uses `len(requiredProtectedObjects)`
   (`postgres.go:384-385`) and the script's own restore assertion is symbolic. And
   **`docs/operations/sec7-database-copies.md:70`**, which quotes the message
   `sec7_protected_object has 0 row(s), expected exactly 12` -- the only one of the four an operator
   reads, and the one that will not match what their database prints. All four become thirteen. The
   `:740` comment's own parenthetical explains it was written symbolically *"precisely because D45
   already changed this number once"* and then states the old number; the fix is to drop the number,
   not to update it.
2. **D46's `Recovery:` line is circular on the state it most often appears in.** It names
   `scripts/ci/provision_test_roles.sh grant-ddl-ownership`, which on a bricked database fails with
   the same message (CAP #5 §7.11 point 4 reproduced it) unless
   `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE` runs first. The prerequisite goes
   into the message. The pointer to the document stays -- an operator who follows it succeeds
   today -- but a message that names a command should name the command that works.
3. **The operator document's snippets gain connection parameters.** `psql -c "ALTER EVENT TRIGGER
   ... DISABLE;"` (`:79`) and `psql -c "SELECT evtname, evtenabled ..."` (`:86`) fail on literal
   copy-paste for an operator whose shell carries no `PG*` environment, while the same document's
   "Before you clone" section sets `PGDATABASE=` on its script line (`:39`) -- so the two halves
   disagree about how much environment the reader is assumed to have. And step 2's
   `PGDATABASE=<the restored db> ./scripts/ci/provision_test_roles.sh grant-ddl-ownership` (`:83`)
   reads four more variables the document never names -- `PGHOST`, `PGPORT`, `PGSUPERUSER`,
   `PGSUPERPASSWORD`, defaulting to `localhost`, `5432`, `owl_ci`, `owl_ci`
   (`scripts/ci/provision_test_roles.sh:33-37`). A DR restore on any other host or port silently
   targets the wrong server, or the operator's own.
4. **The cross-cluster precondition is stated.** Both procedures require the four `owl_*` roles to
   already exist in the target cluster: `grant-ddl-ownership` performs
   `ALTER TABLE ... OWNER TO owl_ledger_ddl` and D47 casts `$2::regrole`. A restore into a
   **different** cluster -- the ordinary DR shape, and the shape the document's own title invites --
   has no roles until `create-roles` has been run there. The document mentions neither the
   requirement nor the subcommand.
5. **A missing guard trigger reports a raw constraint violation.** On a clone whose
   `screening_ledger_anchor_immutable` has been dropped -- which is exactly the state that document
   section is written for, and exactly what J-B leaves behind -- `grant-ddl-ownership`'s registry
   `INSERT` fails with
   `null value in column "objid" of relation "sec7_protected_object" violates not-null constraint`.
   Fail-closed and correct, and it names neither the missing trigger nor the remedy. A named
   precondition check before the `INSERT` replaces it.

---

### D57. The unpinned PGDG apt key and repository

`.github/workflows/ci.yml:223-227` and `.github/workflows/release-qualification.yml:185-189` add,
identically, an unpinned signing key and an unscoped repository:

```sh
sudo curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=...] https://apt.postgresql.org/pub/repos/apt $(...)-pgdg main" | sudo tee /etc/apt/sources.list.d/pgdg.list
sudo apt-get update
sudo apt-get install -y postgresql-client-17
```

CAP #5 §7.7 named this and accepted it as low risk with its containment stated, and this addendum
does not reopen that rating: the step runs only on the CI runner, installs only a client binary, and
its artifacts are two throwaway databases no release artifact derives from -- `scripts/deployment/`
and the release-qualification determinism checks do not consume it. It is nonetheless a **named
deviation from this repository's otherwise-consistent pinning discipline**, in workflows where every
other dependency is pinned by digest (`actions/checkout@3d3c42e...`, `actions/setup-go@b7ad1da...`,
`rustup toolchain install 1.97.1`), and the brief asked for it to be fixed if cheap.

**Decision: scope the repository, and pin the key by fingerprint -- with the fingerprint captured at
implementation time, not asserted here.**

- **An APT preferences pin restricting the PGDG origin to `postgresql-client-*`.** This closes
  CAP #5 §7.7 property 2 -- that `apt-get update` makes PGDG a candidate source for **every** package
  on the runner, not only the one the step wants -- and it is the half of this that is unambiguously
  cheap and needs no external fact.
- **A fingerprint assertion on the fetched key**, checked with `gpg --show-keys` immediately after
  the `curl` and before the repository is added, so a substituted key fails the step rather than
  becoming its trust root. `--fail` guards against a 404 body being written as a key and does
  nothing about content.
- **`postgresql-client-17` stays unpinned by minor version.** CAP #5 §7.7 property 3 notes this makes
  the fixture tool non-reproducible; it is also what keeps the client matched to the floating
  `postgres:17` service container the step exists to match. Recorded as a decision, not an omission.

**The fingerprint constant is not written in this document, and that is deliberate.** This arc does
not assert values it has not executed, and the fingerprint cannot be established from the tree -- it
requires fetching the key. The implementation PR captures it from the fetched key, records the
capture in its description, and a reviewer cross-checks its last eight hex digits against the
`ACCC4CF8` the key URL's own filename already carries. **If that capture cannot be made
reproducibly at implementation time, D57's second bullet is dropped and the APT scope pin ships
alone**, with the residual re-stated in the PR rather than quietly widened. This condition is
pre-declared here for the same reason D26's was: so the disposition is not decided after the fact by
whichever result arrived.

---

### D58. Test ownership and pre-declared withdrawal conditions

The specific shape the implementation must satisfy, so nothing weaker can be claimed to discharge
this addendum -- the standard D20 (`0007:1293-1338`), D26 (`0007:1874-1885`), D37
(`0007:2623-2662`), D42 (`0007:3455-3523`) and D49 (`0007:4237-4307`) set.

**Every test below must fail before its change, per CLAUDE.md rule 5.** Where a CAP #5 transcript
exists, the test reproduces that transcript, not a paraphrase. Several assertions are stated as
"must pass today and fail after" -- deliberately, per D42's note (`0007:3461-3465`): for these
findings the current behaviour is *acceptance*, so a test asserting only the post-fix refusal cannot
distinguish a working fix from a test that never exercised the path.

1. **D50.** `TestD50IndexReferentSurvivesConcurrentRebuild` (pgx): all five `REINDEX ...
   CONCURRENTLY` forms -- `INDEX`, `TABLE` on both protected relations, `SCHEMA`, `DATABASE` --
   each asserting that the database is **wedged today** (an unrelated `CREATE TABLE` fails after the
   statement) and healthy after, with the SQLSTATE captured rather than inferred. **Plus every
   D26/D34/D40 form unchanged**, including all four CAP #2 escapes, all three inheritance forms with
   the `TEMP` variant, `CREATE RULE`, `CREATE TRIGGER`, `CREATE UNIQUE INDEX ... ((1))` and
   `CREATE POLICY`. **Plus `ALTER INDEX ... RENAME` asserted as succeeding today and blocked
   after** -- the one row that proves D50 is a tightening and not only a relaxation. **Plus the
   collateral-damage set**, which for this decision must include `REINDEX TABLE CONCURRENTLY` and
   `CREATE INDEX CONCURRENTLY` on an **unprotected** relation, `CREATE VIEW` over a protected one,
   and unrelated `CREATE TABLE`/`DROP TABLE`/`CREATE OR REPLACE FUNCTION`. D37's rule verbatim: a
   suite that proves only the blocks has not proven D50 is safe to install.
2. **D50's residual.** `TestCreateIndexConcurrentlyWedgeIsSelfHealing` (pgx): assert the wedge after
   a superuser `CREATE INDEX CONCURRENTLY` on a protected relation, then assert `DROP INDEX` clears
   it **with no event-trigger disable and no re-provisioning**. This is the property that keeps R24
   an accepted residual rather than a second J-A.
3. **D51.** `TestProvisioningStateDetectsMaintainRegrant` (pgx): assert `CheckProvisioningState`
   returns `Provisioned=true` **today** with `MAINTAIN` held; assert the revoke makes
   `REINDEX ... CONCURRENTLY` as `owl_ledger_ddl` fail with `42501` and leave the database healthy;
   assert a self-re-grant by `owl_ledger_ddl` succeeds and produces a **specifically named**
   provisioning failure. All three halves are required -- a test that proves only the revoke has
   proven D51 is a prevention, which R25 says it is not.
4. **D52.** The recovery is a committed test, not only a document:
   `TestD52WedgedDatabaseRecoversByDocumentedProcedure` (pgx) executes the three steps above against
   a database it wedges itself and asserts DDL works afterwards and both event triggers are back to
   `evtenabled='A'`.
   **CAP #5 §11 point 1(c) asks whether the wedged state should become a permanent CI fixture, as
   `owl_ci_sec7_restored` now is. Decided here rather than defaulted: no.** A database in which
   every DDL statement fails is a poor shared fixture -- every later test that touches it inherits
   the failure, and its diagnosis is the failure under test -- and J-B is the standing demonstration
   of what a shared fixture with destructive state costs. The wedge is built and torn down inside
   tests 1, 2 and 4, each of which needs a pristine starting state anyway and each of which builds
   it from a `TEMPLATE` clone. Recorded as a decision so a later reader does not add the fixture on
   the reasoning that Addendum 5 added one.
5. **D53.** Two successive `go test -count=1` runs of the copy suite both pass, and -- the finding
   itself -- `scripts/ci/run-ci.sh` followed by an independent `go test -race -count=1 ./...` both
   pass against one provisioning cycle. The restoring cleanup asserts the trigger is back.
6. **D54.** All **four** messages, each on its own fixture: a real `pg_dump | psql` restore; a
   drop-and-recreate in place with the binding matching; a relation genuinely absent with the
   binding matching; and CAP #5 §7.5's `pg_dump --exclude-table` copy-with-missing-relation, which
   must report **the copy**, not (c). Plus the zero-binding-rows and binding-table-absent states,
   each asserting the fourth message and, for the second, that **no bare catalog error escapes**.
   Plus the ordering determinism assertion, and D46's existing negative retained unchanged: a
   corrupted `identity` on a healthy database leaves every DDL statement succeeding.
7. **D55.** Table-driven over the three spellings measured above (`"a.b".c`, `a."b.c"`,
   `public."Weird Name"`), asserting the resolver and the recorded value agree after, and asserting
   the ambiguous-key `count(*) = 2` case resolves or refuses deterministically rather than binding
   arbitrarily.

**Withdrawal conditions, declared now rather than decided after the fact:**

- **If D50's collateral-damage cases fail against the real schema** in a way the lab did not
  reproduce -- most plausibly around SEC-1's RLS migrations or
  `db/rollback/014_tenant_isolation_down.sql`, the same places D37 and D42 named -- D50 falls back
  to recording **both** `index_oids` and `index_defs` and comparing only the definitions, keeping
  the OID array as a reported diagnostic. **That fallback is strictly worse and must be recorded as
  such, not presented as equivalent**: it leaves a second recorded column that nothing compares,
  which is H-E's exact shape and the reason D47 had to be written at all.
- **D50 and D51 ship together or not at all.** The reasoning is in D51's closing paragraph and it
  cuts both ways; splitting them leaves either an unexplained no-op capability or a wedge one
  self-re-grant away.
- **If D51's revoke is found to break any legitimate operation** this addendum did not enumerate --
  the grep for maintenance commands run as `owl_ledger_ddl` returned nothing across `internal/`,
  `cmd/`, `scripts/` and `.github/`, but a grep is not a proof about an operator's habits -- D51 is
  withdrawn and R24/R25 carry J-A's residual with D50 alone. That outcome is pre-declared here, not
  decided afterwards.
- **D54's four messages ship together.** Adding the fourth message without reordering the branches
  leaves the unclassifiable case reported as (c), which is J-C; reordering without the fourth
  message leaves zero binding rows asserting "copy", which is J-D.

**Addendum 5's and Addendum 4's pre-declared withdrawal conditions remain correctly un-triggered**,
re-verified against what *this* addendum designs rather than inherited from CAP #5's confirmation.
The instance binding is not made a gate -- D50, D51 and D52 never read it, and D54 part (c) reads it
strictly less confidently than before, never more. D47's clean-state positive is unaffected by D50:
the column it reconciles changes spelling, not existence, and its declared literal
(`internal/screeningledger/postgres.go:495-516`) moves with it in the same PR, which is D49's second
condition satisfied rather than triggered. D46 is not split from D45. D40's collateral-damage cases
pass, so Addendum 4's `pg_depend` fallback is **not** required and **must not** be adopted. D38(a)
and D38(b) remain shipped together.

---

### New accepted risks

**R24 -- two non-atomic index routes remain, and both are self-healing rather than prevented.** After
D50, `CREATE INDEX CONCURRENTLY` on a protected relation still wedges (it genuinely adds a
definition, and refusing it is correct), and a **cancelled** `REINDEX ... CONCURRENTLY` still wedges
by leaving an invalid `<index>_ccnew` behind -- a route no CAP found, and one whose wedge surfaces on
a later, unrelated DDL statement rather than on the cancelling session's own. Both are cleared by
`DROP INDEX`, executed, with no event-trigger disable and no re-provisioning; both are unreachable to
`owl_ledger_ddl`, which holds `CREATE` on no schema (asserted by D41 part three) and, after D51, no
`MAINTAIN` on either table. The residual is therefore superuser-only and terminates where R12/R17 put
every other one. Recorded rather than designed away because "self-healing" is a property of the
current index sets: a protected relation that ever carries a non-constraint index makes
`DROP INDEX CONCURRENTLY` reachable, and D49's fourth invalidating condition already requires the
literals to move if that happens.

**R25 -- `REVOKE MAINTAIN` is an accident boundary, not a security boundary.** The owner can
`GRANT MAINTAIN` back to itself (executed), `GRANT` reports `objid=NULL` so D34 never sees it, and
only the next `CheckProvisioningState` reports the restored capability. D51 therefore prevents the
routine mistake completely and converts the deliberate act from a silent capability into a named
verification failure -- **it does not prevent the deliberate act**, and a later reader must not cite
D51 as prevention or remove D50 on its strength. This is the same shape as R13's restatement of
`--allow-genesis` ("the operator asserts genesis," never "genesis was verified") and is stated for
the same reason.

**R26 -- the recorded index definition is a PostgreSQL-version-dependent rendering.**
`pg_get_indexdef` produces text, and a major-version upgrade can re-render an unchanged index --
adding or normalising a clause -- so a recording made under one major may not compare equal under
the next even though nothing about the index changed. The failure direction is fail-closed and the
remedy is the one already documented (`grant-ddl-ownership` re-records), and it joins CAP #5 §10
point 1's standing condition that a different PostgreSQL major invalidates every DDL result in this
document. **This was not executed in this pass and is stated as unverified rather than asserted** --
the standard Addendum 3 set (`0007:2129-2139`) and R22 followed. It is worth weighing against what
it replaces: an OID recording is invalidated by an ordinary maintenance command on *every* version,
which is J-A.

### Staging

Same shape and reason as §8 and the five prior addenda (`0007:1397-1414`, `0007:2038-2058`,
`0007:2694-2716`, `0007:3566-3586`, `0007:4342-4367`): each stage independently reviewable and
independently provable.

1. **This addendum**, merged before any code (CLAUDE.md rule 7).
2. **Stage H1 -- the wedge.** D50 and D51 together (D58's second withdrawal condition), plus D52's
   per-branch diagnostic, its operator-document section and its recovery test. The HIGH, and the
   only stage that changes a security mechanism. D50's collateral-damage cases are a shipping
   requirement and its withdrawal condition is discharged or invoked here.
3. **Stage H2 -- the test instrument.** D53. Sequenced second and not last, which is a departure
   from where a MEDIUM would ordinarily fall: H1's own proof has to be runnable twice against one
   provisioning cycle, and today it is not.
4. **Stage H3 -- the diagnostics.** D54 and D55, sequenced after H1 because D52 has just changed the
   `RAISE` sites D54 reorders, and splitting them would produce two conflicting versions of the same
   eight lines.
5. **Stage H4 -- the document and the pin.** D56 and D57. Blocks nothing, and is therefore
   sequenced last and explicitly **not** droppable -- D23 was sequenced last on the same
   "blocks nothing" reasoning and CAP #2 rated the resulting gap HIGH, a lesson Addendum 5's staging
   already recorded (`0007:4348-4354`) and this addendum does not un-learn.
6. **`SECURITY.md` and `README.md` language.** R3's rule unchanged. `README.md:93-97`'s
   requalification notice stays until every stage above has landed and its reproduction passes.
   CAP #5 §9 re-confirmed that nothing in PR #152 re-asserted the guarantee; that must remain true
   through this addendum as well.

**SEC-7 does not close on this addendum, and for the second consecutive time the reason is not a
forgery.** §8's closing condition -- "a deliberately forged chain fails a CI run that nobody chose
to invoke" -- is met in the CI sense by `d20_exploit_test.go` and, since D23, in the operational
sense too, and CAP #5 found no bypass of any limb of the invariant. What remains open is limb (c)
being rendered **unsatisfiable** rather than false: a non-superuser reaching, in one ordinary
maintenance statement, a state in which the control denies the database to everyone including the
party who would repair it. That is a smaller and different barrier than the five that preceded it,
and D50 through D52 are the whole of it. The closing sentence stands and now has a sixth addendum
behind it.

### Addendum 6 summary

- **CAP #5's verdict is QUALIFIED, not PASS, for the fifth consecutive audit -- and for the second
  consecutive audit with no forgery bypass.** Six findings remain, one HIGH, and five of the six
  require no adversary at all. D31's scoping principle, Addendum 4's referent principle and
  Addendum 5's population principle all held; this addendum reopens none of them.
- **J-A is a different axis, not a sixth turn of the class screw.** CAP #5 states it as atomicity;
  this addendum sharpens it to the referent a *legitimate* operation rewrites, and notes that the
  two are not independent -- PostgreSQL performs exactly those rewrites non-atomically, because they
  are the maintenance operations that must not hold long locks. Fixing the referent therefore fixes
  most of the atomicity problem as a consequence.
- **The design is D50-D58.** The index referent becomes the index definition set, with the
  interception point investigated, found to exist, and rejected for being object-blind (D50); the
  `MAINTAIN` capability removed at its source and its restoration asserted, with the self-re-grant
  stated as the limit (D51); the drifted non-copied database given a naming diagnostic and a tested
  recovery (D52); the copy fixtures made non-destructive so the Definition of done's two commands can
  both pass (D53); D46's diagnostic ordered by evidence, made deterministic, and given a fourth
  message for evidence it does not have (D54); one referent, one spelling (D55); four stale counts, a
  circular recovery line and the document's missing preconditions (D56); the PGDG scope pin with its
  fingerprint capture pre-declared as a condition (D57); and the proof obligations with pre-declared
  withdrawal conditions (D58).
- **This design pass executed its mechanism assumptions, and one of them refuted the fix this
  section was expected to reach.** `ddl_command_start` **does** fire for every `CONCURRENTLY` form
  and an exception there **does** prevent the catalog change -- and it exposes `tg_tag` and nothing
  else, so prevention there is an action enumeration over the whole database, which is what D31
  exists to forbid. Also confirmed by execution: `REINDEX ... CONCURRENTLY` preserves the index's
  name, definition, flags, key and constraint OID and rewrites only its OID; `REINDEX SCHEMA` and
  `REINDEX DATABASE CONCURRENTLY` reach the same wedge and appear in no prior record;
  `CREATE INDEX CONCURRENTLY`'s wedge is self-healing by `DROP INDEX` while `REINDEX`'s is not; a
  cancelled rebuild leaves an invalid `_ccnew` index and wedges a later unrelated statement;
  PostgreSQL 17's `MAINTAIN` is revocable from a table's owner and re-grantable by that owner;
  `to_regclass` raises only on a malformed name and an untaken plpgsql branch is never planned; and
  the definition-keyed comparison costs 0.540 ms per DDL statement against the shipped 0.513 ms.
- **Three risks are recorded** rather than designed away: two self-healing non-atomic routes remain
  and are superuser-only (R24); `REVOKE MAINTAIN` is an accident boundary and not a security one
  (R25); and the recorded definition is a version-dependent rendering, stated as unverified across
  majors rather than asserted (R26).
- **This addendum revises no prior decision.** D1-D7, D8-D20, AR7, D21-D30, D31-D37, D38-D42 and
  D43-D49 stand. R1-R23 stand. D40's index comparison changes its recorded column; its principle,
  its `objid` phase, its other six properties and every collateral-damage guarantee are untouched,
  and D50 is that principle applied to the one column written before it.

**Audit basis commit:** `71fbb428bf8ef267f9607afc8dee9dd0bc5bc7f4`

Every file:line citation in this addendum was verified against that tree -- the same commit CAP #5
was produced against, so no drift separates the audit from this design. For a CAP record covering
the implementation of this addendum, use the tip of whichever stage PR is under audit, not this
value.

## Addendum 7: the quantifier -- the population a control's assertion ranges over, and CAP #6's seven findings (2026-08-27)

- **Status:** Proposed
- **Trigger:** a sixth Composition Audit Program record produced against the implemented Addendum 6
  (`docs/backlog/sec-7-cap-record-a653941.md`, adversarial posture, audit basis commit
  `a653941af734dd7e5384d8cda3228bcb96c9811d`) returned **QUALIFIED, not PASS** for the sixth
  consecutive audit -- and for the **third** consecutive audit with **no forgery bypass**. Seven
  findings remain, one HIGH (K-A), one MEDIUM (K-B) and five LOW (K-C, K-D, K-E, K-F, K-G). **None
  is a forgery**, and five of the seven require no adversary at all. **SEC-7 is not closed.**
- **What CAP #6 confirmed and this addendum does not disturb.** D50 is credited as the cleanest
  decision in six rounds and this addendum reopens none of it: all five `REINDEX ... CONCURRENTLY`
  forms complete and leave the database healthy, `REINDEX SYSTEM CONCURRENTLY` is refused by
  PostgreSQL itself, `ALTER INDEX ... RENAME` and `SET (fillfactor)` moved from *succeeds* to
  *blocked* as D50 predicted, and the referent was proved insensitive to six `search_path` values
  and a deliberately planted shadowing relation. D53 closes J-B by execution. D54's fourth message
  and its determinism are real. D55 holds against ten identifier spellings. The cryptographic core
  is unregressed at 106 top-level PASS, 0 SKIP, 0 FAIL. **D31's scoping principle, Addendum 4's
  referent principle, Addendum 5's population principle and Addendum 6's atomicity principle all
  held.**
- **Scope:** a pure addition. Nothing above this section is edited -- not D1-D7, not D8-D20, not
  AR7, not D21-D30, not D31-D37, not D38-D42, not D43-D49, not D50-D58, not §3.4, §6.1 or the D19
  correction note, not R1-R26. Decision numbering continues at **D59**; risk numbering at **R27**.
  Where a prior decision's *text* is wrong rather than merely superseded -- D54(c)'s stated reason
  for rejecting an exception block, and R25's "to itself" -- the new decision says so in its own
  words and states what the old claim actually rests on afterwards. That is the convention AR7
  established for R7, Addendum 3 followed for D21 point 3, Addendum 4 for D35's biconditional and
  Addendum 5 for R19's precondition.
- **Verification basis:** every `file:line` below was re-derived from the working tree at
  `a653941af734dd7e5384d8cda3228bcb96c9811d` rather than copied from the CAP record or from a prior
  addendum.
- **This design pass executed its mechanism assumptions, as Addendum 3 established and Addenda 4, 5
  and 6 held to -- and this time the execution refuted the fix this section was expected to reach,
  and falsified one of the CAP record's own claims.** Two disposable PostgreSQL 17.11 clusters were
  built on ports 55440 and 55441; the first was provisioned with the **real** schema in
  `.github/workflows/ci.yml:141-235`'s exact order (`create-roles`, all seventeen
  `db/migrations/*.sql` as `owl_migrator`, `grant-app-privileges`, `grant-ddl-ownership`), baseline
  confirmed at thirteen `sec7_protected_object` rows, two `sec7_protected_relation` rows, one
  `sec7_instance_binding` row, both event triggers `evtenabled='A'`, `owl_ledger_ddl` holding
  `CREATE` on neither schema nor database, and `MAINTAIN` false for every `owl_*` non-superuser --
  byte-identical to CAP #6 §7.0's recorded baseline, including both `index_defs` renderings. The
  second cluster existed solely for the cross-cluster DR procedure (D66). Every destructive probe
  ran against a `CREATE DATABASE ... TEMPLATE` clone. Both clusters were torn down. The three
  results that changed the design, each with its transcript in the section that relies on it:
  1. **An `indisvalid = false` index can still enforce uniqueness**, provided `indisready` is true.
     That refutes the obvious K-F fix -- filtering invalid indexes out of D40's comparison -- which
     would have bought R24's convenience by giving up a real protection (D65).
  2. **The instance-binding read is not on the passing path**, so D54(c)'s stated reason for
     rejecting an exception block does not hold, and the exception block is the mechanism K-E
     actually needs -- a shape guard alone is provably insufficient (D64).
  3. **`pg_maintain` is the one predefined role that reports `MAINTAIN = true`** on an ordinary
     table, which is what forces D60's closed set to be scoped by a structural discriminator rather
     than asserted as simply empty over every non-superuser role (D59, D60).

---

### Drift found while writing this addendum

Recorded rather than silently corrected, the convention §3.4, §6.1, `0007:717-720`,
`0007:1474-1490`, `0007:2141-2160`, `0007:2804-2826`, `0007:3689-3712` and `0007:4476-4498` set.

1. **CAP #6 §7.4's own account of the wedged state is wrong in one of its three clauses, and the
   error understates K-A.** The record states that on the database `owl_migrator` has just wedged,
   *"`Migrate()` fails, `CheckProvisioningState` returns `Provisioned=false`, `VerifyAnchored`
   refuses."* Re-executed against the reproduced state: `Migrate()` does fail
   (`ERROR: ... its index set changed (SQLSTATE P0001)`), but **`CheckProvisioningState` returns
   `Provisioned=true Reason=""`** -- byte-identical to a healthy database. The reason is structural
   and is worth stating because D62 depends on it: `protectedRelationStateReason` filters the live
   side of its index comparison to the *declared* index names
   (`internal/screeningledger/postgres.go:569`, `ic.relname = ANY($7)`), so a `_ccnew` leftover --
   whose name is not among them -- is never in the live set it compares. D40's runtime comparison
   (`scripts/ci/provision_test_roles.sh:751-754`) is unfiltered and therefore does see it. **The
   provisioning-state check is blind to exactly the live drift that wedges every DDL statement in
   the database.** Executed:

   ```
   recorded index_defs           {"CREATE UNIQUE INDEX screening_ledger_anchor_pkey ON public.screening_ledger_anchor USING btree (ledger_id, sequence)"}
   live, UNfiltered (D40 sees)   {"... screening_ledger_anchor_pkey ...","... screening_ledger_anchor_pkey_ccnew ..."}
   live, filtered to declared    {"... screening_ledger_anchor_pkey ..."}          <- D47 compares THIS
   => D40 wedges; CheckProvisioningState reports Provisioned=true Reason=""
   ```

   CAP #6 §7.5's contrasting claim -- that D47 *does* catch the **laundered** baseline -- is
   correct and was re-executed: once `grant-ddl-ownership` has re-recorded the drift, the recorded
   side gains a member the declared-name filter excludes from the live side, and D47 fires. The two
   claims are about two different states and only the §7.4 one is false. R28 records the residual.
2. **D54(c)'s stated reason for rejecting `EXCEPTION WHEN undefined_table` does not hold.**
   `0007:5079-5083` rejects it because it *"opens a subtransaction on a path that runs on every DDL
   statement in the database, which is R17's accepted risk paid on the passing path as well as the
   failing one."* The binding read sits strictly inside the `NOT EXISTS` branch
   (`provision_test_roles.sh:690-708`), which is the already-failing path. Executed: a binding
   replaced by a view whose first column is `(1/0)::bigint`, on an otherwise **healthy** database,
   left `CREATE TABLE` succeeding -- the read is never reached when nothing is wrong. The
   *conclusion* D54(c) reached (guard with `to_regclass` on a literal) remains correct and is not
   withdrawn; what is withdrawn is the reason given for not *also* using an exception block, which
   is the mechanism K-E needs. D64 states this in its own words rather than editing D54.
3. **R25's limit is stated one step too narrowly, which is K-A.** `0007:5340-5344` reads *"The owner
   can `GRANT MAINTAIN` back to itself (executed), `GRANT` reports `objid=NULL` so D34 never sees
   it, and only the next `CheckProvisioningState` reports the restored capability."* Each clause is
   true; the quantifier is not. The owner can grant it to **any** role, and only the self-grant is
   observed. Per this document's convention the sentence is **not edited**; D60 withdraws the
   narrowing and states what remains true of R25 afterwards.
4. **Addendum 6's `file:line` citations resolve against `71fbb42`, not against this tree**, and
   CAP #6 §12 lists five examples. Re-derived at this commit and confirmed: D40's index comparison
   is `provision_test_roles.sh:751-754`, the relation loop is `:673`, the D46/D55 resolver is
   `:718-720`, `protectedRelationStateReason` is `postgres.go:552-598` and
   `requiredProtectedRelationStates` is `:522-543`. Expected, not a defect.
5. **`docs/operations/sec7-database-copies.md` names `screening-ledger status` exactly once**, at
   `:69`, inside "Before you clone production into staging". Neither the drift section (`:109-128`)
   nor "Recovering a bricked restore" (`:130-161`) mentions it. Confirmed by grep at this commit,
   and it is the substance of K-B's second half.

---

### Addendum 7 context: the referent and the population were right, and the quantifier was a literal

Addendum 1 diagnosed the original's structural error as fixing instances rather than causes
(`0007:1494-1497`). Addendum 2 named its findings as one class -- "a control whose installation is
asserted rather than checked, by the party the control constrains" (`0007:1499-1500`). Addendum 3
sharpened it to "a control that decides what to protect, or what to protect against, by listing
members of an open set" (`0007:2172-2173`) and produced D31. Addendum 4 sharpened it again to "the
enumeration was fixed and the referent drifted" (`0007:2853-2857`) and produced D40. Addendum 5
moved one axis over -- "the referent is correct and its population was never stated"
(`0007:3742-3746`) -- and produced D43. Addendum 6 moved to a third -- the referent a *legitimate*
operation rewrites (`0007:4526-4534`) -- and produced D50.

CAP #6 §0.1 looked for a seventh turn of the class screw inside the security boundary and, like
CAP #4 and CAP #5, did not find one. What it found is the same question asked about a fourth part
of a control's specification, and CAP #6 §11 phrases it exactly:

> **Every control has a referent, a population, and a *quantifier*. Addendum 4 fixed referents.
> Addendum 5 fixed populations. K-A is a control whose referent and population are both right and
> whose quantifier is a literal: `has_table_privilege('owl_ledger_ddl', ...)` asks about the role
> the fix happened to be written for, not about the role that can cause the harm. Ask not only
> "what does it compare, over what population?" but "is the fact I am asserting true of a *name* I
> chose, or of every party that could hold this capability -- and can the party I constrain move
> the capability to a name I did not write down?"**

That is right, and this addendum adopts it. One sharpening is worth adding, because it is what
makes D60 a decision rather than a patch and what makes D61 possible at all:

> **A capability removed and a capability asserted-absent must be quantified over the same
> population. Where a control revokes a privilege from a role, the matching assertion is not "that
> role lacks it" but "the complete set of parties holding it is the declared one" -- and that set
> is enumerated from the catalog at check time, never written down as a name.**

The two halves of D51 fail this test in opposite directions and that is the whole of K-A. The
`REVOKE` (`provision_test_roles.sh:192`, `:294`) removes a privilege from a role; the assertion
(`internal/screeningledger/postgres.go:280-288`) is quantified over **tables** -- the loop is
`for _, table := range requiredDDLOwnedTables` -- with the role a string literal inside the query.
Two protected tables are enumerated correctly. One role is named. The capability is grantable to
any role by an owner the controls exist to bind.

**Why this is not simply "add the other roles to the list."** The set of roles that could hold
`MAINTAIN` is open in exactly the sense D31 named: `CREATE ROLE` is available to the bootstrap
superuser at any time, and a grant to a role created after this addendum ships would sit outside
any list written today. D31's answer to an open set of actions was a closed set of objects; the
answer to an open set of role names is a closed set of *facts about the live catalog* --
enumerate the roles that exist now, and assert the resulting set is the declared one.

---

### D59. The quantifier principle, and where PostgreSQL actually supports it

**Decision: where a control asserts that a capability is absent, it enumerates the parties that
could hold it from the live catalog and asserts the resulting set equals a declared one. A role
name is never the quantifier.**

Four sub-decisions follow, each verified by execution against PostgreSQL 17.11 during this design
pass rather than reasoned from the manual.

**1. `pg_roles` is readable in full by `owl_migrator`, with no new role, DSN or grant.** This is the
same property D33's, D41's and D45's existing facts have (`0007:2422-2425`, `0007:3404-3406`,
`0007:3967-3969`) and it was checked rather than assumed, because a check that needs a new
credential is a check that will be skipped. Executed as `owl_migrator`:

```
20 rows visible to owl_migrator in pg_roles
20 with rolsuper readable
20 with oid readable
```

**2. `has_table_privilege` over that enumeration accounts for role membership and for `PUBLIC`;
a raw ACL scan does not.** D39 already established the second half by execution when it rejected
`aclexplode` over `pg_attribute.attacl` as "strictly weaker" -- an ACL entry names a grantee
literally, so it does not expand membership (`0007:3155-3170`). The same reasoning applies here and
the membership route was re-executed directly, because K-A's whole point is that the capability
moves to a name nobody wrote down:

```
CREATE ROLE cap7_member NOSUPERUSER ...            oid=16952  MAINTAIN=false
GRANT pg_maintain TO cap7_member                   oid=16952  MAINTAIN=true
[cap7_member] REINDEX INDEX screening_ledger_anchor_pkey   -> REINDEX      <- genuinely usable
```

and the `PUBLIC` route, which makes every normal role report true and is named individually by the
enumeration:

```
[owl_ledger_ddl] GRANT MAINTAIN ON TABLE screening_ledger_anchor TO PUBLIC;   -> GRANT
enumeration -> owl_migrator, owl_app, owl_ledger_anchor, owl_ledger_ddl, cap7_member
```

**3. System roles are excluded by a structural discriminator, never by a name pattern -- and this
is the fact that decides the shape of the check.** The naive form of D60 is "no non-superuser role
holds `MAINTAIN`", and it is false on a correctly provisioned database. Executed over every role in
the cluster:

```
owl_ci                oid=10    super=true    MAINTAIN(anchor)=true
pg_monitor            oid=3373  super=false   MAINTAIN(anchor)=false
pg_read_all_data      oid=6181  super=false   MAINTAIN(anchor)=false
pg_write_all_data     oid=6182  super=false   MAINTAIN(anchor)=false
pg_maintain           oid=6337  super=false   MAINTAIN(anchor)=TRUE     <- the one that matters
owl_migrator          oid=16385 super=false   MAINTAIN(anchor)=false
owl_app               oid=16386 super=false   MAINTAIN(anchor)=false
owl_ledger_anchor     oid=16387 super=false   MAINTAIN(anchor)=false
owl_ledger_ddl        oid=16388 super=false   MAINTAIN(anchor)=false
```

`pg_maintain` is a predefined role whose members hold `MAINTAIN` on every relation, and
`has_table_privilege` answers for the role itself as it would for a member. Fifteen of the sixteen
predefined roles report false; one reports true. The exclusion is therefore **`oid >= 16384`**
(`FirstNormalObjectId`, the boundary above which all user-created objects are assigned) rather than
`rolname NOT LIKE 'pg\_%'`, which would be a name pattern and therefore enumeration by inference --
CLAUDE.md's named prohibition, and the shape D31 exists to forbid. The boundary is observable in
the transcript above: every predefined role is at or below 6337 and every provisioned role is at or
above 16385.

**The exclusion does not create a hole, and that is the load-bearing property.** Excluding the
predefined role does not exclude its *members*: `cap7_member` above is a normal role at oid 16952,
holds `MAINTAIN` transitively through `pg_maintain`, and the enumeration names it. What is excluded
is a role nothing can authenticate as -- `pg_maintain` has `NOLOGIN` by construction -- so the
exclusion removes a false positive and no true one.

**4. The enumeration cannot raise, and its cost is negligible.** Both were checked because the
failure mode of a check matters as much as its success, the standard D41 set for
`pg_identify_object` (`0007:3407-3409`). Every `(role, privilege)` pair over all eight table
privileges and every role in the cluster was evaluated:

```
160 (role, privilege) pairs evaluated with no exception
table-level enumeration      x500 -> 3.09 ms total (0.0062 ms each)
column-granularity form      x500 -> 7.23 ms total (0.0145 ms each)
```

**What this principle does not reach, stated rather than left to be discovered.** The enumeration is
a **point-in-time observation**, not an interception. `GRANT` reports `objid = NULL`, so D34 cannot
see it -- the residual Addendum 3 recorded (`provision_test_roles.sh:671-673`) and CAP #4, CAP #5
and CAP #6 each re-confirmed. A capability granted, used, and revoked between two verification runs
leaves no trace in any mechanism this addendum adds. R27 states this as a risk rather than letting
D60 imply prevention.

---

### D60. K-A (HIGH): the `MAINTAIN` assertion becomes a closed set over the live role population

**The finding, restated from the code and reproduced end to end.** `grant-ddl-ownership` revokes
`MAINTAIN` from one named role on each protected table (`scripts/ci/provision_test_roles.sh:192`,
`:294`) and asserts the negative for that same one named role, both in the script
(`:264-269`, `:381-386`) and in the verifier (`internal/screeningledger/postgres.go:280-288`). The
owner still owns both tables, and an owner may grant a table privilege to any role whether or not
it still holds that privilege itself. Executed, from the shipped baseline:

```
[owl_ledger_ddl] GRANT MAINTAIN ON TABLE screening_ledger_anchor TO owl_migrator;   -> GRANT
  MAINTAIN: owl_ledger_ddl=false   owl_migrator=true
CheckProvisioningState -> Provisioned=true  Reason=""
```

`owl_migrator` is inside §2's adversary set. It then reaches J-A's wedge by cancelling a rebuild --
a statement it now has the privilege to run:

```
[owl_migrator] REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey
    -> ERROR: canceling statement due to user request
    indexes: screening_ledger_anchor_pkey(valid=true), screening_ledger_anchor_pkey_ccnew(valid=false)

[owl_migrator]        CREATE TABLE cap7_z(x int);  => ERROR: ... D50: ... its index set changed
[bootstrap superuser] CREATE TABLE cap7_z2(x int); => ERROR: ... D50: ... its index set changed
Migrate()                                          => ERROR: ... its index set changed (SQLSTATE P0001)
CheckProvisioningState                             -> Provisioned=true  Reason=""
```

Every DDL statement in the database fails for every role including the bootstrap superuser, and the
provisioning-state check reports the database clean throughout -- both before the wedge (the
capability transfer) and after it (the drift; see the drift note above, which corrects CAP #6 §7.4
on this point).

**Decision: `requiredProvisioningState` asserts that the set of roles holding `MAINTAIN` on either
protected table is empty, over the live role population, and the assertion names every role it
finds.**

The check, in D59's shape and illustrative only -- the implementation PR owns the real form:

```sql
SELECT coalesce(string_agg(r.rolname, ', ' ORDER BY r.rolname), '')
FROM pg_roles r
WHERE NOT r.rolsuper AND r.oid >= 16384
  AND has_table_privilege(r.rolname, $1::regclass, 'MAINTAIN')
```

- **The set is asserted empty, full stop, and the brief's allowlist question is answered by
  measurement rather than by judgement.** The complete privilege matrix over both protected
  relations was enumerated on the shipped baseline:

  ```
  MAINTAIN holders (normal, non-superuser) on screening_ledger_anchor:              <EMPTY>
  MAINTAIN holders (normal, non-superuser) on screening_ledger_retention_tombstone: <EMPTY>
  ```

  **Nothing in this system has any legitimate need to hold `MAINTAIN` on either table.** D51
  already established the substance -- nothing in `internal/`, `cmd/`, `scripts/` or `.github/`
  runs `VACUUM`, `ANALYZE`, `CLUSTER`, `REINDEX` or `LOCK TABLE` as `owl_ledger_ddl`, and
  autovacuum is a background worker unaffected by table-level grants (`0007:4863-4869`) -- and the
  measurement extends it from one role to every role. **No allowlist is introduced.** An empty-set
  assertion needs no declared literal to drift out of sync with, which is a real advantage over the
  matrix form D61 considers for the other probes, and it is the reason this decision is smaller
  than that one.
- **Detection, executed against the K-A state itself:**

  ```
  MAINTAIN holders on screening_ledger_anchor: owl_migrator
  MAINTAIN holders on screening_ledger_retention_tombstone: <EMPTY>
  ```

  The state that reports `Provisioned=true Reason=""` today becomes a named provisioning failure
  identifying the table and the role.
- **`MAINTAIN` has no column form**, so `has_table_privilege` is the right question here and
  `anyColumnPrivilege` is not -- D51 already stated this explicitly to stop a later reader "fixing"
  it into a column probe (`0007:4872-4876`), and D59's enumeration changes the quantifier without
  changing that. Stated again because the two corrections touch the same lines.
- **`grant-ddl-ownership`'s `REVOKE` gains `FROM PUBLIC` alongside `FROM owl_ledger_ddl`**, so that
  the provisioning step removes the capability over the same population the assertion ranges over.
  This is not what closes K-A -- the assertion is -- but a `REVOKE` narrower than its own check is
  the asymmetry this addendum exists to remove, and leaving it would reproduce the finding's shape
  in the installer.
- **The script's two postconditions (`:264-269`, `:381-386`) move to the same enumeration**, so the
  installer proves the property it installs rather than a narrower one.

**What this buys, and what it does not, stated with the same specificity as D51 stated its own
limit.** D51 is an accident boundary, not a security boundary (R25), and **D60 does not change
that**. The owner can still grant `MAINTAIN` to any role, `GRANT` still reports `objid = NULL`, and
D34 still never sees it. What changes is that the resulting state stops being invisible: today the
system's entire report on a transferred capability is `Provisioned=true Reason=""`, and after D60
it is a named failure on the next `verify`. **D60 converts an unobserved capability transfer into an
observed one. It does not prevent the transfer**, and a later reader must not cite it as
prevention.

**R25's narrowing is withdrawn, and what remains true of it is stated exactly.** Per this document's
convention the sentence at `0007:5340-5344` is not edited. What was overstated is the quantifier --
"the owner can re-grant it *to itself*" describes one instance of a capability the owner holds over
every role. R25's substantive decision stands unchanged: `REVOKE MAINTAIN` remains an accident
boundary, the residual still terminates at the parties R12/R17 name, and D50 must not be removed on
D51's or D60's strength. **R25's conclusion is correct and its precondition was narrower than the
code's exposure**; D60 is what makes the sentence true of the population it describes, exactly as
D47 did for R19 (`0007:4137-4161`) and D39 for D35 (`0007:3176-3201`).

---

### D61. The sweep: every other named-role assertion, and the two shapes that are not this one

The brief requires the fix to generalise rather than patch one instance, and CAP #6 §11 point 1(b)
asks the question directly of D39's probes. Every privilege assertion in the verification and
provisioning paths was enumerated at this commit -- by reading the two files, not by inference --
and each was classified.

| Site | Assertion | Same shape? |
|---|---|---|
| `postgres.go:280-288` | `owl_ledger_ddl` lacks `MAINTAIN` on each protected table | **Yes -- K-A.** D60 |
| `postgres.go:248-260` | `owl_migrator` lacks `INSERT` on tombstone and anchor | **Yes.** Negative fact, named role, owner-grantable privilege |
| `postgres.go:261-267` | `owl_ledger_anchor` lacks `SELECT` on anchor | **Yes.** Same |
| `provision_test_roles.sh:226-261`, `:351` | the installer's `SELECT`/`INSERT`/`UPDATE`/`DELETE` postconditions | **Yes**, installer side |
| `postgres.go:211-218` | `relowner` of each protected table **is** `owl_ledger_ddl` | **No** -- see below |
| `postgres.go:224-232` | `prosecdef` true and `proowner` **is** `owl_ledger_ddl` | **No** -- same reason |
| `postgres.go:332-342` | `owl_ledger_ddl` lacks `CREATE` on schema and database (D41 part three) | **No** -- see below |

**The two that are not this shape, argued rather than asserted.** An unargued "the others were
checked too" is exactly what this arc exists to stop, so the reason is recorded.

- **Ownership is single-valued and is asserted positively.** `pg_class.relowner` holds exactly one
  OID; `pg_proc.proowner` likewise. An assertion that it **equals** `owl_ledger_ddl` is already a
  complete quantification over the population "roles that own this relation," because that
  population has exactly one member by construction. There is no name the capability can move to
  that the assertion would not see, which is precisely what is false for a grantable privilege.
- **D41 part three's two `CREATE` probes are complete *given* the ownership assertion.** The
  capability they exist to deny -- creating an index, trigger, policy or inheritance child on a
  protected relation -- requires **both** `CREATE` on the schema **and** ownership of (or the
  relevant privilege on) the target relation. `owl_migrator` legitimately holds `CREATE` on schema
  `public` (`provision_test_roles.sh:69`, `GRANT ALL ON SCHEMA public TO owl_migrator`), so "no
  role holds `CREATE` on `public`" is false by design and asking it would be wrong. The only role
  for which the conjunction is reachable is the owner, and the owner is asserted by name and is
  single-valued. **The probe's quantifier is complete because the other conjunct's population is
  closed**, and D41 part three is correct as written. Recorded so a later change cannot "generalise"
  it into an assertion that fails on a correctly provisioned database.

**Decision: D39's three probes are re-quantified over the live role population, at column
granularity, against a declared allowlist -- and the allowlist is measured, not assumed.**

D39's correction is not disturbed: the question stays at column granularity, because
`has_column_privilege` subsumes the table-level probe and catches the routes a raw ACL scan misses
(`0007:3152-3170`). What changes is the quantifier. Unlike `MAINTAIN`, the answer here is **not**
the empty set -- `owl_ledger_anchor` legitimately holds `INSERT` on the anchor and `owl_migrator`
legitimately holds `SELECT` on both -- so this decision does need a declared literal. It was
enumerated on the shipped baseline rather than transcribed from D17's table:

```
screening_ledger_anchor              | owl_ledger_anchor | INSERT
screening_ledger_anchor              | owl_ledger_ddl    | DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE
screening_ledger_anchor              | owl_migrator      | SELECT
screening_ledger_retention_tombstone | owl_ledger_ddl    | DELETE,INSERT,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE
screening_ledger_retention_tombstone | owl_migrator      | SELECT
```

Five rows, and `owl_app` holds nothing on either relation -- which is D17's table
(`0007:1194-1199`) confirmed against the catalog rather than against its own prose. The
`owl_ledger_ddl` rows are the owner's implicit privileges, and they carry no `MAINTAIN`, which is
D51's revoke visible in the matrix.

- **The declared literal is `requiredTablePrivilegeHolders`**, written out in `postgres.go` beside
  `requiredProtectedRelationStates` (`:522-543`), never derived by scanning the provisioning script
  -- CLAUDE.md's "never enumerate targets by inference", the same standard D41 set for
  `requiredProtectedObjects` (`0007:3424-3428`).
- **The check asserts set equality**, so a privilege granted to any role not in the literal is a
  named failure, and a privilege *missing* from a role the design requires to have it is equally a
  failure. That second direction is new and is worth having: the installer asserts
  `owl_ledger_anchor` can `INSERT` (`provision_test_roles.sh:236`) and the verifier never did.
- **It subsumes the three probes it replaces**, rather than sitting beside them -- the same
  "replace, do not supplement" reasoning D39 used for `has_table_privilege` and D50 for
  `index_oids`. Two recordings of one property is a second thing to keep in sync.
- **A coverage gap the CAP does not name, closed by the same change.** The installer asserts
  `owl_ledger_anchor` holds neither `UPDATE` (`provision_test_roles.sh:246`) nor `DELETE` (`:251`)
  on the anchor; the verifier checks only `SELECT` (`postgres.go:261-267`). The installer proves
  more than the verifier does, which is G-A's shape -- the installer checks and the verifier does
  not -- on a smaller surface. A matrix over all eight privileges closes it by construction rather
  than by adding two more probes.

**Cost**, measured because the column form is a per-role, per-column question: 0.0145 ms per
relation per privilege over the live role population (D59 point 4). The full matrix is eight
privileges over two relations, so under 0.25 ms added to a check that already performs several
dozen catalog queries.

**R23's coordinated-edit surface grows by one literal and this addendum does not pretend otherwise.**
D60 adds none (an empty-set assertion has no literal to drift). D61 adds one, and it is the fifth
such declaration in `postgres.go`. The mitigating property is unchanged and is why the arrangement
survives: it fails closed. R29 records it.

---

### D62. K-B (MEDIUM): what `grant-ddl-ownership` is allowed to record

**The finding, restated from the code and reproduced.** D50 states the principle plainly
(`0007:4820-4821`): *"having D40 re-record the live state when it detects index drift would let a
genuine attack launder itself into the recording, which is the one thing a recorded-state control
must never do."* The runtime control does not do it. `grant-ddl-ownership` does: it is a
`DELETE FROM sec7_protected_relation` (`provision_test_roles.sh:528`) followed by an
`INSERT ... SELECT` straight out of the live catalog (`:530-542`), asserted only by a row count of
two (`:543-548`). Executed with an attacker-introduced index and the operator document's recovery
followed verbatim:

```
[superuser] CREATE INDEX CONCURRENTLY cap6_evil ON screening_ledger_anchor (anchored_at)
    -> ERROR: ... D50: ... its index set changed        health: WEDGED
step 1  ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE     -> ALTER EVENT TRIGGER
step 2  PGDATABASE=... ./scripts/ci/provision_test_roles.sh grant-ddl-ownership
        -> exit 0, three PASS lines, zero warnings
step 3  both event triggers = A                                          health: healthy

RECORDED AFTERWARDS:
  CREATE INDEX cap7_evil ON public.screening_ledger_anchor USING btree (anchored_at)
  CREATE UNIQUE INDEX screening_ledger_anchor_pkey ON public.screening_ledger_anchor USING btree (ledger_id, sequence)
```

D47 is the whole of the defence and it is out of band -- re-executed, it reports the laundered
baseline correctly:

```
CheckProvisioningState -> Provisioned=false
  Reason="sec7_protected_relation's recorded index_defs for public.screening_ledger_anchor do not
          match its declared primary-key index (ADR-0007 Addendum 5 D47 / Addendum 6 D50)"
```

but `docs/operations/sec7-database-copies.md` names `screening-ledger status` exactly once, at
`:69`, inside "Before you clone production into staging". Neither the drift section (`:109-128`)
nor "Recovering a bricked restore" (`:130-161`) mentions it, and the recovery's own step 3 checks
`evtenabled` only. An operator following the procedure end to end is told three times that it
passed and never told to run the one check that would have said otherwise.

**Decision, two parts, and the first is the mechanism.**

**(a) `grant-ddl-ownership` refuses to re-record a state that diverges from the declared literals.**
Before the `DELETE`/`INSERT`, and after the ownership transfer that precedes it, the step asserts
that each protected relation's live catalog state matches what
`requiredProtectedRelationStates` (`postgres.go:522-543`) declares -- the declared trigger names,
the declared index names, `relkind`, the RLS flags and an empty policy set. Any divergence is a
**named refusal** identifying the unexpected object and the remedy, not a `PASS`. Illustrative
only:

```sql
-- refuses, naming cap7_evil, rather than recording it
SELECT d.identity, c.relname AS undeclared_index
FROM declared d
JOIN pg_class t ON (pg_identify_object('pg_class'::regclass, t.oid, 0)).identity = d.identity
JOIN pg_index ix ON ix.indrelid = t.oid
JOIN pg_class c  ON c.oid = ix.indexrelid
WHERE NOT (c.relname = ANY(d.declared_index_names))
```

Executed against the drifted database, and -- the case that decides whether this is safe to install
-- against a genuine `pg_dump | psql` restore, which is the state the recovery legitimately exists
for:

```
drifted database   -> public.screening_ledger_anchor: UNDECLARED live index cap7_evil     (REFUSES)
restored database  -> <no undeclared index -- precondition PASSES>                        (RECOVERS)
   restore is genuinely in the state needing recovery:
   ERROR: ADR-0007 Addendum 5 D46: ... no longer exists. This database is a copy or restore ...
```

**The discrimination is exact, and it is the whole reason this shape works.** A logical copy
reassigns OIDs and carries the declared objects unchanged, so it passes; a drifted database carries
an object nothing declared, so it refuses. I-A's recovery path is undisturbed and K-B's laundering
is refused, by one comparison.

**Why this is not Addendum 4's rejected "let the detector re-baseline itself" shape, stated because
the brief requires it to be confirmed rather than assumed.** The rejected shape is a control that
resolves a disagreement between its recording and reality *by trusting reality*. D62 does the
opposite: the authority is `requiredProtectedRelationStates`, a literal declared in the repository,
committed, reviewed, and unwritable from the database. The step still re-records OIDs -- which is
the entire legitimate purpose of re-provisioning a copy, and which no attacker can influence
without also satisfying the declared literal -- but it may no longer record an object the
repository never declared. **The comparison terminates on something the attacker cannot write**,
which is D8's own criterion (`0007:941-948`), and the human confirmation step in (b) is a second
gate behind that rather than the mechanism. Had the human step been the mechanism, this decision
would be the rejected shape with a prompt attached.

**(b) Both recovery procedures require `screening-ledger status` first, with explicit stop
guidance.** `docs/operations/sec7-database-copies.md`'s drift section (`:109-128`) and "Recovering
a bricked restore" (`:130-161`) each gain it as step 0, with the instruction stated as a stop rather
than a suggestion: if it reports anything other than `Provisioned=true`, **investigate before
re-provisioning** -- because on a drifted database the thing it reports is the object the
re-provision is about to adopt.

**One honest limit on (b), which is why (a) is the mechanism and (b) is not.** On the
**un-laundered** wedge -- the state an operator actually meets first --
`CheckProvisioningState` returns `Provisioned=true Reason=""`, because D47's live-side filter
excludes an undeclared index by name (see this addendum's drift note 1). So step 0 would report
clean on exactly the state that sends the operator to the recovery in the first place, and only
report the problem afterwards, once the drift has been recorded. **A documentation step alone
would therefore not have closed K-B**, and this is recorded rather than discovered because it is
the kind of gap this arc has shipped before. R28 carries the residual; D65 narrows it for the
`indisvalid` case specifically.

---

### D63. K-C and K-D (LOW, LOW): the loop orders by evidence, and the document stops asserting what it never checked

**One decision, because they are one branch structure and one sentence about it.**

**K-C, restated from the code.** D54(b) made the diagnostic deterministic by ordering the relation
loop on `identity` (`scripts/ci/provision_test_roles.sh:673`). Determinism is genuine -- CAP #6
proved it against a physically reversed heap order and this pass reproduced that -- but `identity`
is a **name**, and the loop runs every property check for relation *n* before relation *n+1*'s
existence check. `public.screening_ledger_anchor` sorts first. Executed on a composite state (the
anchor's index set drifted **and** the tombstone's recorded relation absent):

```
ERROR: ... D50: protected relation "public.screening_ledger_anchor" (objid 16914): its index set changed
ERROR: ... D50: protected relation "public.screening_ledger_anchor" (objid 16914): its index set changed
ERROR: ... D50: protected relation "public.screening_ledger_anchor" (objid 16914): its index set changed
```

Three firings, one message, and the tombstone's absence never mentioned. D54(a) applied "order by
evidence, not by what is cheapest to compute" **inside** one branch; the loop enclosing it still
orders by a column that happens to be `NOT NULL` and happens to sort.

**Decision: the loop orders by evidence -- absence before property drift -- with `identity`
retained as the tiebreaker, so determinism is preserved rather than traded for it.**

```sql
FOR rel IN SELECT * FROM sec7_protected_relation r2
  ORDER BY (EXISTS (SELECT 1 FROM pg_class c2 WHERE c2.oid = r2.objid)), r2.identity LOOP
```

`false` sorts before `true` in PostgreSQL, so a relation whose recorded OID resolves to nothing is
reported ahead of one that merely drifted. Executed on the same composite state, and then with the
registry's rows physically reordered so the tombstone sits first in heap order -- CAP #6's own
stronger check:

```
evidence-ordered loop, 3 statements:
  ERROR: ... D46: protected relation "public.screening_ledger_retention_tombstone" (registry objid 999998) no longer exists ...   x3
physical heap order reversed, 3 more statements:
  ERROR: ... D46: protected relation "public.screening_ledger_retention_tombstone" (registry objid 999998) no longer exists ...   x3
```

The absence now outranks the drift, and one database state still produces one message.

**K-D, restated from the code and the document.** The instance binding is read in exactly one place
-- inside the `NOT EXISTS` branch (`provision_test_roles.sh:690-708`). The other **eight** branches
never consult it. `docs/operations/sec7-database-copies.md:122-123` nonetheless reads all eight as
positive evidence:

> This is **not** a copy or restore -- the database is the one it has always been, and its recorded
> state has simply drifted from live catalog state.

Executed on a `CREATE DATABASE ... TEMPLATE` clone -- the one copy shape the document's own table
says needs **no action** -- which was then drifted:

```
recorded: 7678767502711990796/16384   live: 7678767502711990796/19073
sysid matches=true   dboid matches=false        <- a copy by D46's own discriminator
ERROR: ... D50: protected relation "public.screening_ledger_anchor" (objid 16914): its index set changed
```

The sentence is false for that database.

**Decision: the document states what the eight branches actually establish, and no more.** The
sentence is replaced by one that says the recorded state has drifted from live catalog state and
that **these branches do not determine whether the database is a copy** -- pointing at the binding
and at `screening-ledger status` (D62(b)) for that question. The remedy the section then gives is
unchanged, because re-provisioning is correct for both a drifted original and a drifted copy; what
changes is that the document stops asserting a fact it never checked.

**Making the eight branches read the binding was evaluated and is not adopted**, so the choice is
visible rather than silent. It would add a binding read to eight already-failing paths to refine a
message whose remedy does not change, and it would put more weight on `sec7_instance_binding` at
exactly the moment D64 is narrowing how confidently that table is read. D45's never-gates property
is unaffected either way. The cheaper and more honest fix is for the prose to stop claiming the
branches answer a question they do not ask.

---

### D64. K-E (LOW): J-D's resolution, applied to the referent D54(c) actually needed

**The finding is J-D's exact shape reached by a different mutation**, and the brief is right that
it should be closed the way J-D was closed rather than by inventing an approach. D54(c) guarded the
binding table's **existence** with `to_regclass` on a literal (`provision_test_roles.sh:690`), and
that guard is correct and is not withdrawn. What it does not cover is the table's **shape**.
Executed, both states reproduced verbatim:

```
[binding present, column renamed: system_identifier -> sysid_renamed]
CREATE TABLE ... => ERROR: column b.system_identifier does not exist

[binding replaced by a view: SELECT (1/0)::bigint AS system_identifier, ...]
CREATE TABLE ... => ERROR: division by zero
                    CONTEXT: SQL statement "SELECT b.system_identifier, b.database_oid, b.database_name
```

A bare catalog error escaping the event-trigger function, naming neither the protected relation nor
the cause -- R17's accepted risk realised by the very kind of reference D46 rejected `to_regclass`
in order to avoid.

**The obvious fix is insufficient, and this was established by execution rather than reasoned
about.** A shape guard -- checking via `pg_attribute` that the three expected columns are present
on a `relkind='r'` relation -- catches the renamed column and does **not** catch the raising view,
because a raising view is perfectly well-shaped:

```
renamed-column state   -> shape ok = false      <- detected
raising-view state     -> shape ok = true       <- NOT detected, and it still raises
```

**Decision: the binding read is wrapped in an exception handler on the already-failing path, and an
unreadable binding is classified as D54's fourth message rather than as evidence of anything.**

This is J-D's own resolution -- *the read cannot raise* -- applied to the referent D54(c) narrowed
one step too far. It subsumes the shape guard entirely: a renamed column raises `42703` and is
caught by the same handler, so one mechanism covers both states and there is no second thing to
keep in sync. Executed against both:

```
raising-view state    -> ERROR: ... protected relation "public.screening_ledger_anchor" (registry objid 999999)
                                 no longer exists; the instance binding is present but could not be read, so
                                 whether this database is a copy cannot be determined -- investigate the
                                 sec7_instance_binding relation before re-provisioning
renamed-column state  -> the same message
```

**D54(c)'s stated reason for rejecting this is withdrawn, and what remains true of D54(c) is stated
exactly.** `0007:5079-5083` rejected an exception block because it "opens a subtransaction on a path
that runs on every DDL statement in the database ... paid on the passing path as well as the failing
one." The binding read is inside the `NOT EXISTS` branch, so it is never reached on the passing
path. Executed -- a binding that raises, on an otherwise **healthy** database:

```
healthy database, binding replaced by a raising view, DDL statement -> CREATE TABLE   (succeeds)
```

and measured, shipped against prototype, 400 DDL statements on a healthy database:

```
shipped    : 400 DDL stmts in 69.4 ms (0.173 ms/stmt)
prototype  : 400 DDL stmts in 70.3 ms (0.176 ms/stmt)
```

The passing path is unchanged in kind, because the handler is never entered there. **D54(c)'s
conclusion stands and its `to_regclass` guard is kept** -- it is still the cheapest way to classify
an absent table, and it still avoids planning a statement against a relation that does not exist.
What is withdrawn is only the reason given for not *also* handling a present-but-unreadable one.
Per this document's convention `0007:5079-5083` is not edited.

**Reachability is unchanged and remains the reason this is LOW.** `sec7_instance_binding` is a
`sec7_protected_object` member, so the mutation is refused for every non-superuser and for the
bootstrap superuser while the triggers are live; the state requires the superuser with the event
triggers already disabled. Reported because D54(c) was written to remove exactly this class and
removed one member of it.

---

### D65. K-F (LOW): `indisvalid`/`indisready` join the referent set -- and the filter that would have been wrong

**The finding, reproduced.** `pg_get_indexdef` renders what an index *is*, not whether it is *in
force*, so D50's definition set -- and D47's reconciliation of it -- are both blind to a validity
flag. Executed:

```
before: screening_ledger_anchor_pkey valid=true ready=true
UPDATE pg_index SET indisvalid=false, indisready=false WHERE indexrelid='screening_ledger_anchor_pkey'::regclass;  -> UPDATE 1
after:  screening_ledger_anchor_pkey valid=false ready=false
pg_get_indexdef  -> CREATE UNIQUE INDEX screening_ledger_anchor_pkey ON public.screening_ledger_anchor USING btree (ledger_id, sequence)
                    (identical to the valid rendering)

[owl_ledger_anchor] INSERT ... VALUES ('L',1,'aaa',...),('L',1,'FORGED',...);   -> INSERT 0 2
   rows at (L,1): 2        1 | aaa      1 | FORGED
health: healthy      CheckProvisioningState -> Provisioned=true  Reason=""
```

The anchor table's primary key is silently disabled and no SEC-7 control notices.

**The obvious fix is wrong, and the execution that refutes it is the reason this decision is shaped
the way it is.** The tempting move is to filter the live side of D40's and D47's comparisons to
`indisvalid AND indisready`: the invalidated primary key then disappears from the live set, the
comparison mismatches, and K-F is caught -- and, as a bonus, a cancelled rebuild's invalid `_ccnew`
never enters the live set either, so R24's cancelled-`REINDEX` wedge disappears. Both halves were
executed and both work:

```
K-F state         recorded {pkey}  live UNfiltered {pkey}        live +valid {}         -> filter DETECTS
cancelled REINDEX recorded {pkey}  live UNfiltered {pkey,_ccnew} live +valid {pkey}     -> filter removes the wedge
```

**It is nonetheless rejected, because an invalid index can still enforce.** `indisready` and
`indisvalid` are different facts, and a cancelled rebuild leaves `indisvalid=false` with
`indisready=**true**` -- the index is not used for queries but *is* maintained by writes. Executed
on a lab table, isolating index semantics from the SEC-7 controls:

```
(i)  indisvalid=false, indisready=true   (the _ccnew shape)
     INSERT a duplicate -> ERROR: duplicate key value violates unique constraint "cap7_ix"
(ii) indisvalid=false, indisready=false  (the K-F shape)
     INSERT a duplicate -> INSERT 0 1
```

A filter on validity would therefore hide a **live, write-blocking object** on a protected
relation -- which is the harm `CREATE UNIQUE INDEX ... ((1))` causes and which D40 blocks as one of
its own attack forms. It would have bought R24's convenience by giving up a real protection, and
nothing in the definition-set comparison would have shown it. **This also settles R24's framing:
the wedge a cancelled rebuild causes is not merely inconvenient -- the leftover genuinely
participates in writes, so D40 has reason to refuse it, and R24 stands as written.**

**Decision: an index-validity branch is added beside D40's existing trigger-enablement branch. The
recorded referent and the comparison are untouched.**

D40 already answers exactly this question for triggers -- a set comparison for *which* triggers
exist, plus a separate branch for whether they are *in force*
(`provision_test_roles.sh:761-763`, `tgenabled <> 'O'`). `indisvalid`/`indisready` is to an index
what `tgenabled` is to a trigger, and the shipped code has the pattern already. Illustrative only:

```sql
IF EXISTS (SELECT 1 FROM pg_index ix2 WHERE ix2.indrelid = rel.objid
                                        AND NOT (ix2.indisvalid AND ix2.indisready)) THEN
  RAISE EXCEPTION '... protected relation "%" (objid %): one of its indexes is not valid and ready',
    rel.identity, rel.objid;
END IF;
```

- **No schema change, no recorded-column change, no new declared literal.** `index_defs` keeps its
  D50 meaning exactly, `requiredProtectedRelationStates` is untouched, and D49's second withdrawal
  condition is not engaged. **R23's coordinated-edit surface does not grow**, which the filter
  design would also have achieved but only by giving up the protection above.
- **D47 gains the same assertion** on the declared indexes, so `screening-ledger status` reports the
  state rather than only the next DDL statement -- the half that matters, since K-F's consequence
  is read at verification time.
- **`LatestAnchor` gains a deterministic tiebreaker.** `postgres.go:955` orders
  `ORDER BY sequence DESC LIMIT 1` with nothing to break a tie, which is unreachable while the
  primary key is in force and is what turns K-F into selection non-determinism rather than a stable
  refusal. Adding a total order costs nothing and removes a run-to-run difference from a
  verification path.

**Executed, in full: the same battery against the shipped code and against the prototype.** Built by
adding the branch above to `sec7_protect_ddl_objects()` -- everything else unchanged -- against the
real provisioned schema, each attempt from a pristine `TEMPLATE` clone.

| Attempt | role | shipped | prototype |
|---|---|---|---|
| `UPDATE pg_index SET indisvalid=false, indisready=false` then any DDL | superuser | **undetected** | **BLOCKED, names the relation** |
| `REINDEX INDEX CONCURRENTLY ..._pkey` | superuser | healthy | **healthy** |
| `REINDEX TABLE CONCURRENTLY` (both protected relations) | superuser | healthy | **healthy** |
| `REINDEX SCHEMA CONCURRENTLY public` | superuser | healthy | **healthy** |
| `REINDEX DATABASE CONCURRENTLY` | superuser | healthy | **healthy** |
| `REINDEX INDEX` / `REINDEX TABLE` (plain) | superuser | healthy | **healthy** |
| `VACUUM FULL` / `CLUSTER` | superuser | healthy | **healthy** |
| `DROP TRIGGER ..._immutable` | `owl_ledger_ddl` | blocked D34 | **blocked D34** |
| `ALTER TABLE ... DISABLE TRIGGER ALL` | `owl_ledger_ddl` | blocked D34 | **blocked D34** |
| `ALTER TRIGGER ... RENAME TO` | `owl_ledger_ddl` | blocked D34 | **blocked D34** |
| `DROP OWNED BY owl_ledger_ddl` (plain and `CASCADE`) | `owl_ledger_ddl` | blocked D34 | **blocked D34** |
| `CREATE RULE ... DO INSTEAD NOTHING` | `owl_ledger_ddl` | blocked D40 | **blocked D40** |
| `CREATE TEMP TABLE ... INHERITS` | `owl_ledger_ddl` | blocked D40 | **blocked D40** |
| `CREATE TRIGGER ... ON anchor` | `owl_ledger_ddl` | blocked D40 | **blocked D40** |
| `CREATE OR REPLACE FUNCTION screening_ledger_reject_mutation()` | `owl_migrator` | blocked D34 | **blocked D34** |
| `ALTER INDEX ..._pkey RENAME` | superuser | blocked D50 | **blocked D50** |
| `CREATE INDEX` (plain) on anchor | superuser | blocked D50 | **blocked D50** |
| `CREATE POLICY ON anchor` | superuser | blocked D40 | **blocked D40** |
| `DROP TABLE anchor CASCADE` | superuser | blocked D34 | **blocked D34** |
| unrelated `CREATE TABLE` / `CREATE OR REPLACE FUNCTION` | `owl_migrator` | ok | **ok** |
| `CREATE VIEW` over a protected table | superuser | ok | **ok** |
| `CREATE INDEX` on `screening_ledger_event` (unprotected) | superuser | ok | **ok** |
| `REINDEX TABLE CONCURRENTLY screening_ledger_event` (unprotected) | superuser | ok | **ok** |
| `CREATE INDEX CONCURRENTLY` on `screening_ledger_event` (unprotected) | superuser | ok | **ok** |

**D50 is entirely preserved**: every legitimate `CONCURRENTLY` form still completes and leaves the
database healthy, so the new branch does not fire transiently during a rebuild -- the collateral
question that would have re-introduced J-A. Every prior CAP's attack form is still blocked, and
every collateral-damage case still passes, including the two `CONCURRENTLY` forms on an unprotected
relation. D37's rule applies verbatim (`0007:2643-2645`): a suite that proves only the blocks has
not proven D65 is safe to install, and the last five rows are why this table has them.

**What D65 is, stated so it is not read as more.** It is a **detector**, not a preventer: the
duplicate `INSERT` K-F enables still succeeds at the DML layer, and the invalidated index is
reported on the next DDL statement and by the next `verify`. Reaching the state requires direct
catalog DML, which requires the bootstrap superuser, so the residual terminates where R12/R17 put
every other one. It is fixed anyway on the H-E standard the ADR has now used six times: a claim the
recorded state makes about its referent that is true of the rendering and not of the property that
matters.

---

### D66. K-G (LOW): the cross-cluster procedure, corrected and executed

D56 point 4 added a cross-cluster precondition to
`docs/operations/sec7-database-copies.md`. CAP #6 found the resulting procedure cannot be completed
as written. All three defects were reproduced at this commit.

**Defect 1 -- the `create-roles` snippet carries no connection parameters.** The snippet (`:42-46`)
sets `PGSUPERUSER` and `PGSUPERPASSWORD` and nothing else, while the `grant-ddl-ownership` snippet
directly below it (`:50-53`) sets `PGHOST`, `PGPORT` and `PGDATABASE`. The script's defaults are
`localhost`, `5432`, `owl_ci` (`scripts/ci/provision_test_roles.sh:33-37`), and the document's own
warning about exactly this hazard (`:56-58`) is attached to the snippet that already has them.
Copy-pasted literally by a DR operator it targets their own server on 5432, or -- with host and
port supplied but the database default left alone -- fails on a fresh cluster:

```
PGHOST=localhost PGPORT=55441 ... ./scripts/ci/provision_test_roles.sh create-roles
  -> psql: error: ... FATAL:  database "owl_ci" does not exist
```

**This audit deliberately did not execute the unset form**, because doing so would run `CREATE ROLE`
and `GRANT ALL ON SCHEMA public` against the developer's own PostgreSQL server on 5432. The hazard
is established by the script's defaults and the transcript above; it does not need to be
demonstrated destructively, and a design pass that demonstrated it that way would be making the
document's own mistake.

**Defect 2 -- supplying the restored database does not fix it.** `create-roles` runs
`GRANT ALL ON SCHEMA public TO owl_migrator` (`provision_test_roles.sh:69`) in `PGDATABASE`, and a
restored database refuses every DDL statement:

```
PGDATABASE=owl_dr_noroles ... create-roles
  -> ERROR: ADR-0007 Addendum 5 D46: protected relation "public.screening_ledger_anchor"
            (registry objid 16914) no longer exists. This database is a copy or restore ...
```

**Defect 3 -- the ordering is wrong.** The document explains the role requirement as a precondition
of `grant-ddl-ownership`. It is a precondition of the **restore**:

```
restore into a role-less cluster                  -> 81 errors
  psql:...:32: ERROR:  role "owl_migrator" does not exist
same restore with the four owl_* roles created first -> 0 errors
```

**Decision: the document states the precondition where it belongs, names the database to run
`create-roles` against, and carries connection parameters on every snippet.**

- **The roles are created before the restore**, and the section says so in that order, with the
  81-error failure named as what happens otherwise. Roles are cluster-wide, not per-database, which
  is why this is possible at all and which the document should state.
- **`create-roles` is directed at `PGDATABASE=postgres`** -- or any un-restored database on the
  target cluster -- because the subcommand performs a schema grant in whatever database it connects
  to, and the restored one refuses DDL. This is the invocation the document never names.
- **Every snippet in both procedures carries `PGHOST`/`PGPORT`/`PGSUPERUSER`/`PGSUPERPASSWORD`**,
  and the defaults warning moves above the first snippet rather than below it, so it is read before
  the command it protects. D56 point 3 already did this for the bricked-restore procedure's `psql`
  lines; this extends it to the one snippet that was missed.

**The corrected procedure is tested, not described**, to the standard D48 set and D52 followed, and
on a genuinely separate cluster -- the shape the section's own title invites and which no prior
record had executed before CAP #6:

```
step 1  PGHOST=localhost PGPORT=55441 PGDATABASE=postgres ... create-roles
        -> PASS: owl_migrator, owl_app, owl_ledger_anchor, and owl_ledger_ddl provisioned
step 2  pg_dump <source cluster> | psql <target cluster, owl_dr2>      -> 0 errors
        restored database is bricked, as expected:
        ERROR: ADR-0007 Addendum 5 D46: ... no longer exists. This database is a copy or restore ...
step 3  ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE  -> ALTER EVENT TRIGGER
step 4  PGDATABASE=owl_dr2 ... grant-ddl-ownership                     -> 3 PASS lines
step 5  both event triggers = A ;  owl_migrator CREATE TABLE           -> ok

enforcement genuinely live on the DR copy:
  [owl_ledger_ddl] DROP TRIGGER screening_ledger_anchor_immutable
      -> ERROR: ADR-0007 Addendum 3 D34: screening_ledger_anchor_immutable on public... is protected
  [owl_ledger_ddl] REINDEX INDEX CONCURRENTLY screening_ledger_anchor_pkey
      -> ERROR: permission denied for index screening_ledger_anchor_pkey     <- D51's revoke survived the restore
  binding rebound: 7678770394798010976/16937 owl_dr2
```

---

### D67. Test ownership and pre-declared withdrawal conditions

The specific shape the implementation must satisfy, so nothing weaker can be claimed to discharge
this addendum -- the standard D20 (`0007:1293-1338`), D26 (`0007:1874-1885`), D37
(`0007:2623-2662`), D42 (`0007:3455-3523`), D49 (`0007:4237-4307`) and D58 (`0007:5231-5321`) set.

**Every test below must fail before its change, per CLAUDE.md rule 5.** Where a CAP #6 transcript
exists the test reproduces that transcript, not a paraphrase. Several assertions are stated as
"must pass today and fail after" -- deliberately, per D42's note (`0007:3461-3465`): for these
findings the current behaviour is *acceptance*, so a test asserting only the post-fix refusal
cannot distinguish a working fix from a test that never exercised the path.

1. **D60.** `TestProvisioningStateDetectsMaintainGrantToAnyRole` (pgx): assert
   `CheckProvisioningState` returns `Provisioned=true Reason=""` **today** after
   `GRANT MAINTAIN ON screening_ledger_anchor TO owl_migrator` by `owl_ledger_ddl`, and a
   specifically named failure after. Table-driven over the routes D59 established: a direct grant
   to a third role, a grant to `PUBLIC`, the self-re-grant D58 test 3 already covers (which must
   keep passing), and **membership in `pg_maintain`**, which is the route a raw ACL scan would miss.
   Plus the end-to-end limb: `owl_migrator` cancels a `REINDEX ... CONCURRENTLY` and the database
   wedges, asserting the SQLSTATE rather than inferring it. Plus the **positive** that stops the
   check being over-tightened: a clean provisioned database, and specifically a database on which
   the predefined role `pg_maintain` exists and is untouched, returns `Provisioned=true` -- the
   assertion that would fail if anyone implemented the naive "no non-superuser role" form.
2. **D61.** `TestProvisioningStateDetectsPrivilegeGrantToUndeclaredRole` (pgx): table-driven over
   the eight table privileges and both protected relations, asserting the declared five-row matrix
   is accepted and that a grant to any role outside it is a named failure -- including the
   column-level routes D39 established, so D39 is proven un-regressed rather than assumed. Plus the
   **missing-privilege** direction: revoking `owl_ledger_anchor`'s `INSERT` is equally a failure.
3. **D62.** `TestGrantDdlOwnershipRefusesToRecordUndeclaredState`: reproduce CAP #6 §7.5's exact
   laundering -- superuser `CREATE INDEX CONCURRENTLY`, then the operator document's recovery
   verbatim -- asserting it **succeeds today** with the attacker's index in `index_defs`, and
   refuses after, naming the index. **Plus the two positives that make it safe to install**: a
   genuine `pg_dump | psql` restore re-provisions successfully (the I-A recovery path must keep
   working, and it is the reason this shape was chosen over a live-state comparison), and a
   first-ever `grant-ddl-ownership` run on a freshly migrated database succeeds. A suite that proves
   only the refusal has not proven D62 is safe.
4. **D63.** `TestD63DiagnosticOrdersByEvidence` (pgx): the composite state above -- one relation
   drifted, the other absent -- asserting the **absent** relation is named, and asserting
   determinism against a physically reversed heap order, which is the check CAP #6 performed and
   the shipped D54(b) test does not.
5. **D64.** `TestD64UnreadableBindingReportsFourthMessage` (pgx): both K-E states -- a renamed
   column and a binding replaced by a raising view -- each asserting a bare catalog error escapes
   **today** and a named SEC-7 diagnostic after. Plus D54's existing negatives retained unchanged
   (absent table, zero rows), and **the passing-path negative**: a raising binding on an otherwise
   healthy database leaves every DDL statement succeeding, which is the property that keeps the
   handler off the hot path.
6. **D65.** `TestD65IndexValidityIsAssertedAndConcurrentRebuildStillSucceeds` (pgx): CAP #6 §7.10's
   exact `UPDATE pg_index`, asserting `Provisioned=true Reason=""` and healthy DDL **today** and a
   named failure from both D40 and D47 after. **Plus every D50/D40/D34/D26 form unchanged**,
   **plus** all five `REINDEX ... CONCURRENTLY` forms asserted still healthy -- the collateral case
   that would re-introduce J-A if the branch fired transiently -- **plus** the collateral-damage set
   including both `CONCURRENTLY` forms on an unprotected relation and `CREATE VIEW` over a protected
   one. Plus a unit-level assertion that an `indisvalid=false, indisready=true` unique index still
   rejects a duplicate, which is the fact that refutes the filter design and which a later reader
   will otherwise re-derive.
7. **D66.** The cross-cluster procedure is executed, not described: a test or a scripted check that
   creates the roles on a target cluster, restores, recovers, and asserts enforcement is live on the
   copy. If a second cluster is impractical in CI, the ordering assertion (roles before restore)
   must at minimum be a scripted check, and the PR says which form shipped.

**Withdrawal conditions, declared now rather than decided after the fact:**

- **If D65's collateral-damage cases fail against the real schema** in a way the lab did not
  reproduce -- most plausibly around SEC-1's RLS migrations or
  `db/rollback/014_tenant_isolation_down.sql`, the same places D37, D42 and D58 named -- D65 falls
  back to asserting index validity in **D47 only**, leaving D40's runtime branch out. That fallback
  is strictly worse and must be recorded as such: it detects K-F at verification time and not at
  DDL time, so a drifted database keeps running until someone runs `verify`.
- **The validity *filter* must not be adopted as a simplification of D65.** It is the design this
  section was expected to reach and it is refuted above by execution: an
  `indisvalid=false, indisready=true` index still enforces uniqueness, so filtering hides a live
  write-blocking object. A later reader who rediscovers the filter should find this paragraph
  before implementing it.
- **D60 must not be implemented as "no non-superuser role holds `MAINTAIN`".** `pg_maintain`
  reports true on a correctly provisioned database, so that form fails closed on a healthy system
  and would be "fixed" by weakening it. The exclusion is `oid >= 16384`, and D67 test 1's positive
  exists to make the naive form fail loudly.
- **If D61's declared matrix cannot be stated as a stable literal** for both protected relations in
  the shipped configuration, the implementation stops and this addendum is amended rather than
  shipping a matrix covering some privileges and not others -- a check that runs on part of its
  referent is the shape of every finding in this document. D60 is unaffected by this condition,
  since an empty-set assertion carries no literal.
- **D63's two halves ship together.** Reordering the loop without correcting the document leaves
  the prose asserting "not a copy" from eight branches that still do not read the binding;
  correcting the document without reordering leaves the masking.

**Prior addenda's pre-declared withdrawal conditions remain correctly un-triggered**, re-verified
against what *this* addendum designs rather than inherited from CAP #6's confirmation. D50 and D51
shipped together and neither is reopened. D50's collateral-damage cases pass with D65's branch
installed, so Addendum 6's "record both `index_oids` and `index_defs`" fallback is **not** required
and **must not** be adopted. D51's revoke was not found to break any legitimate operation, and D60
widens it rather than withdrawing it. The instance binding is still not a gate -- D64 reads it
strictly less confidently than before, never more, and D63 declines to add readers. D47's
clean-state positive is unaffected: D65 adds an assertion beside its comparison rather than
changing the recorded column, so D49's second condition is not engaged. D46 is not split from D45.
D40's collateral-damage cases pass, so Addendum 4's `pg_depend` fallback is not required. D38(a)
and D38(b) remain shipped together.

---

### New accepted risks

**R27 -- the privilege enumeration is a point-in-time observation, not an interception.** D60 and
D61 report the set of privilege holders at the moment `verify` runs. `GRANT` reports `objid = NULL`,
so D34 cannot see it -- the residual Addendum 3 recorded
(`scripts/ci/provision_test_roles.sh:671-673`) and CAP #4, CAP #5 and CAP #6 each re-confirmed --
and no mechanism in this document observes a capability that is granted, used, and revoked between
two verification runs. The window is therefore bounded by verification cadence, which joins anchor
cadence (R2, R11), policy re-issue cadence (R14) and purge attestation (R16) as a security parameter
this design leaves unscheduled, and which is still §8/D6/D18's separate gate concern. **D60 converts
an unobserved capability into an observed one; it does not convert it into a prevented one**, and
neither it nor D51 may be cited as prevention. CAP #6 §11 point 1(c) asks whether a protected
relation's ACL belongs among D40's recorded properties -- which would close this window by making a
`GRANT` itself a recorded-state divergence. **It is not adopted here**, and the reason is stated so
it is not read as an oversight: `GRANT` is not DDL that any event trigger fires on, so an ACL
column in `sec7_protected_relation` would be compared only on the *next unrelated* DDL statement,
making an unrelated statement fail for a change it did not make -- R18's blast radius on a new
axis, and a worse trade than the observation D60 buys. The question is genuinely open and belongs to
an eighth addendum if the cadence gate ever lands.

**R28 -- `CheckProvisioningState` is blind to live index drift, and D62(b) inherits that.**
`protectedRelationStateReason` filters the live side of its index comparison to the declared index
names (`internal/screeningledger/postgres.go:569`), so an *undeclared* live index -- an attacker's,
or a cancelled rebuild's `_ccnew` -- is never in the set it compares, and the check reports
`Provisioned=true Reason=""` on a database whose every DDL statement is failing. This is measured,
not inferred (drift note 1), and it falsifies CAP #6 §7.4's own account of the wedged state. It is
**accepted rather than closed**, for a reason D47 already argued: the filter exists so that a
*rewritten recording* fails whether the recorded OID is fabricated, stale, or belongs to a real but
undeclared object (`0007:4121-4126`), and widening the live side to all indexes would make D47
report live drift as a recording error, conflating two states D47 was written to separate. What
closes the operational consequence is D62(a) -- the recovery refuses to record the undeclared object
in the first place -- and what narrows it is D65, after which an invalid leftover is reported by
D40 and D47 alike. **The residual is that `screening-ledger status` on a wedged, un-laundered
database still reports clean**, and D62(b)'s required-first-step is therefore a second gate and not
the mechanism. Recorded so a later reader does not cite the status check as sufficient.

**R29 -- the coordinated-edit surface grew by one literal, and R23's aggravating property is
unchanged.** R23 (`0007:4331-4340`) records that the controls are split across `db/migrations/`,
`SchemaSQL`, `provision_test_roles.sh`'s registry populations and row-count assertions, and
`postgres.go`'s literal declarations, with nothing cross-checking them. D60 adds none -- an
empty-set assertion has no literal to drift. D61 adds `requiredTablePrivilegeHolders`, the fifth
such declaration. D62 adds no new literal, reusing `requiredProtectedRelationStates`, which is why
that shape was chosen over a separate declaration in the script. D65 adds none. The mitigating
property is unchanged and is the reason the arrangement survives: **every one of those assertions
fails closed.** The aggravating property is unchanged too, and §10.3's first risk -- that the
controls have no single owner -- is not addressed by this addendum and is not claimed to be.

### Staging

Same shape and reason as §8 and the six prior addenda (`0007:1397-1414`, `0007:2038-2058`,
`0007:2694-2716`, `0007:3566-3586`, `0007:4342-4367`, `0007:5360-5384`): each stage independently
reviewable and independently provable. Ordered by dependency rather than severity.

1. **This addendum**, merged before any code (CLAUDE.md rule 7).
2. **Stage J1 -- the quantifier.** D59, D60 and D61 together. The HIGH, and the only stage that
   changes what a security check asserts. One stage rather than three because all three edit
   `checkProvisioningState` and the provisioning script's postconditions, and splitting them would
   produce conflicting versions of the same function -- the reasoning Addendum 4's staging used for
   D39 and D41 (`0007:3579-3582`). D60's positive (a clean database with `pg_maintain` present
   still passes) is a shipping requirement, not a nicety.
3. **Stage J2 -- the referent and the recorder.** D65 then D62, in that order and in one stage.
   D65 changes what counts as a drifted index, and D62's precondition is a comparison over the same
   declared state; shipping D62 first would mean writing the precondition twice. D65's
   collateral-damage cases -- every `CONCURRENTLY` form still healthy -- are a shipping requirement
   and its withdrawal condition is discharged or invoked here.
4. **Stage J3 -- the diagnostics.** D63 and D64, sequenced after J2 because D62(b) edits the same
   two operator-document sections D63 corrects, and because both touch the `RAISE` sites and the
   branch structure J2 has just changed.
5. **Stage J4 -- the DR procedure.** D66. Blocks nothing, and is therefore sequenced last and
   explicitly **not** droppable -- D23 was sequenced last on the same "blocks nothing" reasoning and
   CAP #2 rated the resulting gap HIGH, a lesson Addendum 5's staging recorded
   (`0007:4348-4354`), Addendum 6 repeated (`0007:5377-5380`), and this addendum does not un-learn.
6. **`SECURITY.md` and `README.md` language.** R3's rule unchanged. `README.md:93-97`'s
   requalification notice stays until every stage above has landed and its reproduction passes.
   CAP #6 §9 re-confirmed that nothing in PR #153 or #154 re-asserted the guarantee; that must
   remain true through this addendum as well.

**SEC-7 does not close on this addendum, and for the third consecutive time the reason is not a
forgery.** §8's closing condition -- "a deliberately forged chain fails a CI run that nobody chose
to invoke" -- is met in the CI sense by `d20_exploit_test.go` and, since D23, in the operational
sense too, and CAP #6 found no bypass of any limb of the invariant. What remains open is a
capability the controls do not **observe** rather than one they fail to block: an owner can move a
maintenance privilege to a role inside the adversary set in one statement, and every mechanism in
the system reports the result as `Provisioned=true Reason=""`. That is a smaller and different
barrier than the six that preceded it, and D59 through D61 are the whole of it. The closing
sentence stands and now has a seventh addendum behind it.

### Addendum 7 summary

- **CAP #6's verdict is QUALIFIED, not PASS, for the sixth consecutive audit -- and for the third
  consecutive audit with no forgery bypass.** Seven findings remain, one HIGH, and five of the seven
  require no adversary at all. D31's scoping principle, Addendum 4's referent principle,
  Addendum 5's population principle and Addendum 6's atomicity principle all held; this addendum
  reopens none of them, and D50 in particular is left entirely intact.
- **The class is a fourth part of a control's specification, not a seventh turn of the same screw.**
  Addendum 4 fixed referents; Addendum 5 fixed populations; K-A is a control whose referent and
  population are both right and whose **quantifier** is a literal role name. The principle: a
  capability removed and a capability asserted-absent must be quantified over the same population,
  and where that population is a set of roles it is enumerated from the catalog at check time,
  never written down as a name.
- **The design is D59-D67.** The quantifier principle with its PostgreSQL support established by
  execution (D59); the `MAINTAIN` assertion as a closed set over the live role population, asserted
  empty because the baseline was measured empty (D60); the sweep, with D39's probes re-quantified
  against a measured five-row matrix and D41 part three argued **not** to be this shape (D61); a
  recovery procedure that may no longer record what the repository never declared (D62); the
  relation loop ordered by evidence and the operator document's "not a copy" overclaim corrected
  (D63); J-D's own resolution applied to the referent D54(c) narrowed one step too far, with D54(c)'s
  stated reason withdrawn (D64); `indisvalid`/`indisready` named in the referent set beside D40's
  existing trigger-enablement branch, with the filter design refuted by execution (D65); the
  cross-cluster DR procedure corrected and executed on a second real cluster (D66); and the proof
  obligations with pre-declared withdrawal conditions (D67).
- **This design pass executed its mechanism assumptions, and the execution refuted the fix this
  addendum was expected to reach and falsified one of the CAP record's own claims.** An
  `indisvalid=false, indisready=true` index **still enforces uniqueness**, so filtering invalid
  indexes out of D40's comparison would have hidden a live write-blocking object -- the obvious K-F
  fix, rejected with its transcript. `CheckProvisioningState` returns **`Provisioned=true
  Reason=""`** on the wedged database CAP #6 §7.4 says it refuses, because D47's live side is
  filtered to declared index names. The instance-binding read is **not** on the passing path, so
  D54(c)'s stated reason for rejecting an exception block does not hold and a shape guard alone is
  provably insufficient against a well-shaped raising view. Also confirmed by execution:
  `pg_maintain` is the one predefined role reporting `MAINTAIN = true`, which forces the `oid >=
  16384` discriminator; `pg_roles` is fully readable by `owl_migrator` with no new grant;
  `has_table_privilege` expands role membership and accounts for `PUBLIC` and raised on none of 160
  (role, privilege) pairs; the enumeration costs 0.0062 ms and its column form 0.0145 ms; the
  evidence-ordered loop stays deterministic under a physically reversed heap order; and the
  corrected cross-cluster restore completes with 0 errors where the document's order produces 81.
- **Three risks are recorded** rather than designed away: the enumeration is an observation and not
  an interception, with the ACL-as-recorded-property alternative evaluated and declined (R27);
  `CheckProvisioningState` is blind to live index drift and D62(b) inherits that, which is why
  D62(a) is the mechanism (R28); and the coordinated-edit surface grew by one literal (R29).
- **This addendum revises no prior decision.** D1-D7, D8-D20, AR7, D21-D30, D31-D37, D38-D42,
  D43-D49 and D50-D58 stand. R1-R26 stand. Two sentences are withdrawn as narrower or less accurate
  than what the code does -- R25's "to itself" (`0007:5340-5344`) and D54(c)'s subtransaction
  rationale (`0007:5079-5083`) -- explicitly and in D60's and D64's own words; neither substantive
  decision is disturbed, and D60 and D64 are what make the withdrawn sentences true of the
  populations they describe.

**Audit basis commit:** `a653941af734dd7e5384d8cda3228bcb96c9811d`

Every file:line citation in this addendum was verified against that tree -- the same commit CAP #6
was produced against, so no drift separates the audit from this design. For a CAP record covering
the implementation of this addendum, use the tip of whichever stage PR is under audit, not this
value.

## Addendum 8: the name as terminating literal -- CAP #7's demonstrated forgery of a retention claim, and the remediation design (2026-08-28)

- **Status:** Proposed
- **Trigger:** a seventh Composition Audit Program record produced against the implemented
  Addendum 7 (`docs/backlog/sec-7-cap-record-1033860.md`, adversarial posture, audit basis commit
  `1033860599b56a6676cf8cb9ce163c3e35eea3d1`) returned **QUALIFIED, not PASS** for the seventh
  consecutive audit -- and, unlike the previous three, **it demonstrates a forgery**. Nine findings
  remain. **SEC-7 is not closed.**
- **What CAP #7 confirmed and this addendum does not disturb.** D65 works exactly as specified on a
  declared, present index, and all eleven legitimate maintenance operations still complete and leave
  the database healthy, so J-A is not re-introduced. D66's script completes end to end on a
  genuinely second cluster. D63's four diagnostic messages are all reachable, distinguishable and
  correct. D64 is live and behaved as specified. The suites are unregressed at 103 top-level PASS,
  0 SKIP, 0 FAIL in `internal/screeningledger`, and `go test -race -count=1 ./...` exits 0 across 98
  packages. The baseline was re-confirmed byte-identical during this design pass (below).
  **D31's scoping principle, Addendum 4's referent principle, Addendum 5's population principle,
  Addendum 6's atomicity principle and Addendum 7's quantifier principle all held**, and this
  addendum reopens none of them.
- **Scope:** a pure addition. Nothing above this section is edited -- not D1-D7, not D8-D20, not
  AR7, not D21-D30, not D31-D37, not D38-D42, not D43-D49, not D50-D58, not D59-D67, not §3.4, §6.1
  or the D19 correction note, not R1-R29. Decision numbering continues at **D68**; risk numbering at
  **R30**. Where a prior decision's *text* is narrower than what the code does, the new decision
  says so in its own words -- the convention AR7 established for R7 and every addendum since has
  followed.
- **Verification basis:** every `file:line` below was re-derived from the working tree at
  `1033860599b56a6676cf8cb9ce163c3e35eea3d1` rather than copied from the CAP record or from a prior
  addendum.
- **This design pass executed its mechanism assumptions, as Addendum 3 established and Addenda 4, 5,
  6 and 7 held to -- and this time the execution refuted the fix this addendum was expected to
  reach, and corrected the CAP record's own account of its setup.** A disposable PostgreSQL 17.11
  cluster was built on port 55480 and provisioned with the **real** schema in
  `.github/workflows/ci.yml:141-235`'s exact order (`create-roles`, all seventeen
  `db/migrations/*.sql` as `owl_migrator`, `grant-app-privileges`, `grant-ddl-ownership`), baseline
  confirmed at thirteen `sec7_protected_object` rows, two `sec7_protected_relation` rows, one
  `sec7_instance_binding` row, both event triggers `evtenabled='A'`, and twenty roles of which
  `pg_maintain` (oid 6337) is the only predefined role reporting `MAINTAIN=true` -- byte-identical
  to CAP #7 §7.0's recorded baseline. Every destructive probe ran against a
  `CREATE DATABASE ... TEMPLATE` clone. The cluster was torn down. The developer's own server on
  port 5432 was never contacted. The three results that changed the design:
  1. **`pg_get_triggerdef` is `search_path`-SENSITIVE**, unlike `pg_get_indexdef`. The obvious
     D69 -- D50's move applied to triggers -- would have shipped a control blind to the very
     substitution it was written to catch (D69).
  2. **`pg_has_role(..., 'MEMBER')` does model `SET ROLE` reachability**, transitively and through
     both `NOINHERIT` and `WITH INHERIT FALSE`, so L-A(ii) needs no bespoke `pg_auth_members`
     traversal (D73).
  3. **The attribution data L-B forges is already MACed under `K_chain` and committed under
     `K_anchor`**, and D32's condition 3 simply does not read it -- which makes an independent
     tombstone MAC the wrong answer rather than a deferred one (D70).

---

### Drift found while writing this addendum

Recorded rather than silently corrected, the convention §3.4, §6.1, `0007:717-720`,
`0007:1474-1490`, `0007:2141-2160`, `0007:2804-2826`, `0007:3689-3712`, `0007:4476-4498` and
`0007:5500-5554` set.

1. **CAP #7 §7.2's stated setup for L-B understates its own precondition by one statement, and the
   error overstates how close the attack is to the documented recovery.** The record's transcript
   shows `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE` -- annotated
   "(step 1 of the documented recovery)" -- followed directly by
   `DROP TRIGGER screening_ledger_retention_tombstone_immutable`. Re-executed against the real
   provisioned schema, that `DROP TRIGGER` is **refused**, because a drop fires `sql_drop`, which is
   `sec7_protect_ddl_objects_on_drop`'s event, and that trigger is still `ENABLE ALWAYS`:

   ```
   [only _on_alter disabled, exactly as docs/operations/sec7-database-copies.md:187 instructs]
   DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone;
     -> ERROR: ADR-0007 Addendum 3 D34: screening_ledger_retention_tombstone_immutable on
               public.screening_ledger_retention_tombstone (objid 16468) is protected by a
               superuser-only DDL event trigger and cannot be dropped

   [both disabled -- the state the transcript actually requires]
   DROP TRIGGER ...  -> DROP TRIGGER
   ```

   The finding is **undiminished**: the forgery works, it is undetectable afterwards, and D62(a)
   still does not refuse the substituted object. What changes is one clause of its framing. The
   setup is not "the documented recovery window"; it is that window **plus a second
   `ALTER EVENT TRIGGER ... DISABLE` the operator document never instructs**. This is recorded
   because L-B's severity argument must not rest on a precondition the code does not actually have
   -- and because D34 deserves the credit: it blocks the drop in the state the document does create.
2. **CAP #7 L-B's `cap7_noop` variant is the weaker of two substitutions, and only the stronger one
   refutes the obvious fix.** Rebinding to a function with a *different name* is caught by any
   comparison that looks at the function at all. Rebinding to a no-op with the **same name in a
   different schema** is not, and it is what forces D69's shape. The CAP tried the first; this pass
   executed the second.
3. **Addendum 7's `file:line` citations resolve against `a653941`, not against this tree.** PR #156
   moved several: `requiredProtectedRelationStates` is `internal/screeningledger/postgres.go:501-522`,
   `protectedRelationStateReason` is `:531-593`, the D60 enumeration is `:638-655`, D61's matrix
   literal is `:696-702`, D62(a)'s refusal loop is `scripts/ci/provision_test_roles.sh:568-604` and
   D40's runtime index comparison is `:870-873`. Expected, not a defect.

---

### Addendum 8 context: the referent, the population and the quantifier were right, and the declaration was a name

Addendum 1 diagnosed the original's structural error as fixing instances rather than causes
(`0007:1494-1497`). Addendum 2 named its findings as one class -- "a control whose installation is
asserted rather than checked, by the party the control constrains" (`0007:1499-1500`). Addendum 3
sharpened it to "a control that decides what to protect, or what to protect against, by listing
members of an open set" (`0007:2172-2173`) and produced D31. Addendum 4 sharpened it again to "the
enumeration was fixed and the referent drifted" (`0007:2853-2857`) and produced D40. Addendum 5
moved one axis over -- "the referent is correct and its population was never stated"
(`0007:3742-3746`) -- and produced D43. Addendum 6 moved to a third, the referent a *legitimate*
operation rewrites (`0007:4526-4534`), and produced D50. Addendum 7 moved to a fourth, the
quantifier (`0007:5574-5580`), and produced D60.

CAP #7 §0.1 states what survived all five, and it is right:

> Addendum 4's referent principle, Addendum 5's population principle and Addendum 7's quantifier
> principle are each correct and each was applied to one axis. The defect that survives all three is
> that **the terminating literal is still a name** -- the thing D8 requires to be "something the
> attacker cannot write" is a string, and what it points at is whatever currently bears that string.

Every one of the three highest-ranked findings is that defect:

| Mechanism | The declaration | What the name denotes | Finding |
|---|---|---|---|
| D62(a) launder-refusal | `t.tgname NOT IN (declared)` (`provision_test_roles.sh:579`), `c.relname NOT IN (declared)` (`:584`) | whatever object currently bears the name -- including a no-op | **L-B** |
| D47 recorded-state comparison | `indexNames`, `triggerNames` (`postgres.go:501-522`), live side filtered to them (`:543`, `:548`, `:561`) | the empty set, when nothing bears the name | **L-C** |
| D60/D61 population | `NOT r.rolsuper AND r.oid >= 16384` (`postgres.go:626`) | "predefined" -- a property the discriminator infers from a number | **L-A** |

**The principle this addendum adopts, stated once and applied four times:**

> **A control's declaration must terminate on what an object *does*, not on what it is *called*.
> Where a control declares an object by name, the name is an address and never evidence: the control
> must additionally assert that a live object bearing that name exists, and that it has the
> properties that make it the control it is. And where a control excludes a party, it must exclude
> it by a property it structurally has, never by a range that happens to contain it.**

The load-bearing clause is the last one in the first sentence, and D69 is where it bites hardest.
Addendum 4 already prescribed "a closed set of properties of the object" (`0007:2855-2857`) and D40
implemented exactly that for a *relation* -- `relowner`, `relkind`, both RLS flags, rules,
inheritance, and the trigger, index and policy sets. What no addendum did was ask the same question
one level down, about the objects **inside** those sets. D40 records *which* triggers exist. Nowhere
in this repository is it declared what any of them **does**.

---

### D68. The naming principle, and where PostgreSQL actually supports it

**Decision: where a control declares an object by name, the name locates the object and never
certifies it. Three assertions are required, not one: the named object exists, the named object has
the declared properties, and no undeclared object is present. D62(a) has the third only.**

Three sub-decisions follow, each verified by execution against PostgreSQL 17.11 during this design
pass rather than reasoned from the manual.

**1. `pg_identify_object` is the session-independent spelling of an object's identity, and the
`pg_get_*def` renderers are not.** Executed by OID, so the probe itself introduces no name
resolution, across five `search_path` values:

```
pg_get_indexdef(16920)
  public            -> CREATE UNIQUE INDEX screening_ledger_anchor_pkey ON public.screening_ledger_anchor USING btree (ledger_id, sequence)
  pg_catalog        -> (identical)
  public,pg_catalog -> (identical)
  pg_temp,public    -> (identical)
  pg_catalog,public -> (identical)          <- INSENSITIVE, as CAP #6 established

pg_get_triggerdef(16925)
  public            -> ... EXECUTE FUNCTION screening_ledger_reject_mutation()
  pg_catalog        -> ... EXECUTE FUNCTION public.screening_ledger_reject_mutation()   <- SENSITIVE
  public,pg_catalog -> ... EXECUTE FUNCTION screening_ledger_reject_mutation()
  pg_temp,public    -> ... EXECUTE FUNCTION screening_ledger_reject_mutation()
  pg_catalog,public -> ... EXECUTE FUNCTION screening_ledger_reject_mutation()
```

The table is always schema-qualified in both; the **function** in a trigger definition is qualified
only when `search_path` does not already reach it. This is D55's "one referent, one spelling"
(`0007:5089-5131`) as a property of a *renderer* rather than of a hand-composed join key, and it is
why D69 does not simply repeat D50.

**2. `pg_identify_object` on a trigger's `tgfoid` is readable by `owl_migrator`, needs no new role,
DSN or grant, and does not raise.** The same property D33's, D41's, D45's and D59's facts have
(`0007:2422-2425`, `0007:3404-3406`, `0007:3967-3969`, `0007:5615-5624`), checked rather than
assumed because a check needing a new credential is a check that will be skipped.

**3. A property-based declaration is D40's own shape, not a new one.** D40 compares a closed set of
properties of a *relation* and Addendum 4 argued that case in full (`0007:2853-2865`). D68 applies
the identical reasoning to the objects inside D40's recorded sets. This matters for R23/R29: the
declaration grows, but it grows along an axis this document already committed to, and it introduces
no new *kind* of literal.

**What this principle does not reach, stated rather than left to be discovered.** It is a
**declaration** discipline, not an interception. Nothing here observes a substitution while it
happens -- under T2 the event triggers are disabled by the party performing it, which is the whole
premise of the recovery window. What D68 changes is that the substituted object can no longer be
**recorded as legitimate** afterwards, and can no longer pass verification. R30 states this rather
than letting D69 imply prevention.

---

### D69. L-B (CRITICAL): the trigger referent becomes what the trigger *does* -- and the definition rendering that would have been wrong

**Severity, decided here rather than inherited.** CAP #7 rates L-B HIGH and states explicitly that
"if this project weights 'forgery demonstrated' above 'superuser precondition', L-B escalates to
CRITICAL", leaving the judgement visible rather than resolving it. **This addendum rates it
CRITICAL**, on one ground that is not reachability:

- **It is the first state in seven rounds that is permanently undetectable after the fact.** Every
  other finding in this arc, once reached, leaves evidence somewhere: D40 wedges, D47 reports, D46
  diagnoses, the anchor's MAC catches an in-place rewrite (`anchor.go:34-37`). A forged tombstone
  leaves none. `screening_ledger_retention_tombstone` is
  `(snapshot_sha256, purged_at, operator, reason)`
  (`db/migrations/008g_screening_ledger.sql:7`) with no MAC and no digest, the DDL layer was
  laundered, and no mechanism anywhere retains any record that the row ever read differently.
  "Detected late" and "never detectable" are different kinds of failure, and every prior CRITICAL in
  this document (F-E, G-C, H-A) was rated on an invariant limb being demonstrably false end to end,
  which this is.
- **The counter-argument, recorded rather than resolved silently:** the setup needs the bootstrap
  superuser with **both** event triggers disabled (drift note 1), which is one statement beyond what
  the operator document instructs, and CAP #6 rated K-F HIGH at comparable reachability. A reader
  who weights precondition over detectability should read this as HIGH. This addendum does not,
  because the invariant §1 states -- "no combination of capabilities §2 grants can forge a history or
  **retention** claim" -- is the thing being falsified, and it is falsified silently and permanently.

**The finding, restated from the code.** D62(a)'s two set comparisons are
`t.tgname NOT IN (declared)` (`scripts/ci/provision_test_roles.sh:579`) and
`c.relname NOT IN (declared)` (`:584`). Neither consults what the object *is*.
`requiredProtectedRelationStates` (`internal/screeningledger/postgres.go:501-522`) declares
`triggerNames` and `indexNames` and nothing else, and `protectedRelationStateReason` filters the
live side of every comparison to those names (`:543`, `:548`, `:561`), so both sides of the
comparison are the substituted object. Executed, against the real provisioned schema:

```
[T2] both event triggers DISABLE
     DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone;
     CREATE FUNCTION owl_migrator.screening_ledger_reject_mutation() ... BEGIN RETURN NEW; END
     CREATE TRIGGER screening_ledger_retention_tombstone_immutable
       BEFORE DELETE OR UPDATE ON screening_ledger_retention_tombstone
       FOR EACH ROW EXECUTE FUNCTION owl_migrator.screening_ledger_reject_mutation();

D47's comparison, run verbatim against three databases:
  healthy baseline                          triggersOK=true  indexesOK=true  D65validOK=true
  tombstone guard is a shadowed no-op       triggersOK=true  indexesOK=true  D65validOK=true
  anchor has NO primary key at all (L-C)    triggersOK=true  indexesOK=true  D65validOK=true

[owl_ledger_ddl, non-superuser] UPDATE screening_ledger_retention_tombstone
                                  SET operator='someone-else' WHERE snapshot_sha256='snap-ddd';
  -> UPDATE 1
```

**Investigated and REJECTED: record `pg_get_triggerdef`, which is D50's move applied to triggers.**
This is the design this section was expected to reach, and it is refuted by execution. The
substitution above was rendered by two sessions at the same instant -- the session
`grant-ddl-ownership` runs as, and the session `PostgresSink` connects as:

```
[owl_ci      -- the RECORDER]  ... FOR EACH ROW EXECUTE FUNCTION owl_migrator.screening_ledger_reject_mutation()
[owl_migrator -- the VERIFIER] ... FOR EACH ROW EXECUTE FUNCTION screening_ledger_reject_mutation()
                                                              ^ byte-identical to the legitimate rendering

pg_identify_object('pg_proc', tgfoid, 0)  ->  owl_migrator.screening_ledger_reject_mutation()
                                              (the same value in BOTH sessions)
```

`search_path` is `"$user", public` for both, so a schema named after the *verifying* role makes the
rendering the verifier sees identical to the legitimate one, on a trigger that does nothing.
**A declared-definition comparison would therefore refuse this substitution in the installer and
accept it in the verifier**, which is worse than either outcome alone: the mechanism would appear to
work in the place it is tested and fail in the place it runs. Recording `pg_get_triggerdef` is the
obvious answer, it is what D50 did for indexes, and it is **wrong here for a reason specific to the
renderer**: `pg_get_indexdef` renders no schema-qualified object other than the table, and
`pg_get_triggerdef` renders a function. A later reader who rediscovers the rendering should find
this paragraph before implementing it.

**Decision: the declared trigger referent becomes a closed set of session-independent catalog
properties, and `pg_get_triggerdef` is not among them.**

`requiredProtectedRelationStates` and D62(a)'s cross-language declaration gain, per declared trigger
name, the properties below. Every one was measured on the shipped baseline rather than transcribed:

```
tgname                                            tgtype  tgqual  tgnargs  tgattr  tgenabled  tgfoid identity
screening_ledger_anchor_immutable                     27   NULL         0  {}      O          public.screening_ledger_reject_mutation()
screening_ledger_anchor_no_truncate                   34   NULL         0  {}      O          public.owl_reject_truncate()
screening_ledger_retention_tombstone_immutable        27   NULL         0  {}      O          public.screening_ledger_reject_mutation()
screening_ledger_retention_tombstone_no_truncate      34   NULL         0  {}      O          public.owl_reject_truncate()
```

`tgtype` 27 is `ROW|BEFORE|DELETE|UPDATE`; 34 is `BEFORE|TRUNCATE` at statement level. The bitmask is
a documented, version-stable ABI, which is precisely what `pg_get_triggerdef`'s text is not.

**Each property is load-bearing, and that is measured, not argued.** Three substitutions were
executed, each keeping everything the previous one changed:

| Substitution | `pg_get_triggerdef` | `tgfoid` identity | `tgtype` | `tgqual` | `tgattr` |
|---|---|---|---|---|---|
| rebind to `cap7_noop()` -- CAP #7's own variant | catches | **catches** | misses | misses | misses |
| rebind to a same-named no-op in another schema | **MISSES** | **catches** | misses | misses | misses |
| `WHEN (false)`, real guard function | catches | misses | misses | **catches** | misses |
| `BEFORE DELETE OR UPDATE OF snapshot_sha256`, real function, no WHEN | catches | misses | misses | misses | **catches** |

The last two were executed end to end and both forge successfully today:

```
WHEN (false):        tgfoid=public.screening_ledger_reject_mutation()  tgtype=27  tgqual NOT NULL
                     [owl_ledger_ddl] UPDATE ... -> UPDATE 1
UPDATE OF one column: tgfoid, tgtype, tgqual, tgnargs ALL unchanged; only tgattr moves {} -> {1}
                     [owl_ledger_ddl] UPDATE ... SET operator=..., reason=... -> UPDATE 1
```

**Neither `tgfoid` nor the definition rendering is sufficient alone**, which is why this is a
property set and not a single comparison, and why the "replace, do not supplement" reasoning D39 and
D50 both used does not apply here: those cases had one referent subsuming another. These four
properties are independent, and each is the only one that sees its own row of that table.

**Where it is asserted.** Both places, for D62(a)'s own reason -- the installer and the verifier fail
independently, which is G-A's shape:

- **D62(a)** (`provision_test_roles.sh:568-604`, before the `DELETE FROM sec7_protected_relation` at
  `:605`, so the ordering that makes it a precondition is preserved) refuses to record a relation
  whose declared trigger does not match the declared properties, naming the trigger and the property.
- **`protectedRelationStateReason`** (`postgres.go:531-593`) asserts the same properties, so
  `screening-ledger status` reports the state rather than only the next `grant-ddl-ownership` run.

Executed against the proposed assertion, all five states:

```
shadowed no-op guard                      -> behaviourOK=false   (refused)
WHEN (false)                              -> behaviourOK=false   (refused)
UPDATE OF one column                      -> behaviourOK=false   (refused)
clean baseline, screening_ledger_anchor   -> behaviourOK=true    (accepted)
clean baseline, ..._retention_tombstone   -> behaviourOK=true    (accepted)
```

The last two are the over-tightening positives D37's rule requires: a suite that proves only the
refusals has not proven D69 is safe to install.

---

### D70. L-B, the data half: the retention claim's attribution is adjudicated against the anchored attestation -- and the tombstone-MAC question, answered

D69 closes the DDL route. The brief asks a second and more fundamental question: should
`screening_ledger_retention_tombstone` gain its own integrity mechanism, independent of DDL-level
protection, the way the anchor has via `anchorMAC`? **The investigation produced an answer that is
the opposite of the expected one, and it is stated with the evidence rather than asserted.**

**The attribution data L-B forges is already externally authenticated. Nothing reads it.**
`Store.PurgeExpired` writes the audit entry with the *same* operator and reason it passes to the
definer function:

```go
// internal/screeningledger/replay.go:258
_, err = s.AppendAudit("purge_expired", operator, reason, "", purgeExpiredAuditDetails{SnapshotSHA256: purgedSHA256})
```

`AuditEvent` carries both as first-class fields (`internal/screeningledger/types.go:96-97`),
`hashAudit` MACs the whole marshalled event under `K_chain` (`audit.go:35`), and the anchor commits
`audit_sha256` and `audit_sequence` under `K_anchor` (`anchor.go:34-37`, D11/AR7). So a forged
`operator` or `reason` in the mirror **already contradicts a value the adversary cannot forge**.

D32's adjudication does not look. Condition 3 is:

```go
// internal/screeningledger/postgres.go:1182-1191
`SELECT EXISTS (SELECT 1 FROM screening_ledger_retention_tombstone WHERE snapshot_sha256=$1)`
```

An existence test on one column. `operator`, `reason` and `purged_at` are never read by anything.

**Decision: D32's condition 3 stops being an existence check and becomes a comparison against the
anchored attestation, in both directions.**

- **Forward.** For every adjudicated `PurgeClaim`, the tombstone row's `operator` and `reason` must
  equal the attesting audit entry's `Operator` and `Reason`. `PurgeChecker` returns the row rather
  than a bool. `purged_at` is compared as an ordering bound and never for equality -- the tombstone's
  `clock_timestamp()` and the audit entry's `OccurredAt` are different clocks, and an equality
  comparison there would be a false-failure generator, which is the shape D45 was pre-declared never
  to become.
- **Reverse.** Every tombstone row must correspond to an anchored `purge_expired` attestation. This
  is the set-equality direction D61 established (`0007:5867-5873`), and it closes a route the forward
  comparison structurally cannot: adjudication is driven by the set of snapshots whose **local
  envelope** is marked purged (`store.go:393`), so a tombstone row for a snapshot that was never
  purged locally generates no claim and is adjudicated by nothing. That route is reachable --
  `owl_migrator` holds `EXECUTE` on both `screening_ledger_purge_snapshots` overloads
  (`provision_test_roles.sh:360-361`), so a direct SQL purge writes a tombstone with no audit entry
  at all, and `owl_ledger_ddl` holds `INSERT` on the relation by D61's own declared matrix
  (`postgres.go:700`).

**The tombstone-MAC question, answered: do not add one, because it would be weaker than the
mechanism above rather than stronger.** The reasoning, stated in full because the brief asks for a
real recommendation:

1. **The fact is already covered by two keys.** A tombstone MAC would be a third recording of
   something `K_chain` already MACs and `K_anchor` already commits. Addendum 6 D50 and Addendum 4
   D39 both rejected a second recording of one property for the same reason -- it is a second thing
   to keep in sync -- and H-E is what happens when one of them goes unchecked.
2. **There is no custody domain to put the key in, and that is structural, not economical.** §5.3
   points 1-2 explain why `anchorMAC` works: `K_anchor` is held by a **different role**
   (`owl_ledger_anchor`) in a **different custody domain** from the ledger writer. The tombstone has
   no separate writer identity -- it is written server-side by a `SECURITY DEFINER` function as a
   side effect of a purge `owl_migrator` legitimately performs, which is exactly the reasoning D27
   used to decline a fourth role (`0007:1893-1900`). So a tombstone MAC has two possible homes and
   both fail: the definer function computes it, and the key lives in the database where the
   bootstrap superuser -- the terminus of every residual in this document -- can read it; or the CLI
   computes it and passes it in, and **the constrained role supplies its own evidence**, which is
   G-C's exact refuted shape (`0007:2292-2298`).
3. **A `K_chain`-keyed MAC would be forgeable by the adversary it is aimed at.** §5.2's stated
   residual is a party holding `K_chain`; the mirror-writing adversary §2 admits by name is
   frequently that party. A MAC under the key the attacker may hold adds a step to the forgery and
   does not prevent it -- the argument §5.1 already made about `K_redact`.

**What this recommendation does not close, stated rather than left to an eighth CAP.** D70 makes
retention integrity depend on the **file-side audit chain being present and anchored**. A deployment
that ever needs a retention claim verifiable from the Postgres mirror **alone** -- no ledger
directory, no `K_anchor` cross-check, an auditor reading the database -- gets nothing from D70, and
that case genuinely does need a keyed record in the mirror. **That is a follow-on ADR, not an
addendum item**, and this addendum scopes it honestly rather than pretending otherwise: it
introduces a new key, a new custody boundary and a new writer identity, which is more than an
addendum has ever introduced and more than one should. What such a follow-on would have to cover:
where the key lives and who holds it; whether the tombstone gains a writer role the way the anchor
did in D17; how the MAC is bound to the anchored attestation so the two records cannot be
recombined (D11's problem, one table over); and the migration, which is free today at zero tombstone
rows and never free afterwards. **The register should carry it**, and the re-entry condition is the
one §5.3 set for RFC 3161: the first deployment that screens real traffic, where the mirror is read
independently of the ledger directory. R31 records it.

---

### D71. L-C (HIGH): a declared name must resolve to a live object

**The finding, restated from the code and reproduced.** D62(a) looks only for undeclared *extras*
(`provision_test_roles.sh:579`, `:584`). D56's missing-object guard covers triggers
(`:633-645`) and has no index equivalent anywhere in the script. `requiredSchemaObjects`
(`postgres.go:827-882`) declares relations, triggers and columns -- **never an index**. And D47
filters the live side to declared names (`postgres.go:548`), so when nothing bears the name both
sides are the empty array and the comparison passes vacuously. D65's validity branch (`:559-563`)
is filtered the same way, so the addendum's newest assertion is vacuously true over zero rows too.

Executed, on a `TEMPLATE` clone of the fully provisioned schema:

```
[T2] ALTER TABLE screening_ledger_anchor DROP CONSTRAINT screening_ledger_anchor_pkey;
     grant-ddl-ownership                       -> exit 0
     live indexes on screening_ledger_anchor   -> <none>
     recorded index_defs                       -> {}
     D47's comparison  indexesOK=true  D65validOK=true
[owl_ledger_anchor] INSERT ... ('dupe',9,'aaa',...),('dupe',9,'FORGED',...)   -> INSERT 0 2
```

Addendum 5's population axis, on an empty population.

**Decision: every declared name is asserted to resolve to a live object, in the installer and in the
verifier, and the asymmetry between triggers and indexes is removed.**

- **Installer:** D62(a) gains a missing-declared-**index** precondition, mirroring D56's existing
  missing-trigger loop (`:633-645`) statement for statement, and D56's own loop is extended to the
  declared index names so one mechanism covers both object kinds rather than two half-mechanisms
  covering one each.
- **Verifier:** `protectedRelationStateReason` gains an existence assertion per declared index name,
  placed beside D65's validity branch -- the same filtered query with `EXISTS` instead of
  `NOT EXISTS`. This also repairs D65's vacuity: after D71 the validity assertion can no longer pass
  on a relation with no indexes at all.

Executed against the proposed assertion:

```
anchor with its primary key dropped   -> indexPresentOK=false   (refused)
clean baseline, both relations        -> indexPresentOK=true    (accepted)
```

**Why this does not subsume D69 and must not be read as doing so.** A presence check alone closes
L-C and leaves L-B untouched -- an object bearing the declared name is present in every one of D69's
substitutions. CAP #7 §11 point 1 makes exactly this point, and the two decisions are stated
separately so a later change cannot remove one on the other's strength, the arrangement D41 part
three set for D40 (`0007:3447-3448`).

---

### D72. L-A(i) (HIGH): the predefined-role exclusion becomes an explicit allowlist

**The finding, reproduced from the shipped baseline.** `owl_ledger_ddl` -- a non-superuser, the
owner, the party these controls exist to bind -- moves the capability below the discriminator in one
statement:

```
[owl_ledger_ddl] GRANT MAINTAIN ON TABLE screening_ledger_anchor TO pg_read_all_data;   -> GRANT
relacl: {owl_ledger_ddl=arwdDxt/owl_ledger_ddl, owl_ledger_anchor=a/owl_ledger_ddl,
         owl_migrator=r/owl_ledger_ddl, pg_read_all_data=m/owl_ledger_ddl}
                                          ^ MAINTAIN is literally granted

shipped D60 enumeration (NOT rolsuper AND oid >= 16384)   -> <EMPTY>
```

D59 point 3 chose `oid >= 16384` to avoid a name pattern, on the correct reasoning that
`rolname NOT LIKE 'pg\_%'` is enumeration by inference (`0007:5666-5671`). **The OID range is
enumeration by inference too**: it infers "predefined, therefore structurally exempt" from a number.
D31's answer to a bad pattern was never a range -- it was a **closed set**, and a closed set of
names is what this needed from the start.

**Decision: the discriminator becomes an explicit, declared allowlist of the predefined roles that
structurally carry `MAINTAIN`, and its membership is measured rather than assumed.**

Every role in the cluster was enumerated on the shipped baseline -- sixteen predefined roles, of
which exactly one reports `MAINTAIN = true`:

```
owl_ci  oid 10  super=t  MAINTAIN=t          <- excluded by NOT rolsuper, unchanged
pg_monitor 3373, pg_read_all_settings 3374, pg_read_all_stats 3375, pg_stat_scan_tables 3377,
pg_signal_backend 4200, pg_checkpoint 4544, pg_use_reserved_connections 4550,
pg_read_server_files 4569, pg_write_server_files 4570, pg_execute_server_program 4571,
pg_database_owner 6171, pg_read_all_data 6181, pg_write_all_data 6182,
pg_create_subscription 6304                  -> all MAINTAIN=false
pg_maintain 6337                             -> MAINTAIN=TRUE   <- the only one
owl_migrator 16385, owl_app 16386, owl_ledger_anchor 16387, owl_ledger_ddl 16388 -> false
(20 roles total)
```

So the allowlist is `{pg_maintain}`, and the brief's "confirm this is the only one" is answered by
enumeration rather than by trusting CAP #7's own count. Detection, executed on the L-A(i) state:

```
NOT rolsuper AND rolname <> 'pg_maintain'  ->  pg_read_all_data      (named)
```

**The property D59 established is preserved and re-tested, not discarded.** Excluding the role does
not exclude its members: a normal role granted `pg_maintain` is still named
(`GRANT pg_maintain TO cap8_inh` -> enumeration reports `cap8_inh`), and `pg_maintain` is `NOLOGIN`
by construction, so the exclusion removes a false positive and no true one. **The over-tightening
positive D67 test 1 requires still holds**: a clean provisioned database on which `pg_maintain`
exists and is untouched returns `<EMPTY>`, executed against both the baseline and a `TEMPLATE`
clone.

**Why an allowlist and not simply dropping the exclusion.** Asserting "no non-superuser role holds
`MAINTAIN`" fails closed on a healthy system, which D67's own withdrawal condition already
pre-declares as the form that must not ship (`0007:6438-6441`). The allowlist is the smallest
structure that states *why* the one role is exempt, and it states it as a name the repository
declares rather than a boundary the catalog happens to have.

---

### D73. L-A(ii) (HIGH): "holder" has two senses, and the check asserts both

**The finding, reproduced.** `has_table_privilege` answers with `pg_has_role(..., 'USAGE')`
semantics; `SET ROLE` uses `MEMBER`. A non-inheriting member holds the capability *usably* and
reports false. Executed:

```
CREATE ROLE cap8_noinh LOGIN NOSUPERUSER NOINHERIT;  GRANT pg_maintain TO cap8_noinh;
CREATE ROLE cap8_mif   LOGIN NOSUPERUSER;            GRANT pg_maintain TO cap8_mif WITH INHERIT FALSE;
CREATE ROLE cap8_chain LOGIN NOSUPERUSER NOINHERIT;  GRANT cap8_noinh TO cap8_chain;   -- transitive

  rolname     has_table_privilege   pg_has_role USAGE   pg_has_role MEMBER
  cap8_noinh  false                 false               TRUE
  cap8_mif    false                 false               TRUE
  cap8_chain  false                 false               TRUE

[cap8_noinh]                     REINDEX INDEX screening_ledger_anchor_pkey -> ERROR: permission denied
[cap8_noinh, SET ROLE pg_maintain] same statement                           -> REINDEX     <- usable
```

**Q answered: a built-in does capture this, and no bespoke `pg_auth_members` traversal is needed.**
`pg_has_role(member, role, 'MEMBER')` is exactly `SET ROLE` reachability, it is transitive
(`cap8_chain` reaches `pg_maintain` through `cap8_noinh` and reports true), it covers both
`NOINHERIT` and per-grant `WITH INHERIT FALSE`, and it is readable by `owl_migrator` for arbitrary
role pairs. Exception-freedom and cost were checked because the failure mode of a check matters as
much as its success, the standard D41 and D59 set: **1058 `(role, role, table)` combinations
evaluated with no exception.**

**Decision: the holder enumeration asks the `MEMBER` question, and a second, independent
grantee-side assertion is added beside it. Neither subsumes the other.**

- **Holder-side**, re-quantified: a role is named if it can `SET ROLE` -- transitively, inherit flag
  ignored -- to any role for which `has_table_privilege` is true.

  ```sql
  SELECT r.rolname FROM pg_roles r
  WHERE NOT r.rolsuper AND r.rolname <> ALL (<D72's allowlist>)
    AND EXISTS (SELECT 1 FROM pg_roles s
                WHERE pg_has_role(r.oid, s.oid, 'MEMBER')
                  AND has_table_privilege(s.rolname, $1::regclass, 'MAINTAIN'))
  ```

  Executed: names all three roles above; returns `<EMPTY>` on the clean baseline.

- **Grantee-side**: an `aclexplode(relacl)` scan naming every literal `MAINTAIN` grantee. Executed on
  the L-A(i) state, it names `pg_read_all_data`.

**Why both, argued rather than asserted, because D39 rejected an ACL scan by name.** D39 rejected
`aclexplode` as "strictly weaker" (`0007:3164-3170`) and was **right about it as a replacement**: an
ACL entry names a grantee literally and does not expand membership, which is the case D39's own
transcript showed it missing. It is **not** weaker as a *second* assertion, and CAP #7 §11 point 3
says so. The two limbs see different things:

- The holder-side limb cannot see a grant to a role that has **no members yet** -- which is exactly
  what L-A(i) leaves behind. `pg_read_all_data` holds `MAINTAIN`, nobody is a member, and the
  capability sits latent and invisible until someone joins.
- The grantee-side limb cannot see a member who reaches the privilege through a role the ACL never
  names -- `pg_maintain` membership, which is L-A(ii).

They also differ usefully in **diagnostics**: a `GRANT ... TO PUBLIC` makes the holder-side limb name
eighteen roles (executed), while the grantee-side limb names `PUBLIC` once. The addendum records
that this is a supplement and not a replacement, so a later change cannot remove either on the
other's strength.

**Applies identically to D61's matrix** (`postgres.go:736-777`), which CAP #7 confirms has the same
hole and which the same two limbs close, and to the installer's postconditions so it proves the
property it installs rather than a narrower one -- D60's own reasoning (`0007:5781-5782`).

**All seven routes Addendum 7's investigation closed were re-executed under the new shape and remain
closed**: inheriting `pg_maintain` membership (named), `GRANT ... TO PUBLIC` (all four `owl_*` roles
named), `pg_database_owner` on a non-superuser-owned database, the self-re-grant D58 test 3 covers,
a `CREATE ROLE` landing below oid 16384 (not reachable), `owl_migrator`/`owl_ledger_ddl` granting
role membership (refused), and `owl_migrator` self-`ALTER ROLE ... NOINHERIT` (refused). **D72 and
D73 ship together** -- D72 alone leaves the NOINHERIT path, D73 alone leaves the sub-16384 grantee.

---

### D74. L-D through L-H: the second-cluster DR tooling

`scripts/ci/verify_cross_cluster_dr.sh` is Addendum 7's newest infrastructure and every one of these
was verified against the file at this commit.

**L-D (MEDIUM) -- the script asserts this round's own mechanisms, or stops claiming to.** Grepping
the script for `D60|D61|D62|D65|MAINTAIN|CheckProvisioning|screening-ledger status|provisioned`
returns nothing; its five assertions are both event triggers `evtenabled='A'` (`:106-111`),
`owl_migrator` can `CREATE TABLE` (`:113`), D34 blocks `DROP TRIGGER` (`:116-125`), D51's revoke
blocks `REINDEX ... CONCURRENTLY` (`:127-136`), and the restore is bricked beforehand (`:86-96`).
All are Addendum 3/5/6 properties. The final line nevertheless claims **"enforcement genuinely live
on the recovered copy"** (`:138`).

**Decision: the assertion is made real rather than the claim narrowed.** The script runs
`screening-ledger status` against the recovered copy and asserts `Provisioned=true`, and asserts
D60's `MAINTAIN` enumeration is empty and D61's matrix is exact. The reason to prefer this over
narrowing the sentence is specific: **L-A(i) is precisely a state a DR copy carries across** -- a
`GRANT MAINTAIN` survives `pg_dump` in the relation's ACL -- and D61's matrix is exactly the kind of
thing a restore's own `GRANT` statements can get wrong. A round whose HIGH findings are about
privileges should not ship a DR proof that checks no privilege.

**L-E (MEDIUM) -- the copy is passwordless, and a `SIGKILL` leaves it running.** `initdb --auth=trust`
(`:55`) with the default `listen_addresses='localhost'` means that for the whole run any local user
can connect as the bootstrap superuser, with no password, to a full logical copy of the primary's
SEC-7 database. The `ALTER USER ... WITH PASSWORD` at `:71` is inert against `trust`.

- **`--auth=scram-sha-256` with `--pwfile`**, which also makes `:71` meaningful rather than
  decorative. Verified during this design pass: the disposable cluster this addendum's own
  transcripts were produced on was built exactly that way, so the change is known to work rather
  than assumed.
- **The `SIGKILL` orphan is a real limit and gets a real answer rather than silence.** `trap ...
  EXIT` (`:52`) does not run on `SIGKILL`, and the postmaster survives with its data directory in
  the system temp dir. **`SIGKILL` cannot be trapped -- that is not a defect to fix but a property
  to design around**, so enumerating "add a handler" would be the enumerative non-answer. Two
  mechanisms are available and both are specified: the data directory is created under a path the
  script records, and a **`postmaster.pid`-based reaper** runs at the *start* of every invocation,
  stopping any cluster a previous run left behind before initialising a new one -- so the leak is
  bounded by the interval between runs rather than unbounded; and the operator document gains the
  manual cleanup step (`pg_ctl -D <dir> -m immediate stop`) for the case where no further run
  happens. Neither is a trap, and neither pretends to be. The ephemeral-runner mitigation
  (`ci.yml:39` `ubuntu-latest`, `release-qualification.yml:31` `ubuntu-24.04`, both destroyed after
  the job) bounds this in CI and bounds nothing on a developer workstation, which is where the
  operator document steers people.

**L-F (LOW) -- `DR_LOG` leaks the primary's instance binding.** `mktemp` at `:44`, referenced at
`:56` and `:67`, and absent from `cleanup()` (`:47-51`, which frees `DR_DATA_DIR`, `DR_SOCK_DIR` and
`DR_ERR_TMP` only). It holds the postmaster log, which includes D46's diagnostic naming the
primary's `system_identifier`/database OID verbatim. `cleanup()` removes it; the failure path
(`:66-68`) still prints it to stderr first, so the diagnostic value is kept and only the durable
copy is dropped.

**L-G (LOW) -- `pg_dump` is the one binary taken from `PATH`.** The preflight loop at `:34` iterates
`initdb pg_ctl postgres psql pg_isready` against `$PG_BIN_DIR`; `pg_dump` at `:83` is neither in that
list nor `$PG_BIN_DIR`-prefixed. `pg_dump` joins the loop and gains the prefix. **This repository has
already been bitten once by exactly this** -- `ci.yml:213-219`'s own comment describes the
version-mismatch failure that made Addendum 5's `create-restored-database` fixture install a pinned
client -- so this is a known failure class left uncovered in the one place it is most likely to
recur.

**L-H (LOW) -- quoting.** `:71` builds `ALTER USER $PRIMARY_PGSUPERUSER WITH PASSWORD
'$PRIMARY_PGSUPERPASSWORD'` by interpolation. The identifier is quoted via `format('%I')` and the
password passed as a parameter rather than interpolated. Rated LOW because both values are
workflow-controlled today; fixed because after L-E's change the statement stops being decorative and
starts being the thing that sets the credential.

**L-I is not adopted, and the reason is stated rather than left as an omission.** CAP #7's ninth
finding -- `ALTER DEFAULT PRIVILEGES ... GRANT MAINTAIN ON TABLES` succeeds for `owl_ledger_ddl` and
is observed by nothing, because `pg_default_acl` is outside every recorded referent -- is real and
was re-confirmed as a latent pre-authorisation that takes effect only when a protected relation is
**recreated**. That state is D46 message (b), which already refuses. Adding `pg_default_acl` to
D40's recorded properties would make an unrelated DDL statement fail for a change it did not make,
which is the trade R27 already declined for relation ACLs (`0007:6476-6483`). It joins that standing
question rather than being closed here, and R32 records it.

---

### D75. Test ownership and pre-declared withdrawal conditions

The specific shape the implementation must satisfy, so nothing weaker can be claimed to discharge
this addendum -- the standard D20 (`0007:1293-1338`), D26 (`0007:1874-1885`), D37
(`0007:2623-2662`), D42 (`0007:3455-3523`), D49 (`0007:4237-4307`), D58 (`0007:5231-5321`) and D67
(`0007:6365-6461`) set.

**Every test below must fail before its change, per CLAUDE.md rule 5.** Where a CAP #7 transcript
exists the test reproduces that transcript, not a paraphrase. Several assertions are stated as "must
pass today and fail after" -- deliberately, per D42's note (`0007:3461-3465`): for these findings the
current behaviour is *acceptance*, so a test asserting only the post-fix refusal cannot distinguish a
working fix from a test that never exercised the path.

1. **D69.** `TestD69TriggerReferentIsBehaviourNotName` (pgx), table-driven over all four
   substitutions in D69's table -- `cap7_noop`, the **same-named function in another schema**,
   `WHEN (false)`, and `BEFORE DELETE OR UPDATE OF <column>` -- each asserting that
   `CheckProvisioningState` returns `Provisioned=true Reason=""` **today**, that the tombstone
   forgery it enables actually succeeds as `owl_ledger_ddl` (otherwise the test proves a probe
   changed rather than a hole closed), and that both `grant-ddl-ownership` and
   `CheckProvisioningState` refuse after, naming the trigger and the property. **Plus the
   over-tightening positives**: a clean provisioned database, and a database on which
   `grant-ddl-ownership` has been re-run, both accepted. **Plus a unit-level assertion that
   `pg_get_triggerdef` renders identically for a same-named function in another schema**, which is
   the fact that refutes the rendering design and which a later reader will otherwise re-derive.
2. **D70.** `TestPurgeAttributionIsAdjudicatedAgainstTheAnchoredAttestation` (pgx): a legitimate
   purge, anchored; then `operator` and `reason` rewritten in the tombstone with the guard trigger
   neutered; assert `VerifyAnchored` **succeeds today** and fails after, naming the divergence.
   Plus the reverse direction: a tombstone row inserted with no corresponding audit attestation --
   both via a direct `screening_ledger_purge_snapshots` call as `owl_migrator` and via a direct
   `INSERT` as `owl_ledger_ddl` -- is a named failure after. Plus the positive that keeps legitimate
   retention working: a `Store.PurgeExpired` purge, anchored, verifies clean, and `purged_at` skew
   between the two clocks does **not** fail it.
3. **D71.** `TestDeclaredIndexMustResolveToALiveObject` (pgx): CAP #7 §7.3's exact drop, asserting
   `grant-ddl-ownership` exits 0 and `CheckProvisioningState` returns `Provisioned=true Reason=""`
   **today**, and that both refuse after. Both protected relations, and the duplicate-row insert
   asserted as succeeding today so the consequence is proven rather than described.
4. **D72/D73.** `TestMaintainHoldersAreEnumeratedOverGranteesAndMembers` (pgx), table-driven over:
   the `pg_read_all_data` grant (L-A(i)); `NOINHERIT` membership, `WITH INHERIT FALSE`, and a
   **transitive** chain (L-A(ii)); and **all seven routes Addendum 7 closed**, which must keep
   passing. Each asserts `Provisioned=true Reason=""` today and a named failure after. Plus the two
   positives: a clean database on which `pg_maintain` exists and is untouched returns
   `Provisioned=true` -- D67 test 1's positive, retained verbatim, which the naive "no non-superuser
   role" form fails -- and D61's five-row matrix is still accepted unchanged.
5. **D74.** The DR script's own assertions become the test: it asserts `Provisioned=true`, an empty
   `MAINTAIN` set and the exact D61 matrix on the recovered copy; a run leaves the system temp
   directory's file count unchanged (L-F); the preflight refuses a `$PG_BIN_DIR` missing `pg_dump`
   (L-G); and a `SIGKILL`ed run followed by a second invocation leaves no listener on the DR port,
   which is the reaper's proof (L-E).

**Withdrawal conditions, declared now rather than decided after the fact:**

- **The `pg_get_triggerdef` rendering must not be adopted as a simplification of D69.** It is the
  design this section was expected to reach and it is refuted above by execution: the renderer is
  `search_path`-sensitive, so the recorder and the verifier can disagree about the same trigger at
  the same instant, and the disagreement falls in the direction that accepts a neutered guard in the
  process that actually runs the check. A later reader who rediscovers it should find D69's
  two-session transcript before implementing it.
- **If D69's property set cannot be stated as a stable literal** for all four declared triggers in
  the shipped configuration, the implementation stops and this addendum is amended rather than
  shipping a comparison covering some properties and not others -- a check that runs on part of its
  referent is the shape of every finding in this document. The four rows were measured, so this
  condition is expected to remain un-triggered; it is declared because `tgattr` and `tgqual` are the
  two the arc has never recorded before.
- **D69 and D71 ship together.** D71 alone closes L-C and leaves L-B, which is CAP #7 §11 point 1's
  own observation; D69 alone leaves a declared name that resolves to nothing passing vacuously.
- **D72 and D73 ship together**, for the reason D73 states: each leaves the other's escape open.
- **If D70's bidirectional comparison cannot be implemented without restructuring `VerifyAnchored`'s
  or `PurgeChecker`'s contract beyond returning the tombstone row**, the implementation stops and the
  design is amended. It does not ship a forward comparison alone -- that leaves the fabricated-row
  route D70 identifies, and a retention check that runs on part of its evidence is the same shape
  again.
- **If D74's L-E reaper is found to interfere with concurrent CI jobs sharing a runner**, the reaper
  is withdrawn and the manual cleanup step ships alone, with the residual re-stated in the PR rather
  than quietly widened.

**Prior addenda's pre-declared withdrawal conditions remain correctly un-triggered**, re-verified
against what *this* addendum designs rather than inherited from CAP #7's confirmation. D65's branch
is untouched and D71 repairs its vacuity rather than changing it, so Addendum 7's "assert validity in
D47 only" fallback is **not** required. D50's collateral-damage cases are unaffected -- D69 and D71
add assertions beside the index comparison and never change `index_defs`, so D49's second withdrawal
condition is not engaged and Addendum 6's "record both `index_oids` and `index_defs`" fallback must
not be adopted. D60's empty-set assertion survives D72 with its literal changed from a range to a
name, not removed. The instance binding is still not a gate. D46 is not split from D45. D40's
collateral-damage cases pass, so Addendum 4's `pg_depend` fallback is not required. D38(a) and
D38(b) remain shipped together.

---

### New accepted risks

**R30 -- D68 is a declaration discipline, not an interception, and the T2 window is unchanged.**
Nothing in this addendum observes a substitution at the moment it happens: under T2 the event
triggers are disabled by the party performing it, which is the premise of the documented recovery.
What changes is that a substituted object can no longer be **recorded as legitimate** (D69 in
`grant-ddl-ownership`) and can no longer **pass verification** (D69 and D71 in
`CheckProvisioningState`). D60's own framing applies unchanged and is restated here so D69 is not
cited as more: it converts an unobserved substitution into an observed one; it does not prevent the
substitution. The residual terminates at the bootstrap superuser, where R12/R17 put every other one.
Note also that D34 is doing more work here than CAP #7 credits -- it refuses the `DROP TRIGGER` in
the state the operator document actually creates (drift note 1), and only a second, undocumented
`ALTER EVENT TRIGGER ... DISABLE` opens the window.

**R31 -- retention integrity now depends on the audit chain being present and anchored, and a
mirror-only deployment is not covered.** D70 adjudicates the tombstone against a fact authenticated
under `K_chain` and committed under `K_anchor`, which is strictly stronger than the tombstone MAC it
declines -- but only for a verifier that holds the ledger directory. An auditor reading the Postgres
mirror alone gets no retention guarantee from this addendum, and that case genuinely needs a keyed
record in the mirror with its own custody boundary and its own writer identity. D70 states what a
follow-on ADR would have to cover; **the issue register should carry it**, and it is not claimed as
closed here. The failure direction is fail-closed and the migration is free at zero tombstone rows,
which is the same argument D11, D25, D32 and D38 each made and the reason this is cheap to defer and
expensive to defer indefinitely.

**R32 -- `pg_default_acl` remains outside every recorded referent, joining R27's standing question.**
CAP #7's L-I is real: `ALTER DEFAULT PRIVILEGES ... GRANT MAINTAIN ON TABLES` succeeds for
`owl_ledger_ddl`, is observed by nothing, and takes effect the moment a protected relation is
recreated. It is not closed here for the reason R27 already gave about relation ACLs -- `GRANT` and
`ALTER DEFAULT PRIVILEGES` are not DDL any event trigger fires on, so a recorded default-ACL column
would be compared only on the *next unrelated* DDL statement, making an unrelated statement fail for
a change it did not make. Its exploitation path terminates in D46 message (b), which refuses. The
question is genuinely open and belongs with R27's, to an addendum written after the cadence gate
lands.

**R33 -- the coordinated-edit surface grew along the axis R23 and R29 already track.** D69 adds four
properties per declared trigger to `requiredProtectedRelationStates` and to D62(a)'s cross-language
declaration; D71 adds an existence assertion in two places; D72 adds a one-member allowlist; D73 adds
a second privilege-enumeration limb. No new *kind* of literal is introduced -- every one of them is a
property of an object this document already declares -- but the count grew again and this addendum
does not pretend otherwise. The mitigating property is unchanged and is why the arrangement
survives: **every one of those assertions fails closed.** The aggravating property is unchanged too,
and §10.3's first risk -- that the controls have no single owner -- is not addressed here and is not
claimed to be.

### Staging

Same shape and reason as §8 and the seven prior addenda (`0007:1397-1414`, `0007:2038-2058`,
`0007:2694-2716`, `0007:3566-3586`, `0007:4342-4367`, `0007:5360-5384`, `0007:6512-6540`): each
stage independently reviewable and independently provable. Ordered by dependency rather than
severity.

1. **This addendum**, merged before any code (CLAUDE.md rule 7).
2. **Stage K1 -- the declaration.** D68, D69 and D71 together (D75's third withdrawal condition).
   The CRITICAL, and the only stage that changes what a security check asserts about an object.
   D69's over-tightening positives are a shipping requirement, not a nicety, and its withdrawal
   condition is discharged or invoked here.
3. **Stage K2 -- the retention claim.** D70. Sequenced after K1 because its forward comparison is
   meaningful only once the guard trigger it corroborates is itself verified, and because K1 is what
   stops the DDL route the same attack takes. Not sequenced first despite carrying the same
   CRITICAL: the DDL half is the reachable one, and D70 without D69 leaves the tombstone's own guard
   substitutable.
4. **Stage K3 -- the quantifier's two senses.** D72 and D73 together. Independently provable and
   depends on neither K1 nor K2; sequenced third only because both edit `checkProvisioningState`,
   which K1 has just changed, and splitting them across that edit would produce conflicting versions
   of the same function -- the reasoning Addendum 4's staging used for D39 and D41
   (`0007:3579-3582`) and Addendum 7's for D59-D61.
5. **Stage K4 -- the DR tooling.** D74. Blocks nothing, and is therefore sequenced last and
   explicitly **not** droppable -- D23 was sequenced last on the same "blocks nothing" reasoning and
   CAP #2 rated the resulting gap HIGH, a lesson Addendum 5's staging recorded (`0007:4348-4354`)
   and Addenda 6 and 7 both repeated. Per CLAUDE.md Boundaries the workflow wiring for any new
   assertion is named explicitly in the PR description, following D30's precedent.
6. **`SECURITY.md` and `README.md` language.** R3's rule unchanged. `README.md:93-97`'s
   requalification notice stays until every stage above has landed and its reproduction passes.
   CAP #7 §9 re-confirmed that nothing in PR #155 or #156 re-asserted the guarantee; that must
   remain true through this addendum as well.

**SEC-7 does not close on this addendum, and for the first time in four rounds the reason is a
forgery.** §8's closing condition -- "a deliberately forged chain fails a CI run that nobody chose to
invoke" -- remains met for the **chain**: the anchor MAC still catches L-B's anchor-side rewrite and
CAP #7 confirmed the cryptographic layer is unbroken. It is **not** met for the **retention claim**,
which the invariant names alongside history and which L-B forges silently and permanently. That is a
larger barrier than the three that preceded it, not a smaller one, and D69 through D71 are the whole
of it. The closing sentence stands and now has an eighth addendum behind it.

### Addendum 8 summary

- **CAP #7's verdict is QUALIFIED, not PASS, for the seventh consecutive audit -- and for the first
  time in four rounds it demonstrates a forgery.** Nine findings remain, and the three
  highest-ranked are one defect. D31's scoping principle, Addendum 4's referent principle,
  Addendum 5's population principle, Addendum 6's atomicity principle and Addendum 7's quantifier
  principle all held; this addendum reopens none of them.
- **The class is the one CAP #7 names: the terminating literal is still a name.** Addendum 4 fixed
  referents, 5 populations, 6 the referent a legitimate operation rewrites, 7 quantifiers -- and
  every one of them still ends on a string, with whatever currently bears that string standing in
  for the thing declared. The principle: a name is an address and never evidence; a control must
  assert that the named object exists and that it has the properties that make it the control it is,
  and must exclude a party by a property it structurally has rather than by a range that happens to
  contain it.
- **The design is D68-D75.** The naming principle with its PostgreSQL support established by
  execution (D68); the trigger referent as a closed set of session-independent catalog properties,
  with the definition rendering refuted rather than adopted (D69); the retention claim's attribution
  adjudicated against the already-anchored attestation, and the tombstone-MAC question answered with
  a recommendation against and a follow-on ADR scoped (D70); every declared name asserted to resolve
  to a live object, in the installer and the verifier alike (D71); the predefined-role exclusion as
  an explicit measured allowlist rather than an OID range (D72); "holder" split into grantee and
  member, with D39's rejected ACL scan restored as a second assertion rather than a replacement
  (D73); the DR tooling's five findings, including a `SIGKILL` answer that does not pretend `SIGKILL`
  can be trapped (D74); and the proof obligations with pre-declared withdrawal conditions (D75).
- **This design pass executed its mechanism assumptions, and the execution refuted the fix this
  addendum was expected to reach and corrected the CAP record twice.** `pg_get_triggerdef` is
  **`search_path`-sensitive** where `pg_get_indexdef` is not, so the same trigger renders
  differently to the recorder and the verifier, and a same-named no-op in another schema renders
  **byte-identically to the legitimate guard** in the session that actually runs the check -- the
  D50-shaped answer, refuted with its two-session transcript. `pg_has_role(..., 'MEMBER')` does model
  `SET ROLE` reachability transitively and through both non-inheriting forms, over 1058 pairs with no
  exception. `pg_maintain` is the only one of sixteen predefined roles reporting `MAINTAIN = true`,
  enumerated rather than trusted. `WHEN (false)` and `UPDATE OF <column>` are two further
  substitutions no CAP has tried, both of which forge successfully today and neither of which
  `tgfoid` alone catches. And CAP #7 §7.2's own setup is one `ALTER EVENT TRIGGER ... DISABLE` short
  of reproducible, because D34 refuses the `DROP TRIGGER` in the state the operator document creates.
- **L-B is rated CRITICAL rather than CAP #7's HIGH**, on the ground that it is the first state in
  seven rounds that is permanently undetectable after the fact -- the tombstone carries no MAC, the
  DDL layer was laundered, and nothing anywhere retains evidence the row read differently. The
  counter-argument, that its setup needs the superuser with both event triggers disabled, is recorded
  in D69 rather than resolved silently.
- **Four risks are recorded** rather than designed away: D68 is a declaration discipline and not an
  interception (R30); retention integrity now depends on the audit chain and a mirror-only
  deployment needs its own ADR (R31); `pg_default_acl` joins R27's standing question (R32); and the
  coordinated-edit surface grew along R23/R29's existing axis (R33).
- **This addendum revises no prior decision.** D1-D7, D8-D20, AR7, D21-D30, D31-D37, D38-D42,
  D43-D49, D50-D58 and D59-D67 stand. R1-R29 stand. D59 point 3's `oid >= 16384` discriminator is
  replaced by D72 with the reasoning stated in D72's own words rather than by editing D59, and D59's
  substantive property -- that excluding a predefined role does not exclude its members -- is
  preserved and re-tested.

**Audit basis commit:** `1033860599b56a6676cf8cb9ce163c3e35eea3d1`

Every file:line citation in this addendum was verified against that tree -- the same commit CAP #7
was produced against, so no drift separates the audit from this design. For a CAP record covering
the implementation of this addendum, use the tip of whichever stage PR is under audit, not this
value.

## Addendum 9: composition -- a property set is only as strong as its weakest member, and CAP #8's forgery through D69's own fix (2026-08-28)

- **Status:** Proposed
- **Trigger:** an eighth Composition Audit Program record produced against the implemented
  Addendum 8 (`docs/backlog/sec-7-cap-record-be62ceb.md`, adversarial posture, audit basis commit
  `be62ceb3dcddc785a1312783740a422a94425aa3`) returned **QUALIFIED, not PASS** for the eighth
  consecutive audit. Eleven findings remain, and for the **second consecutive round** the record
  demonstrates a forgery. **SEC-7 is not closed.**
- **What CAP #8 confirmed and this addendum does not disturb.** All four substitutions D69 was
  written against are refused by both the installer and the verifier. **D72 and D73 are the
  strongest decisions in the round and close L-A completely** -- every route CAP #7 named, every
  route Addendum 7 had closed, and several no CAP has tried are named by one or both limbs, and
  PostgreSQL reserves the `pg_` prefix for `CREATE ROLE` so the name-keyed allowlist cannot be
  spoofed. D70's forward comparison genuinely catches an operator/reason rewrite, and it survives
  even M-A's neutering. D71 refuses an absent declared index in both places. D74's L-D fix chose the
  stronger option and is genuinely closed. The suites are unregressed at 113 top-level PASS, 0 FAIL
  in `internal/screeningledger`; `go test -race -count=1 ./...` exits 0 across 98 packages;
  `scripts/ci/run-ci.sh` exits 0 in full. **D31's scoping principle, Addendum 4's referent
  principle, Addendum 5's population principle, Addendum 6's atomicity principle, Addendum 7's
  quantifier principle and Addendum 8's naming principle all held**, and this addendum reopens none
  of them.
- **Scope:** a pure addition. Nothing above this section is edited -- not D1-D7, not D8-D20, not
  AR7, not D21-D30, not D31-D37, not D38-D42, not D43-D49, not D50-D58, not D59-D67, not D68-D75,
  not the D19 correction note, not R1-R33. Decision numbering continues at **D76**; risk numbering
  at **R34**. Where a prior decision's *text* is narrower than what the code does, the new decision
  says so in its own words -- the convention AR7 established and every addendum since has followed.
- **Verification basis:** every `file:line` below was re-derived from the working tree at
  `be62ceb3dcddc785a1312783740a422a94425aa3` rather than copied from the CAP record or from a prior
  addendum. PR #158 moved several of Addendum 8's own citations: `requiredProtectedTriggerState` is
  `internal/screeningledger/postgres.go:527-539`, `requiredProtectedRelationStates` is `:547-568`,
  `protectedRelationStateReason` is `:577-700`, D69's live-behaviour loop is `:667-697`, D71's
  existence branch is `:610-626`, D62(a)'s refusal loop is `scripts/ci/provision_test_roles.sh:592-628`,
  D69's installer limb is `:645-667` and D56/D71's missing-object loop is `:702-723`. Expected, not
  a defect.
- **This design pass executed its mechanism assumptions, as Addendum 3 established and Addenda 4-8
  held to -- and for the second addendum running, the execution refuted the fix this addendum was
  expected to reach.** A disposable PostgreSQL 17.11 cluster was built on **port 55500** and
  provisioned with the **real** schema in `.github/workflows/ci.yml:141-235`'s exact order
  (`create-roles`, all seventeen `db/migrations/*.sql` as `owl_migrator`, `grant-app-privileges`,
  `grant-ddl-ownership`). Baseline confirmed byte-identical to CAP #8 section 7.0: thirteen
  `sec7_protected_object` rows, two `sec7_protected_relation` rows, one `sec7_instance_binding` row,
  both event triggers `evtenabled='A'`, and D69's four-row trigger-property table exact down to
  `tgfoid` 16462 and 16846. Every destructive probe ran against a `CREATE DATABASE ... TEMPLATE`
  clone. **The cluster was torn down and the teardown was proven by pasted `lsof` and `ps` output in
  the PR description, not asserted** -- CAP #8 section 12 records that the Addendum 8 design pass
  claimed a teardown its own cluster survived by seven hours, and this addendum treats that as a
  standing obligation rather than a one-off. The developer's own server on port 5432 was never
  contacted. The four results that changed the design:
  1. **`pg_proc.prosrc` is session-independent, cross-role stable, and survives `pg_dump` while
     OIDs do not** -- so it is a *better* referent than the `tgfoid` D69 already relies on, not
     merely an additional one (D76, D77).
  2. **`owl_reject_truncate()` has TWO legitimate bodies**, because `db/migrations/012_truncate_guards.sql:9-12`
     and `internal/screeningledger/postgres.go:1576` disagree on whitespace. A single declared
     digest -- the shape CAP #8 section 11 point 1 recommends -- **fails closed on a clean,
     unattacked, migration-bootstrapped database**, which is D45's pre-declared false-failure shape
     and D75's own "cannot be stated as a stable literal" withdrawal condition (D77).
  3. **The guard functions are already first-class protected objects and `ddl_command_end` already
     fires for `CREATE OR REPLACE FUNCTION`**, so there is no event-trigger extension to make; the
     gap is entirely R30's stated T2 window (D76).
  4. **D62(a)'s, D69's and D71's precondition checks are pure `SELECT`s** and run correctly with both
     event triggers `ENABLE ALWAYS`, so M-D closes by statement ordering at zero cost (D79).

---

### Drift found while writing this addendum

Recorded rather than silently corrected, the convention section 3.4, section 6.1, `0007:717-720`,
`0007:1474-1490`, `0007:2141-2160`, `0007:2804-2826`, `0007:3689-3712`, `0007:4476-4498`,
`0007:5500-5554` and `0007:6660-6700` set.

1. **CAP #8's M-C and M-D transcripts reproduce only inside the documented recovery window, and the
   record does not say so.** Both were re-executed here. With `sec7_protect_ddl_objects_on_alter`
   **re-enabled** before `grant-ddl-ownership` runs, D40's and D50's runtime second phase fires on
   the script's own first DDL statement and the script dies there instead:

   ```
   [_on_alter re-enabled first]
   grant-ddl-ownership -> EXIT=1
     ERROR: ADR-0007 Addendum 6 D50: protected relation "public.screening_ledger_anchor"
            (objid 16914): its index set changed
     pg_event_trigger count AFTER the refusal -> 2      <- the triggers SURVIVE

   [only _on_alter down, exactly as docs/operations/sec7-database-copies.md:187 instructs]
   grant-ddl-ownership -> EXIT=0, 3 PASS lines          <- M-C reproduces
   ```

   The findings are **undiminished** -- the documented recovery is precisely the state an operator
   is told to create, and both reproduce there. What changes is that D40 and D50 deserve credit for
   catching both substitutions in the state where the event triggers are up, and a reader
   re-executing CAP #8 section 7.3 or 7.4 without that ordering will conclude the findings do not
   reproduce. This is the same class of correction Addendum 8's own drift note 1 made about CAP #7's
   L-B setup, in the opposite direction: there the record understated a precondition, here it omits
   an ordering.
2. **CAP #8's M-I names `DR_BINARY` and the audit brief calls it "the `DR_LOG` leak."** `DR_LOG` is
   genuinely fixed -- `cleanup()` frees it at `scripts/ci/verify_cross_cluster_dr.sh:74`, and a
   measured run confirms it is removed. What recurred is the **class**, in a new instance. Recorded
   because the distinction is the whole content of D83: an instance was fixed and the class was not,
   which is Addendum 1's original diagnosis of this arc (`0007:1494-1497`) reappearing inside a
   remediation for it.
3. **A third instance of that class exists and no CAP has named it.** `DR_BOOTSTRAP_PWFILE`
   (`:103`) is freed at `:107`, on the success path only, and is absent from `cleanup()` (`:64-75`).
   An `initdb` failure therefore leaves a file containing a cluster's bootstrap password in the
   system temp directory. Found by reading `cleanup()` against every `mktemp` in the file rather
   than by reproducing it.

---

### Addendum 9 context: five axes were right, and the sixth is that a set has a weakest member

Addendum 1 diagnosed the original's structural error as fixing instances rather than causes
(`0007:1494-1497`). Addendum 2 named its findings as one class -- "a control whose installation is
asserted rather than checked, by the party the control constrains" (`0007:1499-1500`). Addendum 3
sharpened it to "a control that decides what to protect, or what to protect against, by listing
members of an open set" (`0007:2172-2173`). Addendum 4 sharpened it again to "the enumeration was
fixed and the referent drifted" (`0007:2853-2857`). Addendum 5 moved one axis over -- "the referent
is correct and its population was never stated" (`0007:3742-3746`). Addendum 6 moved to a third, the
referent a *legitimate* operation rewrites (`0007:4526-4534`). Addendum 7 moved to a fourth, the
quantifier (`0007:5574-5580`). Addendum 8 moved to a fifth, the name as terminating literal
(`0007:6732-6738`), and produced D69.

CAP #8 section 0.1 states what survived all six, and it is right:

> Addendum 4's referent principle, Addendum 5's population principle, Addendum 6's atomicity
> principle, Addendum 7's quantifier principle and Addendum 8's naming principle are each correct.
> The defect that survives all five is that **a property set is only as strong as its weakest
> member, and D69's weakest member is a name for a body nobody declared.**

D69 did exactly what Addendum 8's principle prescribed: it replaced `tgname` with four catalog
properties. Three of them -- `tgtype`, `tgqual`, `tgnargs`/`tgattr` -- are genuinely properties of
behaviour, and each is the only one of the four that sees its own substitution. The fourth, and the
only one that says *which code runs*, is `pg_identify_object('pg_proc', tgfoid, 0).identity`
(`postgres.go:676`) -- **a string**. The declaration got strictly stronger and still terminated on a
name, because *adding* properties to a set does not remove the weakest one.

| Mechanism | The declaration | What the weakest member denotes | Finding |
|---|---|---|---|
| D69 trigger behaviour | four catalog properties (`postgres.go:667-697`, `provision_test_roles.sh:645-667`) | whatever body currently sits behind that OID | **M-A** |
| D71 declared index | `indexNames` plus an `EXISTS` (`postgres.go:610-626`) | any relation of that name, unique or not | **M-C** |
| D70 reverse pass | `WHERE snapshot_sha256 = ANY($1)` (`postgres.go:1404`) | only snapshots this chain already references | **M-E** |
| D70 `purged_at` | `record.PurgedAt.After(anchoredAt)` (`anchor.go:311`) | an upper bound and no lower one | **M-B** |

**The principle this addendum adopts, stated once and applied five times:**

> **A control's declaration may terminate on a name only where that name's referent has its own
> declared properties. A property set inherits the strength of its weakest member, not its
> strongest: where one member of the set is an identity, the object that identity addresses must
> itself be declared, or the set is exactly as forgeable as that one member. Adding properties to a
> set does not repair the weakest one.**

Addendum 8's D68 already said "the name is an address and never evidence" and required three
assertions -- the named object exists, has the declared properties, and no undeclared object is
present. D76 supplies the missing fourth: **and where one of those declared properties is itself a
name, that rule applies again, recursively, until the declaration terminates on something the
adversary cannot rewrite.** D69 stopped after one level. `tgfoid`'s identity is the address of a
body, and nowhere in this repository is it declared what
`screening_ledger_reject_mutation()` should *do*.

---

### D76. The composition principle, and where PostgreSQL supports it

**Decision: a declared property set must terminate on evidence. Where a member of the set is an
identity, the object it addresses gains its own declaration, and the recursion stops only at a value
the adversary cannot rewrite without the control noticing.**

Four sub-decisions follow, each verified by execution against PostgreSQL 17.11 during this design
pass rather than reasoned from the manual.

**1. `pg_proc.prosrc` is session-independent, where the `pg_get_*def` renderers are not.** Probed by
OID, so the probe itself introduces no name resolution, across the same five `search_path` values
D68 point 1 used:

```
md5(prosrc) of oid 16462          md5(pg_get_triggerdef) of screening_ledger_anchor_immutable
  public            2ab5e9a7...     public            1c1b44df...
  pg_catalog        2ab5e9a7...     pg_catalog        00d2d2df...   <- SENSITIVE
  public,pg_catalog 2ab5e9a7...     public,pg_catalog 00d2d2df...
  pg_temp,public    2ab5e9a7...     pg_temp,public    00d2d2df...
  pg_catalog,public 2ab5e9a7...     pg_catalog,public 00d2d2df...
                    ^ INSENSITIVE
```

This is the property D69 required and could not get from `pg_get_triggerdef`. **D69's refutation of
the rendering is restated, not reopened**: the renderer stays rejected, and the reason a later reader
must find before re-proposing it is unchanged (`0007:6853-6875`, `0007:7347-7352`). `prosrc` is not
a rendering -- it is the stored body itself, which is why it has a property the renderer does not.

**2. `prosrc` is identical in the recorder's session and the verifier's, which is the exact test
`pg_get_triggerdef` failed.** The two sessions D69's two-session transcript used -- the one
`grant-ddl-ownership` runs as, and the one `PostgresSink` connects as:

```
[owl_ci       -- the RECORDER]  search_path="$user", public  sha256(prosrc)=5632734b5c67...81f4bb1
[owl_migrator -- the VERIFIER]  search_path="$user", public  sha256(prosrc)=5632734b5c67...81f4bb1
```

**3. `prosrc` is readable by `owl_migrator` with no new role, DSN or grant, and does not raise** --
the standard D33's, D41's, D45's, D59's and D68's facts were each held to (`0007:2422-2425`,
`0007:3404-3406`, `0007:3967-3969`, `0007:5615-5624`, `0007:6783-6786`), checked rather than assumed
because a check needing a new credential is a check that will be skipped.

**4. `prosrc` survives `pg_dump | psql` byte-identically while OIDs are reassigned.** This is the
result that makes `prosrc` a *better* referent than the one D69 already trusts, not merely an
additional one, and it matters for D66/D74's DR path specifically:

```
                     pristine                          restored (pg_dump | psql)
sha256(prosrc)       e8db5083...  owl_reject_truncate   e8db5083...   <- IDENTICAL
                     5632734b...  screening_..._mutation 5632734b...  <- IDENTICAL
pg_proc oid          16846 / 16462                      17090 / 17093 <- REASSIGNED
```

D41 and D46 exist because a restore moves OIDs. The body does not move. A declaration that
terminates on the body is stable across exactly the operation that forces every OID-keyed mechanism
in this document to be re-recorded.

**What this principle does not reach, stated rather than left to be discovered.** Like D68, D76 is a
**declaration** discipline and not an interception, and **the guard functions were already
first-class protected objects before this addendum** -- that was verified rather than assumed:

```
[owl_migrator, both event triggers live]
CREATE OR REPLACE FUNCTION public.screening_ledger_reject_mutation() ...
  -> ERROR: ADR-0007 Addendum 3 D34: public.screening_ledger_reject_mutation()
            (objid 16462, tag CREATE FUNCTION) is protected by a superuser-only DDL event trigger

[with only sec7_protect_ddl_objects_on_drop disabled]
  -> same refusal          <- the refusal comes from _on_alter, i.e. ddl_command_end
```

So `ddl_command_end` **does** fire for `CREATE OR REPLACE FUNCTION`, the function **is** in
`sec7_protected_object` by OID, and D34 **does** block the substitution while it is enabled. **There
is no registry extension to make and no new event to hook.** The gap is R30's stated one and nothing
else: under T2 the event triggers are disabled by the party performing the substitution, which is the
premise of the documented recovery. R34 states this rather than letting D77 imply prevention.

---

### D77. M-A (CRITICAL): the declared trigger referent gains the function's body -- and the single authoritative text that does not exist

**Severity, decided here rather than inherited.** CAP #8 rates M-A CRITICAL and this addendum agrees,
on both of the grounds Addendum 8 used for L-B, each of which M-A meets more strongly:

- **It is permanently undetectable after the fact.** No mechanism anywhere in this repository records
  what the guard function's body was, so once the swap is laundered nothing retains evidence the
  function ever behaved differently. This is the ground on which L-B was raised from CAP #7's HIGH.
- **Its precondition is *lower* than L-B's, not higher.** L-B needed the documented recovery window
  **plus** a second, undocumented `ALTER EVENT TRIGGER ... DISABLE` -- Addendum 8's own drift note 1
  established that, and credited D34 for it. M-A needs **one statement, in the state
  `docs/operations/sec7-database-copies.md:187` step 1 creates by itself**, because
  `CREATE OR REPLACE FUNCTION` fires `ddl_command_end` only. The counter-argument Addendum 8 recorded
  against L-B therefore does not exist here.

**The finding, restated from the code and reproduced.** D69's declaration is
`requiredProtectedTriggerState` (`postgres.go:527-539`): `tgtype`, `tgnargs`, `tgattr`, `functionOID`,
plus `tgqual IS NULL` asserted as a literal in the query (`:673`). `functionOID` is
`pg_identify_object('pg_proc', t.tgfoid, 0).identity` (`:676`). Executed against the real provisioned
schema, in the documented state and nothing beyond it:

```
ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE;         (step 1, as documented)
CREATE OR REPLACE FUNCTION public.screening_ledger_reject_mutation()
  RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;     (ONE statement, as owl_migrator)
ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS;
```

Every declared property is unchanged, because the OID never moved:

```
tgname                                            tgtype qual_null tgnargs tgattr tgenabled tgfoid identity
screening_ledger_anchor_immutable                     27     t         0      {}       O     16462  public.screening_ledger_reject_mutation()
screening_ledger_anchor_no_truncate                   34     t         0      {}       O     16846  public.owl_reject_truncate()
screening_ledger_retention_tombstone_immutable        27     t         0      {}       O     16462  public.screening_ledger_reject_mutation()
screening_ledger_retention_tombstone_no_truncate      34     t         0      {}       O     16846  public.owl_reject_truncate()

pg_proc oid 16462  prosrc " BEGIN RETURN NEW; END "
                   sha256 b3771fd2...  (was 5632734b...)
```

Every observer reports clean, and `Migrate()` does not repair:

```
grant-ddl-ownership       -> EXIT=0, 3 PASS lines, 0 FAIL lines
screening-ledger migrate  -> {"operation":"migrate","provisioned":true,"provisioning_reason":"",
                              "screening_ledger_anchor_owner":"owl_ledger_ddl","status":"ok"}
prosrc after migrate      -> " BEGIN RETURN NEW; END "     <- unrepaired
```

Exploited at T1, as `owl_ledger_ddl` (`rolsuper=f`), using only privileges D61's own declared matrix
grants:

```
UPDATE screening_ledger_retention_tombstone SET reason='no retention obligation',
       operator='someone-else' WHERE snapshot_sha256='snap-cap9';        -> UPDATE 1
 snap-cap9 | 2026-08-01 10:00:00-04 | someone-else | no retention obligation

[the same one statement against owl_reject_truncate(), then:]
TRUNCATE screening_ledger_retention_tombstone;   -> tombstone rows after: 0
TRUNCATE screening_ledger_anchor;                -> anchor rows after:    0
```

**Decision: the declared trigger property set gains the bound function's body, as a closed set of
accepted `prosrc` digests declared per guard function and joined through the trigger's own `tgfoid`.**

`requiredProtectedTriggerState` and D62(a)/D69's cross-language declaration gain, per declared
trigger, an `acceptedBodySHA256 []string`. The comparison joins `pg_trigger` to `pg_proc` on
`tgfoid`, so it verifies the body of the function the trigger **actually calls** rather than the body
of whatever function currently bears the declared name -- the two are the same object today and the
join is what keeps them the same object under a future rebind. Illustrative shape only:

```sql
SELECT encode(sha256(convert_to(p.prosrc, 'UTF8')), 'hex') = ANY($7)
FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
WHERE t.tgrelid = $1::regclass AND NOT t.tgisinternal AND t.tgname = $2
```

Executed against the exact reproduction above, and against both over-tightening positives:

```
neutered clone, D69's four properties      -> behaviourOK = TRUE   (accepted today)
neutered clone, the proposed body digest   -> bodyOK      = FALSE  (refused)
    naming screening_ledger_anchor_immutable and screening_ledger_retention_tombstone_immutable,
    and NOT the two _no_truncate triggers, whose function was untouched

clean migration-bootstrapped baseline      -> bodyOK = TRUE for all four
clean SchemaSQL-only-bootstrapped database -> bodyOK = TRUE for both functions
```

**The set has two members for one function, and that is forced by execution rather than chosen.**
CAP #8 section 11 point 1 recommends the opposite -- *"`SchemaSQL` already contains the authoritative
text of both functions, so the declaration has a natural home and needs no new literal in a third
place."* **There is no single authoritative text.** `owl_reject_truncate()` is created by two
independent bootstrap paths whose literals disagree on whitespace:

```
db/migrations/012_truncate_guards.sql:9-12   ->  " BEGIN\n  RAISE EXCEPTION ...;\nEND "
internal/screeningledger/postgres.go:1576    ->  " BEGIN RAISE EXCEPTION ...;END "

measured on one cluster, two databases:
  owl_ci                 (migrations)  owl_reject_truncate  e8db5083...
  owl_ci_schemasql_only  (SchemaSQL)   owl_reject_truncate  fd848d02...
  both databases                       screening_..._mutation 5632734b...   <- agrees, 008g:10 == postgres.go:1553
```

Declaring only SchemaSQL's text -- the CAP's own recommendation, implemented literally -- returns
**two FALSE on a clean, unattacked, migration-bootstrapped baseline**, which is every CI database and
the production bootstrap path:

```
screening_ledger_anchor_no_truncate                live e8db5083...  declared fd848d02...  bodyOK=f
screening_ledger_retention_tombstone_no_truncate   live e8db5083...  declared fd848d02...  bodyOK=f
```

That is **D45's pre-declared false-failure shape** and it engages **D75's own withdrawal condition**
("if D69's property set cannot be stated as a stable literal ... the implementation stops and this
addendum is amended rather than shipping a comparison covering some properties and not others"). The
condition is answered here rather than left to be tripped in implementation.

**Convergence to one text was investigated and is not available**, which is why the set and not the
merge is the decision:

- **A repairing migration cannot run.** `CREATE OR REPLACE FUNCTION owl_reject_truncate()` in a new
  migration executes as `owl_migrator` and is refused by D34 on every already-provisioned database
  -- the same refusal transcribed under D76 point 4. A migration that fails on every deployed
  database is not a migration.
- **Rewriting SchemaSQL's literal converges nothing that already exists.** SchemaSQL creates the
  function only when `to_regprocedure(...) IS NULL`, so an existing SchemaSQL-bootstrapped database
  keeps its current body regardless.

Both texts are committed, reviewed and unwritable from the database, so the set is closed in D31's
sense -- a closed set of declared values, not a pattern and not a range. **R35 records the cost**: a
third bootstrap path, or an edit to either literal, must add its digest here, and a CI gate is named
in D85 to make that failure loud rather than silent.

**Where it is asserted.** Both places, for D62(a)'s and G-A's reason -- the installer and the
verifier must fail independently:

- **The installer** (`provision_test_roles.sh:645-667`, D69's own loop, extended) refuses to record a
  relation whose declared trigger's bound body is not in the accepted set, naming the trigger, the
  function and the live digest.
- **`protectedRelationStateReason`** (`postgres.go:667-697`) asserts the same, so
  `screening-ledger status` reports the state rather than only the next `grant-ddl-ownership` run.

**Neither the body nor D69's four properties is sufficient alone, and this is measured rather than
argued.** The body digest alone misses `WHEN (false)` and `UPDATE OF <column>`, which do not touch
the function at all; D69's four miss the body swap. The "replace, do not supplement" reasoning D39
and D50 used does not apply, for the reason D69 already gave about its own four: these are
independent properties, and each is the only one that sees its own substitution.

---

### D78. M-A, the bootstrap half: SchemaSQL's presence guard becomes an assertion

**The finding, restated from the code.** `SchemaSQL` guards both function definitions with
`IF to_regprocedure('screening_ledger_reject_mutation()') IS NULL THEN` (`postgres.go:1552`) and
`IF to_regprocedure('owl_reject_truncate()') IS NULL THEN` (`:1575`). That is
presence-implies-correctness -- the third shape D21's general form (`0007:1657-1662`) declares "never
safe" -- so `Migrate()` neither repairs nor detects the swap, which is the transcript under D77.

The comments at `:1536-1551` and `:1570-1574` argue the guard is safe because "once it exists its
protections either already are, or are about to be, in place," and explicitly retire the self-heal
CAP #2 credited in favour of D34's stronger prevention. **That argument was correct about the object
and wrong about the window.** D34 does prevent the replacement while it is enabled; the state D77
demonstrates is the one where it was not, and in that state the retired self-heal is exactly what is
missing and the guard's own reasoning no longer holds.

**Decision: both guards become D21's second safe shape -- assert and fail closed -- and deliberately
do not repair.**

The `DO` block asserts that the function exists **and** that its body digest is in D77's accepted
set, and raises naming the function, the live digest, the accepted set and the remedy. Repair is
rejected for a reason specific to this path rather than as a general preference: `Migrate()` runs as
`owl_migrator` on every CLI invocation, and a repairing `CREATE OR REPLACE` is refused by D34 on
every provisioned database -- so a repairing guard would convert a silent acceptance into a hard
failure of `migrate`, `sync` and `import-audit` on exactly the healthy databases it was meant to
protect. **A refusal that names the remedy is strictly better than a repair that cannot execute.**
D84 gives the operator that remedy as a documented step inside the recovery window.

The failure direction is fail-closed on a database whose guard has been altered, and unchanged on
every healthy one -- both bootstrap paths' digests are accepted, per D77.

---

### D79. M-D (HIGH): a refusal must not disarm the database

**The finding, reproduced with a control.** `grant-ddl-ownership` drops both event triggers at
`provision_test_roles.sh:478-479`, deliberately moved to the top of the step; the comment at
`:466-477` argues the widened window is "not a new exposure, only a longer version of the one this
idempotent, superuser-only script has always had." **That argument holds only if the step
completes.** `set -euo pipefail` plus an explicit `exit 1` at D62(a) (`:605`, `:610`), D69 (`:664`)
and D56/D71 (`:720`) means it does not, and `CREATE EVENT TRIGGER` is at `:998-999`.

Executed, in the state the operator document creates:

```
[only _on_alter down, as docs/operations/sec7-database-copies.md:187 instructs]
grant-ddl-ownership -> EXIT=1
  FAIL: declared trigger screening_ledger_anchor_immutable on screening_ledger_anchor does not
        match its declared behavior ... (ADR-0007 Addendum 8 D69)
pg_event_trigger count AFTER the refusal -> 0
```

The consequence, executed as `owl_ledger_ddl` (T1, non-superuser) in the state that refusal leaves,
against a clean control:

```
[after the D69 refusal]        DROP TRIGGER screening_ledger_anchor_no_truncate ...  -> DROP TRIGGER
                               TRUNCATE screening_ledger_anchor;                     -> TRUNCATE TABLE
                               DROP TABLE screening_ledger_anchor CASCADE;           -> DROP TABLE
                               to_regclass('screening_ledger_anchor') IS NOT NULL    -> false

[control: pristine database]   DROP TABLE screening_ledger_anchor CASCADE;
  -> ERROR: ADR-0007 Addendum 3 D34: public.screening_ledger_anchor (objid 16914) is protected
            by a superuser-only DDL event trigger and cannot be dropped
```

The identical statement is refused on the pristine database and succeeds after the remedy tool
refused. **The refusal is fail-closed for recording and fail-open for enforcement**, and none of the
five `FAIL` messages says so.

**Is this closable, or is it a residual to name honestly? It is closable, and the two must not be
confused.** The brief asks the question and it deserves a decided answer:

- **The T2 window itself is NOT closable and stays named honestly.** A bootstrap superuser who
  disables the event triggers can neuter any control in this document. That is R30, and R12/R17 put
  every residual in this arc at the same terminus. D51's "accident boundary, not security boundary"
  call is the right shape for that, and nothing here changes it.
- **M-D is not that residual.** "The remedy tool leaves the database *less* protected than it found
  it" is statement ordering in a script this repository owns. It is not a property of PostgreSQL and
  it is not a consequence of the T2 premise -- a refusal that had not dropped the triggers would
  leave the database exactly as protected as it was.

**Decision: the preconditions move above the drop, and any non-zero exit restores what the step took
down.**

- **Hoist.** D62(a) (`:592-628`), D69/D77 (`:645-667`) and D56/D71 (`:702-723`) move above
  `:478-479`. **Verified that this is possible rather than assumed**: all three are pure `SELECT`s,
  and each was executed against the pristine baseline with both event triggers `ENABLE ALWAYS`,
  returning its correct value and leaving both triggers at `'A'`:

  ```
  [both event triggers 'A']
  D69's behaviour probe            -> behaviour_ok = t
  D62(a)'s undeclared-index probe  -> (0 rows)
  D71's existence probe            -> present = 1
  pg_event_trigger after all three -> both still 'A'
  ```

  No DDL, so `ddl_command_end` never fires. The ordering that makes D62(a) a precondition of the
  `DELETE FROM sec7_protected_relation` at `:668` is preserved -- moving the checks earlier only
  strengthens it.
- **Restore on failure.** Hoisting closes the three refusals this arc added; it does not close a
  failure occurring anywhere else after `:478` (a `psql` error, the row-count assertion at `:684-687`,
  D56's loop). A `trap` on non-zero `EXIT` re-creates both event triggers if they are absent,
  because the script's own postcondition should be "either fully provisioned, or exactly as
  protected as when I started" and is currently neither.
- **Say it in the message.** Every `FAIL` in this step names the remedy; none names the state. Each
  gains a sentence stating whether enforcement is currently live, so an operator reading only the
  error knows whether the database is exposed.

---

### D80. M-C (HIGH): the declared index referent becomes what the index *is*

**The finding, reproduced.** `requiredProtectedRelationStates` (`postgres.go:547-568`) declares
`indexNames: []string{"screening_ledger_anchor_pkey"}` and nothing else about the index. D71's
verifier limb (`:610-626`) is a pure `EXISTS` per declared name; the installer limb (`:702-723`) is a
pure existence loop; D62(a)'s index check (`:610`) refuses only an **undeclared** name. `index_defs`
is compared recorded-against-live, and `grant-ddl-ownership` re-records it from live -- the launder
D69 closed for triggers, still open for indexes.

Executed on a `TEMPLATE` clone, inside the documented recovery window (drift note 1):

```
                              indisunique indisprimary indkey  definition
pristine                          t            t       "1 2"   CREATE UNIQUE INDEX ... (ledger_id, sequence)
after substitution                f            f       "1"     CREATE INDEX ... (ledger_id)

D71's existence check on the substituted index   -> indexPresentOK = TRUE   (accepted)
grant-ddl-ownership                              -> EXIT=0, 3 PASS lines
recorded index_defs, re-recorded from live       -> {"CREATE INDEX screening_ledger_anchor_pkey
                                                     ON public.screening_ledger_anchor USING btree (ledger_id)"}
screening-ledger migrate                         -> "provisioned":true, "provisioning_reason":""
```

D69 gave triggers behaviour; D71 gave indexes existence. CAP #7 section 11 point 1 asked for both
halves in one sentence and Addendum 8 implemented one of them.

**Decision: the declared index gains the properties that make a primary-key index the control it is.**

Beside `indexNames`, per declared index: `indisunique`, `indisprimary`, `indkey`, and
`indpred`/`indexprs` both null. Every value measured on the shipped baseline rather than transcribed
from the migration:

```
screening_ledger_anchor_pkey                 indisunique=t indisprimary=t indkey="1 2" indpred=NULL indexprs=NULL
screening_ledger_retention_tombstone_pkey    indisunique=t indisprimary=t indkey="1"   indpred=NULL indexprs=NULL
```

Each is load-bearing and each sees a different substitution: `indisunique` sees the non-unique index
above; `indisprimary` distinguishes a constraint-backed primary key from a bare unique index, which
matters because only the former is what `ON CONFLICT` and the foreign keys resolve against;
`indkey` sees a correctly-unique index on the **wrong columns**; `indpred` sees a partial index that
enforces uniqueness over only some rows; `indexprs` sees an expression index that enforces it over a
transform of them. Executed against the substitution, the proposed assertion returns
`indexShapeOK = FALSE` where D71 returns `TRUE`.

`indisvalid`/`indisready` are **not** added here: D65 already asserts them (`postgres.go:596-609`),
D71 repaired that branch's vacuity, and this addendum does not touch it.

**Why this does not subsume D71 and must not be read as doing so.** A shape check on an index that
does not exist has nothing to evaluate; D71's `EXISTS` is what makes D80 meaningful, exactly as D71's
own text says of D69 (`0007:7073-7077`). **D80 and D71 are stated separately so a later change cannot
remove one on the other's strength**, the arrangement D41 part three set for D40.

**D77 and D80 ship together.** D75's own withdrawal condition forbids "shipping a comparison covering
some properties and not others"; that condition is engaged for indexes today, and shipping D77 alone
would engage it again in the same round that closed it for triggers.

---

### D81. M-B (HIGH): the `purged_at` bound is asymmetric

**The finding, measured rather than reasoned about.** `purgeAttributionMismatch` (`anchor.go:307-314`)
compares `operator` and `reason` for equality and `purged_at` as `record.PurgedAt.After(anchoredAt)`
(`:311`). `time.Time.After` is strict and there is no second comparison, so the bound exists in one
direction only. Measured at microsecond resolution, the resolution PostgreSQL `timestamptz` stores:

```
purged_at == anchored_at         -> ACCEPTED
purged_at == anchored_at + 1us   -> REJECTED
purged_at == anchored_at - 1us   -> ACCEPTED
purged_at == 1999-01-01          -> ACCEPTED
purged_at == year 1              -> ACCEPTED
```

The bound is exact and correct in the direction it points; there is nothing to game at that edge. A
tombstone backdated to 1999 with `operator` and `reason` intact verifies clean end to end, so **the
*when* of a retention claim is unauthenticated -- and the *when* is the half a retention obligation
is actually stated in.** "Purged within 90 days" and "purged in 1999" are different claims about the
same row, and only one of them is checked.

**Why the current implementation enforces one side only, stated from D70's own text rather than
guessed.** D70 (`0007:6975-6980`) rejects `OccurredAt` as a comparand because the tombstone's
`clock_timestamp()` and the audit entry's `OccurredAt` are different clocks -- a Go process's
`time.Now()` against Postgres's own -- and an equality there would be a false-failure generator,
D45's pre-declared shape. **That reasoning is sound and this addendum preserves it.** What it
justifies is rejecting *equality against `OccurredAt`*. What it does not justify, and what the
implementation silently took from it, is leaving the direction **unbounded**. An ordering bound is
not an equality, and the two clocks' skew is bounded in practice while 27 years is not.

**Decision: `purged_at` gains a lower bound in the same clock domain the upper bound already uses.**

The upper bound compares against `anchoredAt`, which is `screening_ledger_anchor.anchored_at` -- a
Postgres `clock_timestamp()` from the same database as `purged_at`, which is precisely why D70 chose
it. The lower bound is drawn from the same domain: the `anchored_at` of the **anchor immediately
preceding** the one that attests to this purge. A legitimate purge is written by
`Store.PurgeExpired` (`RecordPurge`, then `AppendAudit`) after the previous anchor and before the
next, so the true window is exactly `(previous anchor's anchored_at, attesting anchor's anchored_at]`
-- both endpoints in one clock, no cross-clock comparison introduced, and no legitimate skew can
fail it because there is no second clock involved.

Where no previous anchor exists (the first anchor in a chain), the lower bound falls back to the
snapshot's own `created_at` -- a purge cannot predate the thing it purges -- which is again a
Postgres value from the same database. **Both fallbacks are stated so the implementation does not
have to choose one silently**, and the genesis case is named rather than left to be discovered, which
is the correction Addendum 3's own genesis-boundary finding (H-A) was about.

---

### D82. M-E (CRITICAL): the reverse pass's population

**Severity, decided here rather than left open.** CAP #8 section 7.5 rates M-E HIGH and states
explicitly that "if this project weights 'invariant limb false at T1, with no precondition at all'
above 'the forged claim names data outside the ledger', M-E escalates to CRITICAL," leaving the
judgement visible rather than resolving it -- the same convention Addendum 8 met for L-B.
**This addendum rates M-E CRITICAL**, on the ground the arc has used for every prior CRITICAL:

- **The invariant limb section 1 names is demonstrably false, end to end, at T1.** Every prior
  CRITICAL in this document (F-E, G-C, H-A, L-B, M-A) was rated on exactly that. M-E meets it at the
  **lowest reachability tier in the threat model** -- `owl_ledger_ddl` is a role section 2 admits by
  name, the privilege is one D61's own matrix declares, and there is **no precondition at all**: no
  superuser, no event-trigger disable, no laundering, one `INSERT`. Every other finding in this arc
  terminates at the bootstrap superuser (R12/R17). This one does not.
- **The counter-argument, recorded rather than resolved silently:** the forged claim concerns a
  snapshot outside this ledger's own history, so no statement this ledger makes about *its* data is
  made false, and the scope limit that causes it is a stated design decision with a real motivation
  rather than an oversight. A reader who weights blast radius over reachability should read this as
  HIGH. This addendum does not, because a fabricated retention record attributed to a named operator
  under a named policy, in a table an auditor reads, is the artifact the invariant exists to protect
  -- and "outside this ledger's history" is a property of the *forgery's content*, not of the
  system's ability to detect it.

**The finding, restated from the code and reproduced.** `AllPurgeRecords` (`postgres.go:1400-1409`)
is `WHERE snapshot_sha256 = ANY($1)`, `$1` being `VerifyReport.KnownSnapshotSHA256`, passed at
`anchor.go:378`. The forward loop is driven by which snapshots the *local envelope* marks purged, so
a row for a snapshot the chain never references generates no claim either. Both directions are blind
to the same population.

Executed against a clean, provisioned database, as `owl_ledger_ddl`:

```
INSERT INTO screening_ledger_retention_tombstone (snapshot_sha256, purged_at, operator, reason)
VALUES ('cap9unknown0000...0000','2020-01-01 00:00:00+00','compliance-bot',
        'purged under 90d retention policy');                              -> INSERT 0 1

the reverse pass's predicate, with a KnownSnapshotSHA256 not containing it:
  snapshot_sha256 | status
  snap-cap9       | IN reverse-pass scope        <- the fabricated row is ABSENT
```

**D70's scope limit is legitimate and this addendum does not remove it.** Its stated reason -- another
ledger's rows in a shared schema must never be named as this ledger's forgery -- is correct, and
widening the *adjudicating* scope would make a shared-schema deployment fail on rows it has no
standing to judge.

**Decision: the reverse pass keeps its adjudicating population and gains a second, unfiltered
reporting population.**

Two passes over one query rather than one widened query:

- **Adjudicated**, unchanged: rows whose `snapshot_sha256` is in `KnownSnapshotSHA256` are compared
  against the attesting entry and **fail** verification on divergence, exactly as D70 specified.
- **Reported**, new: every other tombstone row is surfaced in `VerifyReport` -- named, counted, and
  carried into the CLI's output -- without failing verification. A row this ledger cannot adjudicate
  is not evidence of *this ledger's* forgery, but its existence is a fact the verifier currently
  destroys and an auditor needs.

**Reporting is sufficient to close M-E and adjudicating is not available**, and the distinction is
the whole decision: the failure M-E demonstrates is that the row is *invisible*, not that it is
*unjudged*. A deployment that owns its schema exclusively -- which is every deployment this
repository configures -- can then treat a non-empty report as a failure by policy, and a
shared-schema deployment retains D70's correct behaviour. R36 records that this addendum does not
make the single-tenant case fail closed on its own, and why.

---

### D83. M-F, M-I, M-J, M-K: the DR tooling, and a withdrawal that is honoured rather than argued

**M-F -- the D74 reaper is withdrawn, because its own pre-declared condition is met.** D75 states:
*"If D74's L-E reaper is found to interfere with concurrent CI jobs sharing a runner, the reaper is
withdrawn and the manual cleanup step ships alone, with the residual re-stated in the PR rather than
quietly widened."* CAP #8 section 7.7 executed exactly that interference -- two runs three seconds
apart sharing the default `DR_DATA_DIR`, where run B's reaper stopped run A's **live, healthy**
cluster and `rm -rf`'d its data directory, run A failing at step 2 with `connection refused`.

**The condition is met and the reaper is withdrawn. It is not patched.** That is the point of
pre-declaring a withdrawal condition, and this addendum honours it rather than re-arguing it. The
concurrency race was not re-executed during this design pass; it did not need to be, because the
mechanism is visible in the code and is sufficient on its own:

```
scripts/ci/verify_cross_cluster_dr.sh:87-91
if [[ -f "$DR_DATA_DIR/postmaster.pid" ]]; then
  echo "== D74 L-E: reaping a cluster a previous (likely SIGKILLed) run left running at $DR_DATA_DIR =="
  "$PG_BIN_DIR/pg_ctl" -D "$DR_DATA_DIR" -m immediate stop >/dev/null 2>&1 || true
fi
rm -rf "$DR_DATA_DIR"
```

The predicate is the **presence** of a `postmaster.pid`, with no test of whether the process it names
is alive, and no test of whether it belongs to a dead run rather than a live one. **That is D21's
condemned shape one domain over** -- presence implies abandonment, exactly as presence implied
correctness -- and it is worth naming, because the arc's own principle predicted this failure in a
place nobody was looking for it. `pg_ctl -m immediate stop` then acts on a healthy cluster, and
`rm -rf` completes the damage.

**What replaces it**, since D74's finding (a `SIGKILL`ed run leaks a live cluster, and `SIGKILL`
cannot be trapped) remains true and unanswered:

1. **A unique per-invocation data directory.** The fixed path existed *only* so a later run could
   rediscover the leak; with the reaper gone the reason is gone, and a per-invocation directory means
   two concurrent runs have nothing to collide over. This also closes M-K entirely: the ~60 s
   `pg_ctl` stall and the `rm -rf` against a world-writable predictable path both disappear with the
   fixed path that caused them.
2. **The manual cleanup step D74 promised and never shipped.** D74's decision text names
   `pg_ctl -D <dir> -m immediate stop` explicitly; `grep -c pg_ctl docs/operations/sec7-database-copies.md`
   returns **0**. D84 ships it.
3. **The script prints its own data directory at startup**, which is what makes step 2 actionable
   against a non-fixed path -- an operator whose run was `SIGKILL`ed needs the path, and with the
   fixed path withdrawn the script is the only thing that knows it.

**The residual is stated rather than closed:** on a developer workstation, a `SIGKILL`ed run leaks a
running cluster until the operator runs the documented command or reboots. CI is bounded by the
ephemeral runner (`ci.yml:39` `ubuntu-latest`, `release-qualification.yml:31` `ubuntu-24.04`, both
destroyed after the job), as D74 already recorded. **A mechanism that reliably reaps only abandoned
clusters is available** -- a fixed *parent* directory with one subdirectory per invocation, reaped
only where the recorded PID fails a liveness test -- and it is deliberately **not** adopted here: it
is the same shape as the withdrawn reaper with a better predicate, and adopting a variant of a
mechanism in the same round its withdrawal condition fired is how a withdrawal becomes decorative.
R37 records it as available for a later addendum if the leak proves painful in practice.

**M-I -- the temp-file leak, closed as a class rather than as a third instance.** Measured on a
**successful** run of the script during this design pass:

```
system temp entries before: 2763
system temp entries after:  2764
new entry: <TMPDIR>/tmp.ljMNN13pon   15M   drwx------
             containing: screening-ledger (15,255,058 bytes)
```

**D75 test 5's own obligation -- "a run leaves the system temp directory's file count unchanged
(L-F)" -- is unmet by the implementation that claimed it.**

**Why the fix did not hold, which is the part that matters because this has now failed twice.**
`cleanup()` (`:64-75`) enumerates temp paths **by name**: `DR_DATA_DIR`, `DR_SOCK_DIR`, and -- added
by D74 -- `DR_LOG` and `DR_ERR_TMP` (`:74`). Every future `mktemp` must be remembered and added by
hand. The same commit that added `DR_LOG` to that list added `DR_BINARY="$(mktemp -d)/..."` (`:222`)
and did not. **The fix was an instance fix for a class defect** -- Addendum 1's original diagnosis of
this entire arc (`0007:1494-1497`), reappearing inside a remediation written for it. A third instance
already exists and no CAP has named it: `DR_BOOTSTRAP_PWFILE` (`:103`) is freed at `:107` on the
success path only and is absent from `cleanup()`, so an `initdb` failure leaves a file containing a
cluster's bootstrap password in the system temp directory.

**Decision: the enumeration is removed rather than extended.** One `mktemp -d` scratch root is
created once, at the top; `DR_SOCK_DIR`, `DR_LOG`, `DR_ERR_TMP`, `DR_BOOTSTRAP_PWFILE`, `DR_BINARY`
and the per-invocation data directory are all allocated **inside** it; `cleanup()` removes that single
root. A new temp path then cannot be added without being covered, because there is nowhere else to
put one. This is D31's closed-set answer applied to the script's own scratch state, and it is the
only form of this fix that a fourth instance cannot defeat. **D85 makes the temp-count assertion a
test rather than a claim, specifically because the claim has now been made twice and been wrong
twice.**

**M-J -- what the scram change closed, and the custody model for what it did not.** D74's
`--auth=scram-sha-256 --pwfile` genuinely ends passwordless access, verified by CAP #8 against a real
`SIGKILL` orphan (`fe_sendauth: no password supplied`). What remains:

```
scripts/ci/verify_cross_cluster_dr.sh:31   : "${PRIMARY_PGSUPERPASSWORD:=owl_ci}"
.github/workflows/ci.yml:289                 PRIMARY_PGSUPERPASSWORD: owl_ci
.github/workflows/release-qualification.yml:251   PRIMARY_PGSUPERPASSWORD: owl_ci
```

`owl_ci` is published in this repository, and `listen_addresses` stays `localhost`, so any local user
who reads the repository reaches a full logical copy of the primary's SEC-7 database as the bootstrap
superuser for the life of the run.

**The custody model, stated as the brief asks, because "rotate it" is not a model:**

1. **A CI-only credential is generated per run and never defaulted.** The script **already does
   exactly this** thirty lines below the defect -- `DR_BOOTSTRAP_PASSWORD` is 32 bytes of
   `/dev/urandom` (`:104`). The pattern is present, reviewed, and simply not applied to the one
   credential that outlives `initdb`. `PRIMARY_PGSUPERPASSWORD` for the **DR cluster** becomes a
   per-run generated value, and the `:=owl_ci` default is removed so an unset variable fails rather
   than silently selecting a published string.
2. **The distinction that decides the rule: a value that could be mistaken for a deployment default
   must not exist at all.** The risk is not that an attacker guesses `owl_ci` on a CI runner -- the
   ephemeral runner bounds that, and D74 said so correctly. The risk is that a value written in a
   workflow file, in a script default, and in an operator-facing repository is **copied** into
   something that is not CI. A per-run generated secret cannot be copied because there is nothing to
   copy. This is why the fix is "generate," not "change the value" or "move it to a secret."
3. **The primary-cluster credential is a different question and is not changed here.** The four
   `owl_*` passwords and `PGSUPERPASSWORD=owl_ci` for the *primary* CI database are fixtures the
   whole suite depends on, they are set in both workflows, and changing them is a CI-wide change with
   its own blast radius. **Named as out of scope rather than silently left**: this addendum changes
   the credential the DR script *creates*, not the credentials CI *provisions*.
4. **Both workflow files are named as the implementation target**, so the pair cannot drift. They
   match today -- both were read in full during this design pass, and `ci.yml:283-291` and
   `release-qualification.yml:245-253` carry the identical `PG_BIN_DIR` and five `PRIMARY_*`
   variables -- and per CLAUDE.md Boundaries the workflow wiring for this change is named explicitly
   in the stage PR description, following D30's precedent.

**M-K -- withdrawn with the fixed path**, per the reasoning under M-F. CAP #8 recorded it honestly as
narrower than it first looks -- `pg_ctl` validates the data directory, so no arbitrary-process-kill
primitive was demonstrated -- and both halves of what remained (a ~60 s stall, a `rm -rf` against a
path another local user can own first) are properties of the fixed path rather than of the reaper's
logic.

---

### D84. M-G, M-H: the operator document

**M-G -- the Addendum 8 implementation changed no documentation at all.** `git show --stat 1949763`
lists eleven files, none under `docs/`. Greps against `docs/operations/sec7-database-copies.md` at
this commit: `pg_ctl` 0, `immediate stop` 0, `D69` 0, `D71` 0, `D72` 0, `D73` 0, `D74` 0,
`Addendum 8` 0. D74's decision text promises the manual cleanup step by name and it is absent, and
the document nowhere records the two new refusal modes `grant-ddl-ownership` gained.

**M-H -- the required first step of both recovery procedures is not runnable as written.** The
invocation at `:86`, run literally against a live provisioned database:

```
screening-ledger status --postgres-dsn-env <VAR> --policy-file <policy> --policy-public-key-file <key>
  -> rc=1   "snapshot encryption key is required"
```

The error names none of the flags it actually needs. Fully specified -- adding `--key-file`/`--key-env`,
`--anchor-key-file`/`--anchor-key-env`, `--ledger-dir` and `--ledger-id` -- it works and is correctly
fail-closed, **so the control is sound and the document is wrong**. Recorded as a smaller
observation rather than a finding, because it makes the above worse: the CLI **silently accepts
unknown flags**, verified by execution (`--totally-bogus-flag xyz` returned `rc=0` with no
diagnostic), so an operator who mistypes a flag in this procedure gets no signal at all.

**Decision: the document is brought level with what the code does, and every claim in it is executed
before it is written.** It gains:

- **The corrected step 0**, with the full flag list, transcribed from an invocation that actually ran
  rather than reconstructed.
- **D74's manual cleanup step**, `pg_ctl -D <dir> -m immediate stop`, against the data directory the
  script now prints (D83).
- **The refusal modes**: D62(a)'s two, D69/D77's, D56/D71's, and D80's -- what each means and what to
  do about it.
- **M-D's warning**, until D79 lands, and D79's postcondition after it: what state a refusal leaves
  the database in, and how to confirm enforcement is live before trusting the clone.
- **D78's repair procedure**: the operator action for a guard function whose body no longer matches,
  which is the remedy D78 deliberately does not perform automatically.

**This decision is a shipping requirement, not a nicety.** D74 promised a documentation change,
Addendum 8's implementation shipped none, and a document that describes a procedure nobody executed
is the same defect as a control nobody tested -- which is the failure this entire arc exists to
correct. **D85 requires that every command written into this document was run, with its output
pasted in the stage PR.**

---

### D85. Test ownership and pre-declared withdrawal conditions

The specific shape the implementation must satisfy, so nothing weaker can be claimed to discharge
this addendum -- the standard D20 (`0007:1293-1338`), D26 (`0007:1874-1885`), D37 (`0007:2623-2662`),
D42 (`0007:3455-3523`), D49 (`0007:4237-4307`), D58 (`0007:5231-5321`), D67 (`0007:6365-6461`) and
D75 (`0007:7296-7344`) set.

**Every test below must fail before its change, per CLAUDE.md rule 5.** Where a CAP #8 transcript
exists the test reproduces that transcript, not a paraphrase. Several are stated as "must pass today
and fail after" -- deliberately, per D42's note (`0007:3461-3465`): for these findings the current
behaviour is *acceptance*, so a test asserting only the post-fix refusal cannot distinguish a working
fix from a test that never exercised the path.

1. **D77.** `TestGuardFunctionBodyIsDeclaredNotAddressed` (pgx): CAP #8 section 7.1's exact
   reproduction -- `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE` followed by one
   `CREATE OR REPLACE FUNCTION`, and **nothing else** -- asserting that D69's four properties are
   byte-identical after it, that `grant-ddl-ownership` exits 0 and `CheckProvisioningState` returns
   `Provisioned=true Reason=""` **today**, that the tombstone forgery and the `TRUNCATE` it enables
   actually succeed as `owl_ledger_ddl` (otherwise the test proves a probe changed rather than a hole
   closed), and that both refuse after, naming the trigger, the function and the live digest. Both
   guard functions, both protected relations.
   **Plus the over-tightening positives, which are a shipping requirement and not a nicety:** a clean
   **migration-bootstrapped** database and a clean **SchemaSQL-only-bootstrapped** database
   (`create-schemasql-only-database`) are both accepted. **This is the test that catches the
   single-digest error**; without the second positive, a declaration sourced from either literal
   alone passes its own suite and fails in CI or in production.
   **Plus a unit-level assertion that the two `owl_reject_truncate()` literals differ** --
   `db/migrations/012_truncate_guards.sql` against `internal/screeningledger/postgres.go`'s SchemaSQL
   -- so the fact that forces the two-member set is pinned by a test rather than only by this
   addendum's prose, and a later reader who "simplifies" the set to one member breaks a test that
   explains why.
2. **D78.** `TestSchemaSQLRefusesAnAlteredGuardBody` (pgx): `Migrate()` against a database whose
   guard body has been swapped returns `"provisioned":true` and leaves the body unrepaired **today**,
   and fails closed after, naming the function and the remedy. Plus the positive: `Migrate()` on both
   bootstrap paths, and repeated `Migrate()` on a fully provisioned database, still succeed -- the
   case D34 would refuse if this were implemented as a repair.
3. **D79.** `TestRefusalPathLeavesEnforcementInstalled` (shell or pgx): for **each** of the five
   refusal paths (D62(a)'s undeclared trigger and undeclared index, D69/D77's behaviour, D56/D71's
   missing object, D80's index shape), assert `grant-ddl-ownership` exits 1 **and**
   `SELECT count(*) FROM pg_event_trigger` is **2**, both `evtenabled='A'`. Today that count is 0,
   measured. Plus the consequence as a named regression: `DROP TABLE screening_ledger_anchor CASCADE`
   as `owl_ledger_ddl` is refused by D34 after a refusal, where it succeeds today. Plus the
   over-tightening positive: a clean run still provisions and still installs both triggers.
   **The test must run each refusal in the documented recovery state** (`_on_alter` disabled), per
   drift note 1, or it will not reproduce.
4. **D80.** `TestDeclaredIndexShapeIsVerifiedNotOnlyPresence` (pgx): CAP #8 section 7.3's exact
   substitution on both relations, asserting `grant-ddl-ownership` exits 0 and
   `CheckProvisioningState` returns `Provisioned=true` **today**, that the duplicate
   `(ledger_id, sequence)` insert succeeds today so the consequence is proven rather than described,
   and that both refuse after. Table-driven over the five properties, each substitution changing only
   its own: non-unique, unique-but-not-primary, correct-uniqueness-wrong-columns, partial
   (`indpred`), and expression (`indexprs`). Plus the positive: both clean relations accepted, and
   D65's validity branch unregressed.
5. **D81.** `TestPurgedAtIsBoundedOnBothSides` (pgx): the boundary measured at microsecond
   resolution -- equal accepted, `+1us` rejected, `-1us` accepted **today**; and after, a `purged_at`
   before the preceding anchor's `anchored_at` rejected while all three of those keep their current
   verdicts. Plus CAP #8's own end-to-end case: a tombstone backdated to 1999 with attribution intact
   verifies clean today and fails after. **Plus the positive D45's rule requires**: a real
   `Store.PurgeExpired` purge, anchored, verifies clean, and clock skew between the Go process and
   Postgres does not fail it -- the false-failure D70 correctly refused to create.
6. **D82.** `TestReverseAdjudicationReportsUnknownTombstones` (pgx): CAP #8 section 7.5's exact
   single `INSERT` as `owl_ledger_ddl` for a snapshot outside `KnownSnapshotSHA256`, asserting
   `VerifyAnchored` returns `status=verified err=nil` **today** and that the row is named in
   `VerifyReport` after. Plus: rows **inside** the known set still **fail** verification on
   divergence (D70 unregressed, both existing reverse tests keep passing), and a clean ledger reports
   nothing.
7. **D83.** The DR script's own assertions become the test: a run leaves the system temp directory's
   file count **unchanged** -- asserted by counting, not by inspection -- and this obligation is
   restated from D75 test 5 **because it was claimed and unmet once already**; `cleanup()` removes one
   scratch root and the script contains no `mktemp` outside it, asserted by a grep-based unit check so
   a fourth instance cannot be added silently; no `PRIMARY_PGSUPERPASSWORD` default remains in the
   script or either workflow; and two concurrent invocations both succeed, which is the withdrawn
   reaper's own failure condition asserted as a test rather than left to a ninth CAP.
8. **D84.** Every command written into `docs/operations/sec7-database-copies.md` is executed and its
   output pasted in the stage PR, step 0 included. This is not automatable and is stated as a review
   obligation rather than pretended into a test.

**Withdrawal conditions, declared now rather than decided after the fact:**

- **D77 must not be reduced to a single declared digest per function.** It is the design CAP #8
  section 11 point 1 recommends and it is refuted above by execution: `owl_reject_truncate()` has two
  legitimate bodies, and a single digest fails closed on a clean, unattacked, migration-bootstrapped
  database. A later reader who rediscovers the simplification should find D77's two-database
  transcript and the D85 test 1 assertion that pins it.
- **`prosrc` must not be normalised, trimmed or whitespace-folded to collapse the two literals into
  one.** That would replace a closed set of two committed values with a hand-written equivalence
  relation over program text -- a new parsing surface, in a security comparison, invented in the same
  pass that implements it, which is exactly what CLAUDE.md rule 7 forbids and what D69's own
  rendering refutation was about. If the two texts genuinely must converge, that is a schema change
  with its own ADR, not a `regexp_replace` in a `WHERE` clause.
- **If D77's accepted-digest set cannot be stated for all four declared triggers across both
  bootstrap paths**, the implementation stops and this addendum is amended rather than shipping a
  comparison covering some triggers and not others -- D75's own condition, restated because D77 is
  the decision that engaged it.
- **D77 and D80 ship together**, per D75's "some properties and not others": D77 alone leaves indexes
  with presence where triggers have behaviour, which is the asymmetry this round exists to close.
- **D79 must not be implemented as "restore on failure" alone.** The hoist is the part that closes
  the three refusals this arc added; the trap is the backstop for everything else. A trap-only
  implementation leaves a window between `:478` and the first refusal in which a crash still
  disarms, and the hoist is free.
- **The withdrawn D74 reaper must not be reintroduced in this round, in any form, including a
  liveness-checking variant.** R37 records that variant as available to a later addendum. Adopting a
  variant of a mechanism in the same round its own withdrawal condition fired would make every future
  pre-declared withdrawal condition decorative, which is a worse outcome than the leak it addresses.
- **If D82's reporting population cannot be surfaced without changing `VerifyReport`'s contract
  beyond adding a field**, the implementation stops and the design is amended. It does not silently
  widen the *adjudicating* population instead -- that breaks the shared-schema case D70 correctly
  protects, and D70's reasoning for the limit is sound.

**Prior addenda's pre-declared withdrawal conditions remain correctly un-triggered**, re-verified
against what *this* addendum designs rather than inherited from CAP #8's confirmation. D65's branch is
untouched and D80 adds beside it rather than changing it, so Addendum 7's "assert validity in D47
only" fallback is **not** required. D50's collateral-damage cases are unaffected -- D77 and D80 add
assertions and never change `index_defs`, so D49's second withdrawal condition is not engaged and
Addendum 6's "record both `index_oids` and `index_defs`" fallback must not be adopted. D60's empty-set
assertion is untouched by this addendum, as are D72's allowlist and D73's two limbs -- CAP #8 found no
route past either and this addendum adds nothing to them. The instance binding is still not a gate.
D46 is not split from D45. D40's collateral-damage cases pass, so Addendum 4's `pg_depend` fallback is
not required. D38(a) and D38(b) remain shipped together. D69's rejection of `pg_get_triggerdef` is
re-verified by independent execution above and stands.

### New accepted risks

**R34 -- D76 is a declaration discipline, not an interception, and the T2 window is unchanged.**
Nothing in this addendum observes a substitution at the moment it happens: under T2 the event
triggers are disabled by the party performing it, which is the premise of the documented recovery.
D68's R30 said this and it is restated rather than assumed inherited, because D77 is the decision most
likely to be over-claimed. What changes is that a substituted **body** can no longer be recorded as
legitimate (D77 in `grant-ddl-ownership`), can no longer pass verification (D77 in
`CheckProvisioningState`), and can no longer be walked past silently by the bootstrap path (D78). It
converts an unobserved substitution into an observed one; it does not prevent it. **D34 is doing more
work here than a reader might credit** -- it refuses `CREATE OR REPLACE FUNCTION` in every state
except the one the operator document itself creates (D76 point 4). The residual terminates at the
bootstrap superuser, where R12/R17 put every other one.

**R35 -- the accepted-digest set is a new coordinated-edit literal, and it is the most fragile one
this document has added.** R23, R29 and R33 already track the cross-language declaration surface;
D77 adds a value that must change whenever either guard function's committed text changes, in Go and
in bash, and whose two-member cardinality encodes a whitespace difference between two files that a
routine reformat would silently alter. **The mitigation is a CI gate, named here rather than left to
the implementation's discretion**: a check that extracts both bootstrap paths' literal function
bodies from `db/migrations/*.sql` and `internal/screeningledger/postgres.go`, digests them, and
asserts the declared set is exactly that set -- so an edit to either literal fails the gate rather
than shipping a control that refuses every healthy database. Without that gate this decision is one
reformat away from being D45's false-failure shape, and this addendum states that plainly rather than
trusting review to catch it. The aggravating property section 10.3 names -- that these controls have
no single owner -- is unchanged and not addressed here.

**R36 -- D82 reports where a single-tenant deployment would want it to fail.** The reporting
population closes M-E's invisibility and stops short of failing verification, because this repository
configures no shared-schema deployment today but D70's limit exists to protect one. A deployment that
owns its schema exclusively should treat a non-empty report as a verification failure, and **that
policy is not expressed anywhere in this repository** -- there is no configuration surface for it and
this addendum does not invent one. The re-entry condition is the same one section 5.3 set for RFC 3161
and D70 set for R31: the first deployment that screens real traffic. Until then the fact is visible
and unjudged, which is strictly better than invisible and is honestly less than adjudicated.

**R37 -- the DR cluster leak is bounded by an operator action rather than by a mechanism.** With the
D74 reaper withdrawn (D83), a `SIGKILL`ed run on a workstation leaks a live cluster until the operator
runs the documented `pg_ctl` command. CI is bounded by the ephemeral runner. A liveness-checking
per-invocation reaper is the mechanism that would close this properly and is deliberately not adopted
in the round that withdrew its predecessor; it is recorded here so a later addendum has the analysis
rather than re-deriving it. **The failure mode this accepts is a leaked disposable cluster; the
failure mode it refuses is a mechanism that kills a healthy one**, which is what the withdrawn reaper
demonstrably did.

**R31 is re-stated as a live register item rather than a deferred one.** D70 argued against a
tombstone MAC and the argument is good **against a MAC as a replacement** for the anchored
adjudication. M-B, M-E and M-C's tombstone limb are three states in which the anchored attestation is
present, correct, and simply not asked the question -- and D81, D82 and D80 each close one of them
without a MAC. What none of them closes is R31's own case: an auditor reading the Postgres mirror
**alone**, with no ledger directory and no `K_anchor` cross-check, still gets no retention guarantee
from any of this. That is the follow-on ADR D70 scoped, its migration is still free at zero tombstone
rows and never free afterwards, and **the issue register should carry it as live**. This addendum
does not open it, for D70's own stated reason -- a new key, a new custody boundary and a new writer
identity is more than an addendum should introduce -- and does not let it drift out of view either.

### Staging

Same shape and reason as section 8 and the eight prior addenda (`0007:1397-1414`, `0007:2038-2058`,
`0007:2694-2716`, `0007:3566-3586`, `0007:4342-4367`, `0007:5360-5384`, `0007:6512-6540`,
`0007:7429-7459`): each stage independently reviewable and independently provable. Ordered by
dependency rather than severity.

1. **This addendum**, merged before any code (CLAUDE.md rule 7).
2. **Stage L1 -- the refusal that does not disarm.** D79. Sequenced **first**, ahead of the CRITICAL,
   which is a deliberate departure from every prior addendum's ordering and is argued rather than
   assumed: D77 and D80 each **add a refusal path**, and every refusal path added before D79 lands is
   another way to reach the state where the protected tables can be dropped. Shipping the CRITICAL
   first would make the database strictly easier to destroy for the duration between stages. D79 is
   also the cheapest stage in the round.
3. **Stage L2 -- the declaration.** D76, D77, D78 and D80 together (D75's and D85's "ship together"
   conditions). The CRITICAL, and the only stage that changes what a security check asserts about an
   object. D77's over-tightening positives across **both** bootstrap paths are a shipping
   requirement, and its withdrawal conditions are discharged or invoked here.
4. **Stage L3 -- the retention claim.** D81 and D82. Sequenced after L2 because both corroborate a
   tombstone whose own guard trigger L2 is what verifies, and because D82 carries the round's second
   CRITICAL at the lowest reachability tier -- it is not sequenced first only because it depends on
   nothing L1 or L2 breaks, and splitting `adjudicatePurgeClaims` across L2's edits would produce
   conflicting versions of one function.
5. **Stage L4 -- the DR tooling and the document.** D83 and D84. Blocks nothing, and is therefore
   sequenced last and explicitly **not** droppable -- D23 was sequenced last on the same "blocks
   nothing" reasoning and CAP #2 rated the resulting gap HIGH, a lesson Addendum 5's staging recorded
   (`0007:4348-4354`) and Addenda 6, 7 and 8 each repeated. **Addendum 8 is the round that proves the
   point**: its D74 promised a documentation change, its implementation shipped none, and M-G is that
   omission. Per CLAUDE.md Boundaries the workflow wiring for D83's credential change is named
   explicitly in the stage PR description, following D30's precedent.
6. **`SECURITY.md` and `README.md` language.** R3's rule unchanged. `README.md:93-97`'s
   requalification notice stays until every stage above has landed and its reproduction passes.
   CAP #8 section 9 re-confirmed that nothing in PR #157 or #158 re-asserted the guarantee; that must
   remain true through this addendum as well.

**SEC-7 does not close on this addendum, and for the second round running the reason is a forgery.**
Section 8's closing condition -- "a deliberately forged chain fails a CI run that nobody chose to
invoke" -- remains met for the **chain**: `anchorMAC` catches M-A's and M-C's anchor-side rewrites,
and CAP #8 re-confirms the cryptographic layer is unbroken across all eight rounds. It is **not** met
for the **retention claim**, which the invariant names alongside history and which this round forges
three ways -- one of them, M-E, at T1 with no precondition at all. D77 through D82 are the whole of
that barrier.

### Addendum 9 summary

- **CAP #8's verdict is QUALIFIED, not PASS, for the eighth consecutive audit, and for the second
  consecutive round it demonstrates a forgery.** Eleven findings. D31's scoping principle, Addendum
  4's referent principle, Addendum 5's population principle, Addendum 6's atomicity principle,
  Addendum 7's quantifier principle and Addendum 8's naming principle all held; this addendum reopens
  none of them.
- **The class is composition: a property set is only as strong as its weakest member.** D69 did what
  Addendum 8's principle prescribed -- it replaced a name with four catalog properties -- and the one
  property that says which code runs is `pg_identify_object(tgfoid)`'s identity, a string.
  `CREATE OR REPLACE FUNCTION` preserves the OID and replaces the body, so all four declared
  properties survive a guard that now returns `NEW`. **Adding properties to a set does not repair the
  weakest one.**
- **The design is D76-D85.** The composition principle with its PostgreSQL support established by
  execution (D76); the guard function's body as a closed set of accepted `prosrc` digests joined
  through `tgfoid` (D77); SchemaSQL's presence guard as an assertion that refuses rather than a repair
  that cannot run (D78); the remedy tool's refusals hoisted above its own teardown (D79); the declared
  index referent as what the index *is* (D80); `purged_at` bounded on both sides in one clock domain
  (D81); the reverse pass's second, reporting population (D82); the DR tooling with a withdrawal
  honoured rather than argued and a temp-leak class closed rather than a third instance patched
  (D83); the operator document brought level with the code (D84); and the proof obligations with
  pre-declared withdrawal conditions (D85).
- **This design pass executed its mechanism assumptions, and the execution refuted the fix CAP #8
  itself recommended.** `pg_proc.prosrc` is `search_path`-**insensitive**, identical in the recorder's
  and the verifier's sessions, readable by `owl_migrator` with no new grant, and **survives
  `pg_dump | psql` byte-identically while OIDs are reassigned** -- so it is a better referent than the
  `tgfoid` D69 already trusts. But **`owl_reject_truncate()` has two legitimate bodies**, because
  `db/migrations/012` and SchemaSQL disagree on whitespace, and the single authoritative text CAP #8
  section 11 point 1 assumes does not exist: declaring only SchemaSQL's returns two FALSE on a clean,
  unattacked baseline. **The guard functions were already protected objects and `ddl_command_end`
  already fires for `CREATE OR REPLACE FUNCTION`**, so there was no registry extension to make -- the
  gap is R30's window and nothing else. And **D62(a)'s, D69's and D71's precondition checks are pure
  `SELECT`s**, so M-D closes by statement ordering at zero cost.
- **Two severities are decided here rather than left open**, both with the counter-argument recorded
  rather than resolved silently. **M-A is CRITICAL** on both of Addendum 8's own grounds for L-B, each
  met more strongly -- permanently undetectable, and at a *lower* precondition than L-B, since
  `CREATE OR REPLACE FUNCTION` fires `ddl_command_end` alone and needs only the disable the operator
  document instructs. **M-E is escalated from CAP #8's HIGH to CRITICAL**, on the ground every prior
  CRITICAL in this document used: the invariant limb is demonstrably false end to end, and here at
  **T1 with no precondition at all** -- one `INSERT`, on a privilege D61's own matrix declares, by a
  role section 2 admits by name.
- **Four risks are recorded** rather than designed away: D76 is a declaration discipline and not an
  interception (R34); the accepted-digest set is the most fragile coordinated-edit literal yet added
  and gets a named CI gate (R35); D82 reports where a single-tenant deployment would want it to fail
  (R36); the DR cluster leak is bounded by an operator action rather than a mechanism (R37). **R31 is
  re-stated as live rather than deferred**: D80, D81 and D82 each close a state where the anchored
  attestation was present and simply not asked, and none of them reaches the mirror-only auditor D70
  scoped a follow-on ADR for.
- **This addendum revises no prior decision.** D1-D7, D8-D20, AR7, D21-D30, D31-D37, D38-D42,
  D43-D49, D50-D58, D59-D67 and D68-D75 stand. R1-R33 stand. D69's four properties are **kept and
  supplemented**, not replaced -- the body digest misses `WHEN (false)` and `UPDATE OF <column>`, and
  D69's four miss the body, so each remains the only member of the set that sees its own
  substitution. D69's refutation of `pg_get_triggerdef` was re-derived by independent execution and
  is re-affirmed.

**Audit basis commit:** `be62ceb3dcddc785a1312783740a422a94425aa3`

Every file:line citation in this addendum was verified against that tree -- the same commit CAP #8
was produced against, so no drift separates the audit from this design. For a CAP record covering the
implementation of this addendum, use the tip of whichever stage PR is under audit, not this value.
