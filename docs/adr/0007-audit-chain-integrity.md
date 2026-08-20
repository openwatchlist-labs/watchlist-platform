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
