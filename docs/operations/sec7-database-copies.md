# Operator procedure: copying, cloning, and restoring a SEC-7-protected database

ADR-0007 Addendum 5 (D43, D45, D46, D48). Read this **before** you clone, dump, or restore a
database that holds `screening_ledger_anchor` and `screening_ledger_retention_tombstone`.

## The one thing to know

The SEC-7 DDL protections -- the two event triggers installed by
`scripts/ci/provision_test_roles.sh grant-ddl-ownership` -- decide what to protect by looking up
**raw PostgreSQL OIDs** in two registry tables, `sec7_protected_object` and
`sec7_protected_relation`.

**An OID identifies an object inside one running database. It is not a property of the schema.**

`pg_dump` faithfully copies the registries *and* the event triggers, and copies their meaning not at
all, because the restored objects are assigned new OIDs. The result is a database where the
enforcement machinery is present and pointed at nothing.

**A database that has been logically copied is not protected until `grant-ddl-ownership` is re-run
on it.** Nothing about its appearance will tell you that: the tables are there, the owners are
right, the guard triggers are there, and both event triggers report `evtenabled = 'A'`.

## Which operations are safe

| Operation | Relation OIDs | Protections after the copy |
|---|---|---|
| `pg_dump --schema-only` restore | reassigned | **INERT.** The registries arrive empty (a schema-only dump carries no rows), so the event trigger function returns on every lookup. The table's owner can drop the anchor's immutability trigger. |
| `pg_dump` full restore / `pg_restore` | reassigned | **BROKEN.** The registry rows arrive pointing at OIDs that no longer exist, so every DDL statement in the database fails -- for every role, superuser included. See "Recovering a bricked restore" below. |
| `CREATE DATABASE ... TEMPLATE` | **preserved** | **Live and correct.** No action needed. |
| `pg_basebackup`, streaming replica, volume snapshot | **preserved** | **Live and correct.** No action needed. |

The rule behind the table: a **physical** copy preserves OIDs and needs nothing; a **logical** copy
reassigns them and must be re-provisioned.

## Before you clone production into staging

```sh
# on the clone, as the bootstrap superuser
PGDATABASE=<the clone> ./scripts/ci/provision_test_roles.sh grant-ddl-ownership
```

Then confirm it took, from a host that can reach the clone as `owl_migrator`:

```sh
screening-ledger status --postgres-dsn-env <VAR> --policy-file <policy> --policy-public-key-file <key>
```

Until that reports the database as provisioned, **the clone is not representative of production for
any SEC-7 purpose.** A schema review performed against an un-reprovisioned clone will report the
controls as installed and will be wrong.

## Reading `protected relation ... no longer exists`

Addendum 5 D46 gives this failure three distinct messages. They mean different things and have
different fixes.

**(a) "This database is a copy or restore of another"** -- the message names both the instance the
registries were recorded in and the instance you are on. This is the full-restore case. The database
is bricked for DDL until you re-provision. Follow "Recovering a bricked restore".

**(b) "the relation was dropped and recreated"** -- the instance matches, so this is not a copy:
someone dropped and recreated a protected relation in place (which requires the bootstrap superuser,
since the event triggers block it otherwise). Re-run `grant-ddl-ownership` to re-record the new
OIDs.

**(c) "no relation of that name is present"** -- the protected relation is genuinely gone. Do not
re-provision over this; find out what removed it first. `grant-ddl-ownership` will fail anyway, and
should.

A related message, `sec7_protected_object has 0 row(s), expected exactly 12`, is the **schema-only
clone** case. The registries were never populated in this database. Re-run `grant-ddl-ownership`.

## Recovering a bricked restore

Verified against a real restored database. Every step needs the bootstrap superuser.

```sh
# 1. get DDL working again. Either branch works; the first is narrower.
psql -c "ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE;"
#    or, per statement:  SET event_triggers = off;

# 2. re-record the registries against this database's actual OIDs
PGDATABASE=<the restored db> ./scripts/ci/provision_test_roles.sh grant-ddl-ownership

# 3. confirm both event triggers are back to ENABLE ALWAYS
psql -c "SELECT evtname, evtenabled FROM pg_event_trigger;"   -- expect 'A' for both
```

`ALTER EVENT TRIGGER ... DISABLE` succeeds even while the invariant is failing -- that was verified,
because a recovery path that itself needs working DDL would be no recovery path at all. Step 2
re-enables the triggers as part of its normal run; step 3 is the check that it did.

**Do not skip step 2 and simply leave the event triggers disabled.** That is the state described in
the first table row: everything looks installed and nothing is enforcing.

## `event_triggers = off` is not a bypass

The GUC is `SUSET`. A non-superuser -- including `owl_ledger_ddl`, the protected tables' own owner
and the role these controls exist to bind -- gets `permission denied to set parameter
"event_triggers"`. Re-confirmed by execution. The residual terminates at the bootstrap superuser,
where ADR-0007 R12 and R17 put every other residual in this design.

## What this does not cover

- **Backup content.** This document is about the protections, not the data. `pg_dump` remains a
  correct way to back the database up; the point is that the *restore* needs a re-provisioning step
  the backup does not record.
- **The ledger directory.** The file-backed chain, `R`, `K_anchor` and the Ed25519 policy keypair
  are separate custody concerns -- see `screening-ledger-policy-signing.md` for the policy key, and
  ADR-0007 §5.1-§5.2 for the rest.
- **Whether a copy's *history* is trustworthy.** Re-provisioning restores the DDL protections; it
  says nothing about the chain. Run `screening-ledger verify` in anchored mode for that.
