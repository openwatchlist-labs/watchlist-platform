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

**The target cluster needs the four `owl_*` roles first.** `grant-ddl-ownership` runs
`ALTER TABLE ... OWNER TO owl_ledger_ddl` and casts `owl_ledger_ddl`/`owl_migrator` to `::regrole` --
if this is a **different** cluster from the one the source database came from (the ordinary DR
shape), those roles do not exist there yet until `create-roles` has been run on it:

```sh
# on the target cluster, as the bootstrap superuser, ONLY if this is a different cluster
# from the source (roles are per-cluster, not per-database)
PGSUPERUSER=<bootstrap superuser> PGSUPERPASSWORD=<...> ./scripts/ci/provision_test_roles.sh create-roles
```

Then, on the clone itself:

```sh
# on the clone, as the bootstrap superuser
PGHOST=<host> PGPORT=<port> PGSUPERUSER=<bootstrap superuser> PGSUPERPASSWORD=<...> \
  PGDATABASE=<the clone> ./scripts/ci/provision_test_roles.sh grant-ddl-ownership
```

`PGHOST`/`PGPORT`/`PGSUPERUSER`/`PGSUPERPASSWORD` default to `localhost`/`5432`/`owl_ci`/`owl_ci`
(`scripts/ci/provision_test_roles.sh:33-37`) -- set them explicitly for any host or port other than
the defaults, or the command silently targets the wrong server.

**If the guard triggers are missing** (the state a restored `owl_ci_sec7_cloned`-style fixture is
in before this step runs, or the state left behind if `screening_ledger_anchor_immutable` was ever
dropped without being recreated), `grant-ddl-ownership` now names the missing trigger and refuses
before attempting the registry population, rather than failing later with a raw
`null value in column "objid" ... violates not-null constraint`.

Then confirm it took, from a host that can reach the clone as `owl_migrator`:

```sh
screening-ledger status --postgres-dsn-env <VAR> --policy-file <policy> --policy-public-key-file <key>
```

Until that reports the database as provisioned, **the clone is not representative of production for
any SEC-7 purpose.** A schema review performed against an un-reprovisioned clone will report the
controls as installed and will be wrong.

## Reading `protected relation ... no longer exists`

Addendum 5 D46, extended by Addendum 6 D54, gives this failure **four** distinct messages, checked
in this order -- the instance-binding comparison runs before name resolution, so a database whose
binding mismatches always reports "this is a copy," whether or not the recorded relation happens to
resolve by name under its old spelling. They mean different things and have different fixes.

**(a) "This database is a copy or restore of another"** -- the message names both the instance the
registries were recorded in and the instance you are on. This is the full-restore case (including a
`pg_dump --exclude-table` copy, which reports this message too, not (c) -- excluding one table from
the dump does not exempt the others' OIDs from being reassigned). The database is bricked for DDL
until you re-provision. Follow "Recovering a bricked restore".

**(b) "the relation was dropped and recreated in place"** -- the instance matches, so this is not a
copy: someone dropped and recreated a protected relation in place (which requires the bootstrap
superuser, since the event triggers block it otherwise). Re-run `grant-ddl-ownership` to re-record
the new OIDs.

**(c) "no relation of that name is present"** -- the instance matches and the protected relation is
genuinely gone. Do not re-provision over this; find out what removed it first. `grant-ddl-ownership`
will fail anyway, and should.

**(d) "the instance binding is absent or empty, so whether this database is a copy cannot be
determined"** -- either `sec7_instance_binding` itself does not exist, or it exists with zero rows.
This is the state a database provisioned before Addendum 5 (D45), or a schema-only clone before
`grant-ddl-ownership` has run on it, is in. It is deliberately **not** classified as a copy (message
(a)) or as genuinely gone (message (c)) -- the evidence to tell those apart is exactly what is
missing. If this is a fresh, never-provisioned database, run `grant-ddl-ownership`; otherwise
investigate before doing so.

A related message, `sec7_protected_object has 0 row(s), expected exactly 13`, is the **schema-only
clone** case. The registries were never populated in this database. Re-run `grant-ddl-ownership`.

## A drifted, non-copied database

`REINDEX ... CONCURRENTLY` and its siblings no longer wedge the two protected tables (ADR-0007
Addendum 6 D50/D51) -- but a superuser can still reach the state below by other means (R24), and a
database that predates this addendum may already be in it. Every D40 branch other than the four
above -- owner, relkind, RLS flags, rules, inheritance, triggers, indexes, policies -- raises with
the relation's own identity named (Addendum 6 D52), for example:

```
ERROR: ADR-0007 Addendum 4 D40: protected relation "public.screening_ledger_anchor" (objid 16914):
       its index set changed
```

This is **not** a copy or restore -- the database is the one it has always been, and its recorded
state has simply drifted from live catalog state. The recovery is the same as "Recovering a bricked
restore" below: `grant-ddl-ownership` re-derives and re-records the correct state from the live
catalog. `REINDEX ... CONCURRENTLY` was this state's most likely cause before D50/D51 shipped; after,
it requires a bootstrap-superuser action (`CREATE INDEX CONCURRENTLY` on a protected relation, or a
cancelled `REINDEX ... CONCURRENTLY` -- both self-healing by `DROP INDEX` with no event-trigger
disable and no re-provisioning, R24).

## Recovering a bricked restore

Verified against a real restored database. Every step needs the bootstrap superuser.

```sh
# 1. get DDL working again. Either branch works; the first is narrower.
#    Needs the same connection parameters as any other psql invocation
#    against this database -- PGHOST/PGPORT/PGUSER/PGPASSWORD or -h/-p/-U,
#    which this snippet omits only for brevity, not because they are
#    optional.
psql -h <host> -p <port> -U <bootstrap superuser> -d <the restored db> \
  -c "ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE;"
#    or, per statement:  SET event_triggers = off;

# 2. re-record the registries against this database's actual OIDs
PGHOST=<host> PGPORT=<port> PGSUPERUSER=<bootstrap superuser> PGSUPERPASSWORD=<...> \
  PGDATABASE=<the restored db> ./scripts/ci/provision_test_roles.sh grant-ddl-ownership

# 3. confirm both event triggers are back to ENABLE ALWAYS
psql -h <host> -p <port> -U <bootstrap superuser> -d <the restored db> \
  -c "SELECT evtname, evtenabled FROM pg_event_trigger;"   -- expect 'A' for both
```

Step 2 also requires the four `owl_*` roles already exist in the target cluster -- see "Before you
clone production into staging" above if this is a restore into a **different** cluster from the
source.

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
