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

**Read this before you run anything below -- the connection-parameter defaults are not obvious, and
copying a snippet without setting them targets the wrong server.** `PGHOST`/`PGPORT`/`PGSUPERUSER`/
`PGSUPERPASSWORD` default to `localhost`/`5432`/`owl_ci`/`owl_ci`
(`scripts/ci/provision_test_roles.sh:33-37`) when left unset. Every snippet below sets them
explicitly for exactly this reason; do the same with your own cluster's real host, port, and
bootstrap superuser credentials -- an unset `PGHOST`/`PGPORT` silently targets `localhost:5432`,
which on a DR runner or an operator's own workstation is very often a **different, unrelated**
PostgreSQL server, not the cluster you meant to reach (ADR-0007 Addendum 7 D66).

**If this is a restore into a DIFFERENT cluster from the one the source database came from (the
ordinary DR shape), the four `owl_*` roles must exist on the target cluster BEFORE you restore into
it -- not after, and not only before `grant-ddl-ownership`.** Roles are cluster-wide, not
per-database, which is why this is possible at all -- but the restore itself (not merely
`grant-ddl-ownership`, which runs afterward) carries `ALTER TABLE ... OWNER TO owl_ledger_ddl` and
grant statements that name these roles, and a role-less target cluster refuses the restore itself
with dozens of `role "owl_migrator" does not exist` errors, confirmed by execution (81 errors on an
unprepared cluster; zero once the roles exist first). Run `create-roles` against `PGDATABASE=postgres`
(or any other database on the target cluster that has **not** yet been restored into) -- the
subcommand performs a schema grant in whatever database it connects to, and the restored database
itself refuses all DDL, including this one, until provisioning has run on it:

```sh
# on the TARGET cluster, BEFORE restoring into it, against an un-restored database
PGHOST=<target host> PGPORT=<target port> PGDATABASE=postgres \
  PGSUPERUSER=<bootstrap superuser> PGSUPERPASSWORD=<...> \
  ./scripts/ci/provision_test_roles.sh create-roles
```

Then perform the restore itself (a plain `pg_dump | psql`, `CREATE DATABASE ... TEMPLATE` on the same
cluster, or your own snapshot/replica mechanism), and continue with "Recovering a bricked restore"
below, using the same `PGHOST`/`PGPORT`/`PGSUPERUSER`/`PGSUPERPASSWORD` for the target cluster
throughout. If the clone is on the **same** cluster as its source, the roles already exist and this
step is not needed -- go straight to:

```sh
# on the clone, as the bootstrap superuser
PGHOST=<host> PGPORT=<port> PGSUPERUSER=<bootstrap superuser> PGSUPERPASSWORD=<...> \
  PGDATABASE=<the clone> ./scripts/ci/provision_test_roles.sh grant-ddl-ownership
```

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

**Step 0: run `screening-ledger status` first (ADR-0007 Addendum 7 D62(b)).** If it reports anything
other than provisioned, **investigate before re-provisioning** -- on a drifted database, the object
`grant-ddl-ownership` is about to adopt as legitimate is exactly the object that should not be
adopted. **This step is a second gate, not the mechanism that makes re-provisioning safe** --
`grant-ddl-ownership` itself now refuses to record an undeclared trigger, index, RLS state, or policy
by name (D62(a)), which is what actually stops a genuine attack from laundering itself into the
registry. State this honestly rather than as a guarantee this step alone provides: on the
**un-laundered** drift described below (the state you meet first, before anyone has re-run
`grant-ddl-ownership` over it), `screening-ledger status` currently reports the database as
provisioned anyway, because the live-index comparison it reads is filtered to the *declared* index
names and an undeclared object is invisible to it by construction (Addendum 5 D47, R28) -- so step 0
will not catch this specific state on its own. Run it anyway: it is a real gate against every OTHER
drift and against re-running `grant-ddl-ownership` a second time over an already-laundered registry.

`REINDEX ... CONCURRENTLY` and its siblings no longer wedge the two protected tables (ADR-0007
Addendum 6 D50/D51) -- but a superuser can still reach the state below by other means (R24), and a
database that predates this addendum may already be in it. Every D40 branch other than the four
above -- owner, relkind, RLS flags, rules, inheritance, triggers, indexes, policies -- raises with
the relation's own identity named (Addendum 6 D52), for example:

```
ERROR: ADR-0007 Addendum 4 D40: protected relation "public.screening_ledger_anchor" (objid 16914):
       its index set changed
```

**What these eight branches establish, and no more (ADR-0007 Addendum 7 D63):** the recorded state
has drifted from live catalog state. They do **not** by themselves determine whether the database is
a copy -- that is a separate question `sec7_instance_binding` and `screening-ledger status` (D62(b))
answer, not this error. The remedy below is the same either way: re-provisioning is correct for both
a drifted original and a drifted copy. The recovery is the same as "Recovering a bricked restore"
below: `grant-ddl-ownership` re-derives and re-records the correct state from the live catalog, and
now refuses rather than records if an object it finds was never declared (D62(a)). `REINDEX ...
CONCURRENTLY` was this state's most likely cause before D50/D51 shipped; after, it requires a
bootstrap-superuser action (`CREATE INDEX CONCURRENTLY` on a protected relation, or a cancelled
`REINDEX ... CONCURRENTLY` -- both self-healing by `DROP INDEX` with no event-trigger disable and no
re-provisioning, R24), or a directly forged `pg_index.indisvalid`/`indisready` flag on a protected
relation's index (ADR-0007 Addendum 7 D65), which is now itself named as a distinct failure rather
than passing silently.

## Recovering a bricked restore

**Step 0: run `screening-ledger status` first (ADR-0007 Addendum 7 D62(b)).** On a genuinely bricked
restore (message (a), "this database is a copy or restore of another"), this reports the database as
unprovisioned, naming the mismatched instance -- confirming you are looking at the state this section
describes before you act on it. If it instead reports the database as already provisioned, stop:
something other than an ordinary logical copy produced this state, and re-running `grant-ddl-ownership`
blind is not the next step. As with the drift section above, this is a second gate: the mechanism that
actually makes recovery safe to run is `grant-ddl-ownership` itself refusing to record any undeclared
object it finds (D62(a)), not this status check.

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
