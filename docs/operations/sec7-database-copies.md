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
# ADR-0007 Addendum 9 D84 (M-H): the invocation this document previously
# showed is not runnable as written -- it fails with "snapshot encryption
# key is required," naming none of the flags it actually needs. Verified
# by execution: this is the complete, fully-specified flag set.
screening-ledger status --postgres-dsn-env <VAR> \
  --policy-file <policy> --policy-public-key-file <key> \
  --key-file <K_snap key file> --anchor-key-file <K_anchor key file> \
  --ledger-dir <ledger directory> --ledger-id <ledger id>
```

`--key-env`/`--anchor-key-env` (an environment variable name, rather than a file path) work the same
way if that is how these keys are provisioned in your environment.

**This CLI silently accepts unknown flags.** `--totally-bogus-flag xyz` returns `rc=0` with no
diagnostic (confirmed by execution) -- an operator who mistypes a flag in this procedure gets no
signal at all. Recorded as an observation rather than fixed here: it makes getting the flag list
above exactly right more important, not less.

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

## Refusal modes `grant-ddl-ownership` can report (ADR-0007 Addendum 9 D84)

`grant-ddl-ownership` now refuses to record several states as legitimate rather than silently
recording whatever it finds. Each is checked **before** any DDL runs (Addendum 9 D79), so a refusal
here always leaves the database exactly as protected as it was found -- confirm this with
`SELECT evtname, evtenabled FROM pg_event_trigger;` if in doubt; a refusal should never change what
that query returns.

- **D62(a): an undeclared trigger or index.** "has an undeclared trigger/index" names an object on a
  protected table that is not one of the four declared triggers or two declared indexes. Investigate
  before re-running -- an attacker-planted object should never be recorded as legitimate.
- **D62(a): relkind, RLS flags, or an RLS policy.** A protected table's own shape has changed
  (unlikely; these are structural facts about the table, not something ordinary DDL touches).
  Investigate before re-running.
- **D69 / Addendum 9 D77: a declared trigger's behavior or body.** "does not match its declared
  behavior" names the trigger and, since Addendum 9, covers both *what the trigger does*
  (`tgtype`/`tgqual`/`tgnargs`/`tgattr`) and *what its bound function's body actually contains*
  (`prosrc`, joined through the trigger's own `tgfoid`) -- a `CREATE OR REPLACE FUNCTION` that
  preserves every catalog property while swapping the function's implementation is exactly what this
  catches. This is the one refusal mode with a documented remedy below (D78's repair procedure) rather
  than "investigate": if the substitution is illegitimate, treat it as a compromise and investigate
  fully; if it is a legitimate edit to a guard function's own source, follow D78's repair procedure.
- **D56 / D71: a declared trigger or index does not exist at all.** Names the missing object and the
  migration or backup that would restore it. Re-run the named migration, or restore the object, before
  re-running `grant-ddl-ownership`.
- **Addendum 9 D80: a declared index exists but has the wrong shape.** "does not match the declared
  shape" -- non-unique where a unique index is declared, unique-but-not-primary, correct uniqueness on
  the wrong columns, a partial predicate, or an expression index. The index resolves to something
  (D71 alone would accept it); it is not the *thing* the declaration requires. Investigate before
  re-running -- do not simply `DROP INDEX` and recreate one that happens to satisfy this check, since
  that is itself an unaudited DDL statement against a protected table.

**D78's repair procedure**, for the one case above with a documented remedy: `Migrate()` and
`grant-ddl-ownership` both deliberately do **not** repair a guard function whose body does not match
its declared accepted digest set -- a repairing `CREATE OR REPLACE FUNCTION` would itself be refused
by D34 on every already-provisioned database, converting a silent acceptance into a hard failure of
every `migrate`/`sync`/`import-audit`/`grant-ddl-ownership` invocation on the healthy databases this
exists to protect. To repair a body genuinely confirmed legitimate (for example, after intentionally
editing `db/migrations/012_truncate_guards.sql` or the `SchemaSQL` constant and rolling the change out):

```sh
# as the bootstrap superuser, with the target guard function's OWN event-trigger disable window open
# (see "Recovering a bricked restore" below for how to open and close that window safely)
psql -h <host> -p <port> -U <bootstrap superuser> -d <database> \
  -c "CREATE OR REPLACE FUNCTION public.<guard function>() RETURNS trigger LANGUAGE plpgsql AS \$\$ <the declared body> \$\$;"
```

Then re-run `grant-ddl-ownership` to confirm the repaired body is now in the accepted set.

**D87's repair procedure (ADR-0007 Addendum 10, corrected by Addendum 12 D111): the same shape, one
object over.** Both `screening_ledger_purge_snapshots` overloads -- the definer functions that
actually write `purged_at` -- are now `requiredDefinerFunctions` members with their own declared
accepted body digests (D87/D86 row 8, moved again by Addendum 12 D107), so `Migrate()`'s
`db/migrations/019`/`020`/`021`/`022` re-application and any legitimate edit to their bodies is
refused by D34 on an already-provisioned database, exactly as D78 already refuses for the two guard
functions. This is a **re-provisioning event**, not a repair `Migrate()`/`grant-ddl-ownership`
attempt on their own: open the same event-trigger disable window as above, apply the migration or
`CREATE OR REPLACE FUNCTION` directly, then re-run `grant-ddl-ownership` to re-enable enforcement
and confirm the new body is in its declared accepted set. On a **fresh** database this cost does not
apply at all -- the new migration runs before `grant-ddl-ownership` ever installs the event
triggers. **Verified by execution: the migration must be applied as the bootstrap superuser, not as
`owl_migrator`** -- `grant-ddl-ownership` has already transferred ownership of both overloads to
`owl_ledger_ddl`, so `owl_migrator` (the identity `db/migrations/` ordinarily runs as) gets a plain
`ERROR: must be owner of function screening_ledger_purge_snapshots` regardless of event-trigger
state, distinct from and in addition to D34's own refusal:

```sh
# as the bootstrap superuser, with the event-trigger disable window open (see step 1 above)
psql -h <host> -p <port> -U <bootstrap superuser> -d <database> -v ON_ERROR_STOP=1 \
  -f db/migrations/022_screening_ledger_purge_chain_corroboration.sql
```

**This `db/migrations/` filename is a pointer to the newest purge migration, not a fixed reference
-- it has already moved twice (020 to 021 for D98, 021 to 022 for D107) and will move again the next
time either overload's body changes.** Confirm which file is current by listing
`db/migrations/0*_screening_ledger_purge_*.sql` in apply order and applying the last one, rather than
trusting this document's own literal filename against a tree that has moved past it.

**Confirmation, named rather than described.** "Confirm the new bodies are in their declared
accepted sets" means two concrete commands, both of which must be run and both of which now check
the body digest (ADR-0007 Addendum 12 D111(a) closes the half that used to check nothing):

```sh
# 1. the installer's OWN assertion (D111(a)): grant-ddl-ownership now joins the prosrc digest
#    comparison it already performs for the two guard functions to both purge_snapshots overloads,
#    and exits non-zero, naming the function and the live digest, if either substitution is present.
scripts/ci/provision_test_roles.sh grant-ddl-ownership

# 2. the independent verifier (unchanged by D111, D33's own "installer AND verifier" convention):
#    reads live prosrc through the function's own regprocedure OID, so it follows whatever body is
#    actually live regardless of which migration file most recently created it.
screening-ledger status --postgres-dsn-env <VAR> \
  --policy-file <path> --policy-public-key-file <path> --ledger-dir <dir> --ledger-id <id>
```

Before Addendum 12 D111, only command 2 examined the body at all -- `grant-ddl-ownership` printed
`PASS` unconditionally, whether or not the two purge_snapshots overloads had actually been repaired
correctly (D111's own reproduction: the pre-D111 procedure installs the superseded, pre-D98
ANY-expired bodies and is told it succeeded). Both commands must now report clean before the
recovery is considered complete.

**A note on `screening_ledger_snapshot` (ADR-0007 Addendum 10 D89, R40):** that table's own guard
triggers (`screening_ledger_snapshot_guard_trigger`, `screening_ledger_snapshot_no_truncate`) are
**not** protected objects -- neither the table, the guard function, nor either trigger appears in
`sec7_protected_object`. `owl_migrator` can drop them with no event-trigger refusal and nothing
observes it. This is a known, separately-scoped gap (not part of any SEC-7 retention-claim guarantee
this document describes: D89 withdrew `created_at` as a referent of any control, so this relation's
guards no longer undermine a purge's `purged_at` floor either way) -- do not assume the drop is
refused the way the anchor and tombstone tables' own triggers are.

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
unprovisioned -- confirming you are looking at the state this section describes before you act on it.
**This step's own message does not name the mismatched instance** (ADR-0007 Addendum 10 D94, N-H):
it reports `sec7_protected_object has no row whose OID resolves (via pg_identify_object) to pg_class
public.screening_ledger_anchor (ADR-0007 Addendum 4 D41): the registry is stale, repointed, or was
never populated with this object`, which is D41's registry-resolution reason, not an instance
identifier. **The instance IS named, on a different surface**: the first ordinary DDL statement run
against the database (for example, step 2 below, or an accidental `CREATE TABLE` by `owl_migrator`)
raises D46's message, which names both the recorded and the live `system_identifier`/database OID/name.
If step 0 instead reports the database as already provisioned, stop:
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

**If step 2 itself refuses (ADR-0007 Addendum 9 D79, extended by Addendum 10 D90):** every
precondition `grant-ddl-ownership` can refuse on (the "Refusal modes" section above) is checked
**before** the event triggers are ever taken down, so most refusals leave the database in exactly the
state step 2 started in. For a failure **after** that point (a `psql` error, the registry row-count
assertion, or any other failure once enforcement is already down), the trap now restores the **full
declared state** -- not only the two event triggers, but all three registries
(`sec7_protected_object`=13, `sec7_protected_relation`=2, `sec7_instance_binding`=1), from the same
declared literals the normal run uses, and it asserts its own postcondition before finishing. **Before
Addendum 10, the trap re-created the two event triggers but left them `evtenabled='O'` (not `'A'`) and
never touched the registries** -- a database in that state passed for "restored" by eye (both event
triggers present) while a single, unprotected `CREATE OR REPLACE FUNCTION` on the shared row-guard
function succeeded with no event-trigger disable of its own. Confirm a real restoration, not merely
that the trap ran, with:

```sh
psql -h <host> -p <port> -U <bootstrap superuser> -d <the restored db> -c "
  SELECT evtname, evtenabled FROM pg_event_trigger WHERE evtname LIKE 'sec7%';   -- expect 'A' for both
  SELECT (SELECT count(*) FROM sec7_protected_object) obj,
         (SELECT count(*) FROM sec7_protected_relation) rel,
         (SELECT count(*) FROM sec7_instance_binding) bind;                     -- expect 13, 2, 1
"
```

If either check comes back short, `grant-ddl-ownership` printed a `WARNING` naming exactly which
counts are short when the trap fired -- re-run it from a clean state rather than trusting the database
until that warning is gone.

## `event_triggers = off` is not a bypass

The GUC is `SUSET`. A non-superuser -- including `owl_ledger_ddl`, the protected tables' own owner
and the role these controls exist to bind -- gets `permission denied to set parameter
"event_triggers"`. Re-confirmed by execution. The residual terminates at the bootstrap superuser,
where ADR-0007 R12 and R17 put every other residual in this design.

## Cleaning up a killed `scripts/ci/verify_cross_cluster_dr.sh` run (ADR-0007 Addendum 9 D83/D84)

This script stands up a genuinely second, disposable PostgreSQL cluster to test the cross-cluster DR
procedure above end to end. It prints its own scratch root at startup:

```
== D83: this run's scratch root is /tmp/tmp.XXXXXXXXXX -- if this run is SIGKILLed, clean up
   manually with: <PG_BIN_DIR>/pg_ctl -D <scratch root>/data -m immediate stop; rm -rf <scratch root> ==
```

A normal exit (success or a handled failure) always cleans this up itself. **`SIGKILL` cannot be
trapped** -- if this script's process is killed with `SIGKILL` (not `Ctrl-C`, which is `SIGINT` and
is trapped), the second cluster it started keeps running and its scratch root is never removed.
Earlier versions of this script kept a fixed, rediscoverable path specifically so a later run could
find and reap a leaked cluster automatically; that reaper is **withdrawn** as of Addendum 9 (its own
pre-declared withdrawal condition fired: two runs sharing a runner three seconds apart had one run's
reaper kill the *other* run's live, healthy cluster). There is no automatic reaper now. If a run of
this script was `SIGKILL`ed, find the scratch root from that run's own printed startup line (or from
`ps aux | grep postgres` -- the leaked `postmaster` process's `-D` argument names its data directory)
and run the two commands the script itself printed. CI is unaffected: the runner is destroyed after
the job regardless.

## What this does not cover

- **Backup content.** This document is about the protections, not the data. `pg_dump` remains a
  correct way to back the database up; the point is that the *restore* needs a re-provisioning step
  the backup does not record.
- **The ledger directory.** The file-backed chain, `R`, `K_anchor` and the Ed25519 policy keypair
  are separate custody concerns -- see `screening-ledger-policy-signing.md` for the policy key, and
  ADR-0007 §5.1-§5.2 for the rest.
- **Whether a copy's *history* is trustworthy.** Re-provisioning restores the DDL protections; it
  says nothing about the chain. Run `screening-ledger verify` in anchored mode for that.
