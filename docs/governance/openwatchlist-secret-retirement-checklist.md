# OpenWatchlist secret-retirement checklist

The following values were exposed in terminal/chat diagnostics and must be retired permanently:

- the legacy `openwatchlist` PostgreSQL role password;
- the legacy `OPENWATCHLIST_SIGNING_KEY_HEX` value;
- the unrelated Clawbot Redis password exposed by the read-only Docker inventory output.

## R0 teardown evidence

- [ ] OpenWatchlist PostgreSQL container removed.
- [ ] OpenWatchlist PostgreSQL volume/bind data removed after verified backup.
- [ ] OpenWatchlist runtime container removed.
- [ ] Remote `.env`, signing-key, TLS, and runtime-secret files removed with the allowlisted deployment roots.
- [ ] Protected unrelated services remain present.

## Manual GitHub actions

- [ ] Remove or replace matching repository secrets in the legacy repository.
- [ ] Remove or replace matching environment secrets in the legacy repository.
- [ ] Review organization secrets that may have granted access to the legacy repository.
- [ ] Do not copy any legacy value into the clean repository.
- [ ] Record secret names and fingerprints only; never record raw values.

## Local evidence handling

- [ ] Keep the R0 private backup directory mode `0700`.
- [ ] Move secret-bearing diagnostics to encrypted/offline forensic storage or delete them after retention approval.
- [ ] Remove downloaded `.env`, key, and password files from ordinary project folders.
- [ ] Clear shell history entries containing raw credentials when operational policy permits.

## New deployment

- [ ] Generate a new PostgreSQL password.
- [ ] Generate a new signing key.
- [ ] Store new values in the new repository's controlled environment/secret system.
- [ ] Verify the new runtime does not log or export raw secrets.
- [ ] Confirm the old credentials cannot authenticate before declaring retirement complete.

## R0.2 backup note

The private logical PostgreSQL dump and deployment archive may contain retired credentials or credential-derived data. Keep the archive mode 0700, offline or encrypted, and never import its old secrets into the new canonical repository.

## R0.3 runtime-state note

The g732 runtime-state tar is a private, live best-effort snapshot captured through the allowlisted container. It can contain outbox, backup, request, or credential-derived material. Keep it under the same 0700/offline controls as the database dump and do not import it into the new canonical repository.
