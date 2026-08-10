# Phase 9F r1 — authenticated multi-tenant review console

Phase 9F adds a governed operator surface over the deterministic alert, case, and assistance stores.

- Short-lived HMAC-SHA256 `owat1` tokens bind subject, tenant, roles, registry checksum, and session epoch.
- Registry changes or session-epoch increments revoke existing tokens.
- Tenant scope and actor identity come only from verified claims; request values are overwritten.
- Analysts can investigate and propose but cannot approve. Reviewers approve decisions and assistance drafts independently. Existing Phase 9A–9B four-eyes checks remain authoritative.
- The browser console is same-origin, bearer-token based, cookie-free, CSP protected, and served by `review-console-api`.
- Every protected request, including denial, enters an append-only hash-chained security audit.
- PostgreSQL tables retain immutable identity-registry snapshots and security-audit events.

The checked-in signing key is a validation fixture only. A deployment must replace it with a protected random key of at least 32 bytes. Production OIDC/SSO federation remains an external identity integration point; it must map to this internal tenant/permission contract.

Phase 9F does not alter screening policy, activation state, case decision semantics, regulatory disposition, or watchlist catalog content.
