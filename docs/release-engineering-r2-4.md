# R2.4 public release and controlled deployment closure

R2.4 qualified the published `v0.1.0-rc.4` release through deterministic input
validation, role-bounded staging, controlled activation, smoke testing, full
rollback, protected-state comparison, and controlled reactivation.

The public release boundary is:

- release ID `361927608`;
- main commit `210dc3c00d43f4f4e9ceae6905c24c9c9ea99584`;
- main tree `51b93dd4a4e27b5607c2a460580829490e9742d1`;
- Linux AMD64 runtime SHA-256
  `1cf61dce31fad81d8511bac76c5a29aef3c0375a3a26d0c92f58a70a3494a29f`.

The public repository records the sanitized deployment contract and accepted
closure. Generated evidence and environment-specific configuration remain
outside Git history.
