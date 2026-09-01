# Changelog

All notable changes to Freehold are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning follows [SemVer](https://semver.org/).

## Versioning stance (pre-1.0)

Freehold is in its `0.x` line: a **security preview**. Per SemVer, anything MAY change in a `0.x`
release, and it will — the on-disk formats (`.freehold` bundle v1, key envelope v3) are current but
not permanently frozen, and the public API is not yet stable. **1.0 is gated on an external security
audit and a real cross-browser/device pass**, not on feature completeness. Until then, treat every
`0.x` bump as potentially breaking and re-enroll if a format note says so.

## [Unreleased]

### Security (internal audit follow-up)
- Fixed 8 integrity/robustness/DoS findings from an internal review (no confidentiality break found):
  `phys_size` unsigned-underflow floor; filename-header UTF-8 panic → graceful; FFI offset/size range
  guards at the wasm C boundary; disk-lookup `unwrap` → error propagation; read-modify-write torn
  in-range block fails closed; SQL text-bind `i32` length guard; standalone-decryptor output filename
  sanitization (path-traversal); and gating the test/attacker-simulation surface behind `testing-api`
  so the hardened `--no-default-features` build compiles and never exports `run_tests`.
- Replaced a crate-wide `#![allow(dead_code)]` with precise, verified handling; all three build
  profiles (default, `--no-default-features`, `--features pool-management`) are warning-clean.
- Pinned Argon2id recovery-KEK parameters explicitly (no longer `Argon2::default()`), reproduced
  bit-for-bit in the standalone decryptor.
- Gated `console_error_panic_hook` behind a default `panic-hook` feature (dropped from production
  builds).

### Added
- **DEK rotation** end to end: `rotateKey()` re-encrypts every DB under a fresh DEK′ and issues a new
  envelope wrapping DEK′ under only the presenting passkey + a fresh recovery code (evicting absent
  methods), staged crash-safely behind a two-store commit barrier.
- **Standalone decryptor** (`crates/freehold-decrypt`): recover plaintext SQLite from a `.freehold`
  bundle with the recovery code and no Freehold/SQLite runtime — proves self-custody. Native tests.
- **Cross-device sync epoch** now attests the key-envelope generation (#3c): a peer refuses a
  rolled-back envelope that would re-plant an evicted device's slot.
- **Recovery codes** carry a Crockford checksum for transcription-error detection (no new dependency).
- **Device/browser test app** (`examples/demo/app.html`) driving the real SDK against actual WebAuthn
  + OPFS; `docs/` gained the bundle-format spec, DEK-rotation design, supply-chain inventory, and this
  audit-readiness packet. Optional off-by-default `pool-management` feature exposes the upstream
  pool-capacity API for vendoring consumers.

### Changed
- **DEK rotation now carries the freshness anchor forward.** A strict, peer-attested `epoch_floor`
  (and the `committed` high-water) set before a rotation is preserved across it: the pre-rotation anchor
  is snapshotted into the DEK′-sealed rotation-intent record and re-established under DEK′ on roll-forward,
  instead of silently resetting to 0. Closes a one-generation rollback window that a cross-device epoch
  had previously closed. The rotation-intent record format is bumped to v2 (ephemeral; no on-disk
  migration). Proven by `run_tests` RK3.
- `session_export` no longer relies on the session's open-time envelope snapshot — it embeds the
  current (rollback-guarded) envelope, so a recovery/passkey added mid-session is included in exports.

## [0.1.0] — earlier milestones (pre-changelog)
- Tier 1: capability preflight + non-bypassable recovery backup.
- Key envelope v3 (N-KEK, `env_generation`, DEK-keyed MAC anti-rollback).
- Encrypting OPFS SAHPool VFS (XChaCha20-Poly1305 block device, per-DB HKDF subkeys, trusted-generation
  anchor, full-state Merkle root, crash-injection tested).
- Server-blind Freehold Sync over a pluggable blind relay (version-vector conflicts, fork preservation).
