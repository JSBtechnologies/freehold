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
- **Counterparty-verifiable grant tokens (D-DC3)**: a grant is no longer only a broker-local id — the
  vault now **signs** the grant claims with its Ed25519 identity key, so any counterparty (the app, a
  downstream processor) can verify the grant against the vault's **pinned public key** with no DEK and
  no broker round-trip. The token is the custody-v1 proto `Grant` (`claims` = a canonical
  `freehold-grant-v1` claim over grantId/appId/tier/sorted-scopes/purpose/validity, `proof` = the
  signature), bound by audience to the verified `app_id` (D-DC2). Verification recomputes the claim from
  the presented fields (so a signature can't be re-paired with different claims) and pins the vault key.
  Reuses the audited attestation primitive — no new crypto. Reference + E2E in the custody demo (a
  tampered token is rejected); `docs/grant-token-design.md`.
- **Requester authentication (Disclosure-plane app identity, D-DC2)**: custody apps now authenticate
  with a cryptographic identity instead of a phishable origin/name. Each app holds a WebCrypto Ed25519
  keypair and its `app_id` is a **commitment** to its public key
  (`app_id = "app_" + base64url(SHA-256("freehold-app-id-v1" ‖ pubkey))[..12]`). The broker verifies a
  challenge-response handshake on connect — `app_id == H(pubkey)` ∧ Ed25519 signature over its
  challenge — and binds the port to the **verified** id; it never trusts a self-asserted id in a later
  message. A lookalike app cannot claim a trusted app's id (it can't produce the committed key) or spoof
  it in the consent prompt. Same commitment discipline as relay-auth (D-RA1), on the Disclosure plane.
  Reference implementation + E2E in the custody demo (an impersonation attempt is rejected);
  `docs/requester-auth-design.md`.
- **Relay authentication (blind-relay access control)**: the blind relay now authorizes every op
  without ever seeing the DEK (`docs/relay-auth-design.md`, D-RA1). Each database has a DEK-derived
  Ed25519 relay-auth key (`HKDF(DEK, "…relay-auth-v1" ‖ db_uuid)`), and `sync_id` is now **bound** to
  its public key — `sync_id = SHA-256("freehold-sync-id-v1" ‖ pubkey)[..16]` — so the relay authorizes
  **statelessly**: it checks `sync_id == H(pubkey)` and an Ed25519 signature over a domain-separated op
  message (a Push binds its exact blob bytes; reads sign empty). Possession of the bucket *is*
  possession of the key — no trust-on-first-use, no land-grab — plus a per-key rate limit. `sync()`
  signs every op in the worker; `HttpRelay` forwards `{pubkey, sig}`; the zero-dependency Node relay
  verifies with built-in `crypto`. New public API: `vault.relayAuth()` / `vault.syncId()` /
  `RelayMethod` for driving a relay directly. E2E proves an unsigned push is rejected. No new crypto —
  the audited Ed25519 + HKDF primitives, used as-is. Blindness/unlinkability unchanged (per-DB key).
- **Real blind-relay transport (Sync plane over Connect)**: the version-vector sync engine now has a
  network wire, not just the in-memory mock. A frozen `.proto` contract
  (`proto/freehold/sync/v1/relay.proto` — `PushBlob`/`ListBlobs`/`GetBlob` + server-streaming
  `Subscribe`; opaque `bytes` only), a zero-dependency Node **blind relay server**
  (`server/relay-server.mjs`; Connect JSON codec + SSE Subscribe; blind by construction — it only ever
  moves base64 blobs), and an **`HttpRelay`** SDK adapter (`@freehold/db/relay-http`) that is a drop-in
  for `InMemoryRelay`, so `sync({ relay })` works unchanged over the wire. The transport carries the
  security boundary, it does not define it — blobs are sealed under a DEK subkey before they reach it
  and the relay stays server-blind (data-custody §2). The Disclosure-plane message family
  (`DataRequest`/`Grant`/`Attestation`/`Disclosure`) is frozen in `proto/freehold/custody/v1/` so the
  app SDK surface is stable, even though disclosure still runs on the Local-plane broker. Proven E2E by
  `tests/sync-http-e2e.spec.js` (two browser contexts converge over a real HTTP relay; stale; fork with
  loser-preservation; live Subscribe). Next transport item: relay authentication (rate-limit +
  `sync_id`-ownership proof) — blindness is not authorization. See `docs/transport-design.md`.
- **Verifiable tier-2 attestations (vault signing key)**: a DEK-derived **Ed25519 vault identity**
  (`HKDF(DEK, "freehold-vault-identity-v1")` — same across a user's devices, never persisted) signs a
  tier-2 claim ("18+ ✓") bound to a verifier **audience** (anti-replay) and an expiry. A remote party
  verifies it against the vault **public key** with **no DEK and no PII** — the raw data behind the fact
  is never transmitted. SDK: `vaultPublicKey()`, `attest(claim, {audience, ttlSeconds})`,
  `verifyAttestation(att, expect)`. The custody showcase's `profile.attest.over18` now returns a signed
  attestation the relying party verifies against a pinned key. This lights up data-custody D-DC3's
  "swappable proof" (DEK-MAC → signature) with **no envelope-format change**. New audited dependency
  `ed25519-dalek` (`freehold` only; not in the decryptor). Proven by `run_tests` **VS** and
  `attest-e2e`. See `docs/vault-signing-design.md`.
- **Convenience tier (device-key unlock)**: opt-in `enrollConvenience()` auto-unlocks a vault on its
  device with no passkey gesture, keying a slot with a 32-byte secret wrapped under a non-extractable
  WebCrypto key (never stored in the clear, never in a bundle). The device slot now carries its own
  envelope `kind` (`KIND_DEVICE`) so `listMethods()` reports it honestly, and `exportBundle()` **strips
  the device slot** (re-MAC under the session DEK, generation preserved — D-CV7) since a device-bound
  key is meaningless off-device. A device-only vault refuses to export (nothing left to open it). Proven
  by `run_tests` **M3e** and the two-context `convenience-e2e` spec. See `docs/convenience-tier-design.md`.
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
