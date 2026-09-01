---
slug: header-free-encrypted-vfs
artifact: audit-readiness
version: 0.1
status: DRAFT 2026-08-31 — packet to make an external security audit fast; not itself an audit.
created: 2026-08-31
kind: audit-readiness-packet
---

# Freehold — security audit-readiness packet

Everything an external auditor needs to spend their hours *finding bugs* instead of reconstructing
what the system is supposed to do. This is not a claim of correctness — it is a map. The trust story
has **not** been externally validated; that is the point of the engagement this packet supports.

## 1. System in one paragraph
Freehold is passkey-unlocked, end-to-end-encrypted SQLite for the browser. A random 256-bit **DEK**
encrypts every DB block; the DEK is wrapped by N independent KEKs (one per unlock method) in a
**key envelope**, and never persisted in the clear. A WebAuthn passkey's PRF output (or a recovery
code) derives a KEK that unwraps the DEK **inside a Web Worker**; the DEK stays in wasm memory until
lock and is zeroized. Sync and export move only ciphertext + non-secret lineage metadata, so a relay
or server **never sees a key or plaintext**. Components: a Rust→wasm core (`crates/freehold`), a
zero-runtime-dependency JS SDK (`packages/db`, `@freehold/db`), and a standalone runtime-free
decryptor (`crates/freehold-decrypt`).

## 2. Assets, adversaries, scope
**Assets (most→least sensitive):** the DEK; the plaintext database; a passkey's PRF output / the
recovery code; the key envelope (non-secret ciphertext, but rollback-sensitive); sync/version metadata
(non-secret lineage).

**In-scope adversaries:**
- **Honest-but-curious relay / server / network** — sees only ciphertext + `sync_id` routing labels.
  Goal to verify: no plaintext, no key, no cross-user linkability leaks.
- **All-storage attacker** (can read/rewrite OPFS + IndexedDB) — e.g. malware on the device, another
  origin via a browser bug. Goal: cannot forge a higher envelope generation (DEK-keyed MAC), cannot
  roll the DB image back below the trusted generation, cannot transplant blocks across DBs.
- **Compromised/evicted device** — held the DEK once. Goal: after `rotateKey()` it can read no new
  state and cannot mint a valid new epoch (rotation limit honestly stated: it does not un-leak what
  was already exfiltrated, nor old exported copies).
- **Malicious `.freehold` bundle** fed to the standalone decryptor — path traversal, malformed TLV.

**Out of scope (stated, not hidden):** a live-compromised worker/JS context (already holds the DEK);
side channels (timing/cache); the browser's own WebAuthn/OPFS implementation correctness; multi-user
signing keys (#7, not in v1); denial of service by wiping storage (an all-storage attacker can delete
data — the local anchor is a *backstop*, not a guarantee against deletion).

## 3. Cryptographic design → code map
All primitives are audited RustCrypto used as-is (no invented crypto). The **entire** crypto boundary
is `crates/freehold/src/crypto.rs` — keep review focused there plus `envelope.rs`.

| Concern | Primitive | Where |
|---|---|---|
| Block AEAD | XChaCha20-Poly1305, 192-bit random nonce/block | `crypto.rs`: `Crypto::seal_into`/`open_into` |
| Block AAD (position+framing bind) | `file_id(16) ‖ db_uuid(16) ‖ block_index_LE(8) ‖ 4096_LE(4) ‖ cipher_id(1)` | `crypto.rs`: `aad()` |
| Key hierarchy | HKDF-SHA256 subkeys from the DEK | `crypto.rs`: `Crypto::{db_key,pool_key,anchor_key,epoch_key,sync_key}`, `sync_id` |
| Envelope (N-KEK wrap) | XChaCha20-Poly1305 per slot; HMAC-SHA256 whole-envelope MAC | `envelope.rs`: `create_envelope`, `open_with_prf/recovery`, `compute_mac` |
| Passkey KEK | `HKDF(prf_output,"freehold-kek-v1")` | `envelope.rs`: `kek_from_prf` |
| Recovery KEK | Argon2id (pinned m=19456,t=2,p=1), Crockford code + checksum | `envelope.rs`: `recovery_argon2`, `kek_from_recovery`, `generate_recovery_code`, `verify_recovery_checksum` |
| Anti-rollback (envelope) | monotonic `env_generation` under the DEK-keyed MAC + SDK floor | `envelope.rs`: `check_fresh`; SDK `#envelope`/`#bumpFloor` in `packages/db/index.js` |
| Anti-rollback (DB image) | trusted-generation anchor, double-buffered, sealed under `anchor_key` | `vfs.rs`: `anchor_load`/`anchor_save`/`anchor_record_full`, `open_and_authenticate` |
| Full-state integrity | plaintext Merkle root (D-MR), sealed in the manifest at commit | `crypto.rs`: `FullStateRoot`; `vfs.rs`: `full_state_root` |
| DEK rotation | fresh DEK′ + fresh envelope + shadow re-seal + 2-store commit barrier | `envelope.rs`: `rotate_envelope`; `vfs.rs`: `stage_rotation`/`recover_rotation`; `lib.rs`: `rotate_dek` |
| Sync epoch (freshness) | DEK-authenticated token attesting db_gen + env_gen | `vfs.rs`: `export_epoch`/`apply_epoch`; `lib.rs`: `session_begin` |
| Bundle format | TLV container "FREEHOLD" v1 | `bundle.rs`; spec: `docs/bundle-format.md` |

## 4. Invariant ledger (the load-bearing claims)
Each is stated with **where enforced** and **where tested**. An auditor should try to break each.

1. **Fresh random nonce per seal; fail closed on RNG error / all-zero.** — `crypto.rs` seal paths;
   tested implicitly by every round-trip + §17.F self-test.
2. **AAD binds file identity + block index + framing** → a block cannot authenticate in another
   file/position/DB. — `crypto.rs` `aad()`; tested: run_tests block-relocation/ciphertext-audit.
3. **Per-DB subkey `K_db = HKDF(DEK,"vfs-db-v1"‖db_uuid)`** → wrong-DB manifest fails to *decrypt*,
   not merely an AAD check. — `crypto.rs` `db_key`; tested: cross-DB open refusal.
4. **DEK-keyed envelope MAC** → a kept older envelope cannot be forged to a higher generation. —
   `envelope.rs` `compute_mac`/`open_with_kek`; tested: run_tests **M3b** (forged-gen → Tamper).
5. **Envelope generation floor** → a genuine stale envelope re-planting a revoked slot is refused. —
   SDK `#envelope`; worker `session_begin` (cross-device, #3c); tested: **M3b**, **SE3c**.
6. **Whole-file / block rollback refused** below the trusted generation (± crash slack; strict for a
   peer-attested epoch floor). — `vfs.rs` `open_and_authenticate` + anchor; tested: **MK**, §14.8
   crash sweep, **SE**.
7. **Crash-atomic commit barriers** — journal finalization seals the manifest before the barrier
   write; DEK rotation commits on the single IndexedDB envelope put with an OPFS intent record. —
   `vfs.rs` `journal_finalize_barrier`, `stage_rotation`/`recover_rotation`; tested: **MK6**, **RK2**.
8. **DEK never persisted; zeroized on drop.** — `Zeroizing` in `crypto.rs`/`envelope.rs`; DEK′ never
   leaves the worker (D-RK3). Known residual: the pool's registration appdata (holding the DEK) is a
   leaked `'static` that survives until the worker dies — a locked session can't reach it (no VFS, no
   handles); documented in `vfs.rs` `session_lock_inner` and BUILD-NOTES.
9. **Rotation evicts** — post-rotation the old DEK opens nothing that survives; old methods orphaned
   (re-admit = re-enroll). A strict peer-attested `epoch_floor` set before rotation is **carried
   forward** (snapshotted into the DEK′-sealed intent, re-established under DEK′ on roll-forward), not
   reset — tested: **M3c**, **RK**, **RK2**, **RK3** (anchor carry-forward), `tests/rotate-e2e.spec.js`.
10. **Server-blind** — bundle/sync carry only ciphertext + non-secret metadata. — `bundle.rs`,
    `sync.rs`; tested: **SJ**, `tests/sync-e2e.spec.js`, ciphertext audit.

## 5. Test coverage matrix
- **In-wasm `run_tests()`** (`lib.rs`, gated behind `testing-api`; run via `tests/merkle-root.spec.js`):
  sections M2 (block device/crypto), M3b (envelope anti-rollback), M3c/RK/RK2/RK3 (DEK rotation), M3d
  (recovery checksum), MK (full-state Merkle root + crash injection), SE/SE3c (sync-epoch rollback),
  SY/SJ (sync engine + SDK boundary), S (session model), §14.8 crash sweep, perf.
- **Playwright E2E** (real WebAuthn virtual authenticator): `merkle-root` (full suite gate),
  `backup-gate` (#2 mandatory backup), `rotate-e2e` (DEK rotation end-to-end), `sync-e2e`
  (multi-device convergence/fork), `app-smoke` (test-app lifecycle). Generator: `decrypt-fixture`
  (skipped unless `FH_GEN_FIXTURE=1`).
- **Native `cargo test -p freehold-decrypt`** (6 tests): real-bundle recovery, wrong code fails closed,
  code normalization, checksum round-trip/typo, tampered magic, output path-traversal sanitization.
- **Gap (honest):** the wasm core cannot `cargo test` natively (its `sqlite-wasm-rs` C build rejects
  MSVC), so core coverage runs only in-browser; there is no CI; testing is single-browser (headless
  Chromium) with a *virtual* authenticator — real Safari/iOS/Firefox behavior is unproven.

## 6. Recent internal audit (context for the reviewer)
An internal pass (Aug 2026) found and fixed 8 integrity/robustness/DoS items — no confidentiality
break was found. See commits `774ac5d` (#4 decryptor path traversal), `0af167c` (#1 phys_size
underflow, #3 filename panic, #5 FFI range guards, #6 disk-lookup unwraps, #7 RMW torn-block, #8
text-bind/escape), `3d49719` (#2 gate the test/attacker-sim surface so the hardened build compiles).
These are self-review, not a substitute for external eyes.

## 7. Build / reproduce
- wasm core: `cd crates/freehold && wasm-pack build --target web --release --out-dir ../../examples/demo/pkg`
- run the harness + E2E: `npx playwright test` (vite dev server auto-starts on :5178).
- decryptor: `cargo test -p freehold-decrypt`; CLI `cargo run -p freehold-decrypt --release -- <bundle> <code> <out>`.
- feature flags: `testing-api` (default; attacker-sim + `run_tests` — OFF for the hardened production
  build via `--no-default-features`), `panic-hook` (default; dev diagnostics), `pool-management`
  (off; optional vendoring capacity API). All three profiles build warning-clean.

## 8. Documents to read (in order)
`docs/design-spec.md` (§17 invariant ledger) → `docs/bundle-format.md` → `docs/dek-rotation-design.md`
→ `docs/sync-epoch-design.md` → `docs/supply-chain.md`. Source review focus: `crypto.rs`, `envelope.rs`,
then `vfs.rs` (VFS/anchor/rotation), then `lib.rs` (the wasm boundary) and `packages/db/index.js`.

## Cross-links
[[header-free-encrypted-vfs]] design-spec, [[bundle-format]], [[dek-rotation-design]],
[[sync-epoch-design]], [[supply-chain]].
