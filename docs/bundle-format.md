---
slug: header-free-encrypted-vfs
artifact: bundle-format
version: 1.0
status: SHIPPED 2026-08-31 — format frozen at bundle v1 / envelope v3; standalone decryptor proves it.
created: 2026-08-31
parent: header-free-encrypted-vfs/design-spec.md §14 (cross-device image) / §11 (envelope)
kind: format-spec
---

# The `.freehold` bundle format + standalone recovery (issue #6)

This is the **on-disk contract** for a `.freehold` export and everything needed to decrypt it with no
Freehold runtime — the executable proof of self-custody. `crates/freehold-decrypt` implements exactly
the read side described here using only audited RustCrypto crates (Argon2id, XChaCha20-Poly1305,
HKDF-SHA256, HMAC-SHA256), independent of the VFS/SQLite runtime that wrote it.

> **What you need to recover your data:** the `.freehold` file and your **recovery code**. A passkey
> cannot be used off-device (its PRF output never leaves the authenticator, by design), so the
> device-independent recovery code is the portability key. Guard it like the master password it is.

## Layers, bottom-up

All multi-byte integers are little-endian. Three nested formats; the decryptor reverses them in order.

### 1. Bundle container (`bundle.rs`) — magic `FREEHOLD`, version 1
```
bundle  = "FREEHOLD"(8) | version(1)=1 | section*         (sections run to EOF)
section = tag(1) | payload
  tag 1  envelope     u32 len | bytes        (the key envelope, §2)
  tag 2  cred_id      u32 len | bytes        (WebAuthn credential id; public, unused for decryption)
  tag 3  file         u16 name_len | utf8 name | u32 data_len | bytes   (one encrypted DB file, §3)
  tag 4  epoch_token  u32 len | bytes        (sync-epoch freshness token; irrelevant to decryption)
```
A bundle carries the envelope once, then one `file` section per pool file — for each database `X`
both `X.db` (the SQLite image) and `X.db#manifest` (its metadata). Unknown tags are a hard error, not
a skip. The container has no integrity layer of its own: every payload is either public metadata or
AEAD-authenticated, so tampering surfaces as an AEAD failure below.

### 2. Key envelope (`envelope.rs`) — magic `FREEHENV`, version 3
```
blob   = header(36) | slot(74)* | mac(32)
header = "FREEHENV"(8) | version(1)=3 | slot_count(1) | reserved(2) | env_salt(16) | env_generation(8)
slot   = kek_id(1) | kind(1) | nonce(24) | wrapped_dek_ct(32) | tag(16)
mac    = HMAC-SHA256( HKDF(DEK,"freehold-envelope-mac-v1"), header ‖ all-slots )
```
A random 256-bit **DEK** is wrapped independently in each slot. To recover it from the **recovery
code** (a `kind = 1` slot):

1. `KEK = Argon2id(normalize(code), salt = env_salt)` — 32-byte output, default `argon2` v0.5 params.
   `normalize` = strip all whitespace, upper-case (hyphens are significant).
2. `DEK = XChaCha20-Poly1305{key=KEK}.open(nonce, ct=wrapped_dek_ct, tag, aad = "freehold-envelope-v3" ‖ kek_id ‖ kind)`.
3. Verify the envelope MAC under the recovered DEK (tamper check). `env_generation` is anti-rollback
   metadata (issue #3) and is not needed to decrypt.

The AAD binds `kind`, so a recovery KEK can only open a recovery slot. Passkey slots (`kind = 0`, KEK
= `HKDF(prf_output,"freehold-kek-v1")`) are **not** recoverable off-device and the tool ignores them.

### 3. Encrypted block device (`crypto.rs`)
Each `X.db` file section is that file's data region: a uniform grid of physical blocks
```
P = 4096 + 24 + 16 = 4136 bytes   →   ciphertext(4096) | nonce(24) | tag(16)
```
Block `k` (0-based, = its position in the file) decrypts to a 4096-byte SQLite page under
```
K_db  = HKDF( DEK, "freehold/vfs-db-v1\0" ‖ db_uuid )                      (XChaCha20-Poly1305 key)
aad_k = file_id(16) ‖ db_uuid(16) ‖ k_LE(8) ‖ 4096_LE(4) ‖ cipher_id(1)=1
plain_k = open(K_db, nonce_k, ct_k, tag_k, aad_k)
```
where `file_id = SHA-256(name)[..16]` (name = the section's file name, e.g. `"app.db"`) and `db_uuid`
is the DB's random 128-bit id, read in the clear from the **manifest** section's plaintext header
(`X.db#manifest` bytes `[8..24]`; bytes `[0..8]` are the manifest magic). Concatenating `plain_0 ‖
plain_1 ‖ …` yields the exact plaintext SQLite file (the block count × 4096 = the original file size).
Encryption changes neither `db_uuid` nor any plaintext byte, so the recovered image is byte-identical
to what the source device stored — open it with any `sqlite3`.

## Using the tool
```
cargo build -p freehold-decrypt --release
./target/release/freehold-decrypt  my-vault.freehold  "YOUR-RECOVERY-CODE"  ./out
# → ./out/app.sqlite (one <name>.sqlite per database), openable in any SQLite.
```
Proven by `cargo test -p freehold-decrypt` against a golden fixture exported by the real browser stack
(`tests/decrypt-fixture.spec.js`): the recovered image has the SQLite magic, is a whole number of
pages, and contains the known row; a wrong code fails closed; case/whitespace-normalized codes open;
a tampered magic is rejected.

## Guarantee & limit
Anyone with the `.freehold` file **and** the recovery code recovers the data with ~350 lines of Rust
over five public crates — no server, no Freehold install, no account. That is the portability promise.
Conversely, the recovery code IS the master key to that file: possession of the bundle alone reveals
nothing (all AEAD), but a leaked recovery code opens any copy of the bundle it was minted for. After a
[[dek-rotation-design|DEK rotation]] a *new* recovery code is issued and old bundle copies remain
readable only by whoever held the *old* code — rotation protects future state, it cannot un-leak an
old exported copy.

## Exporting after mid-session method changes (fixed)
`exportBundle()` embeds the **current** envelope: it passes the SDK's rollback-guarded IndexedDB copy
into `session_export`, which uses it for both the embedded envelope and the attested epoch generation.
So a recovery method or passkey added *during* a live session (`addRecoveryCode`/`addPasskey`) is
present in a bundle exported later in that same session — no re-`unlock()` needed. (Earlier the session
retained an open-time envelope snapshot that could go stale; the session no longer stores the envelope
at all. The golden fixture is generated with the recovery code added mid-session, so the native decrypt
test is the regression guard.)

## Cross-links
[[header-free-encrypted-vfs]] design-spec §11 (envelope) / §14 (cross-device image), envelope v3
(issue #3), [[dek-rotation-design]] (§2 rotation limit this inherits).
