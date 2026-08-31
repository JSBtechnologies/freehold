---
slug: header-free-encrypted-vfs
artifact: design-spec
version: 1.1     # 1.0 = pre-review; 1.1 = after 3-agent adversarial review (2026-08-28)
status: implemented     # draft-for-review -> revised-post-review -> implemented (M1–M3 built + security-reviewed, all findings fixed; see ../security-review.md)
created: 2026-08-28
updated: 2026-08-28
parent: header-free-encrypted-vfs/README.md
kind: security-critical-design
reviewed-by: adversarial-review.md (crypto-construction / crash-consistency / plaintext-leak)
---

# Encrypting VFS — design spec (design-before-code)

> **⚠ READ §17 FIRST.** This spec went through a 3-agent adversarial review (see
> `adversarial-review.md`). The review found the crypto core sound but the surrounding machinery
> under-specified/unsafe. **§17 is the normative v1.1 revision delta and SUPERSEDES any conflicting
> text in §1–§16.** Where §1–§16 and §17 disagree, §17 wins. Key reversal: **v1 journal mode is now
> rollback-journal, not WAL** (WAL caused committed-data corruption via the block device).

> **What this is.** The reviewed-before-coded design for the moat artifact: a header-free,
> whole-file-encrypted SQLite storage layer built as our own VFS. Security-critical. Not yet
> implemented. All design decisions are resolved (§15); §17 hardens them post-review.

---

## 0. What changed from the topic's initial sketch (read before the rest)

The topic README's design surface assumed **AES-256-GCM in reserved bytes, SQLCipher-style**.
Two facts surfaced during design change that starting point. Both are load-bearing:

1. **The SAHPool VFS is synchronous, so WebCrypto cannot be used in the I/O path.** `xRead`/
   `xWrite` are called synchronously by SQLite (the whole reason SAHPool uses OPFS *sync*
   access handles). `crypto.subtle` (SubtleCrypto) is **Promise-only — there is no synchronous
   WebCrypto API**. You cannot `await` inside a synchronous `xRead`. `[High]` Therefore the
   cipher **must be a synchronous, pure-Rust AEAD** (RustCrypto), and hardware-accelerated
   AES via WebCrypto is off the table for the page path. This *resolves* the topic's stated
   "WebCrypto vs Rust-AES tradeoff": it's Rust. (See §5.)

2. **We encrypt at the VFS I/O layer, not the SQLite pager-codec layer.** SQLCipher/sqlite3mc
   stash their IV+MAC in per-page *reserved bytes* because they run at the pager codec
   (`SQLITE_HAS_CODEC`), where SQLite cooperates by leaving those bytes unused. Our recon proved
   that codec path is exactly what the SAHPool VFS *cannot* expose (`PRAGMA key` → "Encryption
   is not supported by the VFS"). We sit one layer lower, at `sqlite3_io_methods`, where SQLite
   hands us **raw byte ranges with no notion of our reserved bytes**. So the reserved-bytes
   trick doesn't apply cleanly, and — critically — it *cannot* frame the WAL/journal files,
   whose byte layout is not page-aligned. The robust construction at this layer is an
   **offset-translating encrypted block device** (§4), which is agnostic to SQLite's file
   framing and therefore covers main DB, journal, WAL, and temp *uniformly*.

Everything downstream (page layout, nonce placement, file coverage) follows from these two.

---

## 1. Terminology: what "header-free" means here

"Header-free" in this project = **no COOP/COEP HTTP response headers required** (no
cross-origin isolation, no `SharedArrayBuffer`). It does **not** mean "zero metadata bytes in
the file." A small amount of per-file crypto framing on disk is fine and does not violate
header-free. Success signal remains **`crossOriginIsolated === false`** at runtime. `[High]`

---

## 2. Architecture: where the cipher sits

```
   SQLite core (pager, btree)                <- sees ONLY plaintext, unmodified page size
        |  sqlite3_io_methods (xRead/xWrite/xTruncate/xFileSize/xSync/xShm*)
        v
   >>> EncryptedBlockDevice  (THE NEW LAYER — this spec)  <<<
        |  offset translation + per-block AEAD (encrypt on write / decrypt on read)
        v
   SAHPool sync-access-handle I/O  (sqlite-wasm-vfs / rsqlite-vfs, unmodified)
        |
        v
   OPFS FileSystemSyncAccessHandle   <- sees ONLY ciphertext
```

- Above the new layer: SQLite believes it is talking to an ordinary file. Plaintext only.
- Below: OPFS stores ciphertext only. A raw dump of the OPFS file is indistinguishable from
  random without the DEK.
- The new layer is the *entire* trusted crypto boundary. Keep it small and reviewable.

We **adapt** `sqlite-wasm-vfs`'s `sahpool` (on `rsqlite-vfs`) by inserting `EncryptedBlockDevice`
between its `SQLiteIoMethods` and the sync-access-handle reads/writes. We do **not** modify
SQLite C and do **not** use the sqlite3mc codec.

---

## 3. Threat model (recap — full model in [[secure-local-db-threat-model]])

**Defended:**
- **At-rest confidentiality.** An attacker who reads the OPFS bytes (malware, disk forensics,
  another process, a stolen device) learns nothing without the DEK.
- **At-rest integrity / tamper.** Flipping any ciphertext byte fails AEAD auth on read.
- **Cross-file/cross-block relocation.** Moving a valid block to a different offset or file
  fails auth (AAD binds `fileId || blockIndex`, §6).

**Partially defended (see §10 — "somewhat" anti-rollback, generation-counter in v1 per D4):**
- **Whole-file rollback** (restore an older file image): **detected** by the manifest's monotonic
  `db_generation` vs the `TrustedGeneration` anchor (§10.2, §10.4). `[High]`
- **Whole consistent-snapshot rollback** (restore old data *and* old manifest together):
  *detected on next sync* + raised-bar locally, **not** cryptographically prevented offline —
  no external monotonic anchor can exist purely inside OPFS (§10.4). `[Medium]`
- **Partial / surgical rollback** (revert *some* blocks, keep others): **deferred** — needs the
  Merkle-over-tags tree (§10.2), added in a later version. Narrow at-rest-without-key threat.
- *Note:* rollback protection only matters against an attacker who can rewrite OPFS **but lacks
  the DEK**; an attacker holding the key edits directly and rollback is moot for them.

**Explicitly NOT defended:**
- **Live-memory compromise while unlocked.** The DEK and decrypted pages are in wasm linear
  memory while the DB is open; an attacker executing in-page can read them. Mitigated by
  zeroize-on-lock (§11), not eliminated.
- **Traffic/size analysis.** File size and write patterns leak coarse activity. Out of scope v1.

Key source: DEK = 256-bit key from M2 (WebAuthn-PRF → HKDF), injected at VFS registration; never
persisted by the VFS.

---

## 4. The encrypted block device (the heart of the design)

Impose our **own fixed plaintext block size `B`** on every file, independent of SQLite's
internal structure, and translate offsets. Default `B = 4096` (match SQLite default page size;
configurable, must be ≥ SQLite page size and a power of two).

**Physical layout.** The physical (on-disk) file is a sequence of fixed-size *physical blocks*:

```
 physical block i  =  [ ciphertext (B bytes) | nonce (Nn bytes) | tag (16 bytes) ]
 physical block size  P = B + Nn + 16
```

(`Nn` = 24 for XChaCha20-Poly1305, or 12 for AES-256-GCM — see §5.)

**Offset translation.** A logical byte offset `L` (what SQLite asks for) maps to:

```
 block index      k          = L / B
 intra-block off  o          = L % B
 physical offset of block k  = k * P
```

- **`xRead(buf, len, L)`**: for each block `k` covering `[L, L+len)`, read the `P` physical
  bytes at `k*P`, AEAD-open into a `B`-byte plaintext block, copy the requested sub-range into
  `buf`. A read past EOF returns `SQLITE_IOERR_SHORT_READ` (SQLite treats the tail as zeros —
  this is how an empty/new DB is detected; no special-casing needed). `[High]`
- **`xWrite(buf, len, L)`**:
  - *Whole-block, block-aligned write* (`o == 0 && len == B`): AEAD-seal `buf` with a fresh
    nonce, write `P` bytes at `k*P`. No read needed.
  - *Partial write* (`o != 0 || len < B`): **read-modify-write** — AEAD-open the existing block
    (or zero-fill if it doesn't exist yet), overlay `buf`, re-seal with a **fresh** nonce, write
    back. Every re-seal gets a new nonce (§8).

**Why the main DB never needs read-modify-write.** SQLite writes the main database file in
whole pages at page-aligned logical offsets. With `B` = page size, every main-DB write is
`o == 0 && len == B` → whole-block path. Read-modify-write only occurs for WAL/journal (whose
writes are not `B`-aligned) and those files are transient. `[Medium — verify SQLite never issues
sub-page main-DB writes for the configured page size; hot-journal spill edge cases to test]`

**Why this model and not reserved-bytes.** Reserved-bytes (1:1 offset) requires pager
cooperation we don't have at the VFS layer and *cannot frame the WAL/journal* (their bytes are
not page-aligned: 32-byte WAL header + 24-byte frame headers throw off any page grid). The
block device is **framing-agnostic** — it encrypts any byte range of any file identically — which
is exactly what makes whole-file coverage (§7) leak-proof. Cost: offset math + partial-block
read-modify-write. Accepted. `[High]`

---

## 5. AEAD selection

**Constraint (from §0.1): synchronous, pure-Rust, audited AEAD.** Two candidates, both from
the audited RustCrypto suite, both used behind a generic `aead::Aead` trait so we can swap and
benchmark without touching the block-device logic.

| | **XChaCha20-Poly1305 (recommended)** | AES-256-GCM (alternative) |
|---|---|---|
| Crate | `chacha20poly1305::XChaCha20Poly1305` | `aes-gcm::Aes256Gcm` |
| Nonce | **192-bit** | 96-bit |
| Random-nonce safety | Collision negligible (~2⁻⁹⁶ birthday) → **random nonce per write is safe indefinitely, no counter, no rekey pressure** | NIST caps a key at ~2³² random-nonce writes for a 2⁻³² margin → **must track per-key write count and rekey before exhaustion** |
| Speed in wasm | Software ChaCha is fast + constant-time by design; **no AES-NI available to sync wasm anyway** | Software AES in wasm (RustCrypto fixslice) is constant-time but slower; no HW accel in sync path |
| Overhead/block | 24 + 16 = **40 B** (~1% of 4096) | 12 + 16 = 28 B (~0.7%) |
| Standards | Widely deployed (WireGuard, age, libsodium `secretbox` family) | FIPS-blessed |

**DECIDED (D1, 2026-08-28): XChaCha20-Poly1305.** The 192-bit nonce dissolves the single hardest
correctness hazard of this whole design — GCM nonce reuse under a crash-prone browser with no
durable counter — while also being the faster software cipher in wasm. `[High]` `Nn = 24`,
overhead 40 B/block. Code stays generic over `aead::Aead` so an AES-256-GCM swap remains a
one-type change if a FIPS mandate ever arrives. Not invented crypto — a standard audited AEAD
used as-is.

---

## 6. Per-block format & associated data

```
 seal(  key  = DEK,
        nonce = random Nn bytes (fresh every write),
        plaintext = B-byte block,
        aad  = DOMAIN(8) || file_id(8) || block_index_LE(8)  )   // 24 bytes AAD
   -> ciphertext (B) || tag (16)
 on disk:  ciphertext || nonce || tag
```

- **`DOMAIN`** = fixed 8-byte constant per DB instance (or per DEK) for domain separation.
- **`file_id`** = stable per-file id (0 = main DB, and a distinct id per journal/WAL/temp file
  the VFS opens). Binding it stops a valid block from one file authenticating in another.
- **`block_index`** = `k`. Binding it stops **cross-block relocation** (moving block 5's
  ciphertext to offset 9 fails auth). `[High]`

AAD is authenticated-but-not-encrypted; it is derivable from position, so storing only
`nonce`+`tag` on disk is sufficient. The nonce is stored (not derived) precisely so we can use
fresh randomness per write (§8).

---

## 7. File coverage — no plaintext escapes (the top "silent leak" risk)

**Principle: the VFS encrypts EVERY file it is asked to open, by default, keyed by the DEK.**
No allow-listing "just the main DB." A forgotten file type must fail *closed* (encrypted), not
open (plaintext). The block device (§4) makes this uniform because it doesn't care about framing.

| File SQLite may open | Handling |
|---|---|
| **Main DB** | Encrypted block device, whole-block writes. |
| **Rollback journal** (`-journal`) | Contains original *page images* (plaintext user data). **Encrypted** via block device (partial writes → read-modify-write). |
| **WAL** (`-wal`) | Contains page-image frames (plaintext user data). **Encrypted** via block device. |
| **WAL index / shared mem** (`-shm`) | In single-connection `locking_mode=EXCLUSIVE`, SQLite keeps the wal-index in heap via `xShmMap`; the SAHPool VFS backs it with **in-memory** buffers → never on disk → no leak. **Must confirm** in `sqlite-wasm-vfs`; if it ever persists, encrypt it too (metadata-only, low sensitivity, encrypt for uniformity). `[Medium — verify]` |
| **Temp DB / sorter / statement journals** | Contain plaintext user data. **Force into memory** so they never reach the VFS: `PRAGMA temp_store = MEMORY` **and** compile SQLite with `SQLITE_TEMP_STORE=3` (belt-and-suspenders). Any temp file that *does* reach the VFS is still encrypted by default. `[High]` |

**Mandated connection pragmas / build flags (defense in depth):**
- `SQLITE_TEMP_STORE=3` (compile) + `PRAGMA temp_store=MEMORY` (runtime) — temp never hits disk.
- `PRAGMA locking_mode=EXCLUSIVE` — single connection (SAHPool is single-connection anyway);
  keeps `-shm` in memory and simplifies nonce/write reasoning.
- Journaling mode: **REVISED (D2, v1.1): rollback-journal** (`journal_mode=DELETE`/`TRUNCATE`),
  **NOT WAL.** The review found WAL causes *committed-data corruption* through the block device:
  WAL frames (4120 B) never align to the 4096 B encryption grid, so appending a frame read-modify-
  writes a block that also holds an already-committed frame; a torn write there destroys committed
  data (`adversarial-review.md` B). Rollback-journal keeps durable state in the whole-block-aligned
  main DB, removing the hazard — and since we're single-connection (`locking_mode=EXCLUSIVE`),
  WAL's concurrency benefit doesn't apply anyway. The `-journal` file is encrypted like everything
  else. Never use `journal_mode=MEMORY/OFF` (leak-free but corruptible — unacceptable). WAL may
  return post-v1 with frame-aligned encryption. See §17.B.

---

## 8. Nonce management

- **Fresh random nonce on every seal**, drawn from a CSPRNG (`crypto.getRandomValues` via
  `getrandom`, or WebCrypto sync `getRandomValues` — note `getRandomValues` *is* synchronous,
  unlike `subtle`). Stored in the block's `nonce` field.
- With XChaCha20's 192-bit nonce, per-write randomness is safe with no counter and no
  crash-recovery concern (a crash that loses a write just means that block is re-sealed with a
  new random nonce next time — no reuse). `[High]`
- If D1 selects AES-256-GCM instead: add a **per-DEK monotonic write-odometer** persisted in an
  authenticated metadata block, and trigger DEK rotation (§11) before ~2³² writes; a crash that
  rolls the odometer back **must** force rotation on next open (fail safe). This fragility is the
  main argument for XChaCha20. `[High]`

---

## 9. Crash consistency & atomicity

Encryption is a transparent transform; it must not weaken SQLite's crash guarantees.

- **Main DB writes are whole-block** (§4), so a torn write can only damage a page SQLite already
  protected via the journal/WAL — SQLite's normal torn-page recovery applies unchanged.
- **`xSync` must durably flush ciphertext** to the OPFS access handle before returning. The
  SAHPool handle's `flush()` provides this. The encryption adds no reordering.
- **Torn encryption block in journal/WAL** (a partial-block write interrupted by a crash): the
  block fails AEAD-open on recovery → SQLite sees a corrupt journal/WAL record. SQLite's journal
  format has its own record checksums and treats the first bad record as end-of-journal → it
  stops replay there. Net effect: the in-flight transaction is *not* committed — the **correct**
  outcome, not corruption. `[Medium — must be validated with fault-injection/crash tests, §14]`
- **No cross-block write atomicity is assumed.** Each physical block is sealed independently; we
  never rely on two blocks being updated atomically.

---

## 10. Rollback / substitution defense — IN SCOPE v1 (D4 resolved)

The tag authenticates a block's *contents*, not its *freshness*: an attacker with OPFS write
access can restore an older-but-valid ciphertext and it will authenticate. v1 defends against
this with an authenticated **manifest** + a **Merkle tree over block tags**. Read honestly about
the boundary of what's achievable purely inside OPFS (10.4).

### 10.1 The manifest (authenticated freshness root)
A dedicated, AEAD-sealed metadata block (its own reserved `file_id = 0xFFFF`, block 0):

```
 manifest = seal(DEK, nonce, plaintext = {
     format_version : u16,
     cipher_id      : u8,          // 1 = XChaCha20-Poly1305
     block_size B   : u32,
     db_generation  : u64,         // monotonic, bumped once per durability barrier (xSync/commit)
     merkle_root    : [u8; 32],    // root over the leaf set below
     leaf_count     : u64,
 }, aad = DOMAIN || 0xFFFF || 0 || db_generation)
```

The manifest is the single trust anchor: verify it first on open; everything else is checked
against it. It is itself freshness-bound by `db_generation` (10.4).

### 10.2 v1 = generation counter; Merkle tree DEFERRED (D4/D6 resolved 2026-08-28)
**Rationale (stakeholder, threat-model-driven):** rollback only helps an attacker who can rewrite
OPFS **but lacks the DEK** (with the key they'd just edit directly). That is a narrow slice; the
*realistic* and *cheap-to-defend* rollback threat is a stale/malicious sync peer, handled by the
sync epoch (10.4). So v1 covers the base we can cheaply cover and defers the expensive part:
- **v1 (build now):** the manifest's monotonic **`db_generation`** gives **whole-file** freshness.
  On open, reject a manifest whose generation is older than the `TrustedGeneration` anchor
  (10.4). Bumped once per durability barrier (commit/xSync). No Merkle tree. `[High]` for
  whole-file rollback detection.
- **Deferred to a later version (when sync exists, cheap then):** a **Merkle tree over per-block
  tags** to also catch *partial/surgical* rollback (revert some blocks, keep others). Leaves =
  per-block AEAD tags (no extra crypto, only hashing). Additive — no data-format migration needed
  (the manifest already reserves `merkle_root`; it's `0` / unused in v1).

**Why this dissolves the WAL problem:** a Merkle root would have had to span the growing/truncating
WAL (the hardest part of the whole build). A single monotonic generation counter does not — it's
one number bumped at each durability barrier — so **v1 keeps WAL (D2) with no penalty.** The old
"D6" fork (how the tree spans WAL) is therefore **moot for v1** and folded into the deferred tree's
own design.

### 10.4 Boundary: whole-consistent-snapshot rollback (be honest)
Partial rollback is *prevented* (10.2). But an attacker who restores an **entire consistent old
snapshot — old data blocks *and* the matching old manifest** — produces an internally consistent
DB that verifies. Detecting *that* requires a monotonic anchor the attacker **cannot** roll back,
which does not exist purely inside OPFS (they can rewrite any OPFS byte). v1 therefore ships a
pluggable freshness anchor and two best-effort backstops:
- **`TrustedGeneration` interface:** `last_seen() -> u64` / `record(u64)`; open **rejects** a
  manifest whose `db_generation < last_seen()`.
- **Local backstop (v1 default):** persist `last_seen` outside the DB file (separate OPFS entry /
  IndexedDB). Raises the bar (attacker must find and roll back a second store) but is not a proof.
- **Strong anchor (integrates with sync):** the sync server / group epoch records max
  `db_generation` per device and rejects stale on next online sync → whole-snapshot rollback is
  caught the moment the device syncs. This is where real anti-rollback lives; owned by
  [[encrypted-local-first-sync]]. `[Medium]`

**Net v1 guarantee:** confidentiality + tamper + relocation + **whole-file rollback DETECTION**
(via the generation anchor). v1 has **NO partial-rollback protection** — with `merkle_root = 0`
the manifest authenticates only its own generation number, not the data-block contents, so an
attacker without the DEK could pair the current manifest with an older valid data-block set and it
would not be detected; that gap closes only when the deferred Merkle tree lands (§10.2).
Whole-consistent-snapshot rollback is *detected on next sync* + *raised-bar* locally, not
cryptographically prevented offline. Stated plainly so no one over-trusts it. `[High]` on the
guarantee as scoped. *(Corrected in the 2026-08-28 adversarial review — the prior wording claimed
partial-rollback prevention the deferred-tree v1 does not provide; see `adversarial-review.md` A.)*

---

## 11. Key lifecycle

- **Injection:** DEK handed to the VFS at registration (e.g. `install_freehold(cfg, dek)`),
  held in a `zeroize::Zeroizing<[u8;32]>`. Never written to OPFS, never logged.
- **Zeroize:** wipe DEK and any decrypted-page scratch buffers on DB close / lock / drop. Favors
  Rust (`Zeroize`/`ZeroizeOnDrop`). Cannot guarantee wasm linear memory is never paged, but
  minimizes window. `[Medium]`
- **Add/remove authenticator = re-wrap, NOT re-encrypt.** The DEK is constant; only its
  KEK-wrapped copies change (envelope mgmt in M2, [[secure-local-db-threat-model]] B). Adding a
  passkey does **zero** file I/O to the encrypted DB. `[High]`
- **DEK rotation (suspected compromise):** generate DEK′, stream every block (open with DEK, seal
  with DEK′) into a **new** OPFS file, then atomic-swap. Crash-safe via write-new-then-swap;
  never in-place. Offline/maintenance operation. `[High]` **STATUS: designed, not yet built**
  (tracked as issue #4). Until it ships, the two notes below bound what "revocation" actually means.
- **Revoking a method ≠ containing a compromised device.** `remove_slot` drops one KEK-wrapped copy
  of the DEK; **the DEK itself is unchanged.** A device that was unlocked and then compromised may
  already hold the DEK in memory — removing its slot does nothing about that. **Genuine eviction of
  a compromised device requires DEK rotation** (above) so all prior key material becomes useless. A
  compromised device also remains able to mint valid sync epochs until rotation (it is inside the
  trust boundary — see [[header-free-encrypted-vfs/sync-epoch-design]] §2.1). `[High]`
- **Envelope rollback.** The envelope blob is stored in attacker-controllable local storage and (as
  of format v2) carries **no monotonic generation**, so restoring an older copy silently **re-plants
  a removed slot** — revocation is not durable against a local rollback of the envelope. The fix is
  to bring the envelope under the same anti-rollback umbrella as `db_generation`: an `env_generation`
  counter, floor-enforced locally and bound into the cross-device epoch so a stale envelope cannot
  propagate (tracked as issue #3; format bump to v3). `[High]`

---

## 12. `xFileSize` / `xTruncate` arithmetic

SQLite expects **logical** sizes; the physical file is larger (overhead `P−B` per block).

- `xFileSize` → `logical = full_blocks * B + last_partial_plaintext_len`. For the main DB
  (whole blocks) `logical = (physical_size / P) * B`. For WAL/journal a trailing partial block
  must be accounted for.
- `xTruncate(logical)` → truncate physical to `ceil(logical/B)` blocks, re-seal the final
  partial block if needed.
- **This math is a classic bug site** (off-by-`P` errors silently corrupt). Property-test it:
  round-trip `logical → physical → logical` for random sizes; assert monotonic and exact. §14.

---

## 13. Performance budget

- XChaCha20-Poly1305 over a 4 KB block in wasm: order single-digit µs/block (software throughput
  ~hundreds of MB/s). One AEAD op per page read, one per page write; partial WAL writes add one
  open per touched block. Expected acceptable for a local interactive DB. `[Medium — measure]`
- Space overhead ~1% (40 B / 4096 B).
- **Benchmark gate before "implemented":** insert/select/update throughput vs the plaintext M0
  SAHPool baseline; flag if >~2× slowdown on realistic workloads. §14.

---

## 14. Test plan (must pass before status → implemented)

1. **AEAD test vectors:** RustCrypto known-answer vectors for the chosen cipher (proves we wired
   the primitive correctly — do not hand-roll).
2. **Round-trip:** write N rows, close, reopen with correct DEK → all rows intact.
3. **Wrong key:** reopen with wrong DEK → first block open fails → DB unreadable (no plaintext).
4. **Tamper:** flip one on-disk ciphertext byte → AEAD auth failure on read of that block.
5. **Cross-block swap:** copy block 5's physical bytes over block 9 → auth failure (AAD).
5b. **Whole-file rollback:** restore an older file image → manifest `db_generation < last_seen()`
    (local backstop) rejects it; a mock sync anchor rejects the stale generation (§10.2/§10.4).
5c. **Partial rollback (deferred feature):** test placeholder — when the Merkle tree lands, revert
    some blocks while keeping others → Merkle path vs `merkle_root` fails. Not built in v1.
6. **Ciphertext audit:** raw-dump the OPFS file → assert no plaintext row values / no
   `"SQLite format 3"` magic anywhere (incl. after WAL checkpoint).
7. **File coverage:** exercise WAL mode + a large temp-spilling query; audit `-wal`, `-journal`,
   any temp file for plaintext. `-shm` confirmed memory-only.
8. **Crash/fault injection:** interrupt writes mid-transaction (truncate the physical file at
   random offsets, corrupt a journal block) → DB opens to a consistent pre- or post-transaction
   state, never corrupt.
9. **Size math:** property test `xFileSize`/`xTruncate` round-trips.
10. **`crossOriginIsolated === false`** at runtime (header-free preserved).
11. **Perf:** throughput vs plaintext SAHPool baseline.

---

## 15. Decisions register

- **D1 — AEAD cipher. ✅ RESOLVED: XChaCha20-Poly1305** (2026-08-28). `Nn=24`, 40 B/block. Generic
  over `aead::Aead` for a future AES-256-GCM swap. (§5)
- **D2 — Journaling mode. ✅ RE-RESOLVED (v1.1): rollback-journal** (2026-08-28, reversing the
  earlier WAL pick after the review found WAL corrupts committed data via the block device). Encrypted
  `-journal`; state stays in the whole-block main DB; WAL post-v1 only. (§7, §17.B, `adversarial-review.md` B)
- **D3 — Block size `B`. ✅ DEFAULT: 4096** (= page size). Revisit only if benchmarks demand. (§4)
- **D4 — Anti-rollback in v1. ✅ RESOLVED: "somewhat" — generation counter only** (2026-08-28).
  Manifest `db_generation` gives whole-file rollback detection; strong enforcement via sync epoch.
  Merkle-over-tags (partial rollback) **deferred** to a later version — additive, no migration.
  Rationale: rollback only matters against an attacker without the DEK (narrow); don't gold-plate.
- **D5 — Authenticated metadata block. ✅ RESOLVED: YES**, introduced now (the §10.1 manifest);
  `DOMAIN` = 8-byte per-DB constant in the manifest, `file_id` assigned per opened file
  (0 = main DB, 0xFFFF = manifest, others per WAL/journal/temp). `merkle_root` reserved (0 in v1).
- **D6 — Merkle root vs WAL. ✅ MOOT for v1** — deferring the Merkle tree (D4) removes the
  WAL-spanning problem entirely; v1 keeps WAL with no penalty. Re-opens only if/when the tree is
  built (folded into that design).

---

## 16. Implementation checklist (after review only)

1. Vendor `sqlite-wasm-vfs` `sahpool` as `prototype/freehold` (fork, keep upstream diff small).
2. Implement `EncryptedBlockDevice` (offset translation + `XChaCha20Poly1305` via generic `Aead`):
   `read_block`, `write_block` (whole + read-modify-write), `file_size`, `truncate`.
3. Splice it between the sahpool `SQLiteIoMethods` and the sync-access-handle calls.
4. DEK injection at registration; `Zeroizing` storage; zeroize on close.
5. Enforce mandated pragmas/build flags (§7): `SQLITE_TEMP_STORE=3`, `temp_store=MEMORY`,
   `locking_mode=EXCLUSIVE`, `journal_mode=DELETE` (rollback-journal — **not** WAL, §17.B), and
   **enforce `B == page_size` exactly** at open (§17.I).
6. **Anti-rollback (D4, "somewhat"):** double-buffered manifest block (§17.C) with monotonic
   `db_generation` + `db_uuid` + per-file authenticated length + `TrustedGeneration` anchor state
   machine (§17.C/D/E/J). **No Merkle tree in v1** (deferred).
6b. **Structural fail-closed (§17.G):** the VFS owns `xOpen`; every file handle's `pMethods` is
   exclusively the encrypted vtable; no reachable path to a raw sync-access-handle write.
7. Test harness for §14 incl. rollback tests 5b/5c (reuse the `vfs-recon-spike` Vite + worker rig).
8. Security review of the block device + AEAD wiring + Merkle/manifest, then status → `implemented`.

**Toolchain:** Rust 1.96 + LLVM 22.1.8 + wasm-pack; env per [[rust-wasm-toolchain-setup]].

**Non-negotiables:** vetted AEAD used as-is (no invented crypto); every file encrypted by
default (fail closed); fresh nonce per write; DEK never persisted; `crossOriginIsolated` stays
false.

---

## 17. v1.1 revision delta (NORMATIVE — supersedes §1–§16 on conflict)

Outcome of the 2026-08-28 3-agent adversarial review (`adversarial-review.md`). The crypto core
(XChaCha20-Poly1305 + fresh random 192-bit nonce, offset-translated block device, VFS-layer
placement, AAD position-binding, sync-cipher requirement) is **confirmed sound** and unchanged.
The items below are mandatory hardening. Letters match `adversarial-review.md` themes.

**A — v1 rollback claim corrected.** v1 provides whole-file rollback **detection** only (generation
anchor); **no** partial-rollback protection until the deferred Merkle tree lands. (§10.4 fixed.)

**B — Journal mode: rollback-journal, NOT WAL.** WAL frames straddle the encryption grid →
appending a frame RMWs a block holding an already-committed frame → torn write destroys committed
data. Use `journal_mode=DELETE`/`TRUNCATE`; `-journal` encrypted via the block device. Single-
connection means WAL's concurrency win doesn't apply. WAL returns post-v1 only with frame-aligned
encryption. This also dissolves the §10-era WAL/Merkle interaction and half the §K torn-record
error-mapping tension.

**C — Double-buffer the manifest (crash-durability).** The manifest is the DB's trust anchor;
a single in-place torn write must not brick the DB. Keep **two manifest slots** (ping-pong by
generation parity). Write the inactive slot → xSync → on open select the highest-`db_generation`
slot that authenticates. Reject only if **both** slots fail. (Supersedes §10.1's single-block
manifest.)

**D — Freshness-anchor state machine (must not brick on normal crash).** The external
`TrustedGeneration` anchor and the in-file manifest are non-atomic stores. Rules:
- Ordering (invariant): data blocks written → xSync → manifest slot written → xSync →
  **then** `record(last_seen)`. `record()` never precedes the manifest's durable xSync.
- Store the anchor as a window `{committed_gen, in_flight_gen}`.
- On open: `manifest_gen == last_seen − 1` (a lost final bump from a crash) is **recoverable** —
  re-adopt the manifest, do **not** treat as rollback. Only `manifest_gen` far below
  `committed_gen` signals an attack. A normal power-loss must never make the DB unopenable.
- Bump `db_generation` **exactly once per logical commit** — hook `SQLITE_FCNTL_COMMIT_PHASETWO`
  (or the post-commit sync), never intra-commit syncs (§P).
- Verify the manifest (and `db_generation ≥ committed_gen`) **before** servicing any main-DB `xRead`.

**E — Per-DB key derivation (fixes DOMAIN + cross-DB + ATTACH).** Do not use a bare 8-byte
`DOMAIN` AAD of undefined origin. Instead derive a **per-database subkey**:
`K_db = HKDF(DEK, "vfs-db-v1" || db_uuid)`, where `db_uuid` = random 128-bit value fixed at DB
creation, stored in the manifest plaintext and verified after open (a wrong-DB manifest then fails
to *decrypt*, not merely fails an AAD check). All block seals use `K_db`. Rotation regenerates the
subkey domain. (Supersedes the §6 `DOMAIN` definition.)

**F — RNG fail-closed gate.** Nonce security is 100% RNG-dependent and RMW re-seals amplify any
weakness. At registration, self-test the CSPRNG (two draws distinct, neither all-zero) and **fail
closed** on failure. Every seal hard-errors (`SQLITE_IOERR`, no write) if the RNG call fails or
returns all-zeros — **never** fall back to a non-random nonce. Add VM/tab-snapshot and fork to §3
as nonce-reuse vectors. **Keep XChaCha20 + random nonce** — reject SIV (leaks page-equality) and
synthetic-counter nonces (reintroduce crash-rollback fragility).

**G — Fail-closed is STRUCTURAL, not documentary.** The encrypted VFS owns `xOpen` and returns
`sqlite3_file` objects whose `pMethods` is **exclusively** the encrypted io_methods. There must be
**no reachable code path** from any file handle to a raw sync-access-handle write. Build-time
assertion that the base sahpool write methods are unreachable + a negative test asserting zero
plaintext for *every* file opened during a full workload. (Supersedes the aspirational §7
"encrypt every file" principle with an enforced invariant.)

**H — Complete the file inventory.** Route through the block device and cover in tests:
**ATTACH**-ed databases (each gets its own `db_uuid` subkey + its own double-buffered manifest);
the **super-journal / master-journal** (multi-DB commits); temp/statement files. Derive
`file_id = HASH(canonical_path)` (**not** a fixed small-int table — no `file_id=0` collision
between two main DBs). **VACUUM INTO / backup-API** targets MUST be encrypted-VFS paths; `.dump`
(SQL text to app memory) is an inherent app-boundary residual leak — document it, don't pretend
the VFS covers it.

**I — Enforce `B == page_size` EXACTLY (not `≥`).** The "main-DB writes are whole-block" property
that §9's torn-write safety rests on holds only when `B == page_size`. At open, read the header and
**refuse** (fail closed) if `page_size != B`. **Reject** runtime `PRAGMA page_size` changes and
ATTACH/restore of a mismatched-page-size DB. (Supersedes §4's `B ≥ page_size`.)

**J — Authenticate the partial-final-block length.** For rollback-journal/temp files the logical
size isn't a multiple of B; the final block's plaintext length `j < B` must be stored
**authenticated** (a per-file length field in the manifest, or encoded into the final block's
AAD/plaintext-prefix). `xFileSize`/`xTruncate` derive logical size from that authenticated length,
**never** from `physical/P*B` alone. `xTruncate` = reseal-then-truncate (crash leaves old-or-valid,
never torn tail). (Supersedes §12's physical-size inference.)

**K — Define the AEAD-failure → SQLite error mapping.** Main-DB (and manifest) auth failure →
hard `SQLITE_IOERR` — **never** `SHORT_READ`, never zeros (those mean EOF and would mask
tamper/corruption as truncation). Reserve zero-fill strictly for reads genuinely past physical
EOF. Distinguish "short read (EOF)" from "auth failure" at every call site.

**L — Bind cipher + block size into every block's AAD; make cipher-swap deliberate.** AAD becomes
`file_id || block_index || B_LE(4) || cipher_id(1)` (position + framing + cipher, all
authenticated). Refuse to open a file whose manifest `cipher_id` ≠ the compiled cipher; assert
`Nn == CIPHER.nonce_len` at registration. Any AES-256-GCM build is gated behind a mandatory
persisted-nonce-odometer type (the 96-bit nonce needs it) — the swap is NOT one line. (Extends §6.)

**M — Zeroize in place.** Use `decrypt_in_place`/`encrypt_in_place` on a single reusable
`Zeroizing` block buffer; never let plaintext land in a dropped `Vec`. No decrypted plaintext,
nonce, or key bytes in any log/error string (§Q). (Extends §11.)

**N — `-shm` in memory is STRUCTURAL.** The VFS pins `locking_mode=EXCLUSIVE` and implements
`xShmMap` to return only heap buffers (never a file). Test asserts no `-shm` ever appears in OPFS.
(Converts §7's `[Medium — verify]` into an enforced invariant.)

**O — `SQLITE_TEMP_STORE=3` is the sole temp guarantee** (compile-time, un-overridable); the
runtime `temp_store=MEMORY` pragma is redundant belt. Forbid RBU/session extensions in v1 (their
aux files may bypass temp_store) or route them through the block device.

**Verification (§14 additions).** Add tests: rollback-journal crash/fault-injection (replaces the
WAL cases); manifest torn-write → other slot recovers (C); `last_seen`-ahead-by-one → recovers, not
bricked (D); ATTACH + super-journal plaintext audit (H); structural fail-closed negative test for
every opened file (G); RNG-failure → seal refused (F); `page_size != B` → open refused (I);
partial-final-block size round-trip + interrupted truncate (J); AEAD-failure returns IOERR not
SHORT_READ (K). Plus the M2 task: empirically verify OPFS `flush()` durability per target browser
and that no VFS write-back cache holds data past xSync.

**Still SOUND / unchanged:** §0 (sync-cipher + VFS-layer rationale), §5 (XChaCha20 choice), the
random-nonce-no-counter decision (§8, conditional on F), DEK lifecycle (§11: Zeroizing, never
persisted, re-wrap≠re-encrypt, rotation via write-new-then-swap), rollback threat scoping (§10),
`crossOriginIsolated===false` (§1).
