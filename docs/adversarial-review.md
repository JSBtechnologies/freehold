---
slug: header-free-encrypted-vfs
artifact: adversarial-review
reviews: design-spec.md
status: findings-adjudicated
created: 2026-08-28
method: 3 independent red-team agents (crypto-construction / crash-consistency / plaintext-leak+correctness), then adjudicated
---

# Adversarial review of the encrypting-VFS design spec — findings & adjudication

Three hostile reviewers each tried to break `design-spec.md` from a distinct angle. This doc
de-duplicates their findings into themes, **adjudicates** each (accept / reject / modify — I am
allowed to reject a reviewer), rates severity, and states the fix. Convergent findings (flagged
by ≥2 reviewers independently) are marked **⇉**. Verdict at bottom.

**Headline:** the design's *cryptographic core* (XChaCha20-Poly1305, offset-translated block
device, AAD position-binding, sync-cipher choice) survived — every reviewer independently
confirmed those as sound. What did **not** survive: (1) an over-claim I introduced, (2) WAL as
the v1 journal mode, and (3) a cluster of "asserted but not architecturally enforced / not fully
specified" gaps. None are fatal to the approach; all are fixable. Two are decisions.

---

## A ⇉ — §10.4 over-claims "partial-rollback prevention" that v1 does not have  [Critical: correctness-of-claim]
*Flagged by crypto-H5 AND crash-C2 independently.* When the Merkle tree was deferred (D4→
generation-counter), the §10.4 "Net v1 guarantee" line and test 5c were left saying v1 *prevents
partial rollback*. With `merkle_root = 0`, the manifest authenticates only its own generation
number — it does **not** bind data-block contents, so an attacker (without DEK) can pair the
current manifest with an older valid data-block set and nothing detects it. **ACCEPT — this is a
real self-contradiction I introduced.** Fix: §10.4 states plainly *v1 = whole-file rollback
**detection** via the generation anchor, NO partial-rollback protection*. Fix test 5c wording.
*(Fixed immediately — see spec.)*

## B ⇉ — WAL causes committed-data CORRUPTION via read-modify-write  [Critical]  → DECISION
*Flagged by crash-H1/H2 AND crypto-H1 (file_id reuse) AND plaintext-H2, from three angles.*
WAL frames are 24 B header + 4096 B page = 4120 B, and the WAL file has a 32 B header, so frame
boundaries **never** align to the 4096 B encryption grid. Every WAL append is therefore an RMW of
a physical block that often also holds the tail of an **already-committed** frame. A torn write
there (ordinary power loss) fails AEAD-open on a block containing committed data → committed data
is lost, not just the in-flight transaction. This **breaks the §9 claim** that "torn block → just
an uncommitted transaction." **ACCEPT — serious.** Three fixes exist: (a) pad every WAL frame to a
full encryption block (wasteful, complex); (b) per-frame AEAD for WAL (a second codec); (c)
**switch v1 to rollback-journal** (the spec's own D2/D6 escape hatch) — state lives only in the
main DB, which is whole-block, so the hazard largely vanishes.
**Adjudication → recommend (c), and it's a user decision (reverses D2=WAL).** Extra argument the
reviewers didn't note: we run **single-connection `locking_mode=EXCLUSIVE`**, so WAL's headline
benefit (concurrent readers during a write) *doesn't even apply here* — WAL's remaining upside is
mostly write-batching. So reversing to rollback-journal costs little in our config and removes a
Critical corruption class. **See "Decisions for the user" below.**

## C — Manifest is a single in-place block; one torn write bricks the DB  [Critical]
*crash-C3.* The manifest (the trust anchor for the whole DB) is re-sealed and rewritten in place
every commit. A torn 4 KB write on power loss → manifest fails AEAD-open → **entire DB unopenable**
though all data + the previous manifest were durable. **ACCEPT.** Fix: **ping-pong double-buffer
the manifest** (two slots A/B; write inactive slot, xSync, on open pick the higher-generation slot
that authenticates). Standard superblock/uberblock technique (ext4/ZFS). Reject only if *both*
slots fail.

## D ⇉ — `last_seen` freshness anchor can brick the DB after a normal crash  [Critical]
*crash-C1/M4 AND plaintext-H3/M4.* The manifest (inside the file) and `last_seen` (outside, in
IndexedDB/OPFS) are two non-atomic stores. If `record(last_seen=G+1)` ever lands before the
manifest write is durable, a crash leaves manifest=G, anchor=G+1 → open sees `db_generation <
last_seen` → **hard-refuses → permanent data loss from an ordinary power cut.** **ACCEPT.** Fixes:
(1) mandate strict ordering — `record()` only *after* the manifest xSync returns; (2) make open
**crash-tolerant**: treat `manifest_gen == last_seen − 1` (a lost final bump) as *recoverable*
(re-adopt the manifest), not a rollback; store the anchor as a window `{committed, in_flight}` so
open can distinguish "attacker rolled back 50 gens" from "crash lost the last +1"; (3) verify the
manifest *before* servicing any `xRead` of the main DB.

## E ⇉ — `DOMAIN` provenance undefined → cross-DB block substitution & chicken-egg  [Critical→High]
*crypto-C1/H4/H5 AND crash-L2 AND plaintext-L3.* §6 says `DOMAIN` is "a fixed 8-byte constant per
DB (or per DEK)" but never says where it comes from. If compile-time constant → all DBs under one
DEK share AAD space → block 0 of DB-A authenticates as block 0 of DB-B. If random-per-DB → it must
be stored to open the manifest, but the manifest AAD *uses* DOMAIN → circular. **ACCEPT.** Fix:
**derive a per-DB subkey** `K_db = HKDF(DEK, "vfs-db-v1" || db_uuid)`, `db_uuid` = random 128-bit
fixed at DB creation, stored in manifest plaintext and verified after open (a wrong-DB manifest
then fails to *decrypt*, not just fails an AAD tag). This also cleanly separates ATTACH-ed DBs
(Theme H) and rotation epochs.

## F ⇉ — Nonce safety rests entirely on RNG health; no fail-closed gate  [Critical→High]
*crypto-C2/C3 AND crash-H4 AND plaintext-M2.* XChaCha's whole security is the 192-bit **random**
nonce; RMW re-seals the same plaintext thousands of times, amplifying any RNG weakness. The spec
has no defense against `getRandomValues` throwing, returning zeros, or replaying after a
VM/tab-snapshot restore. **ACCEPT (the fail-closed gate).** Fix: at registration run an RNG
self-test (two draws distinct, not all-zero) and **fail closed**; every seal must hard-error
(`SQLITE_IOERR`, no write) if the RNG call fails — never fall back to a non-random nonce. Add
snapshot/fork to §3 as a nonce-reuse vector.
**REJECT the reviewers' deeper suggestions** (AES-GCM-SIV; synthetic HKDF-counter nonce): SIV's
deterministic nonce leaks *plaintext-equality* (which DB pages are identical — a lot of structural
leakage for a database), and a synthetic counter nonce needs a durably-persisted counter, which
reintroduces exactly the crash-rollback fragility we chose XChaCha to avoid. **Keep XChaCha20 +
fresh random nonce + fail-closed RNG gate.**

## G — "Encrypt every file" is asserted, not architecturally enforced (fail-OPEN risk)  [Critical]
*plaintext-C3.* We *adapt* a third-party sahpool VFS by "splicing" the block device in. If any
`xRead/xWrite/xTruncate/xShm*` on any file handle is left wired to the base path, that file is
silent plaintext — and the default failure mode of a *missed* method in a fork is plaintext
passthrough = **fail-open**, the opposite of the stated principle. **ACCEPT.** Fix: make it
**structural** — the encrypted VFS owns `xOpen` and returns `sqlite3_file` objects whose
`pMethods` is *exclusively* the encrypted io_methods; there is no reachable path from any handle
to a raw sync-access-handle write. Build-time assertion that base write methods are unreachable +
a negative test asserting zero plaintext for every file opened during a full workload.

## H — File inventory incomplete: ATTACH, super-journal, backup/VACUUM INTO  [Critical→High]
*plaintext-C1/C2/M3.* §7 lists only one connection's files. Unwalked: **ATTACH**-ed DBs (each
opens its own DB/-wal/-journal; the small-int `file_id` table has no slot for a *second* main DB →
`file_id=0` collision), the **super-journal** for multi-DB commits, and **VACUUM INTO / backup
API / .dump** targets. **ACCEPT.** Fixes: derive `file_id = HASH(canonical path)` (not a fixed
small-int table) so collisions can't happen; each ATTACH-ed DB gets its own manifest + `db_uuid`
subkey (Theme E); assert the super-journal flows through the block device (test it); require
backup/VACUUM-INTO targets to be encrypted-VFS paths; document `.dump` (text to app memory) as an
inherent app-boundary residual leak.

## I ⇉ — Enforce `B == page_size` exactly (not `≥`)  [High]
*crash-H3 AND plaintext-C4.* The "main-DB writes are always whole-block" claim (which the entire
§9 torn-write argument rests on) holds *only* if `B == page_size`. `PRAGMA page_size=`, VACUUM, or
an ATTACH/backup with a different page size breaks alignment → the hot main-DB path silently
becomes partial-block RMW that the code may not even implement → torn = unreadable committed page.
**ACCEPT.** Fix: enforce `B == page_size` *exactly* at open (read header, refuse mismatch),
**reject** runtime `page_size` changes and ATTACH of mismatched-page-size DBs. Revisit §9 wording.

## J ⇉ — Partial-final-block length is not authenticated → xFileSize/xTruncate corruption  [High]
*crash-M1 AND plaintext-H5/H4.* For WAL/journal a file's logical size isn't a multiple of B, so
the final block holds `j < B` plaintext bytes — but `j` is stored nowhere authenticated. Inferring
it from `physical % P` is ambiguous after a crash and lets `xFileSize` over-report → SQLite reads
junk-tail → silent corruption. **ACCEPT.** Fix: store the authenticated per-file logical length
(in the manifest, or encode `j` into the final block's plaintext/AAD); `xFileSize`/`xTruncate`
derive logical size from that, never from `physical/P*B` for non-whole-block files. Make truncate
reseal-then-truncate (atomic-ish) and fault-test crash *between* the two ops.

## K ⇉ — AEAD-open failure has no defined SQLite error mapping (+ tamper vs torn-WAL tension)  [Medium→High]
*plaintext-M1/H3 AND crypto/crash notes.* On wrong-key/tamper/torn, the block fails AEAD-open —
the spec never says what code is returned. If `SHORT_READ`, SQLite reads it as EOF/zeros
(data-loss/misdetect); if `IOERR`, differs from `CORRUPT`. And §9 *wants* a torn WAL record to
reach SQLite's checksum layer as "end-of-journal," which conflicts with "auth-fail → IOERR."
**ACCEPT.** Fix: main-DB auth failure → hard `SQLITE_IOERR` (never SHORT_READ, never zeros);
distinguish short-read (EOF) from auth-failure everywhere. *Note:* choosing rollback-journal
(Theme B) partly dissolves the torn-WAL half of this tension.

## L — Zeroize gaps: RMW scratch & AEAD-open output buffers  [Medium]
*crypto-M3 AND plaintext-L2.* §11 zeroizes the DEK + "scratch," but RMW decrypts a full block into
a buffer and `Aead::decrypt` returns a `Vec` whose freed heap isn't wiped. **ACCEPT.** Fix: use
`decrypt_in_place`/`encrypt_in_place` on a single reusable `Zeroizing` block buffer; never let
plaintext land in a dropped `Vec`.

## M — Cipher-agility footgun: swap silently breaks nonce-safety & layout  [High]
*crypto-H3/H2.* The generic-over-`aead::Aead` "one-type swap" to AES-GCM changes `Nn` 24→12 (so
`P` changes → old files misread) and silently reintroduces the 96-bit nonce-reuse story with no
odometer the compiler enforces. **ACCEPT.** Fix: bind `cipher_id` **and** `B` into *every block's*
AAD; refuse to open a file whose manifest `cipher_id` ≠ compiled cipher; assert `Nn ==
CIPHER.nonce_len` at registration; gate any GCM build behind a mandatory persisted-odometer type.
Make the swap *deliberate*, not one-line.

## N — shm memory-only must be structural, not assumed  [High]
*plaintext-H6 (spec's own `[Medium — verify]`).* "`-shm` stays in memory" rests on EXCLUSIVE
locking being honored and sahpool's `xShmMap` never falling back to a file. **ACCEPT.** Fix: the
VFS *pins* `locking_mode=EXCLUSIVE` and implements `xShmMap` to only ever return heap buffers
(never a file); test asserts no `-shm` ever appears in OPFS.

## O — `SQLITE_TEMP_STORE=3` is the sole guarantee; pragma is redundant  [Medium]
*plaintext-H1.* **ACCEPT (clarification).** State the compile flag is the guarantee (can't be
overridden by a wrong runtime pragma); forbid RBU/session extensions in v1 (their aux files may
not honor temp_store) or route them through the block device.

## P — Manifest bump must be exactly once per logical commit  [Medium]
*crash-M3.* SQLite calls xSync multiple times per commit; bumping/re-sealing the manifest on every
xSync multiplies the torn-manifest (C) and anchor-race (D) windows. **ACCEPT.** Fix: bump on
exactly the post-commit barrier (hook `SQLITE_FCNTL_COMMIT_PHASETWO` / the final sync), not
intra-commit syncs.

## Q — Log hygiene  [Low]
*plaintext-L1.* **ACCEPT.** No decrypted plaintext, nonce, or key bytes in any error string/log.

## M2 durability caveat — OPFS `flush()` true-durability is browser-dependent  [Medium, inherited]
*crash-M2.* Not our bug to fix, but load-bearing: verify empirically per target browser that
`FileSystemSyncAccessHandle.flush()` reaches storage; ensure no VFS write-back cache holds data
past xSync (flush internal buffers to the handle first). **ACCEPT as a verification task.**

---

## Confirmed SOUND by all reviewers (the core survived)
- Synchronous pure-Rust AEAD is mandatory (SubtleCrypto is async) — §0.1. ✓
- VFS-I/O-layer placement over pager codec for framing-agnostic whole-file coverage — §0.2. ✓
- XChaCha20-Poly1305 + fresh random 192-bit nonce, no counter → no crash-induced nonce reuse
  (conditional on the RNG gate, Theme F) — §5/§8. ✓ *(strongest decision in the design)*
- AAD `file_id || block_index` defeats cross-block/cross-file relocation *within a
  correctly-assigned id space* (Themes E/H fix the id space) — §6. ✓
- Offset-translation bulk math `k*P`, `P=B+Nn+16` — correct except the trailing-partial-block
  case (Theme J) — §4/§12. ✓
- DEK in `Zeroizing`, never persisted; re-wrap≠re-encrypt; rotation via write-new-then-swap — §11. ✓
- Rollback threat scoping (only matters vs an attacker *without* the DEK) — logically sound — §10. ✓
- `crossOriginIsolated===false` success signal consistent with sync-OPFS/no-SAB — §1. ✓

## Verdict
**Approach validated; spec is v1.0 and needs a v1.1 revision pass before code.** No finding
invalidates "build our own encrypting VFS"; they harden it. Effort concentrated in: manifest
durability (C), the freshness-anchor state machine (D), per-DB key derivation (E), the RNG gate
(F), structural fail-closed coverage (G/H), and `B==page_size` + partial-length authentication
(I/J). Most are mechanical once decided.

## Decisions for the user
- **DEC-1 (Theme B): journal mode.** Reviewers converge on **rollback-journal for v1** to kill the
  WAL committed-data-corruption class; and since we're single-connection, WAL's main benefit
  doesn't apply here. *Recommend: reverse D2 → rollback-journal for v1, revisit WAL post-v1 with
  frame-aligned encryption.*
- **DEC-2 (Theme A):** already fixed (over-claim corrected) — no input needed, just noting it.
Everything else (C–Q) I can fold into a spec v1.1 revision without a decision.
