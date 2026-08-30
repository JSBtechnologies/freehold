# freehold — build notes & honest §17 ledger

**What this is.** Milestones 1+2+3 of the header-free encrypting VFS from
`topics/header-free-encrypted-vfs/design-spec.md` (v1.1). It forks `sqlite-wasm-vfs` 0.2.0's
`sahpool` VFS and splices an XChaCha20-Poly1305 **encrypted block device** in at the `VfsFile`
(`xRead`/`xWrite`) boundary; **M2 adds the anti-rollback manifest, per-DB subkeys, and the §17
hardening; M3 adds crash/fault-injection, the size-math property test, and the perf baseline**.
Per CLAUDE.md "no silent gaps", this file states **exactly** which design-spec items are
implemented now vs deferred — so nobody over-trusts the prototype.

## Files
- `src/crypto.rs` — the trusted crypto core (seal/open, AAD, HKDF subkey domains, RNG gate). Meant to be read in full.
- `src/manifest.rs` — manifest + TrustedGeneration-anchor payload formats (§10/§17.C/D/E/J). New in M2.
- `src/vfs.rs` — forked sahpool; the substantive changes vs upstream are `SyncAccessFile`'s `VfsFile` impl (the block device) and the M2 pool machinery (manifest/anchor/xOpen/xSync hooks). Every change tagged `// ENC:`.
- `src/lib.rs` — wasm entry `run_tests()` + the §14 test cases M1+M2 cover.
- `index.html` / `worker.js` / `package.json` — Vite + dedicated-worker rig.

## On-disk format (post-security-review; NOT readable by/from pre-review M2 images — fail closed)
```
sahpool physical file = [ 4096-byte sahpool header (filename+flags, PLAINTEXT) | DATA REGION ]
DATA REGION           = sequence of physical blocks, each P = 4136 bytes:
physical block k      = [ ciphertext (4096) | nonce (24) | tag (16) ]
AAD (45 bytes)        = file_id(16) || key_domain(16) || block_index_LE(8) || B_LE(4) || cipher_id(1)
  * file_id   = SHA-256(path)[..16]   (widened 8→16, security-review L1)
  * key_domain = owning DB's db_uuid  (zeros for pool/temp; security-review M1/3d — redundant
                 cross-DB bind on top of key separation, so a transplanted block fails the AAD too)

per-DB block key      = K_db = HKDF-SHA256(DEK, "freehold/vfs-db-v1\0" ‖ db_uuid)  (§17.E)
pool-domain key       = HKDF(DEK, "freehold-v1")        (files with no owning DB, e.g. temp)
anchor key            = HKDF(DEK, "freehold-anchor-v1")

manifest (pool file "<db>#manifest", SQLite never opens it):
  [ magic "ENCMFST1"(8) | db_uuid(16) | pad(40) | slot0 (P bytes) | slot1 (P bytes) ]
  slot = seal(K_db, payload, key_domain=db_uuid, aad-fid=manifest_file_id, block_index=slot_index),
  ping-pong by db_generation % 2 (§17.C). payload = { version, cipher_id, B, db_generation, db_uuid,
  merkle_root (reserved 0), per-file authenticated lengths (§17.J) }.

anchor ("anchor.bin" beside .opaque/): DOUBLE-BUFFERED (security-review C2) — two sealed blocks
  (slot 0 @ 0, slot 1 @ P), ping-pong by a monotonic seq; load picks the highest-seq slot that
  authenticates, so a torn anchor write leaves the prior slot intact. Each slot holds
  { seq, [ (db_uuid, committed, in_flight) ... ] }.
```

## Design-spec §17 ledger

### IN (implemented & exercised live in-browser)
- **§5 / §8** XChaCha20-Poly1305, audited RustCrypto used as-is; fresh CSPRNG nonce per seal.
- **§4** offset-translating encrypted block device (whole-block + read-modify-write).
- **§6 / §17.L** AAD binds position (file_id, block_index) **and** framing (B, cipher_id); the
  manifest's cipher_id/B are verified at decode (a mismatched cipher or block size refuses to open).
- **§10 / §17.C — double-buffered manifest + `db_generation`.** Bumped once per main-DB xSync
  (≈ once per commit); written to the ping-pong slot, flushed durable, then the anchor records it.
  **Torn-slot recovery verified live:** corrupting the active slot recovers via the other slot (one
  generation behind, tolerated per §17.D), DB not bricked.
- **§10.4 / §17.D — TrustedGeneration anchor + state machine.** Sealed `{committed, in_flight}`
  window per db_uuid in `anchor.bin`; ordering data-xSync → manifest slot → xSync → record.
  Open rejects `manifest_gen + 1 < committed` as **ROLLBACK**; exactly-one-behind is recoverable.
  **Whole-file rollback detection verified live** (restored old image+manifest → open refused,
  traced to the anchor check: "manifest gen 3 < trusted 5").
- **§17.E — per-DB `db_uuid`-salted subkey.** Every main DB (incl. ATTACH-ed) gets a random 128-bit
  uuid at creation; all its blocks + satellites sealed with K_db. A wrong DEK now fails at
  **manifest decrypt** during open — verified live (wrong-key open rejected before any SQL).
- **§17.F** RNG fail-closed: `rng_selftest()` at registration; every seal errors on RNG failure or
  an all-zero nonce; `db_uuid` generation fails closed too.
- **§17.H (partial) — file inventory.** `file_id = SHA256(name)[..8]` for every file; **ATTACH-ed
  DBs get their own db_uuid + manifest** (verified live); journals/WAL bind to the owner's K_db at
  xOpen. Super-journal (multi-DB txn) and VACUUM-INTO paths still untested — see DEFERRED.
- **§17.I — `B == page_size` enforced.** Two layers, both verified live: (a) at open, block 0 is
  decrypted and a header page_size ≠ 4096 refuses to open; (b) at write, a main-DB header write
  declaring page_size ≠ B is refused (`SQLITE_IOERR`) — this fired for real: **this
  `sqlite-wasm-rs` build's default page_size is 8192**, so any DB not pinned with
  `PRAGMA page_size=4096` is refused at creation (the harness pins it, incl. per-ATTACH).
- **§17.J (main DB full; satellites partial) — authenticated lengths.** The manifest stores per-file
  logical lengths; at open the main DB's length must equal its whole-block physical size (catches
  physical truncation AEAD can't see) and is applied authoritatively. `xTruncate` is
  reseal-then-truncate (trimmed tail re-sealed zeroed). Satellite lengths apply only when consistent
  with the physical layout — a stale journal length falls back to the physical estimate + SQLite's
  record checksums (honest residual).
- **§17.K** AEAD auth failure → `SQLITE_IOERR`, never a short read; genuine past-EOF → short read.
  Verified live by the tamper (flip one byte) and relocation (copy block 0 over block 1) tests.
- **§17.M** in-place seal/open on caller buffers; plaintext scratch, DEK, and derived keys in
  `Zeroizing`.
- **§17.G (partial, structural)** the VFS owns `xOpen`; every handle's `pMethods` is the encrypted
  io_methods; raw `phys_*` writers private. The §14.6 audit now sweeps **every pool file** (main,
  manifests, ATTACH-ed) for plaintext after a full workload — clean.
- **§7 / D2** rollback-journal enforced; `-journal` encrypted by the same block device; no
  `-wal`/`-shm` ever appears (asserted).
- **§14.8 — crash/fault injection (M3).** A dev-harness fault injector drops all persistence after
  the Nth operation ("power loss here"); the sweep crashes a commit at **every** persist-op
  boundary (n=1..18), discards the connection on the dead disk, drops all caches, reopens.
  **Result: every reopen succeeds; the count is always exactly pre- or post-transaction (11
  rollbacks, 7 commits in the sweep); zero corruption, zero bricks.** Two recovery rules were
  added to make this hold (found by analysis before the sweep confirmed them):
  (a) **hot-journal deferral** — with a nonzero rollback journal present, the strict §17.I/§17.J
  open-checks (length equality, block-0 decrypt) are deferred to post-replay state, since a
  mid-commit crash legitimately leaves the main file grown or block 0 torn and SQLite's replay
  (whose pre-images are AEAD-protected) restores it; (b) **journal-reset barrier** — deleting or
  truncating-to-zero the journal is the real commit/rollback finalization in rollback-journal
  mode, so it refreshes the manifest; a crash between manifest-write and journal-delete can no
  longer leave a manifest describing a state that replay rolled back.
- **§14.9 — size-math property test (M3).** 400 random SQLite-shaped ops (append/overwrite writes,
  shrink-only truncates, reads incl. past-EOF) against a shadow byte-array model: all read-backs,
  zero-fills, and `size()` round-trips exact.
- **§14.11 — perf baseline (M3, release build, Chrome).** AEAD micro: **363 MB/s ≈ 10.8 µs per
  4 KiB block** (spec §13 predicted single-digit µs / hundreds of MB/s — met). 500-row batched
  txn: 17 ms. Full scan of 532 rows: <1 ms. Single-row commits: **16.9 ms/commit** — dominated by
  OPFS `flush()` count (journal + main + manifest + anchor ≈ 7–9 flushes/commit), not by crypto;
  known optimization target (coalesce anchor writes / skip redundant journal-reset refresh).
  Deliberately **no null-cipher "plaintext baseline" build** — that would create the exact
  unencrypted-write code path §17.G exists to forbid; the AEAD micro + flush accounting bound the
  encryption overhead instead (crypto is noise next to flush latency).

### DEFERRED (NOT in M2 — do not assume these guarantees yet)
- **Whole-consistent-snapshot rollback is DETECTED-BY-BACKSTOP only (§10.4).** The anchor is a
  raised-bar local backstop: an attacker who can rewrite all of OPFS can also delete `anchor.bin`
  (a missing/unreadable anchor is treated as fresh, or the DB never opens — either way no silent
  acceptance of *known-old* state, but a wiped anchor + old image is indistinguishable from a first
  run). The strong anchor is the sync epoch — lands with the sync milestone. Also, **exactly one
  generation of rollback is tolerated by design** (§17.D crash recovery).
- **Partial/surgical rollback (full-state Merkle root) — NOW IMPLEMENTED** (freehold-vfs-merkle-root
  D-MR1..D-MR5). The manifest's reserved `merkle_root` (bytes 32..64) now holds a full-state root =
  SHA-256 hash-of-hashes over the main DB's plaintext blocks (index-ordered; `crypto::FullStateRoot`).
  It is recomputed + sealed on every commit and verified at open; a mismatch REFUSES the DB
  ("PARTIAL ROLLBACK DETECTED"), closing the reserved-0 gap above. Hash choice: SHA-256 (reused from
  the existing `sha2` dep — a hash, not a cipher; no new crypto primitive). Boundaries:
  - **Legacy zero-root (D-MR2):** an all-zero root = pre-Merkle image → verification skipped and a
    real root is sealed on the next commit; additionally, a durable zero-root DB self-populates a
    root on its first writable, journal-free open (F2 migration) so it does not stay unverified.
  - **Hot-journal handling — F1-a CLOSED via D-MR6 (commit-barrier fix + VFS-owned replay).**
    - **"Hot" = valid decrypted journal magic** (matches SQLite's own test), NOT nonzero size (under
      EXCLUSIVE mode a finalized journal persists with a zeroed header). A journal that fails AEAD
      (forged/planted-foreign) is not hot → the on-disk root check runs immediately.
    - **Commit barrier moved to TRUE commit (D-MR6).** The generation bump + manifest seal fired at
      BOTH main-DB xSync AND journal finalization; the xSync firing sealed a synced-but-not-yet-
      committed state, so the manifest could run *several generations ahead* of a hot journal's
      rollback target (no bounded root reference could then verify a legit replay — the earlier
      blocker). Now the barrier fires ONLY at journal finalization, which in this VFS is: xDelete of
      `<db>-journal`, xTruncate-to-0, OR (the common EXCLUSIVE-mode case) a **header-zeroing write**
      to journal offset 0 that clears the magic. The seal happens BEFORE the finalizing op becomes
      durable, so a committed image is never left with a manifest ≥2 behind. The sealed root now
      advances **once per commit** and always describes a durably-committed state.
    - **VFS-owned rollback-journal replay at open.** With a hot journal present the VFS parses the
      AEAD-authenticated journal (header magic/nRec/nonce/initPages/sector/pageSize; per-record
      `pgno|data|cksum` with SQLite's exact sparse checksum `cksum=nonce; i=pageSize-200; while i>0
      {cksum+=data[i]; i-=200}`, stopping on the first bad checksum = SQLite's SQLITE_DONE
      torn-final-record rule), applies pre-images to a shadow of the current image, truncates to
      initPages, and requires the shadow's root ∈ {`merkle_root`, `prev_merkle_root`} BEFORE serving
      any page. This verifies the EXACT image SQLite will serve, provenance-independent, so
      re-planting a hot journal before every open cannot suppress it.
    - **Bounded ±1 via `prev_merkle_root`** (reserved manifest bytes 4064..4096, backward-compatible,
      zero in pre-D-MR6 manifests). Each seal writes prev = the prior commit's root, absorbing the ONE
      irreducible journal-vs-manifest atomicity instant (crash after the manifest is sealed N+1 but
      before the journal delete becomes durable — the still-hot journal rolls back to R_N = prev).
    - **Guarantee:** a rollback of depth **≥2** (to a root older than prev) matches NEITHER accepted
      root → REFUSED on EVERY open, cross- AND same-generation, re-plant-proof (regression MK(d):
      depth-≥2 re-planted before 4 consecutive opens → refused every time, never stale). Never
      laundered (recovery does not re-seal below the sealed root). **Residual = the irreducible
      1-commit floor:** a rollback of depth EXACTLY 1 to the genuine immediately-previous committed
      state matches `prev_merkle_root` and MAY pass — this is fundamental (two separate durable
      objects cannot be updated atomically) and is the accepted boundary. Nothing deeper is accepted.
    - **Anchor + sync-epoch under once-per-commit (D-MR6 item 4).** Generation now advances ~half as
      fast, so a 1-commit whole-file rollback sits inside the anchor's ±1 crash slack. To keep
      PEER-attested freshness strict, `AnchorEntry` gained a `epoch_floor` (anchor magic bumped
      `ENCANCH1`→`ENCANCH2`; old anchors decode as absent = fresh, the existing safe fallback).
      `apply_epoch` raises it; the open path refuses `db_generation < epoch_floor` with NO ±1 slack
      (an external attestation has no local crash gap). The local self-commit `committed` keeps its
      ±1 slack. Verified by SE (sync-epoch) + sync-e2e.
    - **Crash-sweep: 0 corrupt/bricked** after the barrier change (13 rolled back, 5 committed). Full
      crash-window analysis in `topics/freehold-vfs-merkle-root/D-MR6-commit-barrier-design.md`.
    - **Review-round-3 hardening (D-MR6.1):**
      - *Single finalization barrier, no double-fire (#3):* the three finalization hooks (header-zero
        xWrite, xDelete, xTruncate-to-0) route through one `journal_finalize_barrier` that seals only
        when the journal is genuinely HOT. Deleting an already-finalized journal at connection close is
        a no-op → generation advances **exactly once per commit** (MK6(e): 3 commits ⇒ +3, not ~6).
      - *No silent skip (#2):* if a hot journal's owner DB is not open at a finalization write, the
        barrier hard-errors (SQLITE_IOERR) instead of silently skipping the seal (the old bogus
        `pool_key([0;32])` path is gone).
      - *Anchor AAD binding (H1):* the anchor now seals via `seal_bytes`/`open_bytes` with an AAD that
        binds the anchor format magic + slot (`anchor_aad`), so an old-format (ENCANCH1) or
        slot-swapped blob FAILS AUTHENTICATION. A peer `epoch_floor` is written to **both** double-
        buffer slots, so a single-slot tamper cannot drop it (MK6(g.1): single-slot tamper after an
        epoch → stale REFUSED). **Residual (§10.4, unchanged):** a full two-slot wipe / same-version
        lower-seq replay still falls back to "fresh" — the local anchor is a deletable backstop; the
        un-wipeable strong anchor is the online sync epoch (MK6(g.2) asserts this boundary explicitly).
      - *Multi-record / multi-header journal replay (#4):* verified against SQLite `pager.c` — within a
        segment, page records are packed CONTIGUOUSLY at stride `pageSize+8` (first record at the
        sector-padded header end); a SECOND sector-aligned header appears only on a pager-cache spill
        (large txn) or savepoint. `replay_journal_root` now LOOPS over header segments (round up to the
        next sector, require the magic, else stop = SQLITE_DONE). MK6(h): a 1500-row baseline + a large
        crashed UPDATE (≥2 journal records) replays to the EXACT baseline (root matches, reopens clean).
        Honest note: the test reliably exercises the MULTI-RECORD path; a guaranteed multi-HEADER
        (cache-spill) journal is hard to force deterministically in-harness, so that branch is defensive
        + format-cited rather than positively hit every run.
      - *Overflow/OOM guards:* manifest `decode` caps the file-count `n` before `n*stride` (wasm32
        usize overflow / `Vec::with_capacity` OOM, M-2); `replay_journal_root` bounds `pgno` before
        `shadow.resize` (attacker pgno near u32::MAX → OOM, L1).
  - **WAL out of scope (F3):** WAL frames are outside the root's scope; `SQLITE_OPEN_WAL` is REFUSED
    for a tracked DB (the VFS mandates journal=DELETE anyway).
  - **Perf:** root recompute is O(blocks) per open (~one AEAD-decrypt + SHA-256 leaf per block).
    Negligible for small DBs; for very large DBs a persisted Merkle *tree* with incremental update is
    the future optimization. Measured commit latency unchanged (~6 ms/commit on the CI machine).
  - **Consumer:** `full_state_root()` is exposed on the pool/util for block-delta (D-BD9) to use as a
    base fingerprint + result check.
- **§17.D precise commit hook.** Generation bumps on every main-DB xSync, not on
  `SQLITE_FCNTL_COMMIT_PHASETWO`; extra intra-op syncs (e.g. VACUUM) burn generations harmlessly
  (monotonic), but the "exactly once per logical commit" refinement is future work.
- **§17.H (rest):** super-journal (multi-DB atomic commit), VACUUM INTO / backup-API targets,
  `PRAGMA journal_mode` changes mid-life. Untested paths — treat as unsupported.
- **§17.N/O:** `-shm` stays off via rollback-journal + EXCLUSIVE (io_methods have no xShm* at all,
  so WAL mode cannot even be enabled — structural in effect); `SQLITE_TEMP_STORE=3` compile flag
  still not asserted (runtime `temp_store=MEMORY` only).
- **Security review** — the only remaining gate before design-spec status `implemented`.
- **Commit-latency optimization** — 16.9 ms/commit is flush-bound (see §14.11 above); acceptable
  for interactive use, but the anchor's two writes per barrier and the double barrier
  (xSync + journal-reset) are coalescable.
- **Filename plaintext residual.** The sahpool header stores filenames in plaintext (upstream
  behavior); manifest headers store `db_uuid` in plaintext (random, non-identifying). DB *contents*
  are fully encrypted.
- **M1→M2 migration:** none. A pre-M2 (manifest-less) non-empty DB refuses to open (fail closed).

## Security review (2026-08-28) — 3 adversarial agents, all findings resolved
Full adjudication: `topics/header-free-encrypted-vfs/security-review.md`. Crypto core judged
**sound** by all three; the crash-consistency and leak reviewers found real CRITICAL/HIGH bugs in
the surrounding machinery, now **fixed + regression-tested**:
- **CRITICAL** create-order brick + torn manifest-header brick + silent anchor-orphan/cap →
  reordered (manifest durable before anchor), torn-header recovery on empty DBs, explicit anchor cap.
  (Regression **test E**.)
- **CRITICAL** single-buffered anchor silently nullified rollback on a torn write → **double-buffered
  anchor**. (Regression **test D**.)
- **HIGH** deleted `import_db*` (raw-plaintext writer bypassing the block device — §17.G violation).
- **MEDIUM** bound `db_uuid` into block AAD (`key_domain`); feature-gated the test/attacker API;
  `checked_*` offset math; honest super-journal comment.
- **LOW** widened `file_id` to 16 B; hardened RNG self-test (3 draws + non-zero floor); doc fixes.
Accepted boundaries (documented, not defects): ±1-generation rollback tolerance (offline-fundamental;
sync epoch is the strong fix), `in_flight` reserved, RustCrypto key-schedule not zeroized (§11 non-goal).

## M2+M3 guarantee (stated plainly)
Everything M1 gave (confidentiality + tamper + relocation resistance, fail-closed, RNG-gated), plus:
**whole-file rollback detection** via the anchored generation counter (one-generation crash
tolerance; local backstop only until sync lands), **per-DB key separation** (wrong key/wrong DB
fails at manifest decrypt), **page-size enforcement**, **authenticated main-DB length**, a
**crash-safe double-buffered manifest**, and now **empirically demonstrated crash consistency**
(power loss at every persist boundary → pre- or post-txn state, never corrupt, never bricked).
Still NO partial-rollback protection. The one remaining gate: **security review**.

## Verified live (2026-08-28, Chrome, Vite, dedicated worker, release build; post-security-review)
All §14 M2+M3 checks pass, plus the two new torn-write regressions: round-trip,
wrong-key-rejected-at-manifest, byte-flip tamper → IOERR, cross-block relocation → IOERR, whole-file
rollback → refused (anchor), torn manifest **slot** → recovered, **(D) torn anchor slot + rollback →
still refused (double-buffer held)**, **(E) torn manifest header on empty DB → recreated, not
bricked**, ATTACH own-manifest + audit, page_size 8192 → refused, crash sweep n=1..18 clean (11
rollbacks / 7 commits / 0 corrupt), size-math property test exact, full-pool ciphertext audit clean,
no -wal/-shm, `crossOriginIsolated === false`. Perf (release): AEAD 381 MB/s (10.2 µs/block),
16.6 ms/single-commit (flush-bound), 500-row batched txn 18 ms.

Note: SQLite surfaces our detailed VFS error strings only through `xGetLastError`; `sqlite3_errmsg`
after a failed open shows the generic "unable to open database file". The rollback path was
positively confirmed via a temporary trace during verification.

## Build
```
# LLVM on PATH (see memory rust-wasm-toolchain-setup)
$env:PATH = "C:\Program Files\LLVM\bin;$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
wasm-pack build --target web --dev
npm install   # first time
npm run dev    # open the printed localhost URL; the worker runs run_tests()
```
Quirk: this `sqlite-wasm-rs` build's **default page_size is 8192** — every DB (including ATTACH-ed
ones) must be pinned to 4096 via PRAGMA before first write, or §17.I refuses it (by design).
Quirk: `wasm-opt` (binaryen) crashes on this module on Windows (0xc0000409) — disabled via
`[package.metadata.wasm-pack.profile.release] wasm-opt = false`; rustc `-O` provides the
optimization that matters (dev build AEAD: 13 MB/s → release: 363 MB/s). Use `--release` for any
perf measurement.
