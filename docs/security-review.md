---
slug: header-free-encrypted-vfs
artifact: security-review
version: 1.0
status: complete
created: 2026-08-28
parent: header-free-encrypted-vfs/design-spec.md
reviews: prototype/epochdb (Milestones 1–3)
method: 3 independent adversarial red-team agents (crypto-construction / crash-consistency / leak+memory-safety)
---

# Security review — epochdb encrypting VFS (M1–M3)

Three independent red-team agents attacked the built prototype (not the spec), each told to
**disprove** the guarantees. This document adjudicates every finding: what was confirmed, what was
already handled in code the agent couldn't see, what was rejected, and how each real issue was
fixed + regression-tested. All fixes are landed and verified in-browser (release build); the full
§14 suite plus two new torn-write regressions pass.

## Verdict
**Crypto core: sound** (all three reviewers agree — AEAD wiring, 192-bit random nonce, HKDF domain
separation, AAD position/framing binding, per-DB subkey verification are correct). The
crash-consistency and leak reviewers each found **real CRITICAL/HIGH bugs in the surrounding
machinery** — now fixed. Post-fix, the prototype is judged ready for the design-spec `implemented`
status. The known-and-documented boundaries (one-generation rollback tolerance; local-only anchor
until sync; no partial-rollback/Merkle) remain as scoped, not as review failures.

## What each reviewer attacked
- **Crypto construction** (`crypto.rs`, `manifest.rs`): AEAD API, nonce/RNG gate, AAD binding,
  HKDF, manifest `db_uuid`, `file_id` truncation.
- **Crash consistency & anti-rollback** (`vfs.rs` manifest/anchor state machine): §17.D ordering,
  double-buffering, the M3 recovery fixes, ±1 tolerance, RefCell re-entrancy, fault-model fidelity.
- **Leak & memory safety** (`vfs.rs`, `lib.rs`): structural fail-closed (§17.G), file inventory,
  §17.K mapping, zeroize, unsafe/FFI, offset arithmetic.

---

## Findings & resolutions

### CRITICAL — fixed
- **C1 (crash 1a/1b/2) — create-order brick + anchor-orphan accumulation.** `create_manifest`
  wrote the anchor's `in_flight` *before* the manifest existed; a crash there orphaned an anchor
  entry, and `encode_anchor` silently capped at 127 → anti-rollback silently disabled. A torn
  plaintext manifest **header** write on a brand-new DB bricked it (magic check fails → both slots
  skipped). **Fix:** reordered so the manifest (header + slot) is written and flushed durable
  BEFORE any anchor write (no orphan possible); added a **torn-header recovery path** — if the
  manifest fails to authenticate AND the main DB has no durable data, discard and recreate rather
  than brick (real data present ⇒ still refuse, fail closed); made the anchor table bound explicit
  (errors loudly at `ANCHOR_CAP`, never silently drops a live DB). **Regression: test E** (torn
  manifest header on empty DB → recovered, not bricked).
- **C2 (crash 6) — single-buffered anchor silently nullified rollback protection.** The manifest
  was double-buffered against torn writes but the anchor was one in-place block; a torn anchor
  write made `anchor_load` return empty → the rollback check was skipped (worse than a brick).
  **Fix:** double-buffered the anchor (two slots, ping-pong by a monotonic `seq`, load picks the
  highest-`seq` slot that authenticates; the file is pre-sized to both slots). **Regression:
  test D** (corrupt the active anchor slot + restore an old snapshot → rollback STILL rejected).

### HIGH — fixed
- **H1 (leak 1.1) — `import_db_unchecked` wrote raw plaintext into the data region**, bypassing the
  block device — a §17.G structural-fail-closed violation, one public wrapper from a leak. **Fix:**
  **deleted** `import_db`/`import_db_unchecked` (dead code; the block device has no raw-import path).

### MEDIUM — fixed
- **M1 (crypto 3d) — block AAD didn't bind the DB identity.** Cross-DB isolation rested solely on
  key separation. **Fix:** bound the owning DB's `db_uuid` into every block's AAD as `key_domain`
  (zeros for pool/temp), so cross-DB transplant fails at the AAD layer even under a hypothetical
  `K_db` collision. (Threaded through the whole block device + manifest/anchor seals.)
- **M2 (leak 1.2) — test/attacker-simulation API was ungated.** `import_raw` (bypasses AEAD),
  fault injector, raw export, proptest were `pub` on the production type. **Fix:** gated behind a
  default-on `testing-api` Cargo feature; a production consumer builds `--no-default-features` and
  the raw/fault surface vanishes at compile time.
- **M3 (leak 5.5) — unchecked `offset+len` / `k*P` on wasm32.** **Fix:** `checked_add`/`checked_mul`
  → `SQLITE_IOERR` on overflow in the block-device read/write paths.
- **M4 (leak 2.2) — `SUPER_JOURNAL` appeared covered but `bind_satellite` is a no-op for it.**
  **Fix:** explicit comment that multi-DB atomic commit is DEFERRED (§17.H) and a super-journal is
  encrypted under the pool key, not a per-DB `K_db` — no misleading coverage.

### LOW — fixed / hardened
- **L1 (crypto 6) — 64-bit `file_id`.** Widened to **16 bytes** (2⁻¹²⁸ collision).
- **L2 (crypto 2b) — RNG self-test accepted distinct-but-biased draws.** Hardened to 3 draws,
  pairwise-distinct, each with a minimum non-zero-byte population floor.
- **L3 (leak 1.3) — `xSync` called the commit barrier for every file.** Added an explicit
  `SQLITE_OPEN_MAIN_DB` flag gate (was already safe via the `dbs` lookup; now also structural).
- **L4 (crypto 4b, leak 2.1) — docs.** Documented HKDF salt=None rationale, and the `install`
  caller invariant that temp files fall back to the pool-domain key unless kept in memory.

### Confirmed already-correct in code the reviewer couldn't see
- **payload/header `db_uuid` cross-check (crypto 5b):** `read_manifest` derives `K_db` from the
  header uuid and rejects any slot whose decrypted `db_uuid` disagrees.
- **anchor AAD (crypto 7):** the anchor was already sealed with a dedicated `file_id` + block index
  (now also NO_DOMAIN key_domain).
- **§17.K AEAD-fail → IOERR at every call site** (leak 3.1/3.2); **offset/slice math in-bounds for
  all valid inputs** (leak 5.6/6.1); **FFI pointer/borrow patterns safe** under the pause guard
  (leak 5.1–5.4); **no reachable double-borrow** (crash 3).

### Accepted / documented boundaries (not defects)
- **±1 generation tolerance (crash 5)** — permits exactly one committed transaction to be rolled
  back undetected. This is the fundamental offline trade-off (collapsing it to 0 reintroduces a
  torn-slot brick risk). Surfaced at the API boundary; the strong fix is the external sync epoch.
- **`in_flight` anchor field (crash 9)** — recorded but not yet consulted by the open check; kept
  as reserved telemetry for the future sync-epoch anchor. Documented.
- **Fault model coarseness (crash 10)** — the injector drops whole writes, not torn intra-block
  writes; this is why the M3 sweep passed while C1/C2 existed. Addressed by the two new
  attacker-simulation regressions (D, E) that reproduce torn manifest-header and torn-anchor writes
  directly. A fuller byte-level torn-write generator remains a future test improvement.
- **RustCrypto key-schedule not zeroized (leak 4.8)** — library limitation; the DEK and all derived
  key *bytes* are `Zeroizing`; consistent with §11's stated live-memory non-goal.

## On-disk format bump
These fixes change the AAD (wider `file_id` + `key_domain`) and the anchor layout, so the format is
**not compatible with the pre-review M2 image** — acceptable pre-release (no migration; a stale
image fails closed). Bumped in BUILD-NOTES.

## Residual follow-ups (tracked, not blocking `implemented`)
- Partial/surgical rollback (Merkle-over-tags) — deferred by design (D4).
- Super-journal / VACUUM-INTO per-DB coverage (§17.H rest).
- Byte-level torn-write fuzz generator; `SQLITE_TEMP_STORE=3` compile-flag assertion.
