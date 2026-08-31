---
slug: header-free-encrypted-vfs
artifact: dek-rotation-design
version: 0.1
status: SIGNED OFF 2026-08-31 — D-RK1 (orphan + re-enroll) confirmed by stakeholder; D-RK2..4 stand as recommended. Building.
created: 2026-08-31
parent: header-free-encrypted-vfs/design-spec.md §11 / §361
kind: security-critical-design
depends-on: envelope v3 (issue #3, shipped) — env_generation + DEK-keyed MAC + SDK floor
---

# DEK rotation + re-encryption — design (v0.1, design-before-code)

> Turns "revoke a method" (drop one KEK slot; DEK unchanged) into **true eviction of a device that
> already saw the key**, by rotating the DEK and re-encrypting every block under it. This is the
> operation the sync-epoch doc's §2.1 calls out as *designed, not built* — the reason "revoke ≠
> contain" today. Builds on envelope v3 ([[header-free-encrypted-vfs/design-spec]] §11) and the
> per-DB subkey `K_db = HKDF(DEK, "vfs-db-v1"‖db_uuid)` (crypto.rs).

## 1. The problem it closes
`removeMethod()` deletes one slot's wrap of the DEK. The DEK itself is unchanged, so a device that
unlocked once and was then compromised **still holds the DEK** and can read/mint/decrypt everything —
dropping its slot only stops *future* unlocks by that passkey, it does not contain the leak. The
design-spec named the fix (§11): rotate the DEK (DEK→DEK′), re-encrypt the database under it, and
issue a new envelope that wraps DEK′ **only** under the methods you still trust. After that, the old
DEK opens nothing that survives.

## 2. Guarantee (what it does and does NOT buy) — honestly up front
- **Buys:** after rotation completes, the pre-rotation DEK is cryptographically useless against the
  post-rotation database — every block, the manifest/anchor, the sync-id and the epoch key are all
  re-derived from DEK′. A device evicted at rotation cannot read new state, cannot mint a valid new
  epoch, and its passkey no longer wraps the live DEK.
- **Does NOT buy:** it does not un-leak what the compromised device *already exfiltrated* before
  rotation (that plaintext is gone), and it does not reach copies of the *old* encrypted image the
  attacker kept — those still open under the old DEK the attacker holds. Rotation protects **future
  state**, and forces the attacker off the live database. This is the standard limit of key rotation
  and must be stated in the demo/README.

## 3. The core constraint — why "re-wrap every slot under DEK′" is impossible AND wrong (D-RK1)

Each slot wraps the DEK under a KEK derived from that method's *secret material*:
- passkey slot: `KEK = HKDF(prf_output)` — `prf_output` only exists during a live WebAuthn assertion
  **on that authenticator**. It never leaves the device; the envelope never stores it.
- recovery slot: `KEK = Argon2id(recovery_code, env_salt)` — derivable from the code **alone**, no
  device.

At a rotation ceremony you hold exactly ONE method's material (the one the user just authenticated
with), plus optionally a recovery code the user types. You therefore **cannot** re-wrap DEK′ into a
*foreign* passkey slot — you don't have its PRF output, and by design you never can from another
device.

Crucially, this is not merely hard — **re-wrapping foreign slots would defeat the purpose.** The
whole point of rotation is to evict a device. If you could re-wrap DEK′ under every prior KEK, you
would re-admit the compromised device's passkey (its KEK would wrap DEK′ too). You cannot
cryptographically tell "re-wrap for good device B" apart from "re-wrap for compromised device X"
without B or X physically present. So:

> **DECISION D-RK1 (recommend): rotation deliberately ORPHANS every method not present at the
> ceremony.** The new envelope is built fresh (new `env_salt`, generation continues climbing) and
> contains DEK′ wrapped ONLY under (a) the method the user authenticated the rotation with, and
> (b) a freshly generated recovery code minted during the ceremony (so the user is never left
> single-homed on one device). Every other passkey/older recovery code is dead.

Re-admitting a trusted-but-absent device B is then a **re-enrollment**, not a re-wrap: on B, the user
unlocks with the new recovery code (device-independent by construction), obtaining DEK′, then
`addPasskey()` adds B's passkey slot the normal way. The recovery code is the bridge that makes
"rotate on A, keep using B" possible without ever moving PRF material between devices.

This keeps the property that made the envelope strong (KEK material never leaves its authenticator)
and makes eviction *mean* something.

## 4. Re-encryption mechanics (D-RK2)

`db_uuid` is the DB's identity and does **not** change; only the DEK changes, so `K_db` changes but
every block's plaintext, `file_id`, `key_domain` (= db_uuid) and `block_index` are identical.
Re-encryption of one block is therefore exactly:

```
plain = open_into(K_db_old, file_id, uuid, blk, sealed_old)   // existing VFS read path
sealed_new = seal_into(K_db_new, file_id, uuid, blk, plain)   // existing VFS write path
```

No format change, no layout change — same grid, new key. The same applies to pool/temp files
(`pool_key`) and the anchor (`anchor_key`), all re-derived from DEK′.

> **DECISION D-RK2 (recommend): never re-encrypt in place. Build a complete SHADOW image, sealed
> under DEK′, then commit by atomic swap.** In-place re-encryption is unrecoverable on a mid-way
> crash (some blocks under DEK, some under DEK′, no key opens the whole file). The SAHPool already
> has a name→file indirection; the shadow is a second set of pool files. Order:
> 1. Allocate shadow pool files. For every block of every live DB file: `open(DEK)`→`seal(DEK′)`
>    into the shadow. Recompute the manifest/anchor + full-state Merkle root under DEK′ for the
>    shadow (reuses the existing D-MR root machinery).
> 2. `flush()` the shadow durably.
> 3. Only now build the new envelope (§5) and reach the commit barrier (§6).
>
> A crash before the barrier leaves the shadow as unreferenced garbage (GC'd on next open); the live
> image + old envelope are untouched and open normally. Rotation simply "didn't happen".

This lands on the crash-safety-critical path, so it needs the same class of fault-injection tests as
the existing §17.C/D journal and D-MR Merkle sections in `run_tests` (crash after each numbered step
→ open must yield exactly one consistent {old} or {new} state, never a mixed/torn one).

## 5. Envelope handling under rotation (D-RK3)

The new envelope is not a `rebuild()` of the old one (that would re-MAC old slots under DEK′ but keep
their old KEK wraps, which still wrap the *old* DEK — nonsense). It is a **fresh `create_envelope`
under DEK′** with the presenting passkey, then `add_recovery_slot` for the freshly minted code. New
`env_salt`; generation is carried forward as `old_generation + 1` (monotonic across the rotation, so
the SDK floor still refuses any pre-rotation envelope). Because DEK′ is fresh, the old envelope's MAC
key no longer verifies the new envelope and vice-versa — the two are cryptographically disjoint,
which is the point.

> **DECISION D-RK3 (recommend): a new wasm entry point `rotate_dek` performs the whole ceremony
> atomically in the worker** — takes the presenting method's material + the current envelope, opens
> to get DEK, generates DEK′ and a recovery code, drives the §4 shadow re-seal, emits `(new_envelope,
> new_recovery_code)`, and returns them to the SDK only after the VFS commit barrier (§6) has swapped
> the image. The DEK/DEK′ never leave the worker; the recovery code is returned once for the user to
> record (same one-time-display contract as enroll).

## 6. The commit barrier — spanning two stores (D-RK4)

The image lives in OPFS (pool files); the envelope lives in IndexedDB (SDK, `idbSet('envelope')`).
There is no cross-store transaction, so we need a recoverable linearization point. Observation: the
**shadow image only decrypts under DEK′, the live image only under DEK**, and DEK′ lives *only* in
the new envelope. So **which envelope is authoritative decides which image is readable** — the
envelope swap is the natural commit point.

Protocol (crash-safe by construction):
1. Write a rotation-intent record in OPFS alongside the shadow: `{db_uuid, old_gen, new_gen,
   shadow_ref}` (sealed under DEK′ so it's self-authenticating and tamper-evident).
2. **Commit = the single `idbSet('envelope', new_envelope)` + `env_floor := new_gen`.** This is the
   linearization point (one IDB put is atomic).
3. Post-commit: swap shadow→live in the pool (or flip the name indirection), delete the old image,
   clear the intent record.

Recovery on next `open()`:
- **No intent record** → normal open.
- **Intent record present, envelope generation == new_gen** (commit happened) → roll FORWARD: finish
  the pool swap / GC the old image if step 3 was interrupted.
- **Intent record present, envelope generation == old_gen** (crash before commit) → roll BACK:
  discard the shadow + intent, keep the live image. Rotation is retried by the user.

The old image is retained until step 3 completes, so either outcome is a fully consistent state. The
SDK gains a `rotateKey()` that calls `rotate_dek`, persists the returned envelope, bumps the floor,
surfaces the new recovery code through the same mandatory-backup UI as enroll, and (if sync is on)
mints a fresh epoch under DEK′ so peers adopt the rotated line.

> **DECISION D-RK4 (recommend): the IndexedDB envelope put is the commit barrier; the OPFS
> intent-record + generation comparison drives roll-forward/back on open.** No new durable store,
> no two-phase commit protocol invented — it rides the existing anchor/generation machinery.

## 7. Interaction with sync / epochs (#3c) and multi-device
After rotation, DEK′ implies a new `K_epoch = HKDF(DEK′, "freehold-epoch-v1")` and a new `sync_id`.
A peer still on the old DEK cannot verify the new epoch — which is correct: an evicted device is
*supposed* to fall off the line. Trusted devices re-join by re-enrolling (§3) which gives them DEK′
and hence the new epoch key. This is clean **only once #3c binds env_generation into the epoch**; the
two issues should land in that order (envelope-rollback prevention first, then rotation rides it).
Multi-*user* signing keys (#7) are unaffected — still out of v1 scope.

## 8. Decisions to confirm before code
- **D-RK1** rotation orphans absent methods; re-admit = re-enroll via the new recovery code. *(the
  load-bearing one — it defines the UX and the security meaning of "evict".)*
- **D-RK2** shadow re-seal + atomic swap; never in place.
- **D-RK3** fresh envelope under DEK′ via a worker-side `rotate_dek`; DEK′ never leaves the worker.
- **D-RK4** IndexedDB envelope put = commit barrier; OPFS intent record drives crash recovery.

On sign-off: build in the order (a) `rotate_dek` + shadow re-seal in vfs.rs/lib.rs with
fault-injection tests in `run_tests`, (b) SDK `rotateKey()` + open-path recovery, (c) demo
"revoke + rotate" flow, (d) an E2E spec (rotate on A → old envelope refused, new recovery opens,
second passkey re-enrolls).

## Build status (2026-08-31)
- **Increment 1a DONE:** `envelope::rotate_envelope` (the D-RK1/D-RK3 envelope half) + a private
  `set_generation` re-MAC helper. Proven by `run_tests` **M3c** (pinned in `merkle-root.spec.js`):
  a rotation yields a fresh envelope whose DEK′ ≠ the old DEK, is opened by the surviving passkey and
  the newly minted recovery code, **refuses** the orphaned old recovery code and the revoked passkey,
  carries the generation strictly forward (pre-rotation envelope refused by the new floor), and leaves
  the old envelope still yielding the old DEK (the two are cryptographically disjoint). No VFS/SDK
  wiring yet — this is the envelope contract in isolation. All 3 E2E specs stay green.
- **Increment 1b DONE:** physical DB re-encryption (§4) as a pool→pool re-seal —
  `OpfsSAHPoolUtil::reseal_db(db_name, new_dek)` (vfs.rs, `reseal_db_ciphertext`): re-keys a CLOSED
  DB's main file (uniform block grid) + manifest (plaintext header + 2 sealed slots) by pure per-block
  `open(db_key(DEK,uuid))→seal(db_key(DEK′,uuid))` — same `db_uuid`, same plaintext, no recompute.
  Proven by `run_tests` **RK** (pinned in `merkle-root.spec.js`): a DB written under DEK, re-keyed to
  dek′, imported into a pool built with dek′, opens and reads back intact; the SAME re-sealed image
  under the OLD DEK recovers nothing (the eviction property). The pool-global anchor is NOT carried
  (destination establishes a fresh one; carrying the generation floor is increment-2 work). This is a
  proof-only primitive (`#[cfg(feature = "testing-api")]`) — it graduates to a wired ceremony next.
- **Increment 2a DONE:** the crash-safe worker ceremony core. `rotate_dek(prf)` (lib.rs, worker op)
  authorizes with the presenting passkey, mints DEK′ + a fresh envelope (`rotate_envelope`, orphaning
  absent methods — D-RK1), closes handles, and **stages** the OPFS half crash-safely (D-RK2/D-RK4):
  `OpfsSAHPoolUtil::stage_rotation` re-seals every DB to shadow files (`~rot` suffix, via the 1b
  `reseal_db_ciphertext` — now production, no `testing-api` gate) and writes a `__rotate_intent__`
  record sealed under DEK′; the live image + old envelope are untouched, so a pre-commit crash is a
  no-op. `recover_rotation` (called in `session_begin` before anything opens) reconciles on the next
  unlock against the just-installed DEK: the intent opens under DEK′ ⇒ roll FORWARD (live := shadow,
  GC staging); it does not ⇒ roll BACK (discard staging, keep live). DEK/DEK′ never leave the worker
  (D-RK3); only the new envelope + one-time recovery code cross back. The IndexedDB `idbSet('envelope')`
  remains THE commit barrier — it is the SDK step in 2b. New `rotate_intent_key` subkey (crypto.rs)
  gives the intent its own AEAD domain. Proven by `run_tests` **RK2** (pinned in `merkle-root.spec.js`),
  which models the barrier by which DEK re-opens the same storage: staging never mutates the live
  image; a crash BEFORE commit rolls BACK (old DEK reads old data, staging GC'd); a crash AFTER rolls
  FORWARD (new DEK reads the data) and is idempotent; the rolled-forward DB no longer opens under the
  OLD DEK (eviction, end to end). `rotate_dek` added to the vault-worker OPS allowlist. All 3 E2E green.
  NOTE (deferred, safe): the pool-global anchor is NOT carried across rotation — the new-DEK pool reads
  the old-DEK anchor as "fresh" and re-seeds the rollback floor from the (plaintext-preserved) manifest
  generation on first open. Safe because the DEK′ line begins at rotation, so no older DEK′ image can
  exist to roll back to; an explicit anchor re-seal can be added if a stricter local floor is wanted.
- **Increment 2b NEXT:** SDK `rotateKey()` — assert the surviving passkey, call `rotate_dek`,
  `idbSet('envelope', new_env)` (THE barrier) + `#bumpFloor` + `idbDel('epoch')` (old epoch is stale
  under DEK′), surface the recovery code through the mandatory-backup UI, then re-`unlock()` (which
  rolls the shadow forward). Then 2c demo "revoke + rotate" flow and 2d an E2E (§8 order (b)-(d)).

## Cross-links
[[header-free-encrypted-vfs]] design-spec §11 (the named-but-unbuilt rotation this fulfils),
[[sync-epoch-design]] §2.1 (why revoke ≠ contain today; this closes it), envelope v3 (issue #3, the
generation/MAC this rotation carries forward).
