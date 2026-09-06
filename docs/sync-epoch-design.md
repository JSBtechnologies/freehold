---
slug: header-free-encrypted-vfs
artifact: sync-epoch-design
version: 0.1
status: VERIFIED end-to-end on real hardware 2026-08-28 — rollback PREVENTION confirmed live across two devices
created: 2026-08-28
parent: header-free-encrypted-vfs/design-spec.md §10.4
kind: security-critical-design
depends-on-finding: cross-device passkey-PRF unlock CONFIRMED (Chrome+Google, Win→Mac, localhost, 2026-08-28)
---

# Sync-epoch anchor

> Upgrades the VFS's rollback **detection** (M2 local anchor) into rollback **prevention that can't
> propagate**, using the peer channel we just proved works. Builds directly on
> [[encrypted-local-first-sync]] and the M2 `TrustedGeneration` anchor (design-spec §10.4).

## 1. The problem it closes
M2/M3 ship a **local** `anchor.bin` recording max `db_generation` per `db_uuid`. It is a raised-bar
*backstop*: an attacker who can rewrite all of OPFS can also wipe/rewrite the anchor, so offline
rollback is only *detected*, not *prevented* — plus a deliberate ±1-generation tolerance for crash
recovery. The design-spec named the fix (§10.4): record the epoch **somewhere the local attacker
cannot roll back**. Until now that "somewhere" was hypothetical. **It is no longer** — the proven
cross-device channel is the user's *other device*.

## 2. Guarantee (what it does and does NOT buy) — stated honestly up front
- **Buys:** a rolled-back device is **caught the moment it syncs with any other device** that holds a
  fresher epoch, and its stale state **cannot propagate** (the peer refuses to accept it). Whole-
  consistent-snapshot rollback — undetectable locally in M2 — becomes detectable-and-rejected at the
  sync boundary. Supersedes the ±1 tolerance *once a device has synced at least once*.
- **Does NOT buy:** a **fully isolated device that never syncs** still cannot detect its own offline
  rollback — there is no external reference to check against. This is information-theoretically
  fundamental, not an implementation gap. The value is that isolation is the *only* remaining hole,
  and any sync closes it.

## 2.1 Trust-boundary clarifications (read before trusting the guarantee)

Two things the words above are easy to over-read. Both are properties of the model, not bugs.

**Server-blind ≠ sync-provider-trusted — confidentiality is guaranteed, availability and freshness
are not.** A sync provider (or relay, or malicious peer) *never* sees a key and *cannot* decrypt
your data — that is unconditional. It can still, however, **withhold your writes, serve you a stale
version, or partition you from your other devices.** The epoch machinery makes such staleness
**detectable and non-propagating** at the sync boundary (a peer refuses to accept an epoch older
than one it has seen) — but it cannot *force* a dishonest provider to deliver your latest state or
stay reachable. In one line: **Freehold protects confidentiality from the sync path
unconditionally; availability and freshness are *detectable* but depend on the provider's
honesty.** If you need a liveness guarantee, run a provider you control, or sync device-to-device.

**A compromised device is inside the trust boundary until the DEK is rotated.** The epoch's
forge-resistance is stated as "an attacker *without the DEK* cannot forge one" — the flip side is
that any device that *holds* the DEK (i.e. one you unlocked, then had compromised) **can mint valid
epochs**, exactly like every other device of yours, until it is evicted. Eviction is **not** just
`removeMethod()` (that only drops one KEK slot; the DEK is unchanged and the compromised host may
already hold it, a captured older envelope is now refused locally by the v3 generation floor, but the DEK is
unchanged — see the envelope-rollback note in [[header-free-encrypted-vfs/design-spec]] §11).
**True revocation of a compromised device requires DEK rotation + re-encryption** (design-spec §11 /
§361). Until that lands as a wired operation
(currently designed, not built — tracked as issue #4), treat "revoke a method" as *reducing unlock
surface*, **not** as containing a device that already saw the key. "Next sync catches it" catches
rolled-back *state*, never a *leaked key*.

## 3. Trust model — DECISION D-SE1
**Recommend: peer-to-peer among the user's OWN devices, server-blind. No trusted server in v1.**
Rationale: it matches the whole thesis and the just-proven result (devices sync directly, no server
sees anything). A server, if ever added, is just one more peer that happens to be always-on — the
protocol shouldn't require it. *(Open for sign-off; strong recommendation.)*

## 4. Epoch representation — DECISION D-SE2
**Recommend: reuse the DEK; no per-device asymmetric keys in v1.** All of a user's devices already
share the DEK (via the passkey envelope), so an epoch token can be **AEAD-authenticated** under a
DEK-derived key — any of the user's devices can mint and verify it, an attacker without the DEK
cannot forge one.

```
K_epoch  = HKDF(DEK, "freehold-epoch-v1")
epoch token (per db_uuid) = seal(K_epoch, nonce, plaintext = {
    db_uuid   : 16,
    generation: u64,     // the db_generation this device last committed
    device_id : 16,      // random per-install id (distinguishes this device's line)
    stamp     : u64,     // monotonic-ish wall clock, tiebreak only (not security-load-bearing)
}, aad = "freehold-epoch" || db_uuid)
```
*(v2/multi-USER would need real per-device signing keys — a device shouldn't be able to forge another
user's epoch. Out of scope for single-user v1; noted so we don't design it away.)*

## 5. Exchange & enforcement — DECISION D-SE3
**Recommend: carry the epoch in the export/import bundle** (extend the bundle we already built and
proved). The bundle becomes the sync channel; no new transport needed for v1.

Each device keeps, in its local anchor, the **max epoch it has ever seen per db_uuid** (its own
commits + every peer epoch it has imported). Rules:
- **On export:** attach this device's current epoch token for the db.
- **On import / sync:** verify the incoming epoch (AEAD). Let `incoming.generation` vs the local
  `seen_max` for that db_uuid:
  - `incoming >= seen_max` → accept; record `seen_max = incoming`.
  - `incoming <  seen_max` → **REJECT: rollback attempt** — this bundle is staler than a state we've
    already witnessed. (This is the prevention: stale state can't enter a device that knows better.)
- **On open (local):** unchanged M2 check against the local anchor, but the local anchor's `seen_max`
  is now also fed by peers — so a wiped-then-rolled-back local device that later imports/opens against
  a peer-fed anchor is caught.

**Honest note on the wipe-both problem:** if the attacker wipes the local anchor too, a *single*
device has no memory. The epoch only bites when a *second* store remembers — i.e. another device.
That's the design: freshness lives in the union of the user's devices, not in any one of them.

## 6. First buildable increment (proposed)
1. `K_epoch` + epoch-token seal/open in `crypto.rs`/a small `epoch.rs`.
2. Extend `export_bundle` to append the epoch token; extend `import_bundle` to verify + enforce the
   §5 rule (reject stale), and fold peer epochs into the local anchor's `seen_max`.
3. Test (single browser, two "devices" = two pool dirs): export gen N from A → simulate an attacker
   rolling A back to gen N−2 → try to import A's stale bundle into B (which has seen N) → **rejected**;
   and the reverse (fresh accepted, `seen_max` advances).
4. Demo: surface "this bundle is older than what this device has seen — refusing" in `passkey.html`.

## 7. Decisions to confirm before code
- **D-SE1** peer-to-peer server-blind v1 (recommended). 
- **D-SE2** DEK-derived AEAD epoch, no asymmetric device keys in v1 (recommended).
- **D-SE3** epoch carried in the bundle, reject-stale-on-import (recommended).
Everything else follows. On sign-off, build §6.

## Build status (2026-08-28)
Stakeholder signed off D-SE1/2/3. **First increment implemented** in `prototype/freehold`
(compiles clean, dev + release):
- `crypto.rs`: `epoch_key(DEK)` + general `seal_bytes`/`open_bytes` (small-payload AEAD).
- `vfs.rs`: per-install `device_id`; `export_epoch(db)` → sealed `{db_uuid, generation, device_id}`;
  `apply_epoch(token)` → verify under K_epoch, raise the local anchor `committed` high-water mark.
  Enforcement rides the EXISTING open-path check (`manifest_gen + 1 < committed` → reject) — the
  epoch just raises `committed` from peer attestation, so almost all the logic is already-verified code.
- `lib.rs`: `sync_epoch_test()` — 3 pool dirs = 3 "devices": A commits to a high gen + exports a
  stale image and a late epoch; **B applies A's epoch then is fed only the stale image → open must be
  REJECTED** (B never saw the fresh state, so the peer epoch is the sole cause); **contrast device C
  imports the same stale image with NO epoch → opens** (proves the epoch is what prevents it).
- **VERIFIED in-browser 2026-08-28:** `SE.` line green — "A commits to gen 6 and attests epoch=6;
  B (never saw the fresh state) applies the peer epoch then is fed the STALE image → open REJECTED;
  contrast device with NO epoch opens the same stale image → the peer epoch is exactly what prevents
  the rollback ✅". Mechanism proven. All M2/M3/crash/audit checks still pass on the same build.

**Scope (updated 2026-08-28):** the epoch *mechanism* is proven via the 3-pool automated test
(`SE.` green). **Bundle/demo wiring DONE + pushed** (`JSBtechnologies/freehold` @ f39ff64,
release wasm): `export_db` appends a `#epoch|<hex>` line (mints the token — needs the passkey);
`import_db_image` returns the peer epoch (page stores it); `unlock`/`unlock_recovery` apply it before
open; the `Add data (new version)` button advances the generation to create a v1/v2 pair.

**⭐ CONFIRMED ON REAL HARDWARE 2026-08-28.** Live two-device test passed: Windows+Chrome →
Mac+Chrome (Google Password Manager synced passkey, localhost). Device B imported v2 and unlocked;
re-importing the STALE v1 → **unlock REFUSED**. Rollback *prevention* (not just detection) verified
end-to-end across two physical machines on the server-blind channel. `[High]` — this closes the
security review's residual (local-only anchor / ±1 window) with a real-hardware data point. Honest
boundary unchanged: a fully-isolated never-syncing device still can't detect its own offline
rollback (information-theoretic). The recovery path also carries/enforces the epoch.

## Cross-links
[[encrypted-local-first-sync]] (owns the sync channel + the multi-user/group future),
[[header-free-encrypted-vfs]] design-spec §10.4 (the deferred strong anchor this fulfils),
[[passkey-prf-unlock]] (the proven cross-device channel this rides on).
