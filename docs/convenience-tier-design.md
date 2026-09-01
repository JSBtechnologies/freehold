---
slug: freehold-convenience-tier
artifact: convenience-tier-design
version: 0.1
status: DRAFT 2026-09-01 — design-before-code. Records the security-tier ladder + the device-key
  convenience slot (decisions D-CV1..6); awaiting sign-off before code. Not yet implemented.
created: 2026-09-01
kind: security-design
depends-on: envelope v3 (N-KEK slots, passkey slot = HKDF(prf,"freehold-kek-v1"); shipped). Implementable
  SDK-only — no change to the Rust crypto/envelope core.
---

# Freehold — convenience tier (device-key unlock)

> Freehold's default is the hardened tier: the DEK is never persisted, unwrapped only via a WebAuthn
> passkey (user-present, UV) inside the worker. That's right for secrets, but heavy for a to-do list.
> This adds an **opt-in convenience tier** so the same engine drops into everyday, non-critical apps
> with **zero-friction auto-unlock** — without weakening the hardened tier or inventing new crypto.

## 1. The security ladder
One vault, a spectrum of unlock methods (they can coexist as slots in the same N-KEK envelope):

| Tier | KEK material | User gesture | Key at rest? | For |
|---|---|---|---|---|
| **Passkey** (default) | WebAuthn PRF, held in the authenticator | biometric / UV | **no** | secrets, the custody model |
| **Recovery code** | Argon2id over a code the user holds | type the code | only if the user stores it | backup / device-independent |
| **Device key** (new) | a 32-byte secret held on-device, wrapped at rest by a non-extractable WebCrypto key | **none** | yes — device-bound, JS-non-extractable | everyday / non-critical apps |

The app picks its tier at enroll; **default stays hardened**. Convenience is always an explicit choice.

## 2. Honest boundary (state it loudly)
Convenience mode is **not** "no key at rest" — that's the whole point of it being a separate tier. What
it is: a key that is **device-bound and non-extractable-by-JS**, usable **without a user gesture**. So:
- A same-origin script (XSS, a poisoned dependency) running **while the device key exists** can auto-
  unlock — there is no user-presence check to stop it. This is strictly weaker than the passkey tier.
- What it still buys over the naive "stash a key in localStorage": the secret cannot be **read out and
  carried elsewhere** (the wrapping key is non-extractable), and it is **bound to this device** (never
  in the envelope or a bundle). A storage dump / backup / cross-origin read yields wrapped bytes + an
  opaque key handle, not a portable key.

> **DECISION D-CV1: convenience mode is opt-in, never default, and always labeled.** `listMethods()`
> surfaces the slot as `kind:'device'` so the UI can show "this vault auto-unlocks on this device."
> The hardened tier's guarantees are unchanged for vaults that don't enroll a device key.

## 3. The mechanism — reuse the passkey slot, no core change
A passkey slot is `KEK = HKDF(prf_output, "freehold-kek-v1")`. Nothing requires `prf_output` to come
from WebAuthn — it just needs to be a 32-byte secret the worker can feed the same derivation. So a
**device slot is a passkey-style slot keyed by a locally-generated 32-byte secret `S`.**

> **DECISION D-CV2: `S` is treated exactly as a PRF output.** Enroll a device slot with the existing
> passkey-slot path (`enroll(S)` for a fresh vault, or `add_passkey(existing, S, envelope)` to add one),
> and unlock with `session_open(S, envelope, epoch)`. The Rust envelope/crypto core is **unchanged** —
> this is entirely an SDK addition. `S` is passed as a transferable buffer (detached → zeroized on the
> main thread) exactly like a PRF today.

### 3.1 `S` at rest — wrapped under a non-extractable device key
`S` is **never stored in the clear.** At enroll:
1. `S = crypto.getRandomValues(32)`.
2. `deviceKey = crypto.subtle.generateKey({name:'AES-GCM',length:256}, /*extractable*/ false, ['encrypt','decrypt'])` — a **non-extractable** CryptoKey.
3. `wrappedS = AES-GCM(deviceKey, iv, S)`.
4. Store `{ deviceKey, wrappedS, iv }` in IndexedDB (the CryptoKey by reference — its bytes never enter JS).
5. Enroll the envelope slot with `S`, then zeroize `S`.

Auto-unlock (no prompt):
1. Read `{deviceKey, wrappedS, iv}` from IDB.
2. `S = AES-GCM.decrypt(deviceKey, iv, wrappedS)` → a transferable buffer.
3. `session_open(S, envelope, epoch)`; zeroize `S`.

> **DECISION D-CV3: the wrapping key is a non-extractable WebCrypto key in IndexedDB.** Reading storage
> yields wrapped bytes + an opaque handle, not `S`. The key can be *used* (decrypt) only by script on
> this origin — that is the accepted convenience bargain (see §2). Fallback when a browser can't persist
> a non-extractable CryptoKey (older Safari): degrade to a clearly-labeled weaker sub-tier (raw `S` in
> IDB) or refuse convenience mode — never silently. `S` in the clear is the floor, and it must say so.

## 4. Durability & recovery
A device key dies with the device (storage clear, new device, eviction). So:

> **DECISION D-CV4: convenience enroll also mints a recovery code by default.** Otherwise a storage
> wipe = data loss with no way back. The app may show it once (mandatory-backup contract) or, for
> truly throwaway data, opt out explicitly. Reuses `needsBackup()` / the existing backup gate.

## 5. Interactions
- **Bundles / sync:** the device slot is device-local. It travels in the envelope as an ordinary slot,
  but no other device holds `deviceKey`, so it is **dead weight elsewhere** (unopenable). 
  > **DECISION D-CV5: strip the device slot on `exportBundle()`** (export the passkey/recovery slots
  > only) — a bundle is portable custody; a device-bound convenience key has no meaning off-device.
- **DEK rotation:** rotation orphans absent methods. A device slot present at the ceremony is re-
  established (the SDK re-wraps a fresh `S'` under a fresh device key); absent = orphaned like any slot.
- **Mixed vaults:** passkey + device slots can coexist — one device auto-unlocks, others require the
  passkey. Useful and free (they're just slots), but the UI must make the device's weaker posture clear.
- **Labeling:** a `kind:'device'` byte in the slot is a small **optional** Rust nicety for honest
  `listMethods()`; until then the SDK infers "device" from the presence of the wrapped-`S` record.
  > **DECISION D-CV6: ship SDK-only first (device slot masquerades as a passkey slot cryptographically);
  > add the `device` slot-kind label to the envelope later** if we want it enforced in the core.

## 6. Build order (SDK-only)
1. **Design sign-off** (this note) — it changes the at-rest posture, so it gets the same gate as the
   other crypto work.
2. `packages/db`: `enrollConvenience({ backup })`, device-key generate/wrap/store, auto-`unlock()` path
   when a device record exists, `exportBundle()` device-slot stripping (D-CV5), `listMethods()` device
   inference. A `mode` on the vault so the UI reflects the tier.
3. E2E: convenience enroll → reload → **auto-unlocks with no gesture** → data intact; bundle excludes
   the device slot; a passkey still unlocks the same vault.
4. (Optional, later) Rust `device` slot-kind label (D-CV6).

## 7. What this unlocks (product)
The same engine now spans: **convenience** (zero-friction, everyday local encrypted SQLite, no backend)
→ **passkey** (no key at rest, the custody model) → hardened builds (`--no-default-features`). One
opt-in flag moves an app along the ladder; nothing about the hardened tier changes for apps that don't
ask for convenience.

## Cross-links
[[data-custody-protocol]] (the custody model this convenience tier sits under), [[dek-rotation-design]]
(rotation re-establishes/orphans the device slot), [[audit-readiness]] (trust status + limits), Freehold
DB design-spec (envelope v3, the passkey-slot derivation `S` reuses).
