---
slug: freehold-convenience-tier
artifact: convenience-tier-design
version: 0.2
status: PARTIAL 2026-09-01 — §1–7 (SDK-only tier) SHIPPED (enrollConvenience/isConvenience/auto-unlock,
  ca2495b). §8 adds the concrete D-CV5 (export strip) + D-CV6 (device slot-kind label) design — a small,
  DEK-gated core change; design-before-code, awaiting sign-off.
created: 2026-09-01
kind: security-design
depends-on: envelope v3 (N-KEK slots, passkey slot = HKDF(prf,"freehold-kek-v1"); shipped). §1–7 are
  SDK-only; §8 (D-CV5/D-CV6) touches the Rust envelope core (a new slot kind + a strip helper).
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
  > **Concrete design in §8.**
- **DEK rotation:** rotation orphans absent methods. A device slot present at the ceremony is re-
  established (the SDK re-wraps a fresh `S'` under a fresh device key); absent = orphaned like any slot.
- **Mixed vaults:** passkey + device slots can coexist — one device auto-unlocks, others require the
  passkey. Useful and free (they're just slots), but the UI must make the device's weaker posture clear.
- **Labeling:** a `kind:'device'` byte in the slot is a small **optional** Rust nicety for honest
  `listMethods()`; until then the SDK infers "device" from the presence of the wrapped-`S` record.
  > **DECISION D-CV6: ship SDK-only first (device slot masquerades as a passkey slot cryptographically);
  > add the `device` slot-kind label to the envelope later** if we want it enforced in the core.
  > SDK-only shipped (ca2495b). **§8 now specifies the core label** — required so D-CV5 can *find* the
  > device slot to strip without guessing.

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

## 8. D-CV5 + D-CV6 implementation design (2026-09-01)
The SDK-only tier (§1–7) shipped with the device slot wearing `KIND_PASSKEY` — it *masquerades* as a
passkey slot. That was fine to prove the mechanism, but it leaves two honesty gaps: `listMethods()` calls
a device slot "passkey" (D-CV6), and `exportBundle()` can't tell which slot to strip (D-CV5). Both are
closed by one small, **DEK-gated** core change. D-CV6 lands first because D-CV5 depends on it (you can't
strip what you can't identify).

### 8.1 Why this is low-risk (the load-bearing facts)
- **Relabeling does not touch the decrypt path.** `open_with_kek` reads each slot's *own* `kind` byte and
  feeds it into `slot_aad(kek_id, kind)` (envelope.rs:465–476). A device-kind slot therefore opens with
  the **unchanged** `open_with_prf(S)` derivation — the KEK is still `HKDF(S,"freehold-kek-v1")`; only the
  authenticated `kind` byte differs. No new KEK derivation, no new AEAD path.
- **Stripping is hygiene, not a security boundary.** Every envelope mutation (`remove_slot`, `rebuild`,
  `finalize`) re-MACs under the DEK (envelope.rs:224, 351–359). An attacker who could forge a stripped
  envelope would already hold the DEK — i.e. have won. So stripping cannot *create* a downgrade; it only
  keeps a device-bound, off-device-useless slot out of a portable bundle.
- **The DEK stays encapsulated in the worker.** Stripping needs the DEK to re-MAC, and the SDK never holds
  the DEK. So the strip runs inside `session_export_inner` (lib.rs:2836) via a pool method — the exact
  pattern `export_epoch` already uses to mint a DEK-authenticated token without exposing the key to JS.

### 8.2 D-CV6 — the `device` slot kind (core)
- **envelope.rs:** add `pub const KIND_DEVICE: u8 = 2;` (0 passkey, 1 recovery, 2 device — envelope.rs:64).
  Add `pub fn create_device_envelope(dek, secret) -> Result<Vec<u8>>` mirroring `create_envelope` but
  wrapping slot 0 as `wrap_slot(dek, &kek_from_prf(secret), 0, KIND_DEVICE)`. (The only difference from a
  passkey enroll is the `kind` byte; KEK derivation is identical.)
- **lib.rs:** new `#[wasm_bindgen] pub fn enroll_device(secret: &[u8]) -> Result<Vec<u8>, JsValue>`
  mirroring `enroll`. And extend `list_methods` (lib.rs:2432) to map `KIND_DEVICE → "device"`,
  `KIND_RECOVERY → "recovery"`, else `"passkey"`.
- **SDK (packages/db):** `enrollConvenience` calls `enroll_device` instead of `enroll` for slot 0 (the
  recovery add is unchanged). `listMethods()` and `index.d.ts` document `kind: 'passkey'|'recovery'|'device'`.
- **Unlock is untouched:** the convenience unlock path still calls `session_open(S, …)`; the device-kind
  slot opens because AAD carries the slot's own kind.

### 8.3 D-CV5 — strip the device slot on export (core + worker)
- **envelope.rs:** add `pub fn strip_kind(blob, dek, kind) -> Result<Vec<u8>, EnvelopeError>`: drop every
  slot whose `kind == kind`, re-MAC under `dek`, and **error (`Format`) if it would leave zero slots**.
  Factor `rebuild` into `rebuild_gen(blob, dek, keep, count, gen)` so the existing add/remove paths pass
  `read_generation+1` (unchanged) and `strip_kind` passes `read_generation` **unbumped** (§8.4).
- **vfs.rs pool:** `pub fn strip_export_envelope(&self, envelope: &[u8]) -> Result<Vec<u8>>` that reads the
  installed DEK internally and calls `envelope::strip_kind(envelope, dek, KIND_DEVICE)` — DEK never leaves
  the pool (mirror `export_epoch`).
- **lib.rs `session_export_inner`:** before `bundle::encode(envelope, …)` (lib.rs:2872), replace `envelope`
  with `s.util.strip_export_envelope(envelope)?`. Read the attested `env_gen` from the **stripped** blob
  (same number — §8.4) so the epoch stays internally consistent. A device-only vault (no passkey/recovery)
  makes `strip_kind` error; surface it verbatim: *"this vault has only a device key — add a passkey or
  recovery code before exporting."* With `backup:true` (the D-CV4 default) a recovery slot always survives.

### 8.4 Decision — stripping does NOT bump the generation
> **DECISION D-CV7: `strip_kind` re-MACs but preserves `env_generation`.** Rationale: (1) re-MAC is
> mandatory regardless (fewer slots ⇒ different body); (2) no *authorization state* relevant to other
> devices changed — you're withholding a device-local slot, not revoking a method; (3) an attacker can't
> forge a strip anyway (needs the DEK); (4) it keeps the epoch's attested `env_gen` equal to the source
> vault's. The two same-generation bodies (local, with the device slot; exported, without) never conflict:
> the freshness floor compares generation *numbers* per device, and neither device ever holds both bodies
> at the same generation in a way that matters. Bumping would instead jump the importing device's floor
> and force the epoch to attest a generation no persisted envelope actually has.

### 8.5 Rotation interaction (scope guard)
`rotate_envelope` rebuilds via `create_envelope` (passkey kind) from the surviving PRF. For a convenience
vault that surviving secret is `S`, so a rotation today would relabel the device slot back to
`KIND_PASSKEY`. Convenience rotation is **not** wired in the SDK (rotation is a hardened-tier op), so this
is out of scope here — but flagged: if convenience rotation is ever added, its re-establishment step must
use `create_device_envelope`, not `create_envelope`.

### 8.6 Tests
- **In-wasm `run_tests` (new CV-strip case):** `enroll_device(S)` → `list_methods` shows `0:device`; add a
  recovery slot; `strip_kind(env, dek, KIND_DEVICE)` ⇒ generation **unchanged**, MAC verifies, opens under
  the recovery code, and does **not** open under `S` (device slot gone). Assert `strip_kind` on a
  device-only envelope returns `Format`.
- **SDK E2E (`convenience-e2e.spec.js`, extend):** after `enrollConvenience`, `listMethods()` contains a
  `device` entry; `exportBundle()` → `importBundle()` in a fresh context ⇒ imported vault has **no** device
  slot, does **not** auto-unlock (no device record), opens via the recovery code, data intact.

### 8.7 Build order
1. D-CV6 core (`KIND_DEVICE`, `create_device_envelope`, `enroll_device`, `list_methods` map) + SDK wiring.
2. D-CV5 core (`strip_kind`, `strip_export_envelope`, `session_export_inner` hook).
3. Tests (§8.6). Rebuild the three wasm profiles warning-clean; `cargo test -p freehold-decrypt` (decryptor
   is unaffected — it never sees a device slot in a bundle, and now provably won't).
> **Migration:** pre-release, no persisted user data. Convenience vaults enrolled before this change carry a
> `KIND_PASSKEY` device slot — they still **unlock** normally, but list as `passkey` and won't be stripped
> on export. Re-enrolling convenience gets the honest label. No on-disk migration is written.

## Cross-links
[[data-custody-protocol]] (the custody model this convenience tier sits under), [[dek-rotation-design]]
(rotation re-establishes/orphans the device slot), [[audit-readiness]] (trust status + limits), Freehold
DB design-spec (envelope v3, the passkey-slot derivation `S` reuses).
