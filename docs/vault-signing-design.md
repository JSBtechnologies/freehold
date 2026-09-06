---
slug: freehold-vault-signing
artifact: vault-signing-design
version: 0.1
status: BUILT 2026-09-01 — signed off (D-VS1 DEK-derived, full build) and implemented: attest.rs +
  ed25519-dalek, wasm bindings, SDK attest/verify, custody showcase, run_tests VS + attest-e2e.
created: 2026-09-01
kind: security-design
depends-on: Freehold DB crypto core (HKDF-off-DEK subkeys — crypto.rs; shipped); data-custody-protocol
  §6/D-DC3 (swappable grant/attestation proof); this is the "#7" gate that lights up verifiable tier-2.
---

# Freehold vault signing key & verifiable tier-2 attestations

> Today a tier-2 attestation ("18+ ✓", "card valid") is a bare fact the vault's *own* broker returns —
> the relying app must **trust the broker's word** (data-custody-protocol §6: symmetric/trust-local
> proof). This adds an **Ed25519 vault-identity signing key** so the vault emits a **signed** claim a
> *remote* party can verify against a registered public key, **without ever seeing the PII and without
> the DEK**. It is the "#7" milestone D-DC3 named — and it turns out to need **no envelope change**.

## 1. What key this is (and is not)
The custody note (§6) sketched "a private key wrapped in the envelope like the DEK." On closer look the
attestation use-case wants a **vault identity** — *"this user's vault attests X"* — which must be the
**same on every one of the user's devices**. All their devices already share the DEK (via the passkey
envelope), so the identity key should be **derived from the DEK**, exactly like every other Freehold
subkey (`db_key`, `epoch_key`, `sync_key`, `sync_id` — all `HKDF(DEK, "freehold-…-v1")`, crypto.rs).

> **DECISION D-VS1: the vault identity signing key is `Ed25519(seed = HKDF(DEK, "freehold-vault-identity-v1"))`.**
> Deterministic, identical across the user's devices, **never persisted** (re-derived on unlock, the
> seed lives in `Zeroizing` in the worker and is dropped on lock), and it requires **zero change to the
> envelope format**. HKDF-SHA256 yields a uniform 32-byte value; feeding it as an Ed25519 seed is
> standard (Ed25519 hashes the seed internally to the scalar + nonce prefix) — no invented crypto.

This is **not** the per-device sync-epoch key. sync-epoch-design D-SE2 deferred *per-device* signing
(so one device can't forge another's freshness epoch) to a multi-user v2; that key is `device_id`-bound
and is a **different** key from this vault-identity key. Do not conflate them (§7).

> **DECISION D-VS2: DEK rotation rotates the vault identity.** Because the key is DEK-derived, a
> `rotateKey()` (the nuclear re-key / device-eviction path) produces a **new** vault public key —
> verifiers must re-register it. This is acceptable and arguably correct: a compromise-driven re-key
> *should* mint a fresh identity. If a stable-across-rotation identity is ever required, the upgrade is
> an **independent** Ed25519 keypair sealed under `HKDF(DEK, …)` and carried in the bundle (an envelope/
> bundle-format change) — explicitly deferred, noted so we don't design it away.

## 2. The attestation — canonical, audience-bound, time-bounded
A verifiable attestation must resist (a) forgery — solved by the signature; (b) **replay to a different
verifier** — solved by binding an **audience**; (c) **staleness** — solved by an expiry. The signed
message is domain-separated and length-prefixed so no two field layouts can ever collide:

```text
msg = "freehold-attestation-v1"                      (domain separator)
    ‖ u16_LE(claim.len)    ‖ claim      (UTF-8)       (e.g. "profile.over18=true")
    ‖ u16_LE(audience.len) ‖ audience   (bytes)       (verifier-supplied challenge / origin)
    ‖ u64_LE(issued_at)                               (unix seconds; from JS — wasm has no clock)
    ‖ u64_LE(expiry)                                  (unix seconds)
signature = Ed25519_sign(identity_seed, msg)          (64 bytes)
```

- **claim** is an opaque, canonical UTF-8 string the broker chooses and the verifier knows to expect
  (`"profile.over18=true"`). Keeping it a flat string (not JSON) removes canonicalization ambiguity.
- **audience** binds the attestation to one verifier/session. A remote verifier issues a fresh random
  challenge; the vault signs it in; the verifier checks it matches — so a captured attestation can't be
  replayed to a *different* verifier or reused later. For the local showcase, audience is the RP's id.
- **issued_at / expiry** come from JS (`Date.now()`); the wasm core never reads a clock. Verification
  policy (the time window) is the **caller's**, not baked into the signature.

> **DECISION D-VS3: sign the domain-separated, length-prefixed `msg` above; bind audience + expiry.**
> **DECISION D-VS4: the attestation object is `{ v:1, claim, audience, issuedAt, expiry, publicKey,
> signature }`.** Verification is **pure**: recompute `msg`, `Ed25519_verify(publicKey, msg, sig)`, then
> the caller checks `now < expiry`, `claim == expected`, `audience == expected`, and `publicKey ==` the
> registered vault key. **No DEK is needed to verify** — any remote party verifies with the public key
> and any Ed25519 library against this documented message format.

## 3. Core surface (Rust) — a small new `attest.rs`
crypto.rs stays "small and reviewable" (its header says so), so signing lands in a sibling module:

```rust
// attest.rs — vault identity + verifiable attestations. Audited ed25519-dalek, used as-is.
pub fn vault_identity_seed(dek: &[u8;32]) -> Zeroizing<[u8;32]>   // HKDF(DEK, "freehold-vault-identity-v1")
pub fn vault_public_key(dek: &[u8;32]) -> [u8;32]                 // SigningKey::from(seed).verifying_key()
pub fn canonical_message(claim: &str, audience: &[u8], issued_at: u64, expiry: u64) -> Vec<u8>
pub fn attest(dek: &[u8;32], claim: &str, audience: &[u8], issued_at: u64, expiry: u64) -> [u8;64]
pub fn verify(pubkey: &[u8;32], claim: &str, audience: &[u8], issued_at: u64, expiry: u64, sig: &[u8;64]) -> bool
```

`attest` needs the DEK (worker-only); `verify` is pure (pubkey only). Neither reads a clock — the caller
supplies `issued_at`/`expiry` and enforces the time window.

wasm bindings (lib.rs):
- `session_vault_pubkey() -> Vec<u8>` — session-gated (derives from the live session DEK).
- `session_attest(claim: &str, audience: &[u8], issued_at: f64, expiry: f64) -> Vec<u8>` — 64-byte sig.
- `verify_attestation(pubkey, claim, audience, issued_at, expiry, sig) -> bool` — **pure**, no session;
  the SDK's reference verifier + the tests call it. (u64 times cross as f64 — exact through 2⁵³.)

> **DECISION D-VS5: add `ed25519-dalek` v2 as the signing/verifying dependency.** It is audited
> (Quarkslab, 2019) and the de-facto standard, RustCrypto-adjacent (implements the `signature`/`ed25519`
> traits). Used strictly as-is for sign/verify — no invented crypto. `docs/supply-chain.md` gains the
> entry. The **standalone decryptor does not** take this dependency (attestations never travel in a
> `.freehold` bundle; a bundle is ciphertext, an attestation is a live signed claim) — an offline
> attestation-verify CLI, if ever wanted, is a separate opt-in tool.

## 4. SDK surface (`packages/db`)
```ts
vaultPublicKey(): Promise<Uint8Array>                         // 32 bytes; needs an open session
attest(claim: string, opts?: { audience?: Uint8Array|string, ttlSeconds?: number }): Promise<Attestation>
verifyAttestation(att: Attestation, expect: {                  // pure; callable on any (even locked) vault
  claim?: string, audience?: Uint8Array|string,
  publicKey?: Uint8Array, now?: number                         // defaults to Date.now()
}): { ok: boolean, reason?: string }
interface Attestation { v: 1; claim: string; audience: Uint8Array; issuedAt: number; expiry: number;
                        publicKey: Uint8Array; signature: Uint8Array }
```
`attest` stamps `issuedAt = now`, `expiry = now + ttlSeconds` (default 300), coerces a string audience to
UTF-8 bytes, calls `session_attest`, and returns the object. `verifyAttestation` recomputes and calls the
pure `verify_attestation`, then applies the expectation policy (expiry, claim, audience, pubkey match).

## 5. Custody showcase — D-DC3 lights up (no protocol change above §6)
The broker's tier-2 caps return a **signed** attestation instead of a bare fact:
```js
'profile.attest.over18': { tier: 2, run: async ({ audience }) => {
  const value = ageFrom(await field('dob')) >= 18;
  const attestation = await vault.attest(`profile.over18=${value}`, { audience });
  return { data: { claim: 'over18', value, attestation }, detail: 'attested over18 — signed by your vault, DOB withheld' };
}}
```
The relying-party component calls `verifyAttestation(att, { claim, audience, publicKey: registeredVaultKey })`
and shows **"verified against your vault's key ✓"** — making the "the server trusts the vault's *key*,
not its *word*" row of the roles table (data-custody-protocol §2) real. Nothing in §5/§6 of the protocol
changes; the `proof` field simply upgraded from DEK-MAC to Ed25519 (D-DC3).

## 6. Honest limits
- **Registration/PKI is out of scope.** This mints + signs; *distributing/pinning* the vault public key
  to a verifier (a directory, TOFU pin, or manual registration) is the verifier's problem. The showcase
  hard-codes "registered = the pubkey we just read," which is honest for a same-page demo, not a PKI.
- **Attestation ≠ non-retention.** A signed "18+ ✓" still says nothing about what the verifier keeps
  (custody §10). It minimizes: the *fact* is transmitted and verifiable; the DOB never is.
- **DEK-rotation re-keys the identity** (D-VS2) — a feature for eviction, friction for routine rotation.
- **Not audited** — inherits Freehold's pre-1.0 status ([[audit-readiness]]).

## 7. Scope guard — vault identity vs. per-device epoch key
| Key | Derivation | Same across a user's devices? | Purpose | Status |
|---|---|---|---|---|
| **Vault identity** (this note) | `HKDF(DEK, "freehold-vault-identity-v1")` | **yes** (shared DEK) | verifiable tier-2 attestations | THIS build |
| **Per-device epoch key** (sync-epoch D-SE2 v2) | `device_id`-bound | **no** (device-unique) | multi-user epoch non-forgeability | deferred |
Same primitive (Ed25519), different key, different purpose. This note builds only the first.

## 8. Build order
1. **Design sign-off** (this note) — new signing dependency + a new signed artifact ⇒ same crypto gate.
2. `attest.rs` core + `ed25519-dalek` dep; wasm bindings (`session_vault_pubkey`, `session_attest`,
   `verify_attestation`); `run_tests` **VS** case.
3. SDK: `vaultPublicKey` / `attest` / `verifyAttestation` (+ `index.d.ts`, worker OPS allowlist).
4. Custody broker tier-2 caps return signed attestations; RP component verifies + shows the badge.
5. E2E: attest → verify ok; expired → reject; wrong audience → reject; tampered sig → reject; wrong
   pubkey (different DEK) → reject. Rebuild 3 wasm profiles warning-clean; decryptor unaffected.
6. Docs: `supply-chain.md` (+dalek), `data-custody-protocol.md` D-DC3 ("lit"), CHANGELOG.

## Cross-links
[[data-custody-protocol]] (§6/D-DC3 swappable proof — this is the asymmetric half), [[sync-epoch-design]]
(D-SE2 per-device key = a *different*, deferred key), [[dek-rotation-design]] (rotation re-keys the
identity, D-VS2), [[audit-readiness]] (trust status), [[convenience-tier-design]] (device tier can still
attest — the identity is DEK-derived, tier-independent).
