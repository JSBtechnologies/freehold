//! Blind-relay authorization — proving *who may append to / read a bucket* without the relay ever
//! learning the DEK (docs/relay-auth-design.md).
//!
//! A blind relay stores opaque sealed blobs; blindness (§2 of the data-custody protocol) protects the
//! *contents*, but says nothing about *access*. Without authorization anyone who learns a `sync_id`
//! could append garbage (storage-exhaustion / poison) or enumerate a bucket. This module closes that
//! gap with the audited Ed25519 primitive already used for vault-identity attestations (attest.rs) —
//! **no new cryptography**.
//!
//! ## The key (per-database, DEK-derived)
//!
//! `seed   = HKDF(DEK, "freehold-sync-relay-auth-v1" ‖ db_uuid)`  →  `sk = Ed25519(seed)`.
//! Per-`db_uuid` (not one per vault) so two databases of the same vault present *different* public
//! keys to the relay — the relay cannot link a user's buckets by a shared key, matching the per-DB
//! unlinkability `sync_id` already provides. Deterministic across all of a user's devices (they share
//! the DEK), held in `Zeroizing`, re-derived on unlock, dropped on lock — same lifecycle as the vault
//! identity key.
//!
//! ## sync_id is BOUND to the public key (D-RA1 — stateless authorization, no land-grab)
//!
//! `sync_id = SHA-256("freehold-sync-id-v1" ‖ auth_pubkey)[..16]`.
//!
//! The relay authorizes an op with a **stateless** check needing no per-bucket ownership record:
//!   1. the request carries `(pubkey, sig)`;
//!   2. `sync_id == SHA-256(LABEL ‖ pubkey)[..16]`  — the bucket name commits to the key; and
//!   3. `sig` verifies over the canonical op message under `pubkey`.
//! Possession of the bucket therefore *is* possession of the DEK-derived key. A stranger cannot claim
//! an unused bucket (no trust-on-first-use window to race): to present a `pubkey` hashing to a given
//! `sync_id` they would have to invert SHA-256. `sync_id` stays 16 opaque bytes, deterministic across
//! devices, unguessable, and reveals nothing — it is now additionally a *commitment* to the key.
//!
//! ## The signed message (domain-separated, length-prefixed — cannot collide across ops)
//!
//! ```text
//!  msg = "freehold-relay-auth-v1" ‖ u8(method) ‖ sync_id(16) ‖ u32_LE(arg.len) ‖ arg
//! ```
//! `method` ∈ {1=Push, 2=List, 3=Get, 4=Subscribe}. `arg` binds the **push** to its exact blob bytes
//! (a captured Push signature cannot be replayed to store *different* bytes); read ops sign an empty
//! `arg`, so one read credential is reusable within a sync pass (they are idempotent — binding the
//! cursor adds nothing over the pubkey↔bucket commitment). Verification is **pure** (public key only,
//! no DEK): the relay recomputes `msg` and checks the Ed25519 signature.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// HKDF info prefix for the per-DB relay-auth signing seed (‖ db_uuid).
const AUTH_INFO_PREFIX: &[u8] = b"freehold-sync-relay-auth-v1";
/// Domain label hashed with the auth pubkey to name the bucket (§ D-RA1).
const SYNC_ID_LABEL: &[u8] = b"freehold-sync-id-v1";
/// Domain separation for the signed op message.
const MSG_DOMAIN: &[u8] = b"freehold-relay-auth-v1";

/// Op codes bound into the signed message (kept in sync with server/relay-server.mjs + index.js).
pub const METHOD_PUSH: u8 = 1;
pub const METHOD_LIST: u8 = 2;
pub const METHOD_GET: u8 = 3;
pub const METHOD_SUBSCRIBE: u8 = 4;

/// The per-DB Ed25519 signing seed: `HKDF(DEK, "freehold-sync-relay-auth-v1" ‖ db_uuid)`. Held in
/// `Zeroizing` so the private material never outlives the caller's scope.
fn signing_seed(dek: &[u8; 32], db_uuid: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut info = [0u8; 27 + 16];
    debug_assert_eq!(AUTH_INFO_PREFIX.len(), 27);
    info[..27].copy_from_slice(AUTH_INFO_PREFIX);
    info[27..].copy_from_slice(db_uuid);
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(&info, seed.as_mut_slice())
        .expect("HKDF expand of 32 bytes never fails");
    seed
}

/// The per-DB relay-auth Ed25519 **public key** (32 bytes) — safe to hand to the relay; it is the
/// bucket's owning capability, not the key.
pub fn public_key(dek: &[u8; 32], db_uuid: &[u8; 16]) -> [u8; 32] {
    SigningKey::from_bytes(&signing_seed(dek, db_uuid))
        .verifying_key()
        .to_bytes()
}

/// The opaque 16-byte relay bucket id committed to `pubkey`: `SHA-256(LABEL ‖ pubkey)[..16]`.
pub fn sync_id_from_pubkey(pubkey: &[u8; 32]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(SYNC_ID_LABEL);
    h.update(pubkey);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// The bucket id for `(DEK, db_uuid)` — `sync_id_from_pubkey(public_key(..))`. Replaces the previous
/// direct `HKDF(DEK, "freehold-sync-id-v1" ‖ db_uuid)`; still deterministic across devices, still 16
/// opaque bytes, now cryptographically bound to the auth key so the relay can authorize statelessly.
pub fn sync_id(dek: &[u8; 32], db_uuid: &[u8; 16]) -> [u8; 16] {
    sync_id_from_pubkey(&public_key(dek, db_uuid))
}

/// The exact bytes signed for one relay op — domain-separated + length-prefixed so no two op/arg
/// layouts collide. `arg` is bounded to a `u32` length (a blob is ≤ a few MiB); a `debug_assert`
/// guards a caller passing a >4 GiB value that would truncate the prefix.
pub fn canonical_message(method: u8, sync_id: &[u8; 16], arg: &[u8]) -> Vec<u8> {
    debug_assert!(arg.len() <= u32::MAX as usize, "relay-auth: arg too long");
    let mut m = Vec::with_capacity(MSG_DOMAIN.len() + 1 + 16 + 4 + arg.len());
    m.extend_from_slice(MSG_DOMAIN);
    m.push(method);
    m.extend_from_slice(sync_id);
    m.extend_from_slice(&(arg.len() as u32).to_le_bytes());
    m.extend_from_slice(arg);
    m
}

/// Sign a relay op. Returns `(pubkey, signature)`; the SDK sends both to the relay. The `sync_id` is
/// recomputed here from the derived key (never taken from the caller) so a signature is intrinsically
/// bound to the bucket the key owns.
pub fn sign(dek: &[u8; 32], db_uuid: &[u8; 16], method: u8, arg: &[u8]) -> ([u8; 32], [u8; 64]) {
    let sk = SigningKey::from_bytes(&signing_seed(dek, db_uuid));
    let pubkey = sk.verifying_key().to_bytes();
    let sid = sync_id_from_pubkey(&pubkey);
    let msg = canonical_message(method, &sid, arg);
    (pubkey, sk.sign(&msg).to_bytes())
}

/// Verify a relay-op signature — **pure**, no DEK. Recomputes `sync_id` from `pubkey` (so the caller
/// gets the pubkey↔bucket commitment for free) and checks the Ed25519 signature with `verify_strict`
/// (rejects malleable / small-order signatures). A malformed key/sig yields false, never a panic. The
/// relay separately checks that this `sync_id` equals the routed bucket.
pub fn verify(pubkey: &[u8; 32], method: u8, arg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else { return false };
    let sid = sync_id_from_pubkey(pubkey);
    let msg = canonical_message(method, &sid, arg);
    vk.verify_strict(&msg, &Signature::from_bytes(sig)).is_ok()
}

/// Self-contained checks (callable from `run_tests`): key determinism, the pubkey↔sync_id commitment,
/// sign/verify round-trip, and rejection of cross-op / wrong-key / tampered-arg signatures.
#[cfg(feature = "testing-api")]
pub fn self_check() -> Result<(), String> {
    let dek = [0x11u8; 32];
    let uuid = *b"freehold-ra-uuid";

    // Deterministic per (DEK, db_uuid); different db_uuid ⇒ different key ⇒ different bucket.
    let pk = public_key(&dek, &uuid);
    if pk != public_key(&dek, &uuid) {
        return Err("relay_auth: public_key not deterministic".into());
    }
    let mut other = uuid;
    other[0] ^= 0xff;
    if public_key(&dek, &other) == pk {
        return Err("relay_auth: public_key not sensitive to db_uuid".into());
    }
    // sync_id is the commitment to the pubkey, and matches the DEK-path derivation.
    if sync_id(&dek, &uuid) != sync_id_from_pubkey(&pk) || sync_id(&dek, &uuid).len() != 16 {
        return Err("relay_auth: sync_id != H(pubkey)".into());
    }

    // Push binds its blob; a valid sig verifies, a tampered arg does not.
    let blob = b"opaque-sealed-bytes";
    let (spk, sig) = sign(&dek, &uuid, METHOD_PUSH, blob);
    if spk != pk {
        return Err("relay_auth: sign returned a different pubkey".into());
    }
    if !verify(&pk, METHOD_PUSH, blob, &sig) {
        return Err("relay_auth: valid Push signature rejected".into());
    }
    if verify(&pk, METHOD_PUSH, b"different-bytes", &sig) {
        return Err("relay_auth: Push signature accepted for different blob".into());
    }
    if verify(&pk, METHOD_LIST, blob, &sig) {
        return Err("relay_auth: Push signature accepted as List (cross-op)".into());
    }
    // Wrong key rejects.
    let wrong = public_key(&dek, &other);
    if verify(&wrong, METHOD_PUSH, blob, &sig) {
        return Err("relay_auth: signature accepted under the wrong pubkey".into());
    }
    // Read ops sign an empty arg and round-trip.
    let (_, rsig) = sign(&dek, &uuid, METHOD_GET, &[]);
    if !verify(&pk, METHOD_GET, &[], &rsig) {
        return Err("relay_auth: valid Get signature rejected".into());
    }
    Ok(())
}
