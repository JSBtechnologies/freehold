//! Vault identity signing + verifiable tier-2 attestations (docs/vault-signing-design.md).
//!
//! The vault's **identity** is an Ed25519 keypair seeded off the DEK:
//! `seed = HKDF(DEK, "freehold-vault-identity-v1")` — deterministic, identical across all of a user's
//! devices (they share the DEK), never persisted (re-derived on unlock, held in `Zeroizing`, dropped on
//! lock). Feeding a uniform HKDF output as an Ed25519 seed is standard (Ed25519 hashes the seed to the
//! scalar + nonce prefix); audited `ed25519-dalek` used as-is — no invented crypto.
//!
//! An attestation is a signature over a **domain-separated, length-prefixed** message binding the claim,
//! an **audience** (a verifier-supplied challenge/origin — anti-replay to a different verifier), and a
//! validity window (`issued_at`/`expiry`, supplied by the caller — the core reads no clock):
//!
//! ```text
//!  msg = "freehold-attestation-v1"
//!      ‖ u16_LE(claim.len)    ‖ claim      (UTF-8, e.g. "profile.over18=true")
//!      ‖ u16_LE(audience.len) ‖ audience   (bytes)
//!      ‖ u64_LE(issued_at) ‖ u64_LE(expiry)                     (unix seconds)
//! ```
//!
//! Verification is **pure** (public key only, no DEK): any remote party recomputes `msg`, checks the
//! Ed25519 signature, then applies its own policy (time window, expected claim/audience/pubkey).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const IDENTITY_INFO: &[u8] = b"freehold-vault-identity-v1";
const ATTEST_DOMAIN: &[u8] = b"freehold-attestation-v1";

/// The Ed25519 seed of the vault identity key: `HKDF(DEK, "freehold-vault-identity-v1")`. Held in
/// `Zeroizing` — the private key material never outlives the caller's scope.
pub fn vault_identity_seed(dek: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(IDENTITY_INFO, seed.as_mut_slice())
        .expect("HKDF expand of 32 bytes never fails");
    seed
}

/// The vault's 32-byte Ed25519 public key (its identity). Safe to publish/register with a verifier.
pub fn vault_public_key(dek: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&vault_identity_seed(dek))
        .verifying_key()
        .to_bytes()
}

/// The exact bytes signed by an attestation — domain-separated + length-prefixed so no two field
/// layouts can collide. `claim`/`audience` are bounded to `u16` lengths (attestation claims are tiny);
/// a `debug_assert` guards against a caller passing a >64 KiB value that would truncate the prefix.
pub fn canonical_message(claim: &str, audience: &[u8], issued_at: u64, expiry: u64) -> Vec<u8> {
    debug_assert!(claim.len() <= u16::MAX as usize, "attest: claim too long");
    debug_assert!(audience.len() <= u16::MAX as usize, "attest: audience too long");
    let mut m = Vec::with_capacity(ATTEST_DOMAIN.len() + 2 + claim.len() + 2 + audience.len() + 16);
    m.extend_from_slice(ATTEST_DOMAIN);
    m.extend_from_slice(&(claim.len() as u16).to_le_bytes());
    m.extend_from_slice(claim.as_bytes());
    m.extend_from_slice(&(audience.len() as u16).to_le_bytes());
    m.extend_from_slice(audience);
    m.extend_from_slice(&issued_at.to_le_bytes());
    m.extend_from_slice(&expiry.to_le_bytes());
    m
}

/// Sign an attestation with the vault identity key. Needs the DEK (worker-only). Returns the 64-byte
/// Ed25519 signature; the caller assembles the `{claim, audience, issued_at, expiry, pubkey, sig}` object.
pub fn attest(dek: &[u8; 32], claim: &str, audience: &[u8], issued_at: u64, expiry: u64) -> [u8; 64] {
    let sk = SigningKey::from_bytes(&vault_identity_seed(dek));
    let msg = canonical_message(claim, audience, issued_at, expiry);
    sk.sign(&msg).to_bytes()
}

/// Verify an attestation signature against a public key. **Pure** — no DEK, no clock. `verify_strict`
/// rejects malleable / small-order signatures. Returns false on a malformed public key or any mismatch;
/// the caller separately enforces the time window and the expected claim/audience/pubkey.
pub fn verify(
    pubkey: &[u8; 32],
    claim: &str,
    audience: &[u8],
    issued_at: u64,
    expiry: u64,
    sig: &[u8; 64],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else { return false };
    let signature = Signature::from_bytes(sig);
    let msg = canonical_message(claim, audience, issued_at, expiry);
    vk.verify_strict(&msg, &signature).is_ok()
}
