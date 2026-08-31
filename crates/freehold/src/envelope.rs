//! Passkey-PRF envelope (build-spec M2/M3; threat-model B). A random 256-bit DEK is wrapped by
//! **N independent KEKs** — one per unlock method — so any single method opens the DB and losing
//! one method loses nothing. The DEK is constant; adding/removing a method is a *re-wrap* of the
//! DEK into a new slot, never a re-encryption of the database (threat-model B, §11).
//!
//! Audited RustCrypto used as-is; no invented crypto. Keep this file small and reviewable.
//!
//! ```text
//!  blob   = header(36) | slot[0..slot_count] | mac(32)
//!  header = magic "FREEHENV"(8) | version(1)=3 | slot_count(1) | reserved(2) | env_salt(16)
//!           | env_generation(8, LE)                                                (36 bytes)
//!  slot   = kek_id(1) | kind(1) | nonce(24) | wrapped_dek_ct(32) | tag(16)          (74 bytes)
//!  mac    = HMAC-SHA256( HKDF(DEK,"freehold-envelope-mac-v1"), header ‖ all-slots ) (32 bytes)
//!  aad    = "freehold-envelope-v3" | kek_id | kind
//!
//!  kind 0 (passkey):  KEK = HKDF-SHA256(prf_output, info="freehold-kek-v1")
//!  kind 1 (recovery): KEK = Argon2id(normalized_recovery_code, salt = env_salt)
//! ```
//!
//! Unlock derives the KEK from whatever material you present (a passkey's PRF output, or the
//! recovery code) and tries it against every slot; the slot wrapped with that KEK opens. The AAD
//! binds `kek_id` + `kind`, so a passkey KEK can never open a recovery slot (or vice-versa) even by
//! fluke. A wrong method opens no slot and fails cleanly.
//!
//! ## v3 anti-rollback (issue #3)
//! `env_generation` is a monotonic counter bumped on every mutation (add/remove method). The whole
//! envelope (header incl. generation + all slots) is authenticated by a **DEK-keyed HMAC** — so an
//! attacker who kept an *older* copy of the envelope to re-plant a revoked slot cannot forge a
//! higher generation onto it (the MAC only verifies under the real DEK, which they don't hold), and
//! a genuine older copy is caught by a generation *floor* the caller enforces (see `check_fresh`).
//! The MAC — not per-slot AAD — carries the generation because a mutation only holds the DEK, never
//! the *other* slots' KEKs, so it cannot re-seal foreign slots. Verified at open, recomputed on
//! every mutation (which is why `remove_slot` now needs the DEK: revoking is an authorized op).

use argon2::Argon2;
use chacha20poly1305::{
    aead::AeadInPlace, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const DEK_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
// "FREEH(old)ENV(elope)" — the bare product name b"FREEHOLD" is the .freehold bundle's magic
// (bundle.rs), and the two formats' version namespaces must stay independent, so the envelope
// gets its own. Envelopes from earlier versions do NOT open here (pre-release break; re-enroll).
const MAGIC: &[u8; 8] = b"FREEHENV";
const VERSION: u8 = 3;
const SALT_LEN: usize = 16;
const SALT_OFF: usize = 12;
const GEN_OFF: usize = 28;
const GEN_LEN: usize = 8;
const HEADER_LEN: usize = 8 + 1 + 1 + 2 + SALT_LEN + GEN_LEN; // 36
const SLOT_LEN: usize = 1 + 1 + NONCE_LEN + DEK_LEN + TAG_LEN; // 74
const MAC_LEN: usize = 32;

const KEK_INFO: &[u8] = b"freehold-kek-v1";
const MAC_INFO: &[u8] = b"freehold-envelope-mac-v1";
const WRAP_AAD_PREFIX: &[u8] = b"freehold-envelope-v3";

pub const KIND_PASSKEY: u8 = 0;
pub const KIND_RECOVERY: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// CSPRNG failure — no key/nonce/salt generated (fail closed).
    Rng,
    /// Malformed blob (bad magic/version/length).
    Format,
    /// No slot opened with the presented material — wrong passkey/PRF/UV, wrong recovery code, or tamper.
    Unlock,
    /// A slot opened but the envelope-wide MAC failed — header/generation/slots were tampered.
    Tamper,
    /// The envelope's generation is below the caller's freshness floor — a rolled-back envelope.
    Rollback,
    /// Internal AEAD seal failure (should not happen for well-formed input).
    Seal,
    /// KDF failure (Argon2id).
    Kdf,
}

/// One slot's public descriptor, for the demo's "unlock methods" list.
#[derive(Clone, Copy)]
pub struct SlotInfo {
    pub kek_id: u8,
    pub kind: u8,
}

fn slot_aad(kek_id: u8, kind: u8) -> Vec<u8> {
    let mut a = WRAP_AAD_PREFIX.to_vec();
    a.push(kek_id);
    a.push(kind);
    a
}

fn kek_from_prf(prf_output: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, prf_output);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(KEK_INFO, kek.as_mut_slice())
        .expect("HKDF expand of 32 bytes never fails");
    kek
}

/// Normalize a recovery code so trivial transcription differences (case, spacing) don't change the
/// KEK, then stretch it with Argon2id. The `env_salt` (per-envelope random, stored plaintext in the
/// header) makes the KDF output unique per database — salts need uniqueness, not secrecy.
fn kek_from_recovery(code: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    let norm = code.split_whitespace().collect::<Vec<_>>().join("").to_uppercase();
    let mut kek = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(norm.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|_| EnvelopeError::Kdf)?;
    Ok(kek)
}

/// Wrap `dek` under `kek` into a `SLOT_LEN` slot.
fn wrap_slot(dek: &[u8; DEK_LEN], kek: &[u8; 32], kek_id: u8, kind: u8) -> Result<Vec<u8>, EnvelopeError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| EnvelopeError::Rng)?;
    if nonce.iter().all(|&b| b == 0) {
        return Err(EnvelopeError::Rng);
    }
    let mut ct = Zeroizing::new(dek.to_vec());
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &slot_aad(kek_id, kind), ct.as_mut_slice())
        .map_err(|_| EnvelopeError::Seal)?;
    let mut slot = Vec::with_capacity(SLOT_LEN);
    slot.push(kek_id);
    slot.push(kind);
    slot.extend_from_slice(&nonce);
    slot.extend_from_slice(&ct);
    slot.extend_from_slice(&tag);
    Ok(slot)
}

fn body_len(slot_count: usize) -> usize {
    HEADER_LEN + slot_count * SLOT_LEN
}

/// Validate framing and return the slot count. Checks magic, version and the exact total length
/// (header + slots + MAC). Does NOT verify the MAC (that needs the DEK — see `open_with_kek`).
fn parse(blob: &[u8]) -> Result<usize, EnvelopeError> {
    if blob.len() < HEADER_LEN + MAC_LEN || &blob[..8] != MAGIC.as_slice() || blob[8] != VERSION {
        return Err(EnvelopeError::Format);
    }
    let slot_count = blob[9] as usize;
    if blob.len() != body_len(slot_count) + MAC_LEN {
        return Err(EnvelopeError::Format);
    }
    Ok(slot_count)
}

fn read_generation(blob: &[u8]) -> u64 {
    let mut g = [0u8; GEN_LEN];
    g.copy_from_slice(&blob[GEN_OFF..GEN_OFF + GEN_LEN]);
    u64::from_le_bytes(g)
}

/// The generation counter of a well-formed envelope (0 on a malformed blob).
pub fn envelope_generation(blob: &[u8]) -> u64 {
    if parse(blob).is_err() {
        return 0;
    }
    read_generation(blob)
}

/// Reject an envelope whose generation is below `floor` — the caller's record of the newest
/// generation it has ever accepted. This is the anti-rollback enforcement point (issue #3): a
/// genuine older envelope replayed to re-plant a revoked slot is caught here. Locally the floor is
/// itself a backstop (an attacker who rewrites all storage rewrites it too); cross-device the
/// generation is bound into the sync epoch so a stale envelope cannot propagate.
pub fn check_fresh(blob: &[u8], floor: u64) -> Result<(), EnvelopeError> {
    parse(blob)?;
    if read_generation(blob) < floor {
        return Err(EnvelopeError::Rollback);
    }
    Ok(())
}

fn mac_key(dek: &[u8; DEK_LEN]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut k = Zeroizing::new([0u8; 32]);
    hk.expand(MAC_INFO, k.as_mut_slice())
        .expect("HKDF expand of 32 bytes never fails");
    k
}

fn compute_mac(body: &[u8], dek: &[u8; DEK_LEN]) -> [u8; MAC_LEN] {
    let k = mac_key(dek);
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k.as_slice())
        .expect("HMAC accepts any key length");
    m.update(body);
    let out = m.finalize().into_bytes();
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// Append the DEK-keyed MAC over `body` (= header ‖ slots), yielding a complete envelope blob.
fn finalize(mut body: Vec<u8>, dek: &[u8; DEK_LEN]) -> Vec<u8> {
    let mac = compute_mac(&body, dek);
    body.extend_from_slice(&mac);
    body
}

fn next_kek_id(blob: &[u8], slot_count: usize) -> u8 {
    let mut max = None;
    for i in 0..slot_count {
        let id = blob[HEADER_LEN + i * SLOT_LEN];
        max = Some(max.map_or(id, |m: u8| m.max(id)));
    }
    max.map_or(0, |m| m.wrapping_add(1))
}

/// Fresh random 256-bit DEK. Fail-closed on RNG error / all-zero draw.
pub fn random_dek() -> Result<Zeroizing<[u8; DEK_LEN]>, EnvelopeError> {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    getrandom::getrandom(dek.as_mut_slice()).map_err(|_| EnvelopeError::Rng)?;
    if dek.iter().all(|&b| b == 0) {
        return Err(EnvelopeError::Rng);
    }
    Ok(dek)
}

/// Generate a high-entropy (128-bit) recovery code, Crockford-Base32, grouped for transcription.
/// NOTE: a production build should prefer a BIP39 checksummed word list (threat-model B); this
/// prototype uses Base32 to avoid a heavier wasm dependency — the KEK derivation is identical
/// either way (Argon2id over the normalized string).
pub fn generate_recovery_code() -> Result<String, EnvelopeError> {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford (no I,L,O,U)
    let mut ent = [0u8; 16];
    getrandom::getrandom(&mut ent).map_err(|_| EnvelopeError::Rng)?;
    let mut chars = String::new();
    // 128 bits → 26 base32 symbols (last carries 3 bits).
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &byte in ent.iter() {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            chars.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        chars.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    // Group into 5-char blocks: XXXXX-XXXXX-...
    let grouped = chars
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-");
    Ok(grouped)
}

/// Create a new envelope (generation 1) with a single passkey slot (kek_id 0). Random per-envelope salt.
pub fn create_envelope(dek: &[u8; DEK_LEN], prf_output: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let mut header = vec![0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    header[9] = 1; // slot_count
    getrandom::getrandom(&mut header[SALT_OFF..SALT_OFF + SALT_LEN]).map_err(|_| EnvelopeError::Rng)?;
    header[GEN_OFF..GEN_OFF + GEN_LEN].copy_from_slice(&1u64.to_le_bytes());
    let slot = wrap_slot(dek, &kek_from_prf(prf_output), 0, KIND_PASSKEY)?;
    header.extend_from_slice(&slot);
    Ok(finalize(header, dek))
}

/// Rebuild an envelope body from `blob`'s existing slots plus `add`, with the generation bumped and
/// `slot_count` set to `count`, then re-MAC under `dek`. Shared by the add/remove paths.
fn rebuild(blob: &[u8], dek: &[u8; DEK_LEN], keep: &[u8], count: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(HEADER_LEN + keep.len());
    body.extend_from_slice(&blob[..HEADER_LEN]);
    body[9] = count as u8;
    let next_gen = read_generation(blob).wrapping_add(1);
    body[GEN_OFF..GEN_OFF + GEN_LEN].copy_from_slice(&next_gen.to_le_bytes());
    body.extend_from_slice(keep);
    finalize(body, dek)
}

/// Append a passkey slot wrapping the SAME `dek` under the KEK derived from `prf_output`. Bumps the
/// generation and re-MACs. Caller must hold the DEK (i.e. have unlocked).
pub fn add_passkey_slot(blob: &[u8], dek: &[u8; DEK_LEN], prf_output: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let n = parse(blob)?;
    let slot = wrap_slot(dek, &kek_from_prf(prf_output), next_kek_id(blob, n), KIND_PASSKEY)?;
    let mut keep = blob[HEADER_LEN..body_len(n)].to_vec();
    keep.extend_from_slice(&slot);
    Ok(rebuild(blob, dek, &keep, n + 1))
}

/// Append a recovery slot wrapping the SAME `dek` under the Argon2id KEK of `recovery_code`.
pub fn add_recovery_slot(blob: &[u8], dek: &[u8; DEK_LEN], recovery_code: &str) -> Result<Vec<u8>, EnvelopeError> {
    let n = parse(blob)?;
    let kek = kek_from_recovery(recovery_code, &blob[SALT_OFF..SALT_OFF + SALT_LEN])?;
    let slot = wrap_slot(dek, &kek, next_kek_id(blob, n), KIND_RECOVERY)?;
    let mut keep = blob[HEADER_LEN..body_len(n)].to_vec();
    keep.extend_from_slice(&slot);
    Ok(rebuild(blob, dek, &keep, n + 1))
}

/// Remove the slot with `kek_id`, bump the generation and re-MAC. Needs the `dek` (revoking is an
/// authorized op — see the v3 note). Refuses to remove the last remaining slot (would orphan the DEK).
pub fn remove_slot(blob: &[u8], dek: &[u8; DEK_LEN], kek_id: u8) -> Result<Vec<u8>, EnvelopeError> {
    let n = parse(blob)?;
    if n <= 1 {
        return Err(EnvelopeError::Format);
    }
    let mut keep = Vec::with_capacity((n - 1) * SLOT_LEN);
    let mut kept = 0usize;
    for i in 0..n {
        let at = HEADER_LEN + i * SLOT_LEN;
        if blob[at] != kek_id {
            keep.extend_from_slice(&blob[at..at + SLOT_LEN]);
            kept += 1;
        }
    }
    if kept == n {
        return Err(EnvelopeError::Format); // no such slot
    }
    Ok(rebuild(blob, dek, &keep, kept))
}

/// List the slots (kek_id + kind) for a UI. Empty on a malformed blob.
pub fn slot_infos(blob: &[u8]) -> Vec<SlotInfo> {
    let Ok(n) = parse(blob) else { return Vec::new() };
    (0..n)
        .map(|i| {
            let at = HEADER_LEN + i * SLOT_LEN;
            SlotInfo { kek_id: blob[at], kind: blob[at + 1] }
        })
        .collect()
}

/// Verify the envelope-wide MAC under a candidate DEK (constant-time via HMAC's own compare).
fn mac_ok(blob: &[u8], n: usize, dek: &[u8; DEK_LEN]) -> bool {
    let k = mac_key(dek);
    let Ok(mut m) = <Hmac<Sha256> as Mac>::new_from_slice(k.as_slice()) else { return false };
    m.update(&blob[..body_len(n)]);
    m.verify_slice(&blob[body_len(n)..body_len(n) + MAC_LEN]).is_ok()
}

/// Try `kek` against every slot; on the first that authenticates, verify the envelope MAC and return
/// the DEK. A slot that opens but whose envelope MAC fails means the header/generation/slots were
/// tampered — surfaced as `Tamper`, never a silent success.
fn open_with_kek(blob: &[u8], kek: &[u8; 32]) -> Result<Zeroizing<[u8; DEK_LEN]>, EnvelopeError> {
    let n = parse(blob)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek));
    for i in 0..n {
        let at = HEADER_LEN + i * SLOT_LEN;
        let kek_id = blob[at];
        let kind = blob[at + 1];
        let nonce = &blob[at + 2..at + 2 + NONCE_LEN];
        let ct = &blob[at + 2 + NONCE_LEN..at + 2 + NONCE_LEN + DEK_LEN];
        let tag = &blob[at + 2 + NONCE_LEN + DEK_LEN..at + SLOT_LEN];
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        dek.copy_from_slice(ct);
        if cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce),
                &slot_aad(kek_id, kind),
                dek.as_mut_slice(),
                Tag::from_slice(tag),
            )
            .is_ok()
        {
            if !mac_ok(blob, n, &dek) {
                return Err(EnvelopeError::Tamper);
            }
            return Ok(dek);
        }
    }
    Err(EnvelopeError::Unlock)
}

/// Unlock with a passkey's PRF output.
pub fn open_with_prf(blob: &[u8], prf_output: &[u8]) -> Result<Zeroizing<[u8; DEK_LEN]>, EnvelopeError> {
    let kek = kek_from_prf(prf_output);
    open_with_kek(blob, &kek)
}

/// Unlock with the recovery code.
pub fn open_with_recovery(blob: &[u8], recovery_code: &str) -> Result<Zeroizing<[u8; DEK_LEN]>, EnvelopeError> {
    parse(blob)?;
    let kek = kek_from_recovery(recovery_code, &blob[SALT_OFF..SALT_OFF + SALT_LEN])?;
    open_with_kek(blob, &kek)
}
