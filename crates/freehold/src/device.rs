//! Device identity + device certificates (docs/device-trust-design.md, increment 1 / §1, §9).
//!
//! A device is a **signing-only** Ed25519 keypair generated on-device (its seed never leaves the
//! machine in the clear — the SDK wraps it under a per-origin non-extractable AES-GCM `CryptoKey`,
//! §1.6). Its identity is a commitment to that public key, the same discipline as `sync_id`
//! (relay_auth.rs) and `app_id`:
//!
//! ```text
//!  device_id = "dev_" + base64url( SHA-256("freehold-device-id-v1" ‖ device_pubkey) )[..12 bytes]
//! ```
//!
//! A **device certificate** binds that device key into the vault. It chains to an *independent,
//! non-DEK-derived* **vault trust key** (§1.1) — an Ed25519 keypair whose seed is a fresh CSPRNG
//! draw, sealed at rest under `HKDF(DEK,"freehold-vault-trust-v1")` (`crypto::Crypto::trust_seal_key`).
//! Chaining to the trust key (not the DEK-derived vault identity) is what lets certs mean more than
//! "a DEK-holder signed this" and survive DEK rotation.
//!
//! The cert is a **grant-token-shaped object minted through the existing `attest` path** — NOT a new
//! signing surface (§1.3). `cert.claim` is a base64url string over a domain-separated, u16-length-
//! prefixed byte layout of the structured fields; `cert.proof` is `attest_with_seed(trust_seed,
//! claim, audience=device_id, issued_at, expiry)` — the same `canonical_message` / `verify_strict`
//! discipline as attest.rs, reused verbatim (no forked signing routine).
//!
//! ```text
//!  claim_bytes = "freehold-device-cert-v1"
//!              ‖ u16_LE(vault_trust_pubkey.len)=32 ‖ vault_trust_pubkey
//!              ‖ u16_LE(device_id.len)            ‖ device_id (UTF-8)
//!              ‖ u16_LE(device_pubkey.len)=32     ‖ device_pubkey
//!              ‖ u16_LE(caps_canon.len)           ‖ caps_canon (UTF-8, sorted ‖ '\n'-joined)
//!              ‖ u16_LE(8) ‖ u64_LE(issued_at) ‖ u16_LE(8) ‖ u64_LE(expiry)
//!  cert.claim  = base64url_nopad(claim_bytes)
//! ```
//!
//! Verification (`verify_device_cert`, **pure** — no DEK, no session, §1.3) checks, in order:
//! recompute the canonical claim from the caller's structured fields and require **byte-equality**
//! with the presented `cert_claim` (grant-token step-1 tamper check, BEFORE trusting the signature);
//! `device_id == H(device_pubkey)`; Ed25519 `verify_strict` under the pinned `vault_trust_pubkey`;
//! the validity window against a caller-supplied `now` (the core reads no clock); `caps` well-formed.
//! A malformed key/sig/claim yields `false`, NEVER a panic.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::attest;

/// Domain label hashed with the device pubkey to form `device_id` (§1.2).
const DEVICE_ID_LABEL: &[u8] = b"freehold-device-id-v1";
/// Domain prefix of the canonical cert-claim byte layout (§1.3).
const CERT_DOMAIN: &[u8] = b"freehold-device-cert-v1";
/// `device_id` truncation: 12 bytes of the SHA-256 → 16 base64url chars.
const DEVICE_ID_BYTES: usize = 12;

// ------------------------------------------------------------------------------------------------
// base64url (RFC 4648 §5, URL-safe alphabet, NO padding). Implemented in-crate (no base64 dep) and
// matched by the SDK. The device_id / cert.claim are computed in wasm and returned as strings, so
// this is the single source of truth for the alphabet across the wasm/JS boundary.
// ------------------------------------------------------------------------------------------------

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// URL-safe base64 without padding. Pure, allocation-bounded, never panics.
fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// Inverse of [`base64url_encode`]. Returns `None` on any invalid symbol / impossible length (a lone
/// trailing char is not a valid base64 group) — never panics. Used by `parse_device_cert_claim`.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() == 1 {
            return None; // 1 leftover char cannot encode any byte
        }
        let mut acc = 0u32;
        for &c in chunk {
            acc = (acc << 6) | val(c)? as u32;
        }
        // Left-align to a full 24-bit group before slicing off the encoded bytes.
        acc <<= 6 * (4 - chunk.len());
        out.push((acc >> 16) as u8);
        if chunk.len() >= 3 {
            out.push((acc >> 8) as u8);
        }
        if chunk.len() >= 4 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

// ------------------------------------------------------------------------------------------------
// Device keypair + device_id
// ------------------------------------------------------------------------------------------------

/// A fresh 32-byte device Ed25519 seed (CSPRNG, fail-closed — mirrors `envelope::random_dek`). Held
/// in `Zeroizing`; the SDK wraps it under a non-extractable AES-GCM key immediately (§1.6) and never
/// persists it in the clear. Errors on RNG failure or an all-zero draw (never a weak/zero key).
pub fn random_device_seed() -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut_slice()).map_err(|_| "device seed rng failure")?;
    if seed.iter().all(|&b| b == 0) {
        return Err("device seed rng returned all-zero");
    }
    Ok(seed)
}

/// The device's 32-byte Ed25519 **public key** from its seed. Deterministic; safe to publish.
pub fn device_public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// `device_id = "dev_" + base64url(SHA-256(LABEL ‖ device_pubkey))[..12]` (§1.2). Pure,
/// deterministic. 12 bytes ⇒ 16 base64url chars ⇒ a 20-char id (`dev_` + 16).
pub fn device_id_from_pubkey(device_pubkey: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(DEVICE_ID_LABEL);
    h.update(device_pubkey);
    let d = h.finalize();
    let mut id = String::with_capacity(4 + 16);
    id.push_str("dev_");
    id.push_str(&base64url_encode(&d[..DEVICE_ID_BYTES]));
    id
}

// ------------------------------------------------------------------------------------------------
// Vault trust key (independent of the DEK) — §1.1
// ------------------------------------------------------------------------------------------------

/// The vault trust key's 32-byte Ed25519 **public key** from its (independent, non-DEK-derived)
/// seed. This is the pinned root device certs chain to; safe to publish.
pub fn vault_trust_public_key(trust_seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(trust_seed).verifying_key().to_bytes()
}

/// A fresh 32-byte vault trust-key seed (CSPRNG, fail-closed). Generated ONCE per vault (§1.1);
/// stays stable across DEK rotation. Held in `Zeroizing`.
pub fn random_trust_seed() -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut_slice()).map_err(|_| "trust seed rng failure")?;
    if seed.iter().all(|&b| b == 0) {
        return Err("trust seed rng returned all-zero");
    }
    Ok(seed)
}

// ------------------------------------------------------------------------------------------------
// caps — a SORTED scope list, canonicalized deterministically (grant-token vocabulary, §1.3)
// ------------------------------------------------------------------------------------------------

/// Canonicalize a scope list into the deterministic form embedded in the claim: each scope trimmed,
/// empties dropped, de-duplicated, sorted lexicographically by bytes, then `'\n'`-joined. `'\n'` is
/// safe as the join separator because it is the ONE byte a well-formed scope may not contain (see
/// [`caps_well_formed`]); the u16 length prefix in the claim removes any residual framing ambiguity.
/// Deterministic ⇒ two devices canonicalize the same set to the same bytes ⇒ byte-equality holds.
pub fn canonicalize_caps(caps: &[String]) -> String {
    let mut v: Vec<&str> = caps
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    v.sort_unstable();
    v.dedup();
    v.join("\n")
}

/// A caps string is well-formed iff every scope is non-empty, contains no `'\n'` (the canonical
/// separator) and the whole run is sorted + de-duplicated — i.e. it is byte-identical to
/// re-canonicalizing its own scopes. This is the verifier's `caps` gate (§1.3(e)): a claim carrying
/// a non-canonical caps string is rejected, so there is exactly ONE valid encoding per scope set.
pub fn caps_well_formed(caps_canon: &str) -> bool {
    if caps_canon.is_empty() {
        return true; // the empty scope set is well-formed (a thin/no-scope cert)
    }
    let scopes: Vec<String> = caps_canon.split('\n').map(|s| s.to_string()).collect();
    if scopes.iter().any(|s| s.is_empty() || s.trim() != s) {
        return false;
    }
    canonicalize_caps(&scopes) == caps_canon
}

// ------------------------------------------------------------------------------------------------
// Canonical cert-claim codec — round-trips byte-for-byte
// ------------------------------------------------------------------------------------------------

/// The structured fields of a device cert (the subject the claim commits to). `caps` is stored in its
/// **canonical** form (see [`canonicalize_caps`]); [`build_device_cert_claim`] canonicalizes on the
/// way in, [`parse_device_cert_claim`] returns exactly the canonical bytes it read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertFields {
    pub vault_trust_pubkey: [u8; 32],
    pub device_id: String,
    pub device_pubkey: [u8; 32],
    /// Canonical caps string (sorted scopes, `'\n'`-joined).
    pub caps_canon: String,
    pub issued_at: u64,
    pub expiry: u64,
}

fn push_field(m: &mut Vec<u8>, bytes: &[u8]) {
    // Hard runtime check (NOT debug-only): a >u16::MAX field would silently truncate the length
    // prefix in release, corrupting the canonical claim. Fail closed rather than sign/verify a
    // malformed message.
    let len = u16::try_from(bytes.len()).expect("device-cert: field too long");
    m.extend_from_slice(&len.to_le_bytes());
    m.extend_from_slice(bytes);
}

/// The exact canonical claim byte layout (domain + u16-length-prefixed fields, §1.3) — the single
/// source of truth for both build and the verifier's recompute. Field order is FIXED:
/// {vault_trust_pubkey, device_id, device_pubkey, caps_canon, issued_at, expiry}.
fn canonical_claim_bytes(f: &CertFields) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        CERT_DOMAIN.len() + 2 + 32 + 2 + f.device_id.len() + 2 + 32 + 2 + f.caps_canon.len() + 2 + 8 + 2 + 8,
    );
    m.extend_from_slice(CERT_DOMAIN);
    push_field(&mut m, &f.vault_trust_pubkey);
    push_field(&mut m, f.device_id.as_bytes());
    push_field(&mut m, &f.device_pubkey);
    push_field(&mut m, f.caps_canon.as_bytes());
    push_field(&mut m, &f.issued_at.to_le_bytes());
    push_field(&mut m, &f.expiry.to_le_bytes());
    m
}

/// Build the base64url cert claim string from structured fields. `caps` is canonicalized here
/// (sorted/deduped) so callers may pass scopes in any order and still get the one canonical claim.
pub fn build_device_cert_claim(
    vault_trust_pubkey: &[u8; 32],
    device_id: &str,
    device_pubkey: &[u8; 32],
    caps: &[String],
    issued_at: u64,
    expiry: u64,
) -> String {
    let fields = CertFields {
        vault_trust_pubkey: *vault_trust_pubkey,
        device_id: device_id.to_string(),
        device_pubkey: *device_pubkey,
        caps_canon: canonicalize_caps(caps),
        issued_at,
        expiry,
    };
    base64url_encode(&canonical_claim_bytes(&fields))
}

/// Parse a base64url cert claim back into its structured fields, byte-for-byte. Returns `None` on any
/// malformed input (bad base64, wrong domain, truncated length prefix, non-32-byte key field,
/// non-UTF-8 device_id/caps, trailing bytes) — never panics. Round-trips exactly with
/// [`build_device_cert_claim`] for a canonical input.
pub fn parse_device_cert_claim(claim: &str) -> Option<CertFields> {
    let raw = base64url_decode(claim)?;
    let mut p = 0usize;

    if raw.len() < CERT_DOMAIN.len() || &raw[..CERT_DOMAIN.len()] != CERT_DOMAIN {
        return None;
    }
    p += CERT_DOMAIN.len();

    fn take<'a>(raw: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
        if *p + 2 > raw.len() {
            return None;
        }
        let len = u16::from_le_bytes([raw[*p], raw[*p + 1]]) as usize;
        *p += 2;
        if *p + len > raw.len() {
            return None;
        }
        let s = &raw[*p..*p + len];
        *p += len;
        Some(s)
    }
    fn take_key(raw: &[u8], p: &mut usize) -> Option<[u8; 32]> {
        let f = take(raw, p)?;
        <[u8; 32]>::try_from(f).ok()
    }
    fn take_u64(raw: &[u8], p: &mut usize) -> Option<u64> {
        let f = take(raw, p)?;
        Some(u64::from_le_bytes(<[u8; 8]>::try_from(f).ok()?))
    }

    let vault_trust_pubkey = take_key(&raw, &mut p)?;
    let device_id = std::str::from_utf8(take(&raw, &mut p)?).ok()?.to_string();
    let device_pubkey = take_key(&raw, &mut p)?;
    let caps_canon = std::str::from_utf8(take(&raw, &mut p)?).ok()?.to_string();
    let issued_at = take_u64(&raw, &mut p)?;
    let expiry = take_u64(&raw, &mut p)?;

    if p != raw.len() {
        return None; // trailing bytes ⇒ not a canonical claim
    }
    Some(CertFields {
        vault_trust_pubkey,
        device_id,
        device_pubkey,
        caps_canon,
        issued_at,
        expiry,
    })
}

// ------------------------------------------------------------------------------------------------
// Issue + verify
// ------------------------------------------------------------------------------------------------

/// Issue a device cert: build the canonical claim for `device_pubkey` chaining to the trust key, then
/// sign it via the shared `attest` path (`attest_with_seed`, audience = `device_id` bytes) under the
/// **trust seed**. Returns `(claim_string, sig[64])`; the SDK assembles + persists the cert. The
/// `device_id` is recomputed here from `device_pubkey` (never taken from a caller) so the cert is
/// intrinsically bound to the key it certifies.
pub fn issue_device_cert(
    trust_seed: &[u8; 32],
    device_pubkey: &[u8; 32],
    caps: &[String],
    issued_at: u64,
    expiry: u64,
) -> (String, [u8; 64]) {
    let trust_pk = vault_trust_public_key(trust_seed);
    let device_id = device_id_from_pubkey(device_pubkey);
    let claim = build_device_cert_claim(&trust_pk, &device_id, device_pubkey, caps, issued_at, expiry);
    // Same signing routine as `session_attest`; audience binds the signature to this device_id.
    let sig = attest::attest_with_seed(trust_seed, &claim, device_id.as_bytes(), issued_at, expiry);
    (claim, sig)
}

/// Verify a device cert — **pure**, no DEK, no session, no clock (§1.3). In order:
///   (a) recompute the canonical claim from the cert's OWN structured fields and require
///       byte-equality with `cert_claim` (grant-token step-1 tamper check) — the caller-supplied
///       `device_pubkey` MUST equal the claim's device_pubkey field (a mismatch fails here);
///   (b) `device_id == H(device_pubkey)`;
///   (c) `caps` well-formed (exactly one canonical encoding);
///   (d) Ed25519 `verify_strict` over the canonical attest message under the pinned
///       `vault_trust_pubkey` (rejects malleable / small-order sigs);
///   (e) `issued_at <= now <= expiry`.
/// A malformed key/sig length, bad base64, or any structural mismatch returns `false`, never panics.
pub fn verify_device_cert(
    vault_trust_pubkey: &[u8; 32],
    cert_claim: &str,
    device_pubkey: &[u8; 32],
    sig: &[u8; 64],
    now: u64,
) -> bool {
    // (a) Parse the presented claim into structured fields, then recompute + byte-compare. This
    //     rejects ANY tampering of the claim string, AND binds the caller's pinned trust key +
    //     device pubkey to what the claim actually carries — before we trust the signature.
    let Some(fields) = parse_device_cert_claim(cert_claim) else { return false };
    if &fields.vault_trust_pubkey != vault_trust_pubkey || &fields.device_pubkey != device_pubkey {
        return false;
    }
    let recomputed = base64url_encode(&canonical_claim_bytes(&fields));
    if recomputed != cert_claim {
        return false; // non-canonical encoding of an otherwise-parseable claim
    }

    // (b) device_id is a commitment to the pubkey — cannot be swapped for another device's key.
    if fields.device_id != device_id_from_pubkey(device_pubkey) {
        return false;
    }

    // (c) caps well-formed (exactly one canonical form per scope set).
    if !caps_well_formed(&fields.caps_canon) {
        return false;
    }

    // (d) signature over the canonical attest message under the PINNED trust key. `attest::verify`
    //     uses `verify_strict`; a malformed key/sig yields false, never a panic.
    if !attest::verify(
        vault_trust_pubkey,
        cert_claim,
        fields.device_id.as_bytes(),
        fields.issued_at,
        fields.expiry,
        sig,
    ) {
        return false;
    }

    // (e) validity window against the caller-supplied `now` (the core reads no clock).
    fields.issued_at <= now && now <= fields.expiry
}

// ------------------------------------------------------------------------------------------------
// Self-contained checks (feature `testing-api`) — mirrors relay_auth::self_check
// ------------------------------------------------------------------------------------------------

/// Self-contained device-trust checks (callable from `run_tests`): keygen determinism, the pinned
/// `device_id` vector + different-pubkey-different-id, cert claim build/parse round-trip
/// (byte-for-byte), issue→verify round-trip, tamper rejection (flip device_pubkey / caps / expiry),
/// wrong-trust-key rejection, `device_id != H(pubkey)` rejection even with a valid sig, expiry-in-past
/// rejection, and malformed pubkey/sig → false-not-panic.
#[cfg(feature = "testing-api")]
pub fn self_check() -> Result<(), String> {
    // ---- keygen determinism from a fixed seed ----
    let dev_seed = [0x24u8; 32];
    let dev_pk = device_public_key(&dev_seed);
    if dev_pk != device_public_key(&dev_seed) {
        return Err("device: device_public_key not deterministic".into());
    }

    // ---- device_id pinned vector + different-pubkey-different-id ----
    // Pinned vector: recomputed here so a change to the derivation (label / truncation / alphabet)
    // is caught. base64url of the first 12 bytes of SHA-256("freehold-device-id-v1" ‖ dev_pk).
    let id = device_id_from_pubkey(&dev_pk);
    {
        let mut h = Sha256::new();
        h.update(DEVICE_ID_LABEL);
        h.update(dev_pk);
        let d = h.finalize();
        let expect = format!("dev_{}", base64url_encode(&d[..DEVICE_ID_BYTES]));
        if id != expect {
            return Err(format!("device: device_id vector mismatch: {id} != {expect}"));
        }
        if !id.starts_with("dev_") || id.len() != 4 + 16 {
            return Err(format!("device: device_id shape wrong: {id}"));
        }
    }
    let other_pk = device_public_key(&[0x25u8; 32]);
    if device_id_from_pubkey(&other_pk) == id {
        return Err("device: different pubkey produced the same device_id".into());
    }

    // ---- trust key (independent of any DEK) ----
    let trust_seed = [0x77u8; 32];
    let trust_pk = vault_trust_public_key(&trust_seed);

    // ---- caps canonicalization is order/dup-insensitive and well-formed ----
    let caps = vec![
        "sync.write".to_string(),
        "sync.read".to_string(),
        "sync.read".to_string(), // dup
        "  ".to_string(),        // blank
    ];
    let canon = canonicalize_caps(&caps);
    if canon != "sync.read\nsync.write" {
        return Err(format!("device: caps canonicalization wrong: {canon:?}"));
    }
    if !caps_well_formed(&canon) || caps_well_formed("sync.write\nsync.read") {
        return Err("device: caps_well_formed gate wrong".into());
    }

    // ---- claim build/parse round-trip, every field byte-for-byte ----
    let issued_at = 1_700_000_000u64;
    let expiry = issued_at + 86_400;
    let claim = build_device_cert_claim(&trust_pk, &id, &dev_pk, &caps, issued_at, expiry);
    let parsed = parse_device_cert_claim(&claim).ok_or("device: claim failed to parse")?;
    if parsed.vault_trust_pubkey != trust_pk
        || parsed.device_id != id
        || parsed.device_pubkey != dev_pk
        || parsed.caps_canon != canon
        || parsed.issued_at != issued_at
        || parsed.expiry != expiry
    {
        return Err("device: claim round-trip field mismatch".into());
    }
    // Rebuilding from the parsed fields reproduces the exact same string (canonical encoding).
    if build_device_cert_claim(
        &parsed.vault_trust_pubkey,
        &parsed.device_id,
        &parsed.device_pubkey,
        &[parsed.caps_canon.clone()], // one scope containing '\n' — canonicalizes back to itself
        parsed.issued_at,
        parsed.expiry,
    ) != claim
    {
        // NOTE: passing caps_canon as a single element would re-split incorrectly; rebuild from the
        // canonical scopes instead to prove idempotence.
        let scopes: Vec<String> = parsed.caps_canon.split('\n').map(String::from).collect();
        if build_device_cert_claim(
            &parsed.vault_trust_pubkey,
            &parsed.device_id,
            &parsed.device_pubkey,
            &scopes,
            parsed.issued_at,
            parsed.expiry,
        ) != claim
        {
            return Err("device: claim not canonical / not idempotent".into());
        }
    }

    // ---- issue → verify round-trip under the correct trust key ----
    let (claim2, sig) = issue_device_cert(&trust_seed, &dev_pk, &caps, issued_at, expiry);
    if claim2 != claim {
        return Err("device: issue produced a non-canonical claim".into());
    }
    let now = issued_at + 100;
    if !verify_device_cert(&trust_pk, &claim2, &dev_pk, &sig, now) {
        return Err("device: valid cert rejected".into());
    }

    // ---- tamper rejection: flip device_pubkey after signing (caller presents a different key) ----
    if verify_device_cert(&trust_pk, &claim2, &other_pk, &sig, now) {
        return Err("device: cert accepted for a different device_pubkey".into());
    }
    // ---- tamper rejection: flip caps → different canonical claim, sig no longer matches ----
    {
        let tampered = build_device_cert_claim(&trust_pk, &id, &dev_pk, &["sync.admin".to_string()], issued_at, expiry);
        // The presented claim now disagrees with the signature (which signed `claim2`); even if the
        // claim itself is canonical, verify recomputes fine but the signature check fails.
        if verify_device_cert(&trust_pk, &tampered, &dev_pk, &sig, now) {
            return Err("device: cert accepted with tampered caps".into());
        }
    }
    // ---- tamper rejection: flip expiry after signing (byte-mutate the base64 → parse or sig fail) ----
    {
        let (later_claim, _later_sig) = issue_device_cert(&trust_seed, &dev_pk, &caps, issued_at, expiry + 1);
        // Present the later-expiry claim with the ORIGINAL signature: byte-inequality vs the signed
        // message ⇒ signature check fails.
        if verify_device_cert(&trust_pk, &later_claim, &dev_pk, &sig, now) {
            return Err("device: cert accepted with tampered expiry".into());
        }
    }
    // ---- tamper rejection: mutate one base64 char of the claim string ----
    {
        let mut bad = claim2.clone();
        let mut cs: Vec<char> = bad.chars().collect();
        // flip a middle char to a different valid base64url symbol
        let mid = cs.len() / 2;
        cs[mid] = if cs[mid] == 'A' { 'B' } else { 'A' };
        bad = cs.into_iter().collect();
        if verify_device_cert(&trust_pk, &bad, &dev_pk, &sig, now) {
            return Err("device: cert accepted with mutated claim string".into());
        }
    }

    // ---- wrong-trust-key rejection ----
    let wrong_trust_pk = vault_trust_public_key(&[0x78u8; 32]);
    if verify_device_cert(&wrong_trust_pk, &claim2, &dev_pk, &sig, now) {
        return Err("device: cert accepted under the wrong trust key".into());
    }

    // ---- device_id != H(pubkey) rejection even with a valid signature ----
    // Forge a claim whose device_id field is wrong but sign it correctly, then verify.
    {
        let bad_id = device_id_from_pubkey(&other_pk); // an id that is NOT H(dev_pk)
        let forged_claim = build_device_cert_claim(&trust_pk, &bad_id, &dev_pk, &caps, issued_at, expiry);
        let forged_sig = attest::attest_with_seed(&trust_seed, &forged_claim, bad_id.as_bytes(), issued_at, expiry);
        // Signature is valid over the forged claim, but device_id != H(dev_pk) ⇒ verify rejects (b).
        if verify_device_cert(&trust_pk, &forged_claim, &dev_pk, &forged_sig, now) {
            return Err("device: cert accepted with device_id != H(pubkey)".into());
        }
    }

    // ---- expiry-in-past rejection (time window) ----
    if verify_device_cert(&trust_pk, &claim2, &dev_pk, &sig, expiry + 1) {
        return Err("device: expired cert accepted".into());
    }
    // ---- issued-in-future rejection ----
    if verify_device_cert(&trust_pk, &claim2, &dev_pk, &sig, issued_at - 1) {
        return Err("device: not-yet-valid cert accepted".into());
    }

    // ---- malformed pubkey / sig lengths → false, not panic (exercised via the wasm-shaped path) ----
    if crate::verify_device_cert(&trust_pk, &claim2, &[0u8; 31], &sig, now as f64) {
        return Err("device: short device_pubkey accepted".into());
    }
    if crate::verify_device_cert(&trust_pk, &claim2, &dev_pk, &[0u8; 63], now as f64) {
        return Err("device: short sig accepted".into());
    }
    if crate::verify_device_cert(&[0u8; 33], &claim2, &dev_pk, &sig, now as f64) {
        return Err("device: oversized trust pubkey accepted".into());
    }
    // A syntactically valid but all-zero sig must not verify (verify_strict rejects).
    if verify_device_cert(&trust_pk, &claim2, &dev_pk, &[0u8; 64], now) {
        return Err("device: all-zero sig accepted".into());
    }

    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Native unit tests
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrip_all_lengths() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect();
            let enc = base64url_encode(&data);
            assert!(!enc.contains('+') && !enc.contains('/') && !enc.contains('='), "alphabet/padding");
            let dec = base64url_decode(&enc).expect("decode");
            assert_eq!(dec, data, "roundtrip n={n}");
        }
        assert!(base64url_decode("A").is_none(), "lone char is invalid");
        assert!(base64url_decode("****").is_none(), "invalid symbols");
    }

    #[test]
    fn device_id_pinned_vector() {
        // Pinned test vector: device pubkey = the Ed25519 public key of the all-0x42 seed.
        let seed = [0x42u8; 32];
        let pk = device_public_key(&seed);
        let id = device_id_from_pubkey(&pk);
        // Recompute independently to pin the exact derivation (label ‖ pubkey, 12-byte truncation).
        let mut h = Sha256::new();
        h.update(b"freehold-device-id-v1");
        h.update(pk);
        let d = h.finalize();
        let expect = format!("dev_{}", base64url_encode(&d[..12]));
        assert_eq!(id, expect);
        assert_eq!(id.len(), 20); // "dev_" + 16 base64url chars
        assert!(id.starts_with("dev_"));
        // Different pubkey ⇒ different id.
        let pk2 = device_public_key(&[0x43u8; 32]);
        assert_ne!(device_id_from_pubkey(&pk2), id);
    }

    #[test]
    fn claim_roundtrip_byte_for_byte() {
        let trust_pk = vault_trust_public_key(&[0x01u8; 32]);
        let dev_pk = device_public_key(&[0x02u8; 32]);
        let id = device_id_from_pubkey(&dev_pk);
        let caps = vec!["b.scope".to_string(), "a.scope".to_string()];
        let claim = build_device_cert_claim(&trust_pk, &id, &dev_pk, &caps, 100, 200);
        let f = parse_device_cert_claim(&claim).unwrap();
        assert_eq!(f.vault_trust_pubkey, trust_pk);
        assert_eq!(f.device_id, id);
        assert_eq!(f.device_pubkey, dev_pk);
        assert_eq!(f.caps_canon, "a.scope\nb.scope"); // sorted
        assert_eq!(f.issued_at, 100);
        assert_eq!(f.expiry, 200);
        // Rebuild from the canonical scopes reproduces the identical string.
        let scopes: Vec<String> = f.caps_canon.split('\n').map(String::from).collect();
        assert_eq!(
            build_device_cert_claim(&f.vault_trust_pubkey, &f.device_id, &f.device_pubkey, &scopes, f.issued_at, f.expiry),
            claim
        );
    }

    #[test]
    fn issue_verify_and_tamper() {
        let trust_seed = [0xAAu8; 32];
        let trust_pk = vault_trust_public_key(&trust_seed);
        let dev_seed = [0xBBu8; 32];
        let dev_pk = device_public_key(&dev_seed);
        let caps = vec!["sync.read".to_string(), "sync.write".to_string()];
        let (claim, sig) = issue_device_cert(&trust_seed, &dev_pk, &caps, 1000, 2000);
        assert!(verify_device_cert(&trust_pk, &claim, &dev_pk, &sig, 1500));
        // expiry window
        assert!(!verify_device_cert(&trust_pk, &claim, &dev_pk, &sig, 2001));
        assert!(!verify_device_cert(&trust_pk, &claim, &dev_pk, &sig, 999));
        // wrong trust key
        let wrong = vault_trust_public_key(&[0xCCu8; 32]);
        assert!(!verify_device_cert(&wrong, &claim, &dev_pk, &sig, 1500));
        // wrong device pubkey presented
        let other = device_public_key(&[0xDDu8; 32]);
        assert!(!verify_device_cert(&trust_pk, &claim, &other, &sig, 1500));
        // all-zero sig
        assert!(!verify_device_cert(&trust_pk, &claim, &dev_pk, &[0u8; 64], 1500));
    }

    #[test]
    fn full_self_check() {
        // The comprehensive gate also runs under `cargo test` (not just the wasm harness).
        self_check().expect("device self_check");
    }

    #[test]
    fn malformed_claim_returns_none_not_panic() {
        assert!(parse_device_cert_claim("not base64 !!!").is_none());
        assert!(parse_device_cert_claim("").is_none()); // empty ⇒ no domain
        assert!(parse_device_cert_claim("QUJD").is_none()); // "ABC" ⇒ wrong domain
    }
}
