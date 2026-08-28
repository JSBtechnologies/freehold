//! The trusted crypto core of the encrypting VFS — keep this file small and reviewable.
//!
//! This is the *entire* cryptographic boundary (design-spec §2). Everything else is plumbing.
//! It implements the per-block AEAD of the "encrypted block device" (design-spec §4/§5/§6):
//!
//! ```text
//!  physical block k  =  [ ciphertext (B) | nonce (24) | tag (16) ]     P = B + 24 + 16
//!  seal( key=K, nonce=random24, plaintext=B-byte block,
//!        aad = file_id(16) || key_domain(16) || block_index_LE(8) || B_LE(4) || cipher_id(1) ) // §17.L
//! ```
//! `key_domain` = the owning DB's `db_uuid` (zeros for pool/temp files) — a redundant AAD-layer
//! bind on top of the per-DB *key* separation (§17.E), so cross-DB block transplant fails at the
//! AAD check even in the impossible event two DBs derived the same `K_db` (security-review 3d).
//!
//! Design decisions realised here (see design-spec.md §17 for the normative list):
//!   * §5  cipher  = XChaCha20-Poly1305 (RustCrypto), used as-is — NOT invented crypto.
//!   * §8  nonce   = fresh CSPRNG draw per seal; 192-bit nonce ⇒ no counter, crash-safe.
//!   * §17.F RNG fail-closed: self-test at install; every seal hard-errors on RNG failure or an
//!           all-zero nonce — never a non-random fallback.
//!   * §17.L AAD binds position (file_id, block_index) AND framing (B, cipher_id).
//!   * §17.M in-place seal/open on a caller-owned buffer; key material in `Zeroizing`.
//!   * §17.E per-DB subkey via HKDF (M2): every main DB derives `K_db = HKDF(DEK, "vfs-db-v1"‖db_uuid)`
//!           from the random 128-bit `db_uuid` in its manifest — a wrong-DB manifest fails to
//!           *decrypt*, not merely an AAD check. Files not attributable to a DB (temp) use the
//!           pool-domain subkey; the anchor file uses its own domain.

use chacha20poly1305::{
    aead::AeadInPlace, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Plaintext block size `B`. MUST equal the SQLite page size (design-spec §17.I). Fixed at 4096
/// in M1; a runtime `page_size == B` check is a Milestone-2 item (see BUILD-NOTES).
pub const BLOCK_SIZE: usize = 4096;
/// XChaCha20-Poly1305 nonce length (§5). 24 bytes ⇒ random-nonce-per-write is safe indefinitely.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Physical (on-disk) block size `P = B + Nn + 16` (design-spec §4).
pub const PHYS_BLOCK: usize = BLOCK_SIZE + NONCE_LEN + TAG_LEN;
/// Cipher identifier bound into AAD and (later) the manifest. 1 = XChaCha20-Poly1305.
pub const CIPHER_ID: u8 = 1;
/// Length of a `file_id` (security-review 6: widened 8→16 bytes ⇒ 2⁻¹²⁸ collision, no exploitable
/// AAD-domain overlap over any realistic file set).
pub const FILE_ID_LEN: usize = 16;
/// Length of the per-block `key_domain` (= owning DB's `db_uuid`; zeros for pool/temp).
pub const KEY_DOMAIN_LEN: usize = 16;
/// A `key_domain` value for files with no owning database (pool/temp) and for the anchor.
pub const NO_DOMAIN: [u8; KEY_DOMAIN_LEN] = [0u8; KEY_DOMAIN_LEN];

const AAD_LEN: usize = FILE_ID_LEN + KEY_DOMAIN_LEN + 8 + 4 + 1; // fid|domain|blk|B|cipher (§17.L)

/// Errors from the crypto core. All map to `SQLITE_IOERR` at the VFS boundary (design-spec §17.K):
/// an AEAD failure is tamper/corruption, never EOF — the caller must NOT turn it into a short read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// CSPRNG unavailable or produced an all-zero nonce (§17.F) — fail closed, no write.
    Rng,
    /// AEAD seal failed (should not happen for well-formed input).
    Seal,
    /// AEAD open/authentication failed — wrong key, tampered ciphertext, or relocated block.
    Open,
}

/// Holds one HKDF-derived block subkey. The DEK itself is never stored here.
///
/// Three derivation domains (§17.E):
///   * [`Crypto::db_key`]     — `HKDF(DEK, "enc-sahpool/vfs-db-v1" ‖ db_uuid)`: all blocks of a main
///     DB and its satellite files (journal/wal). Salted by the DB's random `db_uuid`, so a manifest
///     moved to another DB (or opened with another DEK) fails to decrypt outright.
///   * [`Crypto::pool_key`]   — `HKDF(DEK, "enc-sahpool-v1")`: files not attributable to a DB (temp).
///   * [`Crypto::anchor_key`] — `HKDF(DEK, "enc-sahpool-anchor-v1")`: the TrustedGeneration anchor.
pub struct Crypto {
    cipher: XChaCha20Poly1305,
}

impl Crypto {
    fn from_info(dek: &[u8; 32], info: &[u8]) -> Self {
        // Salt = None ⇒ RFC-5869 uses an all-zero HMAC key for extract. Sound here: the DEK is a
        // uniformly-random 256-bit key, so a non-trivial salt adds no security (security-review 4b).
        let hk = Hkdf::<Sha256>::new(None, dek);
        let mut k = Zeroizing::new([0u8; 32]);
        hk.expand(info, k.as_mut_slice())
            .expect("HKDF expand of 32 bytes never fails");
        Crypto {
            cipher: XChaCha20Poly1305::new(Key::from_slice(k.as_slice())),
        }
    }

    /// Pool-domain subkey (files with no owning DB, e.g. temp files that reach the VFS).
    pub fn pool_key(dek: &[u8; 32]) -> Self {
        Self::from_info(dek, b"enc-sahpool-v1")
    }

    /// Per-DB subkey `K_db` (§17.E), salted by the DB's random 128-bit `db_uuid`.
    pub fn db_key(dek: &[u8; 32], db_uuid: &[u8; 16]) -> Self {
        let mut info = [0u8; 22 + 16];
        info[..22].copy_from_slice(b"enc-sahpool/vfs-db-v1\0");
        info[22..].copy_from_slice(db_uuid);
        Self::from_info(dek, &info)
    }

    /// Subkey sealing the local `TrustedGeneration` anchor file (§10.4/§17.D).
    pub fn anchor_key(dek: &[u8; 32]) -> Self {
        Self::from_info(dek, b"enc-sahpool-anchor-v1")
    }

    /// Seal one `B`-byte plaintext block into `out` (`P` bytes: ciphertext‖nonce‖tag), in place.
    ///
    /// A fresh CSPRNG nonce is drawn per call (§8). Fails closed on any RNG problem (§17.F).
    pub fn seal_into(
        &self,
        file_id: &[u8; FILE_ID_LEN],
        key_domain: &[u8; KEY_DOMAIN_LEN],
        block_index: u64,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert_eq!(plaintext.len(), BLOCK_SIZE);
        assert_eq!(out.len(), PHYS_BLOCK);

        // §17.F — fresh random nonce, fail closed. Never fall back to a deterministic nonce.
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| CryptoError::Rng)?;
        if nonce.iter().all(|&b| b == 0) {
            return Err(CryptoError::Rng);
        }

        // Ciphertext is produced in place over out[0..B]; copy plaintext in first.
        out[..BLOCK_SIZE].copy_from_slice(plaintext);
        let aad = aad(file_id, key_domain, block_index);
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, &mut out[..BLOCK_SIZE])
            .map_err(|_| CryptoError::Seal)?;

        out[BLOCK_SIZE..BLOCK_SIZE + NONCE_LEN].copy_from_slice(&nonce);
        out[BLOCK_SIZE + NONCE_LEN..].copy_from_slice(&tag);
        Ok(())
    }

    /// Open one `P`-byte physical block (`phys`) into `out` (`B` bytes plaintext), in place.
    ///
    /// Returns `CryptoError::Open` on any authentication failure — the caller maps that to
    /// `SQLITE_IOERR`, NEVER a short read (§17.K).
    pub fn open_into(
        &self,
        file_id: &[u8; FILE_ID_LEN],
        key_domain: &[u8; KEY_DOMAIN_LEN],
        block_index: u64,
        phys: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert_eq!(phys.len(), PHYS_BLOCK);
        assert_eq!(out.len(), BLOCK_SIZE);

        out.copy_from_slice(&phys[..BLOCK_SIZE]);
        let nonce = &phys[BLOCK_SIZE..BLOCK_SIZE + NONCE_LEN];
        let tag = &phys[BLOCK_SIZE + NONCE_LEN..];
        let aad = aad(file_id, key_domain, block_index);
        self.cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce),
                &aad,
                out,
                Tag::from_slice(tag),
            )
            .map_err(|_| CryptoError::Open)
    }
}

/// Stable per-file identifier bound into AAD (design-spec §6/§17.H): first 16 bytes of
/// SHA-256(canonical path). Distinct files ⇒ distinct AAD domain ⇒ a valid block from one file
/// cannot authenticate in another. (The VFS filename is the canonical path.)
pub fn file_id_for(path: &str) -> [u8; FILE_ID_LEN] {
    let digest = Sha256::digest(path.as_bytes());
    let mut id = [0u8; FILE_ID_LEN];
    id.copy_from_slice(&digest[..FILE_ID_LEN]);
    id
}

/// Build the AAD: `file_id(16) ‖ key_domain(16) ‖ block_index_LE(8) ‖ B_LE(4) ‖ cipher_id(1)` (§17.L).
fn aad(
    file_id: &[u8; FILE_ID_LEN],
    key_domain: &[u8; KEY_DOMAIN_LEN],
    block_index: u64,
) -> [u8; AAD_LEN] {
    let mut a = [0u8; AAD_LEN];
    let mut at = 0;
    a[at..at + FILE_ID_LEN].copy_from_slice(file_id);
    at += FILE_ID_LEN;
    a[at..at + KEY_DOMAIN_LEN].copy_from_slice(key_domain);
    at += KEY_DOMAIN_LEN;
    a[at..at + 8].copy_from_slice(&block_index.to_le_bytes());
    at += 8;
    a[at..at + 4].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
    at += 4;
    a[at] = CIPHER_ID;
    a
}

/// Fresh random 128-bit `db_uuid` for a newly created database (§17.E). Fail-closed on RNG error.
pub fn random_uuid() -> Result<[u8; 16], CryptoError> {
    let mut u = [0u8; 16];
    getrandom::getrandom(&mut u).map_err(|_| CryptoError::Rng)?;
    if u.iter().all(|&b| b == 0) {
        return Err(CryptoError::Rng);
    }
    Ok(u)
}

/// CSPRNG self-test run once at VFS registration (§17.F). Returns false ⇒ registration fails
/// closed (the DB never opens with a broken RNG). Three independent 32-byte draws must be pairwise
/// distinct AND each carry a plausible number of non-zero bytes — the byte-population floor rejects
/// a stuck-low/biased source that returns distinct-but-degenerate values (security-review 2b), not
/// just an all-zero one.
pub fn rng_selftest() -> bool {
    let mut draws = [[0u8; 32]; 3];
    for d in &mut draws {
        if getrandom::getrandom(d).is_err() {
            return false;
        }
        // A healthy 32-byte draw has ~⁠1/256 chance per byte of being zero; fewer than 8 non-zero
        // bytes (of 32) is a ~⁠2⁻⁸⁰ fluke for a real CSPRNG but the signature of a biased source.
        if d.iter().filter(|&&x| x != 0).count() < 8 {
            return false;
        }
    }
    draws[0] != draws[1] && draws[1] != draws[2] && draws[0] != draws[2]
}
