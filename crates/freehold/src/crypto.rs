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
///   * [`Crypto::db_key`]     — `HKDF(DEK, "freehold/vfs-db-v1" ‖ db_uuid)`: all blocks of a main
///     DB and its satellite files (journal/wal). Salted by the DB's random `db_uuid`, so a manifest
///     moved to another DB (or opened with another DEK) fails to decrypt outright.
///   * [`Crypto::pool_key`]   — `HKDF(DEK, "freehold-v1")`: files not attributable to a DB (temp).
///   * [`Crypto::anchor_key`] — `HKDF(DEK, "freehold-anchor-v1")`: the TrustedGeneration anchor.
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
        Self::from_info(dek, b"freehold-v1")
    }

    /// Per-DB subkey `K_db` (§17.E), salted by the DB's random 128-bit `db_uuid`.
    pub fn db_key(dek: &[u8; 32], db_uuid: &[u8; 16]) -> Self {
        let mut info = [0u8; 19 + 16];
        info[..19].copy_from_slice(b"freehold/vfs-db-v1\0");
        info[19..].copy_from_slice(db_uuid);
        Self::from_info(dek, &info)
    }

    /// Subkey sealing the local `TrustedGeneration` anchor file (§10.4/§17.D).
    pub fn anchor_key(dek: &[u8; 32]) -> Self {
        Self::from_info(dek, b"freehold-anchor-v1")
    }

    /// Subkey authenticating cross-device **sync-epoch tokens** (sync-epoch-design §4). Any of a
    /// user's devices (all sharing the DEK) can mint/verify an epoch; an attacker without the DEK
    /// cannot forge one.
    pub fn epoch_key(dek: &[u8; 32]) -> Self {
        Self::from_info(dek, b"freehold-epoch-v1")
    }

    /// Subkey sealing the cross-device **sync blob** (freehold-sync-design §5/§10). The sync layer
    /// wraps the already-encrypted `.freehold` bundle plus its sync metadata (version vector) under
    /// this key so a blind relay stores only ciphertext (§3 leakage bound). Domain-separated from
    /// every other subkey; any of a user's devices (all sharing the DEK) can seal/open, an attacker
    /// without the DEK cannot. This adds NO new cryptography — same `seal_bytes`/`open_bytes` AEAD.
    pub fn sync_key(dek: &[u8; 32]) -> Self {
        Self::from_info(dek, b"freehold-sync-v1")
    }

    /// Subkey sealing the **DEK-rotation intent record** (issue #4 / D-RK4). During a rotation the
    /// staged shadow image + intent are sealed under DEK′; the intent authenticates ONLY under DEK′,
    /// so on the next open "does the intent decrypt under the DEK I just unlocked?" is exactly the
    /// crash-recovery signal — it opens on the post-commit (new) line and fails on the pre-commit
    /// (old) line, deciding roll-forward vs. roll-back. Domain-separated; no new cryptography.
    pub fn rotate_intent_key(dek: &[u8; 32]) -> Self {
        Self::from_info(dek, b"freehold-rotate-intent-v1")
    }

    /// Subkey sealing the **independent vault trust-key seed** (device-trust-design §1.1/§1.5). The
    /// trust key is a standalone Ed25519 keypair (its seed is a fresh CSPRNG draw, NOT HKDF(DEK,…) —
    /// see `device::vault_trust_public_key`); at rest its 32-byte seed is sealed under
    /// `HKDF(DEK, "freehold-vault-trust-v1")` as its own envelope-adjacent slot, carried in the
    /// bundle. This is a *seal domain*, not the key itself: the trust keypair stays stable across DEK
    /// rotation (only the sealing key changes), which is exactly what lets device certs survive
    /// rotation. Domain-separated from every other subkey; no new cryptography — same
    /// `seal_bytes`/`open_bytes` AEAD.
    pub fn trust_seal_key(dek: &[u8; 32]) -> Self {
        Self::from_info(dek, b"freehold-vault-trust-v1")
    }
}

// The per-database **sync-id** (the blind-relay bucket name) now lives in `relay_auth` — it is bound
// to the relay-auth public key (`SHA-256(LABEL ‖ pubkey)[..16]`) so the relay can authorize access
// statelessly (docs/relay-auth-design.md, D-RA1). It moved out of this file to keep the crypto core
// scoped to the block/blob AEAD; `relay_auth::sync_id` is the single source of truth.

impl Crypto {

    /// General small-payload AEAD seal for variable-length authenticated blobs (epoch tokens, etc.).
    /// Output = `nonce(24) || ciphertext || tag(16)`. Fresh random nonce, fail-closed (§17.F).
    pub fn seal_bytes(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| CryptoError::Rng)?;
        if nonce.iter().all(|&b| b == 0) {
            return Err(CryptoError::Rng);
        }
        let mut buf = plaintext.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), aad, &mut buf)
            .map_err(|_| CryptoError::Seal)?;
        let mut out = Vec::with_capacity(NONCE_LEN + buf.len() + TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Inverse of [`Crypto::seal_bytes`]. Authentication failure → `CryptoError::Open`.
    pub fn open_bytes(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Open);
        }
        let (nonce, rest) = sealed.split_at(NONCE_LEN);
        let (ct, tag) = rest.split_at(rest.len() - TAG_LEN);
        let mut buf = ct.to_vec();
        self.cipher
            .decrypt_in_place_detached(XNonce::from_slice(nonce), aad, &mut buf, Tag::from_slice(tag))
            .map_err(|_| CryptoError::Open)?;
        Ok(buf)
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

/// Domain-separation label for the full-state root leaf/interior hashes (freehold-vfs-merkle-root
/// D-MR1). Bound into every hash so a root can never collide with any other SHA-256 use in the core.
const MERKLE_ROOT_LABEL: &[u8] = b"freehold/full-state-root-v1";

/// Incremental accumulator for a full-state root over a DB's plaintext blocks (D-MR1).
///
/// v1 form = a deterministic **flat hash-of-hashes**, index-ordered:
///   root = SHA-256( LABEL ‖ block_count_LE(8) ‖ leaf_0 ‖ leaf_1 ‖ … )
///   leaf_k = SHA-256( LABEL ‖ block_index_LE(8) ‖ plaintext_block_k )
///
/// This is a hash, not a cipher — the "no new crypto primitive for confidentiality" invariant holds
/// (SHA-256 is already in the trusted core for HKDF + file_id). It is **stable across devices** for
/// identical logical state: it depends only on plaintext content + block order, never on nonces,
/// ciphertext, db_uuid, or physical layout. A flat hash-of-hashes (not a full Merkle tree) is
/// accepted for v1 — correctness first; a tree is a future optimization for incremental update
/// (noted in the topic). Binding the leaf index defends against block reordering/relocation, and
/// binding the count defends against truncation/extension of the block set.
pub struct FullStateRoot {
    hasher: Sha256,
    count: u64,
}

impl FullStateRoot {
    pub fn new() -> Self {
        // The running hasher absorbs LABEL, then each leaf digest as it arrives (`update_block`),
        // then the total block count last (`finish`). The count is folded in at the END — once it
        // is known — not reserved up front; see `finish`.
        let mut hasher = Sha256::new();
        hasher.update(MERKLE_ROOT_LABEL);
        FullStateRoot { hasher, count: 0 }
    }

    /// Absorb one `B`-byte plaintext block at `block_index` (indices MUST be fed in ascending order,
    /// contiguously from 0 — the caller iterates the block device in index order).
    pub fn update_block(&mut self, block_index: u64, plaintext: &[u8]) {
        let mut leaf = Sha256::new();
        leaf.update(MERKLE_ROOT_LABEL);
        leaf.update(block_index.to_le_bytes());
        leaf.update(plaintext);
        let leaf = leaf.finalize();
        self.hasher.update(leaf);
        self.count += 1;
    }

    /// Finalize the root. Folds in the block count so a shorter/longer block set never yields the
    /// same root as a prefix/superset (truncation/extension resistance).
    pub fn finish(mut self) -> [u8; 32] {
        self.hasher.update(self.count.to_le_bytes());
        let d = self.hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }
}

impl Default for FullStateRoot {
    fn default() -> Self {
        Self::new()
    }
}

/// The sentinel "no root yet" value = all zeros (D-MR2). Distinguishable from a real root with
/// overwhelming probability (a real SHA-256 output is all-zero with probability 2⁻²⁵⁶).
pub const ZERO_ROOT: [u8; 32] = [0u8; 32];

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
