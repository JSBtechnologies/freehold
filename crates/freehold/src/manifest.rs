//! Manifest + TrustedGeneration-anchor payload formats (design-spec §10, §17.C/D/E/J).
//!
//! The **manifest** is a per-database pool file named `<db>#manifest`. Its data region:
//! ```text
//!   0..8    magic "ENCMFST1"                (plaintext)
//!   8..24   db_uuid (random 128-bit)        (plaintext — needed to derive K_db before decrypting)
//!   24..64  reserved (zeros)
//!   64..64+P        slot 0  = seal(K_db, payload, aad = manifest_file_id ‖ 0 ‖ B ‖ cipher_id)
//!   64+P..64+2P     slot 1  = seal(K_db, payload, aad = manifest_file_id ‖ 1 ‖ B ‖ cipher_id)
//! ```
//! Two slots, ping-pong by `db_generation % 2` (§17.C): a torn manifest write can never brick the
//! DB — open picks the highest-generation slot that authenticates and rejects only if both fail.
//!
//! The **anchor** is a DOUBLE-BUFFERED sealed block in `anchor.bin` (outside the pool), holding
//! the §17.D `{committed, in_flight}` window per `db_uuid` plus a monotonic write `seq`. Two slots
//! (block 0 and block 1), ping-ponged by `seq % 2` (security-review 6): a torn anchor write can no
//! longer silently nullify rollback protection — load picks the highest-`seq` slot that
//! authenticates, so the prior slot survives a torn write. It is the *local backstop* freshness
//! anchor (§10.4): an attacker who can rewrite all of OPFS can also delete it — it raises the bar,
//! the strong anchor is the sync epoch. Honest boundary, stated in BUILD-NOTES.

use crate::crypto::{BLOCK_SIZE, CIPHER_ID, FILE_ID_LEN};

pub const MANIFEST_MAGIC: &[u8; 8] = b"ENCMFST1";
pub const ANCHOR_MAGIC: &[u8; 8] = b"ENCANCH1";
/// Format version 2 = the M2 (manifest-bearing, per-DB-subkey) on-disk format.
/// M1 files (version-less, pool-key) are NOT readable by M2 — fail closed, no silent fallback.
pub const MANIFEST_VERSION: u16 = 2;
/// Data-region offset where slot 0 begins (after the plaintext `{magic, db_uuid}` header).
pub const MANIFEST_HDR_LEN: usize = 64;

/// Sealed manifest payload (fits one plaintext block).
pub struct ManifestPayload {
    /// Monotonic freshness counter, bumped once per main-DB durability barrier (§10.2/§17.D).
    pub db_generation: u64,
    /// Must match the plaintext header uuid — verified after decrypt (§17.E).
    pub db_uuid: [u8; 16],
    /// Authenticated logical lengths (§17.J): `(file_id, logical_len)` for the DB + satellites.
    pub files: Vec<([u8; FILE_ID_LEN], u64)>,
}

impl ManifestPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK_SIZE];
        b[0..2].copy_from_slice(&MANIFEST_VERSION.to_le_bytes());
        b[2] = CIPHER_ID; // §17.L: refuse a manifest sealed for a different cipher
        b[4..8].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes()); // §17.I: B is authenticated
        b[8..16].copy_from_slice(&self.db_generation.to_le_bytes());
        b[16..32].copy_from_slice(&self.db_uuid);
        // 32..64 = merkle_root, reserved zeros in v1 (§10.2 — partial-rollback tree deferred)
        b[64..68].copy_from_slice(&(self.files.len() as u32).to_le_bytes());
        let stride = FILE_ID_LEN + 8;
        let mut at = 68;
        for (fid, len) in &self.files {
            b[at..at + FILE_ID_LEN].copy_from_slice(fid);
            b[at + FILE_ID_LEN..at + stride].copy_from_slice(&len.to_le_bytes());
            at += stride;
        }
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, String> {
        if b.len() != BLOCK_SIZE {
            return Err("manifest payload has wrong size".into());
        }
        let version = u16::from_le_bytes([b[0], b[1]]);
        if version != MANIFEST_VERSION {
            return Err(format!("manifest format_version {version} != {MANIFEST_VERSION}"));
        }
        if b[2] != CIPHER_ID {
            return Err(format!("manifest cipher_id {} != compiled cipher {CIPHER_ID} (§17.L)", b[2]));
        }
        let bs = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize;
        if bs != BLOCK_SIZE {
            return Err(format!("manifest block_size {bs} != B={BLOCK_SIZE} (§17.I)"));
        }
        let db_generation = u64::from_le_bytes(b[8..16].try_into().unwrap());
        let mut db_uuid = [0u8; 16];
        db_uuid.copy_from_slice(&b[16..32]);
        let n = u32::from_le_bytes([b[64], b[65], b[66], b[67]]) as usize;
        let stride = FILE_ID_LEN + 8;
        if 68 + n * stride > BLOCK_SIZE {
            return Err("manifest file table overruns the block".into());
        }
        let mut files = Vec::with_capacity(n);
        for i in 0..n {
            let at = 68 + i * stride;
            let mut fid = [0u8; FILE_ID_LEN];
            fid.copy_from_slice(&b[at..at + FILE_ID_LEN]);
            files.push((fid, u64::from_le_bytes(b[at + FILE_ID_LEN..at + stride].try_into().unwrap())));
        }
        Ok(ManifestPayload { db_generation, db_uuid, files })
    }
}

/// One `{committed, in_flight}` window in the anchor (§17.D), keyed by `db_uuid`.
#[derive(Clone, Copy)]
pub struct AnchorEntry {
    pub uuid: [u8; 16],
    pub committed: u64,
    pub in_flight: u64,
}

/// Max `db_uuid` entries one anchor block can hold. Reserving 20 bytes of header (magic+seq+count).
pub const ANCHOR_CAP: usize = (BLOCK_SIZE - 20) / 32;

/// Layout: `magic(8) | seq_LE(8) | count_LE(4) | entries[count]{uuid(16), committed(8), in_flight(8)}`.
pub fn encode_anchor(seq: u64, entries: &[AnchorEntry]) -> Vec<u8> {
    let mut b = vec![0u8; BLOCK_SIZE];
    b[0..8].copy_from_slice(ANCHOR_MAGIC);
    b[8..16].copy_from_slice(&seq.to_le_bytes());
    let n = entries.len().min(ANCHOR_CAP);
    b[16..20].copy_from_slice(&(n as u32).to_le_bytes());
    let mut at = 20;
    for e in entries.iter().take(n) {
        b[at..at + 16].copy_from_slice(&e.uuid);
        b[at + 16..at + 24].copy_from_slice(&e.committed.to_le_bytes());
        b[at + 24..at + 32].copy_from_slice(&e.in_flight.to_le_bytes());
        at += 32;
    }
    b
}

/// Returns `(seq, entries)` or `None` if the block is not a valid anchor.
pub fn decode_anchor(b: &[u8]) -> Option<(u64, Vec<AnchorEntry>)> {
    if b.len() != BLOCK_SIZE || &b[0..8] != ANCHOR_MAGIC {
        return None;
    }
    let seq = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let n = (u32::from_le_bytes([b[16], b[17], b[18], b[19]]) as usize).min(ANCHOR_CAP);
    let entries = (0..n)
        .map(|i| {
            let at = 20 + i * 32;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&b[at..at + 16]);
            AnchorEntry {
                uuid,
                committed: u64::from_le_bytes(b[at + 16..at + 24].try_into().unwrap()),
                in_flight: u64::from_le_bytes(b[at + 24..at + 32].try_into().unwrap()),
            }
        })
        .collect();
    Some((seq, entries))
}
