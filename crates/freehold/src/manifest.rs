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
pub const ANCHOR_MAGIC: &[u8; 8] = b"ENCANCH2"; // D-MR6: bumped for the 40-byte entry (adds epoch_floor)
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
    /// Full-state Merkle root over the main DB's plaintext blocks (freehold-vfs-merkle-root D-MR1).
    /// Lives in the payload's reserved bytes 32..64. An all-zero root = legacy / not-yet-computed
    /// (D-MR2): verify-at-open is skipped and a real root is populated on the next commit. A
    /// non-zero root is recomputed at open and must match, closing the partial-rollback gap (D-MR3).
    pub merkle_root: [u8; 32],
    /// The PREVIOUS committed generation's full-state root (freehold-vfs-merkle-root D-MR5/D-MR6).
    /// Sealed at bytes 4064..4096 (zero in pre-D-MR5 manifests → backward-compatible, no version
    /// bump). LIVE semantics (D-MR6): each commit writes `prev_merkle_root` = the root being
    /// superseded. At open, a hot-journal replay (or the on-disk image) is accepted iff its root ∈
    /// {`merkle_root`, `prev_merkle_root`}. Because D-MR6 seals ONCE per commit at the true commit
    /// point (journal finalization), the manifest root is at most one commit ahead of a hot journal's
    /// rollback target, so this single previous root is exactly the bounded ±1 tolerance that absorbs
    /// the irreducible journal-vs-manifest atomicity gap. A rollback of depth ≥2 matches neither root
    /// and is refused; depth-exactly-1 to the genuine previous state is the accepted floor.
    pub prev_merkle_root: [u8; 32],
    /// Authenticated logical lengths (§17.J): `(file_id, logical_len)` for the DB + satellites.
    pub files: Vec<([u8; FILE_ID_LEN], u64)>,
}

/// Payload offset of the reserved D-MR5 previous-root region — the last 32 bytes of the manifest
/// block. Placed so it never collides with the file table (which grows up from byte 68) and is zero
/// in pre-D-MR5 manifests.
pub const PREV_ROOT_OFFSET: usize = BLOCK_SIZE - 32;

impl ManifestPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK_SIZE];
        b[0..2].copy_from_slice(&MANIFEST_VERSION.to_le_bytes());
        b[2] = CIPHER_ID; // §17.L: refuse a manifest sealed for a different cipher
        b[4..8].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes()); // §17.I: B is authenticated
        b[8..16].copy_from_slice(&self.db_generation.to_le_bytes());
        b[16..32].copy_from_slice(&self.db_uuid);
        // 32..64 = full-state Merkle root (D-MR1). All-zero = legacy / not-yet-computed (D-MR2).
        b[32..64].copy_from_slice(&self.merkle_root);
        // D-MR5: previous-generation root at the block tail (bytes 4064..4096). Backward-compatible
        // (zero in pre-D-MR5 manifests). The file table below must not reach this region.
        b[PREV_ROOT_OFFSET..PREV_ROOT_OFFSET + 32].copy_from_slice(&self.prev_merkle_root);
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
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&b[32..64]);
        let mut prev_merkle_root = [0u8; 32];
        prev_merkle_root.copy_from_slice(&b[PREV_ROOT_OFFSET..PREV_ROOT_OFFSET + 32]);
        let n = u32::from_le_bytes([b[64], b[65], b[66], b[67]]) as usize;
        let stride = FILE_ID_LEN + 8;
        // M-2 (review): cap `n` FIRST so `n * stride` cannot overflow usize on wasm32 (32-bit) and
        // `Vec::with_capacity(n)` cannot be driven to OOM by a hostile count (reachable via the
        // AEAD-bypassing test import path). The table region is `[68, PREV_ROOT_OFFSET)`; no more than
        // that many entries can fit, so any larger `n` is corrupt/hostile → reject.
        let max_entries = (PREV_ROOT_OFFSET - 68) / stride;
        if n > max_entries {
            return Err("manifest file count exceeds table capacity (corrupt/hostile)".into());
        }
        // The file table must not reach the prev-root region at the block tail (D-MR5).
        if 68 + n * stride > PREV_ROOT_OFFSET {
            return Err("manifest file table overruns the block / prev-root region".into());
        }
        let mut files = Vec::with_capacity(n);
        for i in 0..n {
            let at = 68 + i * stride;
            let mut fid = [0u8; FILE_ID_LEN];
            fid.copy_from_slice(&b[at..at + FILE_ID_LEN]);
            files.push((fid, u64::from_le_bytes(b[at + FILE_ID_LEN..at + stride].try_into().unwrap())));
        }
        Ok(ManifestPayload { db_generation, db_uuid, merkle_root, prev_merkle_root, files })
    }
}

/// One freshness window in the anchor (§17.D), keyed by `db_uuid`.
///
/// - `committed` / `in_flight`: the local self-commit high-water with the ±1 crash-atomicity slack
///   (a lost final manifest/anchor bump is tolerated — see the open-path check).
/// - `epoch_floor` (freehold-vfs-merkle-root D-MR6): a STRICT floor raised by a peer sync-epoch
///   attestation. A peer epoch has NO local crash-atomicity gap, so any manifest at
///   `db_generation < epoch_floor` is a definitive rollback and is refused with NO ±1 slack. This
///   keeps peer-attested freshness strict even though the local generation now advances once per
///   commit (D-MR6 halved the rate, so a 1-commit rollback would otherwise sit inside the ±1 window).
#[derive(Clone, Copy)]
pub struct AnchorEntry {
    pub uuid: [u8; 16],
    pub committed: u64,
    pub in_flight: u64,
    pub epoch_floor: u64,
}

/// Per-entry on-disk size: uuid(16) + committed(8) + in_flight(8) + epoch_floor(8).
const ANCHOR_ENTRY_SIZE: usize = 40;
/// Max `db_uuid` entries one anchor block can hold. Reserving 20 bytes of header (magic+seq+count).
pub const ANCHOR_CAP: usize = (BLOCK_SIZE - 20) / ANCHOR_ENTRY_SIZE;

/// Layout: `magic(8) | seq_LE(8) | count_LE(4) | entries[count]{uuid(16), committed(8), in_flight(8),
/// epoch_floor(8)}`. `ANCHOR_MAGIC` was bumped for the 40-byte entry (D-MR6): a pre-D-MR6 anchor (old
/// magic / 32-byte entries) decodes as `None` → treated as a missing anchor (fresh), the existing
/// safe fallback, and is rewritten in the new format on the next commit/epoch.
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
        b[at + 32..at + 40].copy_from_slice(&e.epoch_floor.to_le_bytes());
        at += ANCHOR_ENTRY_SIZE;
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
            let at = 20 + i * ANCHOR_ENTRY_SIZE;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&b[at..at + 16]);
            AnchorEntry {
                uuid,
                committed: u64::from_le_bytes(b[at + 16..at + 24].try_into().unwrap()),
                in_flight: u64::from_le_bytes(b[at + 24..at + 32].try_into().unwrap()),
                epoch_floor: u64::from_le_bytes(b[at + 32..at + 40].try_into().unwrap()),
            }
        })
        .collect();
    Some((seq, entries))
}
