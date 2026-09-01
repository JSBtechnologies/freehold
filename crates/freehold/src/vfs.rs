//! opfs-sahpool VFS — FORKED from `sqlite-wasm-vfs` 0.2.0 (`src/sahpool.rs`) for the encrypting VFS.
//!
//! The ONLY substantive change vs upstream is that `SyncAccessFile`'s `VfsFile` implementation is
//! no longer raw physical byte I/O — it is the **encrypted block device** (design-spec §4): it
//! translates SQLite's logical byte offsets onto physical `P`-byte blocks and runs XChaCha20-Poly1305
//! per block (via `crate::crypto`). Everything above it (the `SQLiteVfs`/`SQLiteIoMethods`/`VfsStore`
//! plumbing, the pool, headers, capacity management) is upstream, unchanged. Every change is marked
//! `// ENC:` so the security-relevant delta is greppable.
//!
//! Layering (design-spec §2):
//! ```text
//!   SQLite  --logical offsets-->  VfsFile::{read,write,truncate,size}   (THIS FILE: block device)
//!                                        |  per-block AEAD + offset xlate
//!                                        v  phys_{read,write,truncate,size}
//!   sahpool sync-access-handle I/O  --> OPFS FileSystemSyncAccessHandle (ciphertext only)
//! ```
//! Note: the sahpool file already reserves a 4096-byte *plaintext* header per physical file for its
//! own bookkeeping (filename + open flags). Our block device lives entirely in the DATA region after
//! that header, so `HEADER_OFFSET_DATA` framing is untouched. Filenames in that header remain
//! plaintext (a known, documented residual — see BUILD-NOTES; DB *contents* are fully encrypted).

use rsqlite_vfs::{
    ffi::{
        sqlite3_file, sqlite3_filename, sqlite3_vfs, sqlite3_vfs_register, sqlite3_vfs_unregister,
        SQLITE_CANTOPEN, SQLITE_ERROR, SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN, SQLITE_IOERR,
        SQLITE_IOERR_DELETE, SQLITE_OK, SQLITE_OPEN_DELETEONCLOSE, SQLITE_OPEN_MAIN_DB,
        SQLITE_OPEN_MAIN_JOURNAL, SQLITE_OPEN_SUPER_JOURNAL, SQLITE_OPEN_WAL,
    },
    register_vfs, registered_vfs, OsCallback, RegisterVfsError, SQLiteIoMethods,
    SQLiteVfs, SQLiteVfsFile, VfsAppData, VfsError, VfsFile, VfsResult, VfsStore,
};
use std::collections::{HashMap, HashSet};
use std::rc::Rc; // ENC: shared crypto context handed to every pooled file
use std::time::Duration;
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
};
use zeroize::Zeroizing; // ENC: plaintext scratch buffers + retained DEK are zeroized on drop (§17.M)

use crate::crypto::{self, Crypto}; // ENC: the trusted crypto core
use crate::manifest::{
    // ENC (M2): double-buffered manifest + TrustedGeneration anchor (§10, §17.C/D/E/J)
    decode_anchor, encode_anchor, AnchorEntry, ManifestPayload, ANCHOR_MAGIC, MANIFEST_HDR_LEN,
    MANIFEST_MAGIC,
};

/// freehold-vfs-merkle-root H1: AAD for the anchor's AEAD, binding the anchor FORMAT MAGIC and SLOT.
/// An old-format (ENCANCH1) blob or a blob relocated to the other slot fails authentication rather
/// than silently decoding — closing the cross-version / slot-swap substitution paths. `seq` is not in
/// the AAD (it is unknown before decrypt); it is already inside the AEAD-authenticated payload.
fn anchor_aad(slot: usize) -> Vec<u8> {
    let mut a = Vec::with_capacity(24 + 8 + 8);
    a.extend_from_slice(b"freehold-anchor-aad-v2\0\0");
    a.extend_from_slice(ANCHOR_MAGIC);
    a.extend_from_slice(&(slot as u64).to_le_bytes());
    a
}

use js_sys::{Array, DataView, IteratorNext, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetDirectoryOptions,
    FileSystemGetFileOptions, FileSystemReadWriteOptions, FileSystemSyncAccessHandle,
    WorkerGlobalScope,
};

const SECTOR_SIZE: usize = 4096;
const HEADER_MAX_FILENAME_SIZE: usize = 512;
const HEADER_FLAGS_SIZE: usize = 4;
const HEADER_CORPUS_SIZE: usize = HEADER_MAX_FILENAME_SIZE + HEADER_FLAGS_SIZE;
const HEADER_OFFSET_FLAGS: usize = HEADER_MAX_FILENAME_SIZE;
const HEADER_OFFSET_DATA: usize = SECTOR_SIZE;

// ENC (sync-epoch): AAD binding the epoch token to its purpose (sync-epoch-design §4).
const EPOCH_AAD: &[u8] = b"freehold-epoch";

const PERSISTENT_FILE_TYPES: i32 =
    SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_MAIN_JOURNAL | SQLITE_OPEN_SUPER_JOURNAL | SQLITE_OPEN_WAL;

type Result<T, E = OpfsSAHError> = std::result::Result<T, E>;

fn read_write_options(at: f64) -> FileSystemReadWriteOptions {
    let options = FileSystemReadWriteOptions::new();
    options.set_at(at);
    options
}

struct SyncAccessFile {
    handle: FileSystemSyncAccessHandle,
    // The physical `.opaque/` filename, read only to delete the entry in the optional
    // `reduce_capacity`; otherwise written-but-unread, which is fine.
    #[allow(dead_code)]
    opaque: String,
    // ENC (M3): §14.8 fault-injection gate shared with the pool (pass-through when disarmed).
    fault: Rc<FaultState>,
    // ENC (M2): per-file block key. Starts as the pool-domain subkey; rebound to the owning DB's
    // `K_db` when the main DB's manifest is loaded/created (§17.E) or when a satellite opens.
    crypto: RefCell<Rc<Crypto>>,
    // ENC: stable per-file AAD domain; set when a name is bound to this handle. Zero while pooled.
    file_id: Cell<[u8; crypto::FILE_ID_LEN]>,
    // ENC (security-review 3d): the owning DB's `db_uuid`, bound into every block's AAD as a
    // redundant cross-DB guard on top of key separation. `NO_DOMAIN` (zeros) for pool/temp files.
    key_domain: Cell<[u8; crypto::KEY_DOMAIN_LEN]>,
    // ENC (M2, §17.I): true once this handle is bound to a main-DB name; gates the write-path
    // page-size check (refuse to persist an SQLite header whose page_size != B).
    is_main_db: Cell<bool>,
    // ENC: logical (plaintext) size, tracked in memory. For the main DB it is set authoritatively
    // from the manifest's authenticated length at open (§17.J) and must equal the whole-block
    // physical size; satellites use the manifest length when consistent with the physical layout,
    // else the physical estimate (journal tail validity is then SQLite's checksums — see BUILD-NOTES).
    logical_size: Cell<Option<usize>>,
}

// ENC: the encrypted block device. Splits SQLite's logical offsets onto physical P-byte blocks and
// runs per-block AEAD. `read`/`write`/`truncate`/`size` below are the design-spec §4 logic; the
// `phys_*` helpers are the ORIGINAL upstream raw-handle I/O (now private, operating on ciphertext).
impl SyncAccessFile {
    /// Raw physical read of `buf.len()` bytes at data-region offset `at`. Returns bytes actually read.
    fn phys_read(&self, buf: &mut [u8], at: usize) -> VfsResult<usize> {
        let n = self
            .handle
            .read_with_u8_array_and_options(buf, &read_write_options((HEADER_OFFSET_DATA + at) as f64))
            .map_err(OpfsSAHError::Read)
            .map_err(|err| err.vfs_err(SQLITE_IOERR))?;
        Ok(n as usize)
    }

    /// Raw physical write at data-region offset `at`. Errors unless all bytes are written.
    fn phys_write(&self, buf: &[u8], at: usize) -> VfsResult<()> {
        if !self.fault.gate() {
            return Ok(()); // ENC (M3): simulated power loss — the write silently never lands
        }
        let n = self
            .handle
            .write_with_u8_array_and_options(buf, &read_write_options((HEADER_OFFSET_DATA + at) as f64))
            .map_err(OpfsSAHError::Write)
            .map_err(|err| err.vfs_err(SQLITE_IOERR))?;
        if buf.len() != n as usize {
            return Err(VfsError::new(SQLITE_ERROR, "failed to write file".into()));
        }
        Ok(())
    }

    /// Physical size of the data region (bytes of ciphertext blocks), excluding the sahpool header.
    fn phys_size(&self) -> VfsResult<usize> {
        let sz = self
            .handle
            .get_size()
            .map_err(OpfsSAHError::GetSize)
            .map_err(|err| err.vfs_err(SQLITE_IOERR))? as usize;
        // A file smaller than the sahpool header is torn/corrupt — floor at 0 rather than let the
        // unsigned subtraction wrap to a ~4 GB phys size, which would route reads into the zero-fill/
        // short-read path instead of failing closed (§17.K). (audit #1)
        Ok(sz.saturating_sub(HEADER_OFFSET_DATA))
    }

    /// Truncate the physical data region to `size` bytes.
    fn phys_truncate(&self, size: usize) -> VfsResult<()> {
        if !self.fault.gate() {
            return Ok(()); // ENC (M3): simulated power loss
        }
        self.handle
            .truncate_with_f64((HEADER_OFFSET_DATA + size) as f64)
            .map_err(OpfsSAHError::Truncate)
            .map_err(|err| err.vfs_err(SQLITE_IOERR))
    }

    /// Current logical size, computing it from the physical block count on first use.
    /// `(phys / P) * B` is exact for whole-block files (the main DB); journals track in memory.
    fn ensure_logical(&self) -> VfsResult<usize> {
        if let Some(s) = self.logical_size.get() {
            return Ok(s);
        }
        let phys = self.phys_size()?;
        let s = (phys / crypto::PHYS_BLOCK) * crypto::BLOCK_SIZE;
        self.logical_size.set(Some(s));
        Ok(s)
    }
}

impl VfsFile for SyncAccessFile {
    // ENC: decrypt path. For each logical block covering [offset, offset+len): read its physical
    // block, AEAD-open, copy the requested sub-range. A block past physical EOF (or a torn, partially
    // written final block) is treated as EOF: its region is zero-filled and we return a short read.
    // A block that IS fully present but fails AEAD auth is corruption/tamper → hard IOERR, never a
    // short read (§17.K) — that distinction is the whole point of the tamper guarantee.
    fn read(&self, buf: &mut [u8], offset: usize) -> VfsResult<bool> {
        if buf.is_empty() {
            return Ok(true);
        }
        let b = crypto::BLOCK_SIZE;
        let p = crypto::PHYS_BLOCK;
        let file_id = self.file_id.get();
        let domain = self.key_domain.get();
        let phys = self.phys_size()?;

        let start = offset;
        // security-review 5.5: refuse absurd offsets rather than wrap the block-index math on wasm32.
        let end = offset
            .checked_add(buf.len())
            .ok_or_else(|| VfsError::new(SQLITE_IOERR, "read offset+len overflow".into()))?;
        let first = start / b;
        let last = (end - 1) / b;

        let mut plain = Zeroizing::new(vec![0u8; b]);
        let mut physbuf = vec![0u8; p];
        let mut short = false;
        let crypto = self.crypto.borrow(); // ENC (M2): per-DB subkey

        for k in first..=last {
            let blk_start = k * b;
            let copy_lo = start.max(blk_start);
            let copy_hi = end.min(blk_start + b);
            let dst_lo = copy_lo - start;
            let dst_hi = copy_hi - start;
            let phys_at = k
                .checked_mul(p)
                .ok_or_else(|| VfsError::new(SQLITE_IOERR, "physical offset overflow".into()))?;

            if phys_at + p <= phys {
                let n = self.phys_read(&mut physbuf, phys_at)?;
                if n < p {
                    // Size said the block is there but we read fewer bytes: a torn write. Treat the
                    // block as not-yet-durable (EOF) rather than corruption.
                    buf[dst_lo..dst_hi].fill(0);
                    short = true;
                    continue;
                }
                crypto
                    .open_into(&file_id, &domain, k as u64, &physbuf, &mut plain)
                    .map_err(|_| {
                        VfsError::new(SQLITE_IOERR, "AEAD authentication failed on read".into())
                    })?;
                buf[dst_lo..dst_hi]
                    .copy_from_slice(&plain[(copy_lo - blk_start)..(copy_hi - blk_start)]);
            } else {
                // Block entirely (or partially) past physical EOF → zero-fill, short read.
                buf[dst_lo..dst_hi].fill(0);
                short = true;
            }
        }

        Ok(!short)
    }

    // ENC: encrypt path. Whole-block writes (the main-DB case) seal directly with a fresh nonce.
    // Sub-block writes (journal/temp) read-modify-write: open the existing block (or zero), overlay,
    // re-seal with a fresh nonce. Every seal draws a new nonce (§8).
    fn write(&mut self, buf: &[u8], offset: usize) -> VfsResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let b = crypto::BLOCK_SIZE;
        let p = crypto::PHYS_BLOCK;
        let file_id = self.file_id.get();
        let domain = self.key_domain.get();
        let phys = self.phys_size()?;

        // ENC (M2, §17.I): the torn-write safety argument (§9) rests on main-DB writes being
        // whole-block, which holds only when page_size == B. Enforce it structurally: refuse to
        // persist an SQLite header declaring any other page size.
        if self.is_main_db.get() && offset == 0 && buf.len() >= 18 && buf.starts_with(b"SQLite format 3\0")
        {
            let ps = u16::from_be_bytes([buf[16], buf[17]]);
            let ps = if ps == 1 { 65536 } else { ps as usize };
            if ps != b {
                return Err(VfsError::new(
                    SQLITE_IOERR,
                    format!("refusing main-DB write: page_size {ps} != encryption block B={b} (§17.I)"),
                ));
            }
        }

        let start = offset;
        let end = offset
            .checked_add(buf.len())
            .ok_or_else(|| VfsError::new(SQLITE_IOERR, "write offset+len overflow".into()))?;
        let first = start / b;
        let last = (end - 1) / b;

        let mut plain = Zeroizing::new(vec![0u8; b]);
        let mut physbuf = vec![0u8; p];
        let crypto = self.crypto.borrow(); // ENC (M2): per-DB subkey

        for k in first..=last {
            let blk_start = k * b;
            let phys_at = k
                .checked_mul(p)
                .ok_or_else(|| VfsError::new(SQLITE_IOERR, "physical offset overflow".into()))?;
            let ov_lo = start.max(blk_start);
            let ov_hi = end.min(blk_start + b);
            let whole = ov_lo == blk_start && ov_hi == blk_start + b;

            if whole {
                plain.copy_from_slice(&buf[(ov_lo - start)..(ov_hi - start)]);
            } else {
                // read-modify-write
                if phys_at + p <= phys {
                    // In-range block: it MUST read fully. A short read here is a torn write, not
                    // growth — fail closed rather than silently zero-fill over real (partial) data. (audit #7)
                    if self.phys_read(&mut physbuf, phys_at)? < p {
                        return Err(VfsError::new(
                            SQLITE_IOERR,
                            "short read of an in-range block (torn write) on read-modify-write".into(),
                        ));
                    }
                    crypto
                        .open_into(&file_id, &domain, k as u64, &physbuf, &mut plain)
                        .map_err(|_| {
                            VfsError::new(SQLITE_IOERR, "AEAD auth failed on read-modify-write".into())
                        })?;
                } else {
                    // Block past the physical end: a genuinely new block being grown into — zero-fill.
                    plain.fill(0);
                }
                plain[(ov_lo - blk_start)..(ov_hi - blk_start)]
                    .copy_from_slice(&buf[(ov_lo - start)..(ov_hi - start)]);
            }

            crypto
                .seal_into(&file_id, &domain, k as u64, &plain, &mut physbuf)
                .map_err(|_| VfsError::new(SQLITE_IOERR, "AEAD seal failed on write".into()))?;
            self.phys_write(&physbuf, phys_at)?;
        }

        let base = self.logical_size.get().unwrap_or((phys / p) * b);
        self.logical_size.set(Some(base.max(end)));
        Ok(())
    }

    // ENC (M2, §17.J): reseal-then-truncate. A mid-block truncate first re-seals the final kept
    // block with the trimmed tail zeroed (so no stale plaintext survives past logical EOF under the
    // old seal), then truncates the physical file. A crash between the two leaves old-or-valid
    // state, never a torn tail.
    fn truncate(&mut self, size: usize) -> VfsResult<()> {
        let b = crypto::BLOCK_SIZE;
        let p = crypto::PHYS_BLOCK;
        let blocks = size.div_ceil(b);
        let tail = size % b;
        if tail != 0 {
            let k = blocks - 1;
            let phys_at = k * p;
            let phys = self.phys_size()?;
            let mut physbuf = vec![0u8; p];
            if phys_at + p <= phys && self.phys_read(&mut physbuf, phys_at)? >= p {
                let file_id = self.file_id.get();
                let domain = self.key_domain.get();
                let crypto = self.crypto.borrow();
                let mut plain = Zeroizing::new(vec![0u8; b]);
                crypto
                    .open_into(&file_id, &domain, k as u64, &physbuf, &mut plain)
                    .map_err(|_| {
                        VfsError::new(SQLITE_IOERR, "AEAD auth failed on truncate reseal".into())
                    })?;
                plain[tail..].fill(0);
                crypto
                    .seal_into(&file_id, &domain, k as u64, &plain, &mut physbuf)
                    .map_err(|_| VfsError::new(SQLITE_IOERR, "AEAD seal failed on truncate".into()))?;
                self.phys_write(&physbuf, phys_at)?;
            }
        }
        self.phys_truncate(blocks * p)?;
        self.logical_size.set(Some(size));
        Ok(())
    }

    fn flush(&mut self) -> VfsResult<()> {
        if self.fault.crashed.get() {
            return Ok(()); // ENC (M3): dead disk — flush "succeeds", nothing durable
        }
        FileSystemSyncAccessHandle::flush(&self.handle)
            .map_err(OpfsSAHError::Flush)
            .map_err(|err| err.vfs_err(SQLITE_IOERR))
    }

    fn size(&self) -> VfsResult<usize> {
        self.ensure_logical()
    }
}

// ENC (M3, dev-harness): §14.8 fault injection. When armed, the first `countdown` persistence
// operations succeed and every later one is silently dropped ("the power went out here") until
// cleared — SQLite believes its writes landed, the disk disagrees, and the reopen must recover.
// Pass-through when disarmed; shared by Rc between the pool and every pooled file.
pub(crate) struct FaultState {
    countdown: Cell<Option<u32>>,
    crashed: Cell<bool>,
}

impl FaultState {
    fn new() -> Self {
        FaultState { countdown: Cell::new(None), crashed: Cell::new(false) }
    }
    /// True = really persist this op; false = the disk is "dead" from this point on.
    fn gate(&self) -> bool {
        if self.crashed.get() {
            return false;
        }
        match self.countdown.get() {
            None => true,
            Some(0) => {
                self.crashed.set(true);
                false
            }
            Some(n) => {
                self.countdown.set(Some(n - 1));
                true
            }
        }
    }
    #[cfg(feature = "testing-api")]
    fn arm(&self, n: u32) {
        self.countdown.set(Some(n));
        self.crashed.set(false);
    }
    #[cfg(feature = "testing-api")]
    fn clear(&self) {
        self.countdown.set(None);
        self.crashed.set(false);
    }
}

// ENC (M2): per-open-database state — the loaded manifest identity + freshness counter (§10/§17.E).
struct DbState {
    uuid: [u8; 16],
    /// `K_db` — the db_uuid-salted subkey sealing every block of this DB and its satellites.
    crypto: Rc<Crypto>,
    /// Current durable `db_generation` (the value in the last manifest slot written).
    generation: Cell<u64>,
    /// freehold-vfs-merkle-root D-MR6: full-state root of the CURRENT committed generation (the one in
    /// the last sealed manifest slot). On the next commit it is written as `prev_merkle_root`, giving
    /// the bounded ±1 tolerance that absorbs the single journal-vs-manifest atomicity gap. `ZERO_ROOT`
    /// until the DB has a committed root.
    committed_root: Cell<[u8; 32]>,
}

struct OpfsSAHPool {
    /// Directory handle to the VFS root (holds `.opaque/` and the anchor file). ENC (M2).
    dh_root: FileSystemDirectoryHandle,
    /// Directory handle to the `.opaque` subdirectory within the VFS root.
    dh_opaque: FileSystemDirectoryHandle,
    header_buffer: Uint8Array,
    header_buffer_view: DataView,
    available_files: RefCell<Vec<SyncAccessFile>>,
    map_filename_to_file: RefCell<HashMap<String, SyncAccessFile>>,
    is_paused: Cell<bool>,
    open_files: RefCell<HashSet<String>>,
    vfs: Cell<(*mut sqlite3_vfs, bool)>,
    random: fn(&mut [u8]),
    // ENC (M2): the injected DEK, retained (zeroized on drop) to derive per-DB subkeys lazily as
    // databases are created/opened (§17.E). Never persisted, never logged (§11).
    dek: Zeroizing<[u8; 32]>,
    // ENC: pool-domain subkey — files not attributable to a DB (temp) until/unless rebound.
    crypto: Rc<Crypto>,
    // ENC (M2): subkey for the TrustedGeneration anchor file (§17.D). H1: the anchor now seals via
    // `seal_bytes`/`open_bytes` with a version+slot AAD (`anchor_aad`), so no separate `anchor_fid` is
    // needed — the AAD (not a file_id/block-device domain) carries the binding.
    anchor_crypto: Crypto,
    anchor_handle: RefCell<Option<FileSystemSyncAccessHandle>>,
    // ENC (M2): manifest state per open main DB, keyed by the SQLite filename.
    dbs: RefCell<HashMap<String, Rc<DbState>>>,
    // ENC (M3): §14.8 fault-injection gate (dev harness; pass-through when disarmed).
    fault: Rc<FaultState>,
    // ENC (sync-epoch): random per-install device id, stamped into exported epoch tokens (tiebreak
    // / provenance only — not security-load-bearing; the token's authenticity comes from K_epoch).
    device_id: [u8; 16],
}

impl OpfsSAHPool {
    // ENC: takes the 256-bit DEK. Runs the CSPRNG self-test and derives the block key. Fails closed
    // if the RNG is unusable (§17.F) — the pool (and therefore the DB) never comes up with a bad RNG.
    async fn new<C: OsCallback>(options: &OpfsSAHPoolCfg, dek: &[u8; 32]) -> Result<OpfsSAHPool> {
        const OPAQUE_DIR_NAME: &str = ".opaque";

        if !crypto::rng_selftest() {
            return Err(OpfsSAHError::Generic(
                "CSPRNG self-test failed; refusing to open (fail closed)".into(),
            ));
        }

        let vfs_dir = &options.directory;
        let capacity = options.initial_capacity;
        let clear_files = options.clear_on_init;

        let create_option = FileSystemGetDirectoryOptions::new();
        create_option.set_create(true);

        let mut handle: FileSystemDirectoryHandle = JsFuture::from(
            js_sys::global()
                .dyn_into::<WorkerGlobalScope>()
                .map_err(|_| OpfsSAHError::NotSupported)?
                .navigator()
                .storage()
                .get_directory(),
        )
        .await
        .map_err(OpfsSAHError::GetDirHandle)?
        .into();

        for dir in vfs_dir.split('/').filter(|x| !x.is_empty()) {
            let next =
                JsFuture::from(handle.get_directory_handle_with_options(dir, &create_option))
                    .await
                    .map_err(OpfsSAHError::GetDirHandle)?
                    .into();
            handle = next;
        }
        let dh_root = handle.clone(); // ENC (M2): anchor file lives here, beside .opaque

        let dh_opaque = JsFuture::from(
            handle.get_directory_handle_with_options(OPAQUE_DIR_NAME, &create_option),
        )
        .await
        .map_err(OpfsSAHError::GetDirHandle)?
        .into();

        let ap_body = Uint8Array::new_with_length(HEADER_CORPUS_SIZE as _);
        let dv_body = DataView::new(
            &ap_body.buffer(),
            ap_body.byte_offset() as usize,
            (ap_body.byte_length() - ap_body.byte_offset()) as usize,
        );

        let pool = Self {
            dh_root,
            dh_opaque,
            header_buffer: ap_body,
            header_buffer_view: dv_body,
            map_filename_to_file: RefCell::new(HashMap::new()),
            available_files: RefCell::new(Vec::new()),
            is_paused: Cell::new(false),
            open_files: RefCell::new(HashSet::new()),
            vfs: Cell::new((std::ptr::null_mut(), false)),
            random: C::random,
            dek: Zeroizing::new(*dek),                     // ENC (M2)
            crypto: Rc::new(Crypto::pool_key(dek)),        // ENC
            anchor_crypto: Crypto::anchor_key(dek),        // ENC (M2)
            anchor_handle: RefCell::new(None),             // ENC (M2)
            dbs: RefCell::new(HashMap::new()),             // ENC (M2)
            fault: Rc::new(FaultState::new()),             // ENC (M3)
            device_id: crypto::random_uuid().unwrap_or([0u8; 16]), // ENC (sync-epoch)
        };

        pool.acquire_access_handles(clear_files).await?;
        pool.reserve_minimum_capacity(capacity).await?;

        Ok(pool)
    }

    // ENC: helper to build a pooled (nameless) file with the pool-domain crypto handle.
    fn make_file(&self, handle: FileSystemSyncAccessHandle, opaque: String) -> SyncAccessFile {
        SyncAccessFile {
            handle,
            opaque,
            fault: self.fault.clone(),
            crypto: RefCell::new(self.crypto.clone()),
            file_id: Cell::new([0u8; crypto::FILE_ID_LEN]),
            key_domain: Cell::new(crypto::NO_DOMAIN),
            is_main_db: Cell::new(false),
            logical_size: Cell::new(None),
        }
    }

    async fn add_capacity(&self, n: u32) -> Result<u32> {
        for _ in 0..n {
            let opaque = rsqlite_vfs::random_name(self.random);
            let handle: FileSystemFileHandle =
                JsFuture::from(self.dh_opaque.get_file_handle_with_options(&opaque, &{
                    let options = FileSystemGetFileOptions::new();
                    options.set_create(true);
                    options
                }))
                .await
                .map_err(OpfsSAHError::GetFileHandle)?
                .into();
            let sah: FileSystemSyncAccessHandle =
                JsFuture::from(handle.create_sync_access_handle())
                    .await
                    .map_err(OpfsSAHError::CreateSyncAccessHandle)?
                    .into();
            let file = self.make_file(sah, opaque); // ENC
            self.set_associated_filename(&file.handle, None, 0)?;
            self.available_files.borrow_mut().push(file);
        }
        Ok(self.get_capacity())
    }

    async fn reserve_minimum_capacity(&self, min: u32) -> Result<()> {
        self.add_capacity(min.saturating_sub(self.get_capacity()))
            .await?;
        Ok(())
    }

    #[cfg(feature = "pool-management")]
    #[allow(dead_code, clippy::await_holding_refcell_ref)]
    async fn reduce_capacity(&self, n: u32) -> Result<u32> {
        let mut available_files = self.available_files.borrow_mut();
        let available_length = available_files.len();
        let max_reduce = available_length.min(n as usize);
        let files = available_files.split_off(available_length - max_reduce);
        drop(available_files);

        for file in files {
            file.handle.close();
            JsFuture::from(self.dh_opaque.remove_entry(&file.opaque))
                .await
                .map_err(OpfsSAHError::RemoveEntity)?;
        }

        Ok(max_reduce as u32)
    }

    fn get_capacity(&self) -> u32 {
        (self.map_filename_to_file.borrow().len() + self.available_files.borrow().len()) as u32
    }

    #[allow(dead_code)] // paired with the pub `count()` introspection wrapper
    fn get_file_count(&self) -> u32 {
        self.map_filename_to_file.borrow().len() as u32
    }

    fn get_filenames(&self) -> Vec<String> {
        self.map_filename_to_file.borrow().keys().cloned().collect()
    }

    fn get_associated_filename(&self, sah: &FileSystemSyncAccessHandle) -> Result<Option<String>> {
        sah.read_with_buffer_source_and_options(&self.header_buffer, &read_write_options(0.0))
            .map_err(OpfsSAHError::Read)?;
        let flags = self.header_buffer_view.get_uint32(HEADER_OFFSET_FLAGS);
        if self.header_buffer.get_index(0) != 0
            && ((flags & SQLITE_OPEN_DELETEONCLOSE as u32 != 0)
                || (flags & PERSISTENT_FILE_TYPES as u32) == 0)
        {
            return Ok(None);
        }

        let name_length = self
            .header_buffer
            .to_vec()
            .iter()
            .position(|&x| x == 0)
            .unwrap_or_default();
        if name_length == 0 {
            sah.truncate_with_u32(HEADER_OFFSET_DATA as u32)
                .map_err(OpfsSAHError::Truncate)?;
            return Ok(None);
        }
        // A corrupt/tampered filename header must not panic the whole wasm instance (wasm has no
        // unwinding — a panic kills the vault). Treat a non-UTF-8 name as "no associated file"; the
        // slot is then reclaimable rather than fatal. (audit #3)
        match String::from_utf8(self.header_buffer.subarray(0, name_length as u32).to_vec()) {
            Ok(filename) => Ok(Some(filename)),
            Err(_) => Ok(None),
        }
    }

    fn set_associated_filename(
        &self,
        sah: &FileSystemSyncAccessHandle,
        filename: Option<&str>,
        flags: i32,
    ) -> Result<()> {
        if !self.fault.gate() {
            return Ok(()); // ENC (M3): simulated power loss — header change never lands
        }
        self.header_buffer_view
            .set_uint32(HEADER_OFFSET_FLAGS, flags as u32);

        if let Some(filename) = filename {
            if filename.is_empty() {
                return Err(OpfsSAHError::Generic("Filename is empty".into()));
            }
            if HEADER_MAX_FILENAME_SIZE <= filename.len() + 1 {
                return Err(OpfsSAHError::Generic(format!(
                    "Filename too long: {filename}"
                )));
            }
            self.header_buffer
                .subarray(0, filename.len() as u32)
                .copy_from(filename.as_bytes());
            self.header_buffer
                .fill(0, filename.len() as u32, HEADER_MAX_FILENAME_SIZE as u32);
        } else {
            self.header_buffer
                .fill(0, 0, HEADER_MAX_FILENAME_SIZE as u32);
            sah.truncate_with_u32(HEADER_OFFSET_DATA as u32)
                .map_err(OpfsSAHError::Truncate)?;
        }

        sah.write_with_js_u8_array_and_options(&self.header_buffer, &read_write_options(0.0))
            .map_err(OpfsSAHError::Write)?;

        Ok(())
    }

    async fn acquire_access_handles(&self, clear_files: bool) -> Result<()> {
        // ENC (M2): (re)acquire the TrustedGeneration anchor's sync handle (§17.D). Lives beside
        // .opaque so the pool scan never mistakes it for a data file.
        if self.anchor_handle.borrow().is_none() {
            let fh: FileSystemFileHandle = JsFuture::from(
                self.dh_root.get_file_handle_with_options("anchor.bin", &{
                    let o = FileSystemGetFileOptions::new();
                    o.set_create(true);
                    o
                }),
            )
            .await
            .map_err(OpfsSAHError::GetFileHandle)?
            .into();
            let sah: FileSystemSyncAccessHandle = JsFuture::from(fh.create_sync_access_handle())
                .await
                .map_err(OpfsSAHError::CreateSyncAccessHandle)?
                .into();
            // ENC (security-review 6): the anchor is double-buffered across two physical blocks.
            // Pre-size the file to both slots so the first save (which ping-pongs to slot 1) is not
            // a sparse write past EOF. A brand-new anchor reads as two invalid (zero) slots ⇒ fresh.
            if sah.get_size().map(|s| (s as usize) < 2 * crypto::PHYS_BLOCK).unwrap_or(true) {
                sah.truncate_with_f64((2 * crypto::PHYS_BLOCK) as f64)
                    .map_err(OpfsSAHError::Truncate)?;
                FileSystemSyncAccessHandle::flush(&sah).map_err(OpfsSAHError::Flush)?;
            }
            self.anchor_handle.replace(Some(sah));
        }

        let iter = self.dh_opaque.entries();
        while let Ok(future) = iter.next() {
            let next: IteratorNext = JsFuture::from(future)
                .await
                .map_err(OpfsSAHError::IterHandle)?
                .into();
            if next.done() {
                break;
            }
            let array: Array = next.value().into();
            let opaque = array
                .get(0)
                .as_string()
                .ok_or_else(|| OpfsSAHError::Generic("Failed to get file's opaque name".into()))?;
            let value = array.get(1);
            let kind = Reflect::get(&value, &JsValue::from("kind"))
                .map_err(OpfsSAHError::Reflect)?
                .as_string();
            if kind.as_deref() == Some("file") {
                let handle = FileSystemFileHandle::from(value);
                let sah = JsFuture::from(handle.create_sync_access_handle())
                    .await
                    .map_err(OpfsSAHError::CreateSyncAccessHandle)?;
                let sah = FileSystemSyncAccessHandle::from(sah);
                let file = self.make_file(sah, opaque); // ENC
                let clear_file = |file: SyncAccessFile| -> Result<()> {
                    self.set_associated_filename(&file.handle, None, 0)?;
                    self.available_files.borrow_mut().push(file);
                    Ok(())
                };
                if clear_files {
                    clear_file(file)?;
                } else if let Some(filename) = self.get_associated_filename(&file.handle)? {
                    // ENC: bind the file's AAD domain to its (now known) name before mapping it.
                    file.file_id.set(crypto::file_id_for(&filename));
                    file.logical_size.set(None);
                    self.map_filename_to_file
                        .borrow_mut()
                        .insert(filename, file);
                } else {
                    clear_file(file)?;
                }
            }
        }

        Ok(())
    }

    fn release_access_handles(&self) {
        for file in std::mem::take(&mut *self.available_files.borrow_mut())
            .into_iter()
            .chain(std::mem::take(&mut *self.map_filename_to_file.borrow_mut()).into_values())
        {
            file.handle.close();
        }
        // ENC (M2): drop the anchor handle (sync handles are exclusive locks — another pool on the
        // same directory could not open it otherwise) and forget loaded manifest state; the next
        // main-DB xOpen reloads + re-verifies from disk.
        if let Some(h) = self.anchor_handle.take() {
            h.close();
        }
        self.dbs.borrow_mut().clear();
    }

    fn delete_file(&self, filename: &str) -> Result<bool> {
        let mut map_filename_to_file = self.map_filename_to_file.borrow_mut();
        let mut available_files = self.available_files.borrow_mut();

        if let Some(file) = map_filename_to_file.remove(filename) {
            available_files.push(file);
            let Some(file) = available_files.last() else {
                unreachable!();
            };
            self.set_associated_filename(&file.handle, None, 0)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn has_filename(&self, filename: &str) -> bool {
        self.map_filename_to_file.borrow().contains_key(filename)
    }

    fn with_file<E, R, F: Fn(&SyncAccessFile) -> Result<R, E>>(
        &self,
        filename: &str,
        f: F,
    ) -> Option<Result<R, E>> {
        self.map_filename_to_file.borrow().get(filename).map(f)
    }

    fn with_file_mut<E, R, F: Fn(&mut SyncAccessFile) -> Result<R, E>>(
        &self,
        filename: &str,
        f: F,
    ) -> Option<Result<R, E>> {
        self.map_filename_to_file
            .borrow_mut()
            .get_mut(filename)
            .map(f)
    }

    fn with_new_file<E, F: Fn(&SyncAccessFile) -> Result<(), E>>(
        &self,
        filename: &str,
        flags: i32,
        f: F,
    ) -> Result<Result<(), E>> {
        let mut map_filename_to_file = self.map_filename_to_file.borrow_mut();
        let mut available_files = self.available_files.borrow_mut();
        if map_filename_to_file.contains_key(filename) {
            return Err(OpfsSAHError::Generic(format!(
                "{filename} file already exists"
            )));
        }
        let file = available_files
            .pop()
            .ok_or_else(|| OpfsSAHError::Generic("No files available in the pool".into()))?;
        map_filename_to_file.insert(filename.into(), file);

        let Some(file) = map_filename_to_file.get(filename) else {
            unreachable!();
        };
        // ENC: bind AAD domain + reset logical size for the freshly-associated file.
        file.file_id.set(crypto::file_id_for(filename));
        file.logical_size.set(Some(0));
        self.set_associated_filename(&file.handle, Some(filename), flags)?;
        Ok(f(file))
    }

    fn pause_vfs(&self) -> Result<()> {
        if self.is_paused.get() {
            return Ok(());
        }

        if !self.open_files.borrow().is_empty() {
            return Err(OpfsSAHError::Generic(
                "Cannot pause: files may be in use".to_string(),
            ));
        }

        let (vfs, _) = self.vfs.get();
        if !vfs.is_null() {
            unsafe {
                sqlite3_vfs_unregister(vfs);
            }
        }
        self.release_access_handles();

        self.is_paused.set(true);

        Ok(())
    }

    async fn unpause_vfs(&self) -> Result<()> {
        if !self.is_paused.get() {
            return Ok(());
        }

        self.acquire_access_handles(false).await?;

        let (vfs, make_default) = self.vfs.get();
        if vfs.is_null() {
            return Err(OpfsSAHError::Generic(
                "VFS pointer is null. Did you forget to install?".to_string(),
            ));
        }

        match unsafe { sqlite3_vfs_register(vfs, i32::from(make_default)) } {
            SQLITE_OK => {
                self.is_paused.set(false);
                Ok(())
            }
            error_code => Err(OpfsSAHError::Generic(format!(
                "Failed to register VFS (SQLite error code: {error_code})"
            ))),
        }
    }

    // ENC: returns the raw DATA-region bytes (ciphertext blocks) for a file. Used by the test rig's
    // ciphertext audit (design-spec §14.6). Deliberately does NOT decrypt.
    fn export_raw(&self, filename: &str) -> Result<Vec<u8>> {
        let files = self.map_filename_to_file.borrow();
        let file = files
            .get(filename)
            .ok_or_else(|| OpfsSAHError::Generic(format!("File not found: {filename}")))?;

        let sah = &file.handle;
        let actual_size = (sah.get_size().map_err(OpfsSAHError::GetSize)? - HEADER_OFFSET_DATA as f64)
            .max(0.0) as usize;

        let mut data = vec![0; actual_size];
        if actual_size > 0 {
            let read = sah
                .read_with_u8_array_and_options(
                    &mut data,
                    &read_write_options(HEADER_OFFSET_DATA as f64),
                )
                .map_err(OpfsSAHError::Read)?;
            if read != actual_size as f64 {
                return Err(OpfsSAHError::Generic(format!(
                    "Expected to read {actual_size} bytes but read {read}.",
                )));
            }
        }
        Ok(data)
    }

    // NOTE (security-review 1.1): the upstream sahpool's `import_db`/`import_db_unchecked` — which
    // wrote RAW (unencrypted) bytes straight into the data region via the sync handle, bypassing the
    // block device — are DELETED. They violated the §17.G structural fail-closed invariant (a
    // reachable writer that never seals). Importing an already-encrypted image, if ever needed, must
    // go through the block-device `write()` path plus a manifest, not a raw handle write.

    // ================= ENC (M2): manifest + TrustedGeneration anchor (§10, §17.C/D/E/I/J) =========

    /// Best-effort load of the double-buffered sealed anchor: reads BOTH slots and returns the
    /// highest-`seq` one that authenticates (security-review 6 — a torn write to one slot leaves
    /// the other intact). Returns `(seq, entries)`; `(0, [])` if neither slot authenticates.
    /// An unreadable/absent anchor is treated as fresh — the local anchor is a raised-bar backstop,
    /// not a proof (§10.4); the strong anchor is the sync epoch (a later milestone).
    fn anchor_load(&self) -> (u64, Vec<AnchorEntry>) {
        let h = self.anchor_handle.borrow();
        let Some(h) = h.as_ref() else { return (0, Vec::new()) };
        let size = h.get_size().map(|s| s as usize).unwrap_or(0);
        let mut best: Option<(u64, Vec<AnchorEntry>)> = None;
        for slot in 0..2usize {
            let at = slot * crypto::PHYS_BLOCK;
            if at + crypto::PHYS_BLOCK > size {
                continue;
            }
            let mut buf = vec![0u8; crypto::PHYS_BLOCK];
            let Ok(n) = h.read_with_u8_array_and_options(&mut buf, &read_write_options(at as f64))
            else {
                continue;
            };
            if (n as usize) < crypto::PHYS_BLOCK {
                continue;
            }
            // H1: open with the version+slot-bound AAD. A pre-D-MR6 (ENCANCH1) blob or a slot-swapped
            // blob fails here and is skipped (not silently decoded to attacker-chosen contents).
            let Ok(plain) = self.anchor_crypto.open_bytes(&anchor_aad(slot), &buf) else {
                continue;
            };
            if let Some((seq, entries)) = decode_anchor(&plain) {
                if best.as_ref().map_or(true, |(bs, _)| seq > *bs) {
                    best = Some((seq, entries));
                }
            }
        }
        best.unwrap_or((0, Vec::new()))
    }

    /// Write the anchor to the `seq % 2` slot (ping-pong) and flush it durable (security-review 6).
    fn anchor_save(&self, seq: u64, entries: &[AnchorEntry]) -> Result<()> {
        if !self.fault.gate() {
            return Ok(()); // ENC (M3): simulated power loss
        }
        let h = self.anchor_handle.borrow();
        let h = h
            .as_ref()
            .ok_or_else(|| OpfsSAHError::Generic("anchor handle unavailable".into()))?;
        let slot = (seq % 2) as usize;
        let plain = Zeroizing::new(encode_anchor(seq, entries));
        // H1 (review): seal with an AAD that BINDS the anchor format magic + slot, so an old-format
        // (ENCANCH1) blob or a blob moved to the other slot FAILS AUTHENTICATION instead of silently
        // decoding. The `seq` is already inside the AEAD-authenticated payload (unforgeable without the
        // DEK). (Residual, §10.4: a genuinely-old validly-sealed blob replayed at its own slot, or a
        // full two-slot wipe, still falls back — the anchor is a deletable local backstop; the strong
        // un-wipeable anchor is the sync epoch. Documented in BUILD-NOTES.)
        let sealed = self
            .anchor_crypto
            .seal_bytes(&anchor_aad(slot), &plain)
            .map_err(|e| OpfsSAHError::Generic(format!("anchor seal failed: {e:?}")))?;
        if sealed.len() != crypto::PHYS_BLOCK {
            return Err(OpfsSAHError::Generic("anchor sealed size mismatch".into()));
        }
        let n = h
            .write_with_u8_array_and_options(
                &sealed,
                &read_write_options((slot * crypto::PHYS_BLOCK) as f64),
            )
            .map_err(OpfsSAHError::Write)?;
        if n as usize != sealed.len() {
            return Err(OpfsSAHError::Generic("anchor short write".into()));
        }
        h.flush().map_err(OpfsSAHError::Flush)?;
        Ok(())
    }

    /// Upsert the §17.D `{committed, in_flight}` window for `uuid`. Values only move forward.
    /// Advances the anchor `seq` so the write ping-pongs to the other slot.
    fn anchor_record(
        &self,
        uuid: &[u8; 16],
        committed: Option<u64>,
        in_flight: Option<u64>,
    ) -> Result<()> {
        self.anchor_record_full(uuid, committed, in_flight, None)
    }

    /// Full anchor upsert including the D-MR6 strict `epoch_floor`. All values move forward only.
    fn anchor_record_full(
        &self,
        uuid: &[u8; 16],
        committed: Option<u64>,
        in_flight: Option<u64>,
        epoch_floor: Option<u64>,
    ) -> Result<()> {
        let (seq, mut entries) = self.anchor_load();
        if let Some(i) = entries.iter().position(|e| &e.uuid == uuid) {
            let e = &mut entries[i];
            if let Some(c) = committed {
                e.committed = e.committed.max(c);
            }
            if let Some(f) = in_flight {
                e.in_flight = e.in_flight.max(f);
            }
            if let Some(ef) = epoch_floor {
                e.epoch_floor = e.epoch_floor.max(ef);
            }
        } else {
            // security-review 1a: bound the table. With the create-ordering fix (manifest durable
            // before the first anchor write) there are no orphan entries to accumulate, so a full
            // table means a genuine >ANCHOR_CAP concurrent-DB pool — refuse loudly, never silently
            // drop an entry (which would disable a live DB's rollback protection).
            if entries.len() >= crate::manifest::ANCHOR_CAP {
                return Err(OpfsSAHError::Generic(format!(
                    "anchor full ({} DBs); cannot track freshness for another DB in this pool",
                    crate::manifest::ANCHOR_CAP
                )));
            }
            entries.push(AnchorEntry {
                uuid: *uuid,
                committed: committed.unwrap_or(0),
                in_flight: in_flight.unwrap_or(0),
                epoch_floor: epoch_floor.unwrap_or(0),
            });
        }
        // H1 (g.1): when raising a strict `epoch_floor`, persist it to BOTH double-buffer slots so a
        // single-slot tamper/torn-write cannot drop back to a pre-epoch slot that lacks the floor.
        // (Ordinary committed/in_flight bumps keep the single ping-pong write — their ±1 slack already
        // tolerates one slot being one generation behind.) Epochs are rare, so the extra write is cheap.
        if epoch_floor.is_some() {
            self.anchor_save(seq + 1, &entries)?;
            self.anchor_save(seq + 2, &entries)?;
            Ok(())
        } else {
            self.anchor_save(seq + 1, &entries)
        }
    }

    /// Seal + write the ping-pong manifest slot (`db_generation % 2`, §17.C) and flush it durable.
    fn write_manifest_slot(
        &self,
        mfile: &SyncAccessFile,
        crypto_db: &Crypto,
        mname: &str,
        payload: &ManifestPayload,
    ) -> Result<()> {
        let slot = (payload.db_generation % 2) as usize;
        let plain = Zeroizing::new(payload.encode());
        let mut sealed = vec![0u8; crypto::PHYS_BLOCK];
        crypto_db
            .seal_into(
                &crypto::file_id_for(mname),
                &payload.db_uuid, // key_domain: bind the manifest to its DB identity (§17.E/3d)
                slot as u64,
                &plain,
                &mut sealed,
            )
            .map_err(|e| OpfsSAHError::Generic(format!("manifest seal failed: {e:?}")))?;
        mfile
            .phys_write(&sealed, MANIFEST_HDR_LEN + slot * crypto::PHYS_BLOCK)
            .map_err(|e| OpfsSAHError::Generic(format!("manifest write failed: {e:?}")))?;
        mfile.handle.flush().map_err(OpfsSAHError::Flush)?;
        Ok(())
    }

    /// Read + authenticate the manifest: plaintext `{magic, db_uuid}` header → derive `K_db` →
    /// pick the highest-generation slot that authenticates; reject only if both fail (§17.C).
    fn read_manifest(
        &self,
        mfile: &SyncAccessFile,
        mname: &str,
    ) -> Result<([u8; 16], Rc<Crypto>, ManifestPayload)> {
        let mut hdr = [0u8; MANIFEST_HDR_LEN];
        let n = mfile
            .phys_read(&mut hdr, 0)
            .map_err(|e| OpfsSAHError::Generic(format!("manifest hdr read: {e:?}")))?;
        if n < MANIFEST_HDR_LEN || &hdr[0..8] != MANIFEST_MAGIC.as_slice() {
            return Err(OpfsSAHError::Generic("manifest header missing/invalid".into()));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&hdr[8..24]);
        let kdb = Rc::new(Crypto::db_key(&self.dek, &uuid));
        let fid = crypto::file_id_for(mname);
        let phys = mfile
            .phys_size()
            .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?;
        let mut best: Option<ManifestPayload> = None;
        for slot in 0..2usize {
            let at = MANIFEST_HDR_LEN + slot * crypto::PHYS_BLOCK;
            if at + crypto::PHYS_BLOCK > phys {
                continue;
            }
            let mut sealed = vec![0u8; crypto::PHYS_BLOCK];
            match mfile.phys_read(&mut sealed, at) {
                Ok(n) if n >= crypto::PHYS_BLOCK => {}
                _ => continue,
            }
            let mut plain = Zeroizing::new(vec![0u8; crypto::BLOCK_SIZE]);
            if kdb.open_into(&fid, &uuid, slot as u64, &sealed, &mut plain).is_err() {
                continue;
            }
            let Ok(p) = ManifestPayload::decode(&plain) else { continue };
            if p.db_uuid != uuid {
                continue; // §17.E: sealed uuid must corroborate the plaintext header
            }
            if best.as_ref().map_or(true, |b| p.db_generation > b.db_generation) {
                best = Some(p);
            }
        }
        let payload = best.ok_or_else(|| {
            OpfsSAHError::Generic(
                "manifest failed to authenticate in both slots (wrong key, or tampered/corrupt)"
                    .into(),
            )
        })?;
        Ok((uuid, kdb, payload))
    }

    /// Create manifest + DbState for a brand-new (empty) main DB (§17.E).
    ///
    /// Ordering (security-review 1a/1b — §17.D): the manifest (header + slot 0) is written and
    /// flushed durable BEFORE the anchor is touched. A crash before the manifest is durable leaves
    /// NO anchor entry, so the next open (main data still empty) recreates cleanly with a fresh
    /// uuid — no orphan accumulation, no brick. A crash after the manifest is durable but before
    /// the anchor write leaves a manifest at gen 1 with no anchor entry → the next open accepts it
    /// (no entry ⇒ no rollback check) and records committed=1.
    fn create_manifest(&self, name: &str, mname: &str) -> Result<Rc<DbState>> {
        let uuid = crypto::random_uuid()
            .map_err(|e| OpfsSAHError::Generic(format!("uuid rng failed closed: {e:?}")))?;
        let kdb = Rc::new(Crypto::db_key(&self.dek, &uuid));
        let payload = ManifestPayload {
            db_generation: 1,
            db_uuid: uuid,
            // A brand-new DB has no durable blocks yet → zero root (D-MR2 legacy/not-yet sentinel);
            // the first real commit's on_main_synced populates a real root.
            merkle_root: crypto::ZERO_ROOT,
            prev_merkle_root: crypto::ZERO_ROOT,
            files: vec![(crypto::file_id_for(name), 0)],
        };
        self.with_new_file(mname, SQLITE_OPEN_MAIN_DB, |mfile: &SyncAccessFile| -> Result<()> {
            let mut hdr = [0u8; MANIFEST_HDR_LEN];
            hdr[0..8].copy_from_slice(MANIFEST_MAGIC);
            hdr[8..24].copy_from_slice(&uuid);
            mfile
                .phys_write(&hdr, 0)
                .map_err(|e| OpfsSAHError::Generic(format!("manifest hdr write: {e:?}")))?;
            self.write_manifest_slot(mfile, &kdb, mname, &payload)
        })??;
        // Manifest is durable; NOW record the anchor (committed=in_flight=1).
        self.anchor_record(&uuid, Some(1), Some(1))?;
        let st = Rc::new(DbState {
            uuid,
            crypto: kdb,
            generation: Cell::new(1),
            committed_root: Cell::new(crypto::ZERO_ROOT),
        });
        self.dbs.borrow_mut().insert(name.to_string(), st.clone());
        Ok(st)
    }

    /// §17.D open-path verification, run from xOpen BEFORE SQLite reads a single byte:
    /// load/create + authenticate the manifest, enforce anchor freshness, bind `K_db`,
    /// enforce `B == page_size` (§17.I), apply authenticated lengths (§17.J).
    fn open_main_db(&self, name: &str) -> Result<()> {
        let mname = manifest_name(name);
        let main_phys = {
            let files = self.map_filename_to_file.borrow();
            let f = files
                .get(name)
                .ok_or_else(|| OpfsSAHError::Generic(format!("{name} not in pool")))?;
            f.phys_size()
                .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?
        };

        if !self.has_filename(&mname) {
            if main_phys != 0 {
                return Err(OpfsSAHError::Generic(format!(
                    "{name} has data but no manifest (pre-M2 image or foreign file) — refusing, fail closed"
                )));
            }
            let st = self.create_manifest(name, &mname)?;
            let files = self.map_filename_to_file.borrow();
            let f = files
                .get(name)
                .ok_or_else(|| OpfsSAHError::Generic(format!("{name} vanished from pool during open")))?;
            f.crypto.replace(st.crypto.clone());
            f.key_domain.set(st.uuid); // security-review 3d: bind block AAD to this DB's identity
            f.is_main_db.set(true);
            f.logical_size.set(Some(0));
            return Ok(());
        }

        let manifest = {
            let files = self.map_filename_to_file.borrow();
            let mfile = files
                .get(&mname)
                .ok_or_else(|| OpfsSAHError::Generic("manifest file not in pool".into()))?;
            self.read_manifest(mfile, &mname)
        };
        let (uuid, kdb, payload) = match manifest {
            Ok(v) => v,
            Err(e) => {
                // security-review 1b/2: the manifest exists but neither slot (nor the plaintext
                // header) authenticates — e.g. a torn header/slot write during the DB's very first
                // commit. If the main DB has NO durable data, nothing is at risk: discard the
                // broken manifest and recreate cleanly rather than bricking a brand-new DB. If real
                // data IS present, refuse (fail closed) — recreating would orphan the ciphertext.
                if main_phys != 0 {
                    return Err(e);
                }
                self.delete_file(&mname)?;
                let st = self.create_manifest(name, &mname)?;
                let files = self.map_filename_to_file.borrow();
                let f = files
                .get(name)
                .ok_or_else(|| OpfsSAHError::Generic(format!("{name} vanished from pool during open")))?;
                f.crypto.replace(st.crypto.clone());
                f.key_domain.set(st.uuid);
                f.is_main_db.set(true);
                f.logical_size.set(Some(0));
                return Ok(());
            }
        };

        // §17.D freshness state machine: manifest one behind the trusted window is a lost final
        // bump from a normal crash (recoverable, re-adopt); anything older is rollback (refuse).
        // D-MR6: the local `committed` high-water keeps its ±1 crash-atomicity slack, but the
        // peer-attested `epoch_floor` is enforced STRICTLY (no slack) — an external attestation has no
        // local crash gap, so any manifest below it is a definitive rollback.
        let gen = payload.db_generation;
        if let Some(e) = self.anchor_load().1.iter().find(|e| e.uuid == uuid) {
            if gen + 1 < e.committed {
                return Err(OpfsSAHError::Generic(format!(
                    "ROLLBACK DETECTED: manifest db_generation {gen} is older than trusted generation {} — refusing to open",
                    e.committed
                )));
            }
            if e.epoch_floor > 0 && gen < e.epoch_floor {
                return Err(OpfsSAHError::Generic(format!(
                    "ROLLBACK DETECTED: manifest db_generation {gen} is below the peer-attested epoch floor {} — refusing to open",
                    e.epoch_floor
                )));
            }
        }
        self.anchor_record(&uuid, Some(gen), Some(gen))?;

        let files = self.map_filename_to_file.borrow();
        let main = files
            .get(name)
            .ok_or_else(|| OpfsSAHError::Generic(format!("{name} vanished from pool during open")))?;
        main.crypto.replace(kdb.clone());
        main.key_domain.set(uuid); // security-review 3d: bind blocks to this DB's identity
        main.is_main_db.set(true);

        let main_fid = crypto::file_id_for(name);
        // ENC (M3, §14.8/§17.D): a HOT rollback journal means a commit was interrupted — the main
        // file may legitimately be mid-write (grown, or block 0 torn). The journal's pre-images are
        // AEAD-protected and SQLite's replay restores the main file before any page is served. So
        // with a hot journal present, DEFER the strict length/block-0 checks (and the root check) to
        // the post-replay state; refusing here would brick the DB on a normal power loss.
        //
        // freehold-vfs-merkle-root F1: "hot" MUST match SQLite's own definition — a journal with a
        // VALID header (the 8-byte magic present in its decrypted block 0). A mere nonzero size is
        // NOT enough: under `locking_mode=EXCLUSIVE` SQLite FINALIZES a journal by zeroing its header
        // (not by deleting/truncating it), so a rolled-back journal PERSISTS on disk with its header
        // cleared. Treating that persistent-but-dead journal as "hot" would defer the root check
        // forever (a DB that ever crashed could never be root-verified again) — the very gap the
        // reviewer flagged. Decrypting block 0 with `K_db` also authenticates the journal, so a
        // planted/forged journal that fails AEAD is treated as NOT hot → the root check runs and
        // catches any accompanying partial rollback. (Recovery itself never re-seals the manifest
        // root in this VFS — `on_main_synced` does not fire on rollback — so a rollback can never be
        // *laundered*; it is caught at this next journal-free open.)
        let hot_journal = {
            let jn = format!("{name}-journal");
            files.get(&jn).is_some_and(|j| self.journal_is_hot(j, &kdb, &uuid, &jn))
        };
        if main_phys > 0 && hot_journal {
            main.logical_size.set(Some((main_phys / crypto::PHYS_BLOCK) * crypto::BLOCK_SIZE));
        } else if main_phys > 0 {
            // §17.J (main DB): the authenticated manifest length must equal the whole-block
            // physical size — catches physical truncation the per-block AEAD cannot see.
            let phys_len = (main_phys / crypto::PHYS_BLOCK) * crypto::BLOCK_SIZE;
            if let Some((_, l)) = payload.files.iter().find(|(fid, _)| *fid == main_fid) {
                if *l as usize != phys_len {
                    return Err(OpfsSAHError::Generic(format!(
                        "main DB physical length {phys_len} disagrees with authenticated manifest length {l} (truncation/tamper?)"
                    )));
                }
            }
            main.logical_size.set(Some(phys_len));
            // §17.I: decrypt block 0 and refuse any page_size != B before SQLite sees the file.
            let mut sealed = vec![0u8; crypto::PHYS_BLOCK];
            let n = main
                .phys_read(&mut sealed, 0)
                .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?;
            if n < crypto::PHYS_BLOCK {
                return Err(OpfsSAHError::Generic("main DB block 0 torn/short".into()));
            }
            let mut plain = Zeroizing::new(vec![0u8; crypto::BLOCK_SIZE]);
            kdb.open_into(&main_fid, &uuid, 0, &sealed, &mut plain).map_err(|_| {
                OpfsSAHError::Generic(
                    "main DB block 0 failed AEAD authentication (wrong key or tamper)".into(),
                )
            })?;
            if !plain.starts_with(b"SQLite format 3\0") {
                return Err(OpfsSAHError::Generic(
                    "decrypted block 0 is not an SQLite header".into(),
                ));
            }
            let ps = u16::from_be_bytes([plain[16], plain[17]]);
            let ps = if ps == 1 { 65536 } else { ps as usize };
            if ps != crypto::BLOCK_SIZE {
                return Err(OpfsSAHError::Generic(format!(
                    "page_size {ps} != encryption block B={} — refusing (§17.I)",
                    crypto::BLOCK_SIZE
                )));
            }
        } else {
            main.logical_size.set(Some(0));
        }

        // Satellites already on disk (hot journal after a crash): bind K_db and apply the
        // authenticated length when consistent with the physical layout (§17.J; otherwise the
        // physical estimate stands and journal-tail validity falls to SQLite's record checksums).
        for (fname, f) in files.iter() {
            if satellite_parent(fname) == Some(name) {
                f.crypto.replace(kdb.clone());
                f.key_domain.set(uuid);
                if let Some((_, l)) =
                    payload.files.iter().find(|(fid, _)| *fid == crypto::file_id_for(fname))
                {
                    let fp = f
                        .phys_size()
                        .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?;
                    if (*l as usize).div_ceil(crypto::BLOCK_SIZE) == fp / crypto::PHYS_BLOCK {
                        f.logical_size.set(Some(*l as usize));
                    }
                }
            }
        }
        drop(files);

        // freehold-vfs-merkle-root D-MR3: full-state root verification — a NEW fail-closed path
        // alongside the anti-rollback refusal above. If the manifest carries a non-zero root
        // (D-MR2: all-zero = legacy/not-yet-computed → skip), recompute over the ACTUAL main-DB
        // blocks and refuse the DB if it disagrees. This detects PARTIAL rollback: an attacker
        // restoring a subset of blocks to an older generation's ciphertext, which the per-block AEAD
        // (binds position, not generation) and the manifest length check (whole-file only) do NOT
        // catch.
        //
        // D-MR6: the seal now fires ONCE per commit at journal finalization (not at xSync), so the
        // sealed manifest root always describes a durably-committed state and a hot journal rolls back
        // to at most the immediately-previous committed root. The accepted set is therefore the two
        // adjacent committed roots {merkle_root, prev_merkle_root} — a rollback of depth ≥2 matches
        // NEITHER (refused on every open, re-plant-proof), while a depth-exactly-1 rollback to the
        // genuine previous committed state matches prev (the irreducible 1-commit atomicity floor).
        //
        // Hot journal → the VFS OWNS the replay: reconstruct the exact image SQLite will serve and
        // require its root ∈ accepted set BEFORE any page is served (provenance-independent). No hot
        // journal → root the on-disk image and require ∈ accepted set.
        if main_phys > 0 && payload.merkle_root != crypto::ZERO_ROOT {
            let accepted = |r: &[u8; 32]| {
                *r == payload.merkle_root
                    || (payload.prev_merkle_root != crypto::ZERO_ROOT
                        && *r == payload.prev_merkle_root)
            };
            if hot_journal {
                let jname = format!("{name}-journal");
                let served = self.replay_journal_root(name, &jname, &kdb, &uuid)?;
                if !accepted(&served) {
                    return Err(OpfsSAHError::Generic(format!(
                        "PARTIAL ROLLBACK DETECTED: {name} rollback-journal replay produces an image \
                         whose full-state root matches neither the sealed committed root nor the \
                         previous root (planted/re-planted rollback ≥2 commits deep) — refusing to open"
                    )));
                }
            } else {
                let actual = self.full_state_root(name)?;
                if !accepted(&actual) {
                    return Err(OpfsSAHError::Generic(format!(
                        "PARTIAL ROLLBACK DETECTED: full-state Merkle root mismatch for {name} \
                         (some blocks restored to an older generation) — refusing to open"
                    )));
                }
            }
        }

        self.dbs.borrow_mut().insert(
            name.to_string(),
            Rc::new(DbState {
                uuid,
                crypto: kdb,
                generation: Cell::new(gen),
                committed_root: Cell::new(payload.merkle_root),
            }),
        );

        // F2: a durable DB carrying a legacy all-zero root is unverifiable indefinitely if it is
        // never re-committed after upgrade (the anchor does not help — a zero-root manifest sits at
        // the current committed generation). On the first WRITABLE, journal-free open of such a DB,
        // proactively compute + seal a real root now (a migration commit at the same generation) so
        // it is protected from the next open onward, instead of waiting for an organic write. (A
        // read-only path that cannot seal would leave it skipped — documented in BUILD-NOTES; this
        // VFS always opens read-write.)
        if main_phys > 0 && !hot_journal && payload.merkle_root == crypto::ZERO_ROOT {
            self.seal_root_migration(name)?;
        }
        Ok(())
    }

    /// F2 migration: seal a real full-state root for a durable legacy zero-root DB WITHOUT bumping
    /// the freshness generation (this is not a data change — it only fills in the reserved root of
    /// the already-current manifest slot). Idempotent: a subsequent open sees a non-zero root and
    /// verifies normally.
    fn seal_root_migration(&self, name: &str) -> Result<()> {
        let Some(st) = self.dbs.borrow().get(name).cloned() else { return Ok(()) };
        let merkle_root = self.full_state_root(name)?;
        if merkle_root == crypto::ZERO_ROOT {
            return Ok(()); // no durable blocks — nothing to root yet
        }
        let mname = manifest_name(name);
        let files = self.map_filename_to_file.borrow();
        let mut table: Vec<([u8; crypto::FILE_ID_LEN], u64)> = Vec::new();
        for (fname, f) in files.iter() {
            if fname == name || satellite_parent(fname) == Some(name) {
                let l = f
                    .ensure_logical()
                    .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?;
                table.push((crypto::file_id_for(fname), l as u64));
            }
        }
        let gen = st.generation.get();
        let payload = ManifestPayload {
            db_generation: gen,
            db_uuid: st.uuid,
            merkle_root,
            prev_merkle_root: crypto::ZERO_ROOT,
            files: table,
        };
        let mfile = files
            .get(&mname)
            .ok_or_else(|| OpfsSAHError::Generic("manifest file missing at root migration".into()))?;
        self.write_manifest_slot(mfile, &st.crypto, &mname, &payload)?;
        drop(files);
        st.committed_root.set(merkle_root);
        Ok(())
    }

    /// Bind a newly-opened journal/WAL to its owner DB's subkey (§17.E/H).
    ///
    /// F3: `-wal` is REFUSED for any tracked (rooted) DB — WAL frames live OUTSIDE the full-state
    /// root's scope (the root covers the main image only), so allowing WAL would reopen a rollback
    /// gap. The VFS mandates journal=DELETE, so this path is not hit in practice; it fails closed
    /// rather than silently rooting an unprotected WAL DB. The `-journal` shares the owner DB's AAD
    /// domain (its `db_uuid`) as before (security-review 3d).
    fn bind_satellite(&self, name: &str) -> Result<()> {
        let Some(parent) = satellite_parent(name) else { return Ok(()) };
        let Some(st) = self.dbs.borrow().get(parent).cloned() else { return Ok(()) };
        if name.ends_with("-wal") {
            return Err(OpfsSAHError::Generic(format!(
                "refusing WAL satellite {name}: WAL frames are outside the full-state-root scope \
                 (freehold-vfs-merkle-root F3) — this VFS requires journal=DELETE"
            )));
        }
        let files = self.map_filename_to_file.borrow();
        if let Some(f) = files.get(name) {
            f.crypto.replace(st.crypto.clone());
            f.key_domain.set(st.uuid); // security-review 3d: satellites share the DB's AAD domain
        }
        Ok(())
    }

    /// freehold-vfs-merkle-root D-MR6 shared commit barrier for a journal `jname` (of parent `parent`).
    /// Called from EVERY finalization path — the EXCLUSIVE header-zeroing xWrite, xDelete, and
    /// xTruncate-to-0. Seals the manifest (gen N+1) IFF the on-disk journal is genuinely HOT (valid
    /// magic under the owner's real `K_db`). This is the ONE place all three paths converge, so:
    ///   * #2 (no silent skip): if the journal IS hot but the parent DbState is absent, that is an
    ///     invariant violation (a journal cannot be hot without its DB open) → hard `Err` (mapped to
    ///     SQLITE_IOERR by the caller), NEVER a silent no-seal. Absent parent + no journal handle =
    ///     genuinely nothing to finalize → Ok (no-op).
    ///   * #3 (no double-fire): finalizing an ALREADY-dead journal (header zeroed by an earlier
    ///     header-zero xWrite, then a redundant xDelete at connection close) is `journal_is_hot=false`
    ///     → no seal, no generation inflation, no needless flush.
    fn journal_finalize_barrier(&self, jname: &str, parent: &str) -> Result<()> {
        // Resolve the parent's real subkey + uuid (never a bogus placeholder — #2).
        let st = self.dbs.borrow().get(parent).cloned();
        let hot = {
            let files = self.map_filename_to_file.borrow();
            match (files.get(jname), st.as_ref()) {
                (Some(j), Some(st)) => self.journal_is_hot(j, &st.crypto, &st.uuid, jname),
                (Some(j), None) => {
                    // Journal file present but DB not open: we cannot authenticate it. If it is a
                    // full-sized journal it may be hot — refuse to silently skip a possible commit
                    // finalization. (In practice a finalization write always has the DB open.)
                    let has_block0 =
                        j.phys_size().map(|s| s >= crypto::PHYS_BLOCK).unwrap_or(false);
                    if has_block0 {
                        return Err(OpfsSAHError::Generic(format!(
                            "journal {jname} finalized while its DB is not open — cannot authenticate, refusing (fail closed)"
                        )));
                    }
                    false // no full header block → nothing to finalize
                }
                (None, _) => false, // no journal file at all → nothing to finalize
            }
        };
        if hot {
            self.on_main_synced(parent)?;
        }
        Ok(())
    }

    /// freehold-vfs-merkle-root F1: is this rollback journal genuinely HOT (needs replay), matching
    /// SQLite's own test? Decrypt journal block 0 with the owner DB's `K_db`+domain and check for the
    /// 8-byte journal magic. Returns false if the block is absent, fails AEAD (planted/forged), or
    /// carries no magic (a finalized/rolled-back journal whose header SQLite has zeroed). A false
    /// result means the open-path strict checks + root verification run normally.
    fn journal_is_hot(
        &self,
        j: &SyncAccessFile,
        kdb: &Crypto,
        uuid: &[u8; 16],
        jname: &str,
    ) -> bool {
        // SQLite rollback-journal header magic (see sqlite3 os.c `aJournalMagic`).
        const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
        let phys = match j.phys_size() {
            Ok(s) => s,
            Err(_) => return false,
        };
        if phys < crypto::PHYS_BLOCK {
            return false; // no full block 0 → cannot be a valid hot journal
        }
        let mut sealed = vec![0u8; crypto::PHYS_BLOCK];
        match j.phys_read(&mut sealed, 0) {
            Ok(n) if n >= crypto::PHYS_BLOCK => {}
            _ => return false,
        }
        let fid = crypto::file_id_for(jname);
        let mut plain = Zeroizing::new(vec![0u8; crypto::BLOCK_SIZE]);
        // Journals share the owner DB's uuid domain (security-review 3d). A block that fails AEAD is
        // a planted/tampered/foreign journal → treat as NOT hot (fail closed: the root check runs).
        if kdb.open_into(&fid, uuid, 0, &sealed, &mut plain).is_err() {
            return false;
        }
        plain.starts_with(&JOURNAL_MAGIC)
    }

    /// Decrypt the whole of a file into a contiguous plaintext byte stream (one `B`-byte block at a
    /// time, each AEAD-authenticated). Used to parse the rollback journal, whose page records straddle
    /// our fixed encryption-block grid. Every present block MUST authenticate — a failure is a hard
    /// error (tamper), never silently skipped (§17.K). A torn final block truncates the stream (the
    /// journal content past it was never durable).
    fn decrypt_whole_file(
        &self,
        f: &SyncAccessFile,
        crypto: &Crypto,
        domain: &[u8; crypto::KEY_DOMAIN_LEN],
        fid: &[u8; crypto::FILE_ID_LEN],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let phys = f
            .phys_size()
            .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?;
        let p = crypto::PHYS_BLOCK;
        let b = crypto::BLOCK_SIZE;
        let nblocks = phys / p;
        let mut out = Zeroizing::new(vec![0u8; nblocks * b]);
        let mut sealed = vec![0u8; p];
        for k in 0..nblocks {
            let n = f
                .phys_read(&mut sealed, k * p)
                .map_err(|e| OpfsSAHError::Generic(format!("journal read blk {k}: {e:?}")))?;
            if n < p {
                out.truncate(k * b);
                break;
            }
            crypto
                .open_into(fid, domain, k as u64, &sealed, &mut out[k * b..k * b + b])
                .map_err(|_| {
                    OpfsSAHError::Generic(format!("journal blk {k} failed AEAD auth (tamper?)"))
                })?;
        }
        Ok(out)
    }

    /// freehold-vfs-merkle-root D-MR5/D-MR6 (option b): VFS-OWNED rollback-journal replay. Parse the
    /// AEAD-authenticated rollback journal, apply its pre-image pages to a SHADOW copy of the current
    /// main image, truncate to the journal's recorded initial page count, and return the full-state
    /// root of that shadow — the EXACT image SQLite will serve after replaying THIS journal. The caller
    /// requires the returned root to lie in the accepted set {merkle_root, prev_merkle_root}. Because
    /// the check is over the replayed image (provenance-independent), re-planting a hot journal before
    /// every open cannot suppress detection.
    ///
    /// Journal format (sqlite fileformat2 §rollback journal): header in sector 0
    /// `magic(8) nRec_be(4) nonce_be(4) initPages_be(4) sector_be(4) pageSize_be(4)`, padded to the
    /// sector size; then page records at each following sector boundary, `pgno_be(4) data(pageSize)
    /// cksum_be(4)`. Records are consumed until one fails its checksum (SQLite's SQLITE_DONE = normal
    /// end, i.e. a torn final record from a real power loss), a zero pgno is seen, or the stream is
    /// exhausted. `nRec==0`/`0xffffffff` ⇒ derive from remaining size (SQLite's hot-journal behavior).
    fn replay_journal_root(
        &self,
        name: &str,
        jname: &str,
        kdb: &Crypto,
        uuid: &[u8; 16],
    ) -> Result<[u8; 32]> {
        const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
        let b = crypto::BLOCK_SIZE;
        let (jbytes, mut shadow) = {
            let files = self.map_filename_to_file.borrow();
            let jf = files
                .get(jname)
                .ok_or_else(|| OpfsSAHError::Generic(format!("{jname} vanished before replay")))?;
            let mf = files
                .get(name)
                .ok_or_else(|| OpfsSAHError::Generic(format!("{name} vanished before replay")))?;
            let jbytes = self.decrypt_whole_file(jf, kdb, uuid, &crypto::file_id_for(jname))?;
            let main_plain =
                self.decrypt_whole_file(mf, kdb, uuid, &crypto::file_id_for(name))?;
            let shadow: Vec<[u8; crypto::BLOCK_SIZE]> = main_plain
                .chunks_exact(b)
                .map(|c| {
                    let mut a = [0u8; crypto::BLOCK_SIZE];
                    a.copy_from_slice(c);
                    a
                })
                .collect();
            (jbytes, shadow)
        };

        if jbytes.len() < 28 || jbytes[0..8] != JOURNAL_MAGIC {
            return Err(OpfsSAHError::Generic(
                "hot journal has no valid header at replay time".into(),
            ));
        }
        let be32 = |o: usize| -> u32 {
            u32::from_be_bytes([jbytes[o], jbytes[o + 1], jbytes[o + 2], jbytes[o + 3]])
        };
        // First-header framing (all segments share pageSize + sectorSize; the FIRST header's
        // initPages is the committed length the whole rollback restores — SQLite truncates to it).
        let page_size = be32(24) as usize;
        let sector = be32(20) as usize;
        let init_pages = be32(16) as usize;
        if page_size != b {
            return Err(OpfsSAHError::Generic(format!(
                "hot journal page_size {page_size} != B={b} — refusing (§17.I)"
            )));
        }
        if sector == 0 || sector % b != 0 {
            return Err(OpfsSAHError::Generic(format!(
                "hot journal sector size {sector} not a positive multiple of B={b}"
            )));
        }
        let rec_sz = page_size + 8;
        // #4 (review + verified against SQLite pager.c): within ONE journal-header segment, page
        // records are packed CONTIGUOUSLY at stride pageSize+8, first record at the sector-padded
        // header end. SQLite writes a SECOND sector-aligned header when a large transaction spills the
        // page cache mid-write (pagerStress → syncJournal(newHdr=1)) or on a savepoint. We therefore
        // LOOP over segments: parse a header, consume its records (nRec, or size-derived when nRec is
        // 0/0xffffffff), then round up to the next sector boundary and, if another valid magic is
        // present, continue — exactly SQLite's pager_playback / readJournalHdr(journalHdrOffset) loop.
        // Each page is journaled at most once per transaction (pInJournal bitvec), so applying every
        // valid record across all segments reconstructs the committed image regardless of order.
        // L1: bound the max page number before `shadow.resize` so a hostile pgno can't OOM.
        let max_pages: usize = init_pages
            .max(shadow.len())
            .max(jbytes.len() / rec_sz)
            .saturating_add(8);

        let mut seg_off = 0usize; // offset of the current segment's header
        'segments: loop {
            if seg_off + 28 > jbytes.len() || jbytes[seg_off..seg_off + 8] != JOURNAL_MAGIC {
                break; // no further valid header → end of journal (SQLite SQLITE_DONE)
            }
            let hdr = |o: usize| -> u32 {
                let a = seg_off + o;
                u32::from_be_bytes([jbytes[a], jbytes[a + 1], jbytes[a + 2], jbytes[a + 3]])
            };
            let nrec_hdr = hdr(8);
            let nonce = hdr(12);
            let seg_sector = hdr(20) as usize;
            let seg_page = hdr(24) as usize;
            if seg_page != page_size || seg_sector != sector {
                break; // segments must share framing (SQLite invariant) — anything else = end.
            }
            let cap: u64 = if nrec_hdr == 0 || nrec_hdr == 0xffff_ffff {
                u64::MAX
            } else {
                nrec_hdr as u64
            };
            // Records start at the sector boundary after this segment's header.
            let mut off = seg_off + sector;
            let mut applied_seg: u64 = 0;
            while applied_seg < cap && off + rec_sz <= jbytes.len() {
                let pgno = u32::from_be_bytes([
                    jbytes[off],
                    jbytes[off + 1],
                    jbytes[off + 2],
                    jbytes[off + 3],
                ]) as usize;
                let data = &jbytes[off + 4..off + 4 + page_size];
                let stored_cksum = u32::from_be_bytes([
                    jbytes[off + 4 + page_size],
                    jbytes[off + 5 + page_size],
                    jbytes[off + 6 + page_size],
                    jbytes[off + 7 + page_size],
                ]);
                // pager_cksum: cksum = nonce; i = pageSize-200; while i>0 { cksum += data[i]; i -= 200 }
                let mut cksum = nonce;
                let mut i: isize = page_size as isize - 200;
                while i > 0 {
                    cksum = cksum.wrapping_add(data[i as usize] as u32);
                    i -= 200;
                }
                if cksum != stored_cksum {
                    break 'segments; // torn/invalid record → normal end (SQLITE_DONE)
                }
                if pgno == 0 || pgno > max_pages {
                    break 'segments; // zero-marker or out-of-bound pgno → stop (safe end)
                }
                let idx = pgno - 1;
                if idx >= shadow.len() {
                    shadow.resize(idx + 1, [0u8; crypto::BLOCK_SIZE]);
                }
                shadow[idx].copy_from_slice(data);
                applied_seg += 1;
                off += rec_sz;
            }
            // Advance to the next sector-aligned header (round `off` up to a sector multiple).
            let next = off.div_ceil(sector) * sector;
            if next <= seg_off {
                break; // no forward progress → stop (defensive)
            }
            seg_off = next;
        }

        // Truncate to the FIRST header's initial DB size (the committed length the rollback restores).
        if init_pages > 0 && init_pages < shadow.len() {
            shadow.truncate(init_pages);
        }
        let mut root = crypto::FullStateRoot::new();
        for (k, page) in shadow.iter().enumerate() {
            root.update_block(k as u64, page);
        }
        Ok(root.finish())
    }

    /// Compute the full-state Merkle root over `name`'s **plaintext** main-DB blocks in index order
    /// (freehold-vfs-merkle-root D-MR1). Deterministic, layout-independent, stable across devices for
    /// identical logical state. Scope = the main DB file only: in rollback-journal mode it is the
    /// single authoritative committed image (satellites are transient journal state, not part of the
    /// durable snapshot). The DB's `K_db`/domain must already be bound to the handle (post-open).
    ///
    /// Reads exactly `logical_len / B` whole blocks. Any physically-present block that fails AEAD is a
    /// hard error (never silently skipped) — the same tamper stance as the read path (§17.K).
    fn full_state_root(&self, name: &str) -> Result<[u8; 32]> {
        let files = self.map_filename_to_file.borrow();
        let f = files
            .get(name)
            .ok_or_else(|| OpfsSAHError::Generic(format!("{name} not in pool for root")))?;
        let logical = f
            .ensure_logical()
            .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?;
        let file_id = f.file_id.get();
        let domain = f.key_domain.get();
        let crypto = f.crypto.borrow();
        let b = crypto::BLOCK_SIZE;
        let p = crypto::PHYS_BLOCK;
        // Whole-block count of the logical image (main DB is always whole-block, §17.I).
        let blocks = logical / b;
        let mut root = crypto::FullStateRoot::new();
        let mut physbuf = vec![0u8; p];
        let mut plain = Zeroizing::new(vec![0u8; b]);
        for k in 0..blocks as u64 {
            let phys_at = (k as usize) * p;
            let n = f
                .phys_read(&mut physbuf, phys_at)
                .map_err(|e| OpfsSAHError::Generic(format!("root phys_read blk {k}: {e:?}")))?;
            if n < p {
                return Err(OpfsSAHError::Generic(format!(
                    "root: block {k} short/torn ({n}<{p}) while computing full-state root"
                )));
            }
            crypto
                .open_into(&file_id, &domain, k, &physbuf, &mut plain)
                .map_err(|_| {
                    OpfsSAHError::Generic(format!(
                        "root: block {k} failed AEAD authentication (tamper?) while computing full-state root"
                    ))
                })?;
            root.update_block(k, &plain);
        }
        Ok(root.finish())
    }

    /// §17.D commit barrier, run after a main-DB xSync made its ciphertext durable:
    /// record in_flight → seal+flush the ping-pong slot (with the §17.J length table) →
    /// record committed → adopt the new generation.
    fn on_main_synced(&self, name: &str) -> Result<()> {
        let Some(st) = self.dbs.borrow().get(name).cloned() else { return Ok(()) };
        let new_gen = st.generation.get() + 1;
        self.anchor_record(&st.uuid, None, Some(new_gen))?;

        let mname = manifest_name(name);
        // freehold-vfs-merkle-root D-MR1: recompute the full-state root over the now-durable main-DB
        // plaintext blocks and seal it INSIDE the manifest payload. Computed here (before the `files`
        // borrow below) because `full_state_root` borrows the file map itself.
        let merkle_root = self.full_state_root(name)?;
        let files = self.map_filename_to_file.borrow();
        let mut table: Vec<([u8; crypto::FILE_ID_LEN], u64)> = Vec::new();
        for (fname, f) in files.iter() {
            if fname == name || satellite_parent(fname) == Some(name) {
                let l = f
                    .ensure_logical()
                    .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?;
                table.push((crypto::file_id_for(fname), l as u64));
            }
        }
        // D-MR6: carry the current committed root as `prev_merkle_root` (the bounded ±1 tolerance).
        let payload = ManifestPayload {
            db_generation: new_gen,
            db_uuid: st.uuid,
            merkle_root,
            prev_merkle_root: st.committed_root.get(),
            files: table,
        };
        let mfile = files
            .get(&mname)
            .ok_or_else(|| OpfsSAHError::Generic("manifest file missing at commit".into()))?;
        self.write_manifest_slot(mfile, &st.crypto, &mname, &payload)?;
        drop(files);

        self.anchor_record(&st.uuid, Some(new_gen), Some(new_gen))?;
        st.generation.set(new_gen);
        st.committed_root.set(merkle_root); // becomes `prev` on the next commit
        Ok(())
    }

    // ENC: test-rig helper — overwrite a file's raw DATA region (ciphertext) byte-for-byte,
    // simulating an attacker with OPFS write access (§14 tamper/relocation/rollback tests).
    #[cfg(feature = "testing-api")]
    fn import_raw(&self, filename: &str, bytes: &[u8]) -> Result<()> {
        let files = self.map_filename_to_file.borrow();
        let f = files
            .get(filename)
            .ok_or_else(|| OpfsSAHError::Generic(format!("File not found: {filename}")))?;
        f.phys_truncate(bytes.len())
            .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?;
        f.phys_write(bytes, 0)
            .map_err(|e| OpfsSAHError::Generic(format!("{e:?}")))?;
        f.handle.flush().map_err(OpfsSAHError::Flush)?;
        f.logical_size.set(None);
        Ok(())
    }

    #[cfg(feature = "testing-api")]
    fn manifest_generation(&self, db: &str) -> Option<u64> {
        self.dbs.borrow().get(db).map(|s| s.generation.get())
    }

    // ENC (M3, §14.8 test-rig): overwrite `len` bytes of anchor slot `slot` with 0xFF — simulates a
    // torn/tampered anchor write. Proves the double-buffer (security-review 6): corrupting one slot
    // must not nullify rollback protection, because the other slot survives.
    #[cfg(feature = "testing-api")]
    fn corrupt_anchor_slot(&self, slot: usize, len: usize) -> Result<()> {
        let h = self.anchor_handle.borrow();
        let h = h
            .as_ref()
            .ok_or_else(|| OpfsSAHError::Generic("anchor handle unavailable".into()))?;
        let junk = vec![0xFFu8; len];
        h.write_with_u8_array_and_options(
            &junk,
            &read_write_options((slot * crypto::PHYS_BLOCK) as f64),
        )
        .map_err(OpfsSAHError::Write)?;
        h.flush().map_err(OpfsSAHError::Flush)?;
        Ok(())
    }

    // ENC (M3 test-rig): which anchor slot currently holds the highest authenticating seq (i.e. the
    // one an attacker would corrupt to try to roll the anchor back). Returns 0 or 1.
    #[cfg(feature = "testing-api")]
    fn active_anchor_slot(&self) -> usize {
        let (seq, _) = self.anchor_load();
        (seq % 2) as usize
    }

    // issue #4 test-rig (anchor carry-forward): the decoded freshness anchor entries as read under THIS
    // pool's DEK. Used by RK3 to prove a strict epoch floor set under DEK survives rotation under DEK′.
    #[cfg(feature = "testing-api")]
    fn anchor_entries(&self) -> Vec<AnchorEntry> {
        self.anchor_load().1
    }

    // ENC (H1 test-rig): snapshot the raw on-disk anchor bytes (both slots) — an attacker with OPFS
    // write access captures these to replay later. Returns the whole anchor file.
    #[cfg(feature = "testing-api")]
    fn export_anchor_raw(&self) -> Result<Vec<u8>> {
        let h = self.anchor_handle.borrow();
        let h = h
            .as_ref()
            .ok_or_else(|| OpfsSAHError::Generic("anchor handle unavailable".into()))?;
        let size = h.get_size().map(|s| s as usize).unwrap_or(0);
        let mut buf = vec![0u8; size];
        if size > 0 {
            h.read_with_u8_array_and_options(&mut buf, &read_write_options(0.0))
                .map_err(OpfsSAHError::Read)?;
        }
        Ok(buf)
    }

    // ENC (H1 test-rig): overwrite the raw on-disk anchor with captured bytes — simulates an attacker
    // restoring an OLD (or old-format) anchor blob to downgrade the freshness high-water / epoch floor.
    #[cfg(feature = "testing-api")]
    fn import_anchor_raw(&self, bytes: &[u8]) -> Result<()> {
        let h = self.anchor_handle.borrow();
        let h = h
            .as_ref()
            .ok_or_else(|| OpfsSAHError::Generic("anchor handle unavailable".into()))?;
        h.truncate_with_f64(bytes.len() as f64).map_err(OpfsSAHError::Truncate)?;
        if !bytes.is_empty() {
            h.write_with_u8_array_and_options(bytes, &read_write_options(0.0))
                .map_err(OpfsSAHError::Write)?;
        }
        h.flush().map_err(OpfsSAHError::Flush)?;
        Ok(())
    }

    // ============ ENC (sync-epoch): peer-attested freshness (sync-epoch-design §4/§5) =============
    // Mint an epoch token for `db_name`: seal {db_uuid, db_generation, env_generation, device_id}
    // under K_epoch. Any of the user's devices (sharing the DEK) can verify it; nobody without the
    // DEK can forge it. `db_generation` is the manifest's current value (freshest DB state this
    // device has); `env_generation` (#3c) is the key-envelope generation the caller (the live
    // session, which holds the envelope) attests — it lets a peer refuse a rolled-back envelope
    // (e.g. one re-planting a revoked slot) even on a device that never locally saw that generation.
    // Layout: uuid(16) | db_gen(8 LE) | env_gen(8 LE) | device_id(16) = 48 bytes.
    fn export_epoch(&self, db_name: &str, env_generation: u64) -> Result<Vec<u8>> {
        let mname = manifest_name(db_name);
        let (uuid, _kdb, payload) = {
            let files = self.map_filename_to_file.borrow();
            let mfile = files
                .get(&mname)
                .ok_or_else(|| OpfsSAHError::Generic("no manifest — nothing to attest".into()))?;
            self.read_manifest(mfile, &mname)?
        };
        let mut plain = Vec::with_capacity(16 + 8 + 8 + 16);
        plain.extend_from_slice(&uuid);
        plain.extend_from_slice(&payload.db_generation.to_le_bytes());
        plain.extend_from_slice(&env_generation.to_le_bytes());
        plain.extend_from_slice(&self.device_id);
        Crypto::epoch_key(&self.dek)
            .seal_bytes(EPOCH_AAD, &plain)
            .map_err(|e| OpfsSAHError::Generic(format!("epoch seal: {e:?}")))
    }

    // ============ ENC (freehold-sync-design §4/§5): sync-layer key material ============
    // Both derive purely from the DEK (no manifest / generation), exactly like `epoch_key` above: the
    // DEK stays inside the pool. Only the opaque 16-byte `sync_id` (a capability, not the key) and
    // blobs sealed under `sync_crypto` ever cross out — the relay/JS never see the DEK itself.
    fn sync_id(&self, db_uuid: &[u8; 16]) -> [u8; 16] {
        crypto::sync_id(&self.dek, db_uuid)
    }
    fn sync_crypto(&self) -> Crypto {
        Crypto::sync_key(&self.dek)
    }

    // Apply a peer's epoch token: verify under K_epoch, then RAISE this device's local anchor
    // high-water mark (`committed`) for that db_uuid — max only, never lower. The existing open-path
    // rollback check (`manifest_gen + 1 < committed`) then refuses any local DB state older than what
    // a peer has witnessed. Returns `(db_generation, env_generation)` — the DB floor (raised into the
    // anchor here) and the attested key-envelope generation (#3c; the caller enforces it against the
    // envelope it is about to unlock, since the envelope lives outside the pool). A stale token
    // (gen ≤ our committed) is a harmless no-op; a forged/tampered token fails authentication.
    // Accepts the legacy 40-byte layout (no env_gen) → env_generation reads as 0.
    fn apply_epoch(&self, token: &[u8]) -> Result<(u64, u64)> {
        let plain = Crypto::epoch_key(&self.dek)
            .open_bytes(EPOCH_AAD, token)
            .map_err(|_| {
                OpfsSAHError::Generic("epoch token failed authentication (wrong DEK or tampered)".into())
            })?;
        if plain.len() < 24 {
            return Err(OpfsSAHError::Generic("epoch token truncated".into()));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&plain[..16]);
        let gen = u64::from_le_bytes(plain[16..24].try_into().unwrap());
        let env_gen = if plain.len() >= 32 {
            u64::from_le_bytes(plain[24..32].try_into().unwrap())
        } else {
            0
        };
        // D-MR6: a peer epoch is a STRICT external freshness floor (no local ±1 crash slack). Raise
        // both the crash-tolerant `committed` high-water AND the strict `epoch_floor`.
        self.anchor_record_full(&uuid, Some(gen), Some(gen), Some(gen))?;
        Ok((gen, env_gen))
    }

    // ENC (M3 cross-device): serialize a DB's on-disk CIPHERTEXT (main + manifest) as a text bundle
    // `name|hex` per line. The bytes are opaque ciphertext — the DEK is NOT in the bundle, so this is
    // a server-blind sync primitive: carry it anywhere; only the passkey/recovery code opens it.
    fn export_bundle(&self, db_name: &str) -> Result<String> {
        let mname = manifest_name(db_name);
        let mut out = String::new();
        for name in [db_name.to_string(), mname] {
            if self.has_filename(&name) {
                let bytes = self.export_raw(&name)?;
                out.push_str(&name);
                out.push('|');
                for b in &bytes {
                    out.push_str(&format!("{b:02x}"));
                }
                out.push('\n');
            }
        }
        Ok(out)
    }

    // Byte-level import of a decoded bundle's files. Names come from an attacker-controlled
    // `.freehold`, so every name is validated against the export grammar (`valid_pool_filename`)
    // BEFORE any write — a single illegal name aborts the whole import, and there is no `name|hex`
    // text round-trip to confuse (security-review I-1/I-2). Ciphertext is written as-is; it only
    // decrypts later under the real DEK, so a forged image fails closed at open, never bricks.
    fn import_files(&self, files: &[(String, Vec<u8>)]) -> Result<()> {
        for (name, _) in files {
            if !valid_pool_filename(name) {
                return Err(OpfsSAHError::Generic(format!("bundle: illegal file name {name:?}")));
            }
        }
        for (name, bytes) in files {
            self.import_ciphertext_file(name, bytes)?;
        }
        Ok(())
    }

    // Create a fresh pool file and write an already-ENCRYPTED data-region image byte-for-byte.
    // Unlike the deleted `import_db` (which wrote PLAINTEXT bypassing the block device — a §17.G
    // violation), this imports opaque ciphertext produced by another device's identical VFS; the DEK
    // is only needed later to OPEN it. Overwrites any existing file of the same name first.
    fn import_ciphertext_file(&self, filename: &str, ciphertext: &[u8]) -> Result<()> {
        let _ = self.delete_file(filename);
        self.with_new_file(filename, SQLITE_OPEN_MAIN_DB, |file: &SyncAccessFile| -> Result<()> {
            file.phys_truncate(ciphertext.len())
                .map_err(|e| OpfsSAHError::Generic(format!("import truncate: {e:?}")))?;
            file.phys_write(ciphertext, 0)
                .map_err(|e| OpfsSAHError::Generic(format!("import write: {e:?}")))?;
            file.handle.flush().map_err(OpfsSAHError::Flush)?;
            Ok(())
        })?
    }

    // issue #4 / D-RK2 (DEK rotation, physical re-encryption): re-key a CLOSED DB's ciphertext from
    // this pool's DEK to `new_dek`, returning the re-sealed files (main + manifest) ready to import
    // into a pool built with `new_dek`. This is a PURE per-block re-key: `db_uuid`, `file_id`,
    // `key_domain` and every plaintext byte are unchanged, so each block is decrypted under
    // `db_key(DEK,uuid)` and re-sealed under `db_key(new_dek,uuid)` with the IDENTICAL AAD — no
    // content re-encryption, no layout change, and the plaintext-derived Merkle root/generation carry
    // over untouched (no recompute). The pool-global anchor (sealed under `anchor_key`, shared by every
    // DB in the pool) is deliberately NOT carried here — the destination pool establishes a fresh
    // anchor on first commit; carrying the generation floor across rotation is increment-2 (commit
    // barrier) work. Reads via `export_raw`/writes are imported via `import_files`, so this adds no new
    // storage path. Requires the DB to be CLOSED (operates on ciphertext at rest). Production-callable
    // (increment 2): the wired rotation ceremony (`stage_rotation`) drives it; the `reseal_db` util
    // wrapper that also exposes it stays test-only (it is the RK proof harness).
    fn reseal_db_ciphertext(&self, db_name: &str, new_dek: &[u8; 32]) -> Result<Vec<(String, Vec<u8>)>> {
        let mname = manifest_name(db_name);
        // `db_uuid` lives in the manifest's PLAINTEXT header (magic(8) ‖ uuid(16)) — readable with no key.
        let m_raw = self.export_raw(&mname)?;
        if m_raw.len() < 24 || &m_raw[0..8] != MANIFEST_MAGIC.as_slice() {
            return Err(OpfsSAHError::Generic("reseal: manifest header missing/invalid".into()));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&m_raw[8..24]);
        let old_k = Crypto::db_key(&self.dek, &uuid);
        let new_k = Crypto::db_key(new_dek, &uuid);
        let p = crypto::PHYS_BLOCK;
        let b = crypto::BLOCK_SIZE;
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();

        // (1) Main DB file: a uniform block grid from offset 0; block_index = physical block k.
        if self.has_filename(db_name) {
            let raw = self.export_raw(db_name)?;
            let fid = crypto::file_id_for(db_name);
            let nblocks = raw.len() / p;
            let mut resealed = vec![0u8; nblocks * p];
            let mut plain = Zeroizing::new(vec![0u8; b]);
            for k in 0..nblocks {
                old_k
                    .open_into(&fid, &uuid, k as u64, &raw[k * p..k * p + p], &mut plain)
                    .map_err(|_| OpfsSAHError::Generic(format!("reseal main blk {k}: old-DEK auth failed")))?;
                new_k
                    .seal_into(&fid, &uuid, k as u64, &plain, &mut resealed[k * p..k * p + p])
                    .map_err(|e| OpfsSAHError::Generic(format!("reseal main blk {k} seal: {e:?}")))?;
            }
            out.push((db_name.to_string(), resealed));
        }

        // (2) Manifest: a plaintext header (MANIFEST_HDR_LEN, copied verbatim) then up to two sealed
        // slots, each with block_index = slot (matching read_manifest's `at = HDR + slot*P`). A slot
        // that fails to authenticate under the old key is an unwritten/torn slot — copied verbatim (it
        // authenticates under neither key and read_manifest already skips it).
        let fid_m = crypto::file_id_for(&mname);
        let mut m_out = m_raw[..MANIFEST_HDR_LEN].to_vec();
        let mut plain = Zeroizing::new(vec![0u8; b]);
        let mut slot = 0usize;
        loop {
            let at = MANIFEST_HDR_LEN + slot * p;
            if at + p > m_raw.len() {
                break;
            }
            let sealed = &m_raw[at..at + p];
            match old_k.open_into(&fid_m, &uuid, slot as u64, sealed, &mut plain) {
                Ok(()) => {
                    let mut block = vec![0u8; p];
                    new_k
                        .seal_into(&fid_m, &uuid, slot as u64, &plain, &mut block)
                        .map_err(|e| OpfsSAHError::Generic(format!("reseal manifest slot {slot} seal: {e:?}")))?;
                    m_out.extend_from_slice(&block);
                }
                Err(_) => m_out.extend_from_slice(sealed),
            }
            slot += 1;
        }
        out.push((mname, m_out));
        Ok(out)
    }

    // issue #4 / D-RK2+D-RK4 (DEK rotation, increment 2): stage the OPFS half of a rotation ceremony
    // crash-safely. Every named DB is re-keyed to `new_dek` via the pure per-block `reseal_db_ciphertext`
    // and written to SHADOW files (`~rot` suffix) that coexist with the still-live image — nothing live
    // is mutated (D-RK2, never re-encrypt in place). A single intent record (`__rotate_intent__`),
    // sealed under `new_dek`, records `{old_gen, new_gen, db_names}`. The record authenticates ONLY under
    // DEK′, so it is the crash-recovery signal (see `recover_rotation`): after this returns, the SDK's
    // `idbSet('envelope', new_env)` is the commit barrier (D-RK4). A crash BEFORE that leaves the shadow
    // as unreferenced garbage the next open rolls back; a crash AFTER rolls forward. DBs must be CLOSED
    // (this reads ciphertext at rest). Caller supplies `new_dek` (a fresh `random_dek`, never persisted
    // outside the new envelope) so DEK′ is recoverable on the next unlock and nowhere else.
    fn stage_rotation(
        &self,
        new_dek: &[u8; 32],
        db_names: &[String],
        old_gen: u64,
        new_gen: u64,
    ) -> Result<()> {
        // 1. Re-seal each DB under DEK′ into shadow files (main + manifest), leaving the live image alone.
        for db in db_names {
            let files = self.reseal_db_ciphertext(db, new_dek)?;
            for (name, bytes) in files {
                self.import_ciphertext_file(&shadow_name(&name), &bytes)?;
            }
        }
        // 2. Intent record (sealed under DEK′): {old_gen, new_gen}, the DB name list, AND a snapshot of
        // this pool's freshness anchor (per-uuid committed / in_flight / STRICT epoch_floor), captured
        // HERE under the OLD DEK. The old anchor is sealed under `anchor_key`, which DEK′ cannot read, so
        // without this carry the first post-rotation open would find no entry and the peer-attested
        // rollback floor would silently reset to 0. `recover_rotation`'s roll-FORWARD re-establishes it
        // under DEK′ (see there). The snapshot is non-secret lineage metadata (generations + uuids).
        let anchors = self.anchor_load().1;
        let plain = encode_rotation_intent(old_gen, new_gen, db_names, &anchors)?;
        let sealed = Crypto::rotate_intent_key(new_dek)
            .seal_bytes(ROT_INTENT_AAD, &plain)
            .map_err(|e| OpfsSAHError::Generic(format!("rotate intent seal: {e:?}")))?;
        // The intent lands LAST: its presence is what arms recovery, so every shadow must precede it.
        self.import_ciphertext_file(ROT_INTENT_NAME, &sealed)?;
        Ok(())
    }

    // issue #4 / D-RK4: on open, reconcile any staged rotation against THIS pool's DEK (`self.dek`,
    // whichever envelope just unlocked). No intent record → nothing to do. Intent present and it opens
    // under our DEK → we are on the post-commit (new) line: roll FORWARD, replacing each live file with
    // its DEK′ shadow, then dropping shadows + intent. Intent present but it does NOT open under our DEK
    // → we are on the pre-commit (old) line (the envelope swap never happened): roll BACK, discarding the
    // shadows + intent and keeping the untouched live image. Idempotent: forward consumes each shadow and
    // deletes the intent last, so a re-run after a mid-roll crash finishes cleanly. Returns a short note
    // for the test harness / logs; `None` when there was nothing to recover.
    fn recover_rotation(&self) -> Result<Option<String>> {
        if !self.has_filename(ROT_INTENT_NAME) {
            return Ok(None);
        }
        let sealed = self.export_raw(ROT_INTENT_NAME)?;
        match Crypto::rotate_intent_key(&self.dek).open_bytes(ROT_INTENT_AAD, &sealed) {
            Ok(plain) => {
                // Post-commit line: roll FORWARD.
                let (db_names, anchors) = parse_rotation_intent(&plain)?;
                for db in &db_names {
                    for name in [db.clone(), manifest_name(db)] {
                        let sname = shadow_name(&name);
                        if self.has_filename(&sname) {
                            let bytes = self.export_raw(&sname)?;
                            self.import_ciphertext_file(&name, &bytes)?; // live := shadow (DEK′)
                            let _ = self.delete_file(&sname);
                        }
                    }
                }
                // Re-establish the carried freshness anchor under DEK′ — the crux of the carry-forward.
                // `anchor_record_full` moves committed / in_flight / STRICT epoch_floor forward only
                // (max-merge), so replaying it is idempotent: a crash mid-roll re-runs cleanly. Done
                // BEFORE the intent is dropped, so the floor is never lost in the window between the
                // image swap and the intent delete. (The DBs are re-keyed to the SAME db_uuid and the
                // re-seal preserves each manifest generation, so committed == the shadow's manifest gen
                // and epoch_floor <= it — no carried value can trip a false rollback on the next open.)
                for e in &anchors {
                    self.anchor_record_full(
                        &e.uuid,
                        Some(e.committed),
                        Some(e.in_flight),
                        (e.epoch_floor > 0).then_some(e.epoch_floor),
                    )?;
                }
                let _ = self.delete_file(ROT_INTENT_NAME);
                Ok(Some(format!(
                    "rotation rolled FORWARD ({} db, {} anchor)",
                    db_names.len(),
                    anchors.len()
                )))
            }
            Err(_) => {
                // Pre-commit line (intent sealed under a DEK we don't hold): roll BACK.
                self.discard_rotation_staging()?;
                Ok(Some("rotation rolled BACK (pre-commit crash)".into()))
            }
        }
    }

    // Drop every rotation shadow + the intent record. Used on roll-back, and safe to call anytime.
    fn discard_rotation_staging(&self) -> Result<()> {
        let stale: Vec<String> = self
            .get_filenames()
            .into_iter()
            .filter(|n| n.ends_with(ROT_SHADOW_SUFFIX) || n == ROT_INTENT_NAME)
            .collect();
        for n in stale {
            let _ = self.delete_file(&n);
        }
        Ok(())
    }

    // ENC (M3, §14.9): model-based property test of the block device's size/offset arithmetic.
    // Drives a scratch pool file through random SQLite-shaped operations (append/overwrite writes
    // with no sparse holes; shrink-only truncates — SQLite never grows via xTruncate or writes
    // past a gap) and checks every state against a shadow byte-array model: read-back content,
    // zero-fill past EOF, and exact `size()` round-trips (the classic off-by-`P` bug site, §12).
    #[cfg(feature = "testing-api")]
    fn proptest_blockdev(&self, iters: u32) -> Result<String> {
        const NAME: &str = "__proptest__";
        let _ = self.delete_file(NAME);
        self.with_new_file(NAME, SQLITE_OPEN_MAIN_DB, |_f: &SyncAccessFile| -> Result<()> {
            Ok(())
        })??;

        let mut shadow: Vec<u8> = Vec::new();
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let e = |e: VfsError| OpfsSAHError::Generic(format!("{e:?}"));

        let mut writes = 0u32;
        let mut truncates = 0u32;
        for i in 0..iters {
            match rng() % 4 {
                0 | 1 => {
                    // write: offset anywhere in [0, len] (append or overwrite, never a hole)
                    let off = (rng() % (shadow.len() as u64 + 1)) as usize;
                    let len = 1 + (rng() % 8192) as usize;
                    let byte = (i & 0xff) as u8;
                    let buf = vec![byte; len];
                    self.with_file_mut(NAME, |f| f.write(&buf, off))
                        .ok_or_else(|| OpfsSAHError::Generic("proptest file vanished".into()))?
                        .map_err(e)?;
                    if shadow.len() < off + len {
                        shadow.resize(off + len, 0);
                    }
                    shadow[off..off + len].fill(byte);
                    writes += 1;
                }
                2 => {
                    // truncate: shrink-only
                    let size = (rng() % (shadow.len() as u64 + 1)) as usize;
                    self.with_file_mut(NAME, |f| f.truncate(size))
                        .ok_or_else(|| OpfsSAHError::Generic("proptest file vanished".into()))?
                        .map_err(e)?;
                    shadow.truncate(size);
                    truncates += 1;
                }
                _ => {
                    // read: anywhere, including past EOF (must come back zero-filled)
                    let off = (rng() % (shadow.len() as u64 + 512)) as usize;
                    let len = 1 + (rng() % 6000) as usize;
                    let got = self
                        .with_file(NAME, |f| {
                            let mut buf = vec![0u8; len];
                            f.read(&mut buf, off)?;
                            Ok(buf)
                        })
                        .ok_or_else(|| OpfsSAHError::Generic("proptest file vanished".into()))?
                        .map_err(e)?;
                    for (j, &b) in got.iter().enumerate() {
                        let want = shadow.get(off + j).copied().unwrap_or(0);
                        if b != want {
                            return Err(OpfsSAHError::Generic(format!(
                                "§14.9 MISMATCH iter {i}: read[{}] = {b}, model says {want} (off={off} len={len} model_len={})",
                                off + j,
                                shadow.len()
                            )));
                        }
                    }
                }
            }
            // size() must round-trip exactly on every step
            let size = self
                .with_file(NAME, |f| f.size())
                .ok_or_else(|| OpfsSAHError::Generic("proptest file vanished".into()))?
                .map_err(e)?;
            if size != shadow.len() {
                return Err(OpfsSAHError::Generic(format!(
                    "§14.9 SIZE MISMATCH iter {i}: size()={size}, model={}",
                    shadow.len()
                )));
            }
        }
        let _ = self.delete_file(NAME);
        Ok(format!(
            "size-math property test: {iters} ops ({writes} writes, {truncates} truncates) vs shadow model — all reads, zero-fills and size() round-trips exact"
        ))
    }
}

// ENC (M2): the per-DB manifest is a pool file SQLite itself never opens; '#' cannot appear in a
// name SQLite constructs, so it can never collide with a real database/journal path.
fn manifest_name(db: &str) -> String {
    format!("{db}#manifest")
}

// Defense-in-depth (audit #5): the VFS runs on wasm32 where `usize == u32`, so a negative or
// >u32::MAX offset/size from the C boundary would wrap on `as usize`/`as f64`. SQLite's own
// arithmetic normally keeps these in range; this is the belt-and-suspenders bound before we cast.
#[inline]
fn ffi_offset_ok(v: rsqlite_vfs::ffi::sqlite3_int64) -> bool {
    v >= 0 && v <= u32::MAX as rsqlite_vfs::ffi::sqlite3_int64
}

// issue #4 / D-RK4 (DEK rotation): staging file names. Neither can collide with a legitimate pool
// file — `valid_pool_filename` requires a `.db`/`.db#manifest` tail, and `valid_db_name` (session
// layer) forbids `~`/`#`/`_`-prefixed names — so SQLite never opens them and `session_export`'s
// `.ends_with(".db")` filter never mistakes a shadow for a live DB.
const ROT_SHADOW_SUFFIX: &str = "~rot";
const ROT_INTENT_NAME: &str = "__rotate_intent__";
const ROT_INTENT_AAD: &[u8] = b"freehold-rotate-intent";
fn shadow_name(name: &str) -> String {
    format!("{name}{ROT_SHADOW_SUFFIX}")
}

// Rotation-intent record magic + version. Bumped from the v1 layout (which carried only the DB-name
// list) to v2, which appends a snapshot of the freshness anchor so the roll-forward can re-establish
// the peer-attested epoch floor under DEK′ (issue #4 anchor carry-forward). The record is AEAD-sealed
// under DEK′ and lives only for the duration of a ceremony, so no durable-format migration is needed.
const ROT_INTENT_MAGIC: &[u8; 4] = b"FRI2";

// Serialize the rotation intent (framing consumed by `parse_rotation_intent`):
// `MAGIC(4) | old_gen(8) | new_gen(8) | n_names(2) | [len(1)|utf8-name]... | n_anchors(2) |
//  [uuid(16)|committed(8)|in_flight(8)|epoch_floor(8)]...`. The generations are advisory (the envelope
// swap is the real barrier); the names drive the file replacement; the anchor snapshot (captured under
// the OLD DEK at staging time) is re-established under DEK′ on roll-forward so the freshness floor is
// not lost across rotation.
fn encode_rotation_intent(
    old_gen: u64,
    new_gen: u64,
    db_names: &[String],
    anchors: &[AnchorEntry],
) -> Result<Vec<u8>> {
    if db_names.len() > u16::MAX as usize || anchors.len() > crate::manifest::ANCHOR_CAP {
        return Err(OpfsSAHError::Generic("rotate intent too large".into()));
    }
    let mut b = Vec::new();
    b.extend_from_slice(ROT_INTENT_MAGIC);
    b.extend_from_slice(&old_gen.to_le_bytes());
    b.extend_from_slice(&new_gen.to_le_bytes());
    b.extend_from_slice(&(db_names.len() as u16).to_le_bytes());
    for db in db_names {
        if db.len() > 255 {
            return Err(OpfsSAHError::Generic(format!("rotate: db name too long: {db:?}")));
        }
        b.push(db.len() as u8);
        b.extend_from_slice(db.as_bytes());
    }
    b.extend_from_slice(&(anchors.len() as u16).to_le_bytes());
    for e in anchors {
        b.extend_from_slice(&e.uuid);
        b.extend_from_slice(&e.committed.to_le_bytes());
        b.extend_from_slice(&e.in_flight.to_le_bytes());
        b.extend_from_slice(&e.epoch_floor.to_le_bytes());
    }
    Ok(b)
}

// Parse a v2 rotation intent → `(db_names, anchor_snapshot)`. Malformed input (bad magic / truncation)
// fails closed; because the record is AEAD-authenticated under DEK′ before it reaches here, a parse
// error means our own record is corrupt, so it propagates rather than being silently ignored.
fn parse_rotation_intent(plain: &[u8]) -> Result<(Vec<String>, Vec<AnchorEntry>)> {
    let trunc = || OpfsSAHError::Generic("rotate intent truncated".into());
    if plain.len() < 4 || &plain[0..4] != ROT_INTENT_MAGIC {
        return Err(OpfsSAHError::Generic("rotate intent bad magic/version".into()));
    }
    let mut at = 4usize;
    if at + 16 > plain.len() {
        return Err(trunc());
    }
    at += 16; // old_gen | new_gen (advisory)
    let take_u16 = |at: &mut usize, p: &[u8]| -> Result<usize> {
        if *at + 2 > p.len() {
            return Err(OpfsSAHError::Generic("rotate intent truncated".into()));
        }
        let v = u16::from_le_bytes([p[*at], p[*at + 1]]) as usize;
        *at += 2;
        Ok(v)
    };
    let n_names = take_u16(&mut at, plain)?;
    let mut names = Vec::with_capacity(n_names);
    for _ in 0..n_names {
        if at >= plain.len() {
            return Err(trunc());
        }
        let len = plain[at] as usize;
        at += 1;
        if at + len > plain.len() {
            return Err(OpfsSAHError::Generic("rotate intent name overruns record".into()));
        }
        let name = std::str::from_utf8(&plain[at..at + len])
            .map_err(|_| OpfsSAHError::Generic("rotate intent name not utf8".into()))?;
        names.push(name.to_string());
        at += len;
    }
    let n_anchors = take_u16(&mut at, plain)?;
    if n_anchors > crate::manifest::ANCHOR_CAP {
        return Err(OpfsSAHError::Generic("rotate intent anchor count too large".into()));
    }
    let mut anchors = Vec::with_capacity(n_anchors);
    for _ in 0..n_anchors {
        if at + 40 > plain.len() {
            return Err(trunc());
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&plain[at..at + 16]);
        anchors.push(AnchorEntry {
            uuid,
            committed: u64::from_le_bytes(plain[at + 16..at + 24].try_into().unwrap()),
            in_flight: u64::from_le_bytes(plain[at + 24..at + 32].try_into().unwrap()),
            epoch_floor: u64::from_le_bytes(plain[at + 32..at + 40].try_into().unwrap()),
        });
        at += 40;
    }
    Ok((names, anchors))
}

// The only pool file names a legitimate export can produce: `<base>.db` or `<base>.db#manifest`,
// where `<base>` is the `[a-z0-9_-]{1,32}` db-name grammar the session layer enforces. Applied to
// attacker-supplied bundle names on import — forbids path-ish names, the `|`/newline that would
// confuse any text interchange, and manifest/journal shadowing of out-of-grammar names.
fn valid_pool_filename(name: &str) -> bool {
    let core = name.strip_suffix("#manifest").unwrap_or(name);
    let Some(base) = core.strip_suffix(".db") else { return false };
    !base.is_empty()
        && base.len() <= 32
        && base.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

// ENC (M2): map a satellite file back to its owning main DB (§17.H — super-journal deferred).
fn satellite_parent(name: &str) -> Option<&str> {
    name.strip_suffix("-journal")
        .or_else(|| name.strip_suffix("-wal"))
}

type SyncAccessHandleAppData = OpfsSAHPool;

struct SyncAccessHandleStore;

impl VfsStore<SyncAccessFile, SyncAccessHandleAppData> for SyncAccessHandleStore {
    fn add_file(vfs: *mut sqlite3_vfs, filename: &str, flags: i32) -> VfsResult<()> {
        let pool = unsafe { Self::app_data(vfs) };

        pool.with_new_file(filename, flags, |_| Ok(()))
            .map_err(|err| err.vfs_err(SQLITE_CANTOPEN))?
    }

    fn contains_file(vfs: *mut sqlite3_vfs, file: &str) -> VfsResult<bool> {
        let pool = unsafe { Self::app_data(vfs) };
        Ok(pool.has_filename(file))
    }

    fn delete_file(vfs: *mut sqlite3_vfs, file: &str) -> VfsResult<()> {
        let pool = unsafe { Self::app_data(vfs) };
        // freehold-vfs-merkle-root D-MR6: deleting the journal is a commit-finalization point. SEAL
        // the manifest (gen N+1, prev = R_N) BEFORE the journal delete becomes durable, so no crash
        // can leave a committed image with a manifest ≥2 behind (see D-MR6 design note crash table).
        // #3: the barrier only fires if the journal is ACTUALLY HOT — deleting an already-finalized
        // (header-zeroed) journal at connection close is a no-op (no gen inflation, no extra flush).
        if file.ends_with("-journal") {
            if let Some(parent) = satellite_parent(file) {
                let parent = parent.to_string();
                pool.journal_finalize_barrier(file, &parent)
                    .map_err(|err| err.vfs_err(SQLITE_IOERR))?;
            }
        }
        pool.delete_file(file)
            .map_err(|err| err.vfs_err(SQLITE_IOERR_DELETE))?;
        Ok(())
    }

    fn with_file<F: Fn(&SyncAccessFile) -> VfsResult<i32>>(
        vfs_file: &SQLiteVfsFile,
        f: F,
    ) -> VfsResult<i32> {
        let name = unsafe { vfs_file.name() };
        let pool = unsafe { Self::app_data(vfs_file.vfs) };
        pool.with_file(name, f)
            .ok_or_else(|| VfsError::new(SQLITE_IOERR, format!("{name} not found")))?
    }

    fn with_file_mut<F: Fn(&mut SyncAccessFile) -> VfsResult<i32>>(
        vfs_file: &SQLiteVfsFile,
        f: F,
    ) -> VfsResult<i32> {
        let name = unsafe { vfs_file.name() };
        let pool = unsafe { Self::app_data(vfs_file.vfs) };
        pool.with_file_mut(name, f)
            .ok_or_else(|| VfsError::new(SQLITE_IOERR, format!("{name} not found")))?
    }
}

struct SyncAccessHandleIoMethods;

// SQLite's C VFS callbacks (xRead/xWrite/xTruncate/xSync…) have fixed C-style parameter names
// (pFile, zBuf, iOfst, iAmt…) mandated by the FFI signature — keep them verbatim to match the
// upstream contract rather than rename and obscure the mapping.
#[allow(non_snake_case)]
impl SQLiteIoMethods for SyncAccessHandleIoMethods {
    type File = SyncAccessFile;
    type AppData = SyncAccessHandleAppData;
    type Store = SyncAccessHandleStore;

    const VERSION: ::std::os::raw::c_int = 1;

    unsafe extern "C" fn xSectorSize(_pFile: *mut sqlite3_file) -> ::std::os::raw::c_int {
        SECTOR_SIZE as i32
    }

    unsafe extern "C" fn xCheckReservedLock(
        _pFile: *mut sqlite3_file,
        pResOut: *mut ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int {
        *pResOut = 1;
        SQLITE_OK
    }

    unsafe extern "C" fn xDeviceCharacteristics(
        _pFile: *mut sqlite3_file,
    ) -> ::std::os::raw::c_int {
        SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN
    }

    // freehold-vfs-merkle-root D-MR6: in `locking_mode=EXCLUSIVE` SQLite does NOT delete or truncate
    // the journal at commit — it INVALIDATES it by zeroing its header (a write to journal offset 0
    // that clears the magic). That header-zeroing write is the TRUE commit finalization point, so it
    // is a commit barrier: SEAL the manifest (gen N+1) BEFORE the zeroing write becomes durable, then
    // perform the write. A write to offset 0 that SETS the magic (transaction start) is NOT a barrier.
    unsafe extern "C" fn xWrite(
        pFile: *mut sqlite3_file,
        zBuf: *const ::std::os::raw::c_void,
        iAmt: ::std::os::raw::c_int,
        iOfst: rsqlite_vfs::ffi::sqlite3_int64,
    ) -> ::std::os::raw::c_int {
        const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
        let vfs_file = SQLiteVfsFile::from_file(pFile);
        let app_data = SyncAccessHandleStore::app_data(vfs_file.vfs);
        // Defense-in-depth (audit #5): SQLite keeps these in range, but a negative/oversized value
        // would wrap on wasm32 (usize == u32). Reject before casting.
        if !ffi_offset_ok(iOfst) || iAmt < 0 {
            return SQLITE_IOERR;
        }
        let offset = iOfst as usize;
        let size = iAmt as usize;
        let slice = core::slice::from_raw_parts(zBuf.cast::<u8>(), size);

        // Commit finalization: a write to a journal's header (offset 0) that does NOT carry the magic
        // invalidates a previously-hot journal. Seal BEFORE the write lands (via the shared barrier,
        // which #2: hard-errors rather than silently skips if the journal is present-but-unauthable,
        // and #3: no-ops on an already-dead journal so no double-fire / gen inflation).
        if offset == 0 && size >= 8 && !slice.starts_with(&JOURNAL_MAGIC) {
            let name = vfs_file.name();
            if name.ends_with("-journal") {
                if let Some(parent) = satellite_parent(name) {
                    let parent = parent.to_string();
                    if let Err(err) = app_data.journal_finalize_barrier(name, &parent) {
                        return app_data.store_err(err.vfs_err(SQLITE_IOERR));
                    }
                }
            }
        }

        let f = |file: &mut SyncAccessFile| {
            file.write(slice, offset)?;
            Ok(SQLITE_OK)
        };
        match SyncAccessHandleStore::with_file_mut(vfs_file, f) {
            Ok(code) => code,
            Err(err) => app_data.store_err(err),
        }
    }

    unsafe extern "C" fn xClose(pFile: *mut sqlite3_file) -> ::std::os::raw::c_int {
        let vfs_file = SQLiteVfsFile::from_file(pFile);
        let file = vfs_file.name().to_string();
        let app_data = SyncAccessHandleStore::app_data(vfs_file.vfs);
        let ret = Self::xCloseImpl(pFile);
        if ret == SQLITE_OK {
            let exist = app_data.open_files.borrow_mut().remove(&file);
            debug_assert!(exist, "DB closed without open");
        }
        ret
    }

    // ENC (M3, §17.D): mirror of the xDelete journal hook for `locking_mode=EXCLUSIVE`, where SQLite
    // truncates the journal to zero (un-hotting it) instead of deleting it at commit end. D-MR6: SEAL
    // the manifest (gen N+1) BEFORE the truncate-to-0 becomes durable — same ordering rationale as
    // xDelete (a committed image must never be left with a manifest ≥2 behind). A non-zero truncate
    // (mid-transaction journal reset) is data-only, no barrier.
    unsafe extern "C" fn xTruncate(
        pFile: *mut sqlite3_file,
        size: rsqlite_vfs::ffi::sqlite3_int64,
    ) -> ::std::os::raw::c_int {
        let vfs_file = SQLiteVfsFile::from_file(pFile);
        let app_data = SyncAccessHandleStore::app_data(vfs_file.vfs);
        // Defense-in-depth (audit #5): a negative/oversized size would wrap the `size as usize` and the
        // `(HEADER_OFFSET_DATA + size) as f64` truncate below. Reject before use.
        if !ffi_offset_ok(size) {
            return SQLITE_IOERR;
        }
        // Seal FIRST (only for a journal truncate-to-0 = commit finalization). #3: the shared barrier
        // no-ops if the journal is already dead (not hot), so truncating an already-header-zeroed
        // journal never double-fires the generation bump.
        if size == 0 {
            let name = vfs_file.name();
            if name.ends_with("-journal") {
                if let Some(parent) = satellite_parent(name) {
                    let parent = parent.to_string();
                    if let Err(err) = app_data.journal_finalize_barrier(name, &parent) {
                        return app_data.store_err(err.vfs_err(SQLITE_IOERR));
                    }
                }
            }
        }
        let f = |file: &mut SyncAccessFile| {
            file.truncate(size as usize)?;
            Ok(SQLITE_OK)
        };
        match SyncAccessHandleStore::with_file_mut(vfs_file, f) {
            Ok(code) => code,
            Err(err) => app_data.store_err(err),
        }
    }

    // ENC (M2, §17.D): xSync flushes data durable. freehold-vfs-merkle-root D-MR6: xSync is NO LONGER
    // a commit barrier — a main-DB xSync flushes durably but does NOT bump the generation or seal the
    // manifest. The barrier now fires ONLY at journal finalization (the true commit point), so the
    // sealed manifest root always describes a durably-committed state rather than a synced-but-still-
    // rollbackable one. (Previously xSync also sealed, letting the manifest run ahead of a hot
    // journal's rollback target — the F1-a root cause.)
    unsafe extern "C" fn xSync(
        pFile: *mut sqlite3_file,
        _flags: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int {
        let vfs_file = SQLiteVfsFile::from_file(pFile);
        let app_data = SyncAccessHandleStore::app_data(vfs_file.vfs);

        let f = |file: &mut SyncAccessFile| {
            file.flush()?;
            Ok(SQLITE_OK)
        };
        match SyncAccessHandleStore::with_file_mut(vfs_file, f) {
            Ok(code) => code,
            Err(err) => app_data.store_err(err),
        }
    }
}

struct SyncAccessHandleVfs<C>(PhantomData<C>);

// C VFS callback signature (xOpen: pVfs/zName/pFile/pOutFlags) — C-style names kept per the FFI contract.
#[allow(non_snake_case)]
impl<C> SQLiteVfs<SyncAccessHandleIoMethods> for SyncAccessHandleVfs<C>
where
    C: OsCallback,
{
    const VERSION: ::std::os::raw::c_int = 2;
    const MAX_PATH_SIZE: ::std::os::raw::c_int = HEADER_MAX_FILENAME_SIZE as _;

    unsafe extern "C" fn xOpen(
        pVfs: *mut sqlite3_vfs,
        zName: sqlite3_filename,
        pFile: *mut sqlite3_file,
        flags: ::std::os::raw::c_int,
        pOutFlags: *mut ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int {
        let ret = Self::xOpenImpl(pVfs, zName, pFile, flags, pOutFlags);
        if ret == SQLITE_OK {
            let app_data = SyncAccessHandleStore::app_data(pVfs);
            let vfs_file = SQLiteVfsFile::from_file(pFile);
            let name = vfs_file.name().to_string();

            // ENC (M2): a main DB must pass manifest + anchor + page-size verification BEFORE
            // SQLite reads a byte (§17.D); journals/WAL are bound to their owner's K_db (§17.E/H).
            // security-review 2.2: SUPER_JOURNAL is routed here for forward-compatibility, but
            // `bind_satellite` is a deliberate NO-OP for it — its name has no `-journal`/`-wal`
            // suffix so `satellite_parent` returns None, and it stays on the pool-domain key. Multi-
            // DB atomic commit (the only path that opens a super-journal) is DEFERRED (§17.H); a
            // super-journal is still encrypted, just under the pool key rather than a DB's K_db.
            let hook = if flags & SQLITE_OPEN_MAIN_DB != 0 {
                app_data.open_main_db(&name)
            } else if flags & (SQLITE_OPEN_MAIN_JOURNAL | SQLITE_OPEN_SUPER_JOURNAL | SQLITE_OPEN_WAL)
                != 0
            {
                app_data.bind_satellite(&name)
            } else {
                Ok(())
            };
            if let Err(err) = hook {
                let code = app_data.store_err(err.vfs_err(SQLITE_CANTOPEN));
                // xOpenImpl already set pMethods, so per the SQLite VFS contract SQLite WILL call
                // xClose on this handle even though xOpen failed. Leave the name allocation alive
                // for that xClose (freeing it here would double-free); track the handle as open so
                // the close balances.
                app_data.open_files.borrow_mut().insert(name);
                return code;
            }

            app_data.open_files.borrow_mut().insert(name);
        }
        ret
    }

    fn sleep(dur: Duration) {
        C::sleep(dur);
    }

    fn random(buf: &mut [u8]) {
        C::random(buf);
    }

    fn epoch_timestamp_in_ms() -> i64 {
        C::epoch_timestamp_in_ms()
    }
}

/// Build `OpfsSAHPoolCfg`.
pub struct OpfsSAHPoolCfgBuilder(OpfsSAHPoolCfg);

impl OpfsSAHPoolCfgBuilder {
    pub fn new() -> Self {
        Self(OpfsSAHPoolCfg::default())
    }

    pub fn vfs_name(mut self, name: &str) -> Self {
        self.0.vfs_name = name.into();
        self
    }

    pub fn directory(mut self, directory: &str) -> Self {
        self.0.directory = directory.into();
        self
    }

    pub fn clear_on_init(mut self, set: bool) -> Self {
        self.0.clear_on_init = set;
        self
    }

    pub fn initial_capacity(mut self, cap: u32) -> Self {
        self.0.initial_capacity = cap;
        self
    }

    pub fn build(self) -> OpfsSAHPoolCfg {
        self.0
    }
}

impl Default for OpfsSAHPoolCfgBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// `OpfsSAHPool` options.
pub struct OpfsSAHPoolCfg {
    pub vfs_name: String,
    pub directory: String,
    pub clear_on_init: bool,
    pub initial_capacity: u32,
}

impl Default for OpfsSAHPoolCfg {
    fn default() -> Self {
        Self {
            vfs_name: "freehold".into(), // ENC: distinct default so it never shadows plain sahpool
            directory: ".freehold".into(),
            clear_on_init: false,
            initial_capacity: 6,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum OpfsSAHError {
    #[error(transparent)]
    Vfs(#[from] RegisterVfsError),
    #[error("This vfs is only available in dedicated worker")]
    NotSupported,
    #[error("An error occurred while getting the directory handle")]
    GetDirHandle(JsValue),
    #[error("An error occurred while getting the file handle")]
    GetFileHandle(JsValue),
    #[error("An error occurred while creating sync access handle")]
    CreateSyncAccessHandle(JsValue),
    #[error("An error occurred while iterating")]
    IterHandle(JsValue),
    // Constructed only by `reduce_capacity` (the optional pool-management feature).
    #[cfg(feature = "pool-management")]
    #[allow(dead_code)]
    #[error("An error occurred while removing entity")]
    RemoveEntity(JsValue),
    #[error("An error occurred while getting size")]
    GetSize(JsValue),
    #[error("An error occurred while reading data")]
    Read(JsValue),
    #[error("An error occurred while writing data")]
    Write(JsValue),
    #[error("An error occurred while flushing data")]
    Flush(JsValue),
    #[error("An error occurred while truncating data")]
    Truncate(JsValue),
    #[error("An error occurred while getting data using reflect")]
    Reflect(JsValue),
    #[error("Generic error: {0}")]
    Generic(String),
}

impl OpfsSAHError {
    fn vfs_err(&self, code: i32) -> VfsError {
        VfsError::new(code, format!("{self}"))
    }
}

/// SAHPoolVfs management tool.
pub struct OpfsSAHPoolUtil {
    pool: &'static VfsAppData<SyncAccessHandleAppData>,
}

// `OpfsSAHPoolUtil` is the external pool-management tool returned by `install`, re-exported as the
// crate's public vendoring API (see lib.rs) — so its methods are genuine public API, not "dead", even
// where freehold itself has no in-crate caller.
impl OpfsSAHPoolUtil {
    pub fn get_capacity(&self) -> u32 {
        self.pool.get_capacity()
    }

    pub async fn add_capacity(&self, n: u32) -> Result<u32> {
        self.pool.add_capacity(n).await
    }

    /// Upstream sahpool storage-reclaim knob (optional vendoring surface, not used by freehold).
    #[cfg(feature = "pool-management")]
    #[allow(dead_code)] // external API: no in-crate caller by design
    pub async fn reduce_capacity(&self, n: u32) -> Result<u32> {
        self.pool.reduce_capacity(n).await
    }

    #[allow(dead_code)]
    pub async fn reserve_minimum_capacity(&self, min: u32) -> Result<()> {
        self.pool.reserve_minimum_capacity(min).await
    }

    // ===== Test/attacker-simulation surface — compiled out unless `testing-api` (security-review
    // 1.1/1.2). `import_raw` bypasses AEAD (it IS the attacker); the fault injector and raw export
    // exist only to drive the §14 harness. None of these belong in a production build. =====

    /// ENC: raw ciphertext of a file's data region (for the §14.6 ciphertext audit).
    #[cfg(feature = "testing-api")]
    pub fn export_raw(&self, filename: &str) -> Result<Vec<u8>> {
        self.pool.export_raw(filename)
    }

    /// ENC (M2): overwrite a file's raw data region — simulates an attacker with OPFS write access.
    #[cfg(feature = "testing-api")]
    pub fn import_raw(&self, filename: &str, bytes: &[u8]) -> Result<()> {
        self.pool.import_raw(filename, bytes)
    }

    /// ENC (M2): current `db_generation` of an opened main DB (None if never opened in this pool).
    #[cfg(feature = "testing-api")]
    pub fn manifest_generation(&self, db: &str) -> Option<u64> {
        self.pool.manifest_generation(db)
    }


    /// ENC (M3, §14.8): arm the fault injector — the next `n` persistence ops land, then power dies.
    #[cfg(feature = "testing-api")]
    pub fn arm_fault(&self, n: u32) {
        self.pool.fault.arm(n)
    }

    /// ENC (M3): restore the disk to live operation (call after the "crashed" connection closes).
    #[cfg(feature = "testing-api")]
    pub fn clear_fault(&self) {
        self.pool.fault.clear()
    }

    /// ENC (M3, §14.9): run the block-device size-math property test on a scratch pool file.
    #[cfg(feature = "testing-api")]
    pub fn proptest_blockdev(&self, iters: u32) -> Result<String> {
        self.pool.proptest_blockdev(iters)
    }

    /// ENC (M3, §14.8): corrupt `len` bytes of anchor slot `slot` (torn/tampered anchor write).
    #[cfg(feature = "testing-api")]
    pub fn corrupt_anchor_slot(&self, slot: usize, len: usize) -> Result<()> {
        self.pool.corrupt_anchor_slot(slot, len)
    }

    /// ENC (M3): the anchor slot currently holding the highest authenticating seq.
    #[cfg(feature = "testing-api")]
    pub fn active_anchor_slot(&self) -> usize {
        self.pool.active_anchor_slot()
    }

    /// issue #4 (anchor carry-forward): the decoded freshness anchor entries under this pool's DEK.
    #[cfg(feature = "testing-api")]
    pub fn anchor_entries(&self) -> Vec<crate::manifest::AnchorEntry> {
        self.pool.anchor_entries()
    }

    /// ENC (H1 test-rig): snapshot / restore the raw on-disk anchor bytes (attacker replay).
    /// `export_` is the symmetric partner of the used `import_anchor_raw`; kept for the test rig.
    #[cfg(feature = "testing-api")]
    #[allow(dead_code)]
    pub fn export_anchor_raw(&self) -> Result<Vec<u8>> {
        self.pool.export_anchor_raw()
    }
    #[cfg(feature = "testing-api")]
    pub fn import_anchor_raw(&self, bytes: &[u8]) -> Result<()> {
        self.pool.import_anchor_raw(bytes)
    }

    /// issue #4 / D-RK2: re-key a CLOSED DB's ciphertext from this pool's DEK to `new_dek`, returning
    /// the re-sealed (main + manifest) files to import into a pool built with `new_dek`. Same
    /// `db_uuid`, same plaintext — a pure per-block re-seal (see `reseal_db_ciphertext`). Proof-only
    /// for now (increment 1b); the wired rotation ceremony + two-store commit barrier is increment 2.
    #[cfg(feature = "testing-api")]
    pub fn reseal_db(&self, db_name: &str, new_dek: &[u8; 32]) -> Result<Vec<(String, Vec<u8>)>> {
        self.pool.reseal_db_ciphertext(db_name, new_dek)
    }

    /// issue #4 / D-RK2+D-RK4 (DEK rotation, increment 2): stage the OPFS half of a rotation ceremony
    /// crash-safely — re-seal every `db_names` DB to `new_dek` into shadow files + write an intent
    /// record sealed under `new_dek`, leaving the live image untouched (see `stage_rotation`). The DBs
    /// must be CLOSED. The SDK's `idbSet('envelope')` that follows is the commit barrier.
    pub fn stage_rotation(
        &self,
        new_dek: &[u8; 32],
        db_names: &[String],
        old_gen: u64,
        new_gen: u64,
    ) -> Result<()> {
        self.pool.stage_rotation(new_dek, db_names, old_gen, new_gen)
    }

    /// issue #4 / D-RK4: reconcile any staged rotation against this pool's installed DEK on open —
    /// roll FORWARD (intent opens under our DEK: commit happened) or BACK (it does not: pre-commit
    /// crash). No-op when no rotation is staged. See `recover_rotation`.
    pub fn recover_rotation(&self) -> Result<Option<String>> {
        self.pool.recover_rotation()
    }

    /// ENC (M3 cross-device): export a DB's encrypted image (main + manifest) as a `name|hex` bundle.
    /// The DEK is NOT included — the bytes are opaque ciphertext (server-blind sync primitive).
    pub fn export_bundle(&self, db_name: &str) -> Result<String> {
        self.pool.export_bundle(db_name)
    }

    /// ENC (M3 cross-device): import an encrypted DB image produced by `export_bundle` on another
    /// device. Writes ciphertext files; opening them still requires the DEK (passkey/recovery).
    pub fn import_files(&self, files: &[(String, Vec<u8>)]) -> Result<()> {
        self.pool.import_files(files)
    }

    /// ENC (sync-epoch): mint this device's epoch token for `db_name` (DEK-authenticated freshness
    /// attestation to hand to a peer). `env_generation` (#3c) is the current key-envelope generation
    /// the caller attests alongside the DB generation. Requires the pool installed with the REAL DEK.
    pub fn export_epoch(&self, db_name: &str, env_generation: u64) -> Result<Vec<u8>> {
        self.pool.export_epoch(db_name, env_generation)
    }

    /// ENC (sync-epoch): apply a peer's epoch token — verify + raise the local DB freshness
    /// high-water mark so a subsequent rollback below it is refused at open. Returns
    /// `(db_generation, env_generation)`; the caller enforces the attested envelope generation
    /// (#3c) against the envelope it unlocks. Requires the REAL DEK.
    pub fn apply_epoch(&self, token: &[u8]) -> Result<(u64, u64)> {
        self.pool.apply_epoch(token)
    }

    /// ENC (freehold-vfs-merkle-root D-MR1/D-MR5): the full-state Merkle root over the named main
    /// DB's current plaintext blocks. Exposed for block-delta (D-BD9), which uses it as the
    /// authenticated **base fingerprint** (refuse a delta onto a divergent same-generation base) and
    /// the **result check** (recompute after applying a delta, require it == the sealed root before
    /// the atomic swap). Deterministic + stable across devices for identical logical state. The DB
    /// must be open (its `K_db` bound to the handle); returns the same value now sealed in its
    /// manifest at the last commit.
    pub fn full_state_root(&self, db_name: &str) -> Result<[u8; 32]> {
        self.pool.full_state_root(db_name)
    }

    /// ENC (freehold-sync-design §4): the opaque per-DB relay bucket id for this pool's DEK. 16 bytes;
    /// a capability the device holds, safe to hand to the relay — it is NOT the key.
    pub fn sync_id(&self, db_uuid: &[u8; 16]) -> [u8; 16] {
        self.pool.sync_id(db_uuid)
    }

    /// ENC (freehold-sync-design §5): the DEK-derived subkey that seals/opens sync blobs. Returned as
    /// a `Crypto` (a purpose-limited subkey, not the DEK) so the sync layer can seal/open in wasm
    /// without the DEK ever leaving the pool.
    pub fn sync_crypto(&self) -> Crypto {
        self.pool.sync_crypto()
    }

    pub fn delete_db(&self, filename: &str) -> Result<bool> {
        self.pool.delete_file(filename)
    }

    pub async fn clear_all(&self) -> Result<()> {
        self.pool.release_access_handles();
        self.pool.acquire_access_handles(true).await?;
        Ok(())
    }

    pub fn exists(&self, filename: &str) -> Result<bool> {
        Ok(self.pool.has_filename(filename))
    }

    pub fn list(&self) -> Vec<String> {
        self.pool.get_filenames()
    }

    /// Upstream sahpool usage-introspection knob (harmless external API; no in-crate caller).
    #[allow(dead_code)]
    pub fn count(&self) -> u32 {
        self.pool.get_file_count()
    }

    pub fn pause_vfs(&self) -> Result<()> {
        self.pool.pause_vfs()
    }

    pub async fn unpause_vfs(&self) -> Result<()> {
        self.pool.unpause_vfs().await
    }

    pub fn is_paused(&self) -> bool {
        self.pool.is_paused.get()
    }
}

/// Register the encrypting `freehold` VFS with the injected DEK and return a management tool.
///
/// ENC: the DEK (design-spec §11) is bound at registration and lives only inside the pool's `Crypto`
/// (HKDF-derived subkey); it is never written to OPFS. If a VFS with `options.vfs_name` is already
/// registered, this returns a management tool WITHOUT re-registering (and ignores `dek`).
///
/// # Required caller invariant (security-review 2.1)
/// Every DB opened on this VFS MUST be pinned to `page_size == 4096` before its first write, and the
/// connection MUST run `PRAGMA temp_store=MEMORY` (ideally with a `SQLITE_TEMP_STORE=3` compile-time
/// build). Temp/statement-journal files are only forced into memory by those settings; any that DO
/// reach the VFS are still encrypted, but under the **pool-domain** subkey (not a DB's `db_uuid`-
/// salted `K_db`) — a weaker, non-per-DB separation. The block device fails *closed* (encrypted)
/// regardless, but the per-DB isolation guarantee holds only for main-DB + journal/WAL files.
pub async fn install<C: OsCallback>(
    options: &OpfsSAHPoolCfg,
    default_vfs: bool,
    dek: &[u8; 32], // ENC
) -> Result<OpfsSAHPoolUtil> {
    static REGISTER_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _guard = REGISTER_GUARD.lock().await;

    let vfs = match registered_vfs(&options.vfs_name)? {
        Some(vfs) => vfs,
        None => register_vfs::<SyncAccessHandleIoMethods, SyncAccessHandleVfs<C>>(
            &options.vfs_name,
            OpfsSAHPool::new::<C>(options, dek).await?, // ENC
            default_vfs,
        )?,
    };

    let pool = unsafe { SyncAccessHandleStore::app_data(vfs) };
    pool.vfs.set((vfs, default_vfs));

    Ok(OpfsSAHPoolUtil { pool })
}
