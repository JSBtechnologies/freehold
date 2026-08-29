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
    decode_anchor, encode_anchor, AnchorEntry, ManifestPayload, MANIFEST_HDR_LEN, MANIFEST_MAGIC,
};

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
        Ok(self
            .handle
            .get_size()
            .map_err(OpfsSAHError::GetSize)
            .map_err(|err| err.vfs_err(SQLITE_IOERR))? as usize
            - HEADER_OFFSET_DATA)
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
                if phys_at + p <= phys && self.phys_read(&mut physbuf, phys_at)? >= p {
                    crypto
                        .open_into(&file_id, &domain, k as u64, &physbuf, &mut plain)
                        .map_err(|_| {
                            VfsError::new(SQLITE_IOERR, "AEAD auth failed on read-modify-write".into())
                        })?;
                } else {
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
    fn arm(&self, n: u32) {
        self.countdown.set(Some(n));
        self.crashed.set(false);
    }
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
    // ENC (M2): subkey + AAD domain for the TrustedGeneration anchor file (§17.D).
    anchor_crypto: Crypto,
    anchor_fid: [u8; crypto::FILE_ID_LEN],
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
            anchor_fid: crypto::file_id_for("#anchor#"),   // ENC (M2)
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

    #[allow(clippy::await_holding_refcell_ref)]
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
        let filename =
            String::from_utf8(self.header_buffer.subarray(0, name_length as u32).to_vec()).unwrap();
        Ok(Some(filename))
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
            let mut plain = Zeroizing::new(vec![0u8; crypto::BLOCK_SIZE]);
            if self
                .anchor_crypto
                .open_into(&self.anchor_fid, &crypto::NO_DOMAIN, slot as u64, &buf, &mut plain)
                .is_err()
            {
                continue;
            }
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
        let mut sealed = vec![0u8; crypto::PHYS_BLOCK];
        self.anchor_crypto
            .seal_into(&self.anchor_fid, &crypto::NO_DOMAIN, slot as u64, &plain, &mut sealed)
            .map_err(|e| OpfsSAHError::Generic(format!("anchor seal failed: {e:?}")))?;
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
        let (seq, mut entries) = self.anchor_load();
        if let Some(i) = entries.iter().position(|e| &e.uuid == uuid) {
            let e = &mut entries[i];
            if let Some(c) = committed {
                e.committed = e.committed.max(c);
            }
            if let Some(f) = in_flight {
                e.in_flight = e.in_flight.max(f);
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
            });
        }
        self.anchor_save(seq + 1, &entries)
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
        let st = Rc::new(DbState { uuid, crypto: kdb, generation: Cell::new(1) });
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
            let f = files.get(name).unwrap();
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
                let f = files.get(name).unwrap();
                f.crypto.replace(st.crypto.clone());
                f.key_domain.set(st.uuid);
                f.is_main_db.set(true);
                f.logical_size.set(Some(0));
                return Ok(());
            }
        };

        // §17.D freshness state machine: manifest one behind the trusted window is a lost final
        // bump from a normal crash (recoverable, re-adopt); anything older is rollback (refuse).
        let gen = payload.db_generation;
        if let Some(e) = self.anchor_load().1.iter().find(|e| e.uuid == uuid) {
            if gen + 1 < e.committed {
                return Err(OpfsSAHError::Generic(format!(
                    "ROLLBACK DETECTED: manifest db_generation {gen} is older than trusted generation {} — refusing to open",
                    e.committed
                )));
            }
        }
        self.anchor_record(&uuid, Some(gen), Some(gen))?;

        let files = self.map_filename_to_file.borrow();
        let main = files.get(name).unwrap();
        main.crypto.replace(kdb.clone());
        main.key_domain.set(uuid); // security-review 3d: bind blocks to this DB's identity
        main.is_main_db.set(true);

        let main_fid = crypto::file_id_for(name);
        // ENC (M3, §14.8/§17.D): a nonzero rollback journal means a commit was interrupted — the
        // main file may legitimately be mid-write (grown, or block 0 torn). The journal's
        // pre-images are themselves AEAD-protected, and SQLite's replay restores + truncates the
        // main file before any page is served. So with a hot journal present, DEFER the strict
        // length/block-0 checks to post-replay state (they re-arm on the next journal-free open);
        // refusing here would brick the DB on a normal power loss.
        let hot_journal = {
            let jn = format!("{name}-journal");
            files
                .get(&jn)
                .is_some_and(|j| j.phys_size().map(|s| s > 0).unwrap_or(false))
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

        self.dbs.borrow_mut().insert(
            name.to_string(),
            Rc::new(DbState { uuid, crypto: kdb, generation: Cell::new(gen) }),
        );
        Ok(())
    }

    /// Bind a newly-opened journal/WAL to its owner DB's subkey (§17.E/H).
    fn bind_satellite(&self, name: &str) -> Result<()> {
        let Some(parent) = satellite_parent(name) else { return Ok(()) };
        let Some(st) = self.dbs.borrow().get(parent).cloned() else { return Ok(()) };
        let files = self.map_filename_to_file.borrow();
        if let Some(f) = files.get(name) {
            f.crypto.replace(st.crypto.clone());
            f.key_domain.set(st.uuid); // security-review 3d: satellites share the DB's AAD domain
        }
        Ok(())
    }

    /// §17.D commit barrier, run after a main-DB xSync made its ciphertext durable:
    /// record in_flight → seal+flush the ping-pong slot (with the §17.J length table) →
    /// record committed → adopt the new generation.
    fn on_main_synced(&self, name: &str) -> Result<()> {
        let Some(st) = self.dbs.borrow().get(name).cloned() else { return Ok(()) };
        let new_gen = st.generation.get() + 1;
        self.anchor_record(&st.uuid, None, Some(new_gen))?;

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
        let payload = ManifestPayload { db_generation: new_gen, db_uuid: st.uuid, files: table };
        let mfile = files
            .get(&mname)
            .ok_or_else(|| OpfsSAHError::Generic("manifest file missing at commit".into()))?;
        self.write_manifest_slot(mfile, &st.crypto, &mname, &payload)?;
        drop(files);

        self.anchor_record(&st.uuid, Some(new_gen), Some(new_gen))?;
        st.generation.set(new_gen);
        Ok(())
    }

    // ENC: test-rig helper — overwrite a file's raw DATA region (ciphertext) byte-for-byte,
    // simulating an attacker with OPFS write access (§14 tamper/relocation/rollback tests).
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

    fn manifest_generation(&self, db: &str) -> Option<u64> {
        self.dbs.borrow().get(db).map(|s| s.generation.get())
    }

    // ENC (M3, §14.8 test-rig): overwrite `len` bytes of anchor slot `slot` with 0xFF — simulates a
    // torn/tampered anchor write. Proves the double-buffer (security-review 6): corrupting one slot
    // must not nullify rollback protection, because the other slot survives.
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
    fn active_anchor_slot(&self) -> usize {
        let (seq, _) = self.anchor_load();
        (seq % 2) as usize
    }

    // ============ ENC (sync-epoch): peer-attested freshness (sync-epoch-design §4/§5) =============
    // Mint an epoch token for `db_name`: seal {db_uuid, generation, device_id} under K_epoch. Any of
    // the user's devices (sharing the DEK) can verify it; nobody without the DEK can forge it. The
    // generation is the manifest's current db_generation (the freshest state this device has).
    fn export_epoch(&self, db_name: &str) -> Result<Vec<u8>> {
        let mname = manifest_name(db_name);
        let (uuid, _kdb, payload) = {
            let files = self.map_filename_to_file.borrow();
            let mfile = files
                .get(&mname)
                .ok_or_else(|| OpfsSAHError::Generic("no manifest — nothing to attest".into()))?;
            self.read_manifest(mfile, &mname)?
        };
        let mut plain = Vec::with_capacity(16 + 8 + 16);
        plain.extend_from_slice(&uuid);
        plain.extend_from_slice(&payload.db_generation.to_le_bytes());
        plain.extend_from_slice(&self.device_id);
        Crypto::epoch_key(&self.dek)
            .seal_bytes(EPOCH_AAD, &plain)
            .map_err(|e| OpfsSAHError::Generic(format!("epoch seal: {e:?}")))
    }

    // Apply a peer's epoch token: verify under K_epoch, then RAISE this device's local anchor
    // high-water mark (`committed`) for that db_uuid — max only, never lower. The existing open-path
    // rollback check (`manifest_gen + 1 < committed`) then refuses any local state older than what a
    // peer has witnessed. Returns the attested generation. A stale token (gen ≤ our committed) is a
    // harmless no-op; a forged/tampered token fails authentication.
    fn apply_epoch(&self, token: &[u8]) -> Result<u64> {
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
        self.anchor_record(&uuid, Some(gen), Some(gen))?;
        Ok(gen)
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

    fn import_bundle(&self, text: &str) -> Result<()> {
        for line in text.lines() {
            let Some((name, hex)) = line.split_once('|') else { continue };
            if hex.len() % 2 != 0 {
                return Err(OpfsSAHError::Generic("bundle: odd hex length".into()));
            }
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
                .collect();
            self.import_ciphertext_file(name, &bytes)?;
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

    // ENC (M3, §14.9): model-based property test of the block device's size/offset arithmetic.
    // Drives a scratch pool file through random SQLite-shaped operations (append/overwrite writes
    // with no sparse holes; shrink-only truncates — SQLite never grows via xTruncate or writes
    // past a gap) and checks every state against a shadow byte-array model: read-back content,
    // zero-fill past EOF, and exact `size()` round-trips (the classic off-by-`P` bug site, §12).
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
        pool.delete_file(file)
            .map_err(|err| err.vfs_err(SQLITE_IOERR_DELETE))?;
        // ENC (M3, §17.D): in rollback-journal mode, deleting the journal IS the commit/rollback
        // finalization point — the data state just became canonical. Refresh the manifest here so
        // it can never describe a state the journal subsequently rolled back (crash between
        // manifest write and journal delete would otherwise leave a manifest one txn ahead of the
        // recovered data, bricking the next strict open).
        if file.ends_with("-journal") {
            if let Some(parent) = satellite_parent(file) {
                pool.on_main_synced(parent)
                    .map_err(|err| err.vfs_err(SQLITE_IOERR))?;
            }
        }
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

    // ENC (M3, §17.D): mirror of the xDelete journal hook for `locking_mode=EXCLUSIVE`, where
    // SQLite truncates the journal to zero instead of deleting it at commit end. A successful
    // journal reset finalizes the transaction → refresh the manifest to the canonical state.
    unsafe extern "C" fn xTruncate(
        pFile: *mut sqlite3_file,
        size: rsqlite_vfs::ffi::sqlite3_int64,
    ) -> ::std::os::raw::c_int {
        let vfs_file = SQLiteVfsFile::from_file(pFile);
        let app_data = SyncAccessHandleStore::app_data(vfs_file.vfs);
        let f = |file: &mut SyncAccessFile| {
            file.truncate(size as usize)?;
            Ok(SQLITE_OK)
        };
        let code = match SyncAccessHandleStore::with_file_mut(vfs_file, f) {
            Ok(code) => code,
            Err(err) => return app_data.store_err(err),
        };
        if code == SQLITE_OK && size == 0 {
            let name = vfs_file.name();
            if name.ends_with("-journal") {
                if let Some(parent) = satellite_parent(name) {
                    if let Err(err) = app_data.on_main_synced(parent) {
                        return app_data.store_err(err.vfs_err(SQLITE_IOERR));
                    }
                }
            }
        }
        code
    }

    // ENC (M2, §17.D): xSync is the durability barrier. After the data flush, a main-DB sync also
    // bumps `db_generation`, writes+flushes the ping-pong manifest slot, and records the anchor —
    // in exactly that order (data durable → manifest durable → anchor), so a crash at any point
    // leaves an openable state. Satellite syncs flush data only.
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
        let code = match SyncAccessHandleStore::with_file_mut(vfs_file, f) {
            Ok(code) => code,
            Err(err) => return app_data.store_err(err),
        };
        if code != SQLITE_OK {
            return code;
        }
        // security-review 1.3: only a MAIN-DB sync is a commit barrier. `on_main_synced` already
        // no-ops for non-main names (they are absent from `dbs`), but gate on the open flag too so
        // the invariant is explicit and a journal sync can never trigger a generation bump.
        if vfs_file.flags & SQLITE_OPEN_MAIN_DB != 0 {
            if let Err(err) = app_data.on_main_synced(vfs_file.name()) {
                return app_data.store_err(err.vfs_err(SQLITE_IOERR));
            }
        }
        SQLITE_OK
    }
}

struct SyncAccessHandleVfs<C>(PhantomData<C>);

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
    #[error("An error occurred while getting filename")]
    GetPath(JsValue),
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

impl OpfsSAHPoolUtil {
    pub fn get_capacity(&self) -> u32 {
        self.pool.get_capacity()
    }

    pub async fn add_capacity(&self, n: u32) -> Result<u32> {
        self.pool.add_capacity(n).await
    }

    pub async fn reduce_capacity(&self, n: u32) -> Result<u32> {
        self.pool.reduce_capacity(n).await
    }

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

    /// ENC (M3 cross-device): export a DB's encrypted image (main + manifest) as a `name|hex` bundle.
    /// The DEK is NOT included — the bytes are opaque ciphertext (server-blind sync primitive).
    pub fn export_bundle(&self, db_name: &str) -> Result<String> {
        self.pool.export_bundle(db_name)
    }

    /// ENC (M3 cross-device): import an encrypted DB image produced by `export_bundle` on another
    /// device. Writes ciphertext files; opening them still requires the DEK (passkey/recovery).
    pub fn import_bundle(&self, text: &str) -> Result<()> {
        self.pool.import_bundle(text)
    }

    /// ENC (sync-epoch): mint this device's epoch token for `db_name` (DEK-authenticated freshness
    /// attestation to hand to a peer). Requires the pool installed with the REAL DEK.
    pub fn export_epoch(&self, db_name: &str) -> Result<Vec<u8>> {
        self.pool.export_epoch(db_name)
    }

    /// ENC (sync-epoch): apply a peer's epoch token — verify + raise the local freshness high-water
    /// mark so a subsequent rollback below it is refused at open. Requires the REAL DEK.
    pub fn apply_epoch(&self, token: &[u8]) -> Result<u64> {
        self.pool.apply_epoch(token)
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
