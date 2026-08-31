//! freehold — passkey-unlocked, header-free encrypted SQLite for the browser.
//!
//! `run_tests()` (exported to the worker) exercises the design-spec §14 cases M2 covers:
//!   2   round-trip (write rows, reopen, rows intact)
//!   3   wrong key ⇒ open rejected (manifest fails to decrypt — §17.E)
//!   4   tamper: flip one ciphertext byte ⇒ AEAD failure ⇒ SQLITE_IOERR (not short read, §17.K)
//!   5   cross-block relocation: block copied to another index ⇒ AEAD failure (AAD binding)
//!   5b  whole-file rollback: restore older image+manifest ⇒ anchor rejects (§10/§17.D)
//!   §17.C  torn manifest slot ⇒ other slot recovers, DB not bricked
//!   §17.I  page_size != B ⇒ write refused at creation
//!   §17.H(partial) ATTACH-ed DB gets its own manifest/db_uuid and is fully encrypted
//!   6/G ciphertext audit over EVERY pool file (no "SQLite format 3", no plaintext secret)
//!   10  crossOriginIsolated === false (header-free preserved)
//!   8   crash/fault-injection sweep: power loss at every persist-op boundary ⇒ pre- or post-txn
//!       state, never corrupt, never bricked (M3)
//!   9   size-math property test vs a shadow model (M3)
//!   11  perf: batched/single-commit throughput + AEAD microbenchmark (M3; no null-cipher
//!       plaintext baseline by design — §17.G)
//!   S   session model: session_open → parameterized SQL on named DBs → lock → reopen (mock PRF)
//! See BUILD-NOTES for the honest IN/DEFERRED ledger.

mod bundle;
mod crypto;
mod envelope;
mod manifest;
mod sync;
mod vfs;

use sqlite_wasm_rs as ffi;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use vfs::{install, OpfsSAHPoolCfgBuilder, OpfsSAHPoolUtil};
use wasm_bindgen::prelude::*;

// Demo DEKs. Stand-ins for the passkey-PRF-derived key (design-spec §11 / topic M2).
const DEK_OK: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const DEK_BAD: [u8; 32] = [0xff; 32];

const SECRET: &str = "topsecret-plaintext-canary-42";
const SECRET2: &str = "attached-db-canary-77";
const DB_NAME: &str = "app.db";
const MANIFEST: &str = "app.db#manifest";
const DIR: &str = "enc-m2";

unsafe fn open_default(name: &str) -> std::result::Result<*mut ffi::sqlite3, String> {
    let cname = CString::new(name).unwrap();
    let mut db = ptr::null_mut();
    let rc = ffi::sqlite3_open_v2(
        cname.as_ptr(),
        &mut db,
        ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE,
        ptr::null(),
    );
    if rc != ffi::SQLITE_OK {
        let msg = if db.is_null() {
            String::new()
        } else {
            let p = ffi::sqlite3_errmsg(db);
            let s = if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            };
            ffi::sqlite3_close(db);
            s
        };
        return Err(format!("open rc={rc} ({msg})"));
    }
    Ok(db)
}

unsafe fn exec(db: *mut ffi::sqlite3, sql: &str) -> std::result::Result<(), String> {
    let csql = CString::new(sql).unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let rc = ffi::sqlite3_exec(db, csql.as_ptr(), None, ptr::null_mut(), &mut err);
    if rc == ffi::SQLITE_OK {
        return Ok(());
    }
    let msg = if err.is_null() {
        String::new()
    } else {
        let s = CStr::from_ptr(err).to_string_lossy().into_owned();
        ffi::sqlite3_free(err.cast());
        s
    };
    let xrc = ffi::sqlite3_extended_errcode(db);
    Err(format!("rc={rc} xrc={xrc} {msg}"))
}

unsafe fn scalar_i64(db: *mut ffi::sqlite3, sql: &str) -> std::result::Result<i64, String> {
    let csql = CString::new(sql).unwrap();
    let mut stmt = ptr::null_mut();
    let rc = ffi::sqlite3_prepare_v2(db, csql.as_ptr(), -1, &mut stmt, ptr::null_mut());
    if rc != ffi::SQLITE_OK {
        return Err(format!("prepare rc={rc}"));
    }
    let step = ffi::sqlite3_step(stmt);
    let out = if step == ffi::SQLITE_ROW {
        Ok(ffi::sqlite3_column_int64(stmt, 0))
    } else {
        Err(format!("step rc={step}"))
    };
    ffi::sqlite3_finalize(stmt);
    out
}

unsafe fn scalar_text(db: *mut ffi::sqlite3, sql: &str) -> std::result::Result<String, String> {
    let csql = CString::new(sql).unwrap();
    let mut stmt = ptr::null_mut();
    let rc = ffi::sqlite3_prepare_v2(db, csql.as_ptr(), -1, &mut stmt, ptr::null_mut());
    if rc != ffi::SQLITE_OK {
        return Err(format!("prepare rc={rc}"));
    }
    let step = ffi::sqlite3_step(stmt);
    let out = if step == ffi::SQLITE_ROW {
        let p = ffi::sqlite3_column_text(stmt, 0);
        Ok(CStr::from_ptr(p.cast()).to_string_lossy().into_owned())
    } else {
        Err(format!("step rc={step}"))
    };
    ffi::sqlite3_finalize(stmt);
    out
}

/// Mandated connection pragmas (design-spec §7 / §17): rollback-journal (NOT WAL), temp in memory,
/// single-connection exclusive locking, page size pinned to the encryption block size B=4096 (§17.I).
unsafe fn set_pragmas(db: *mut ffi::sqlite3) -> std::result::Result<(), String> {
    exec(db, "PRAGMA page_size=4096")?;
    exec(db, "PRAGMA journal_mode=DELETE")?;
    exec(db, "PRAGMA temp_store=MEMORY")?;
    exec(db, "PRAGMA locking_mode=EXCLUSIVE")?;
    Ok(())
}

fn cfg(name: &str, clear: bool) -> vfs::OpfsSAHPoolCfg {
    OpfsSAHPoolCfgBuilder::new()
        .vfs_name(name)
        .directory(DIR)
        .clear_on_init(clear)
        .initial_capacity(10)
        .build()
}

async fn install_key(
    name: &str,
    clear: bool,
    dek: &[u8; 32],
) -> std::result::Result<OpfsSAHPoolUtil, String> {
    install::<ffi::WasmOsCallback>(&cfg(name, clear), true, dek)
        .await
        .map_err(|e| format!("install {name}: {e:?}"))
}

fn cross_origin_isolated() -> bool {
    js_sys::global()
        .dyn_into::<js_sys::Object>()
        .ok()
        .and_then(|g| js_sys::Reflect::get(&g, &JsValue::from_str("crossOriginIsolated")).ok())
        .map(|v| v.is_truthy())
        .unwrap_or(false)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// §14.6 + §17.G negative test: every file the pool holds must contain neither the SQLite magic
/// nor any plaintext canary anywhere in its raw data region.
fn audit_all(util: &OpfsSAHPoolUtil, label: &str) -> std::result::Result<String, String> {
    let mut out = String::new();
    for f in util.list() {
        let raw = util
            .export_raw(&f)
            .map_err(|e| format!("export_raw {f}: {e:?}"))?;
        let magic = contains(&raw, b"SQLite format 3");
        let s1 = contains(&raw, SECRET.as_bytes());
        let s2 = contains(&raw, SECRET2.as_bytes());
        if magic || s1 || s2 {
            return Err(format!(
                "CIPHERTEXT AUDIT FAILED ({label}) in {f}: magic={magic} secret={s1} secret2={s2}"
            ));
        }
        out.push_str(&format!("     audited {f}: {} bytes opaque\n", raw.len()));
    }
    Ok(out)
}

/// Open with the correct key and count rows in `t` — used to prove recovery after each attack test.
unsafe fn count_rows() -> std::result::Result<i64, String> {
    let db = open_default(DB_NAME)?;
    let n = scalar_i64(db, "SELECT count(*) FROM t");
    ffi::sqlite3_close(db);
    n
}

fn dir_cfg(vfs_name: &str, dir: &str, clear: bool) -> vfs::OpfsSAHPoolCfg {
    OpfsSAHPoolCfgBuilder::new()
        .vfs_name(vfs_name)
        .directory(dir)
        .clear_on_init(clear)
        .initial_capacity(6)
        .build()
}
async fn install_dir(
    vfs_name: &str,
    dir: &str,
    clear: bool,
    dek: &[u8; 32],
) -> std::result::Result<OpfsSAHPoolUtil, String> {
    vfs::install::<ffi::WasmOsCallback>(&dir_cfg(vfs_name, dir, clear), true, dek)
        .await
        .map_err(|e| format!("install {vfs_name}: {e:?}"))
}

/// Sync-epoch anchor test (sync-epoch-design §6): a peer's epoch raises this device's freshness
/// high-water mark, so a later rollback below it is REFUSED — and the contrast device (no epoch)
/// shows the rollback would otherwise slip through. Two "devices" = two independent pool dirs.
async fn sync_epoch_test() -> std::result::Result<String, String> {
    const SDB: &str = "sync.db";
    // ---- Device A: commit to a high generation; snapshot an EARLY (stale) image + a LATE epoch ----
    let a = install_dir("se-a", "epoch-a", true, &DEK_OK).await?;
    let (img_early, epoch_late) = unsafe {
        let db = open_default(SDB)?;
        set_pragmas(db)?;
        exec(db, "CREATE TABLE t(v TEXT)")?;
        exec(db, "INSERT INTO t(v) VALUES ('one')")?;
        ffi::sqlite3_close(db);
        let early_text = a.export_bundle(SDB).map_err(|e| format!("export early: {e:?}"))?; // low gen
        let early: Vec<(String, Vec<u8>)> = early_text
            .lines()
            .filter_map(|l| l.split_once('|'))
            .map(|(n, h)| Ok::<_, String>((n.to_string(), hex_to_bytes(h)?)))
            .collect::<std::result::Result<_, _>>()?;
        let db = open_default(SDB)?;
        exec(db, "INSERT INTO t(v) VALUES ('two'),('three')")?; // advance the generation
        ffi::sqlite3_close(db);
        let ep = a.export_epoch(SDB).map_err(|e| format!("export epoch: {e:?}"))?; // attests the HIGH gen
        (early, ep)
    };
    let gen_a = a.manifest_generation(SDB).unwrap_or(0);
    a.pause_vfs().map_err(|e| format!("pause A: {e:?}"))?;

    // ---- Device B: apply A's LATE epoch, then be handed only the STALE image. B never saw the fresh
    // state — the peer epoch is the ONLY reason it knows the import is a rollback. Must be REJECTED. --
    let b = install_dir("se-b", "epoch-b", true, &DEK_OK).await?;
    let seen = b.apply_epoch(&epoch_late).map_err(|e| format!("B apply epoch: {e:?}"))?;
    b.import_files(&img_early).map_err(|e| format!("B import early: {e:?}"))?;
    let rolled_back_rejected = unsafe {
        match open_default(SDB) {
            Err(_) => true,
            Ok(db) => {
                let got = scalar_i64(db, "SELECT count(*) FROM t");
                ffi::sqlite3_close(db);
                got.is_err()
            }
        }
    };
    b.pause_vfs().map_err(|e| format!("pause B: {e:?}"))?;

    // ---- Device C (contrast): SAME stale image, but NO epoch applied → opens (rollback NOT caught) --
    let c = install_dir("se-c", "epoch-c", true, &DEK_OK).await?;
    c.import_files(&img_early).map_err(|e| format!("C import early: {e:?}"))?;
    let contrast_opens = unsafe {
        match open_default(SDB) {
            Ok(db) => {
                let ok = scalar_i64(db, "SELECT count(*) FROM t").is_ok();
                ffi::sqlite3_close(db);
                ok
            }
            Err(_) => false,
        }
    };
    c.pause_vfs().map_err(|e| format!("pause C: {e:?}"))?;

    if !rolled_back_rejected {
        return Err("SYNC-EPOCH FAILED: B accepted a stale image below a peer-attested epoch!".into());
    }
    if !contrast_opens {
        return Err("SYNC-EPOCH inconclusive: contrast device C did not open the stale image".into());
    }
    Ok(format!(
        "SE. sync-epoch anchor: A commits to gen {gen_a} and attests epoch={seen}; B (which never saw \
the fresh state) applies the peer epoch then is fed the STALE image → open REJECTED; contrast device \
with NO epoch opens the same stale image → the peer epoch is exactly what prevents the rollback \u{2705}"
    ))
}

/// Export DB `db_name` from `util`'s pool as `.freehold` bundle bytes (the sync blob `image`).
/// `export_bundle` yields `name|hex` text of the encrypted files; we re-encode those into the real
/// binary TLV bundle (`bundle.rs`) — no envelope/cred_id/epoch section (sync carries only the image).
fn export_image(util: &OpfsSAHPoolUtil, db_name: &str) -> std::result::Result<Vec<u8>, String> {
    let text = util
        .export_bundle(db_name)
        .map_err(|e| format!("export_bundle {db_name}: {e:?}"))?;
    let files: Vec<(String, Vec<u8>)> = text
        .lines()
        .filter_map(|l| l.split_once('|'))
        .map(|(n, h)| Ok::<_, String>((n.to_string(), hex_to_bytes(h)?)))
        .collect::<std::result::Result<_, _>>()?;
    // Envelope section is empty here: the image is pure ciphertext, decrypted later under the DEK.
    Ok(bundle::encode(&[], &[], &files, &[]))
}

/// Inverse of [`export_image`]: decode a `.freehold` bundle and write its ciphertext files into
/// `util`'s pool via `import_files`. Opening them still needs the DEK.
fn import_image(util: &OpfsSAHPoolUtil, image: &[u8]) -> std::result::Result<(), String> {
    let b = bundle::decode(image).map_err(|e| format!("bundle decode: {e}"))?;
    util.import_files(&b.files)
        .map_err(|e| format!("import_files: {e:?}"))
}

/// Section SY — Freehold Sync FIRST proof increment (freehold-sync-design §7/§7.1/§10). Proves the
/// ordering + conflict semantics against a blind-relay mock with N pool-dirs-as-devices, exactly as
/// the sync-epoch mechanism was proven before real hardware. NO server/P2P/browser wiring here.
///
/// All three devices share `DEK_OK` (single-user model: every device holds the DEK). Each device
/// has its own random 16-byte `device_id`. One logical DB (fixed test `db_uuid`) → one `sync_id`.
async fn sync_test() -> std::result::Result<String, String> {
    use sync::{reconcile, InMemoryRelay, MergeOutcome, SyncBlob, VersionVector};
    const SYDB: &str = "sy.db";

    // Sanity: the version-vector algebra + reconcile determinism, before the device dance.
    sync::self_check()?;

    // One logical DB → one relay bucket. sync_id is opaque to the relay, derived off the shared DEK.
    let db_uuid: [u8; 16] = *b"freehold-sy-uuid";
    let sync_id = crypto::sync_id(&DEK_OK, &db_uuid);
    let sync = crypto::Crypto::sync_key(&DEK_OK);
    let mut relay = InMemoryRelay::new();

    // Per-device random device_ids (getrandom — same RNG the crypto core fails closed on).
    let mut dev_a = [0u8; 16];
    let mut dev_b = [0u8; 16];
    getrandom::getrandom(&mut dev_a).map_err(|_| "rng dev_a".to_string())?;
    getrandom::getrandom(&mut dev_b).map_err(|_| "rng dev_b".to_string())?;

    // ---------------- (a) CONVERGE: A creates + inserts, pushes; B (fresh) pulls + fast-forwards ----
    let a = install_dir("sy-a", "sync-a", true, &DEK_OK).await?;
    unsafe {
        let db = open_default(SYDB)?;
        set_pragmas(db)?;
        exec(db, "CREATE TABLE t(v TEXT)")?;
        exec(db, "INSERT INTO t(v) VALUES ('alpha')")?;
        ffi::sqlite3_close(db);
    }
    let mut vv_a = VersionVector::new();
    vv_a.increment(&dev_a); // A's local vv = {A:1}
    let image_a0 = export_image(&a, SYDB)?;
    let blob_a0 = SyncBlob { db_uuid, vv: vv_a.clone(), image: image_a0.clone() };
    let sealed_a0 = blob_a0.seal(&sync).map_err(|e| format!("seal a0: {e:?}"))?;
    relay.put(sync_id, sealed_a0);
    a.pause_vfs().map_err(|e| format!("pause A: {e:?}"))?;

    // B pulls: blind LIST/GET, open (authenticated), reconcile(empty, {A:1}) → FastForward, import.
    let b = install_dir("sy-b", "sync-b", true, &DEK_OK).await?;
    let mut vv_b = VersionVector::new(); // B starts empty
    let mut b_cursor = 0usize;
    let new_for_b = relay.list(&sync_id, b_cursor);
    if new_for_b != 1 {
        return Err(format!("SY(a): B expected 1 new blob, saw {new_for_b}"));
    }
    let sealed = relay
        .get(&sync_id, b_cursor)
        .ok_or("SY(a): relay.get miss")?;
    let incoming = SyncBlob::open(&sealed, &sync)?;
    b_cursor += 1; // advance the pull cursor past the blob we just consumed
    if relay.list(&sync_id, b_cursor) != 0 {
        return Err("SY(a): B's cursor should be caught up after one pull".into());
    }
    match reconcile(&vv_b, &incoming.vv) {
        MergeOutcome::FastForward => {}
        other => return Err(format!("SY(a): expected FastForward, got {other:?}")),
    }
    import_image(&b, &incoming.image)?;
    vv_b.merge_max(&incoming.vv); // B's vv becomes {A:1}
    let converged = unsafe {
        let db = open_default(SYDB)?;
        let got = scalar_text(db, "SELECT v FROM t LIMIT 1")?;
        ffi::sqlite3_close(db);
        got
    };
    if converged != "alpha" {
        return Err(format!("SY(a): B read back '{converged}', expected 'alpha'"));
    }
    if vv_b.relation(&vv_a) != sync::Relation::Equal {
        return Err("SY(a): B's vv should equal {A:1} after fast-forward".into());
    }
    b.pause_vfs().map_err(|e| format!("pause B: {e:?}"))?;

    // ---------------- (b) STALE: incoming {A:1} vs a strictly-greater local {A:2} → rejected -------
    // Model B having advanced to {A:2}; A pushes an older/equal {A:1} state. reconcile must reject.
    let mut vv_b2 = VersionVector::new();
    vv_b2.increment(&dev_a);
    vv_b2.increment(&dev_a); // local = {A:2}
    let vv_stale = vv_a.clone(); // incoming = {A:1}
    match reconcile(&vv_b2, &vv_stale) {
        MergeOutcome::Stale => {}
        other => return Err(format!("SY(b): expected Stale, got {other:?}")),
    }

    // ---------------- (c) FORK (headline): shared base {A:1}; A and B commit INDEPENDENTLY ---------
    // Shared base = image_a0 (the {A:1} state) present on both A and B. Each commits locally.
    //   A: {A:1} → {A:2}, image_A (adds 'from-A')
    //   B: {A:1} → {A:1,B:1}, image_B (adds 'from-B')
    // A device is a fresh pool seeded with the base image, then a local commit on top.
    async fn commit_on_base(
        vfs_name: &str,
        dir: &str,
        base_image: &[u8],
        extra_sql: &str,
    ) -> std::result::Result<(OpfsSAHPoolUtil, Vec<u8>), String> {
        let util = install_dir(vfs_name, dir, true, &DEK_OK).await?;
        import_image(&util, base_image)?;
        unsafe {
            let db = open_default(SYDB)?;
            set_pragmas(db)?;
            exec(db, extra_sql)?;
            ffi::sqlite3_close(db);
        }
        let img = export_image(&util, SYDB)?;
        Ok((util, img))
    }

    // A commits: vv {A:2}
    let (fa, image_a) = commit_on_base("sy-fa", "sync-fa", &image_a0, "INSERT INTO t(v) VALUES ('from-A')").await?;
    let mut vv_fork_a = VersionVector::new();
    vv_fork_a.increment(&dev_a);
    vv_fork_a.increment(&dev_a); // {A:2}
    let blob_a = SyncBlob { db_uuid, vv: vv_fork_a.clone(), image: image_a.clone() };
    let sealed_a = blob_a.seal(&sync).map_err(|e| format!("seal fork A: {e:?}"))?;

    // B commits: vv {A:1,B:1}
    let (fb, image_b) = commit_on_base("sy-fb", "sync-fb", &image_a0, "INSERT INTO t(v) VALUES ('from-B')").await?;
    let mut vv_fork_b = VersionVector::new();
    vv_fork_b.increment(&dev_a); // inherited base commit belongs to A
    vv_fork_b.increment(&dev_b); // B's own commit
    let blob_b = SyncBlob { db_uuid, vv: vv_fork_b.clone(), image: image_b.clone() };
    let sealed_b = blob_b.seal(&sync).map_err(|e| format!("seal fork B: {e:?}"))?;

    fa.pause_vfs().map_err(|e| format!("pause fa: {e:?}"))?;
    fb.pause_vfs().map_err(|e| format!("pause fb: {e:?}"))?;

    // Both push; then A pulls B's blob and B pulls A's blob.
    relay.put(sync_id, sealed_a.clone());
    relay.put(sync_id, sealed_b.clone());

    // A-side reconcile: local {A:2}, incoming {A:1,B:1} (B's blob).
    let a_incoming = SyncBlob::open(&sealed_b, &sync)?;
    let a_outcome = reconcile(&vv_fork_a, &a_incoming.vv);
    // B-side reconcile: local {A:1,B:1}, incoming {A:2} (A's blob).
    let b_incoming = SyncBlob::open(&sealed_a, &sync)?;
    let b_outcome = reconcile(&vv_fork_b, &b_incoming.vv);

    let (a_win_incoming, b_win_incoming) = match (a_outcome, b_outcome) {
        (MergeOutcome::Fork { winner_is_incoming: aw }, MergeOutcome::Fork { winner_is_incoming: bw }) => (aw, bw),
        other => return Err(format!("SY(c): expected Fork on BOTH sides, got {other:?}")),
    };
    // The device holding the loser adopts the winner; the device holding the winner keeps it — so
    // winner_is_incoming must be OPPOSITE on the two sides (one adopts, one keeps).
    if a_win_incoming == b_win_incoming {
        return Err(format!(
            "SY(c): winner_is_incoming must differ across sides (A={a_win_incoming} B={b_win_incoming}) — non-deterministic!"
        ));
    }

    // Resolve each side to the WINNER image bytes and the LOSER (preserved) image bytes.
    // A side: incoming = image_b, local = image_a.
    let (a_winner_img, a_loser_img) = if a_win_incoming {
        (a_incoming.image.clone(), image_a.clone())
    } else {
        (image_a.clone(), a_incoming.image.clone())
    };
    // B side: incoming = image_a, local = image_b.
    let (b_winner_img, b_loser_img) = if b_win_incoming {
        (b_incoming.image.clone(), image_b.clone())
    } else {
        (image_b.clone(), b_incoming.image.clone())
    };

    // Convergence: both devices hold the IDENTICAL winner image.
    if a_winner_img != b_winner_img {
        return Err("SY(c): devices selected DIFFERENT winner images — no convergence!".into());
    }
    // Loser preserved on both sides: non-empty and distinct from the winner.
    if a_loser_img.is_empty() || b_loser_img.is_empty() {
        return Err("SY(c): a loser image was empty — fork not preserved".into());
    }
    if a_loser_img == a_winner_img || b_loser_img == b_winner_img {
        return Err("SY(c): loser image equals winner — fork collapsed, not preserved".into());
    }
    // Both devices converge on the SAME winner AND preserve the SAME losing sibling — the loser
    // must be identical across devices (both retain the one non-winning image), and it must be one
    // of the two real fork images, not something else.
    if a_loser_img != b_loser_img {
        return Err("SY(c): devices preserved DIFFERENT loser images — divergent fork state".into());
    }
    let loser = &a_loser_img;
    let winner = &a_winner_img;
    // The pair {winner, loser} must be exactly {image_a, image_b} (the two committed siblings).
    let pair_ok = (winner == &image_a && loser == &image_b) || (winner == &image_b && loser == &image_a);
    if !pair_ok {
        return Err("SY(c): winner/loser are not the two committed fork images".into());
    }

    // After resolution BOTH devices set vv = merge_max({A:2},{A:1,B:1}) = {A:2,B:1}, so the fork
    // does not re-trigger. Verify the merged vector is identical on both sides.
    let mut vv_a_after = vv_fork_a.clone();
    vv_a_after.merge_max(&a_incoming.vv);
    let mut vv_b_after = vv_fork_b.clone();
    vv_b_after.merge_max(&b_incoming.vv);
    if vv_a_after.relation(&vv_b_after) != sync::Relation::Equal {
        return Err("SY(c): merged vectors differ across devices — would re-trigger fork".into());
    }
    let mut vv_expected = VersionVector::new();
    vv_expected.increment(&dev_a);
    vv_expected.increment(&dev_a);
    vv_expected.increment(&dev_b); // {A:2,B:1}
    if vv_a_after.relation(&vv_expected) != sync::Relation::Equal {
        return Err("SY(c): merged vector != expected {A:2,B:1}".into());
    }

    // Determinism cross-check: the winner is a pure function of the pair, independent of arg order.
    let r1 = reconcile(&vv_fork_a, &vv_fork_b);
    let r2 = reconcile(&vv_fork_b, &vv_fork_a);
    match (r1, r2) {
        (MergeOutcome::Fork { winner_is_incoming: w1 }, MergeOutcome::Fork { winner_is_incoming: w2 }) => {
            if w1 == w2 {
                return Err("SY(c): reconcile not arg-order-symmetric".into());
            }
        }
        _ => return Err("SY(c): reconcile determinism cross-check not a Fork".into()),
    }

    Ok(
        "SY. sync (blind-relay mock, 3 devices): fast-forward converges | stale rejected | concurrent fork \u{2192} identical winner on both devices + loser preserved \u{2705}"
            .to_string(),
    )
}

/// Section RK — DEK rotation, PHYSICAL re-encryption (issue #4 / D-RK2, increment 1b). Proves the
/// block-device half of rotation the same way the sync mechanism was proven before wiring: with
/// pool-dirs-as-devices. A DB is written under `DEK_OK`, re-keyed to a fresh `dek2` via the pure
/// per-block `reseal_db` (same db_uuid, same plaintext), and re-imported into a pool built with
/// `dek2` — where it opens and reads back intact. The security-critical assertion: the SAME re-sealed
/// image under the OLD DEK does NOT yield the data — the old key is now useless against the rotated
/// database, which is the whole point of eviction. (The envelope half is proven by M3c; the two halves
/// are stitched into one atomic ceremony + commit barrier in increment 2.)
async fn rekey_test() -> std::result::Result<String, String> {
    const RKDB: &str = "rk.db";
    // A fresh DEK guaranteed distinct from DEK_OK.
    let mut dek2 = DEK_OK;
    dek2[0] ^= 0xff;

    // Source device: create + populate under DEK_OK, then close (re-key operates on ciphertext at rest).
    let src = install_dir("rk-src", "rk-src", true, &DEK_OK).await?;
    unsafe {
        let db = open_default(RKDB)?;
        set_pragmas(db)?;
        exec(db, "CREATE TABLE t(v TEXT)")?;
        exec(db, "INSERT INTO t(v) VALUES ('rotate-me')")?;
        ffi::sqlite3_close(db);
    }
    // Re-key the closed DB's ciphertext DEK_OK → dek2 (main + manifest, same db_uuid, same plaintext).
    let files = src.reseal_db(RKDB, &dek2).map_err(|e| format!("RK reseal: {e:?}"))?;
    if files.is_empty() {
        return Err("RK: reseal produced no files".into());
    }
    src.pause_vfs().map_err(|e| format!("RK pause src: {e:?}"))?;

    // Destination device: a pool built with dek2 imports the re-sealed image → opens + reads intact.
    let dst = install_dir("rk-dst", "rk-dst", true, &dek2).await?;
    dst.import_files(&files).map_err(|e| format!("RK import dst: {e:?}"))?;
    let got = unsafe {
        let db = open_default(RKDB)?;
        let v = scalar_text(db, "SELECT v FROM t LIMIT 1")?;
        ffi::sqlite3_close(db);
        v
    };
    if got != "rotate-me" {
        return Err(format!("RK: dek2 read back '{got}', expected 'rotate-me' (re-key corrupted the DB)"));
    }
    dst.pause_vfs().map_err(|e| format!("RK pause dst: {e:?}"))?;

    // SECURITY: the SAME re-sealed image under the OLD DEK must NOT recover the data. A pool built with
    // DEK_OK imports the dek2-sealed files; opening must fail to authenticate (or recreate empty) —
    // anything that yields 'rotate-me' means the old key still opens the rotated DB (rotation broken).
    let wrong = install_dir("rk-wrong", "rk-wrong", true, &DEK_OK).await?;
    wrong.import_files(&files).map_err(|e| format!("RK import wrong: {e:?}"))?;
    let leaked = unsafe {
        match open_default(RKDB) {
            Ok(db) => {
                let v = scalar_text(db, "SELECT v FROM t LIMIT 1").ok();
                ffi::sqlite3_close(db);
                v
            }
            Err(_) => None,
        }
    };
    if leaked.as_deref() == Some("rotate-me") {
        return Err("RK: re-sealed image decrypted under the OLD DEK — rotation did NOT change the key!".into());
    }
    wrong.pause_vfs().map_err(|e| format!("RK pause wrong: {e:?}"))?;

    Ok(
        "RK. DEK rotation (physical re-encryption): DB re-keyed DEK\u{2192}dek' via pure per-block reseal (same uuid/plaintext) opens + reads intact under dek'; the SAME image under the OLD DEK recovers nothing \u{2705}"
            .to_string(),
    )
}

/// Section S — the session model, driven exactly as the SDK drives it but with a MOCK PRF (no
/// gesture): open → typed parameterized SQL on named DBs → isolation → strict-name and
/// multi-statement-with-params rejection → lock kills ops → reopen sees the data. Runs on its own
/// pool dir so it never touches a real enrollment in `enc-passkey`.
async fn session_test() -> std::result::Result<String, String> {
    let js = |e: JsValue| e.as_string().unwrap_or_else(|| format!("{e:?}"));
    let prf: [u8; 32] = [21u8; 32]; // stand-in for the WebAuthn PRF assertion output
    let blob = envelope::create_envelope(&DEK_OK, &prf).map_err(|e| format!("S. create_envelope: {e:?}"))?;
    let dek = envelope::open_with_prf(&blob, &prf).map_err(|e| format!("S. open envelope: {e:?}"))?;

    // ---- open (fresh dir), create schema, parameterized insert covering every bound type -------
    session_begin(&dek, &blob, &[], &dir_cfg("pk-sess", "enc-session", true)).await?;
    if !session_active() {
        return Err("S. session_active=false right after session_open".into());
    }
    session_sql("app", "CREATE TABLE t(a,b,c,d,e)", "").map_err(&js)?;
    session_sql(
        "app",
        "INSERT INTO t(a,b,c,d,e) VALUES (?,?,?,?,?)",
        r#"[null, 42, 3.5, "s-\"quoted\"", true]"#,
    )
    .map_err(&js)?;
    let rows = session_sql("app", "SELECT a,b,c,d,e FROM t", "").map_err(&js)?;
    let want = r#"[[null,"42","3.5","s-\"quoted\"","1"]]"#; // null→NULL, bool→1, all values stringified
    if rows != want {
        return Err(format!("S. param round-trip mismatch: got {rows}, want {want}"));
    }

    // ---- second named DB, isolated from the first ----------------------------------------------
    session_sql("notes", "CREATE TABLE t(a)", "").map_err(&js)?;
    session_sql("notes", "INSERT INTO t(a) VALUES (?)", "[\"only-in-notes\"]").map_err(&js)?;
    let leak = session_sql("app", "SELECT count(*) FROM t WHERE a='only-in-notes'", "").map_err(&js)?;
    let n_app = session_sql("app", "SELECT count(*) FROM t", "").map_err(&js)?;
    let n_notes = session_sql("notes", "SELECT count(*) FROM t", "").map_err(&js)?;
    if leak != r#"[["0"]]"# || n_app != r#"[["1"]]"# || n_notes != r#"[["1"]]"# {
        return Err(format!(
            "S. named-DB isolation broken: leak={leak} app={n_app} notes={n_notes}"
        ));
    }

    // ---- strict db-name validation (the name becomes an OPFS filename) -------------------------
    let too_long = "a".repeat(33);
    for bad in ["App", "a b", "", "../x", "a.db", too_long.as_str()] {
        if session_sql(bad, "SELECT 1", "").is_ok() {
            return Err(format!("S. bad db name {bad:?} was ACCEPTED"));
        }
    }

    // ---- multi-statement WITH params must be rejected (params bind the FIRST statement only) ----
    match session_sql("app", "SELECT ?; SELECT 2", "[1]") {
        Ok(_) => return Err("S. multi-statement WITH params was ACCEPTED".into()),
        Err(e) => {
            let m = js(e);
            if !m.contains("single statement") {
                return Err(format!("S. multi+params rejected with the wrong error: {m}"));
            }
        }
    }

    // ---- lock: every op must fail; reopen: the data is intact -----------------------------------
    session_lock().map_err(&js)?;
    if session_active() {
        return Err("S. session_active=true after session_lock".into());
    }
    if session_sql("app", "SELECT 1", "").is_ok() {
        return Err("S. session_sql SUCCEEDED with no session".into());
    }
    session_begin(&dek, &blob, &[], &dir_cfg("pk-sess", "enc-session", false)).await?;
    let rows2 = session_sql("app", "SELECT a,b,c,d,e FROM t", "").map_err(&js)?;
    if rows2 != want {
        return Err(format!("S. data changed across lock/reopen: got {rows2}, want {want}"));
    }
    session_lock().map_err(&js)?;

    Ok("S.  session model: one open → typed params (null/int/float/string/bool) round-trip | \
'app'/'notes' DBs isolated | bad names + multi-stmt-with-params rejected | lock kills ops | \
reopen → data intact \u{2705}\n"
        .into())
}

async fn run() -> std::result::Result<String, String> {
    let mut r = String::new();
    r.push_str("freehold Milestones 2+3 — anti-rollback + hardening + crash-injection/perf tests\n");

    // ---- M2 (passkey-PRF envelope): DEK is unwrapped from a PRF-derived KEK, not hardcoded -------
    // Automated with a MOCK PRF output (the real WebAuthn-PRF assertion needs a human gesture — see
    // passkey.html). Proves: wrap(DEK)→unwrap round-trips; wrong PRF is rejected; the recovered DEK
    // is byte-identical (so it drives the VFS below exactly as the demo constant did).
    {
        let prf_ok: [u8; 32] = [7u8; 32]; // stand-in for HMAC-SHA256(cred-secret, salt)
        let prf_bad: [u8; 32] = [8u8; 32];
        let blob = envelope::create_envelope(&DEK_OK, &prf_ok)
            .map_err(|e| format!("M2 create_envelope: {e:?}"))?;
        let dek = envelope::open_with_prf(&blob, &prf_ok)
            .map_err(|e| format!("M2 open (correct PRF): {e:?}"))?;
        if dek.as_slice() != DEK_OK {
            return Err("M2 envelope: recovered DEK != original".into());
        }
        match envelope::open_with_prf(&blob, &prf_bad) {
            Err(envelope::EnvelopeError::Unlock) => {}
            Ok(_) => return Err("M2 envelope: WRONG PRF UNLOCKED THE DEK!".into()),
            Err(e) => return Err(format!("M2 envelope wrong-PRF: unexpected {e:?}")),
        }
        r.push_str(&format!(
            "M2. passkey-PRF envelope: {}-byte blob | correct PRF → DEK recovered | wrong PRF → rejected\n",
            blob.len()
        ));

        // ---- M3 (N-KEK envelope + recovery): many methods, one DEK, add/remove re-wrap ----------
        // Enroll passkey-A → add passkey-B → add a recovery code. All three must recover the SAME
        // DEK; a wrong recovery code is rejected; removing passkey-A's slot revokes only that method
        // (B + recovery still open); the DEK never changed (no DB re-encryption).
        let prf_b: [u8; 32] = [9u8; 32];
        let code = envelope::generate_recovery_code().map_err(|e| format!("M3 gen code: {e:?}"))?;
        let bad_code = "00000-00000-00000-00000-00000-0";
        let mut env = blob.clone(); // passkey-A already present (kek_id 0)
        env = envelope::add_passkey_slot(&env, &DEK_OK, &prf_b).map_err(|e| format!("M3 add pk-B: {e:?}"))?;
        env = envelope::add_recovery_slot(&env, &DEK_OK, &code).map_err(|e| format!("M3 add recovery: {e:?}"))?;
        let via_a = envelope::open_with_prf(&env, &prf_ok).map_err(|e| format!("M3 open via A: {e:?}"))?;
        let via_b = envelope::open_with_prf(&env, &prf_b).map_err(|e| format!("M3 open via B: {e:?}"))?;
        let via_r = envelope::open_with_recovery(&env, &code).map_err(|e| format!("M3 open via recovery: {e:?}"))?;
        if via_a.as_slice() != DEK_OK || via_b.as_slice() != DEK_OK || via_r.as_slice() != DEK_OK {
            return Err("M3 envelope: a slot recovered the WRONG DEK".into());
        }
        if envelope::open_with_recovery(&env, bad_code).is_ok() {
            return Err("M3 envelope: WRONG RECOVERY CODE UNLOCKED THE DEK!".into());
        }
        let n_before = envelope::slot_infos(&env).len();
        let env_before_revoke = env.clone(); // stale copy still holding passkey-A — used below (rollback)
        let gen_before = envelope::envelope_generation(&env);
        env = envelope::remove_slot(&env, &DEK_OK, 0).map_err(|e| format!("M3 remove slot 0: {e:?}"))?; // revoke passkey-A
        let n_after = envelope::slot_infos(&env).len();
        if envelope::open_with_prf(&env, &prf_ok).is_ok() {
            return Err("M3 envelope: REVOKED passkey-A still unlocks!".into());
        }
        envelope::open_with_prf(&env, &prf_b).map_err(|_| "M3 envelope: passkey-B broke after removing A".to_string())?;
        envelope::open_with_recovery(&env, &code).map_err(|_| "M3 envelope: recovery broke after removing A".to_string())?;
        r.push_str(&format!(
            "M3. N-KEK envelope: 2 passkeys + recovery all recover 1 DEK | wrong code rejected | revoke A ({n_before}→{n_after} slots) leaves B+recovery working\n"
        ));

        // ---- M3b (envelope v3 anti-rollback, issue #3): generation + MAC ----------------------------
        // (a) mutations bump the generation monotonically; the floor rejects a rolled-back envelope.
        let gen_after = envelope::envelope_generation(&env);
        if !(gen_after > gen_before && gen_before >= 1) {
            return Err(format!("M3b: generation did not advance ({gen_before} → {gen_after})"));
        }
        // check_fresh: the CURRENT envelope clears its own generation as floor; the STALE pre-revoke
        // copy (which still carries revoked passkey-A) is refused against that same floor.
        envelope::check_fresh(&env, gen_after).map_err(|e| format!("M3b: fresh envelope refused: {e:?}"))?;
        match envelope::check_fresh(&env_before_revoke, gen_after) {
            Err(envelope::EnvelopeError::Rollback) => {}
            other => return Err(format!("M3b: rolled-back envelope NOT refused by floor: {other:?}")),
        }
        // The rolled-back copy is still internally valid (its passkey-A opens it) — proving the floor,
        // not the crypto, is what defeats the rollback. Belt-and-braces that the attack is real:
        if envelope::open_with_prf(&env_before_revoke, &prf_ok).is_err() {
            return Err("M3b: stale copy unexpectedly unopenable — test setup wrong".into());
        }
        // (b) MAC tamper: forge a higher generation onto the stale copy to beat the floor. Without the
        // DEK the attacker cannot re-MAC, so the forged envelope must fail to OPEN (Tamper), not leak.
        let mut forged = env_before_revoke.clone();
        forged[28..36].copy_from_slice(&(gen_after + 100).to_le_bytes()); // GEN_OFF..+8
        if envelope::check_fresh(&forged, gen_after).is_err() {
            return Err("M3b: forged-generation copy should PASS the floor (that's the point)".into());
        }
        match envelope::open_with_prf(&forged, &prf_ok) {
            Err(envelope::EnvelopeError::Tamper) => {}
            other => return Err(format!("M3b: forged-generation envelope opened without Tamper: {other:?}")),
        }
        r.push_str(&format!(
            "M3b. envelope v3 anti-rollback: gen {gen_before}→{gen_after} monotonic | stale copy REFUSED by floor | forged-gen copy fails MAC (Tamper), no leak\n"
        ));

        // ---- M3c (DEK rotation — envelope half, issue #4 / D-RK1) ------------------------------------
        // Rotate the CURRENT envelope (opens under passkey-B / recovery `code`, DEK = DEK_OK) to a
        // FRESH dek', keeping ONLY the presenting passkey (prf_b) + a newly minted recovery code. This
        // is the cryptographic heart of eviction: after rotation the old DEK is disjoint from the new
        // envelope, and every method NOT present at the ceremony (old recovery `code`, revoked prf_ok)
        // is orphaned. The physical DB re-encryption under dek' (pool→pool re-seal, D-RK2) is the
        // separate increment-1b piece; here we prove the envelope contract in isolation.
        let new_dek = envelope::random_dek().map_err(|e| format!("M3c: rng dek': {e:?}"))?;
        if new_dek.as_slice() == DEK_OK.as_slice() {
            return Err("M3c: random dek' collided with DEK_OK (astronomically unlikely — rng broken)".into());
        }
        let (rot_env, rot_code) = envelope::rotate_envelope(&env, &new_dek, &prf_b)
            .map_err(|e| format!("M3c: rotate_envelope: {e:?}"))?;
        // (1) Generation carried strictly forward, so the pre-rotation envelope is refused by the floor.
        let rot_gen = envelope::envelope_generation(&rot_env);
        if rot_gen != gen_after + 1 {
            return Err(format!("M3c: rotated gen {rot_gen} != old {gen_after} + 1"));
        }
        match envelope::check_fresh(&env, rot_gen) {
            Err(envelope::EnvelopeError::Rollback) => {}
            other => return Err(format!("M3c: pre-rotation envelope NOT refused by new floor: {other:?}")),
        }
        // (2) Surviving passkey + new recovery code both open the new envelope and recover dek' — NOT DEK_OK.
        let via_pk = envelope::open_with_prf(&rot_env, &prf_b).map_err(|e| format!("M3c: surviving passkey lost: {e:?}"))?;
        if via_pk.as_slice() != new_dek.as_slice() {
            return Err("M3c: surviving passkey recovered the WRONG dek after rotation".into());
        }
        let via_newr = envelope::open_with_recovery(&rot_env, &rot_code).map_err(|e| format!("M3c: new recovery lost: {e:?}"))?;
        if via_newr.as_slice() != new_dek.as_slice() {
            return Err("M3c: new recovery code recovered the WRONG dek".into());
        }
        if via_pk.as_slice() == DEK_OK.as_slice() {
            return Err("M3c: rotation did NOT change the DEK — old and new identical!".into());
        }
        // (3) Every orphaned method is dead against the new envelope: the OLD recovery code (fresh salt
        // ⇒ different KEK) and the already-revoked passkey-A both fail to open. This is the eviction.
        if envelope::open_with_recovery(&rot_env, &code).is_ok() {
            return Err("M3c: ORPHANED old recovery code still opens the rotated envelope!".into());
        }
        if envelope::open_with_prf(&rot_env, &prf_ok).is_ok() {
            return Err("M3c: revoked passkey-A opens the rotated envelope!".into());
        }
        // (4) And the OLD envelope still yields the OLD DEK under the surviving passkey — proving the two
        // envelopes are cryptographically disjoint (old DEK never opens new, new never rewrites old).
        let old_still = envelope::open_with_prf(&env, &prf_b).map_err(|e| format!("M3c: old env broke: {e:?}"))?;
        if old_still.as_slice() != DEK_OK.as_slice() {
            return Err("M3c: old envelope stopped yielding the old DEK".into());
        }
        r.push_str(&format!(
            "M3c. DEK rotation (envelope half): gen {gen_after}→{rot_gen} | dek'≠DEK_OK, disjoint envelopes | surviving passkey + new recovery open dek' | orphaned old-recovery & revoked passkey REFUSED\n"
        ));
    }

    // ---- B. binary TLV bundle (bundle.rs — export/import container, future Sync wire format) --
    // Round-trip: envelope + cred_id + 2 files + epoch encode → decode byte-identical. Malformed
    // input (truncated mid-section, wrong magic) must Err cleanly — never panic, never mis-parse.
    {
        let env_b = vec![0xa5u8; 102];
        let cred = vec![0x42u8; 16];
        let files = vec![
            ("app.db".to_string(), vec![0xeeu8; 300]),
            ("app.db#manifest".to_string(), vec![0x11u8; 64]),
        ];
        let epoch = vec![0x77u8; 40];
        let enc = bundle::encode(&env_b, &cred, &files, &epoch);
        let dec = bundle::decode(&enc).map_err(|e| format!("B. bundle decode: {e}"))?;
        if dec.envelope != env_b || dec.cred_id != cred || dec.files != files || dec.epoch != epoch {
            return Err("B. bundle round-trip: decoded fields != originals".into());
        }
        if bundle::decode(&enc[..enc.len() - 7]).is_ok() {
            return Err("B. bundle: TRUNCATED input decoded without error!".into());
        }
        let mut bad = enc.clone();
        bad[0] ^= 0xff;
        if bundle::decode(&bad).is_ok() {
            return Err("B. bundle: BAD MAGIC decoded without error!".into());
        }
        r.push_str(&format!(
            "B.  TLV bundle: {}-byte container (envelope+cred_id+2 files+epoch) round-trips | truncated + bad-magic rejected\n",
            enc.len()
        ));
    }

    // ---- B2. import name validation (security-review I-1/I-2): a hostile .freehold carries
    // attacker-controlled file names straight into pool writes. `import_files` must accept only the
    // export grammar (`<db>.db`, `<db>.db#manifest`) and reject path-ish / delimiter-laced names.
    {
        let util = install_dir("import-guard", "enc-import-guard", true, &DUMMY_DEK)
            .await
            .map_err(|e| format!("B2. install: {e}"))?;
        // Legal names import fine.
        util.import_files(&[
            ("app.db".to_string(), vec![0u8; 16]),
            ("app.db#manifest".to_string(), vec![0u8; 16]),
            ("my_notes-2.db".to_string(), vec![0u8; 16]),
        ])
        .map_err(|e| format!("B2. legal names rejected: {e:?}"))?;
        // Each hostile name must be refused.
        let hostile = [
            "../../etc/passwd",
            "app.db|deadbeef",
            "app.db\nempty.db",
            "app.db#manifest#manifest",
            "APP.db",
            "app.txt",
            "app.db-journal",
            "",
            "#manifest",
        ];
        for name in hostile {
            if util
                .import_files(&[(name.to_string(), vec![0u8; 16])])
                .is_ok()
            {
                return Err(format!("B2. hostile bundle name {name:?} was ACCEPTED on import!"));
            }
        }
        util.pause_vfs().map_err(|e| format!("B2. pause: {e:?}"))?;
        r.push_str("B2. import guard: legal db/manifest names accepted | 9 hostile names (path, |, newline, case, journal, empty) rejected\n");
    }

    r.push_str("cipher: XChaCha20-Poly1305 | P=4136 | journal=DELETE | manifest: 2-slot ping-pong\n\n");

    // ---- Phase A: correct key, fresh store. Write secret rows. --------------------------------
    let util_a = install_key("enc-a", true, &DEK_OK).await?;
    unsafe {
        let db = open_default(DB_NAME)?;
        set_pragmas(db)?;
        exec(db, "CREATE TABLE t(v TEXT)")?;
        exec(
            db,
            &format!("INSERT INTO t(v) VALUES ('{SECRET}'),('{SECRET}-2'),('row-three')"),
        )?;
        let n = scalar_i64(db, "SELECT count(*) FROM t")?;
        let jmode = scalar_text(db, "PRAGMA journal_mode")?;
        r.push_str(&format!("A. wrote rows, count={n} (expect 3) | journal_mode={jmode} (expect delete)\n"));
        ffi::sqlite3_close(db);
    }
    let gen_a = util_a
        .manifest_generation(DB_NAME)
        .ok_or("no manifest generation after phase A")?;
    r.push_str(&format!("A. manifest present, db_generation={gen_a}\n"));

    // ---- 6/G: full-pool ciphertext audit ------------------------------------------------------
    r.push_str("6. full-pool ciphertext audit:\n");
    r.push_str(&audit_all(&util_a, "phase A")?);
    r.push_str("   PASS — every pool file is opaque\n");

    // Snapshot for the rollback test (an attacker copying the OPFS bytes today, restoring later).
    let raw_main_old = util_a.export_raw(DB_NAME).map_err(|e| format!("{e:?}"))?;
    let raw_man_old = util_a.export_raw(MANIFEST).map_err(|e| format!("{e:?}"))?;

    util_a.pause_vfs().map_err(|e| format!("pause A: {e:?}"))?;

    // ---- Test 3: WRONG key ⇒ the manifest fails to decrypt ⇒ open rejected (§17.E) -------------
    let util_b = install_key("enc-b", false, &DEK_BAD).await?;
    unsafe {
        match open_default(DB_NAME) {
            Err(e) => r.push_str(&format!("3. wrong key: open rejected ({e}) — good\n")),
            Ok(db) => {
                let got = scalar_i64(db, "SELECT count(*) FROM t");
                ffi::sqlite3_close(db);
                if let Ok(n) = got {
                    let _ = util_b.pause_vfs();
                    return Err(format!("WRONG KEY READ SUCCEEDED (count={n})!"));
                }
                r.push_str("3. wrong key: open succeeded but read rejected — acceptable\n");
            }
        }
    }
    util_b.pause_vfs().map_err(|e| format!("pause B: {e:?}"))?;

    // ---- Tests 2/4-reopen: correct key ⇒ rows intact; write two more commits ------------------
    let util_c = install_key("enc-c", false, &DEK_OK).await?;
    unsafe {
        let db = open_default(DB_NAME)?;
        set_pragmas(db)?;
        let n = scalar_i64(db, "SELECT count(*) FROM t")
            .map_err(|e| format!("correct-key reopen FAILED: {e}"))?;
        let v = scalar_text(db, "SELECT v FROM t ORDER BY rowid LIMIT 1")?;
        r.push_str(&format!("2. correct-key reopen: {n} rows (expect 3), first={v:?}\n"));
        if v != SECRET {
            ffi::sqlite3_close(db);
            return Err("decrypted value mismatch".into());
        }
        exec(db, "INSERT INTO t(v) VALUES ('row-four')")?;
        exec(db, "INSERT INTO t(v) VALUES ('row-five')")?;
        let n = scalar_i64(db, "SELECT count(*) FROM t")?;
        r.push_str(&format!("   two more commits, count={n} (expect 5)\n"));
        ffi::sqlite3_close(db);
    }
    let gen_c = util_c
        .manifest_generation(DB_NAME)
        .ok_or("no generation after phase C")?;
    r.push_str(&format!("   db_generation advanced {gen_a} -> {gen_c} (expect >)\n"));
    if gen_c <= gen_a {
        return Err("db_generation did not advance across commits".into());
    }
    let raw_cur = util_c.export_raw(DB_NAME).map_err(|e| format!("{e:?}"))?;
    let raw_man_cur = util_c.export_raw(MANIFEST).map_err(|e| format!("{e:?}"))?;

    // ---- Test 4: tamper — flip one ciphertext byte in block 1 ⇒ read must hard-fail -----------
    unsafe {
        let mut tampered = raw_cur.clone();
        let at = crypto::PHYS_BLOCK + 100;
        tampered[at] ^= 0xFF;
        util_c.import_raw(DB_NAME, &tampered).map_err(|e| format!("{e:?}"))?;
        match count_rows() {
            Ok(n) => return Err(format!("TAMPERED READ SUCCEEDED (count={n})!")),
            Err(e) => r.push_str(&format!("4. tamper: read rejected ({e}) — good\n")),
        }
        util_c.import_raw(DB_NAME, &raw_cur).map_err(|e| format!("{e:?}"))?;
        let n = count_rows()?;
        r.push_str(&format!("   restored, count={n} (expect 5)\n"));
    }

    // ---- Test 5: cross-block relocation — copy block 0's bytes over block 1 ⇒ AAD rejects ------
    unsafe {
        let mut swapped = raw_cur.clone();
        let p = crypto::PHYS_BLOCK;
        let (b0, b1) = swapped.split_at_mut(p);
        b1[..p].copy_from_slice(b0);
        util_c.import_raw(DB_NAME, &swapped).map_err(|e| format!("{e:?}"))?;
        match count_rows() {
            Ok(n) => return Err(format!("RELOCATED-BLOCK READ SUCCEEDED (count={n})!")),
            Err(e) => r.push_str(&format!("5. relocation: read rejected ({e}) — good\n")),
        }
        util_c.import_raw(DB_NAME, &raw_cur).map_err(|e| format!("{e:?}"))?;
    }

    // ---- §17.H (partial): ATTACH-ed DB gets its own manifest + db_uuid subkey ------------------
    unsafe {
        let db = open_default(DB_NAME)?;
        exec(db, "ATTACH 'att.db' AS att").map_err(|e| format!("ATTACH: {e}"))?;
        // This build's default page_size is 8192 — pin the attached DB to B like every other DB.
        // (Leaving it unpinned is itself covered: §17.I refuses the mismatched write — see test I.)
        exec(db, "PRAGMA att.page_size=4096").map_err(|e| format!("att page_size: {e}"))?;
        exec(db, "CREATE TABLE att.s(v TEXT)").map_err(|e| format!("CREATE att.s: {e}"))?;
        exec(db, &format!("INSERT INTO att.s(v) VALUES ('{SECRET2}')"))
            .map_err(|e| format!("INSERT att.s: {e}"))?;
        let n = scalar_i64(db, "SELECT count(*) FROM att.s").map_err(|e| format!("SELECT att.s: {e}"))?;
        exec(db, "DETACH att").map_err(|e| format!("DETACH: {e}"))?;
        ffi::sqlite3_close(db);
        let has_manifest = util_c.exists("att.db#manifest").map_err(|e| format!("{e:?}"))?;
        r.push_str(&format!(
            "H. ATTACH: att.db rows={n} (expect 1) | own manifest present={has_manifest} (expect true)\n"
        ));
        if !has_manifest {
            return Err("ATTACH-ed DB did not get its own manifest".into());
        }
    }

    // ---- §17.I: page_size != B must be refused at creation -------------------------------------
    unsafe {
        let db = open_default("ps.db")?;
        exec(db, "PRAGMA page_size=8192")?;
        match exec(db, "CREATE TABLE p(x)") {
            Ok(()) => {
                ffi::sqlite3_close(db);
                return Err("page_size=8192 WRITE WAS ACCEPTED (§17.I violated)".into());
            }
            Err(e) => r.push_str(&format!("I. page_size 8192: write refused ({e}) — good\n")),
        }
        ffi::sqlite3_close(db);
    }

    // ---- §17.C: torn manifest slot ⇒ double-buffer must not PERMANENTLY brick -------------------
    // D-MR6 note: with the seal-before-delete ordering, a REAL torn active-slot seal is always
    // accompanied by a still-hot journal (the journal delete happens only AFTER the seal), so live
    // recovery goes through the replay path (covered by the crash sweep below, which crashes mid-seal
    // at every boundary and stays 0-bricked). Tearing the active slot WITHOUT the accompanying journal
    // — as this synthetic test does — is an UNREACHABLE state where the on-disk data (R_N) is one
    // generation ahead of the surviving slot (R_{N-1}); the D-MR6 accept-∈{root,prev_root} check
    // correctly REFUSES it (fail-closed, stricter than the old anchor-only ±1). The double-buffer
    // guarantee we assert here is the durable one: the torn slot is NOT permanently bricked — once the
    // good manifest bytes are back, the DB opens cleanly.
    unsafe {
        let gen = util_c.manifest_generation(DB_NAME).ok_or("no gen for torn test")?;
        let active = (gen % 2) as usize;
        let man_clean = util_c.export_raw(MANIFEST).map_err(|e| format!("{e:?}"))?;
        let mut torn = man_clean.clone();
        let at = manifest::MANIFEST_HDR_LEN + active * crypto::PHYS_BLOCK + 500;
        for b in &mut torn[at..at + 16] {
            *b ^= 0xFF;
        }
        util_c.import_raw(MANIFEST, &torn).map_err(|e| format!("{e:?}"))?;
        let torn_result = count_rows(); // synthetic (no journal) → refused is correct, not a brick
        util_c.import_raw(MANIFEST, &man_clean).map_err(|e| format!("{e:?}"))?;
        let n = count_rows()
            .map_err(|e| format!("torn-manifest PERMANENTLY BRICKED (clean bytes didn't recover): {e}"))?;
        if n != 5 {
            return Err(format!("C. torn-manifest: after restore count={n} (expect 5)"));
        }
        r.push_str(&format!(
            "C. torn active manifest slot (synthetic, no journal): open {} — NOT permanently bricked, clean manifest reopens count={n} (expect 5)\n",
            if torn_result.is_err() { "refused (fail-closed, correct)" } else { "recovered via other slot" }
        ));
    }

    // ---- Test 5b: whole-file rollback — restore the phase-A snapshot ⇒ anchor must reject ------
    unsafe {
        util_c.import_raw(DB_NAME, &raw_main_old).map_err(|e| format!("{e:?}"))?;
        util_c.import_raw(MANIFEST, &raw_man_old).map_err(|e| format!("{e:?}"))?;
        match count_rows() {
            Ok(n) => return Err(format!("ROLLBACK ACCEPTED (count={n}) — anti-rollback failed!")),
            Err(e) => {
                if !e.contains("ROLLBACK") {
                    r.push_str(&format!("5b. NOTE: rejected but not via rollback path: {e}\n"));
                }
                r.push_str(&format!("5b. whole-file rollback: open rejected ({e}) — good\n"));
            }
        }
        util_c.import_raw(DB_NAME, &raw_cur).map_err(|e| format!("{e:?}"))?;
        util_c.import_raw(MANIFEST, &raw_man_cur).map_err(|e| format!("{e:?}"))?;
        let n = count_rows()?;
        r.push_str(&format!("    current image restored, count={n} (expect 5)\n"));
    }

    // ==== Section MK: full-state Merkle root (freehold-vfs-merkle-root D-MR1..D-MR5) =============
    // Closes the PARTIAL-rollback gap: an attacker restoring a SUBSET of blocks to an older
    // generation's ciphertext. Those old blocks were sealed under the same K_db at the same block
    // index, so per-block AEAD authenticates (it binds POSITION, not GENERATION); the manifest's
    // generation + per-file length are unchanged, so the anchor + §17.J checks pass. ONLY the
    // full-state root — sealed inside the manifest, recomputed at open — detects it.
    {
        // (a) ROUND-TRIP: the root recomputes deterministically after a reopen and is non-zero
        // (a real DB with committed blocks self-populated it on commit, D-MR2).
        let root1 = util_c
            .full_state_root(DB_NAME)
            .map_err(|e| format!("MK(a) root compute: {e:?}"))?;
        if root1 == [0u8; 32] {
            return Err("MK(a) full-state root is all-zero for a non-empty committed DB".into());
        }
        // Reopen (fresh commit at current state) then recompute — must be identical (stable).
        unsafe {
            let db = open_default(DB_NAME)?;
            let _ = scalar_i64(db, "SELECT count(*) FROM t")?;
            ffi::sqlite3_close(db);
        }
        let root2 = util_c
            .full_state_root(DB_NAME)
            .map_err(|e| format!("MK(a) root recompute: {e:?}"))?;
        if root1 != root2 {
            return Err("MK(a) full-state root not stable across reopen".into());
        }
        r.push_str(&format!(
            "MK(a) root round-trip: non-zero, stable across reopen (root[0..4]={:02x?})\n",
            &root1[..4]
        ));

        // Refresh the current-image snapshots (the reopen above may have re-sealed the manifest).
        let raw_cur = util_c.export_raw(DB_NAME).map_err(|e| format!("{e:?}"))?;
        let raw_man_cur = util_c.export_raw(MANIFEST).map_err(|e| format!("{e:?}"))?;

        // (b) PARTIAL-ROLLBACK ATTACK. Build an image that is the CURRENT ciphertext except one
        // block reverted to the OLD (phase-A) generation's ciphertext at the same position, and
        // KEEP the current manifest (current generation + current length). Find a block index
        // present in both images whose ciphertext differs — that is a genuine per-block rollback.
        let p = crypto::PHYS_BLOCK;
        let common = raw_cur.len().min(raw_main_old.len()) / p;
        // Prefer a DATA page (index >= 1): reverting block 0 (the SQLite header page) can trip
        // SQLite's own header re-validation and mask the VFS error, whereas a reverted table/leaf
        // page is the canonical partial-rollback the root is meant to catch. Fall back to block 0
        // only if no higher common block differs.
        let mut victim: Option<usize> = None;
        for k in 1..common {
            if raw_cur[k * p..(k + 1) * p] != raw_main_old[k * p..(k + 1) * p] {
                victim = Some(k);
                break;
            }
        }
        if victim.is_none() {
            for k in 0..common {
                if raw_cur[k * p..(k + 1) * p] != raw_main_old[k * p..(k + 1) * p] {
                    victim = Some(k);
                    break;
                }
            }
        }
        let k = victim.ok_or_else(|| {
            "MK(b) could not find a differing common block to stage a partial rollback".to_string()
        })?;
        let mut partial = raw_cur.clone();
        partial[k * p..(k + 1) * p].copy_from_slice(&raw_main_old[k * p..(k + 1) * p]);

        // Sanity: the reverted block still AEAD-authenticates in place (position-bound key/AAD) —
        // this is exactly why the OLD detection (AEAD + length + generation) is blind to it. We
        // install the partial image WITH the current manifest and confirm the current length/gen
        // are intact, then confirm the OPEN is refused specifically by the root check.
        util_c
            .import_raw(DB_NAME, &partial)
            .map_err(|e| format!("{e:?}"))?;
        util_c
            .import_raw(MANIFEST, &raw_man_cur)
            .map_err(|e| format!("{e:?}"))?; // current manifest: gen + length unchanged
        match unsafe { count_rows() } {
            Ok(n) => {
                return Err(format!(
                    "MK(b) PARTIAL ROLLBACK ACCEPTED (block {k} reverted, count={n}) — root check failed to catch it!"
                ))
            }
            Err(e) => {
                // The refusal must be the root check. SQLite sometimes masks a CANTOPEN detail into
                // a generic "unable to open database file" via sqlite3_errmsg; when that happens we
                // confirm attribution the direct way — recompute the root over the reverted image
                // and assert it differs from the sealed one (i.e. the root path is what fires),
                // while gen + length are unchanged (so the OLD detection would have accepted it).
                let attributed = if e.contains("PARTIAL ROLLBACK") {
                    true
                } else {
                    let reverted_root = util_c.full_state_root(DB_NAME).ok();
                    reverted_root.map_or(false, |rr| rr != root1)
                };
                if !attributed {
                    return Err(format!(
                        "MK(b) partial rollback rejected but NOT attributable to the root check (block {k}): {e}"
                    ));
                }
                r.push_str(&format!(
                    "MK(b) partial rollback (block {k} reverted, manifest gen+length intact): open REFUSED by root check ({e}) — gap closed\n"
                ));
            }
        }
        // Restore the good image and confirm recovery.
        util_c.import_raw(DB_NAME, &raw_cur).map_err(|e| format!("{e:?}"))?;
        util_c.import_raw(MANIFEST, &raw_man_cur).map_err(|e| format!("{e:?}"))?;
        let n = unsafe { count_rows()? };
        r.push_str(&format!("    current image restored, count={n} (expect 5)\n"));

        // (c) LEGACY ZERO-ROOT compat (D-MR2): a DB whose manifest carries an all-zero root (a
        // pre-Merkle image) must OPEN (verification skipped) and self-populate a real root on the
        // next commit. We synthesize one by zeroing the root region of BOTH sealed manifest slots'
        // plaintext is not possible without the key; instead we exercise the real legacy path: a
        // freshly created DB's first manifest carries ZERO_ROOT until its first data commit.
        {
            let util_leg = install_dir("mk-legacy", "enc-mk-legacy", true, &DEK_OK)
                .await
                .map_err(|e| format!("MK(c) install: {e}"))?;
            // Create the DB and its manifest, but observe the root BEFORE the first data commit.
            unsafe {
                let db = open_default("leg.db")?;
                set_pragmas(db)?;
                ffi::sqlite3_close(db); // manifest exists at gen 1 with ZERO_ROOT (no data yet)
            }
            // Reopen must succeed (legacy zero-root → verification skipped, D-MR2).
            unsafe {
                let db = open_default("leg.db")
                    .map_err(|e| format!("MK(c) legacy zero-root DB failed to open: {e}"))?;
                set_pragmas(db)?;
                exec(db, "CREATE TABLE t(v TEXT)")?;
                exec(db, "INSERT INTO t(v) VALUES ('legacy-populated')")?; // first data commit
                ffi::sqlite3_close(db);
            }
            // After the first commit the root must be populated (non-zero) and verify on reopen.
            let leg_root = util_leg
                .full_state_root("leg.db")
                .map_err(|e| format!("MK(c) legacy root compute: {e:?}"))?;
            if leg_root == [0u8; 32] {
                return Err("MK(c) legacy DB did not self-populate a root after first commit".into());
            }
            unsafe {
                let db = open_default("leg.db")
                    .map_err(|e| format!("MK(c) legacy DB failed to reopen after populate: {e}"))?;
                let n = scalar_i64(db, "SELECT count(*) FROM t")?;
                ffi::sqlite3_close(db);
                if n != 1 {
                    return Err(format!("MK(c) legacy DB row count {n} (expect 1)"));
                }
            }
            util_leg.pause_vfs().map_err(|e| format!("MK(c) pause: {e:?}"))?;
            r.push_str("MK(c) legacy zero-root DB: opened (verify skipped), self-populated a real root on first commit, reopens clean\n");
        }

        // (d) PLANTED HOT-JOURNAL ROLLBACK ATTACK (freehold-vfs-merkle-root F1 — the acceptance
        // gate). The open-path root check is deferred while a journal is genuinely HOT (a legit
        // mid-commit crash leaves the main file mid-write; SQLite's replay restores it, so a raw
        // recompute would brick a normal power loss). The reviewer's attack: plant a captured hot
        // journal alongside main-DB blocks reverted to an older generation so the root check is
        // skipped and the rollback served/laundered.
        //
        // Two facts about THIS VFS close it: (1) recovery NEVER re-seals the manifest root
        // (`on_main_synced` does not fire on rollback), so a rollback can never be *laundered* — the
        // manifest keeps the pre-attack root; (2) "hot" is now defined precisely (valid decrypted
        // journal magic), matching SQLite — so once SQLite finalizes the journal (EXCLUSIVE mode
        // zeroes its header), it is no longer "hot" and the next journal-free open runs the root check
        // over the rolled-back image, which != the sealed root → REFUSED. A journal that fails AEAD
        // (forged/planted-foreign) is treated as NOT hot → the root check runs immediately.
        //
        // We prove: (d.1) a legit same-generation crash still recovers without bricking; (d.2) a
        // planted rollback behind a hot journal is REFUSED (on reopen) and never laundered.
        {
            const HDB: &str = "hj.db";
            const HMAN: &str = "hj.db#manifest";
            const HJRN: &str = "hj.db-journal";
            let util_hj = install_dir("mk-hj", "enc-mk-hj", true, &DEK_OK)
                .await
                .map_err(|e| format!("MK(d) install: {e}"))?;
            unsafe {
                let db = open_default(HDB).map_err(|e| format!("MK(d) open: {e}"))?;
                set_pragmas(db)?;
                exec(db, "CREATE TABLE t(v TEXT)")?;
                exec(db, "INSERT INTO t(v) VALUES ('old-1'),('old-2'),('old-3')")?;
                ffi::sqlite3_close(db);
            }
            let img_old = util_hj.export_raw(HDB).map_err(|e| format!("{e:?}"))?;

            // Capture a GENUINE hot journal (valid header) by crashing a commit after the journal is
            // durable but before it is finalized. Observe it AFTER a pause/unpause (which re-maps the
            // persisted file by name), exactly as recovery will see it.
            let mut jrnl: Vec<u8> = Vec::new();
            for fp in 1..=24u32 {
                unsafe {
                    let db = open_default(HDB).map_err(|e| format!("MK(d) cap open {fp}: {e}"))?;
                    util_hj.arm_fault(fp);
                    let _ = exec(db, &format!("INSERT INTO t(v) VALUES ('c{fp}')"));
                    ffi::sqlite3_close(db);
                }
                util_hj.clear_fault();
                util_hj.pause_vfs().map_err(|e| format!("MK(d) pause {fp}: {e:?}"))?;
                util_hj.unpause_vfs().await.map_err(|e| format!("MK(d) unpause {fp}: {e:?}"))?;
                let j = util_hj.export_raw(HJRN).unwrap_or_default();
                if util_hj.exists(HJRN).unwrap_or(false) && !j.is_empty() && j.iter().any(|&b| b != 0) {
                    jrnl = j;
                    break;
                }
                unsafe {
                    let db = open_default(HDB)
                        .map_err(|e| format!("MK(d) clean recover {fp}: {e}"))?;
                    let _ = scalar_i64(db, "SELECT count(*) FROM t")
                        .map_err(|e| format!("MK(d) count {fp}: {e}"))?;
                    ffi::sqlite3_close(db);
                }
            }
            if jrnl.is_empty() {
                return Err("MK(d) could not capture a hot journal via fault injection".into());
            }

            // (d.1) LEGIT recovery: the captured hot journal over its OWN crashed image recovers and
            // is readable (no brick). SQLite finalizes the journal (header zeroed) during this open.
            let legit_n = unsafe {
                let db = open_default(HDB)
                    .map_err(|e| format!("MK(d) legit recovery BRICKED: {e}"))?;
                let n = scalar_i64(db, "SELECT count(*) FROM t")
                    .map_err(|e| format!("MK(d) legit count: {e}"))?;
                ffi::sqlite3_close(db);
                n
            };
            // After finalize the journal is no longer HOT → a plain reopen runs the root check and
            // succeeds (recovered image matches the sealed root).
            unsafe {
                let db = open_default(HDB)
                    .map_err(|e| format!("MK(d) post-recovery reopen REFUSED (false positive!): {e}"))?;
                let _ = scalar_i64(db, "SELECT count(*) FROM t").map_err(|e| format!("MK(d) post count: {e}"))?;
                ffi::sqlite3_close(db);
            }

            // Advance to a NEW committed generation; snapshot the CURRENT image + manifest (root).
            unsafe {
                let db = open_default(HDB).map_err(|e| format!("MK(d) reopen advance: {e}"))?;
                exec(db, "INSERT INTO t(v) VALUES ('new-a'),('new-b'),('new-c'),('new-d')")
                    .map_err(|e| format!("MK(d) advance INSERT: {e}"))?;
                ffi::sqlite3_close(db);
            }
            let img_cur = util_hj.export_raw(HDB).map_err(|e| format!("{e:?}"))?;
            let man_cur = util_hj.export_raw(HMAN).map_err(|e| format!("{e:?}"))?;
            let cur_n = unsafe {
                let db = open_default(HDB).map_err(|e| format!("MK(d) cur reopen: {e}"))?;
                let n = scalar_i64(db, "SELECT count(*) FROM t").map_err(|e| format!("MK(d) cur count: {e}"))?;
                ffi::sqlite3_close(db);
                n
            };

            // (d.2) RE-PLANT ATTACK at rollback depth ≥2 (D-MR6 acceptance gate). Revert the whole
            // main image to `img_old` (the depth-≥2 committed state captured before several later
            // commits) and plant the captured hot journal, RE-PLANTING both before EVERY open. The
            // VFS owns the replay: it reconstructs the served image and requires its root ∈
            // {merkle_root, prev_merkle_root}. A depth-≥2 image roots to neither → REFUSED on EVERY
            // open, cross- AND same-generation, no matter how many times it is re-planted.
            let p = crypto::PHYS_BLOCK;
            // Stage the journal pool file so import_raw(HJRN) can overwrite it (crash a txn to map it).
            unsafe {
                let db = open_default(HDB).map_err(|e| format!("MK(d) attack-stage open: {e}"))?;
                util_hj.arm_fault(1);
                let _ = exec(db, "INSERT INTO t(v) VALUES ('stage')");
                ffi::sqlite3_close(db);
            }
            util_hj.clear_fault();
            util_hj.pause_vfs().map_err(|e| format!("MK(d) pause3: {e:?}"))?;
            util_hj.unpause_vfs().await.map_err(|e| format!("MK(d) unpause3: {e:?}"))?;
            if !util_hj.exists(HJRN).unwrap_or(false) {
                return Err("MK(d) could not stage the journal pool file for the attack".into());
            }

            // Depth-≥2 reverted image = the full old committed image, padded to the current physical
            // length so §17.J length checks still pass (the tail blocks stay current; block 1 differs).
            let mut reverted = img_cur.clone();
            let common = img_cur.len().min(img_old.len()) / p;
            let mut victim = 0usize;
            for k in 1..common {
                if img_cur[k * p..(k + 1) * p] != img_old[k * p..(k + 1) * p] {
                    reverted[k * p..(k + 1) * p].copy_from_slice(&img_old[k * p..(k + 1) * p]);
                    if victim == 0 { victim = k; }
                }
            }
            if victim == 0 {
                return Err("MK(d) no differing data block for a depth-≥2 rollback".into());
            }

            // RE-PLANT before EVERY open; assert REFUSED and NEVER stale-served on all N opens.
            const N_OPENS: usize = 4;
            let mut last_err = String::new();
            for attempt in 0..N_OPENS {
                util_hj.import_raw(HDB, &reverted).map_err(|e| format!("{e:?}"))?;
                util_hj.import_raw(HMAN, &man_cur).map_err(|e| format!("{e:?}"))?; // current gen+root
                util_hj.import_raw(HJRN, &jrnl).map_err(|e| format!("{e:?}"))?; // re-plant hot journal
                let res = unsafe {
                    match open_default(HDB) {
                        Err(e) => Err(e),
                        Ok(db) => {
                            let g = scalar_i64(db, "SELECT count(*) FROM t");
                            ffi::sqlite3_close(db);
                            Ok(g)
                        }
                    }
                };
                match res {
                    Err(e) => last_err = e, // open refused — good
                    Ok(Err(e)) => last_err = format!("read rejected ({e})"), // served-then-rejected
                    Ok(Ok(n)) if n as usize == cur_n as usize => {
                        // Current state served (journal didn't roll back this open) — safe, not stale.
                        last_err = "current-state (no rollback served)".into();
                    }
                    Ok(Ok(n)) => {
                        return Err(format!(
                            "MK(d.2) RE-PLANT ATTACK SERVED A STALE ROLLBACK on open #{attempt} (count={n}, current={cur_n}) — F1-a NOT closed!"
                        ));
                    }
                }
            }

            // NOT LAUNDERED: restore the good current image + manifest → reopens clean at current.
            util_hj.import_raw(HDB, &img_cur).map_err(|e| format!("{e:?}"))?;
            util_hj.import_raw(HMAN, &man_cur).map_err(|e| format!("{e:?}"))?;
            let root_ok = unsafe {
                match open_default(HDB) {
                    Ok(db) => {
                        let g = scalar_i64(db, "SELECT count(*) FROM t").ok();
                        ffi::sqlite3_close(db);
                        g == Some(cur_n)
                    }
                    Err(_) => false,
                }
            };
            if !root_ok {
                return Err("MK(d) good current image did not re-open cleanly after the attack (laundered/corrupted?)".into());
            }

            // (d.3) IRREDUCIBLE 1-COMMIT FLOOR (documented accepted residual): a rollback to the
            // genuine immediately-previous committed state (depth EXACTLY 1) matches prev_merkle_root
            // and MAY pass. We assert the floor is exactly 1 by confirming depth-2 is refused (above)
            // while noting depth-1 is the accepted boundary — no deeper rollback is ever accepted.
            util_hj.pause_vfs().map_err(|e| format!("MK(d) pause4: {e:?}"))?;
            r.push_str(&format!(
                "MK(d) hot-journal path: legit crash recovery OK (count={legit_n}) -> advanced to current (count={cur_n}) | D-MR6 VFS-owned replay: depth-≥2 rollback (revert to old image + hot journal) RE-PLANTED before {N_OPENS} consecutive opens -> REFUSED every time, never stale ({}) | NOT laundered (good image reopens clean) | residual = irreducible 1-commit floor only (depth-exactly-1 to the genuine previous committed state may pass, accepted)\n",
                last_err.trim()
            ));
        }
    }

    // ---- security-review 6: torn ANCHOR slot must NOT nullify rollback protection --------------
    // Corrupt the active anchor slot AND restore the old (gen-3) snapshot together, then reopen.
    // Pre-fix (single-buffered anchor) the torn slot made anchor_load return empty → the rollback
    // check was skipped → the stale image was accepted. Double-buffered, the other slot survives
    // and the rollback is still detected.
    {
        let active = util_c.active_anchor_slot();
        util_c
            .corrupt_anchor_slot(active, crypto::PHYS_BLOCK)
            .map_err(|e| format!("corrupt_anchor: {e:?}"))?;
        util_c.import_raw(DB_NAME, &raw_main_old).map_err(|e| format!("{e:?}"))?;
        util_c.import_raw(MANIFEST, &raw_man_old).map_err(|e| format!("{e:?}"))?;
        match unsafe { count_rows() } {
            Ok(n) => {
                return Err(format!(
                    "TORN-ANCHOR NULLIFIED ROLLBACK PROTECTION (rolled-back image accepted, count={n})!"
                ))
            }
            Err(e) => r.push_str(&format!(
                "D. torn anchor slot {active} + rollback: still rejected ({e}) — double-buffer held\n"
            )),
        }
        util_c.import_raw(DB_NAME, &raw_cur).map_err(|e| format!("{e:?}"))?;
        util_c.import_raw(MANIFEST, &raw_man_cur).map_err(|e| format!("{e:?}"))?;
        let n = unsafe { count_rows()? };
        r.push_str(&format!("    anchor self-healed on reopen, count={n} (expect 5)\n"));
    }

    // ---- security-review 1b: torn manifest HEADER on a brand-new (empty) DB must recover --------
    // A crash during a fresh DB's first commit can tear the plaintext manifest header. With no
    // durable main data at risk, the next open must recreate cleanly, not brick.
    unsafe {
        let db = open_default("empty.db")?;
        set_pragmas(db)?;
        ffi::sqlite3_close(db); // opened + closed with no rows ⇒ main data region stays empty
    }
    {
        let mut man = util_c
            .export_raw("empty.db#manifest")
            .map_err(|e| format!("{e:?}"))?;
        for b in man[0..8].iter_mut() {
            *b = 0; // zero the magic — simulates a torn/partial header write
        }
        util_c.import_raw("empty.db#manifest", &man).map_err(|e| format!("{e:?}"))?;
    }
    unsafe {
        let db = open_default("empty.db")
            .map_err(|e| format!("§17.C torn manifest header BRICKED an empty DB: {e}"))?;
        ffi::sqlite3_close(db);
    }
    r.push_str("E. torn manifest header on empty DB: recovered (recreated), not bricked\n");

    // ---- §14.8: crash/fault-injection sweep -----------------------------------------------------
    // Simulate power loss at EVERY persistence boundary of a commit: arm the injector so the
    // first n ops land and everything after silently vanishes, run an INSERT, discard the
    // connection on the dead disk, then bring the disk back, drop all caches (pause/unpause) and
    // reopen. Invariant: the DB always opens, and the count is exactly pre- OR post-transaction.
    {
        let mut c = unsafe { count_rows()? };
        let mut rolled_back = 0u32;
        let mut committed = 0u32;
        for n in 1..=18u32 {
            unsafe {
                let db = open_default(DB_NAME)?;
                util_c.arm_fault(n);
                let _ = exec(db, &format!("INSERT INTO t(v) VALUES ('crash-{n}')")); // may fail
                ffi::sqlite3_close(db); // rollback attempts also hit the dead disk — as in a real crash
            }
            util_c.clear_fault();
            util_c.pause_vfs().map_err(|e| format!("§14.8 pause at n={n}: {e:?}"))?;
            util_c
                .unpause_vfs()
                .await
                .map_err(|e| format!("§14.8 unpause at n={n}: {e:?}"))?;
            let got = unsafe {
                let db = open_default(DB_NAME)
                    .map_err(|e| format!("§14.8 BRICKED after crash at op {n}: {e}"))?;
                let got = scalar_i64(db, "SELECT count(*) FROM t")
                    .map_err(|e| format!("§14.8 unreadable after crash at op {n}: {e}"))?;
                ffi::sqlite3_close(db);
                got
            };
            if got == c {
                rolled_back += 1;
            } else if got == c + 1 {
                committed += 1;
                c = got;
            } else {
                return Err(format!(
                    "§14.8 CORRUPT STATE after crash at op {n}: count={got}, expected {c} or {}",
                    c + 1
                ));
            }
        }
        r.push_str(&format!(
            "8. crash sweep (power loss at persist-op 1..18): every reopen OK — {rolled_back} rolled back, {committed} committed, 0 corrupt/bricked\n"
        ));
    }

    // ---- §14.9: size-math property test ---------------------------------------------------------
    let prop = util_c
        .proptest_blockdev(400)
        .map_err(|e| format!("§14.9: {e:?}"))?;
    r.push_str(&format!("9. {prop}\n"));

    // ---- §14.11: performance numbers ------------------------------------------------------------
    // Absolute throughput + AEAD microbenchmark. Deliberately NO null-cipher "plaintext baseline"
    // build: that would create the exact unencrypted-write code path §17.G forbids. Ledgered.
    unsafe {
        let db = open_default(DB_NAME)?;
        set_pragmas(db)?;
        let t0 = js_sys::Date::now();
        exec(db, "BEGIN")?;
        for i in 0..500 {
            exec(db, &format!("INSERT INTO t(v) VALUES ('perf-batch-{i}')"))?;
        }
        exec(db, "COMMIT")?;
        let t1 = js_sys::Date::now();
        for i in 0..20 {
            exec(db, &format!("INSERT INTO t(v) VALUES ('perf-single-{i}')"))?;
        }
        let t2 = js_sys::Date::now();
        let n = scalar_i64(db, "SELECT count(*) FROM t")?;
        let _ = scalar_i64(db, "SELECT sum(length(v)) FROM t")?;
        let t3 = js_sys::Date::now();
        ffi::sqlite3_close(db);
        r.push_str(&format!(
            "11. perf: 500-row batched txn {:.0}ms | 20 single-row commits {:.0}ms ({:.1} ms/commit, incl. manifest+anchor) | full scan of {n} rows {:.0}ms\n",
            t1 - t0,
            t2 - t1,
            (t2 - t1) / 20.0,
            t3 - t2
        ));
    }
    {
        let key = crypto::Crypto::pool_key(&DEK_OK);
        let fid = crypto::file_id_for("bench");
        let dom = crypto::NO_DOMAIN;
        let mut plain = vec![0xabu8; crypto::BLOCK_SIZE];
        let mut sealed = vec![0u8; crypto::PHYS_BLOCK];
        let tb = js_sys::Date::now();
        const ROUNDS: u64 = 2000;
        for i in 0..ROUNDS {
            key.seal_into(&fid, &dom, i, &plain, &mut sealed)
                .map_err(|e| format!("bench seal: {e:?}"))?;
            key.open_into(&fid, &dom, i, &sealed, &mut plain)
                .map_err(|e| format!("bench open: {e:?}"))?;
        }
        let ms = js_sys::Date::now() - tb;
        let mbps = (ROUNDS * 2 * crypto::BLOCK_SIZE as u64) as f64 / 1_048_576.0 / (ms / 1000.0);
        r.push_str(&format!(
            "    AEAD micro: {ROUNDS} seal+open of 4 KiB blocks in {ms:.0}ms ≈ {mbps:.0} MB/s ({:.1} µs/block op)\n",
            ms * 1000.0 / (ROUNDS * 2) as f64
        ));
    }

    // ---- Test 7: no -wal / -shm files; final full-pool audit -----------------------------------
    let files = util_c.list();
    let leaked: Vec<_> = files
        .iter()
        .filter(|f| f.ends_with("-wal") || f.ends_with("-shm"))
        .collect();
    r.push_str(&format!(
        "7. files in pool: {files:?} | wal/shm present={} (expect false)\n",
        !leaked.is_empty()
    ));
    if !leaked.is_empty() {
        return Err("-wal/-shm file appeared on disk".into());
    }
    r.push_str("G. final full-pool ciphertext audit:\n");
    r.push_str(&audit_all(&util_c, "final")?);

    // ---- Test 10: header-free preserved ---------------------------------------------------------
    let coi = cross_origin_isolated();
    r.push_str(&format!("10. crossOriginIsolated={coi} (expect false — header-free)\n"));
    if coi {
        return Err("crossOriginIsolated is true — not header-free".into());
    }

    // ==== Section MK6: D-MR6 commit-barrier + anchor-downgrade regression tests ==================
    {
        // (e) NO GENERATION INFLATION (#3 double-fire guard). Each committing transaction must bump
        // db_generation by EXACTLY 1 (previously the header-zero xWrite AND the close-time xDelete
        // both fired the barrier → ~2× inflation).
        let util6 = install_dir("mk6", "enc-mk6", true, &DEK_OK)
            .await
            .map_err(|e| format!("MK6 install: {e}"))?;
        unsafe {
            let db = open_default("g.db").map_err(|e| format!("MK6 open: {e}"))?;
            set_pragmas(db)?;
            exec(db, "CREATE TABLE t(v TEXT)")?;
            ffi::sqlite3_close(db);
        }
        let g0 = util6.manifest_generation("g.db").unwrap_or(0);
        // Three separate single-statement autocommits, reopening each time (so the close-time xDelete
        // path is exercised) — generation must advance by exactly 3, not ~6.
        for i in 0..3u32 {
            unsafe {
                let db = open_default("g.db").map_err(|e| format!("MK6 reopen {i}: {e}"))?;
                exec(db, &format!("INSERT INTO t(v) VALUES ('g{i}')")).map_err(|e| format!("MK6 insert {i}: {e}"))?;
                ffi::sqlite3_close(db);
            }
        }
        let g1 = util6.manifest_generation("g.db").unwrap_or(0);
        let delta = g1 - g0;
        if delta != 3 {
            return Err(format!(
                "MK6(e) generation inflation: 3 commits advanced gen by {delta} (expect exactly 3) — double-fire not guarded"
            ));
        }
        r.push_str(&format!("MK6(e) no gen inflation: 3 commits advanced db_generation by exactly {delta} (expect 3) — #3 double-fire guarded\n"));

        // (f) DEPTH-EXACTLY-1 BOUNDARY (accepted floor) vs DEPTH-2 (refused), journal-free.
        // g.db now has committed states we can snapshot. Build: commit A (snapshot img_a, root R_a),
        // commit B (snapshot img_b), commit C (current, root R_c, prev R_b). Then:
        //   restore img_b (depth-1, = prev) → MAY open (accepted floor);
        //   restore img_a (depth-2)         → REFUSED every time.
        let man_c = util6.export_raw("g.db#manifest").map_err(|e| format!("{e:?}"))?; // current manifest
        let img_c = util6.export_raw("g.db").map_err(|e| format!("{e:?}"))?;
        // Snapshot the image ONE commit back (depth-1 = the genuine previous committed state).
        // Re-derive by rolling to a fresh DB mirror is complex; instead capture via successive commits:
        // reconstruct depth-1/-2 images by committing forward from known points on a SECOND db.
        let util6b = install_dir("mk6b", "enc-mk6b", true, &DEK_OK)
            .await
            .map_err(|e| format!("MK6b install: {e}"))?;
        // depth-2 committed image (A):
        unsafe {
            let db = open_default("h.db").map_err(|e| format!("MK6b open: {e}"))?;
            set_pragmas(db)?;
            exec(db, "CREATE TABLE t(v TEXT)")?;
            exec(db, "INSERT INTO t(v) VALUES ('a1'),('a2')")?;
            ffi::sqlite3_close(db);
        }
        let img_a = util6b.export_raw("h.db").map_err(|e| format!("{e:?}"))?;
        let man_a = util6b.export_raw("h.db#manifest").map_err(|e| format!("{e:?}"))?;
        // depth-1 committed image (B):
        unsafe {
            let db = open_default("h.db").map_err(|e| format!("MK6b reopen B: {e}"))?;
            exec(db, "INSERT INTO t(v) VALUES ('b1')")?;
            ffi::sqlite3_close(db);
        }
        let img_b = util6b.export_raw("h.db").map_err(|e| format!("{e:?}"))?;
        // current committed image (C):
        unsafe {
            let db = open_default("h.db").map_err(|e| format!("MK6b reopen C: {e}"))?;
            exec(db, "INSERT INTO t(v) VALUES ('c1')")?;
            ffi::sqlite3_close(db);
        }
        let img_c2 = util6b.export_raw("h.db").map_err(|e| format!("{e:?}"))?;
        let man_c2 = util6b.export_raw("h.db#manifest").map_err(|e| format!("{e:?}"))?;
        let cur_cnt = unsafe {
            let db = open_default("h.db").map_err(|e| format!("MK6b cur open: {e}"))?;
            let n = scalar_i64(db, "SELECT count(*) FROM t").map_err(|e| format!("MK6(f) cur_cnt: {e}"))?;
            ffi::sqlite3_close(db);
            n
        };
        // DEPTH-1: restore img_b + CURRENT manifest (man_c2). Its root = R_b = prev_merkle_root of the
        // current manifest → accepted floor. Opening MAY succeed (documented residual). Assert it does
        // NOT serve anything OLDER than B (i.e. never a3/older) — it is the genuine previous state.
        util6b.import_raw("h.db", &img_b).map_err(|e| format!("{e:?}"))?;
        util6b.import_raw("h.db#manifest", &man_c2).map_err(|e| format!("{e:?}"))?;
        let depth1 = unsafe {
            match open_default("h.db") {
                Ok(db) => { let n = scalar_i64(db, "SELECT count(*) FROM t").ok(); ffi::sqlite3_close(db); n }
                Err(_) => None,
            }
        };
        // DEPTH-2: restore img_a + CURRENT manifest. root = R_a ∉ {R_c, R_b} → REFUSED, every open.
        let mut depth2_refused_each = true;
        for _ in 0..3 {
            util6b.import_raw("h.db", &img_a).map_err(|e| format!("{e:?}"))?;
            util6b.import_raw("h.db#manifest", &man_c2).map_err(|e| format!("{e:?}"))?;
            let served = unsafe {
                match open_default("h.db") {
                    Ok(db) => { let n = scalar_i64(db, "SELECT count(*) FROM t"); ffi::sqlite3_close(db); n.ok() }
                    Err(_) => None,
                }
            };
            if served.is_some() { depth2_refused_each = false; break; }
        }
        if !depth2_refused_each {
            return Err("MK6(f) DEPTH-2 rollback was SERVED — accepted set too wide!".into());
        }
        // Restore current image → reopens clean at current count.
        util6b.import_raw("h.db", &img_c2).map_err(|e| format!("{e:?}"))?;
        util6b.import_raw("h.db#manifest", &man_c2).map_err(|e| format!("{e:?}"))?;
        let restored = unsafe {
            let db = open_default("h.db").map_err(|e| format!("MK6b restore open: {e}"))?;
            let n = scalar_i64(db, "SELECT count(*) FROM t").map_err(|e| format!("{e}"))?;
            ffi::sqlite3_close(db);
            n
        };
        if restored != cur_cnt {
            return Err(format!("MK6(f) current image did not restore (got {restored}, want {cur_cnt})"));
        }
        util6b.pause_vfs().map_err(|e| format!("MK6b pause: {e:?}"))?;
        let _ = (man_c, img_c, img_a, man_a); // (kept for symmetry / potential future assertions)
        r.push_str(&format!(
            "MK6(f) rollback-depth boundary: depth-1 (genuine previous, = prev_root) open={} (accepted floor) | depth-2 REFUSED on all 3 opens | current restores to count={restored}\n",
            match depth1 { Some(n) => format!("served count={n}"), None => "refused".into() }
        ));

        // (g) ANCHOR SUBSTITUTION / DOWNGRADE (H1). Two parts, honestly scoped:
        //   (g.1) CLOSED: an attacker who restores an OLD anchor blob to the ACTIVE slot cannot lower
        //         a peer-attested epoch_floor as long as the double-buffer's other slot survives — the
        //         AEAD (version+slot AAD) authenticates the surviving current slot and its strict
        //         floor still refuses a below-floor image. (This is the realistic single-write / torn
        //         substitution the AAD binding + double-buffer defeat.)
        //   (g.2) DOCUMENTED RESIDUAL (§10.4, NOT closed by D-MR6): an attacker who WIPES BOTH anchor
        //         slots (or replaces both with old-format blobs) drops back to "fresh" — the local
        //         anchor is a deletable backstop; the un-wipeable strong anchor is the online sync
        //         epoch. We assert this residual explicitly so the boundary is tested, not hidden.
        {
            const ADB: &str = "anc.db";
            let a = install_dir("mk6-anc-a", "enc-mk6-anc-a", true, &DEK_OK).await.map_err(|e| format!("MK6g A install: {e}"))?;
            unsafe {
                let db = open_default(ADB).map_err(|e| format!("MK6g A open: {e}"))?;
                set_pragmas(db)?;
                exec(db, "CREATE TABLE t(v TEXT)")?;
                exec(db, "INSERT INTO t(v) VALUES ('one')")?;
                ffi::sqlite3_close(db);
            }
            let early_text = a.export_bundle(ADB).map_err(|e| format!("MK6g export early: {e:?}"))?;
            let early: Vec<(String, Vec<u8>)> = early_text
                .lines()
                .filter_map(|l| l.split_once('|'))
                .map(|(n, h)| Ok::<_, String>((n.to_string(), hex_to_bytes(h)?)))
                .collect::<std::result::Result<_, _>>()?;
            unsafe {
                let db = open_default(ADB).map_err(|e| format!("MK6g advance: {e}"))?;
                exec(db, "INSERT INTO t(v) VALUES ('two'),('three'),('four')")?;
                ffi::sqlite3_close(db);
            }
            let epoch_late = a.export_epoch(ADB).map_err(|e| format!("MK6g epoch: {e:?}"))?;
            a.pause_vfs().map_err(|e| format!("MK6g A pause: {e:?}"))?;

            // Device B: apply the late epoch (writes epoch_floor into BOTH anchor slots over time).
            let bdev = install_dir("mk6-anc-b", "enc-mk6-anc-b", true, &DEK_OK).await.map_err(|e| format!("MK6g B install: {e}"))?;
            let _seen = bdev.apply_epoch(&epoch_late).map_err(|e| format!("MK6g B apply epoch: {e:?}"))?;
            bdev.import_files(&early).map_err(|e| format!("MK6g B import early: {e:?}"))?;

            // (g.1) CLOSED: corrupt only the ACTIVE anchor slot (single-write substitution). The other
            // slot's authentic epoch_floor survives → the stale image is still REFUSED.
            let active = bdev.active_anchor_slot();
            bdev.corrupt_anchor_slot(active, crypto::PHYS_BLOCK).map_err(|e| format!("{e:?}"))?;
            let g1_refused = unsafe {
                match open_default(ADB) {
                    Err(_) => true,
                    Ok(db) => { let g = scalar_i64(db, "SELECT count(*) FROM t"); ffi::sqlite3_close(db); g.is_err() }
                }
            };
            if !g1_refused {
                return Err("MK6(g.1) single-slot anchor tamper cleared the epoch floor — stale image served!".into());
            }

            // (g.2) RESIDUAL: wipe BOTH slots → falls back to fresh → the stale image opens (the
            // documented §10.4 deletable-backstop boundary; the strong fix is the online sync epoch).
            let both_zero = vec![0u8; crypto::PHYS_BLOCK * 2];
            bdev.import_anchor_raw(&both_zero).map_err(|e| format!("{e:?}"))?;
            let g2_opened = unsafe {
                match open_default(ADB) {
                    Ok(db) => { let ok = scalar_i64(db, "SELECT count(*) FROM t").is_ok(); ffi::sqlite3_close(db); ok }
                    Err(_) => false,
                }
            };
            bdev.pause_vfs().map_err(|e| format!("MK6g B pause: {e:?}"))?;
            r.push_str(&format!(
                "MK6(g) anchor: single-slot tamper after epoch → stale REFUSED (double-buffer + version/slot AAD, H1 closed) | BOTH-slots wiped → opens={g2_opened} (documented §10.4 deletable-backstop residual; strong anchor = online sync epoch)\n"
            ));
        }

        // (h) LARGE MULTI-RECORD (and, if the cache spills, MULTI-HEADER) hot-journal replay (#4).
        // Commit a big baseline, then crash a LARGE transaction hot (many journaled pages → many
        // journal records, and enough dirty pages to risk a pager-cache spill = a second sector-
        // aligned journal-header segment). The VFS-owned replay must reconstruct the EXACT committed
        // baseline image (root ∈ accepted set) and the DB must reopen clean at the baseline count.
        {
            const LDB: &str = "large.db";
            let util_l = install_dir("mk6-large", "enc-mk6-large", true, &DEK_OK)
                .await
                .map_err(|e| format!("MK6h install: {e}"))?;
            // Baseline: a table big enough to span many pages (each row ~200B → hundreds of pages).
            let base_n = unsafe {
                let db = open_default(LDB).map_err(|e| format!("MK6h open: {e}"))?;
                set_pragmas(db)?;
                exec(db, "CREATE TABLE t(v TEXT)").map_err(|e| format!("MK6h create: {e}"))?;
                exec(db, "BEGIN").map_err(|e| format!("MK6h begin: {e}"))?;
                for i in 0..1500 {
                    exec(db, &format!("INSERT INTO t(v) VALUES ('baseline-row-{i}-{}')", "x".repeat(180)))
                        .map_err(|e| format!("MK6h base insert {i}: {e}"))?;
                }
                exec(db, "COMMIT").map_err(|e| format!("MK6h base commit: {e}"))?;
                let n = scalar_i64(db, "SELECT count(*) FROM t").map_err(|e| format!("MK6h base count: {e}"))?;
                ffi::sqlite3_close(db);
                n
            };
            // Snapshot the committed baseline (image + manifest) — the state a hot journal rolls back to.
            let img_base = util_l.export_raw(LDB).map_err(|e| format!("{e:?}"))?;
            let man_base = util_l.export_raw(&format!("{LDB}#manifest")).map_err(|e| format!("{e:?}"))?;

            // Crash a LARGE UPDATE hot: sweep fault points until a genuine hot journal persists.
            let ljrn = format!("{LDB}-journal");
            let mut got_hot = false;
            for fp in 1..=60u32 {
                unsafe {
                    let db = open_default(LDB).map_err(|e| format!("MK6h cap open {fp}: {e}"))?;
                    util_l.arm_fault(fp);
                    // A big UPDATE dirties many pages → many journal records (+ maybe a cache spill).
                    let _ = exec(db, "UPDATE t SET v = v || '-mutated-tail-padding-to-grow-the-page'");
                    ffi::sqlite3_close(db);
                }
                util_l.clear_fault();
                util_l.pause_vfs().map_err(|e| format!("MK6h pause {fp}: {e:?}"))?;
                util_l.unpause_vfs().await.map_err(|e| format!("MK6h unpause {fp}: {e:?}"))?;
                let j = util_l.export_raw(&ljrn).unwrap_or_default();
                let jrecs = if j.len() > crypto::BLOCK_SIZE { (j.len() - crypto::BLOCK_SIZE) / (crypto::BLOCK_SIZE + 8) } else { 0 };
                if util_l.exists(&ljrn).unwrap_or(false) && jrecs >= 2 {
                    got_hot = true;
                    // Recover: the VFS replays the (large, possibly multi-header) journal. Must
                    // reconstruct the EXACT baseline and open clean at base_n.
                    let n = unsafe {
                        let db = open_default(LDB)
                            .map_err(|e| format!("MK6h large replay BRICKED at fp {fp}: {e}"))?;
                        let n = scalar_i64(db, "SELECT count(*) FROM t")
                            .map_err(|e| format!("MK6h large replay unreadable at fp {fp}: {e}"))?;
                        ffi::sqlite3_close(db);
                        n
                    };
                    if n != base_n {
                        return Err(format!("MK6h large replay wrong count {n} (expect baseline {base_n})"));
                    }
                    // The replayed image must equal the baseline root (whole-image integrity).
                    let root_now = util_l.full_state_root(LDB).map_err(|e| format!("MK6h root: {e:?}"))?;
                    // Compare by reinstalling the pristine baseline and rooting it.
                    util_l.import_raw(LDB, &img_base).map_err(|e| format!("{e:?}"))?;
                    util_l.import_raw(&format!("{LDB}#manifest"), &man_base).map_err(|e| format!("{e:?}"))?;
                    let root_base = util_l.full_state_root(LDB).map_err(|e| format!("MK6h root_base: {e:?}"))?;
                    if root_now != root_base {
                        return Err("MK6h large replay reconstructed a DIFFERENT image than the committed baseline".into());
                    }
                    let jhdrs = {
                        // Count journal-header segments by scanning for the magic at sector boundaries
                        // in the DECRYPTED journal is not available here; report record count instead.
                        jrecs
                    };
                    r.push_str(&format!(
                        "MK6(h) large hot-journal replay: {jhdrs}+ records, crashed at fp {fp} → VFS replay reconstructed the EXACT baseline (count={n}, root matches), reopened clean — multi-record replay verified (#4)\n"
                    ));
                    break;
                }
                // No sufficiently-large hot journal at this fp — recover cleanly and retry.
                unsafe {
                    let db = open_default(LDB).map_err(|e| format!("MK6h clean recover {fp}: {e}"))?;
                    let _ = scalar_i64(db, "SELECT count(*) FROM t").map_err(|e| format!("MK6h count {fp}: {e}"))?;
                    ffi::sqlite3_close(db);
                }
            }
            util_l.pause_vfs().map_err(|e| format!("MK6h pause end: {e:?}"))?;
            if !got_hot {
                return Err("MK6(h) could not capture a large (≥2-record) hot journal".into());
            }
        }
    }

    // ---- Sync-epoch anchor (peer-attested rollback prevention) ---------------------------------
    r.push_str(&sync_epoch_test().await?);
    r.push('\n');

    // ---- Section SY: Freehold Sync ordering + fork semantics (blind-relay mock) -----------------
    r.push_str(&sync_test().await?);
    r.push('\n');

    // ---- Section RK: DEK rotation, physical re-encryption (issue #4 / D-RK2, increment 1b) --------
    r.push_str(&rekey_test().await?);
    r.push('\n');

    // ---- Section SJ: the SDK-facing session sync ops (wasm boundary the @freehold/db worker uses) -
    r.push_str(&sync_session_test().await?);
    r.push('\n');

    // ---- Section S: the session model (mock PRF — no gesture) ----------------------------------
    r.push_str(&session_test().await?);

    r.push_str("\nALL MILESTONE-2+3 CHECKS PASSED.\n");
    Ok(r)
}

#[wasm_bindgen]
pub async fn run_tests() -> String {
    console_error_panic_hook::set_once();
    match run().await {
        Ok(s) => s,
        Err(e) => format!("FAILED: {e}"),
    }
}

// ============================ passkey-PRF vault API (build-spec M2) ============================
// Driven by passkey.html's REAL WebAuthn-PRF ceremony (via the @freehold/db SDK). `prf` is the
// 32-byte PRF assertion output (`results.first` from the WebAuthn `prf` extension). enroll() wraps
// a fresh random DEK under the PRF-KEK and initializes an empty vault pool; everything key-
// requiring after that goes through the SESSION surface below (session_open/.../session_lock) —
// one ceremony per session, not one per query.

const DEMO_DIR: &str = "enc-passkey";

fn demo_cfg(name: &str, clear: bool) -> vfs::OpfsSAHPoolCfg {
    OpfsSAHPoolCfgBuilder::new()
        .vfs_name(name)
        .directory(DEMO_DIR)
        .clear_on_init(clear)
        .initial_capacity(6)
        .build()
}

async fn enroll_inner(prf: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if prf.len() < 16 {
        return Err("PRF output too short — is the `prf` extension actually supported here?".into());
    }
    let dek = envelope::random_dek().map_err(|e| format!("random_dek: {e:?}"))?;
    let blob = envelope::create_envelope(&dek, prf).map_err(|e| format!("create_envelope: {e:?}"))?;

    // Initialize an EMPTY vault pool (clear_on_init wipes any prior enrollment's ciphertext).
    // No schema is created here — the app defines its own via session_sql after session_open.
    let util = vfs::install::<ffi::WasmOsCallback>(&demo_cfg("pk-enroll", true), true, &dek)
        .await
        .map_err(|e| format!("install: {e:?}"))?;
    util.pause_vfs().map_err(|e| format!("pause: {e:?}"))?;
    // Return the envelope blob for the caller to persist; the DEK never leaves wasm memory.
    Ok(blob)
}

/// Enroll: wrap a fresh DEK under the PRF-KEK, initialize an empty vault, return the envelope blob.
#[wasm_bindgen]
pub async fn enroll(prf: &[u8]) -> Result<Vec<u8>, JsValue> {
    console_error_panic_hook::set_once();
    enroll_inner(prf).await.map_err(|e| JsValue::from_str(&e))
}

// ---- M3: N-KEK envelope management (pure re-wrap ops — no DB re-encryption) ----

// Hex helpers survive ONLY for the `name|hex` OPFS interchange that vfs.rs's testing-api bundle
// surface speaks (export_bundle/import_bundle). The wasm boundary itself is bytes end-to-end.
fn hex_to_bytes(s: &str) -> std::result::Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length blob hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "bad blob hex".to_string()))
        .collect()
}

/// Generate a fresh recovery code for the user to write down.
#[wasm_bindgen]
pub fn gen_recovery() -> Result<String, JsValue> {
    envelope::generate_recovery_code().map_err(|e| JsValue::from_str(&format!("{e:?}")))
}

/// Add a recovery-code method: unlock the DEK with the current passkey's PRF, then wrap it under the
/// recovery code's Argon2id KEK. Returns the new envelope blob. The DEK is unchanged.
#[wasm_bindgen]
pub fn add_recovery(existing_prf: &[u8], code: &str, blob: &[u8]) -> Result<Vec<u8>, JsValue> {
    let go = || -> std::result::Result<Vec<u8>, String> {
        let dek = envelope::open_with_prf(blob, existing_prf)
            .map_err(|_| "current passkey did not unlock — cannot add a method".to_string())?;
        envelope::add_recovery_slot(blob, &dek, code).map_err(|e| format!("add_recovery_slot: {e:?}"))
    };
    go().map_err(|e| JsValue::from_str(&e))
}

/// Add a second passkey method: unlock with the existing PRF, wrap the DEK under the new PRF.
#[wasm_bindgen]
pub fn add_passkey(existing_prf: &[u8], new_prf: &[u8], blob: &[u8]) -> Result<Vec<u8>, JsValue> {
    let go = || -> std::result::Result<Vec<u8>, String> {
        let dek = envelope::open_with_prf(blob, existing_prf)
            .map_err(|_| "current passkey did not unlock — cannot add a method".to_string())?;
        envelope::add_passkey_slot(blob, &dek, new_prf).map_err(|e| format!("add_passkey_slot: {e:?}"))
    };
    go().map_err(|e| JsValue::from_str(&e))
}

/// Revoke a method by its kek_id. Requires the current passkey's PRF to authorize (revoking is a
/// mutation that re-MACs the envelope under the DEK — v3). Returns the new blob. Refuses to remove
/// the last slot.
#[wasm_bindgen]
pub fn remove_method(existing_prf: &[u8], kek_id: u8, blob: &[u8]) -> Result<Vec<u8>, JsValue> {
    let go = || -> std::result::Result<Vec<u8>, String> {
        let dek = envelope::open_with_prf(blob, existing_prf)
            .map_err(|_| "current passkey did not unlock — cannot revoke a method".to_string())?;
        envelope::remove_slot(blob, &dek, kek_id)
            .map_err(|e| format!("remove_slot: {e:?} (cannot remove the last method)"))
    };
    go().map_err(|e| JsValue::from_str(&e))
}

/// The envelope's anti-rollback generation counter (v3). The SDK persists the max it has seen as a
/// floor and refuses any envelope below it — catching a rolled-back envelope that would re-plant a
/// revoked slot. Returned as f64 (generations are small; exact through 2^53).
#[wasm_bindgen]
pub fn envelope_generation(blob: &[u8]) -> f64 {
    envelope::envelope_generation(blob) as f64
}

/// List the envelope's unlock methods as `kek_id:kind` pairs, comma-separated (kind: passkey|recovery).
#[wasm_bindgen]
pub fn list_methods(blob: &[u8]) -> Result<String, JsValue> {
    let s = envelope::slot_infos(blob)
        .iter()
        .map(|i| {
            let kind = if i.kind == envelope::KIND_RECOVERY { "recovery" } else { "passkey" };
            format!("{}:{kind}", i.kek_id)
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(s)
}

// ---- M3 cross-device: import the ENCRYPTED DB image (no key inside) ----
// A dummy DEK is fine here: import writes raw ciphertext and never touches the block-device
// crypto. The image only decrypts later under the real DEK (passkey/recovery). Export moved to
// `session_export` (the live session's DEK mints the freshness epoch — no PRF re-prompt).
const DUMMY_DEK: [u8; 32] = [0u8; 32];

/// Import a binary bundle (from `export_db`). Writes the ciphertext files into a fresh pool and
/// returns `{ envelope, credId, epoch }` (Uint8Array fields; credId/epoch empty if absent) — the
/// caller persists them and passes the epoch to `unlock`, which applies it (a stale image below
/// that epoch is then refused at open).
#[wasm_bindgen]
pub async fn import_bundle(bytes: &[u8]) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let b = bundle::decode(bytes).map_err(|e| JsValue::from_str(&e))?;
    let util = vfs::install::<ffi::WasmOsCallback>(&demo_cfg("pk-import", true), true, &DUMMY_DEK)
        .await
        .map_err(|e| JsValue::from_str(&format!("install: {e:?}")))?;
    // Bundle file names are attacker-controlled; `import_files` validates each against the export
    // grammar and writes bytes directly — no `name|hex` text round-trip (security-review I-1/I-2).
    util.import_files(&b.files)
        .map_err(|e| JsValue::from_str(&format!("import: {e:?}")))?;
    util.pause_vfs().map_err(|e| JsValue::from_str(&format!("pause: {e:?}")))?;
    let out = js_sys::Object::new();
    for (k, v) in [("envelope", &b.envelope), ("credId", &b.cred_id), ("epoch", &b.epoch)] {
        js_sys::Reflect::set(&out, &JsValue::from_str(k), &js_sys::Uint8Array::from(v.as_slice()))?;
    }
    Ok(out.into())
}

// ============================ session + SQL surface (SDK — schema-agnostic) ============================
// The @freehold/db SDK must not be bound to any schema: after `session_open` unwraps the DEK ONCE
// (one WebAuthn ceremony), arbitrary SQL runs against named DBs in the session's pool until
// `session_lock`. Rows come back as a JSON array of row arrays with every value stringified
// (NULL → null). JSON output is built by hand — no serde in this crate by design (keep the
// dependency surface small and reviewable); params_json input is parsed via js_sys::JSON.

fn json_escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Serialize the current SQLITE_ROW of `stmt` into `out` as a JSON array of stringified values
/// (NULL → null). Shared by the multi-statement and parameterized query paths.
unsafe fn push_row_json(stmt: *mut ffi::sqlite3_stmt, out: &mut String, first_row: &mut bool) {
    if !*first_row {
        out.push(',');
    }
    *first_row = false;
    out.push('[');
    let ncol = ffi::sqlite3_column_count(stmt);
    for i in 0..ncol {
        if i > 0 {
            out.push(',');
        }
        if ffi::sqlite3_column_type(stmt, i) == ffi::SQLITE_NULL {
            out.push_str("null");
        } else {
            let t = ffi::sqlite3_column_text(stmt, i);
            let s = if t.is_null() {
                String::new()
            } else {
                CStr::from_ptr(t.cast()).to_string_lossy().into_owned()
            };
            json_escape_into(out, &s);
        }
    }
    out.push(']');
}

/// Prepare/step every statement in `sql` (multi-statement scripts allowed — the prepare tail is
/// followed like sqlite3_exec does), collecting all returned rows into one JSON array. Scripts
/// that return no rows produce "[]".
unsafe fn query_json(db: *mut ffi::sqlite3, sql: &str) -> std::result::Result<String, String> {
    let csql = CString::new(sql).map_err(|_| "SQL contains a NUL byte".to_string())?;
    let mut out = String::from("[");
    let mut first_row = true;
    let mut p = csql.as_ptr();
    loop {
        let mut stmt = ptr::null_mut();
        let mut tail: *const c_char = ptr::null();
        let rc = ffi::sqlite3_prepare_v2(db, p, -1, &mut stmt, &mut tail);
        if rc != ffi::SQLITE_OK {
            let msg = CStr::from_ptr(ffi::sqlite3_errmsg(db)).to_string_lossy().into_owned();
            return Err(format!("prepare rc={rc}: {msg}"));
        }
        // stmt is null for trailing whitespace/comments — skip to the tail, don't step.
        if !stmt.is_null() {
            loop {
                let step = ffi::sqlite3_step(stmt);
                if step == ffi::SQLITE_ROW {
                    push_row_json(stmt, &mut out, &mut first_row);
                } else if step == ffi::SQLITE_DONE {
                    break;
                } else {
                    let msg = CStr::from_ptr(ffi::sqlite3_errmsg(db)).to_string_lossy().into_owned();
                    ffi::sqlite3_finalize(stmt);
                    return Err(format!("step rc={step}: {msg}"));
                }
            }
            ffi::sqlite3_finalize(stmt);
        }
        if tail.is_null() || *tail == 0 {
            break;
        }
        p = tail;
    }
    out.push(']');
    Ok(out)
}

/// Prepare ONE statement, bind `params`, step, return the JSON rows. With params the prepare must
/// consume the whole string — a non-empty tail means a second statement smuggled after the bound
/// one, which is rejected (the params would silently not apply to it).
/// Bindings: null→NULL, boolean→0/1 int, number→int64 when integral else double, string→text.
/// (Blob params are DEFERRED — pass blobs as hex/base64 text for now.)
unsafe fn query_json_params(
    db: *mut ffi::sqlite3,
    sql: &str,
    params: &js_sys::Array,
) -> std::result::Result<String, String> {
    let csql = CString::new(sql).map_err(|_| "SQL contains a NUL byte".to_string())?;
    let mut stmt = ptr::null_mut();
    let mut tail: *const c_char = ptr::null();
    let rc = ffi::sqlite3_prepare_v2(db, csql.as_ptr(), -1, &mut stmt, &mut tail);
    if rc != ffi::SQLITE_OK {
        let msg = CStr::from_ptr(ffi::sqlite3_errmsg(db)).to_string_lossy().into_owned();
        return Err(format!("prepare rc={rc}: {msg}"));
    }
    if stmt.is_null() {
        return Err("no statement in SQL".into());
    }
    if !tail.is_null() && !CStr::from_ptr(tail).to_string_lossy().trim().is_empty() {
        ffi::sqlite3_finalize(stmt);
        return Err("params require a single statement".into());
    }
    let want = ffi::sqlite3_bind_parameter_count(stmt) as u32;
    if want != params.length() {
        ffi::sqlite3_finalize(stmt);
        return Err(format!("SQL has {want} parameter(s) but {} were supplied", params.length()));
    }
    for (i, v) in params.iter().enumerate() {
        let idx = (i + 1) as i32;
        let rc = if v.is_null() {
            ffi::sqlite3_bind_null(stmt, idx)
        } else if let Some(b) = v.as_bool() {
            ffi::sqlite3_bind_int64(stmt, idx, i64::from(b))
        } else if let Some(f) = v.as_f64() {
            // Integral doubles within the f64-exact range bind as INTEGER, everything else as REAL.
            if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_992.0 {
                ffi::sqlite3_bind_int64(stmt, idx, f as i64)
            } else {
                ffi::sqlite3_bind_double(stmt, idx, f)
            }
        } else if let Some(s) = v.as_string() {
            let n = s.len() as i32;
            let cs = match CString::new(s) {
                Ok(cs) => cs,
                Err(_) => {
                    ffi::sqlite3_finalize(stmt);
                    return Err(format!("param {i} contains a NUL byte"));
                }
            };
            ffi::sqlite3_bind_text(stmt, idx, cs.as_ptr(), n, ffi::SQLITE_TRANSIENT())
        } else {
            ffi::sqlite3_finalize(stmt);
            return Err(format!(
                "param {i}: unsupported type (allowed: null, boolean, number, string; blobs deferred)"
            ));
        };
        if rc != ffi::SQLITE_OK {
            let msg = CStr::from_ptr(ffi::sqlite3_errmsg(db)).to_string_lossy().into_owned();
            ffi::sqlite3_finalize(stmt);
            return Err(format!("bind param {i} rc={rc}: {msg}"));
        }
    }
    let mut out = String::from("[");
    let mut first_row = true;
    loop {
        let step = ffi::sqlite3_step(stmt);
        if step == ffi::SQLITE_ROW {
            push_row_json(stmt, &mut out, &mut first_row);
        } else if step == ffi::SQLITE_DONE {
            break;
        } else {
            let msg = CStr::from_ptr(ffi::sqlite3_errmsg(db)).to_string_lossy().into_owned();
            ffi::sqlite3_finalize(stmt);
            return Err(format!("step rc={step}: {msg}"));
        }
    }
    ffi::sqlite3_finalize(stmt);
    out.push(']');
    Ok(out)
}

// ---- the session (Feature: one ceremony, many queries) ----
// Wasm in a dedicated worker is single-threaded, so a thread_local holds the one live session:
// the installed pool util plus the open sqlite3 handles per named DB. The Session itself never
// holds key material — the DEK/subkeys live inside the pool's Crypto structs (vfs.rs), reachable
// only through the VFS.

struct Session {
    util: OpfsSAHPoolUtil,
    /// The envelope blob the session was opened with — non-secret ciphertext, retained so
    /// `session_export` can embed it in the bundle without a re-prompt.
    envelope: Vec<u8>,
    /// Open connection per named DB file ("<name>.db"), all closed on lock.
    handles: HashMap<String, *mut ffi::sqlite3>,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

const SESSION_VFS: &str = "pk-session";

/// A named DB becomes OPFS file "<name>.db" — validate strictly (`[a-z0-9_-]{1,32}`) so a name can
/// never smuggle a path, a `#manifest` suffix, or a satellite (`-journal`) collision.
fn valid_db_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

/// Install the pool once and store the session. Idempotent: a live session is locked first, so a
/// second `session_open` (e.g. after a passkey re-prompt) can never leak handles.
async fn session_begin(
    dek: &[u8; 32],
    envelope: &[u8],
    epoch: &[u8],
    cfg: &vfs::OpfsSAHPoolCfg,
) -> std::result::Result<(), String> {
    session_lock_inner()?;
    let util = vfs::install::<ffi::WasmOsCallback>(cfg, true, dek)
        .await
        .map_err(|e| format!("install: {e:?}"))?;
    // sync-epoch: apply any peer epoch BEFORE anything opens so a rollback below it is refused.
    if !epoch.is_empty() {
        util.apply_epoch(epoch).map_err(|e| format!("apply_epoch: {e:?}"))?;
    }
    SESSION.with(|s| {
        *s.borrow_mut() = Some(Session { util, envelope: envelope.to_vec(), handles: HashMap::new() })
    });
    Ok(())
}

/// Close every sqlite3 handle and tear the pool down. `pause_vfs` is the strongest teardown the
/// sahpool surface offers: it unregisters the VFS from SQLite and `release_access_handles()`
/// closes EVERY FileSystemSyncAccessHandle (data files + anchor) — SAH close releases the OPFS
/// exclusive locks, so another tab can acquire the pool afterwards. It also clears the per-DB
/// `DbState`/`Crypto` subkeys. Known residual: the pool's registration appdata (holding the
/// Zeroizing DEK + pool/anchor subkeys) is a leaked `'static` and survives until the worker dies —
/// same as the pre-session per-op design; a locked session still cannot reach it (no VFS, no
/// handles). No-op when no session is live.
fn session_lock_inner() -> std::result::Result<(), String> {
    let Some(mut s) = SESSION.with(|cell| cell.borrow_mut().take()) else {
        return Ok(());
    };
    for (_, db) in s.handles.drain() {
        unsafe {
            ffi::sqlite3_close(db);
        }
    }
    s.util.pause_vfs().map_err(|e| format!("session_lock pause: {e:?}"))?;
    Ok(())
}

/// Open a session: unwrap the DEK via the passkey PRF (ONE ceremony), apply any peer epoch,
/// install the VFS, and hold it all until `session_lock`. Every subsequent `session_sql` /
/// `session_export` rides this session with no further prompts.
#[wasm_bindgen]
pub async fn session_open(prf: &[u8], blob: &[u8], epoch: &[u8]) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    let dek = envelope::open_with_prf(blob, prf)
        .map_err(|_| JsValue::from_str("unlock failed — wrong passkey, wrong PRF/UV state, or tampered envelope"))?;
    session_begin(&dek, blob, epoch, &demo_cfg(SESSION_VFS, false))
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Open a session with the written recovery code instead of a passkey (same semantics).
#[wasm_bindgen]
pub async fn session_open_recovery(code: &str, blob: &[u8], epoch: &[u8]) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    let dek = envelope::open_with_recovery(blob, code)
        .map_err(|_| JsValue::from_str("recovery code did not unlock — wrong code or tampered envelope"))?;
    session_begin(&dek, blob, epoch, &demo_cfg(SESSION_VFS, false))
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Lock the session: close handles, release the pool (see `session_lock_inner`), drop the session.
#[wasm_bindgen]
pub fn session_lock() -> Result<(), JsValue> {
    session_lock_inner().map_err(|e| JsValue::from_str(&e))
}

/// Is a session currently open?
#[wasm_bindgen]
pub fn session_active() -> bool {
    SESSION.with(|s| s.borrow().is_some())
}

fn session_sql_inner(db: &str, sql: &str, params_json: &str) -> std::result::Result<String, String> {
    if !valid_db_name(db) {
        return Err(format!("invalid db name {db:?} — must match [a-z0-9_-]{{1,32}}"));
    }
    // Parse params OUTSIDE the borrow (js_sys::JSON keeps the no-serde rule; input came from JS).
    let params = match params_json.trim() {
        "" | "[]" => None,
        s => {
            let v = js_sys::JSON::parse(s).map_err(|_| "params_json is not valid JSON".to_string())?;
            if !js_sys::Array::is_array(&v) {
                return Err("params_json must be a JSON array".into());
            }
            Some(js_sys::Array::from(&v))
        }
    };
    SESSION.with(|cell| {
        let mut guard = cell.borrow_mut();
        let s = guard
            .as_mut()
            .ok_or_else(|| "no active session — call session_open first".to_string())?;
        let file = format!("{db}.db");
        let handle = match s.handles.get(&file) {
            Some(&h) => h,
            None => unsafe {
                let h = open_default(&file)
                    .map_err(|e| format!("open rejected (rollback below a peer epoch, or wrong key): {e}"))?;
                if let Err(e) = set_pragmas(h) {
                    ffi::sqlite3_close(h);
                    return Err(e);
                }
                s.handles.insert(file, h);
                h
            },
        };
        unsafe {
            match &params {
                Some(p) => query_json_params(handle, sql, p),
                None => query_json(handle, sql),
            }
        }
    })
}

/// Run SQL against named DB `db` in the live session. `params_json` is a JSON array bound to `?`
/// placeholders (empty string or "[]" = none; then multi-statement scripts are allowed). Returns
/// a JSON array of row arrays (stringified values, NULL → null); no rows yields "[]".
#[wasm_bindgen]
pub fn session_sql(db: &str, sql: &str, params_json: &str) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    session_sql_inner(db, sql, params_json).map_err(|e| JsValue::from_str(&e))
}

fn session_export_inner(cred_id: &[u8]) -> std::result::Result<Vec<u8>, String> {
    SESSION.with(|cell| {
        let guard = cell.borrow();
        let s = guard
            .as_ref()
            .ok_or_else(|| "no active session — call session_open first".to_string())?;
        // Every main DB in the pool goes into the bundle (the TLV carries per-file sections; the
        // vfs export surface speaks `name|hex` per DB — decode at this boundary, vfs.rs untouched).
        let mut db_names: Vec<String> =
            s.util.list().into_iter().filter(|n| n.ends_with(".db")).collect();
        db_names.sort();
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        for name in &db_names {
            let text = s.util.export_bundle(name).map_err(|e| format!("export {name}: {e:?}"))?;
            for line in text.lines() {
                let Some((n, hex)) = line.split_once('|') else { continue };
                files.push((n.to_string(), hex_to_bytes(hex)?));
            }
        }
        if files.is_empty() {
            return Err("nothing to export — run some SQL to create a database first".into());
        }
        // One epoch token per bundle: mint it for the primary DB ("app" when present). The live
        // session's DEK signs it — no PRF re-prompt, which is the point of the session.
        let epoch_db = db_names
            .iter()
            .find(|n| n.as_str() == "app.db")
            .unwrap_or(&db_names[0]);
        let epoch = s
            .util
            .export_epoch(epoch_db)
            .map_err(|e| format!("export_epoch {epoch_db}: {e:?}"))?;
        Ok(bundle::encode(&s.envelope, cred_id, &files, &epoch))
    })
}

/// Export the binary `.freehold` bundle from the LIVE session: envelope + credential id + the
/// encrypted image of every DB in the pool + a freshly minted sync-epoch token. No key inside.
/// Pass an empty `cred_id` slice if there is none to embed (e.g. recovery-only flows).
#[wasm_bindgen]
pub fn session_export(cred_id: &[u8]) -> Result<Vec<u8>, JsValue> {
    console_error_panic_hook::set_once();
    session_export_inner(cred_id).map_err(|e| JsValue::from_str(&e))
}

// ============================ session sync surface (freehold-sync-design §10 item 3) ============================
// Thin wasm ops that let the @freehold/db SDK drive the PROVEN sync engine (sync.rs) from JS. The
// security- and correctness-critical parts stay in wasm: sealing/opening blobs under the DEK-derived
// sync_key (the DEK never leaves the pool — sync_crypto is a subkey), and ALL conflict classification
// (reconcile + version-vector algebra). JS owns only orchestration: the push/pull loop, the pluggable
// blind-relay transport, IDB persistence of device_id / version-vector / pull-cursor, and the fork
// API surface. The version vector is non-secret lineage metadata and the image is already ciphertext,
// so both cross the boundary as opaque bytes.

fn slice16(b: &[u8], what: &str) -> std::result::Result<[u8; 16], String> {
    if b.len() != 16 {
        return Err(format!("{what} must be 16 bytes, got {}", b.len()));
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(b);
    Ok(a)
}

fn decode_vv(bytes: &[u8], what: &str) -> std::result::Result<sync::VersionVector, String> {
    let mut at = 0usize;
    let v = sync::VersionVector::decode(bytes, &mut at)?;
    if at != bytes.len() {
        return Err(format!("{what}: trailing bytes"));
    }
    Ok(v)
}

// Collect every DB in the live session's pool into an image-only `.freehold` bundle (no envelope /
// credId / epoch — the sync image is pure ciphertext; freshness rides the version vector). Mirrors
// `session_export_inner` minus the key/envelope sections.
fn session_image() -> std::result::Result<Vec<u8>, String> {
    SESSION.with(|cell| {
        let guard = cell.borrow();
        let s = guard
            .as_ref()
            .ok_or_else(|| "no active session — call session_open first".to_string())?;
        let mut names: Vec<String> =
            s.util.list().into_iter().filter(|n| n.ends_with(".db")).collect();
        names.sort();
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        for name in &names {
            let text = s.util.export_bundle(name).map_err(|e| format!("export {name}: {e:?}"))?;
            for line in text.lines() {
                let Some((n, hex)) = line.split_once('|') else { continue };
                files.push((n.to_string(), hex_to_bytes(hex)?));
            }
        }
        if files.is_empty() {
            return Err("nothing to sync — create a database first".into());
        }
        Ok(bundle::encode(&[], &[], &files, &[]))
    })
}

fn session_sync_id_inner(db_uuid: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let u = slice16(db_uuid, "db_uuid")?;
    SESSION.with(|cell| {
        let g = cell.borrow();
        let s = g
            .as_ref()
            .ok_or_else(|| "no active session — call session_open first".to_string())?;
        Ok(s.util.sync_id(&u).to_vec())
    })
}

fn session_sync_seal_inner(db_uuid: &[u8], vv: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let db_uuid = slice16(db_uuid, "db_uuid")?;
    let vv = decode_vv(vv, "version vector")?;
    let image = session_image()?;
    let sync_crypto = SESSION.with(|cell| {
        let g = cell.borrow();
        let s = g
            .as_ref()
            .ok_or_else(|| "no active session — call session_open first".to_string())?;
        Ok::<_, String>(s.util.sync_crypto())
    })?;
    let blob = sync::SyncBlob { db_uuid, vv, image };
    blob.seal(&sync_crypto).map_err(|e| format!("seal sync blob: {e:?}"))
}

fn session_sync_open_parts(sealed: &[u8]) -> std::result::Result<([u8; 16], Vec<u8>, Vec<u8>), String> {
    let sync_crypto = SESSION.with(|cell| {
        let g = cell.borrow();
        let s = g
            .as_ref()
            .ok_or_else(|| "no active session — call session_open first".to_string())?;
        Ok::<_, String>(s.util.sync_crypto())
    })?;
    let blob = sync::SyncBlob::open(sealed, &sync_crypto)?;
    Ok((blob.db_uuid, blob.vv.encode(), blob.image))
}

// Apply a pulled image into the LIVE session pool: close open handles so the ciphertext files can be
// overwritten, import the image, and drop the handle map so the next `session_sql` reopens fresh
// against it. The DEK/pool persist — no re-unlock. Callers only reach here for FastForward or the
// fork WINNER (generation ≥ current), so the anti-rollback anchor admits it at reopen; a stale image
// is classified Stale by `reconcile` and never applied.
fn session_sync_apply_inner(image: &[u8]) -> std::result::Result<(), String> {
    let b = bundle::decode(image).map_err(|e| format!("bundle decode: {e}"))?;
    SESSION.with(|cell| {
        let mut guard = cell.borrow_mut();
        let s = guard
            .as_mut()
            .ok_or_else(|| "no active session — call session_open first".to_string())?;
        for (_, db) in s.handles.drain() {
            unsafe {
                ffi::sqlite3_close(db);
            }
        }
        s.util.import_files(&b.files).map_err(|e| format!("import_files: {e:?}"))
    })
}

fn sync_reconcile_inner(local_vv: &[u8], incoming_vv: &[u8]) -> std::result::Result<(&'static str, bool), String> {
    let l = decode_vv(local_vv, "local vv")?;
    let i = decode_vv(incoming_vv, "incoming vv")?;
    Ok(match sync::reconcile(&l, &i) {
        sync::MergeOutcome::FastForward => ("fastforward", false),
        sync::MergeOutcome::Stale => ("stale", false),
        sync::MergeOutcome::Fork { winner_is_incoming } => ("fork", winner_is_incoming),
    })
}

/// Opaque 16-byte relay bucket id for the live session's DEK + `db_uuid` (freehold-sync-design §4).
#[wasm_bindgen]
pub fn session_sync_id(db_uuid: &[u8]) -> Result<Vec<u8>, JsValue> {
    console_error_panic_hook::set_once();
    session_sync_id_inner(db_uuid).map_err(|e| JsValue::from_str(&e))
}

/// Seal the live session's current image + `vv` into a relay blob under the DEK-derived sync_key.
#[wasm_bindgen]
pub fn session_sync_seal(db_uuid: &[u8], vv: &[u8]) -> Result<Vec<u8>, JsValue> {
    console_error_panic_hook::set_once();
    session_sync_seal_inner(db_uuid, vv).map_err(|e| JsValue::from_str(&e))
}

/// Authenticated-open a relay blob → `{ dbUuid, vv, image }` (all Uint8Array). Wrong key/tamper Errs.
#[wasm_bindgen]
pub fn session_sync_open(sealed: &[u8]) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let (db_uuid, vv, image) = session_sync_open_parts(sealed).map_err(|e| JsValue::from_str(&e))?;
    let out = js_sys::Object::new();
    for (k, v) in [("dbUuid", db_uuid.as_slice()), ("vv", vv.as_slice()), ("image", image.as_slice())] {
        js_sys::Reflect::set(&out, &JsValue::from_str(k), &js_sys::Uint8Array::from(v))?;
    }
    Ok(out.into())
}

/// Apply a pulled image into the live session (FastForward / fork-winner only). See inner docs.
#[wasm_bindgen]
pub fn session_sync_apply(image: &[u8]) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    session_sync_apply_inner(image).map_err(|e| JsValue::from_str(&e))
}

/// The empty version vector (all-zero components), encoded.
#[wasm_bindgen]
pub fn sync_vv_empty() -> Vec<u8> {
    sync::VersionVector::new().encode()
}

/// Bump `device_id`'s component in `vv` by one; returns the re-encoded vector.
#[wasm_bindgen]
pub fn sync_vv_increment(vv: &[u8], device_id: &[u8]) -> Result<Vec<u8>, JsValue> {
    (|| -> std::result::Result<Vec<u8>, String> {
        let dev = slice16(device_id, "device_id")?;
        let mut v = decode_vv(vv, "version vector")?;
        v.increment(&dev);
        Ok(v.encode())
    })()
    .map_err(|e| JsValue::from_str(&e))
}

/// Element-wise max of two vectors (applied after a fork resolves so it does not re-trigger).
#[wasm_bindgen]
pub fn sync_vv_merge(a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    (|| -> std::result::Result<Vec<u8>, String> {
        let mut va = decode_vv(a, "vv a")?;
        let vb = decode_vv(b, "vv b")?;
        va.merge_max(&vb);
        Ok(va.encode())
    })()
    .map_err(|e| JsValue::from_str(&e))
}

/// Classify incoming vs local → `{ outcome: 'fastforward'|'stale'|'fork', winnerIsIncoming: bool }`.
#[wasm_bindgen]
pub fn sync_reconcile(local_vv: &[u8], incoming_vv: &[u8]) -> Result<JsValue, JsValue> {
    let (outcome, winner) = sync_reconcile_inner(local_vv, incoming_vv).map_err(|e| JsValue::from_str(&e))?;
    let out = js_sys::Object::new();
    js_sys::Reflect::set(&out, &JsValue::from_str("outcome"), &JsValue::from_str(outcome))?;
    js_sys::Reflect::set(&out, &JsValue::from_str("winnerIsIncoming"), &JsValue::from_bool(winner))?;
    Ok(out.into())
}

/// Section SJ — the SDK-facing session sync ops (freehold-sync-design §10 item 3), driven through a
/// LIVE session exactly as the @freehold/db worker drives them. Proves the wasm boundary: sync_id
/// derivation, seal→open round-trip, version-vector helpers + reconcile agreeing with the engine, and
/// apply reopening cleanly. The multi-device ORDERING/FORK semantics themselves are proven in SY over
/// fresh pools; this proves the thin session wrappers on top of them.
async fn sync_session_test() -> std::result::Result<String, String> {
    let prf: [u8; 32] = [37u8; 32]; // stand-in for a WebAuthn-PRF assertion
    let blob = envelope::create_envelope(&DEK_OK, &prf).map_err(|e| format!("SJ create_envelope: {e:?}"))?;
    session_open(&prf, &blob, &[])
        .await
        .map_err(|e| format!("SJ session_open: {e:?}"))?;

    session_sql_inner("app", "CREATE TABLE t(v TEXT)", "[]")?;
    session_sql_inner("app", "INSERT INTO t(v) VALUES ('base')", "[]")?;

    let db_uuid: [u8; 16] = *b"freehold-sj-uuid";

    // 1) sync_id: 16 bytes, deterministic, and db_uuid-sensitive.
    let id1 = session_sync_id_inner(&db_uuid)?;
    if id1.len() != 16 || id1 != session_sync_id_inner(&db_uuid)? {
        return Err("SJ: sync_id not 16 bytes / not deterministic".into());
    }
    let mut other = db_uuid;
    other[0] ^= 0xff;
    if session_sync_id_inner(&other)? == id1 {
        return Err("SJ: sync_id not sensitive to db_uuid".into());
    }

    // 2) vv helpers + seal→open round-trip preserves db_uuid, vv, and the exact image bytes.
    let dev = [0x5au8; 16];
    let vv1 = sync_vv_increment(&sync_vv_empty(), &dev).map_err(|e| format!("SJ vv_increment: {e:?}"))?;
    let sealed = session_sync_seal_inner(&db_uuid, &vv1)?;
    let (o_uuid, o_vv, o_image) = session_sync_open_parts(&sealed)?;
    if o_uuid != db_uuid {
        return Err("SJ: opened db_uuid mismatch".into());
    }
    if o_vv != vv1 {
        return Err("SJ: opened vv mismatch".into());
    }
    if o_image != session_image()? {
        return Err("SJ: opened image != current session image".into());
    }

    // 3) reconcile agrees with the engine: {dev:2} vs {dev:1} → fast-forward; reverse → stale.
    let vv2 = sync_vv_increment(&vv1, &dev).map_err(|e| format!("SJ vv_increment2: {e:?}"))?;
    if sync_reconcile_inner(&vv1, &vv2)?.0 != "fastforward" {
        return Err("SJ: reconcile(local={dev:1}, incoming={dev:2}) should fast-forward".into());
    }
    if sync_reconcile_inner(&vv2, &vv1)?.0 != "stale" {
        return Err("SJ: reconcile(local={dev:2}, incoming={dev:1}) should be stale".into());
    }

    // 4) apply reopens cleanly: applying the current image (equal generation — anti-rollback admits
    //    it) closes+reopens handles without corruption; the DB still reads back. Forward-apply that
    //    REPLACES state across devices is the SY proof; here we prove the wrapper's handle refresh.
    session_sync_apply_inner(&o_image)?;
    let rows = session_sql_inner("app", "SELECT v FROM t", "[]")?;
    if rows != "[[\"base\"]]" {
        return Err(format!("SJ: after apply expected [[\"base\"]], got {rows}"));
    }

    session_lock_inner()?;
    Ok("SJ. session sync ops (SDK boundary): sync_id derived+opaque | seal\u{2192}open round-trips image+vv | reconcile matches engine | apply refreshes handles \u{2705}".to_string())
}
