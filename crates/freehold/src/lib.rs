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
        env = envelope::remove_slot(&env, 0).map_err(|e| format!("M3 remove slot 0: {e:?}"))?; // revoke passkey-A
        let n_after = envelope::slot_infos(&env).len();
        if envelope::open_with_prf(&env, &prf_ok).is_ok() {
            return Err("M3 envelope: REVOKED passkey-A still unlocks!".into());
        }
        envelope::open_with_prf(&env, &prf_b).map_err(|_| "M3 envelope: passkey-B broke after removing A".to_string())?;
        envelope::open_with_recovery(&env, &code).map_err(|_| "M3 envelope: recovery broke after removing A".to_string())?;
        r.push_str(&format!(
            "M3. N-KEK envelope: 2 passkeys + recovery all recover 1 DEK | wrong code rejected | revoke A ({n_before}→{n_after} slots) leaves B+recovery working\n"
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

    // ---- §17.C: torn manifest slot ⇒ the other slot recovers, DB not bricked -------------------
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
        let n = count_rows().map_err(|e| format!("torn-manifest recovery FAILED (bricked): {e}"))?;
        let gen_rec = util_c.manifest_generation(DB_NAME).unwrap_or(0);
        r.push_str(&format!(
            "C. torn active manifest slot: recovered via other slot, count={n} (expect 5), gen {gen}->{gen_rec}\n"
        ));
        util_c.import_raw(MANIFEST, &man_clean).map_err(|e| format!("{e:?}"))?;
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

    // ---- Sync-epoch anchor (peer-attested rollback prevention) ---------------------------------
    r.push_str(&sync_epoch_test().await?);
    r.push('\n');

    // ---- Section SY: Freehold Sync ordering + fork semantics (blind-relay mock) -----------------
    r.push_str(&sync_test().await?);
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

/// Revoke a method by its kek_id. Returns the new blob. Refuses to remove the last slot.
#[wasm_bindgen]
pub fn remove_method(kek_id: u8, blob: &[u8]) -> Result<Vec<u8>, JsValue> {
    envelope::remove_slot(blob, kek_id)
        .map_err(|e| JsValue::from_str(&format!("remove_slot: {e:?} (cannot remove the last method)")))
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
