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
//! See BUILD-NOTES for the honest IN/DEFERRED ledger.

mod bundle;
mod crypto;
mod envelope;
mod manifest;
mod vfs;

use sqlite_wasm_rs as ffi;
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
        let early = a.export_bundle(SDB).map_err(|e| format!("export early: {e:?}"))?; // low gen
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
    b.import_bundle(&img_early).map_err(|e| format!("B import early: {e:?}"))?;
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
    c.import_bundle(&img_early).map_err(|e| format!("C import early: {e:?}"))?;
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

// ============================ passkey-PRF demo API (build-spec M2) ============================
// Driven by passkey.html's REAL WebAuthn-PRF ceremony. `prf` is the 32-byte PRF assertion output
// (`results.first` from the WebAuthn `prf` extension). enroll() wraps a fresh random DEK under the
// PRF-KEK and writes a secret row; unlock() unwraps the DEK from the returned blob and reads it
// back — proving the DB opens ONLY when the same passkey re-derives the same PRF output.

const DEMO_DB: &str = "passkey-demo.db";
const DEMO_DIR: &str = "enc-passkey";
const DEMO_SECRET: &str = "unlocked-by-your-passkey \u{1f510}";

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

    let util = vfs::install::<ffi::WasmOsCallback>(&demo_cfg("pk-enroll", true), true, &dek)
        .await
        .map_err(|e| format!("install: {e:?}"))?;
    unsafe {
        let db = open_default(DEMO_DB)?;
        set_pragmas(db)?;
        exec(db, "CREATE TABLE IF NOT EXISTS secret(v TEXT)")?;
        exec(db, "DELETE FROM secret")?;
        exec(db, &format!("INSERT INTO secret(v) VALUES ('{DEMO_SECRET}')"))?;
        ffi::sqlite3_close(db);
    }
    util.pause_vfs().map_err(|e| format!("pause: {e:?}"))?;
    // Return the envelope blob for the caller to persist; the DEK never leaves wasm memory.
    Ok(blob)
}

async fn unlock_inner(prf: &[u8], blob: &[u8], epoch: &[u8]) -> std::result::Result<String, String> {
    let dek = envelope::open_with_prf(blob, prf)
        .map_err(|_| "unlock failed — wrong passkey, wrong PRF/UV state, or tampered envelope".to_string())?;

    let util = vfs::install::<ffi::WasmOsCallback>(&demo_cfg("pk-unlock", false), true, &dek)
        .await
        .map_err(|e| format!("install: {e:?}"))?;
    // sync-epoch: apply any peer epoch BEFORE opening so a rollback below it is refused at open.
    if !epoch.is_empty() {
        util.apply_epoch(epoch).map_err(|e| format!("apply_epoch: {e:?}"))?;
    }
    let row = unsafe {
        let db = open_default(DEMO_DB)
            .map_err(|e| format!("open rejected (rollback below a peer epoch, or wrong key): {e}"))?;
        set_pragmas(db)?;
        let v = scalar_text(db, "SELECT v FROM secret ORDER BY rowid LIMIT 1")?;
        ffi::sqlite3_close(db);
        v
    };
    util.pause_vfs().map_err(|e| format!("pause: {e:?}"))?;
    Ok(row)
}

/// Enroll: wrap a fresh DEK under the PRF-KEK, create the demo DB, return the envelope blob.
#[wasm_bindgen]
pub async fn enroll(prf: &[u8]) -> Result<Vec<u8>, JsValue> {
    console_error_panic_hook::set_once();
    enroll_inner(prf).await.map_err(|e| JsValue::from_str(&e))
}

/// Unlock: apply any peer `epoch` token (freshness), unwrap the DEK via the PRF, open the DB,
/// return the secret row. Pass an empty slice for `epoch` when there's no peer epoch to apply.
#[wasm_bindgen]
pub async fn unlock(prf: &[u8], blob: &[u8], epoch: &[u8]) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    unlock_inner(prf, blob, epoch).await.map_err(|e| JsValue::from_str(&e))
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
fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

/// Unlock with the recovery code instead of a passkey: derive the Argon2id KEK, unwrap the DEK,
/// open the DB, return the secret row.
#[wasm_bindgen]
pub async fn unlock_recovery(code: &str, blob: &[u8], epoch: &[u8]) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    let dek = envelope::open_with_recovery(blob, code)
        .map_err(|_| JsValue::from_str("recovery code did not unlock — wrong code or tampered envelope"))?;
    let util = vfs::install::<ffi::WasmOsCallback>(&demo_cfg("pk-recover", false), true, &dek)
        .await
        .map_err(|e| JsValue::from_str(&format!("install: {e:?}")))?;
    if !epoch.is_empty() {
        util.apply_epoch(epoch).map_err(|e| JsValue::from_str(&format!("apply_epoch: {e:?}")))?;
    }
    let row = unsafe {
        let db = open_default(DEMO_DB).map_err(|e| JsValue::from_str(&format!("open: {e}")))?;
        let _ = set_pragmas(db);
        let v = scalar_text(db, "SELECT v FROM secret ORDER BY rowid LIMIT 1")
            .map_err(|e| JsValue::from_str(&e))?;
        ffi::sqlite3_close(db);
        v
    };
    util.pause_vfs().map_err(|e| JsValue::from_str(&format!("pause: {e:?}")))?;
    Ok(row)
}

// ---- M3 cross-device: export/import the ENCRYPTED DB image (no key inside) ----
// A dummy DEK is fine here: export reads raw ciphertext and import writes raw ciphertext — neither
// touches the block-device crypto. The image only decrypts later under the real DEK (passkey/recovery).
const DUMMY_DEK: [u8; 32] = [0u8; 32];

/// Add a row to the demo DB (advances db_generation) so you can create a v1/v2 pair for the live
/// two-device rollback test. Applies any peer epoch first, then commits a new note.
#[wasm_bindgen]
pub async fn add_note(prf: &[u8], blob: &[u8], epoch: &[u8]) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    let dek = envelope::open_with_prf(blob, prf)
        .map_err(|_| JsValue::from_str("unlock failed — cannot add data"))?;
    let util = vfs::install::<ffi::WasmOsCallback>(&demo_cfg("pk-note", false), true, &dek)
        .await
        .map_err(|e| JsValue::from_str(&format!("install: {e:?}")))?;
    if !epoch.is_empty() {
        util.apply_epoch(epoch).map_err(|e| JsValue::from_str(&format!("apply_epoch: {e:?}")))?;
    }
    let n = unsafe {
        let db = open_default(DEMO_DB).map_err(|e| JsValue::from_str(&format!("open: {e}")))?;
        set_pragmas(db).map_err(|e| JsValue::from_str(&e))?;
        exec(db, "CREATE TABLE IF NOT EXISTS secret(v TEXT)").map_err(|e| JsValue::from_str(&e))?;
        exec(db, "INSERT INTO secret(v) VALUES ('note @ ' || datetime('now'))")
            .map_err(|e| JsValue::from_str(&e))?;
        let n = scalar_i64(db, "SELECT count(*) FROM secret").unwrap_or(0);
        ffi::sqlite3_close(db);
        n
    };
    util.pause_vfs().map_err(|e| JsValue::from_str(&format!("pause: {e:?}")))?;
    Ok(format!("added a note (DB now has {n} rows — a newer version). Export a fresh bundle."))
}

/// Export a self-contained binary `.freehold` bundle: envelope + credential id + the encrypted DB
/// image + a freshly minted sync-epoch token (bundle.rs TLV). The image is DEK-free; the epoch
/// token is DEK-authenticated freshness. Needs the passkey PRF to mint the epoch. Pass an empty
/// `cred_id` slice if there is none to embed (e.g. recovery-only flows).
#[wasm_bindgen]
pub async fn export_db(prf: &[u8], blob: &[u8], cred_id: &[u8]) -> Result<Vec<u8>, JsValue> {
    console_error_panic_hook::set_once();
    let dek = envelope::open_with_prf(blob, prf)
        .map_err(|_| JsValue::from_str("unlock failed — cannot mint a freshness epoch for export"))?;
    let util = vfs::install::<ffi::WasmOsCallback>(&demo_cfg("pk-export", false), true, &dek)
        .await
        .map_err(|e| JsValue::from_str(&format!("install: {e:?}")))?;
    // The vfs testing-api export surface speaks `name|hex` lines; decode to bytes at this boundary
    // (vfs.rs deliberately untouched) and pack them as binary file sections.
    let text = util
        .export_bundle(DEMO_DB)
        .map_err(|e| JsValue::from_str(&format!("export: {e:?}")))?;
    let epoch = util
        .export_epoch(DEMO_DB)
        .map_err(|e| JsValue::from_str(&format!("export_epoch: {e:?}")))?;
    util.pause_vfs().map_err(|e| JsValue::from_str(&format!("pause: {e:?}")))?;
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for line in text.lines() {
        let Some((name, hex)) = line.split_once('|') else { continue };
        let data = hex_to_bytes(hex).map_err(|e| JsValue::from_str(&e))?;
        files.push((name.to_string(), data));
    }
    if files.is_empty() {
        return Err(JsValue::from_str("nothing to export — enroll and create the DB first"));
    }
    Ok(bundle::encode(blob, cred_id, &files, &epoch))
}

/// Import a binary bundle (from `export_db`). Writes the ciphertext files into a fresh pool and
/// returns `{ envelope, credId, epoch }` (Uint8Array fields; credId/epoch empty if absent) — the
/// caller persists them and passes the epoch to `unlock`, which applies it (a stale image below
/// that epoch is then refused at open).
#[wasm_bindgen]
pub async fn import_bundle(bytes: &[u8]) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let b = bundle::decode(bytes).map_err(|e| JsValue::from_str(&e))?;
    // Re-encode the file sections as the `name|hex` interchange the vfs import surface expects.
    let mut file_lines = String::new();
    for (name, data) in &b.files {
        file_lines.push_str(name);
        file_lines.push('|');
        file_lines.push_str(&bytes_to_hex(data));
        file_lines.push('\n');
    }
    let util = vfs::install::<ffi::WasmOsCallback>(&demo_cfg("pk-import", true), true, &DUMMY_DEK)
        .await
        .map_err(|e| JsValue::from_str(&format!("install: {e:?}")))?;
    util.import_bundle(&file_lines)
        .map_err(|e| JsValue::from_str(&format!("import: {e:?}")))?;
    util.pause_vfs().map_err(|e| JsValue::from_str(&format!("pause: {e:?}")))?;
    let out = js_sys::Object::new();
    for (k, v) in [("envelope", &b.envelope), ("credId", &b.cred_id), ("epoch", &b.epoch)] {
        js_sys::Reflect::set(&out, &JsValue::from_str(k), &js_sys::Uint8Array::from(v.as_slice()))?;
    }
    Ok(out.into())
}

// ============================ generic SQL surface (SDK — schema-agnostic) ============================
// The @freehold/db SDK must not be bound to the demo schema: run arbitrary SQL against the same
// demo-path DB (demo_cfg/DEMO_DB) that enroll() creates. Rows come back as a JSON array of row
// arrays with every value stringified (NULL → null). JSON is built by hand — no serde in this
// crate by design (keep the dependency surface small and reviewable).

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
                    if !first_row {
                        out.push(',');
                    }
                    first_row = false;
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
                            json_escape_into(&mut out, &s);
                        }
                    }
                    out.push(']');
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

/// Shared body for run_sql/run_sql_recovery once the DEK is unwrapped: install on the demo path,
/// apply any peer epoch BEFORE opening (mirrors unlock), execute, return the JSON rows.
async fn sql_inner(dek: &[u8; 32], vfs_name: &str, epoch: &[u8], sql: &str) -> std::result::Result<String, String> {
    let util = vfs::install::<ffi::WasmOsCallback>(&demo_cfg(vfs_name, false), true, dek)
        .await
        .map_err(|e| format!("install: {e:?}"))?;
    if !epoch.is_empty() {
        util.apply_epoch(epoch).map_err(|e| format!("apply_epoch: {e:?}"))?;
    }
    let rows = unsafe {
        let db = open_default(DEMO_DB)
            .map_err(|e| format!("open rejected (rollback below a peer epoch, or wrong key): {e}"))?;
        set_pragmas(db)?;
        let res = query_json(db, sql);
        ffi::sqlite3_close(db);
        res?
    };
    util.pause_vfs().map_err(|e| format!("pause: {e:?}"))?;
    Ok(rows)
}

/// Run arbitrary SQL after a passkey-PRF unlock. Returns a JSON array of row arrays (stringified
/// values, NULL → null); statements that return no rows yield "[]".
#[wasm_bindgen]
pub async fn run_sql(prf: &[u8], blob: &[u8], epoch: &[u8], sql: &str) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    let dek = envelope::open_with_prf(blob, prf)
        .map_err(|_| JsValue::from_str("unlock failed — wrong passkey, wrong PRF/UV state, or tampered envelope"))?;
    sql_inner(&dek, "pk-sql", epoch, sql).await.map_err(|e| JsValue::from_str(&e))
}

/// Run arbitrary SQL after a recovery-code unlock (same semantics as `run_sql`).
#[wasm_bindgen]
pub async fn run_sql_recovery(code: &str, blob: &[u8], epoch: &[u8], sql: &str) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    let dek = envelope::open_with_recovery(blob, code)
        .map_err(|_| JsValue::from_str("recovery code did not unlock — wrong code or tampered envelope"))?;
    sql_inner(&dek, "pk-sql-rec", epoch, sql).await.map_err(|e| JsValue::from_str(&e))
}
