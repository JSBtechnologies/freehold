//! `freehold-decrypt` — recover the plaintext SQLite databases from a `.freehold` bundle using the
//! recovery code, with no Freehold/SQLite runtime. See `docs/bundle-format.md`.
//!
//! Usage:
//!   freehold-decrypt <bundle.freehold> <recovery-code> [out-dir]
//!
//! Writes one `<name>.sqlite` per database into `out-dir` (default: the current directory). Open the
//! result with any `sqlite3`. The recovery code may be quoted with its spaces/case as displayed — it
//! is normalized (whitespace stripped, upper-cased) exactly as the runtime does.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!("usage: freehold-decrypt <bundle.freehold> <recovery-code> [out-dir]");
        return ExitCode::from(2);
    }
    let bundle_path = &args[1];
    let recovery_code = &args[2];
    let out_dir = PathBuf::from(args.get(3).map(String::as_str).unwrap_or("."));

    let bytes = match std::fs::read(bundle_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {bundle_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Advisory only: warn on a likely-mistyped generated code, but still attempt (a custom code has
    // no checksum yet is a valid key — never gate decryption on this).
    if !freehold_decrypt::verify_recovery_checksum(recovery_code) {
        eprintln!("note: recovery code checksum did not match (a typo, or a custom code) — trying anyway");
    }

    let dbs = match freehold_decrypt::recover(&bytes, recovery_code) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("error: cannot create {}: {e}", out_dir.display());
        return ExitCode::FAILURE;
    }

    for db in &dbs {
        // `app.db` -> `app.sqlite`; keep it obvious these are ordinary SQLite files now.
        let stem = db.name.strip_suffix(".db").unwrap_or(&db.name);
        let path = out_dir.join(format!("{stem}.sqlite"));
        let ok_magic = db.sqlite.len() >= freehold_decrypt::SQLITE_MAGIC.len()
            && &db.sqlite[..freehold_decrypt::SQLITE_MAGIC.len()] == freehold_decrypt::SQLITE_MAGIC;
        if let Err(e) = std::fs::write(&path, &db.sqlite) {
            eprintln!("error: cannot write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!(
            "recovered {} -> {} ({} bytes){}",
            db.name,
            path.display(),
            db.sqlite.len(),
            if ok_magic { "" } else { "  [WARNING: not a SQLite header — wrong code?]" }
        );
    }
    ExitCode::SUCCESS
}
