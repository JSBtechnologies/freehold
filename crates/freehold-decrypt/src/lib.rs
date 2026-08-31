//! Standalone `.freehold` decryptor — self-custody / portability proof (issue #6).
//!
//! Given a `.freehold` bundle and the **recovery code**, this reconstructs the plaintext SQLite
//! image of every database inside it, using ONLY audited RustCrypto primitives — no Freehold VFS,
//! no SQLite, no wasm. It is the executable promise behind "your data is yours": if every Freehold
//! device and this project vanished, ~350 lines + five public crates recover your database.
//!
//! It re-implements the read side of three on-disk formats (all normatively described in
//! `docs/bundle-format.md`), deliberately duplicating — never importing — the main crate, so the
//! tool has an independent trust surface:
//!
//! 1. **Bundle** (`bundle.rs`): `magic "FREEHOLD"(8) | version(1)=1 | section*`, TLV sections.
//! 2. **Envelope v3** (`envelope.rs`): `header(36) | slot(74)* | mac(32)`; a recovery slot wraps the
//!    256-bit DEK under `KEK = Argon2id(normalized_code, salt=env_salt)`.
//! 3. **Encrypted block device** (`crypto.rs`): each DB file is a grid of `P = 4096+24+16` byte
//!    physical blocks `ct(4096) | nonce(24) | tag(16)`, sealed with `K_db = HKDF(DEK,
//!    "freehold/vfs-db-v1\0" ‖ db_uuid)` and AAD `file_id(16) | db_uuid(16) | block_index_LE(8) |
//!    4096_LE(4) | cipher_id(1)`. `db_uuid` is read from the manifest file's plaintext header.

use argon2::Argon2;
use chacha20poly1305::{aead::AeadInPlace, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// ---- format constants (mirror of bundle.rs / envelope.rs / crypto.rs) ----
const BUNDLE_MAGIC: &[u8; 8] = b"FREEHOLD";
const BUNDLE_VERSION: u8 = 1;
const TAG_ENVELOPE: u8 = 1;
const TAG_CRED_ID: u8 = 2;
const TAG_FILE: u8 = 3;
const TAG_EPOCH: u8 = 4;

const ENV_MAGIC: &[u8; 8] = b"FREEHENV";
const ENV_VERSION: u8 = 3;
const ENV_HEADER_LEN: usize = 36;
const ENV_SLOT_LEN: usize = 74;
const ENV_MAC_LEN: usize = 32;
const ENV_SALT_OFF: usize = 12;
const ENV_SALT_LEN: usize = 16;
const DEK_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KIND_RECOVERY: u8 = 1;
const WRAP_AAD_PREFIX: &[u8] = b"freehold-envelope-v3";
const MAC_INFO: &[u8] = b"freehold-envelope-mac-v1";

const BLOCK_SIZE: usize = 4096;
const PHYS_BLOCK: usize = BLOCK_SIZE + NONCE_LEN + TAG_LEN; // 4136
const CIPHER_ID: u8 = 1;
const FILE_ID_LEN: usize = 16;
const DB_KEY_LABEL: &[u8] = b"freehold/vfs-db-v1\0"; // 19 bytes incl. the trailing NUL
const MANIFEST_SUFFIX: &str = "#manifest";
const MANIFEST_MAGIC_LEN: usize = 8; // db_uuid lives at manifest bytes [8..24]

#[derive(Debug)]
pub enum Error {
    Bundle(&'static str),
    Envelope(&'static str),
    /// The recovery code opened no slot — wrong code, or a bundle with no recovery method.
    Unlock,
    /// A slot opened but the envelope-wide MAC failed to verify under the recovered DEK (tampered).
    Tamper,
    /// A DB file's block failed to authenticate (wrong key or corrupted image).
    Block(String),
    Kdf,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Bundle(m) => write!(f, "bundle: {m}"),
            Error::Envelope(m) => write!(f, "envelope: {m}"),
            Error::Unlock => write!(
                f,
                "recovery code opened no slot — wrong code, or this bundle has no recovery method"
            ),
            Error::Tamper => write!(f, "envelope MAC failed under the recovered key — tampered bundle"),
            Error::Block(n) => write!(f, "decrypt failed for {n}: wrong key or corrupted image"),
            Error::Kdf => write!(f, "Argon2id key derivation failed"),
        }
    }
}
impl std::error::Error for Error {}

/// One recovered database: its logical name (e.g. `app.db`) and the plaintext SQLite image.
#[derive(Debug)]
pub struct RecoveredDb {
    pub name: String,
    pub sqlite: Vec<u8>,
}

struct Bundle {
    envelope: Vec<u8>,
    files: Vec<(String, Vec<u8>)>,
}

// ---- bounds-checked cursor ----
fn take<'a>(b: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], Error> {
    let end = at.checked_add(n).ok_or(Error::Bundle("length overflow"))?;
    if end > b.len() {
        return Err(Error::Bundle("truncated section"));
    }
    let s = &b[*at..end];
    *at = end;
    Ok(s)
}
fn le_u16(b: &[u8]) -> usize {
    u16::from_le_bytes([b[0], b[1]]) as usize
}
fn le_u32(b: &[u8]) -> usize {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
}

fn parse_bundle(bytes: &[u8]) -> Result<Bundle, Error> {
    if bytes.len() < 9 || &bytes[..8] != BUNDLE_MAGIC.as_slice() {
        return Err(Error::Bundle("bad magic — not a .freehold bundle"));
    }
    if bytes[8] != BUNDLE_VERSION {
        return Err(Error::Bundle("unsupported bundle version"));
    }
    let mut envelope = Vec::new();
    let mut files = Vec::new();
    let mut at = 9usize;
    while at < bytes.len() {
        let tag = bytes[at];
        at += 1;
        match tag {
            TAG_ENVELOPE => {
                let n = le_u32(take(bytes, &mut at, 4)?);
                envelope = take(bytes, &mut at, n)?.to_vec();
            }
            TAG_CRED_ID => {
                let n = le_u32(take(bytes, &mut at, 4)?);
                let _ = take(bytes, &mut at, n)?; // public metadata, unused for decryption
            }
            TAG_FILE => {
                let nlen = le_u16(take(bytes, &mut at, 2)?);
                let name = std::str::from_utf8(take(bytes, &mut at, nlen)?)
                    .map_err(|_| Error::Bundle("file name not UTF-8"))?
                    .to_string();
                let dlen = le_u32(take(bytes, &mut at, 4)?);
                files.push((name, take(bytes, &mut at, dlen)?.to_vec()));
            }
            TAG_EPOCH => {
                let n = le_u32(take(bytes, &mut at, 4)?);
                let _ = take(bytes, &mut at, n)?; // freshness token, irrelevant to decryption
            }
            _ => return Err(Error::Bundle("unknown section tag")),
        }
    }
    if envelope.is_empty() {
        return Err(Error::Bundle("no envelope section"));
    }
    Ok(Bundle { envelope, files })
}

/// Recover the 256-bit DEK from the envelope using the recovery code (the only device-independent
/// method — a passkey's PRF cannot be reproduced off its authenticator, by design). Tries the code's
/// Argon2id KEK against every recovery slot, then verifies the envelope-wide MAC under the DEK.
fn open_envelope(envelope: &[u8], recovery_code: &str) -> Result<Zeroizing<[u8; DEK_LEN]>, Error> {
    if envelope.len() < ENV_HEADER_LEN + ENV_MAC_LEN
        || &envelope[..8] != ENV_MAGIC.as_slice()
        || envelope[8] != ENV_VERSION
    {
        return Err(Error::Envelope("bad magic/version"));
    }
    let slot_count = envelope[9] as usize;
    let body_len = ENV_HEADER_LEN + slot_count * ENV_SLOT_LEN;
    if envelope.len() != body_len + ENV_MAC_LEN {
        return Err(Error::Envelope("length mismatch"));
    }
    let salt = &envelope[ENV_SALT_OFF..ENV_SALT_OFF + ENV_SALT_LEN];

    // KEK = Argon2id(normalized code, env_salt). Normalization matches envelope.rs: drop all
    // whitespace, upper-case (so transcription differences don't change the key). The Argon2id params
    // are PINNED to the exact same explicit values envelope.rs uses (m=19456 KiB, t=2, p=1, out=32) —
    // never `Argon2::default()`, whose values could drift across crate versions — so this tool
    // reproduces the runtime's KEK bit-for-bit regardless of the installed argon2 version.
    let norm = recovery_code.split_whitespace().collect::<String>().to_uppercase();
    let mut kek = Zeroizing::new([0u8; 32]);
    let params = argon2::Params::new(19_456, 2, 1, Some(32)).map_err(|_| Error::Kdf)?;
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(norm.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|_| Error::Kdf)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_slice()));

    for i in 0..slot_count {
        let at = ENV_HEADER_LEN + i * ENV_SLOT_LEN;
        let kek_id = envelope[at];
        let kind = envelope[at + 1];
        if kind != KIND_RECOVERY {
            continue; // only a recovery slot can open with a recovery code (AAD binds `kind`)
        }
        let nonce = &envelope[at + 2..at + 2 + NONCE_LEN];
        let ct = &envelope[at + 2 + NONCE_LEN..at + 2 + NONCE_LEN + DEK_LEN];
        let tag = &envelope[at + 2 + NONCE_LEN + DEK_LEN..at + ENV_SLOT_LEN];
        let mut aad = WRAP_AAD_PREFIX.to_vec();
        aad.push(kek_id);
        aad.push(kind);
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        dek.copy_from_slice(ct);
        if cipher
            .decrypt_in_place_detached(XNonce::from_slice(nonce), &aad, dek.as_mut_slice(), Tag::from_slice(tag))
            .is_ok()
        {
            // Verify the envelope-wide MAC under the recovered DEK — same tamper check the runtime does.
            let mut mac_key = Zeroizing::new([0u8; 32]);
            Hkdf::<Sha256>::new(None, dek.as_slice())
                .expand(MAC_INFO, mac_key.as_mut_slice())
                .expect("HKDF expand of 32 bytes never fails");
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key.as_slice()).expect("HMAC any key len");
            mac.update(&envelope[..body_len]);
            if mac.verify_slice(&envelope[body_len..body_len + ENV_MAC_LEN]).is_err() {
                return Err(Error::Tamper);
            }
            return Ok(dek);
        }
    }
    Err(Error::Unlock)
}

fn file_id_for(name: &str) -> [u8; FILE_ID_LEN] {
    let d = Sha256::digest(name.as_bytes());
    let mut id = [0u8; FILE_ID_LEN];
    id.copy_from_slice(&d[..FILE_ID_LEN]);
    id
}

fn db_cipher(dek: &[u8; DEK_LEN], db_uuid: &[u8; 16]) -> XChaCha20Poly1305 {
    let mut info = Vec::with_capacity(DB_KEY_LABEL.len() + 16);
    info.extend_from_slice(DB_KEY_LABEL);
    info.extend_from_slice(db_uuid);
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, dek)
        .expand(&info, k.as_mut_slice())
        .expect("HKDF expand of 32 bytes never fails");
    XChaCha20Poly1305::new(Key::from_slice(k.as_slice()))
}

// Per-block AAD: file_id(16) | db_uuid(16) | block_index_LE(8) | BLOCK_SIZE_LE(4) | cipher_id(1).
fn block_aad(file_id: &[u8; 16], db_uuid: &[u8; 16], block_index: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(16 + 16 + 8 + 4 + 1);
    a.extend_from_slice(file_id);
    a.extend_from_slice(db_uuid);
    a.extend_from_slice(&block_index.to_le_bytes());
    a.extend_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
    a.push(CIPHER_ID);
    a
}

/// Decrypt one DB file's ciphertext (a whole `export_raw` data region) into its plaintext SQLite
/// image: a uniform grid of `PHYS_BLOCK` blocks, block_index = physical block position.
fn decrypt_db_file(
    name: &str,
    ciphertext: &[u8],
    dek: &[u8; DEK_LEN],
    db_uuid: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() % PHYS_BLOCK != 0 {
        return Err(Error::Block(format!("{name}: not a whole number of {PHYS_BLOCK}-byte blocks")));
    }
    let cipher = db_cipher(dek, db_uuid);
    let file_id = file_id_for(name);
    let nblocks = ciphertext.len() / PHYS_BLOCK;
    let mut out = vec![0u8; nblocks * BLOCK_SIZE];
    for k in 0..nblocks {
        let phys = &ciphertext[k * PHYS_BLOCK..(k + 1) * PHYS_BLOCK];
        let nonce = &phys[BLOCK_SIZE..BLOCK_SIZE + NONCE_LEN];
        let tag = &phys[BLOCK_SIZE + NONCE_LEN..];
        let dst = &mut out[k * BLOCK_SIZE..(k + 1) * BLOCK_SIZE];
        dst.copy_from_slice(&phys[..BLOCK_SIZE]);
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce),
                &block_aad(&file_id, db_uuid, k as u64),
                dst,
                Tag::from_slice(tag),
            )
            .map_err(|_| Error::Block(format!("{name} block {k}")))?;
    }
    Ok(out)
}

/// Recover every database in a `.freehold` bundle to its plaintext SQLite image, using the recovery
/// code. The returned images are byte-identical to what the source device stored (the DB `db_uuid`
/// and every plaintext byte are unchanged by encryption). Manifest/anchor files are internal and are
/// NOT returned — only the SQLite databases you can open directly with any `sqlite3`.
pub fn recover(bundle_bytes: &[u8], recovery_code: &str) -> Result<Vec<RecoveredDb>, Error> {
    let bundle = parse_bundle(bundle_bytes)?;
    let dek = open_envelope(&bundle.envelope, recovery_code)?;

    let mut out = Vec::new();
    for (name, data) in &bundle.files {
        // A database file is `<x>.db`; its `<x>.db#manifest` sibling carries the plaintext db_uuid.
        if !name.ends_with(".db") {
            continue;
        }
        let mname = format!("{name}{MANIFEST_SUFFIX}");
        let manifest = bundle
            .files
            .iter()
            .find(|(n, _)| n == &mname)
            .ok_or(Error::Envelope("missing manifest for a DB file"))?;
        if manifest.1.len() < MANIFEST_MAGIC_LEN + 16 {
            return Err(Error::Envelope("manifest too short for a db_uuid"));
        }
        let mut db_uuid = [0u8; 16];
        db_uuid.copy_from_slice(&manifest.1[MANIFEST_MAGIC_LEN..MANIFEST_MAGIC_LEN + 16]);
        let sqlite = decrypt_db_file(name, data, &dek, &db_uuid)?;
        out.push(RecoveredDb { name: name.clone(), sqlite });
    }
    if out.is_empty() {
        return Err(Error::Bundle("no database files in bundle"));
    }
    Ok(out)
}

/// The 16-byte SQLite file magic (`"SQLite format 3\0"`) — a decrypted image must start with this.
pub const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

#[cfg(test)]
mod tests {
    use super::*;

    // GOLDEN fixture: a REAL bundle exported by the full browser stack (SDK -> worker -> wasm) via
    // tests/decrypt-fixture.spec.js. Decrypting it here proves format fidelity end-to-end with a
    // trust surface (this crate) fully independent of the runtime that wrote it. Regenerate the
    // fixture with `FH_GEN_FIXTURE=1 npx playwright test decrypt-fixture` (code/row are fixed below).
    const GOLDEN: &[u8] = include_bytes!("../tests/fixtures/golden.freehold");
    const CODE: &str = "FREEHOLD-DECRYPT-SELF-CUSTODY-01";
    const ROW: &str = "self-custody-proof";

    #[test]
    fn recovers_real_bundle_to_plaintext_sqlite() {
        let dbs = recover(GOLDEN, CODE).expect("recover with the correct code");
        let app = dbs.iter().find(|d| d.name == "app.db").expect("app.db present");
        // (1) A genuine SQLite image — starts with the file magic.
        assert!(app.sqlite.starts_with(SQLITE_MAGIC), "recovered image is not a SQLite file");
        // (2) The size is a whole number of 4096-byte pages (the block grid decrypted cleanly).
        assert_eq!(app.sqlite.len() % BLOCK_SIZE, 0);
        // (3) The actual row content came back — real data, not just a valid header.
        let needle = ROW.as_bytes();
        assert!(
            app.sqlite.windows(needle.len()).any(|w| w == needle),
            "recovered image does not contain the known row {ROW:?}"
        );
    }

    #[test]
    fn wrong_recovery_code_is_refused() {
        match recover(GOLDEN, "WRONG-CODE-NOPE-00") {
            Err(Error::Unlock) => {}
            other => panic!("wrong code must fail with Unlock, got {other:?}"),
        }
    }

    #[test]
    fn code_normalization_matches_runtime() {
        // Same code, mixed-case with stray surrounding whitespace (as a human might paste it). The
        // runtime normalizes by stripping whitespace + upper-casing (hyphens are significant), so this
        // must still open — proving our normalization matches.
        let spaced = "  FreeHold-Decrypt-Self-Custody-01  ";
        let dbs = recover(GOLDEN, spaced).expect("normalized (case/whitespace) code opens");
        assert!(dbs.iter().any(|d| d.name == "app.db"));
    }

    #[test]
    fn tampered_bundle_magic_is_rejected() {
        let mut bad = GOLDEN.to_vec();
        bad[0] ^= 0xff;
        assert!(matches!(recover(&bad, CODE), Err(Error::Bundle(_))));
    }
}
