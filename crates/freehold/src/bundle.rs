//! Binary TLV container for cross-device export/import — and, by design, the future Freehold
//! Sync wire format. Replaces the JSON+hex bundle (2x size, string churn) with length-prefixed
//! binary sections. Everything inside is either public metadata (cred_id, file names) or
//! ciphertext/AEAD-authenticated data (envelope, encrypted files, epoch token) — the container
//! itself needs no integrity layer of its own; tampering surfaces as an AEAD failure downstream.
//!
//! ```text
//!  bundle  = magic "FREEHOLD"(8) | version(1)=1 | section*   (sections until EOF)
//!  section = tag(1) | payload
//!    tag 1  envelope     u32-LE len | bytes          (N-KEK envelope blob — envelope.rs)
//!    tag 2  cred_id      u32-LE len | bytes          (WebAuthn credential id; optional)
//!    tag 3  file         u16-LE name_len | utf8 name | u32-LE data_len | bytes  (ciphertext)
//!    tag 4  epoch_token  u32-LE len | bytes          (sync-epoch freshness token; optional)
//! ```
//!
//! The bundle owns the bare b"FREEHOLD" magic (it's the user-facing .freehold file); the envelope
//! header uses b"FREEHENV", so the two formats' version namespaces evolve independently. Unknown
//! tags are a hard error, not a skip: a new section kind means a new format version, and silently
//! dropping sections a peer thought it sent is how sync protocols rot.

const MAGIC: &[u8; 8] = b"FREEHOLD";
const VERSION: u8 = 1;

const TAG_ENVELOPE: u8 = 1;
const TAG_CRED_ID: u8 = 2;
const TAG_FILE: u8 = 3;
const TAG_EPOCH: u8 = 4;

/// Decoded bundle. Empty `cred_id`/`epoch` mean the section was absent (both are optional on the
/// wire; `encode` skips them when empty, so absent and empty are deliberately the same thing).
pub struct Bundle {
    pub envelope: Vec<u8>,
    pub cred_id: Vec<u8>,
    pub files: Vec<(String, Vec<u8>)>,
    pub epoch: Vec<u8>,
}

/// Serialize a bundle. Sections are written in tag order (envelope, cred_id, files, epoch) but
/// `decode` accepts any order — order is an encoder convention, not a format requirement.
pub fn encode(envelope: &[u8], cred_id: &[u8], files: &[(String, Vec<u8>)], epoch: &[u8]) -> Vec<u8> {
    let payload: usize = files.iter().map(|(n, d)| 1 + 2 + n.len() + 4 + d.len()).sum();
    let mut out = Vec::with_capacity(9 + 5 + envelope.len() + 5 + cred_id.len() + payload + 5 + epoch.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(TAG_ENVELOPE);
    out.extend_from_slice(&(envelope.len() as u32).to_le_bytes());
    out.extend_from_slice(envelope);
    if !cred_id.is_empty() {
        out.push(TAG_CRED_ID);
        out.extend_from_slice(&(cred_id.len() as u32).to_le_bytes());
        out.extend_from_slice(cred_id);
    }
    for (name, data) in files {
        // Pool filenames are short ("app.db#manifest"-sized); a >64 KiB name is a caller bug.
        debug_assert!(name.len() <= u16::MAX as usize, "bundle: file name too long");
        out.push(TAG_FILE);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    if !epoch.is_empty() {
        out.push(TAG_EPOCH);
        out.extend_from_slice(&(epoch.len() as u32).to_le_bytes());
        out.extend_from_slice(epoch);
    }
    out
}

// Bounds-checked cursor reads — malformed input must Err, never panic/slice out of range.
fn take<'a>(b: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = at.checked_add(n).ok_or_else(|| "bundle: length overflow".to_string())?;
    if end > b.len() {
        return Err("bundle: truncated section".into());
    }
    let s = &b[*at..end];
    *at = end;
    Ok(s)
}
fn take_u16(b: &[u8], at: &mut usize) -> Result<usize, String> {
    let s = take(b, at, 2)?;
    Ok(u16::from_le_bytes([s[0], s[1]]) as usize)
}
fn take_u32(b: &[u8], at: &mut usize) -> Result<usize, String> {
    let s = take(b, at, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
}

/// Strict parse: magic + version checked, every length bounds-checked, unknown tags rejected.
pub fn decode(bytes: &[u8]) -> Result<Bundle, String> {
    if bytes.len() < 9 || &bytes[..8] != MAGIC.as_slice() {
        return Err("bundle: bad magic — not a freehold bundle".into());
    }
    if bytes[8] != VERSION {
        return Err(format!("bundle: unsupported version {} (expected {VERSION})", bytes[8]));
    }
    let mut b = Bundle { envelope: Vec::new(), cred_id: Vec::new(), files: Vec::new(), epoch: Vec::new() };
    let mut have_envelope = false;
    let mut at = 9usize;
    while at < bytes.len() {
        let tag = bytes[at];
        at += 1;
        match tag {
            TAG_ENVELOPE => {
                let n = take_u32(bytes, &mut at)?;
                b.envelope = take(bytes, &mut at, n)?.to_vec();
                have_envelope = true;
            }
            TAG_CRED_ID => {
                let n = take_u32(bytes, &mut at)?;
                b.cred_id = take(bytes, &mut at, n)?.to_vec();
            }
            TAG_FILE => {
                let nlen = take_u16(bytes, &mut at)?;
                let name = String::from_utf8(take(bytes, &mut at, nlen)?.to_vec())
                    .map_err(|_| "bundle: file name is not UTF-8".to_string())?;
                let dlen = take_u32(bytes, &mut at)?;
                b.files.push((name, take(bytes, &mut at, dlen)?.to_vec()));
            }
            TAG_EPOCH => {
                let n = take_u32(bytes, &mut at)?;
                b.epoch = take(bytes, &mut at, n)?.to_vec();
            }
            t => return Err(format!("bundle: unknown section tag {t} — newer format? (version bump territory)")),
        }
    }
    if !have_envelope {
        return Err("bundle: no envelope section".into());
    }
    Ok(b)
}
