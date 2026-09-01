//! Freehold Sync — the ordering / conflict layer over the already-encrypted `.freehold` bundle.
//!
//! Scope (freehold-sync-design §7, §7.1, §10): this module is the **sync layer**, deliberately
//! separated from the security-critical anchor. Everything here is NON-security-critical metadata
//! carried *alongside* an image that is already an AEAD-sealed encrypted DB. The blind relay only
//! ever handles the sealed `Vec<u8>` blobs produced by [`SyncBlob::seal`] — it never inspects, orders
//! by, or interprets content.
//!
//! ## Why the version vector cannot weaken rollback protection (design §7.1)
//!
//! The proven scalar-`db_generation` epoch/anchor (crypto `epoch_key`, `apply_epoch`) is UNCHANGED
//! and still solely owns rollback *prevention* — it is confidentiality/integrity-critical and gated
//! by the DEK-authenticated AEAD token. The [`VersionVector`] here is pure sync-layer bookkeeping:
//! it decides *fast-forward vs. stale vs. fork* so the sync loop knows whether to apply, skip, or
//! flag a blob. If the version vector were ever wrong the worst case is a spurious fork (safe: both
//! images preserved) or a missed fork that LWW still converges — it can NEVER admit a stale image
//! that the anchor would reject, because import still passes through the anchor's freshness check.
//! In other words: the vv is an optimisation for *conflict classification*, not a security control.
//!
//! ## What travels
//!
//! A [`SyncBlob`] is `{ db_uuid, version_vector, image }` where `image` is the `.freehold` bundle
//! bytes (`bundle.rs` TLV) of the encrypted DB. `seal` wraps the whole thing under `sync_key` so the
//! relay stores ciphertext only; `open` authenticated-decodes it, bounds-checked, no panics on
//! hostile input (same bar as `bundle.rs`).

use crate::crypto::{Crypto, CryptoError};
use std::collections::BTreeMap;

/// AAD binding the sealed sync blob to this format/version (domain separation from every other
/// AEAD use of the DEK-derived keys).
const BLOB_AAD: &[u8] = b"freehold-sync-blob-v1";

// ============================ VersionVector ============================

/// A per-device commit counter map `device_id([u8;16]) → u64`. Ordered (`BTreeMap`) so the binary
/// encoding is deterministic across devices without an explicit sort step. Absent component == 0.
///
/// Deterministic binary encoding (used both on the wire inside a sealed blob AND as a tiebreak key
/// in fork resolution, so it MUST be stable):
/// ```text
///   entry_count : u32 LE
///   entries (sorted ascending by device_id):  device_id(16) | count(u64 LE)
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionVector {
    // BTreeMap keyed by device_id keeps entries sorted; we skip zero components on encode.
    counts: BTreeMap<[u8; 16], u64>,
}

/// The lattice relation between two version vectors (a partial order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// Identical in every component.
    Equal,
    /// `self` ≥ other in every component and > in at least one (self is strictly newer).
    Dominates,
    /// other ≥ self in every component and > in at least one (self is strictly older).
    DominatedBy,
    /// Neither dominates — the two lines diverged (a fork).
    Concurrent,
}

impl VersionVector {
    /// Empty vector (all components zero).
    pub fn new() -> Self {
        VersionVector { counts: BTreeMap::new() }
    }

    /// Read one component (absent == 0).
    pub fn get(&self, device_id: &[u8; 16]) -> u64 {
        self.counts.get(device_id).copied().unwrap_or(0)
    }

    /// Record one local commit by `device_id`: bump its counter by one.
    pub fn increment(&mut self, device_id: &[u8; 16]) {
        let c = self.counts.entry(*device_id).or_insert(0);
        *c = c.saturating_add(1);
    }

    /// Element-wise max with `other` — the merge applied on both sides after a fork is resolved so
    /// the fork does not re-trigger and both devices converge to the same vector (design §7.1).
    pub fn merge_max(&mut self, other: &VersionVector) {
        for (id, &c) in &other.counts {
            let e = self.counts.entry(*id).or_insert(0);
            if c > *e {
                *e = c;
            }
        }
    }

    /// Total of all components — used as the primary (deterministic) fork-winner key.
    pub fn total_count(&self) -> u64 {
        self.counts.values().fold(0u64, |a, &c| a.saturating_add(c))
    }

    /// The set of device-ids with a non-zero component, sorted ascending. Used as the SECOND fork
    /// tiebreak; `BTreeMap` iteration is already sorted.
    fn device_id_set(&self) -> Vec<[u8; 16]> {
        self.counts.iter().filter(|(_, &c)| c > 0).map(|(id, _)| *id).collect()
    }

    /// Classify the relation between `self` and `other` over the union of their device-ids.
    /// Dominates iff ≥ in every component and > in at least one; concurrent iff neither dominates.
    pub fn relation(&self, other: &VersionVector) -> Relation {
        let mut self_greater = false; // some component where self > other
        let mut other_greater = false; // some component where other > self
        // Union of keys: iterate both maps' keys.
        for id in self.counts.keys().chain(other.counts.keys()) {
            let a = self.get(id);
            let b = other.get(id);
            if a > b {
                self_greater = true;
            } else if b > a {
                other_greater = true;
            }
        }
        match (self_greater, other_greater) {
            (false, false) => Relation::Equal,
            (true, false) => Relation::Dominates,
            (false, true) => Relation::DominatedBy,
            (true, true) => Relation::Concurrent,
        }
    }

    /// Deterministic binary encoding (see type docs). Zero components are skipped so `{A:1}` and
    /// `{A:1,B:0}` encode identically — semantically equal vectors have equal bytes.
    pub fn encode(&self) -> Vec<u8> {
        let entries: Vec<(&[u8; 16], &u64)> =
            self.counts.iter().filter(|(_, &c)| c > 0).collect();
        let mut out = Vec::with_capacity(4 + entries.len() * 24);
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (id, &c) in entries {
            out.extend_from_slice(id.as_slice());
            out.extend_from_slice(&c.to_le_bytes());
        }
        out
    }

    /// Inverse of [`VersionVector::encode`], bounds-checked; hostile input Errs, never panics.
    /// Returns the number of bytes consumed alongside the vector (it is embedded in a larger blob).
    pub fn decode(bytes: &[u8], at: &mut usize) -> Result<VersionVector, String> {
        let n = take_u32(bytes, at)?;
        // Guard against a hostile length claiming millions of 24-byte entries we don't have.
        let need = n.checked_mul(24).ok_or("vv: length overflow")?;
        let end = at.checked_add(need).ok_or("vv: length overflow")?;
        if end > bytes.len() {
            return Err("vv: truncated entries".into());
        }
        let mut counts = BTreeMap::new();
        let mut prev: Option<[u8; 16]> = None;
        for _ in 0..n {
            let id_slice = take(bytes, at, 16)?;
            let mut id = [0u8; 16];
            id.copy_from_slice(id_slice);
            // Reject non-canonical encodings (unsorted / duplicate ids) — a well-formed encoder
            // always emits strictly ascending ids, so anything else is malformed or hostile.
            if let Some(p) = prev {
                if id <= p {
                    return Err("vv: entries not strictly ascending by device_id".into());
                }
            }
            prev = Some(id);
            let c_slice = take(bytes, at, 8)?;
            let count = u64::from_le_bytes(c_slice.try_into().unwrap());
            if count == 0 {
                return Err("vv: zero component must be omitted".into());
            }
            counts.insert(id, count);
        }
        Ok(VersionVector { counts })
    }
}

// ============================ SyncBlob ============================

/// The unit a device pushes to / pulls from the relay. `image` is the `.freehold` bundle bytes
/// (`bundle.rs`) of the encrypted DB — already ciphertext; the sync layer never sees plaintext.
///
/// Deterministic inner encoding (sealed under `sync_key`):
/// ```text
///   db_uuid(16) | version_vector(encode) | image_len(u32 LE) | image
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncBlob {
    pub db_uuid: [u8; 16],
    pub vv: VersionVector,
    pub image: Vec<u8>,
}

impl SyncBlob {
    fn encode_inner(&self) -> Vec<u8> {
        let vv = self.vv.encode();
        let mut out = Vec::with_capacity(16 + vv.len() + 4 + self.image.len());
        out.extend_from_slice(&self.db_uuid);
        out.extend_from_slice(&vv);
        out.extend_from_slice(&(self.image.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.image);
        out
    }

    /// AEAD-seal a deterministic encoding under `sync_key` (`aad = BLOB_AAD`). The relay stores only
    /// the returned bytes — it cannot read `db_uuid`, the vector, or the image without the DEK.
    pub fn seal(&self, sync: &Crypto) -> Result<Vec<u8>, CryptoError> {
        sync.seal_bytes(BLOB_AAD, &self.encode_inner())
    }

    /// Authenticated decode of a sealed blob. Wrong key / tamper → Err (via AEAD); malformed inner
    /// bytes → Err (bounds-checked). Never panics on hostile input (same bar as `bundle.rs`).
    pub fn open(sealed: &[u8], sync: &Crypto) -> Result<SyncBlob, String> {
        let inner = sync
            .open_bytes(BLOB_AAD, sealed)
            .map_err(|_| "sync blob: AEAD open failed (wrong key or tampered)".to_string())?;
        let mut at = 0usize;
        let mut db_uuid = [0u8; 16];
        db_uuid.copy_from_slice(take(&inner, &mut at, 16)?);
        let vv = VersionVector::decode(&inner, &mut at)?;
        let ilen = take_u32(&inner, &mut at)?;
        let image = take(&inner, &mut at, ilen)?.to_vec();
        if at != inner.len() {
            return Err("sync blob: trailing bytes".into());
        }
        Ok(SyncBlob { db_uuid, vv, image })
    }
}

// ============================ reconcile ============================

/// The outcome of reconciling an incoming blob's vector against local state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Incoming strictly newer (dominates) — apply it, advance local vv.
    FastForward,
    /// Incoming older-or-equal (dominated / equal) — reject, keep local.
    Stale,
    /// Concurrent — a fork. `winner_is_incoming` says which image becomes live; both preserved.
    Fork { winner_is_incoming: bool },
}

/// Reconcile an incoming vector against the local vector (design §7 / §7.1):
///   * incoming Dominates local            → FastForward
///   * incoming Equal or DominatedBy local → Stale (Equal is a no-op; incoming carries nothing new)
///   * Concurrent                          → Fork, winner chosen deterministically (see below)
pub fn reconcile(local_vv: &VersionVector, incoming_vv: &VersionVector) -> MergeOutcome {
    match incoming_vv.relation(local_vv) {
        Relation::Dominates => MergeOutcome::FastForward,
        Relation::Equal | Relation::DominatedBy => MergeOutcome::Stale,
        Relation::Concurrent => MergeOutcome::Fork {
            winner_is_incoming: incoming_wins(local_vv, incoming_vv),
        },
    }
}

/// Deterministic fork-winner rule — a PURE FUNCTION of the two vectors, so both devices independently
/// compute the SAME winner with no coordination (design §7.1). Total order, compared in sequence:
///
///   1. **total_count descending** — the vector that represents more commits wins (more work done).
///   2. **device-id-set lexicographic ascending** — the sorted list of participating device-ids,
///      compared element-by-element; the lexicographically-smaller set wins. (Deterministic, and
///      independent of wall clock — no lying-clock dependence, unlike the design's `stamp` tiebreak
///      which is explicitly not used in this self-contained proof.)
///   3. **full vv encoding bytes ascending** — the canonical `encode()` bytes as a final total
///      tiebreak; two distinct vectors that tie on (1) and (2) still get a stable, agreed order.
///
/// Returns `true` iff the INCOMING vector wins. Because the comparison is symmetric in its two
/// arguments (it computes an order over {local, incoming}), `reconcile(x,y)` and `reconcile(y,x)`
/// select the SAME actual vector as winner — only `winner_is_incoming` flips.
fn incoming_wins(local_vv: &VersionVector, incoming_vv: &VersionVector) -> bool {
    // Compare INCOMING vs LOCAL under the total order; `true` means incoming ranks first (wins).
    // 1) total_count desc → larger total wins.
    let (lt, it) = (local_vv.total_count(), incoming_vv.total_count());
    if it != lt {
        return it > lt;
    }
    // 2) device-id-set lexicographic asc → smaller set wins.
    let (ls, is) = (local_vv.device_id_set(), incoming_vv.device_id_set());
    if is != ls {
        return is < ls;
    }
    // 3) full encoding bytes asc → smaller bytes win.
    incoming_vv.encode() < local_vv.encode()
}

// ============================ InMemoryRelay (blind mock) ============================

/// The blind relay mock (design §5): a per-`sync_id` append-only log of sealed blobs. It ONLY ever
/// stores/serves `Vec<u8>` — it has no way to inspect blob contents, enforcing the "content-opaque"
/// contract by construction. `list(sync_id, since)` returns the current count (new blobs are
/// everything at index ≥ `since`); `get(sync_id, seq)` fetches one by its arrival index.
#[cfg(feature = "testing-api")]
#[derive(Default)]
pub struct InMemoryRelay {
    logs: std::collections::HashMap<[u8; 16], Vec<Vec<u8>>>,
}

#[cfg(feature = "testing-api")]
impl InMemoryRelay {
    pub fn new() -> Self {
        InMemoryRelay { logs: std::collections::HashMap::new() }
    }

    /// Append a sealed blob to `sync_id`'s log; returns its arrival index (monotonic pull cursor).
    pub fn put(&mut self, sync_id: [u8; 16], sealed: Vec<u8>) -> usize {
        let log = self.logs.entry(sync_id).or_default();
        log.push(sealed);
        log.len() - 1
    }

    /// Total number of blobs currently in `sync_id`'s log. A client with cursor `since` has
    /// `list(..) - since` new blobs to pull (indices `since..list(..)`).
    pub fn list(&self, sync_id: &[u8; 16], since: usize) -> usize {
        let len = self.logs.get(sync_id).map(|l| l.len()).unwrap_or(0);
        len.saturating_sub(since)
    }

    /// Fetch one sealed blob by its arrival index.
    pub fn get(&self, sync_id: &[u8; 16], seq: usize) -> Option<Vec<u8>> {
        self.logs.get(sync_id).and_then(|l| l.get(seq).cloned())
    }
}

// ============================ bounds-checked cursor reads ============================
// Same idiom as bundle.rs — malformed input must Err, never panic / slice out of range.

fn take<'a>(b: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = at.checked_add(n).ok_or_else(|| "sync: length overflow".to_string())?;
    if end > b.len() {
        return Err("sync: truncated section".into());
    }
    let s = &b[*at..end];
    *at = end;
    Ok(s)
}

fn take_u32(b: &[u8], at: &mut usize) -> Result<usize, String> {
    let s = take(b, at, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
}

// ============================ self-contained unit-style checks ============================
// Callable from run_tests() (SY section) — asserts VersionVector.relation over the four cases and
// reconcile determinism (arg-order independence of the actual winner). Returns Err on any miss.

#[cfg(feature = "testing-api")]
pub fn self_check() -> Result<(), String> {
    let a = [0xa1u8; 16];
    let b = [0xb2u8; 16];

    // relation: equal
    let mut x = VersionVector::new();
    x.increment(&a);
    let mut y = VersionVector::new();
    y.increment(&a);
    if x.relation(&y) != Relation::Equal {
        return Err("relation: {A:1} vs {A:1} should be Equal".into());
    }
    // relation: dominates / dominated
    y.increment(&a); // y = {A:2}
    if y.relation(&x) != Relation::Dominates {
        return Err("relation: {A:2} vs {A:1} should be Dominates".into());
    }
    if x.relation(&y) != Relation::DominatedBy {
        return Err("relation: {A:1} vs {A:2} should be DominatedBy".into());
    }
    // relation: concurrent  {A:2} vs {A:1,B:1}
    let mut z = VersionVector::new();
    z.increment(&a);
    z.increment(&b);
    if y.relation(&z) != Relation::Concurrent {
        return Err("relation: {A:2} vs {A:1,B:1} should be Concurrent".into());
    }

    // reconcile determinism: winner is the SAME actual vector regardless of arg order.
    let out_fwd = reconcile(&y, &z); // local=y, incoming=z
    let out_rev = reconcile(&z, &y); // local=z, incoming=y
    let (f, rvs) = match (out_fwd, out_rev) {
        (MergeOutcome::Fork { winner_is_incoming: f }, MergeOutcome::Fork { winner_is_incoming: r }) => (f, r),
        _ => return Err("reconcile: concurrent pair must be Fork on both orderings".into()),
    };
    // winner_is_incoming must flip between the two orderings...
    if f == rvs {
        return Err("reconcile: winner_is_incoming must differ when args are swapped".into());
    }
    // ...and resolve to the SAME actual vector. In (local=y, incoming=z): winner = z iff f.
    let winner_fwd = if f { &z } else { &y };
    let winner_rev = if rvs { &y } else { &z };
    if winner_fwd != winner_rev {
        return Err("reconcile: the two orderings selected different actual winners (non-deterministic)".into());
    }

    // encode/decode round-trip of the version vector.
    let enc = z.encode();
    let mut at = 0usize;
    let dec = VersionVector::decode(&enc, &mut at)?;
    if dec != z || at != enc.len() {
        return Err("vv encode/decode round-trip mismatch".into());
    }
    Ok(())
}
