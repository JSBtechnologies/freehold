// @freehold/db — InMemoryRelay: the reference blind-relay implementation for local / same-machine
// sync and for tests (freehold-sync-design §10 item 1, freehold-relay-auth §2). It is a direct JS
// twin of the proven Rust `InMemoryRelay` (crates/freehold/src/sync.rs): a per-`sync_id` append-only
// log of sealed blobs. It ONLY ever stores/serves opaque bytes — it cannot read blob contents, which
// is the "blind by construction" contract. No auth: a single in-process trust domain (tabs+workers,
// VMs/processes on one host through a shared instance). Network sync + auth is the HttpRelay adapter.
//
// The BlindRelay contract (any transport implements exactly this):
//   put(syncId: Uint8Array, sealed: Uint8Array): Promise<number>   // → arrival index (seq)
//   list(syncId: Uint8Array, since: number):     Promise<number>   // → count of blobs at seq ≥ since
//   get(syncId: Uint8Array, seq: number):        Promise<Uint8Array|null>
//
// `syncId` is opaque bytes; we key the log by its hex string. Blobs are copied in/out so a caller
// mutating its buffer can never corrupt stored state.

const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

export class InMemoryRelay {
  #logs = new Map(); // syncId(hex) → Array<Uint8Array>

  #log(syncId) {
    const k = hex(syncId instanceof Uint8Array ? syncId : new Uint8Array(syncId));
    let l = this.#logs.get(k);
    if (!l) { l = []; this.#logs.set(k, l); }
    return l;
  }

  /** Append a sealed blob; resolves to its arrival index (the monotonic pull cursor position). */
  async put(syncId, sealed) {
    const u8 = sealed instanceof Uint8Array ? sealed : new Uint8Array(sealed);
    const log = this.#log(syncId);
    log.push(u8.slice()); // copy — never retain the caller's buffer
    return log.length - 1;
  }

  /** Count of blobs at index ≥ `since` (i.e. how many are new for a client with cursor `since`). */
  async list(syncId, since = 0) {
    return Math.max(0, this.#log(syncId).length - since);
  }

  /** Fetch one sealed blob by arrival index, or null if out of range. */
  async get(syncId, seq) {
    const b = this.#log(syncId)[seq];
    return b ? b.slice() : null;
  }
}
