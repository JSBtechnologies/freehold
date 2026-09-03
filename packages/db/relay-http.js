// @freehold/db — HttpRelay: the network BlindRelay adapter over the Connect wire contract
// (proto/freehold/sync/v1/relay.proto, server/relay-server.mjs). A drop-in for InMemoryRelay: it
// implements the exact same three-method BlindRelay contract, so `vault.sync({ relay })` works
// unchanged over a real network.
//
//   put(syncId, sealed): Promise<number>            // -> arrival index (seq)
//   list(syncId, since): Promise<number>            // -> count of blobs at seq >= since
//   get(syncId, seq):    Promise<Uint8Array|null>
//
// Everything on the wire is opaque: `syncId` and the sealed blob are base64 `bytes` fields (proto3
// JSON mapping) — the relay never sees plaintext, a DEK, or blob structure. The vault sealed the blob
// under a DEK subkey before it ever reached here (crates/freehold/src/sync.rs SyncBlob::seal).
//
// Wire = Connect protocol, JSON codec, unary POST /<pkg>.<Svc>/<Method>. This is intentionally
// hand-rolled (fetch + JSON) so @freehold/db keeps its zero-runtime-dependency stance; a connect-es
// client generated from the same .proto is a drop-in replacement (binary codec, streaming) if wanted.

const SVC = 'freehold.sync.v1.RelayService';

const b64enc = (u8) => {
  const a = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8);
  let s = '';
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s);
};
const b64dec = (b64) => {
  const s = atob(b64);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
};

// Relay-auth envelope → the two extra JSON fields the relay checks (docs/relay-auth-design.md). When
// no auth is supplied (e.g. a legacy caller) the fields are omitted and the relay rejects the op.
const authFields = (auth) =>
  auth && auth.pubkey && auth.sig ? { pubkey: b64enc(auth.pubkey), sig: b64enc(auth.sig) } : {};

export class HttpRelay {
  #base;
  #fetch;
  /**
   * @param {string} baseUrl  Relay origin, e.g. "http://localhost:5180" (no trailing slash needed).
   * @param {object} [opts]
   * @param {typeof fetch} [opts.fetch]  Injectable fetch (tests / non-browser hosts).
   */
  constructor(baseUrl, { fetch: f } = {}) {
    if (!baseUrl) throw new Error('HttpRelay: a base URL is required');
    this.#base = baseUrl.replace(/\/+$/, '');
    this.#fetch = f || globalThis.fetch?.bind(globalThis);
    if (!this.#fetch) throw new Error('HttpRelay: no fetch available (pass opts.fetch)');
  }

  async #rpc(method, body) {
    let res;
    try {
      res = await this.#fetch(`${this.#base}/${SVC}/${method}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (e) {
      throw new Error(`HttpRelay ${method}: network error: ${e.message}`);
    }
    const text = await res.text();
    let json;
    try { json = text ? JSON.parse(text) : {}; } catch { json = {}; }
    if (!res.ok) {
      const msg = json.message || res.statusText || `HTTP ${res.status}`;
      throw new Error(`HttpRelay ${method}: ${json.code || res.status}: ${msg}`);
    }
    return json;
  }

  /** Append a sealed blob; resolves to its arrival index. `auth` = `{ pubkey, sig }` (relay-auth,
   *  docs/relay-auth-design.md) — the vault signs each op; the relay rejects an unsigned/bad one. */
  async put(syncId, sealed, auth) {
    const r = await this.#rpc('PushBlob', { syncId: b64enc(syncId), blob: b64enc(sealed), ...authFields(auth) });
    return Number(r.seq ?? 0);
  }

  /** Count of blobs at index >= `since`. */
  async list(syncId, since = 0, auth) {
    const r = await this.#rpc('ListBlobs', { syncId: b64enc(syncId), since: String(since), ...authFields(auth) });
    return Number(r.count ?? 0);
  }

  /** Fetch one sealed blob by arrival index, or null if out of range. */
  async get(syncId, seq, auth) {
    const r = await this.#rpc('GetBlob', { syncId: b64enc(syncId), seq: String(seq), ...authFields(auth) });
    return r.found && r.blob ? b64dec(r.blob) : null;
  }

  /**
   * Optional low-latency "receive updates" over the server-streaming Subscribe RPC (SSE). Invokes
   * `onSeq(seq)` for every arrival index >= `since`. Returns an unsubscribe function. NEVER required
   * for correctness — sync() converges on the unary poll path alone; this only avoids polling.
   * (Browser EnvironmentEventSource can't POST a body, so we stream the response manually via fetch.)
   */
  async subscribe(syncId, since, onSeq, { signal, auth } = {}) {
    const res = await this.#fetch(`${this.#base}/${SVC}/Subscribe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ syncId: b64enc(syncId), since: String(since), ...authFields(auth) }),
      signal,
    });
    if (!res.ok || !res.body) throw new Error(`HttpRelay Subscribe: HTTP ${res.status}`);
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    (async () => {
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let nl;
          while ((nl = buf.indexOf('\n\n')) >= 0) {
            const frame = buf.slice(0, nl); buf = buf.slice(nl + 2);
            const line = frame.split('\n').find((l) => l.startsWith('data:'));
            if (!line) continue;
            try { const { seq } = JSON.parse(line.slice(5).trim()); onSeq(Number(seq)); } catch { /* skip */ }
          }
        }
      } catch { /* aborted / closed */ }
    })();
    return () => { try { reader.cancel(); } catch { /* already closed */ } };
  }
}
