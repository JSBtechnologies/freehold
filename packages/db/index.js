// @freehold/db — passkey-unlocked encrypted SQLite for the browser, as a typed ESM SDK.
//
// Plain JavaScript + hand-written .d.ts, deliberately NO build step: what you import is what runs.
// The WebAuthn-PRF ceremony lives HERE (main thread — it needs a user gesture); everything that
// touches key material or OPFS runs in a module worker (vault-worker.js) that loads the freehold
// wasm core. The DEK never leaves wasm memory; this file only ever holds PRF outputs, and those
// are transferred (detached) to the worker the moment they exist.

// The PRF salt is a PROTOCOL CONSTANT, not an app choice: the passkey KEK is derived from
// PRF(salt), so changing it silently changes every KEK and orphans every existing envelope.
// Must byte-match the demo lineage ('freehold/passkey-prf/v1').
const PRF_SALT = new TextEncoder().encode('freehold/passkey-prf/v1');
const DEFAULT_RP_NAME = 'freehold demo';

// The whole-vault sync bucket is scoped by the DEK, so a FIXED 16-byte db_uuid is correct: every
// device sharing the DEK derives the SAME sync_id = HKDF(DEK, db_uuid); different users (different
// DEK) never collide. Exactly 16 bytes — a protocol constant, do not change (it re-buckets everyone).
const SYNC_DB_UUID = new TextEncoder().encode('freehold/vault/1');

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

// ---- passkey ceremony helpers (exported — apps may drive the ceremony themselves) ----

/** Register a new resident passkey with the PRF extension. Resolves to the raw credential id. */
export async function registerPasskey(rpName = DEFAULT_RP_NAME) {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: rpName },
    user: { id: rand(16), name: 'demo-user', displayName: 'Demo User' },
    challenge: rand(32),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    extensions: { prf: {} },
  }});
  const ext = cred.getClientExtensionResults();
  if (!ext.prf || ext.prf.enabled === false) {
    throw new Error('This authenticator did not enable the PRF extension.');
  }
  return new Uint8Array(cred.rawId);
}

/** Assert an existing passkey and evaluate PRF(salt). UV is required — the PRF output IS the key
 *  material, so an unverified assertion must never produce it. */
export async function assertPrf(credId) {
  const a = await navigator.credentials.get({ publicKey: {
    challenge: rand(32), userVerification: 'required',
    allowCredentials: credId && credId.length ? [{ type: 'public-key', id: credId }] : [],
    extensions: { prf: { eval: { first: PRF_SALT } } },
  }});
  const res = a.getClientExtensionResults();
  if (!res.prf || !res.prf.results || !res.prf.results.first) {
    throw new Error('No PRF result (authenticator may not support prf on get()).');
  }
  return { prf: new Uint8Array(res.prf.results.first), credId: new Uint8Array(a.rawId) };
}

// ---- tiny promisified IndexedDB (persistence for envelope / credId / epoch — all non-secret) ----
// The envelope is ciphertext, the credId is public, the epoch token is DEK-authenticated freshness;
// none of them unlock anything on their own, so plain IDB is the right durability tier.

const IDB_NAME = 'freehold';
const IDB_STORE = 'meta';

function idbOpen() {
  return new Promise((resolve, reject) => {
    const rq = indexedDB.open(IDB_NAME, 1);
    rq.onupgradeneeded = () => rq.result.createObjectStore(IDB_STORE);
    rq.onsuccess = () => resolve(rq.result);
    rq.onerror = () => reject(rq.error);
  });
}
async function idbTxn(mode, fn) {
  const db = await idbOpen();
  try {
    return await new Promise((resolve, reject) => {
      const rq = fn(db.transaction(IDB_STORE, mode).objectStore(IDB_STORE));
      rq.onsuccess = () => resolve(rq.result);
      rq.onerror = () => reject(rq.error);
    });
  } finally {
    db.close();
  }
}
const idbGet = (key) => idbTxn('readonly', (s) => s.get(key));
const idbSet = (key, value) => idbTxn('readwrite', (s) => s.put(value, key));
const idbDel = (key) => idbTxn('readwrite', (s) => s.delete(key));

// ---- the vault ----

export class FreeholdVault {
  #worker;
  #pending = new Map();
  #seq = 0;
  #rpName;
  #releaseLock = null;   // resolves the Web Lock's callback promise (held until close())
  #lockAfterMs = 0;      // rolling inactivity auto-lock; 0 = disabled
  #lockTimer = null;
  #forkListeners = new Set();  // onFork() callbacks, invoked when sync() detects/resolves a fork

  /** Did the browser grant persistent storage? (navigator.storage.persist(), non-fatal.) */
  persisted = Promise.resolve(false);

  /** @private — use FreeholdVault.open() */
  constructor(worker, rpName) {
    this.#worker = worker;
    this.#rpName = rpName;
    worker.onmessage = (e) => {
      const { id, ok, result, error } = e.data;
      const p = this.#pending.get(id);
      if (!p) return;
      this.#pending.delete(id);
      if (ok) p.resolve(result); else p.reject(new Error(error));
    };
    worker.onerror = (e) => {
      // A worker-level error (bad wasm URL, syntax error) fails every in-flight call.
      const err = new Error('vault worker error: ' + (e.message || 'unknown'));
      for (const p of this.#pending.values()) p.reject(err);
      this.#pending.clear();
    };
  }

  /** WebAuthn + OPFS present? (Does not probe PRF support — that needs a real authenticator.) */
  static isSupported() {
    return typeof navigator !== 'undefined'
      && !!navigator.credentials
      && typeof PublicKeyCredential !== 'undefined'
      && !!(navigator.storage && navigator.storage.getDirectory);
  }

  /**
   * Spawn the vault worker and load the wasm core.
   * `wasmUrl` (required): URL of the wasm-pack JS glue (e.g. `new URL('./pkg/freehold.js', import.meta.url)`).
   * `workerUrl` (optional): override the SDK's own vault-worker.js.
   * `rpName` (optional): WebAuthn relying-party display name.
   * `lockAfterMs` (optional): auto-lock after this many ms of inactivity (rolling; 0/undefined off).
   */
  static async open({ wasmUrl, workerUrl, rpName, lockAfterMs } = {}) {
    if (!wasmUrl) {
      throw new Error('FreeholdVault.open: wasmUrl is required (URL of the wasm-pack JS glue, e.g. pkg/freehold.js)');
    }
    // TAB-LOCK GUARD: the OPFS SAH pool is exclusive per origin, so a second tab would hit opaque
    // handle-acquisition errors deep in the worker. Claim a Web Lock for the vault's lifetime
    // instead (its callback promise stays pending until close() resolves it) and fail fast here.
    // Feature-detected — some WebViews lack navigator.locks; they just skip the guard.
    let releaseLock = null;
    if (typeof navigator !== 'undefined' && navigator.locks) {
      const acquired = await new Promise((resolve) => {
        navigator.locks.request('freehold-vault', { ifAvailable: true }, (lock) => {
          if (!lock) { resolve(false); return; }
          resolve(true);
          return new Promise((release) => { releaseLock = release; });
        }).catch(() => resolve(false));
      });
      if (!acquired) {
        throw new Error('This vault is already open in another tab — close it first.');
      }
    }
    const worker = workerUrl
      ? new Worker(new URL(workerUrl, document.baseURI), { type: 'module' })
      : new Worker(new URL('./vault-worker.js', import.meta.url), { type: 'module' });
    const vault = new FreeholdVault(worker, rpName || DEFAULT_RP_NAME);
    vault.#releaseLock = releaseLock;
    vault.#lockAfterMs = lockAfterMs || 0;
    // STORAGE PERSISTENCE: ask the browser not to evict OPFS under pressure. Best-effort and
    // non-fatal; the answer (a boolean) is exposed as `vault.persisted`.
    vault.persisted = (navigator.storage && navigator.storage.persist)
      ? navigator.storage.persist().catch(() => false)
      : Promise.resolve(false);
    // Resolve the glue URL on THIS thread — the worker's base URL differs from the page's.
    await vault.#call('init', [String(new URL(wasmUrl, document.baseURI))]);
    return vault;
  }

  // Rolling inactivity timer: every session op re-arms it; firing locks the vault.
  #touch() {
    if (!this.#lockAfterMs) return;
    clearTimeout(this.#lockTimer);
    this.#lockTimer = setTimeout(() => { this.lock().catch(() => {}); }, this.#lockAfterMs);
  }

  #call(op, args = [], transfer = []) {
    return new Promise((resolve, reject) => {
      const id = ++this.#seq;
      this.#pending.set(id, { resolve, reject });
      this.#worker.postMessage({ id, op, args }, transfer);
    });
  }

  async #envelope() {
    const e = await idbGet('envelope');
    if (!e) throw new Error('not enrolled on this device — call enroll() or importBundle() first');
    return e;
  }
  async #epoch() {
    return (await idbGet('epoch')) || new Uint8Array(0);
  }
  // Assert the stored credential (or let the platform pick a resident key) and hand back the PRF.
  async #prf() {
    const credId = await idbGet('credId');
    const { prf } = await assertPrf(credId || null);
    return prf;
  }

  /** Register a passkey, wrap a fresh DEK under its PRF-KEK, initialize an empty vault. Persists
   *  the envelope + credential id in IndexedDB. Create your schema via sql() after unlock(). */
  async enroll() {
    await this.lock(); // enrolling re-initializes the pool — a live session would hold its handles
    const credId = await registerPasskey(this.#rpName);
    let { prf } = await assertPrf(credId);
    const envelope = await this.#call('enroll', [prf], [prf.buffer]);
    prf = null; // buffer transferred (detached) — nothing readable remains on this thread
    await idbSet('envelope', envelope);
    await idbSet('credId', credId);
    await idbDel('epoch');
    return { credId };
  }

  /** Has this device an envelope (via enroll() or importBundle())? */
  async isEnrolled() {
    return !!(await idbGet('envelope'));
  }

  /** Assert the passkey ONCE and open a session: the DEK stays unwrapped inside the worker's wasm
   *  until lock(), so sql()/exportBundle() need no further prompts. */
  async unlock() {
    const envelope = await this.#envelope();
    let prf = await this.#prf();
    await this.#call('session_open', [prf, envelope, await this.#epoch()], [prf.buffer]);
    prf = null;
    this.#touch();
  }

  /** Open a session with a written recovery code instead of a passkey.
   *  Note: `code` is a JS string, so (unlike the PRF path's transferable buffer) it cannot be
   *  zeroized and lingers in the main-thread heap until GC. It's a user-facing "write it down"
   *  secret, so this is a known LOW residual; hardening would take it as a transferable Uint8Array. */
  async unlockWithRecovery(code) {
    await this.#call('session_open_recovery', [code, await this.#envelope(), await this.#epoch()]);
    this.#touch();
  }

  /** Lock the session: the worker closes every DB handle, releases the OPFS pool (another tab can
   *  then open it) and drops the key-derived session state. Idempotent. */
  async lock() {
    clearTimeout(this.#lockTimer);
    this.#lockTimer = null;
    await this.#call('session_lock');
  }

  /** Is a session currently open? */
  async isUnlocked() {
    return this.#call('session_active');
  }

  /** Mint a fresh recovery code (does not add it — see addRecoveryCode). */
  async generateRecoveryCode() {
    return this.#call('gen_recovery');
  }

  /** Add a recovery-code unlock method (generating a code if none given). Requires a passkey
   *  assertion to authorize. Resolves to the code — show it ONCE, then forget it. */
  async addRecoveryCode(code) {
    const envelope = await this.#envelope();
    const c = code || await this.generateRecoveryCode();
    let prf = await this.#prf();
    const next = await this.#call('add_recovery', [prf, c, envelope], [prf.buffer]);
    prf = null;
    await idbSet('envelope', next);
    return c;
  }

  /** Register a second passkey and add it as an unlock method (existing passkey authorizes). */
  async addPasskey() {
    const envelope = await this.#envelope();
    let { prf: existing } = await assertPrf((await idbGet('credId')) || null);
    const newCredId = await registerPasskey(this.#rpName);
    let { prf: fresh } = await assertPrf(newCredId);
    const next = await this.#call('add_passkey', [existing, fresh, envelope], [existing.buffer, fresh.buffer]);
    existing = null; fresh = null;
    await idbSet('envelope', next);
    return { credId: newCredId };
  }

  /** Revoke an unlock method by kekId. Refuses to remove the last one. */
  async removeMethod(kekId) {
    const next = await this.#call('remove_method', [kekId, await this.#envelope()]);
    await idbSet('envelope', next);
  }

  /** List unlock methods as [{ kekId, kind }] (kind: 'passkey' | 'recovery'). */
  async listMethods() {
    const s = await this.#call('list_methods', [await this.#envelope()]);
    return s.split(',').filter(Boolean).map((m) => {
      const [kekId, kind] = m.split(':');
      return { kekId: Number(kekId), kind };
    });
  }

  /** Run SQL in the open session (unlock() first — no prompt here, that's the point). `params` is
   *  an array bound to `?` placeholders (null | boolean | number | string; blobs deferred) and
   *  requires a single statement; with no params, multi-statement scripts are allowed. `db` names
   *  the database ([a-z0-9_-]{1,32} → its own SQLite file in the vault). Resolves to an array of
   *  row arrays; every value is a string (SQL NULL → null). */
  async sql(query, params = [], db = 'app') {
    this.#touch();
    const rows = await this.#call('session_sql', [db, query, JSON.stringify(params)]);
    return JSON.parse(rows);
  }

  /** Export the binary `.freehold` bundle from the open session: envelope + credential id + the
   *  encrypted image of every DB in the vault + a freshly minted sync-epoch token. No key inside,
   *  no extra prompt — the session's key mints the epoch. */
  async exportBundle() {
    if (!(await this.isUnlocked())) {
      throw new Error('vault is locked — call unlock() before exportBundle()');
    }
    this.#touch();
    const credId = (await idbGet('credId')) || new Uint8Array(0);
    return this.#call('session_export', [credId]);
  }

  /** Import a `.freehold` bundle: writes the ciphertext files into OPFS and persists the bundled
   *  envelope / credId / epoch. Locks any open session first (the import replaces the pool);
   *  unlock afterwards with the synced passkey or a recovery code. */
  async importBundle(bytes) {
    await this.lock();
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    // Only transfer when the view owns its whole buffer — never detach a caller's larger buffer.
    const transfer = (u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength) ? [u8.buffer] : [];
    const meta = await this.#call('import_bundle', [u8], transfer);
    await idbSet('envelope', meta.envelope);
    if (meta.credId && meta.credId.length) await idbSet('credId', meta.credId);
    if (meta.epoch && meta.epoch.length) await idbSet('epoch', meta.epoch); else await idbDel('epoch');
    return meta;
  }

  // ---- Freehold Sync (freehold-sync-design §10 item 3) ----
  // Server-blind, epoch-ordered replication over a pluggable BlindRelay. The DB seals/opens blobs and
  // classifies conflicts in wasm (proven engine); this loop only orchestrates transport + persistence.
  // Per-device state (all non-secret) lives in IndexedDB: a stable random deviceId, the local version
  // vector (lineage), the relay pull-cursor, and any preserved fork blobs.

  async #deviceId() {
    let id = await idbGet('syncDeviceId');
    if (!id) { id = rand(16); await idbSet('syncDeviceId', id); }
    return id;
  }
  async #syncVv() { return (await idbGet('syncVv')) || await this.#call('sync_vv_empty'); }
  async #syncCursor() { return (await idbGet('syncCursor')) || 0; }
  async #syncForks() { return (await idbGet('syncForks')) || []; }

  /** Register a callback fired when sync() detects a fork (concurrent offline edits). It receives
   *  `{ id, winner: 'local'|'incoming' }`. The loser is preserved — see listForks()/openFork(). */
  onFork(cb) { this.#forkListeners.add(cb); return () => this.#forkListeners.delete(cb); }

  /** Preserved fork siblings (the LWW losers, never silently dropped): `[{ id }]`. Recover the bytes
   *  with openFork(id). */
  async listForks() { return (await this.#syncForks()).map((f) => ({ id: f.id })); }

  /** Recover a preserved fork's decrypted contents: resolves to `{ dbUuid, vv, image }` (the image is
   *  the `.freehold` bundle bytes of the losing sibling). Requires an open session. Throws if unknown. */
  async openFork(id) {
    if (!(await this.isUnlocked())) throw new Error('vault is locked — unlock() before openFork()');
    const f = (await this.#syncForks()).find((x) => x.id === id);
    if (!f) throw new Error('unknown fork id: ' + id);
    return this.#call('session_sync_open', [f.sealed]);
  }

  /**
   * Pull new blobs from the relay, reconcile each against local state (fast-forward / stale / fork),
   * apply winners into the live session, preserve fork losers, then push the current state. Blobs on
   * the wire are ciphertext sealed under a DEK-subkey; the relay only ever sees opaque bytes.
   * `relay` implements the BlindRelay contract (put/list/get) — e.g. `new InMemoryRelay()`.
   * `{ push = true }` — set false to pull-only. Resolves to a report `{ pushed, pulled, applied, forks }`.
   */
  async sync({ relay, push = true } = {}) {
    if (!relay) throw new Error('sync: a relay is required (e.g. new InMemoryRelay())');
    if (!(await this.isUnlocked())) throw new Error('vault is locked — unlock() before sync()');
    this.#touch();

    const syncId = await this.#call('session_sync_id', [SYNC_DB_UUID]);
    const deviceId = await this.#deviceId();
    let localVv = await this.#syncVv();
    let cursor = await this.#syncCursor();
    const forks = await this.#syncForks();
    const report = { pushed: false, pulled: 0, applied: 0, forks: 0 };

    // ---- PULL: consume every blob at seq ≥ cursor, reconcile in order ----
    const count = await relay.list(syncId, cursor);
    for (let i = 0; i < count; i++) {
      const sealed = await relay.get(syncId, cursor + i);
      if (!sealed) continue;
      report.pulled++;
      const incoming = await this.#call('session_sync_open', [sealed]);
      const rec = await this.#call('sync_reconcile', [localVv, incoming.vv]);
      if (rec.outcome === 'fastforward') {
        await this.#call('session_sync_apply', [incoming.image]);
        localVv = await this.#call('sync_vv_merge', [localVv, incoming.vv]);
        report.applied++;
      } else if (rec.outcome === 'stale') {
        // our state already dominates — ignore
      } else { // fork: deterministic winner; the loser is PRESERVED, never dropped
        let loserSealed, winner;
        if (rec.winnerIsIncoming) {
          // incoming wins → preserve our current LOCAL state as the fork, then apply incoming
          loserSealed = await this.#call('session_sync_seal', [SYNC_DB_UUID, localVv]);
          await this.#call('session_sync_apply', [incoming.image]);
          winner = 'incoming';
        } else {
          // local wins → the INCOMING blob is the loser; keep it as-is (already sealed)
          loserSealed = sealed;
          winner = 'local';
        }
        localVv = await this.#call('sync_vv_merge', [localVv, incoming.vv]);
        const id = 'fork-' + (cursor + i) + '-' + forks.length;
        forks.push({ id, sealed: loserSealed });
        report.forks++;
        for (const cb of this.#forkListeners) { try { cb({ id, winner }); } catch { /* listener error is not ours */ } }
      }
    }
    cursor += count;

    // ---- PUSH: publish the current (post-merge) state under an incremented device component ----
    // v1.0 pushes every sync so peers always converge; de-duping unchanged state is a v1.1 optimization.
    if (push) {
      localVv = await this.#call('sync_vv_increment', [localVv, deviceId]);
      const blob = await this.#call('session_sync_seal', [SYNC_DB_UUID, localVv]);
      await relay.put(syncId, blob);
      cursor = await relay.list(syncId, 0); // we've now seen everything up to and including our push
      report.pushed = true;
    }

    await idbSet('syncVv', localVv);
    await idbSet('syncCursor', cursor);
    await idbSet('syncForks', forks);
    return report;
  }

  /** Forget the stored envelope/credId/epoch. (Passkeys still live in the authenticator; the
   *  encrypted OPFS files are untouched but unopenable without the envelope.) */
  async reset() {
    await idbDel('envelope');
    await idbDel('credId');
    await idbDel('epoch');
    // Forget sync lineage too (the DB is being forgotten). deviceId is kept — it's a stable identity.
    await idbDel('syncVv');
    await idbDel('syncCursor');
    await idbDel('syncForks');
  }

  /** Terminate the worker and release the cross-tab lock. The vault is unusable afterwards. */
  close() {
    clearTimeout(this.#lockTimer);
    this.#lockTimer = null;
    if (this.#releaseLock) { this.#releaseLock(); this.#releaseLock = null; }
    this.#worker.terminate();
  }
}
