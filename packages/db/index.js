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
   */
  static async open({ wasmUrl, workerUrl, rpName } = {}) {
    if (!wasmUrl) {
      throw new Error('FreeholdVault.open: wasmUrl is required (URL of the wasm-pack JS glue, e.g. pkg/freehold.js)');
    }
    const worker = workerUrl
      ? new Worker(new URL(workerUrl, document.baseURI), { type: 'module' })
      : new Worker(new URL('./vault-worker.js', import.meta.url), { type: 'module' });
    const vault = new FreeholdVault(worker, rpName || DEFAULT_RP_NAME);
    // Resolve the glue URL on THIS thread — the worker's base URL differs from the page's.
    await vault.#call('init', [String(new URL(wasmUrl, document.baseURI))]);
    return vault;
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

  /** Register a passkey, wrap a fresh DEK under its PRF-KEK, create the DB. Persists the
   *  envelope + credential id in IndexedDB. */
  async enroll() {
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

  /** Assert the passkey, unwrap the DEK, open the DB. Resolves to the demo secret row. */
  async unlock() {
    const envelope = await this.#envelope();
    let prf = await this.#prf();
    const secret = await this.#call('unlock', [prf, envelope, await this.#epoch()], [prf.buffer]);
    prf = null;
    return secret;
  }

  /** Unlock with a written recovery code instead of a passkey. */
  async unlockWithRecovery(code) {
    return this.#call('unlock_recovery', [code, await this.#envelope(), await this.#epoch()]);
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

  /** Run SQL after a passkey unlock. Resolves to an array of row arrays; every value is a string
   *  (SQL NULL → null). Multi-statement scripts are allowed. */
  async sql(query) {
    const envelope = await this.#envelope();
    let prf = await this.#prf();
    const rows = await this.#call('run_sql', [prf, envelope, await this.#epoch(), query], [prf.buffer]);
    prf = null;
    return JSON.parse(rows);
  }

  /** Run SQL after a recovery-code unlock (same semantics as sql()). */
  async sqlWithRecovery(code, query) {
    const rows = await this.#call('run_sql_recovery', [code, await this.#envelope(), await this.#epoch(), query]);
    return JSON.parse(rows);
  }

  /** Export the binary `.freehold` bundle: envelope + credential id + encrypted DB image + a
   *  freshly minted sync-epoch token. No key inside. Requires a passkey assertion. */
  async exportBundle() {
    const envelope = await this.#envelope();
    const credId = (await idbGet('credId')) || new Uint8Array(0);
    let prf = await this.#prf();
    const bytes = await this.#call('export_db', [prf, envelope, credId], [prf.buffer]);
    prf = null;
    return bytes;
  }

  /** Import a `.freehold` bundle: writes the ciphertext files into OPFS and persists the bundled
   *  envelope / credId / epoch. Unlock afterwards with the synced passkey or a recovery code. */
  async importBundle(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    // Only transfer when the view owns its whole buffer — never detach a caller's larger buffer.
    const transfer = (u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength) ? [u8.buffer] : [];
    const meta = await this.#call('import_bundle', [u8], transfer);
    await idbSet('envelope', meta.envelope);
    if (meta.credId && meta.credId.length) await idbSet('credId', meta.credId);
    if (meta.epoch && meta.epoch.length) await idbSet('epoch', meta.epoch); else await idbDel('epoch');
    return meta;
  }

  /** Forget the stored envelope/credId/epoch. (Passkeys still live in the authenticator; the
   *  encrypted OPFS files are untouched but unopenable without the envelope.) */
  async reset() {
    await idbDel('envelope');
    await idbDel('credId');
    await idbDel('epoch');
  }

  /** Terminate the worker. The vault is unusable afterwards. */
  close() {
    this.#worker.terminate();
  }
}
