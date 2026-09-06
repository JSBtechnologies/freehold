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
// device sharing the DEK derives the SAME sync_id (and the SAME relay-auth key) from it; different
// users (different DEK) never collide. Exactly 16 bytes — a protocol constant, do not change (it
// re-buckets everyone). sync_id = SHA-256("freehold-sync-id-v1" ‖ relay_auth_pubkey)[..16] so the
// relay can authorize access statelessly (docs/relay-auth-design.md).
const SYNC_DB_UUID = new TextEncoder().encode('freehold/vault/1');

// Relay-auth op codes bound into each signed request (must match crates/freehold/src/relay_auth.rs
// and server/relay-server.mjs). Reads sign an empty arg (idempotent, one credential reused per pass);
// a Push signs its blob bytes so a captured signature cannot store different bytes.
const RELAY_PUSH = 1, RELAY_LIST = 2, RELAY_GET = 3, RELAY_SUBSCRIBE = 4;
const EMPTY = new Uint8Array(0);

/** Relay-auth op codes for `vault.relayAuth(method, ...)` when driving a BlindRelay directly
 *  (docs/relay-auth-design.md). sync() uses these internally; you only need them for raw ops. */
export const RelayMethod = { Push: RELAY_PUSH, List: RELAY_LIST, Get: RELAY_GET, Subscribe: RELAY_SUBSCRIBE };

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

// Length-then-content byte comparison (constant-time is unnecessary — attestation pubkey/audience are
// public, not secrets; this is an expectation check, not an auth gate).
const eqBytes = (a, b) => {
  const x = new Uint8Array(a), y = new Uint8Array(b);
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
};
const toBytes = (v) => (typeof v === 'string' ? new TextEncoder().encode(v) : new Uint8Array(v));

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

  /** WebAuthn + OPFS present? (Does not probe PRF support — that needs a real authenticator.)
   *  Kept for back-compat; prefer capabilities() for a full, reasoned preflight. */
  static isSupported() {
    return typeof navigator !== 'undefined'
      && !!navigator.credentials
      && typeof PublicKeyCredential !== 'undefined'
      && !!(navigator.storage && navigator.storage.getDirectory);
  }

  /** Full capability preflight. Returns `{ ok, reasons, ...flags }`. Every hard requirement Freehold
   *  needs to even open a vault is probed *synchronously* here so an unsupported browser gets a clear
   *  "why" instead of a crypto failure deep in the worker. PRF (the one feature most likely to be
   *  missing) can't be probed synchronously — use probePrf() for a best-effort async answer.
   *
   *  Flags: secureContext, webauthn, opfs (getDirectory), sahpool (SyncAccessHandle), workers, wasm. */
  static capabilities() {
    const hasNav = typeof navigator !== 'undefined';
    const secureContext = typeof isSecureContext === 'undefined' ? false : isSecureContext;
    const webauthn = hasNav && !!navigator.credentials && typeof PublicKeyCredential !== 'undefined';
    const opfs = hasNav && !!(navigator.storage && navigator.storage.getDirectory);
    // SAHPool is the storage floor with no viable fallback. Its method createSyncAccessHandle() is
    // [Exposed=DedicatedWorker] — absent on the main-thread prototype — so we can only proxy it here
    // by the presence of the OPFS handle type. The definitive check lives in probeSah() (worker-based).
    const sahpool = typeof FileSystemFileHandle !== 'undefined';
    const workers = typeof Worker !== 'undefined';
    const wasm = typeof WebAssembly !== 'undefined';
    const reasons = [];
    if (!secureContext) reasons.push('not a secure context (needs HTTPS or localhost)');
    if (!webauthn) reasons.push('WebAuthn / navigator.credentials unavailable');
    if (!opfs) reasons.push('OPFS (navigator.storage.getDirectory) unavailable');
    if (!sahpool) reasons.push('OPFS file handles unavailable (older browser)');
    if (!workers) reasons.push('Web Workers unavailable');
    if (!wasm) reasons.push('WebAssembly unavailable');
    return {
      ok: secureContext && webauthn && opfs && sahpool && workers && wasm,
      secureContext, webauthn, opfs, sahpool, workers, wasm, reasons,
    };
  }

  /** Best-effort async probe of WebAuthn-PRF support. Resolves to 'supported' | 'unsupported' |
   *  'unknown'. Uses PublicKeyCredential.getClientCapabilities() where present (Chrome 133+/newer);
   *  otherwise 'unknown' — PRF can only be confirmed for certain by enrolling a real authenticator,
   *  and enroll() surfaces a clean error if the authenticator declines the extension. */
  static async probePrf() {
    try {
      if (typeof PublicKeyCredential === 'undefined') return 'unsupported';
      if (typeof PublicKeyCredential.getClientCapabilities === 'function') {
        const caps = await PublicKeyCredential.getClientCapabilities();
        if (caps && Object.prototype.hasOwnProperty.call(caps, 'extension:prf')) {
          return caps['extension:prf'] ? 'supported' : 'unsupported';
        }
      }
      return 'unknown';
    } catch { return 'unknown'; }
  }

  /** Definitive OPFS SyncAccessHandle probe. createSyncAccessHandle() is worker-only, so this spins
   *  a throwaway inline worker to check whether the method exists in a DedicatedWorker scope — the
   *  scope where Freehold's vault actually needs it. Resolves boolean; false ⇒ storage floor unmet
   *  (no viable fallback). Best-effort: resolves false on any worker/timeout error. */
  static async probeSah() {
    if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined') return false;
    const src = "self.postMessage(typeof FileSystemFileHandle !== 'undefined' && " +
      "typeof FileSystemFileHandle.prototype.createSyncAccessHandle === 'function');";
    let url;
    try {
      url = URL.createObjectURL(new Blob([src], { type: 'text/javascript' }));
      const w = new Worker(url);
      return await new Promise((resolve) => {
        const done = (v) => { try { w.terminate(); } catch {} resolve(v); };
        const t = setTimeout(() => done(false), 3000);
        w.onmessage = (e) => { clearTimeout(t); done(!!e.data); };
        w.onerror = () => { clearTimeout(t); done(false); };
      });
    } catch { return false; }
    finally { if (url) { try { URL.revokeObjectURL(url); } catch {} } }
  }

  /**
   * Spawn the vault worker and load the wasm core.
   * `wasmUrl` (required): URL of the wasm-pack JS glue (e.g. `new URL('./pkg/freehold.js', import.meta.url)`).
   * `workerUrl` (optional): override the SDK's own vault-worker.js.
   * `rpName` (optional): WebAuthn relying-party display name.
   * `lockAfterMs` (optional): auto-lock after this many ms of inactivity (rolling; 0/undefined off).
   */
  static async open({ wasmUrl, workerUrl, rpName, lockAfterMs, skipCapabilityCheck } = {}) {
    if (!wasmUrl) {
      throw new Error('FreeholdVault.open: wasmUrl is required (URL of the wasm-pack JS glue, e.g. pkg/freehold.js)');
    }
    // CAPABILITY PREFLIGHT: fail fast with a readable reason instead of a crypto/OPFS error deep in
    // the worker. Opt out with { skipCapabilityCheck: true } only if you probe yourself.
    if (!skipCapabilityCheck) {
      const caps = FreeholdVault.capabilities();
      if (!caps.ok) {
        throw new Error('Freehold is unsupported in this browser: ' + caps.reasons.join('; '));
      }
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
    // ANTI-ROLLBACK (issue #3): refuse an envelope whose generation is below the highest we've seen.
    // Catches a rolled-back envelope that would re-plant a revoked slot. Locally the floor is a
    // backstop (an attacker who rewrites all storage rewrites it too); the wasm MAC additionally
    // stops a forged higher generation. `env_floor` is a plain Number (generations are small).
    const floor = await idbGet('env_floor');
    if (typeof floor === 'number') {
      const gen = await this.#call('envelope_generation', [e]);
      if (gen < floor) {
        throw new Error(`envelope rollback detected (generation ${gen} < floor ${floor}) — refusing a stale envelope`);
      }
    }
    return e;
  }

  // Record the newest envelope generation we've accepted, so a later rollback is caught by #envelope().
  async #bumpFloor(envelope) {
    const gen = await this.#call('envelope_generation', [envelope]);
    const floor = await idbGet('env_floor');
    if (typeof floor !== 'number' || gen > floor) await idbSet('env_floor', gen);
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

  // CONVENIENCE TIER (docs/convenience-tier-design.md): if this device has a device-key record,
  // unwrap the 32-byte secret S from the non-extractable WebCrypto key in IndexedDB and return it as a
  // transferable buffer (the caller detaches it into the worker). S is treated exactly like a passkey
  // PRF output — it opens the same envelope slot. Returns null when this is not a convenience vault.
  async #deviceSecret() {
    const key = await idbGet('deviceKey');
    const wrap = await idbGet('deviceWrap');
    if (!key || !wrap) return null;
    const s = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: wrap.iv }, key, wrap.ct);
    return new Uint8Array(s);
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
    await idbDel('env_floor');      // fresh vault — clear any stale floor, then seed from gen 1
    await this.#bumpFloor(envelope);
    return { credId };
  }

  /** CONVENIENCE TIER — enroll a zero-friction, device-key vault (no passkey). A random 32-byte secret
   *  S wraps a fresh DEK (S is used exactly as a passkey PRF would be), and S itself is stored ONLY
   *  wrapped under a non-extractable WebCrypto key in IndexedDB — device-bound and non-readable by JS,
   *  but usable without a user gesture, so `unlock()` needs no prompt. This is an EXPLICIT, weaker tier
   *  than the passkey path (a same-origin script while the device key exists can auto-unlock) — for
   *  everyday, non-critical data. See docs/convenience-tier-design.md §2 for the honest boundary.
   *
   *  `{ backup = true }` also mints a recovery code (returned once) so a storage wipe / new device isn't
   *  data loss — a device key dies with the device. Pass `backup:false` only for truly throwaway data.
   *  Resolves to the recovery code (or null when backup is off). */
  async enrollConvenience({ backup = true } = {}) {
    await this.lock(); // re-initializes the pool — a live session would hold its handles
    const deviceKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const iv = rand(12);
    let S = rand(32);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, deviceKey, S));
    let envelope = await this.#call('enroll_device', [S], [S.buffer]); // S treated as a PRF output → device-kind slot (D-CV6), then detached
    S = null;
    await idbSet('deviceKey', deviceKey);       // CryptoKey stored by reference (non-extractable)
    await idbSet('deviceWrap', { iv, ct });
    await idbSet('envelope', envelope);
    await idbDel('credId');                     // a pure-device vault has no passkey credential
    await idbDel('epoch');
    await idbDel('env_floor');
    await this.#bumpFloor(envelope);
    if (!backup) return null;
    // Durability: mint a recovery code, authorized by the device secret (unwrapped from the device key).
    const code = await this.generateRecoveryCode();
    let S2 = await this.#deviceSecret();
    envelope = await this.#call('add_recovery', [S2, code, envelope], [S2.buffer]);
    S2 = null;
    await idbSet('envelope', envelope);
    await this.#bumpFloor(envelope);
    return code;
  }

  /** Is this a convenience (device-key) vault — i.e. does `unlock()` auto-open without a gesture? */
  async isConvenience() {
    return !!(await idbGet('deviceKey'));
  }

  /** Has this device an envelope (via enroll() or importBundle())? */
  async isEnrolled() {
    return !!(await idbGet('envelope'));
  }

  /** Does the envelope have a device-independent recovery method (an Argon2id recovery-code slot)?
   *  This is the ONLY unlock that survives losing every device — a passkey slot is bound to an
   *  authenticator. Used to enforce a backup before setup is considered complete. */
  async hasRecoveryMethod() {
    if (!(await this.isEnrolled())) return false;
    return (await this.listMethods()).some((m) => m.kind === 'recovery');
  }

  /** Is a backup still owed? True when enrolled but the only way in is this device's passkey(s) —
   *  i.e. no recovery code exists. Losing/wiping this device in that state = losing the data. The UI
   *  should refuse to treat enrollment as "done" while this is true. See docs/BUILD-NOTES.md. */
  async needsBackup() {
    if (!(await this.isEnrolled())) return false;
    return !(await this.hasRecoveryMethod());
  }

  /** Assert the passkey ONCE and open a session: the DEK stays unwrapped inside the worker's wasm
   *  until lock(), so sql()/exportBundle() need no further prompts. */
  async unlock() {
    const envelope = await this.#envelope();
    const epoch = await this.#epoch();
    // Convenience tier: a device-key vault auto-unlocks with the device-held secret (no gesture).
    // Otherwise assert the passkey. Either way the secret is transferred (detached) into the worker.
    let secret = await this.#deviceSecret();
    if (!secret) secret = await this.#prf();
    await this.#call('session_open', [secret, envelope, epoch], [secret.buffer]);
    secret = null;
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

  /** Advisory check: does `code` look like a correctly-transcribed generated recovery code (its
   *  checksum matches)? Returns false for a typo or a custom (checksum-less) code. Use it to warn in
   *  the UI before an unlock attempt — do NOT gate unlock on it, since a custom code is still valid. */
  async checkRecoveryCode(code) {
    return this.#call('recovery_code_valid', [code]);
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
    await this.#bumpFloor(next);
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
    await this.#bumpFloor(next);
    return { credId: newCredId };
  }

  /** Revoke an unlock method by kekId. Requires a passkey assertion to authorize (v3: revoking
   *  re-MACs the envelope under the DEK). Refuses to remove the last one. */
  async removeMethod(kekId) {
    const envelope = await this.#envelope();
    let prf = await this.#prf();
    const next = await this.#call('remove_method', [prf, kekId, envelope], [prf.buffer]);
    prf = null;
    await idbSet('envelope', next);
    await this.#bumpFloor(next);
  }

  /** Rotate the DEK: re-encrypt every DB under a fresh key (DEK′) and issue a new envelope that wraps
   *  it under ONLY this device's passkey + a freshly minted recovery code. Every OTHER method (other
   *  passkeys, older recovery codes) is intentionally ORPHANED — this is what truly evicts a
   *  compromised device: it may still hold the OLD DEK, but that key is now useless against the
   *  re-encrypted database. Re-admit a trusted device by unlocking it with the new recovery code, then
   *  addPasskey() there. Requires a live session.
   *
   *  Crash-safe across the two stores (OPFS image + IndexedDB envelope) by construction: the worker
   *  stages a shadow image sealed under DEK′ (the live image is untouched), then the single
   *  `idbSet('envelope')` below is THE commit barrier — a crash before it rolls the shadow back on the
   *  next unlock, a crash after it rolls forward. Resolves to the one-time recovery code: show it ONCE
   *  (mandatory backup — the same contract as enroll), then forget it. This re-unlock()s with the new
   *  envelope before returning, so the vault is live under DEK′.
   *
   *  Limit (state it in your UI): rotation protects FUTURE state and forces an attacker off the live
   *  DB; it cannot un-leak what a compromised device already exfiltrated, nor re-encrypt old image
   *  copies the attacker kept (those still open under the old DEK they hold). */
  async rotateKey() {
    if (!(await this.isUnlocked())) {
      throw new Error('vault is locked — call unlock() before rotateKey()');
    }
    const current = await this.#envelope(); // rollback-guarded current envelope (post any add_*)
    let prf = await this.#prf();
    // The worker authorizes against `current`, mints DEK′, builds the new envelope, stages the shadow
    // image, and LOCKS the session. Passing `current` (not the session's open-time snapshot) makes the
    // new generation climb past any recovery/passkey added since unlock, so the floor still accepts it.
    const { envelope, recovery_code } = await this.#call('rotate_dek', [prf, current], [prf.buffer]);
    prf = null;
    // COMMIT BARRIER (D-RK4): one IndexedDB put is the linearization point. Order matters — persist the
    // envelope, THEN raise the floor to its generation, so a crash between them still refuses the old
    // envelope on the next open (floor only ever climbs).
    await idbSet('envelope', envelope);
    await this.#bumpFloor(envelope);
    // The stored epoch was signed under the OLD DEK — meaningless on the DEK′ line. Drop it; a fresh
    // one is minted on the next exportBundle()/sync under DEK′.
    await idbDel('epoch');
    // Finalize: re-unlock with the new envelope — session_open runs the worker's rotation recovery,
    // which rolls the staged shadow forward so the live image is now under DEK′.
    await this.unlock();
    return recovery_code;
  }

  /** List unlock methods as [{ kekId, kind }] (kind: 'passkey' | 'recovery' | 'device'). */
  async listMethods() {
    const s = await this.#call('list_methods', [await this.#envelope()]);
    return s.split(',').filter(Boolean).map((m) => {
      const [kekId, kind] = m.split(':');
      return { kekId: Number(kekId), kind };
    });
  }

  /** The vault's Ed25519 identity public key (32 bytes), DEK-derived and identical across your devices.
   *  Needs an open session. Publish/register it with a verifier so it can check attestations against your
   *  key — not your word. See docs/vault-signing-design.md. */
  async vaultPublicKey() {
    if (!(await this.isUnlocked())) throw new Error('vault is locked — unlock() before vaultPublicKey()');
    return this.#call('session_vault_pubkey', []);
  }

  /** Sign a verifiable tier-2 attestation: a canonical `claim` string signed by the vault identity key,
   *  bound to an `audience` (a verifier challenge / origin — anti-replay to a different verifier) and a
   *  validity window (`ttlSeconds`, default 300). Returns the attestation object; a remote party verifies
   *  it with `vaultPublicKey()` and NO DEK. The raw PII behind the claim is never transmitted. */
  async attest(claim, { audience = new Uint8Array(0), ttlSeconds = 300 } = {}) {
    if (!(await this.isUnlocked())) throw new Error('vault is locked — unlock() before attest()');
    if (typeof claim !== 'string' || !claim) throw new Error('attest: claim must be a non-empty string');
    const aud = toBytes(audience);
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiry = issuedAt + Math.max(1, Math.floor(ttlSeconds));
    const publicKey = await this.#call('session_vault_pubkey', []);
    const signature = await this.#call('session_attest', [claim, aud, issuedAt, expiry]);
    return { v: 1, claim, audience: aud, issuedAt, expiry, publicKey, signature };
  }

  /** Verify an attestation — PURE (no session/DEK; callable on any open vault instance, even locked).
   *  Checks the Ed25519 signature, then your expectations: not expired, and (when supplied) the claim /
   *  audience / publicKey match. `expect.now` is a JS ms timestamp (defaults to Date.now()). Returns
   *  `{ ok, reason }`. A real remote verifier can equivalently check the documented canonical message
   *  with any Ed25519 library — this is the reference implementation. */
  async verifyAttestation(att, expect = {}) {
    if (!att || att.v !== 1) return { ok: false, reason: 'not a v1 attestation' };
    const nowSec = Math.floor((expect.now != null ? expect.now : Date.now()) / 1000);
    if (nowSec >= att.expiry) return { ok: false, reason: 'expired' };
    if (expect.claim != null && expect.claim !== att.claim) return { ok: false, reason: 'claim mismatch' };
    if (expect.audience != null && !eqBytes(toBytes(expect.audience), att.audience)) return { ok: false, reason: 'audience mismatch' };
    if (expect.publicKey != null && !eqBytes(expect.publicKey, att.publicKey)) return { ok: false, reason: 'public key mismatch' };
    const ok = await this.#call('verify_attestation',
      [att.publicKey, att.claim, att.audience, att.issuedAt, att.expiry, att.signature]);
    return ok ? { ok: true } : { ok: false, reason: 'signature invalid' };
  }

  // ---- Device trust (docs/device-trust-design.md §1, increment 1): device identity + certs ----
  // A SIGNING-ONLY Ed25519 device key generated in wasm. Its 32-byte seed is wrapped at rest under a
  // per-origin NON-EXTRACTABLE AES-GCM CryptoKey in IndexedDB — the SAME pattern as the convenience
  // tier's #deviceSecret (the seed is never a non-extractable *signing* key; dalek can't consume one).
  // This is a SEPARATE identity from the version-vector `syncDeviceId` (#deviceId, §1.7) — do not
  // conflate: syncDeviceId is sync lineage, this device_id = H(device_pubkey) is the cert subject.

  /** Provision this device's signing-only Ed25519 identity on first use, or return the existing one.
   *  The seed is generated in wasm, wrapped under a fresh non-extractable AES-GCM CryptoKey in IDB, and
   *  never persisted in the clear. Returns `{ pubkey, deviceId }`. Internal — callers use deviceId()/
   *  issueDeviceCert(); exposed via those. */
  async #deviceIdentity() {
    const existing = await idbGet('deviceIdentityPubkey');
    if (existing) {
      return { pubkey: new Uint8Array(existing), deviceId: await idbGet('deviceCertId') };
    }
    // device_keygen returns seed(32)‖pubkey(32); the seed crosses the boundary once, then is wrapped
    // and dropped (same acceptable window as the convenience-tier secret — see §9 guardrails).
    const packed = await this.#call('device_keygen', []);
    let seed = packed.slice(0, 32);
    const pubkey = packed.slice(32, 64);
    const idKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const iv = rand(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, idKey, seed));
    seed = null; // wrapped — nothing readable remains on this thread
    const deviceId = await this.#call('device_id_from_pubkey', [pubkey]);
    await idbSet('deviceIdentityKey', idKey);          // CryptoKey stored by reference (non-extractable)
    await idbSet('deviceIdentityWrap', { iv, ct });
    await idbSet('deviceIdentityPubkey', pubkey);
    await idbSet('deviceCertId', deviceId);
    return { pubkey, deviceId };
  }

  /** This device's certificate identity: `device_id = "dev_" + base64url(SHA-256(label ‖ pubkey))[..12]`
   *  (docs/device-trust-design.md §1.2). Provisions the device key on first call. This is DISTINCT from
   *  the sync-lineage device id (§1.7) — it is the subject of device certs / revocation / audit. */
  async deviceId() {
    return (await this.#deviceIdentity()).deviceId;
  }

  /** This device's signing-only Ed25519 public key (32 bytes). Provisions the key on first call. */
  async devicePublicKey() {
    return (await this.#deviceIdentity()).pubkey;
  }

  /** Issue a device certificate for THIS device (or a supplied `devicePubkey`) chaining to the vault's
   *  independent trust key (docs/device-trust-design.md §1.3). The trust key is provisioned + sealed
   *  under HKDF(DEK,…) on first use and stays stable across DEK rotation. `caps` is a scope list
   *  (grant-token vocabulary), canonicalized (sorted/deduped) inside wasm. Requires an open session
   *  (the DEK unseals the trust key). Persists the trust-key sealed blob + this device's cert, and
   *  resolves to the cert object `{ v, claim, devicePubkey, trustPublicKey, sig, issuedAt, expiry, caps }`. */
  async issueDeviceCert({ devicePubkey = null, caps = [], ttlSeconds = 365 * 24 * 3600 } = {}) {
    if (!(await this.isUnlocked())) throw new Error('vault is locked — unlock() before issueDeviceCert()');
    const pubkey = devicePubkey ? new Uint8Array(devicePubkey) : await this.devicePublicKey();
    if (pubkey.length !== 32) throw new Error('issueDeviceCert: devicePubkey must be 32 bytes');
    const capsBytes = new TextEncoder().encode((Array.isArray(caps) ? caps : [caps]).join('\n'));
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiry = issuedAt + Math.max(1, Math.floor(ttlSeconds));
    const sealedTrust = (await idbGet('trustSeed')) || EMPTY;
    // Packed: u32_LE(claim.len) ‖ claim(UTF-8) ‖ sig(64) ‖ trust_pubkey(32) ‖ sealed_trust_blob.
    const packed = await this.#call('session_issue_device_cert', [pubkey, capsBytes, sealedTrust, issuedAt, expiry]);
    const dv = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
    const claimLen = dv.getUint32(0, true);
    let off = 4;
    const claim = new TextDecoder().decode(packed.slice(off, off + claimLen)); off += claimLen;
    const sig = packed.slice(off, off + 64); off += 64;
    const trustPublicKey = packed.slice(off, off + 32); off += 32;
    const sealedBlob = packed.slice(off); // possibly-new sealed trust seed
    await idbSet('trustSeed', sealedBlob);
    const cert = {
      v: 1, claim, devicePubkey: pubkey, trustPublicKey, sig, issuedAt, expiry,
      caps: (Array.isArray(caps) ? caps : [caps]).map((s) => String(s).trim()).filter(Boolean).sort(),
    };
    // Persist as THIS device's cert only when it certifies this device's own key.
    const ownPubkey = await this.devicePublicKey();
    if (eqBytes(pubkey, ownPubkey)) await idbSet('deviceCert', cert);
    return cert;
  }

  /** The vault trust public key (32 bytes) — the pinned root device certs chain to. Provisions +
   *  seals the trust key on first use (idempotently, via a throwaway self-cert is NOT done here; the
   *  key is provisioned lazily by issueDeviceCert). Returns null if no cert has ever been issued. */
  async trustPublicKey() {
    const cert = await idbGet('deviceCert');
    return cert ? new Uint8Array(cert.trustPublicKey) : null;
  }

  /** This device's stored certificate (from a prior issueDeviceCert / pairing), or null. */
  async deviceCert() {
    return (await idbGet('deviceCert')) || null;
  }

  /** Verify a device certificate — PURE (no session/DEK/clock; callable even when locked). Checks the
   *  recompute-and-byte-compare tamper gate, `device_id == H(device_pubkey)`, the Ed25519 signature via
   *  verify_strict under the pinned `trustPublicKey`, and the validity window. `expect.now` is a JS ms
   *  timestamp (defaults to Date.now()). `expect.trustPublicKey` (when supplied) must equal the cert's —
   *  pin YOUR vault's trust key so a cert from another vault is rejected. Returns `{ ok, reason }`. */
  async verifyDeviceCert(cert, expect = {}) {
    if (!cert || cert.v !== 1) return { ok: false, reason: 'not a v1 device cert' };
    const trustPk = expect.trustPublicKey != null ? new Uint8Array(expect.trustPublicKey) : new Uint8Array(cert.trustPublicKey);
    if (expect.trustPublicKey != null && !eqBytes(trustPk, cert.trustPublicKey)) {
      return { ok: false, reason: 'trust key mismatch' };
    }
    const nowSec = Math.floor((expect.now != null ? expect.now : Date.now()) / 1000);
    const ok = await this.#call('verify_device_cert',
      [trustPk, cert.claim, new Uint8Array(cert.devicePubkey), new Uint8Array(cert.sig), nowSec]);
    return ok ? { ok: true } : { ok: false, reason: 'invalid (signature / device_id / window / tamper)' };
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
    // Pass the CURRENT (rollback-guarded) envelope, not a worker snapshot: add_recovery/add_passkey/
    // remove_method update IndexedDB but not the open session, so a method added since unlock() would
    // otherwise be missing from the bundle. The worker embeds this verbatim + attests its generation.
    const envelope = await this.#envelope();
    return this.#call('session_export', [credId, envelope]);
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
    // ADOPT the imported envelope's generation as the new floor: an import is an explicit re-baseline
    // of THIS device from a trusted bundle of yours. The local floor guards this device's own envelope
    // timeline against silent rollback. Cross-device envelope rollback is additionally epoch-bound
    // (#3c): the bundle's epoch token attests the envelope generation, and the next unlock refuses a
    // stale envelope below the peer-attested floor (enforced in the worker at session_begin).
    await idbSet('env_floor', await this.#call('envelope_generation', [meta.envelope]));
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

  /** Sign a blind-relay op with the per-vault DEK-derived relay-auth key (docs/relay-auth-design.md).
   *  Returns `{ pubkey, sig }` (Uint8Array 32/64) that the relay verifies statelessly — the DEK never
   *  leaves the worker. A relay that needs no auth (InMemoryRelay) simply ignores the extra argument. */
  async #relayAuth(method, arg = EMPTY) {
    const pk96 = await this.#call('session_relay_sign', [SYNC_DB_UUID, method, arg]);
    return { pubkey: pk96.slice(0, 32), sig: pk96.slice(32) };
  }

  /** The opaque 16-byte relay bucket id for `dbUuid` (default the vault's sync bucket). Safe to hand
   *  to a relay — it is a commitment to the DEK-derived auth key, not the key. Requires an open session. */
  async syncId(dbUuid = SYNC_DB_UUID) {
    if (!(await this.isUnlocked())) throw new Error('vault is locked — unlock() before syncId()');
    return this.#call('session_sync_id', [dbUuid]);
  }

  /** Sign a blind-relay op for `dbUuid`'s bucket with the DEK-derived relay-auth key — for advanced
   *  callers driving a BlindRelay (e.g. HttpRelay) directly (docs/relay-auth-design.md). `method` is a
   *  {@link RelayMethod} code; `arg` binds a Push to its blob bytes (empty for reads). sync() does this
   *  for you; you only need it to authenticate a raw put/list/get/subscribe. Requires an open session. */
  async relayAuth(method, arg = EMPTY, dbUuid = SYNC_DB_UUID) {
    if (!(await this.isUnlocked())) throw new Error('vault is locked — unlock() before relayAuth()');
    const pk96 = await this.#call('session_relay_sign', [dbUuid, method, arg]);
    return { pubkey: pk96.slice(0, 32), sig: pk96.slice(32) };
  }

  /**
   * Pull new blobs from the relay, reconcile each against local state (fast-forward / stale / fork),
   * apply winners into the live session, preserve fork losers, then push the current state. Blobs on
   * the wire are ciphertext sealed under a DEK-subkey; the relay only ever sees opaque bytes.
   * `relay` implements the BlindRelay contract (put/list/get, each taking an optional `auth`) — e.g.
   * `new InMemoryRelay()` (ignores auth) or `new HttpRelay(url)` (forwards it; the relay enforces it).
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

    // Read credentials (List/Get) are idempotent, so one signature each is reused across this pass.
    const listAuth = await this.#relayAuth(RELAY_LIST);
    let getAuth = null; // lazily signed only if there is anything to pull

    // ---- PULL: consume every blob at seq ≥ cursor, reconcile in order ----
    const count = await relay.list(syncId, cursor, listAuth);
    for (let i = 0; i < count; i++) {
      getAuth ||= await this.#relayAuth(RELAY_GET);
      const sealed = await relay.get(syncId, cursor + i, getAuth);
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
      // The Push signature binds the exact blob bytes: a captured signature cannot store other bytes.
      await relay.put(syncId, blob, await this.#relayAuth(RELAY_PUSH, blob));
      cursor = await relay.list(syncId, 0, listAuth); // seen everything up to and including our push
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
    await idbDel('env_floor');
    await idbDel('deviceKey');   // convenience-tier device key + wrapped secret
    await idbDel('deviceWrap');
    // Forget sync lineage too (the DB is being forgotten). deviceId is kept — it's a stable identity.
    await idbDel('syncVv');
    await idbDel('syncCursor');
    await idbDel('syncForks');
    // Device-trust (§1): the vault-scoped trust seed + this device's cert are forgotten with the vault.
    // The device's own signing key (deviceIdentity*) + device_id are KEPT — like syncDeviceId, they are
    // a stable per-device identity (§1.7), independent of any one vault's DEK.
    await idbDel('trustSeed');
    await idbDel('deviceCert');
  }

  /** Terminate the worker and release the cross-tab lock. The vault is unusable afterwards. */
  close() {
    clearTimeout(this.#lockTimer);
    this.#lockTimer = null;
    if (this.#releaseLock) { this.#releaseLock(); this.#releaseLock = null; }
    this.#worker.terminate();
  }
}
