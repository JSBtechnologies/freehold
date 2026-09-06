// Hand-written type surface for @freehold/db (the implementation is plain ESM — no build step).

export interface OpenOptions {
  /** URL of the wasm-pack JS glue, e.g. `new URL('./pkg/freehold.js', import.meta.url)`. Required. */
  wasmUrl: string | URL;
  /** Override the SDK's own vault-worker.js (rarely needed). */
  workerUrl?: string | URL;
  /** WebAuthn relying-party display name shown in the passkey prompt. */
  rpName?: string;
  /** Auto-lock after this many ms of inactivity (rolling — reset on every op). 0/undefined = off. */
  lockAfterMs?: number;
}

export interface UnlockMethod {
  kekId: number;
  kind: 'passkey' | 'recovery' | 'device';
}

/** A verifiable tier-2 attestation: a claim signed by the vault's Ed25519 identity key. See
 *  docs/vault-signing-design.md. `issuedAt`/`expiry` are unix seconds; `audience` binds the intended
 *  verifier (anti-replay). Verify with `FreeholdVault.verifyAttestation` (no DEK needed). */
export interface Attestation {
  v: 1;
  claim: string;
  audience: Uint8Array;
  issuedAt: number;
  expiry: number;
  publicKey: Uint8Array;
  signature: Uint8Array;
}

export interface AttestExpectations {
  claim?: string;
  audience?: Uint8Array | string;
  publicKey?: Uint8Array;
  now?: number; // JS ms timestamp; defaults to Date.now()
}

/** A device certificate: a grant-token-shaped claim binding a signing-only device Ed25519 key into a
 *  vault, signed by the vault's INDEPENDENT trust key (docs/device-trust-design.md §1.3). `claim` is
 *  the base64url canonical claim string; `devicePubkey` is the certified key; `trustPublicKey` is the
 *  pinned root; `sig` is the 64-byte Ed25519 signature. `issuedAt`/`expiry` are unix seconds. Verify
 *  with `FreeholdVault.verifyDeviceCert` (pure — no DEK). The `device_id` is `H(devicePubkey)`. */
export interface DeviceCert {
  v: 1;
  claim: string;
  devicePubkey: Uint8Array;   // 32-byte signing-only device Ed25519 public key
  trustPublicKey: Uint8Array; // 32-byte vault trust public key (the pinned cert root)
  sig: Uint8Array;            // 64-byte Ed25519 signature under the trust key
  issuedAt: number;
  expiry: number;
  caps: string[];             // sorted scope list (grant-token vocabulary)
}

export interface DeviceCertExpectations {
  trustPublicKey?: Uint8Array; // pin YOUR vault's trust key; a cert under another root is rejected
  now?: number;                // JS ms timestamp; defaults to Date.now()
}

/** Metadata carried by a `.freehold` bundle (fields are empty Uint8Arrays when absent). */
export interface BundleMeta {
  envelope: Uint8Array;
  credId: Uint8Array;
  epoch: Uint8Array;
}

/** Row values from sql(): everything is stringified by the wasm core; SQL NULL becomes null. */
export type SqlValue = string | null;

/** A per-op relay-auth envelope (docs/relay-auth-design.md): the vault's per-DB Ed25519 public key
 *  and its signature over the op. The relay authorizes statelessly; a transport that needs no auth
 *  (InMemoryRelay) ignores it. `sync()` produces these from the worker — callers never build them. */
export interface RelayAuth {
  pubkey: Uint8Array; // 32-byte relay-auth public key (== the bucket commitment preimage)
  sig: Uint8Array;    // 64-byte Ed25519 signature over the canonical op message
}

/** Relay-auth op codes for `vault.relayAuth(method, ...)` (docs/relay-auth-design.md). */
export declare const RelayMethod: { readonly Push: 1; readonly List: 2; readonly Get: 3; readonly Subscribe: 4 };

/** The blind-relay transport contract (freehold-sync-design §10). Any transport — in-memory, HTTP,
 *  P2P — implements exactly these three methods over an opaque `syncId` bucket of sealed blobs. The
 *  relay never sees keys or plaintext. `sync()` passes an optional per-op `auth` that a network relay
 *  enforces and an in-process relay ignores (docs/relay-auth-design.md). */
export interface BlindRelay {
  /** Append a sealed blob; resolves to its arrival index (seq). */
  put(syncId: Uint8Array, sealed: Uint8Array, auth?: RelayAuth): Promise<number>;
  /** Count of blobs at seq ≥ `since` (how many are new for a client with that cursor). */
  list(syncId: Uint8Array, since: number, auth?: RelayAuth): Promise<number>;
  /** Fetch one sealed blob by arrival index, or null if out of range. */
  get(syncId: Uint8Array, seq: number, auth?: RelayAuth): Promise<Uint8Array | null>;
}

/** Outcome of a sync() pass. */
export interface SyncReport {
  /** Did we publish our current state this pass? */
  pushed: boolean;
  /** How many blobs we pulled from the relay. */
  pulled: number;
  /** How many pulled blobs fast-forwarded our state. */
  applied: number;
  /** How many concurrent forks were detected+resolved this pass (losers preserved). */
  forks: number;
}

/** The decrypted contents of a preserved fork sibling (openFork). */
export interface ForkImage {
  dbUuid: Uint8Array;
  vv: Uint8Array;
  /** The `.freehold` bundle bytes of the losing sibling. */
  image: Uint8Array;
}

/** Bindable parameter values for sql() `?` placeholders (blobs deferred). */
export type SqlParam = string | number | boolean | null;

/** Register a new resident passkey with the PRF extension; resolves to the raw credential id. */
export declare function registerPasskey(rpName?: string): Promise<Uint8Array>;

/** Assert a passkey (UV required) and evaluate PRF(salt); resolves to the PRF output + credential id. */
export declare function assertPrf(credId?: Uint8Array | null): Promise<{ prf: Uint8Array; credId: Uint8Array }>;

export declare class FreeholdVault {
  private constructor();

  /** Did the browser grant persistent storage (navigator.storage.persist())? Best-effort. */
  persisted: Promise<boolean>;

  /** WebAuthn + OPFS present? (PRF support itself can only be probed with a real authenticator.) */
  static isSupported(): boolean;

  /** Spawn the vault worker and load the wasm core. Throws if the vault is already open in
   *  another tab (Web Lock guard, feature-detected). */
  static open(options: OpenOptions): Promise<FreeholdVault>;

  /** Register a passkey, wrap a fresh DEK, initialize an empty vault; persists envelope + credId
   *  in IndexedDB. Create your schema via sql() after unlock(). */
  enroll(): Promise<{ credId: Uint8Array }>;

  /** CONVENIENCE TIER — enroll a zero-friction device-key vault (no passkey): unlock() then auto-opens
   *  with no gesture. A 32-byte secret wraps the DEK and is stored only under a non-extractable WebCrypto
   *  key (device-bound, JS-non-extractable) — an explicit, weaker tier for everyday data. `{ backup }`
   *  (default true) also mints a recovery code (returned) so a storage wipe isn't data loss. Resolves to
   *  the recovery code, or null when backup is off. See docs/convenience-tier-design.md. */
  enrollConvenience(opts?: { backup?: boolean }): Promise<string | null>;

  /** Whether an envelope is stored on this device (via enroll() or importBundle()). */
  isEnrolled(): Promise<boolean>;

  /** Whether this is a convenience (device-key) vault — i.e. unlock() auto-opens without a gesture. */
  isConvenience(): Promise<boolean>;

  /** Assert the passkey ONCE and open a session — sql()/exportBundle() then need no prompts
   *  until lock(). */
  unlock(): Promise<void>;

  /** Open a session with a written recovery code instead of a passkey. */
  unlockWithRecovery(code: string): Promise<void>;

  /** Close every DB handle, release the OPFS pool and drop the session key state. Idempotent. */
  lock(): Promise<void>;

  /** Is a session currently open? */
  isUnlocked(): Promise<boolean>;

  /** Mint a fresh recovery code (without adding it as a method). */
  generateRecoveryCode(): Promise<string>;

  /** Add a recovery-code method (generating a code if none given); resolves to the code — show it once. */
  addRecoveryCode(code?: string): Promise<string>;

  /** Register a second passkey and add it as an unlock method. */
  addPasskey(): Promise<{ credId: Uint8Array }>;

  /** Revoke an unlock method by kekId (refuses to remove the last one). */
  removeMethod(kekId: number): Promise<void>;

  /** List unlock methods on the envelope. */
  listMethods(): Promise<UnlockMethod[]>;

  /** The vault's Ed25519 identity public key (32 bytes), DEK-derived. Needs an open session. */
  vaultPublicKey(): Promise<Uint8Array>;

  /** Sign a verifiable tier-2 attestation (claim signed by the vault identity key, bound to an audience
   *  and a TTL). Needs an open session. A remote party verifies it with the public key and no DEK. */
  attest(claim: string, opts?: { audience?: Uint8Array | string; ttlSeconds?: number }): Promise<Attestation>;

  /** Verify an attestation (pure — no DEK). Checks the signature, expiry, and any supplied expectations. */
  verifyAttestation(att: Attestation, expect?: AttestExpectations): Promise<{ ok: boolean; reason?: string }>;

  // ---- Device trust (docs/device-trust-design.md §1): device identity + certs ----

  /** This device's certificate identity `device_id = "dev_" + base64url(SHA-256(label ‖ pubkey))[..12]`
   *  (§1.2). Provisions a signing-only device Ed25519 key (seed wrapped under a non-extractable AES-GCM
   *  CryptoKey in IndexedDB) on first call. DISTINCT from the sync-lineage device id (§1.7). */
  deviceId(): Promise<string>;

  /** This device's signing-only Ed25519 public key (32 bytes). Provisions the key on first call. */
  devicePublicKey(): Promise<Uint8Array>;

  /** Issue a device certificate for this device (or a supplied `devicePubkey`) chaining to the vault's
   *  independent trust key (§1.3). Provisions + seals the trust key under HKDF(DEK,…) on first use.
   *  `caps` is a scope list (canonicalized in wasm). Needs an open session. Persists the sealed trust
   *  blob and (for this device's own key) the cert. */
  issueDeviceCert(opts?: { devicePubkey?: Uint8Array; caps?: string[] | string; ttlSeconds?: number }): Promise<DeviceCert>;

  /** The vault trust public key (32 bytes) — the pinned root device certs chain to — or null if no
   *  cert has been issued on this device yet. */
  trustPublicKey(): Promise<Uint8Array | null>;

  /** This device's stored certificate (from issueDeviceCert / pairing), or null. */
  deviceCert(): Promise<DeviceCert | null>;

  /** Verify a device certificate (pure — no DEK). Recompute-and-byte-compare tamper gate,
   *  `device_id == H(devicePubkey)`, verify_strict under the pinned trust key, and the validity window. */
  verifyDeviceCert(cert: DeviceCert, expect?: DeviceCertExpectations): Promise<{ ok: boolean; reason?: string }>;

  /** Run SQL in the open session against named database `db` (default 'app'; [a-z0-9_-]{1,32} —
   *  each name is its own SQLite file). `params` bind `?` placeholders and require a single
   *  statement; with no params, multi-statement scripts are allowed. Rows as arrays of
   *  stringified values. */
  sql(query: string, params?: SqlParam[], db?: string): Promise<SqlValue[][]>;

  /** Export the binary `.freehold` bundle from the open session (envelope + credId + every DB's
   *  encrypted image + epoch; no key inside). Throws if locked. */
  exportBundle(): Promise<Uint8Array>;

  /** Import a `.freehold` bundle and persist its envelope/credId/epoch (locks any open session first). */
  importBundle(bytes: Uint8Array | ArrayBuffer): Promise<BundleMeta>;

  /** Server-blind, epoch-ordered replication over a BlindRelay: pull + reconcile (fast-forward /
   *  stale / fork) + apply winners + preserve fork losers + push. Requires an open session. */
  sync(options: { relay: BlindRelay; push?: boolean }): Promise<SyncReport>;

  /** The opaque 16-byte relay bucket id for `dbUuid` (default the vault's sync bucket) — a commitment
   *  to the DEK-derived relay-auth key, safe to hand to a relay. Requires an open session. */
  syncId(dbUuid?: Uint8Array): Promise<Uint8Array>;

  /** Sign a blind-relay op for `dbUuid`'s bucket with the DEK-derived relay-auth key, for advanced
   *  callers driving a BlindRelay directly (docs/relay-auth-design.md). `method` is a RelayMethod code;
   *  `arg` binds a Push to its blob bytes (empty for reads). sync() does this internally. */
  relayAuth(method: number, arg?: Uint8Array, dbUuid?: Uint8Array): Promise<RelayAuth>;

  /** Register a fork listener (concurrent offline edits detected). Returns an unsubscribe fn. */
  onFork(cb: (fork: { id: string; winner: 'local' | 'incoming' }) => void): () => void;

  /** List preserved fork siblings (LWW losers — never silently dropped). */
  listForks(): Promise<{ id: string }[]>;

  /** Recover a preserved fork's decrypted contents by id. Requires an open session. */
  openFork(id: string): Promise<ForkImage>;

  /** Forget the stored envelope/credId/epoch and sync lineage (passkeys and OPFS ciphertext are
   *  untouched; the stable deviceId is kept). */
  reset(): Promise<void>;

  /** Terminate the worker and release the cross-tab lock; the vault is unusable afterwards. */
  close(): void;
}
