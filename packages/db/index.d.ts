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
  kind: 'passkey' | 'recovery';
}

/** Metadata carried by a `.freehold` bundle (fields are empty Uint8Arrays when absent). */
export interface BundleMeta {
  envelope: Uint8Array;
  credId: Uint8Array;
  epoch: Uint8Array;
}

/** Row values from sql(): everything is stringified by the wasm core; SQL NULL becomes null. */
export type SqlValue = string | null;

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

  /** Whether an envelope is stored on this device (via enroll() or importBundle()). */
  isEnrolled(): Promise<boolean>;

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

  /** Forget the stored envelope/credId/epoch (passkeys and OPFS ciphertext are untouched). */
  reset(): Promise<void>;

  /** Terminate the worker and release the cross-tab lock; the vault is unusable afterwards. */
  close(): void;
}
