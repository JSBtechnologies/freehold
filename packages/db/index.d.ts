// Hand-written type surface for @freehold/db (the implementation is plain ESM — no build step).

export interface OpenOptions {
  /** URL of the wasm-pack JS glue, e.g. `new URL('./pkg/freehold.js', import.meta.url)`. Required. */
  wasmUrl: string | URL;
  /** Override the SDK's own vault-worker.js (rarely needed). */
  workerUrl?: string | URL;
  /** WebAuthn relying-party display name shown in the passkey prompt. */
  rpName?: string;
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

/** Register a new resident passkey with the PRF extension; resolves to the raw credential id. */
export declare function registerPasskey(rpName?: string): Promise<Uint8Array>;

/** Assert a passkey (UV required) and evaluate PRF(salt); resolves to the PRF output + credential id. */
export declare function assertPrf(credId?: Uint8Array | null): Promise<{ prf: Uint8Array; credId: Uint8Array }>;

export declare class FreeholdVault {
  private constructor();

  /** WebAuthn + OPFS present? (PRF support itself can only be probed with a real authenticator.) */
  static isSupported(): boolean;

  /** Spawn the vault worker and load the wasm core. */
  static open(options: OpenOptions): Promise<FreeholdVault>;

  /** Register a passkey, wrap a fresh DEK, create the DB; persists envelope + credId in IndexedDB. */
  enroll(): Promise<{ credId: Uint8Array }>;

  /** Whether an envelope is stored on this device (via enroll() or importBundle()). */
  isEnrolled(): Promise<boolean>;

  /** Assert the passkey, unwrap the DEK, open the DB; resolves to the demo secret row. */
  unlock(): Promise<string>;

  /** Unlock with a written recovery code instead of a passkey. */
  unlockWithRecovery(code: string): Promise<string>;

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

  /** Run SQL (multi-statement allowed) after a passkey unlock; rows as arrays of stringified values. */
  sql(query: string): Promise<SqlValue[][]>;

  /** Run SQL after a recovery-code unlock (same semantics as sql()). */
  sqlWithRecovery(code: string, query: string): Promise<SqlValue[][]>;

  /** Export the binary `.freehold` bundle (envelope + credId + encrypted DB image + epoch; no key inside). */
  exportBundle(): Promise<Uint8Array>;

  /** Import a `.freehold` bundle and persist its envelope/credId/epoch. */
  importBundle(bytes: Uint8Array | ArrayBuffer): Promise<BundleMeta>;

  /** Forget the stored envelope/credId/epoch (passkeys and OPFS ciphertext are untouched). */
  reset(): Promise<void>;

  /** Terminate the worker; the vault is unusable afterwards. */
  close(): void;
}
