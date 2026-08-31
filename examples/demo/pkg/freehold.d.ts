/* tslint:disable */
/* eslint-disable */

/**
 * Add a second passkey method: unlock with the existing PRF, wrap the DEK under the new PRF.
 */
export function add_passkey(existing_prf: Uint8Array, new_prf: Uint8Array, blob: Uint8Array): Uint8Array;

/**
 * Add a recovery-code method: unlock the DEK with the current passkey's PRF, then wrap it under the
 * recovery code's Argon2id KEK. Returns the new envelope blob. The DEK is unchanged.
 */
export function add_recovery(existing_prf: Uint8Array, code: string, blob: Uint8Array): Uint8Array;

/**
 * Enroll: wrap a fresh DEK under the PRF-KEK, initialize an empty vault, return the envelope blob.
 */
export function enroll(prf: Uint8Array): Promise<Uint8Array>;

/**
 * The envelope's anti-rollback generation counter (v3). The SDK persists the max it has seen as a
 * floor and refuses any envelope below it — catching a rolled-back envelope that would re-plant a
 * revoked slot. Returned as f64 (generations are small; exact through 2^53).
 */
export function envelope_generation(blob: Uint8Array): number;

/**
 * Generate a fresh recovery code for the user to write down.
 */
export function gen_recovery(): string;

/**
 * Import a binary bundle (from `export_db`). Writes the ciphertext files into a fresh pool and
 * returns `{ envelope, credId, epoch }` (Uint8Array fields; credId/epoch empty if absent) — the
 * caller persists them and passes the epoch to `unlock`, which applies it (a stale image below
 * that epoch is then refused at open).
 */
export function import_bundle(bytes: Uint8Array): Promise<any>;

/**
 * List the envelope's unlock methods as `kek_id:kind` pairs, comma-separated (kind: passkey|recovery).
 */
export function list_methods(blob: Uint8Array): string;

/**
 * Revoke a method by its kek_id. Requires the current passkey's PRF to authorize (revoking is a
 * mutation that re-MACs the envelope under the DEK — v3). Returns the new blob. Refuses to remove
 * the last slot.
 */
export function remove_method(existing_prf: Uint8Array, kek_id: number, blob: Uint8Array): Uint8Array;

/**
 * Rotate the DEK and re-encrypt every DB under it (issue #4). Requires a live session. Returns
 * `{ envelope, recovery_code }`: the caller MUST persist `envelope` to IndexedDB (the commit
 * barrier), record `env_floor`, surface `recovery_code` once, then re-unlock with the new envelope
 * (which finalizes the swap). The session is locked on return.
 */
export function rotate_dek(prf: Uint8Array, envelope: Uint8Array): Promise<any>;

export function run_tests(): Promise<string>;

/**
 * Is a session currently open?
 */
export function session_active(): boolean;

/**
 * Export the binary `.freehold` bundle from the LIVE session: envelope + credential id + the
 * encrypted image of every DB in the pool + a freshly minted sync-epoch token. No key inside.
 * Pass an empty `cred_id` slice if there is none to embed (e.g. recovery-only flows).
 */
export function session_export(cred_id: Uint8Array): Uint8Array;

/**
 * Lock the session: close handles, release the pool (see `session_lock_inner`), drop the session.
 */
export function session_lock(): void;

/**
 * Open a session: unwrap the DEK via the passkey PRF (ONE ceremony), apply any peer epoch,
 * install the VFS, and hold it all until `session_lock`. Every subsequent `session_sql` /
 * `session_export` rides this session with no further prompts.
 */
export function session_open(prf: Uint8Array, blob: Uint8Array, epoch: Uint8Array): Promise<void>;

/**
 * Open a session with the written recovery code instead of a passkey (same semantics).
 */
export function session_open_recovery(code: string, blob: Uint8Array, epoch: Uint8Array): Promise<void>;

/**
 * Run SQL against named DB `db` in the live session. `params_json` is a JSON array bound to `?`
 * placeholders (empty string or "[]" = none; then multi-statement scripts are allowed). Returns
 * a JSON array of row arrays (stringified values, NULL → null); no rows yields "[]".
 */
export function session_sql(db: string, sql: string, params_json: string): string;

/**
 * Apply a pulled image into the live session (FastForward / fork-winner only). See inner docs.
 */
export function session_sync_apply(image: Uint8Array): void;

/**
 * Opaque 16-byte relay bucket id for the live session's DEK + `db_uuid` (freehold-sync-design §4).
 */
export function session_sync_id(db_uuid: Uint8Array): Uint8Array;

/**
 * Authenticated-open a relay blob → `{ dbUuid, vv, image }` (all Uint8Array). Wrong key/tamper Errs.
 */
export function session_sync_open(sealed: Uint8Array): any;

/**
 * Seal the live session's current image + `vv` into a relay blob under the DEK-derived sync_key.
 */
export function session_sync_seal(db_uuid: Uint8Array, vv: Uint8Array): Uint8Array;

/**
 * Classify incoming vs local → `{ outcome: 'fastforward'|'stale'|'fork', winnerIsIncoming: bool }`.
 */
export function sync_reconcile(local_vv: Uint8Array, incoming_vv: Uint8Array): any;

/**
 * The empty version vector (all-zero components), encoded.
 */
export function sync_vv_empty(): Uint8Array;

/**
 * Bump `device_id`'s component in `vv` by one; returns the re-encoded vector.
 */
export function sync_vv_increment(vv: Uint8Array, device_id: Uint8Array): Uint8Array;

/**
 * Element-wise max of two vectors (applied after a fork resolves so it does not re-trigger).
 */
export function sync_vv_merge(a: Uint8Array, b: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly add_passkey: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly add_recovery: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly enroll: (a: number, b: number) => any;
    readonly envelope_generation: (a: number, b: number) => number;
    readonly gen_recovery: () => [number, number, number, number];
    readonly import_bundle: (a: number, b: number) => any;
    readonly list_methods: (a: number, b: number) => [number, number, number, number];
    readonly remove_method: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly rotate_dek: (a: number, b: number, c: number, d: number) => any;
    readonly run_tests: () => any;
    readonly session_active: () => number;
    readonly session_export: (a: number, b: number) => [number, number, number, number];
    readonly session_lock: () => [number, number];
    readonly session_open: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly session_open_recovery: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly session_sql: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly session_sync_apply: (a: number, b: number) => [number, number];
    readonly session_sync_id: (a: number, b: number) => [number, number, number, number];
    readonly session_sync_open: (a: number, b: number) => [number, number, number];
    readonly session_sync_seal: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly sync_reconcile: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly sync_vv_empty: () => [number, number];
    readonly sync_vv_increment: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly sync_vv_merge: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly rust_sqlite_wasm_abort: () => void;
    readonly rust_sqlite_wasm_assert_fail: (a: number, b: number, c: number, d: number) => void;
    readonly rust_sqlite_wasm_calloc: (a: number, b: number) => number;
    readonly rust_sqlite_wasm_free: (a: number) => void;
    readonly rust_sqlite_wasm_getentropy: (a: number, b: number) => number;
    readonly rust_sqlite_wasm_localtime: (a: number) => number;
    readonly rust_sqlite_wasm_malloc: (a: number) => number;
    readonly rust_sqlite_wasm_realloc: (a: number, b: number) => number;
    readonly sqlite3_os_end: () => number;
    readonly sqlite3_os_init: () => number;
    readonly wasm_bindgen__convert__closures_____invoke__ha22148a4a7c1d5ff: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h44475d2d48e3e63e: (a: number, b: number, c: any, d: any) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
