/* tslint:disable */
/* eslint-disable */

/**
 * Add a row to the demo DB (advances db_generation) so you can create a v1/v2 pair for the live
 * two-device rollback test. Applies any peer epoch first, then commits a new note.
 */
export function add_note(prf: Uint8Array, blob: Uint8Array, epoch: Uint8Array): Promise<string>;

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
 * Enroll: wrap a fresh DEK under the PRF-KEK, create the demo DB, return the envelope blob.
 */
export function enroll(prf: Uint8Array): Promise<Uint8Array>;

/**
 * Export a self-contained binary `.freehold` bundle: envelope + credential id + the encrypted DB
 * image + a freshly minted sync-epoch token (bundle.rs TLV). The image is DEK-free; the epoch
 * token is DEK-authenticated freshness. Needs the passkey PRF to mint the epoch. Pass an empty
 * `cred_id` slice if there is none to embed (e.g. recovery-only flows).
 */
export function export_db(prf: Uint8Array, blob: Uint8Array, cred_id: Uint8Array): Promise<Uint8Array>;

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
 * Revoke a method by its kek_id. Returns the new blob. Refuses to remove the last slot.
 */
export function remove_method(kek_id: number, blob: Uint8Array): Uint8Array;

/**
 * Run arbitrary SQL after a passkey-PRF unlock. Returns a JSON array of row arrays (stringified
 * values, NULL → null); statements that return no rows yield "[]".
 */
export function run_sql(prf: Uint8Array, blob: Uint8Array, epoch: Uint8Array, sql: string): Promise<string>;

/**
 * Run arbitrary SQL after a recovery-code unlock (same semantics as `run_sql`).
 */
export function run_sql_recovery(code: string, blob: Uint8Array, epoch: Uint8Array, sql: string): Promise<string>;

export function run_tests(): Promise<string>;

/**
 * Unlock: apply any peer `epoch` token (freshness), unwrap the DEK via the PRF, open the DB,
 * return the secret row. Pass an empty slice for `epoch` when there's no peer epoch to apply.
 */
export function unlock(prf: Uint8Array, blob: Uint8Array, epoch: Uint8Array): Promise<string>;

/**
 * Unlock with the recovery code instead of a passkey: derive the Argon2id KEK, unwrap the DEK,
 * open the DB, return the secret row.
 */
export function unlock_recovery(code: string, blob: Uint8Array, epoch: Uint8Array): Promise<string>;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly add_note: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly add_passkey: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly add_recovery: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly enroll: (a: number, b: number) => any;
    readonly export_db: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly gen_recovery: () => [number, number, number, number];
    readonly import_bundle: (a: number, b: number) => any;
    readonly list_methods: (a: number, b: number) => [number, number, number, number];
    readonly remove_method: (a: number, b: number, c: number) => [number, number, number, number];
    readonly run_sql: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly run_sql_recovery: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly run_tests: () => any;
    readonly unlock: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly unlock_recovery: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
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
