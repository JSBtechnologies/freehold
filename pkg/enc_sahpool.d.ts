/* tslint:disable */
/* eslint-disable */

/**
 * Add a second passkey method: unlock with the existing PRF, wrap the DEK under the new PRF.
 */
export function add_passkey(existing_prf: Uint8Array, new_prf: Uint8Array, blob_hex: string): string;

/**
 * Add a recovery-code method: unlock the DEK with the current passkey's PRF, then wrap it under the
 * recovery code's Argon2id KEK. Returns the new envelope blob (hex). The DEK is unchanged.
 */
export function add_recovery(existing_prf: Uint8Array, code: string, blob_hex: string): string;

/**
 * Enroll: wrap a fresh DEK under the PRF-KEK, create the demo DB, return the envelope blob (hex).
 */
export function enroll(prf: Uint8Array): Promise<string>;

/**
 * Export the demo DB's encrypted image as a `name|hex` bundle (DEK-free; safe to carry anywhere).
 */
export function export_db(): Promise<string>;

/**
 * Generate a fresh recovery code for the user to write down.
 */
export function gen_recovery(): string;

/**
 * Import an encrypted DB image (from `export_db` on another device) into this device's OPFS.
 */
export function import_db_image(bundle: string): Promise<void>;

/**
 * List the envelope's unlock methods as `kek_id:kind` pairs, comma-separated (kind: passkey|recovery).
 */
export function list_methods(blob_hex: string): string;

/**
 * Revoke a method by its kek_id. Returns the new blob (hex). Refuses to remove the last slot.
 */
export function remove_method(kek_id: number, blob_hex: string): string;

export function run_tests(): Promise<string>;

/**
 * Unlock: unwrap the DEK from `blob_hex` using the PRF output, open the DB, return the secret row.
 */
export function unlock(prf: Uint8Array, blob_hex: string): Promise<string>;

/**
 * Unlock with the recovery code instead of a passkey: derive the Argon2id KEK, unwrap the DEK,
 * open the DB, return the secret row.
 */
export function unlock_recovery(code: string, blob_hex: string): Promise<string>;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly add_passkey: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly add_recovery: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly enroll: (a: number, b: number) => any;
    readonly export_db: () => any;
    readonly gen_recovery: () => [number, number, number, number];
    readonly import_db_image: (a: number, b: number) => any;
    readonly list_methods: (a: number, b: number) => [number, number, number, number];
    readonly remove_method: (a: number, b: number, c: number) => [number, number, number, number];
    readonly run_tests: () => any;
    readonly unlock: (a: number, b: number, c: number, d: number) => any;
    readonly unlock_recovery: (a: number, b: number, c: number, d: number) => any;
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
