// @freehold/db vault worker — the only thread that touches the wasm core (and thus OPFS + key
// material). SAHPool needs a dedicated worker anyway; header-free means no COOP/COEP required.
// The wasm JS glue URL arrives in the `init` message (the SDK ships no wasm of its own — the app
// points it at a wasm-pack `pkg/`), everything after is id-correlated request/response.

let wasm = null;

// Ops the main thread may invoke — a fixed allowlist, NOT arbitrary property lookup on the module.
const OPS = new Set([
  'enroll', 'enroll_device', 'gen_recovery', 'recovery_code_valid', 'add_recovery', 'add_passkey', 'remove_method',
  'list_methods', 'envelope_generation', 'import_bundle', 'rotate_dek',
  'session_open', 'session_open_recovery', 'session_lock', 'session_active',
  'session_sql', 'session_export',
  // Vault signing (docs/vault-signing-design.md): identity pubkey + attest are session-gated; verify is pure.
  'session_vault_pubkey', 'session_attest', 'verify_attestation',
  // Freehold Sync (freehold-sync-design §10 item 3): crypto + conflict logic in wasm; the loop in JS.
  'session_sync_id', 'session_sync_seal', 'session_sync_open', 'session_sync_apply',
  'sync_vv_empty', 'sync_vv_increment', 'sync_vv_merge', 'sync_reconcile',
]);

// Hand result buffers back by transfer where possible (bundles can be MBs — don't copy them twice).
function transferablesOf(result) {
  if (result instanceof Uint8Array) return [result.buffer];
  const t = [];
  if (result && typeof result === 'object') {
    for (const v of Object.values(result)) {
      if (v instanceof Uint8Array) t.push(v.buffer);
    }
  }
  return t;
}

self.onmessage = async (e) => {
  const { id, op, args = [] } = e.data;
  try {
    let result;
    if (op === 'init') {
      wasm = await import(/* @vite-ignore */ args[0]);
      await wasm.default(); // wasm-bindgen init — fetches the .wasm next to the glue
      result = true;
    } else {
      if (!wasm) throw new Error('vault worker not initialized — FreeholdVault.open() must complete first');
      if (!OPS.has(op) || typeof wasm[op] !== 'function') throw new Error('unknown op: ' + op);
      result = await wasm[op](...args);
    }
    self.postMessage({ id, ok: true, result }, transferablesOf(result));
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err && err.message ? err.message : err) });
  }
};
