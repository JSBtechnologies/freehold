// @freehold/db vault worker — the only thread that touches the wasm core (and thus OPFS + key
// material). SAHPool needs a dedicated worker anyway; header-free means no COOP/COEP required.
// The wasm JS glue URL arrives in the `init` message (the SDK ships no wasm of its own — the app
// points it at a wasm-pack `pkg/`), everything after is id-correlated request/response.

let wasm = null;

// Ops the main thread may invoke — a fixed allowlist, NOT arbitrary property lookup on the module.
const OPS = new Set([
  'enroll', 'gen_recovery', 'add_recovery', 'add_passkey', 'remove_method', 'list_methods',
  'import_bundle',
  'session_open', 'session_open_recovery', 'session_lock', 'session_active',
  'session_sql', 'session_export',
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
