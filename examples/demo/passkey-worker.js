// Dedicated worker for the passkey-PRF unlock demo (M2 + M3 N-KEK envelope). The REAL WebAuthn-PRF
// ceremony happens on the main thread (it needs a user gesture); this worker receives PRF bytes /
// recovery codes and runs the envelope + encrypted-DB ops in wasm. Header-free: no COOP/COEP.
import init, {
  enroll, unlock, gen_recovery, add_recovery, add_passkey, remove_method, list_methods, unlock_recovery,
  export_db, import_db_image, add_note,
} from './pkg/freehold.js';

let ready = false;
async function ensure() { if (!ready) { await init(); ready = true; } }

self.onmessage = async (e) => {
  const m = e.data;
  try {
    await ensure();
    const prf = m.prf ? new Uint8Array(m.prf) : null;
    const prf2 = m.prf2 ? new Uint8Array(m.prf2) : null;
    let result;
    switch (m.type) {
      case 'enroll':          result = { blobHex: await enroll(prf) }; break;
      case 'unlock':          result = { secret: await unlock(prf, m.blob, m.epoch || '') }; break;
      case 'gen_recovery':    result = { code: gen_recovery() }; break;
      case 'add_recovery':    result = { blobHex: add_recovery(prf, m.code, m.blob) }; break;
      case 'add_passkey':     result = { blobHex: add_passkey(prf, prf2, m.blob) }; break;
      case 'remove_method':   result = { blobHex: remove_method(m.kekId, m.blob) }; break;
      case 'list_methods':    result = { methods: list_methods(m.blob) }; break;
      case 'unlock_recovery': result = { secret: await unlock_recovery(m.code, m.blob, m.epoch || '') }; break;
      case 'add_note':        result = { msg: await add_note(prf, m.blob, m.epoch || '') }; break;
      case 'export_db':       result = { bundle: await export_db(prf, m.blob) }; break;
      case 'import_db_image':  result = { epochHex: await import_db_image(m.bundle) }; break;
      default: throw new Error('unknown message type: ' + m.type);
    }
    self.postMessage({ id: m.id, ok: true, ...result });
  } catch (err) {
    self.postMessage({ id: m.id, ok: false, error: String(err && err.message ? err.message : err) });
  }
};
