# @freehold/db

Typed ESM SDK for **Freehold DB** — passkey-unlocked, end-to-end-encrypted SQLite in the browser.
Wraps the WebAuthn-PRF ceremony, the vault worker, and the wasm core behind one class. Plain
JavaScript with hand-written `.d.ts` — **no build step**; what you import is what runs.

Published under the `@freehold` npm scope. The SDK ships no wasm of its own: point it at a
wasm-pack `pkg/` build of `crates/freehold` (the repo commits one at `examples/demo/pkg/`).

## Usage

```js
import { FreeholdVault } from '@freehold/db';

if (!FreeholdVault.isSupported()) throw new Error('needs WebAuthn + OPFS');

const vault = await FreeholdVault.open({
  wasmUrl: new URL('./pkg/freehold.js', import.meta.url), // your wasm-pack output
  rpName: 'My App',
  lockAfterMs: 5 * 60_000,                  // optional rolling auto-lock on inactivity
});

await vault.enroll();                       // register passkey, initialize the empty vault
const code = await vault.addRecoveryCode(); // show ONCE, then forget

await vault.unlock();                       // ONE passkey ceremony opens a session…
await vault.sql('CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, body TEXT)');
await vault.sql('INSERT INTO notes(body) VALUES (?)', ['hello 🔐']);   // …then no more prompts
const rows = await vault.sql('SELECT body FROM notes WHERE id >= ?', [1]); // [['hello 🔐']]
await vault.sql('CREATE TABLE t(x)', [], 'scratch'); // named DBs: own SQLite file per name

const bytes = await vault.exportBundle();   // Uint8Array — binary .freehold bundle, no key inside
await vault.lock();                         // drop the session key state, release OPFS
// ...move to device B...
await vault.importBundle(bytes);
await vault.unlockWithRecovery(code);       // or the synced passkey via unlock()
```

`unlock()` asserts the passkey ONCE (user verification required) and opens a **session**: the PRF
output is transferred straight into the worker, the DEK is unwrapped there and never leaves wasm
memory, and every `sql()` / `exportBundle()` rides the session prompt-free until `lock()` (or the
`lockAfterMs` inactivity timer) drops it. `sql()` params bind `?` placeholders
(null/boolean/number/string; blobs deferred) and require a single statement — without params,
multi-statement scripts are allowed. `open()` also claims a Web Lock so a second tab fails fast
("already open in another tab"), and requests `navigator.storage.persist()` (result:
`vault.persisted`). Envelope, credential id and sync-epoch token persist in IndexedDB
(`freehold`/`meta`) — all non-secret.

## License

MIT OR Apache-2.0, at your option.
