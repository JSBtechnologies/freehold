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
});

await vault.enroll();                       // register passkey, create the encrypted DB
const code = await vault.addRecoveryCode(); // show ONCE, then forget

const rows = await vault.sql("SELECT v FROM secret");   // [['unlocked-by-your-passkey 🔐']]

const bytes = await vault.exportBundle();   // Uint8Array — binary .freehold bundle, no key inside
// ...move to device B...
await vault.importBundle(bytes);
await vault.unlock();                       // synced passkey — or vault.unlockWithRecovery(code)
```

Every unlocking call (`unlock`, `sql`, `exportBundle`, …) asserts the passkey (user verification
required); the PRF output is transferred straight into the worker and the DEK never leaves wasm
memory. Envelope, credential id and sync-epoch token persist in IndexedDB (`freehold`/`meta`) —
all non-secret.

## License

MIT OR Apache-2.0, at your option.
