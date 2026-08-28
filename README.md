# enc-sahpool — header-free encrypting SQLite VFS + passkey-PRF unlock

A research prototype: an **XChaCha20-Poly1305 encrypting VFS** for SQLite-Wasm that runs on the
header-free OPFS **SAHPool** storage (no COOP/COEP headers needed), plus a **passkey-PRF unlock**
layer where the database key is derived from a WebAuthn passkey — never stored on disk.

- **The VFS** encrypts every file SQLite touches (main DB, rollback journal, temp) below SQLite,
  with per-DB keys, an anti-rollback manifest + double-buffered freshness anchor, and a passed
  3-agent adversarial security review. See `BUILD-NOTES.md` for the honest guarantee ledger.
- **Passkey-PRF unlock (M2/M3)**: a random data key (DEK) is wrapped by an **N-KEK envelope** — one
  slot per unlock method. Enroll multiple passkeys + a recovery code; any one opens the DB; add/remove
  a method re-wraps the DEK (never re-encrypts the DB). The envelope + encrypted DB can be exported
  as a **key-free bundle** and imported on another device (server-blind).

## Run it (just Node — no Rust toolchain needed)

The built wasm is committed in `pkg/`, so you only need Node:

```bash
npm install
npm run dev
```

Then open the printed `http://localhost:5173` (or similar):
- **`/`** — the VFS self-test suite (M1–M3 crypto/crash/perf checks; runs in a worker).
- **`/passkey.html`** — the passkey-PRF unlock demo (enroll, add methods, unlock, export/import).

WebAuthn needs a **secure context** — `localhost` qualifies, so no HTTPS needed locally. You need a
platform authenticator (Windows Hello / Touch ID) or a security key supporting the WebAuthn `prf`
extension.

## The two-device recovery test

The point of the design: unlock the same DB on another device with no server ever seeing the key.

1. **Device A** (`/passkey.html`): **Enroll** → **Add recovery code** (write it down) → **Export
   bundle** (downloads `enc-sahpool-bundle.json` — contains the envelope + encrypted DB image,
   **no key inside**).
2. Copy the JSON to **Device B** and **Import** it there.
3. On B, try both:
   - **Unlock with passkey** — the make-or-break: does the *synced* passkey re-derive the same PRF
     on B and open the DB? (Provider-dependent — this is what we're testing.)
   - **Unlock with recovery code** — device-independent by construction (Argon2id + in-envelope
     salt); always opens on B. This is the guaranteed fallback.

> **rp.id note:** WebAuthn scopes passkeys to the origin's domain. Two machines on `localhost` share
> `rp.id = "localhost"`, but whether providers *sync* localhost passkeys across devices varies. For a
> faithful synced-passkey test, serve over a real HTTPS domain (so `rp.id` is a syncable domain), or
> use a roaming security key you physically move between machines. The recovery-code path works
> regardless.

## Build from source (optional)

Requires Rust + LLVM + [`wasm-pack`](https://rustwasm.github.io/wasm-pack/):

```bash
wasm-pack build --target web --release   # regenerates pkg/
npm install && npm run dev
```

## Layout

| Path | What |
|---|---|
| `src/crypto.rs` | trusted crypto core (per-block AEAD, HKDF subkeys, RNG gate) |
| `src/manifest.rs` | anti-rollback manifest + freshness-anchor formats |
| `src/vfs.rs` | forked SAHPool VFS with the encrypted block device spliced in |
| `src/envelope.rs` | passkey-PRF / recovery-code N-KEK envelope |
| `src/lib.rs` | wasm entry points: `run_tests`, `enroll`/`unlock`, envelope + export/import |
| `passkey.html` / `passkey-worker.js` | the passkey-PRF unlock demo |
| `index.html` / `worker.js` | the VFS self-test harness |
| `BUILD-NOTES.md` | honest §17 guarantee ledger + security-review outcome |

**Status:** research prototype. The demo DEK constants in `lib.rs` are stand-ins; the passkey flow
uses real random keys. Not production-hardened — see `BUILD-NOTES.md` for the exact boundaries.
