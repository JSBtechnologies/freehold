# EpochDB

**Passkey-unlocked, end-to-end-encrypted SQLite for the browser.** Your data lives encrypted in
the browser's own storage (OPFS), unlocks with a hardware-bound passkey (WebAuthn PRF), and moves
between your devices as a key-free bundle — **no server ever sees a key**.

The name comes from the **sync-epoch anchor**: peer-attested freshness tokens that turn storage
rollback from something you *detect* into something the database *refuses* — verified live across
two physical devices.

## What's inside

- **Header-free encrypting VFS** — an XChaCha20-Poly1305 encrypting VFS for SQLite-Wasm on OPFS
  SAHPool storage. Every file SQLite touches (main DB, journal, temp) is encrypted below SQLite
  with per-DB HKDF subkeys. No COOP/COEP headers needed (`crossOriginIsolated` stays `false`), so
  it drops into any page. Survived 3 adversarial security-review passes; crash-injection sweep
  clean; ~380 MB/s AEAD throughput.
- **Passkey-PRF unlock** — a random data key (DEK) wrapped in an **N-slot key envelope**: one slot
  per unlock method (passkeys via WebAuthn-PRF → HKDF, recovery code via Argon2id). Any one method
  opens the DB; adding/removing a method re-wraps the DEK, never re-encrypts the database. The DEK
  is zeroized after use and never persisted.
- **Anti-rollback** — a double-buffered manifest + freshness anchor locally, upgraded to
  **rollback prevention** across devices by sync-epoch tokens (any of your devices can mint/attest;
  an attacker without the DEK cannot forge one).
- **Server-blind portability** — export the encrypted DB + envelope as a bundle with no key inside;
  import it on another device and unlock with your synced passkey or recovery code. Confirmed on
  real hardware: Windows/Chrome → Mac/Chrome via Google Password Manager passkey sync.

## Ways to use it

| Mode | How | Status |
|---|---|---|
| **Rust crate** (`epochdb`) | Vendor the VFS/envelope in your own Rust→Wasm app; build with `default-features = false` to compile out the test/fault-injection surface. | working |
| **Wasm + JS** | `wasm-pack build crates/epochdb --target web` produces an npm-shaped `pkg/`; drive it from a worker like `examples/demo` does. | working (prebuilt copy committed in `examples/demo/pkg`) |
| **Demo app** | `examples/demo` — self-test harness + full passkey enroll/unlock/export/import UI. | working |

A polished npm package with a high-level JS/TS API (ceremony + worker plumbing wrapped) is the next
layer — see the roadmap.

## Run the demo (Node only — no Rust toolchain needed)

The built wasm is committed in `examples/demo/pkg/`:

```bash
cd examples/demo
npm install
npm run dev
```

Open the printed `http://localhost:5173`:

- **`/`** — the VFS self-test suite (crypto/crash/perf checks; runs in a worker).
- **`/passkey.html`** — the passkey unlock demo: enroll a passkey, add a recovery code and more
  passkeys, unlock by any method, revoke methods, export/import the key-free bundle.

WebAuthn needs a secure context — `localhost` qualifies. You need a platform authenticator
(Windows Hello / Touch ID) or a security key supporting the WebAuthn `prf` extension.

## The two-device test

The point of the design: unlock the same DB on another device with no server ever seeing the key.

1. **Device A** (`/passkey.html`): **Enroll** → **Add recovery code** (write it down) → **Export
   bundle** (downloads `epochdb-bundle.json` — envelope + encrypted DB image, **no key inside**).
2. Copy the JSON to **Device B** and **Import** it there.
3. Unlock on B with the **synced passkey** (provider-dependent — confirmed for Chrome + Google
   Password Manager) or the **recovery code** (device-independent by construction; always works).

> **rp.id note:** passkeys are scoped to the origin's domain. For a faithful synced-passkey test
> across machines, serve over a real HTTPS domain, or use a roaming security key. The recovery-code
> path works regardless.

## Build from source

Requires Rust, [`wasm-pack`](https://rustwasm.github.io/wasm-pack/), and clang/LLVM (the SQLite C
sources compile to wasm via `cc`):

```bash
wasm-pack build crates/epochdb --target web --release --out-dir ../../examples/demo/pkg
cd examples/demo && npm install && npm run dev
```

## Layout

| Path | What |
|---|---|
| `crates/epochdb/src/crypto.rs` | trusted crypto core (per-block AEAD, HKDF subkeys, RNG gate) |
| `crates/epochdb/src/manifest.rs` | anti-rollback manifest + freshness-anchor formats |
| `crates/epochdb/src/vfs.rs` | forked SAHPool VFS with the encrypted block device spliced in |
| `crates/epochdb/src/envelope.rs` | passkey-PRF / recovery-code N-KEK envelope |
| `crates/epochdb/src/lib.rs` | wasm entry points: `run_tests`, enroll/unlock, export/import |
| `examples/demo/` | self-test harness + passkey demo (Vite) |
| `docs/design-spec.md` | the VFS design spec (v1.1) |
| `docs/sync-epoch-design.md` | peer-attested anti-rollback design |
| `docs/security-review.md`, `docs/adversarial-review.md` | review record |
| `docs/BUILD-NOTES.md` | honest §17 guarantee ledger |

## Status & lineage

Research-grade, pre-release. Grown from the `enc-sahpool` prototype; all format identity strings
were rebranded at the fork (`epochdb-*-v1`, envelope magic `EPDBENV2`), so **bundles/DBs created by
the old prototype do not open here** — re-enroll. Crypto is audited RustCrypto used as-is; the
design and its limits are documented honestly in `docs/BUILD-NOTES.md`. Not yet independently
audited — don't bet lives on it.

## Roadmap

- High-level npm package (`epochdb` on npm): TS API wrapping the worker + passkey ceremony.
- BIP39 checksummed recovery phrases (currently Crockford-Base32).
- Broader PRF-stability matrix: iCloud Keychain, 1Password, mobile, roaming keys.
- "Adv Mode": chunk sharding of the encrypted DB across your own devices/peers.

## License

MIT OR Apache-2.0, at your option.
