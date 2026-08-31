# Freehold DB

**Passkey-unlocked, end-to-end-encrypted SQLite for the browser.** Your data lives encrypted in
the browser's own storage (OPFS), unlocks with a hardware-bound passkey (WebAuthn PRF), and moves
between your devices as a key-free bundle — **no server ever sees a key**.

> Cloud storage is a leasehold: you occupy, someone else holds title.
> A **freehold** is property you own outright — no landlord, no lease, no one else's key.

Freehold DB is the first part of the Freehold family: **Freehold DB** (this repo — the local
encrypted database), **Freehold Sync** (server-blind synchronization), and **Freehold Grid**
(idle-time Wasm/WebGPU compute across your own devices). DB is the foundation; the others build
on its keys and sync-epoch machinery.

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
| **Rust crate** (`freehold`) | Vendor the VFS/envelope in your own Rust→Wasm app; build with `default-features = false` to compile out the test/fault-injection surface. | working |
| **Wasm + JS** | `wasm-pack build crates/freehold --target web` produces an npm-shaped `pkg/`; drive it from a worker like `examples/demo` does. | working (prebuilt copy committed in `examples/demo/pkg`) |
| **JS/TS SDK** (`@freehold/db`) | `packages/db` — typed ESM SDK wrapping the passkey ceremony, vault worker and persistence; point it at a `pkg/` build. No build step. | working |
| **Demo app** | `examples/demo` — self-test harness + full passkey enroll/unlock/export/import UI, built on the SDK. | working |

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
   bundle** (downloads `freehold-bundle.freehold` — a binary TLV bundle of envelope + encrypted DB
   image, **no key inside**).
2. Copy the `.freehold` file to **Device B** and **Import** it there.
3. Unlock on B with the **synced passkey** (provider-dependent — confirmed for Chrome + Google
   Password Manager) or the **recovery code** (device-independent by construction; always works).

> **rp.id note:** passkeys are scoped to the origin's domain. For a faithful synced-passkey test
> across machines, serve over a real HTTPS domain, or use a roaming security key. The recovery-code
> path works regardless.

## Build from source

Requires Rust, [`wasm-pack`](https://rustwasm.github.io/wasm-pack/), and clang/LLVM (the SQLite C
sources compile to wasm via `cc`):

```bash
wasm-pack build crates/freehold --target web --release --out-dir ../../examples/demo/pkg
cd examples/demo && npm install && npm run dev
```

## Layout

| Path | What |
|---|---|
| `crates/freehold/src/crypto.rs` | trusted crypto core (per-block AEAD, HKDF subkeys, RNG gate) |
| `crates/freehold/src/manifest.rs` | anti-rollback manifest + freshness-anchor formats |
| `crates/freehold/src/vfs.rs` | forked SAHPool VFS with the encrypted block device spliced in |
| `crates/freehold/src/envelope.rs` | passkey-PRF / recovery-code N-KEK envelope |
| `crates/freehold/src/lib.rs` | wasm entry points: `run_tests`, enroll, session (open/sql/export/lock), import |
| `examples/demo/` | self-test harness + passkey demo (Vite) |
| `docs/design-spec.md` | the VFS design spec (v1.1) |
| `docs/sync-epoch-design.md` | peer-attested anti-rollback design |
| `docs/security-review.md`, `docs/adversarial-review.md` | review record |
| `docs/BUILD-NOTES.md` | honest §17 guarantee ledger |

## Status & lineage

Research-grade, pre-release. Grown from the `enc-sahpool` prototype; all format identity strings
were rebranded at the fork (`freehold-*-v1`; magics: bundle `FREEHOLD`, envelope `FREEHENV`), so **bundles/DBs created by
the old prototype do not open here** — re-enroll. Crypto is audited RustCrypto used as-is; the
design and its limits are documented honestly in `docs/BUILD-NOTES.md`. Not yet independently
audited — don't bet lives on it.

## Roadmap

- ~~Session model (one passkey ceremony, many queries), parameterized SQL, named DBs, cross-tab
  Web Lock guard, `navigator.storage.persist()`~~ — **done**.
- ~~Capability preflight (`FreeholdVault.capabilities()` / `probePrf()` / `probeSah()`) so an
  unsupported browser gets a clear reason, not a crypto failure deep in the worker~~ — **done**.
- ~~Non-bypassable recovery-code backup at enroll (`needsBackup()` / `hasRecoveryMethod()` gate the
  demo's export)~~ — **done**.
- **Envelope anti-rollback** (`env_generation`, floor-enforced + epoch-bound) so revoking a method is
  durable against a local rollback of the envelope — **issue #3, format bump to v3**.
- **DEK rotation + re-encryption**, wired to revocation, so a compromised device can be truly evicted
  (not just have one unlock slot dropped) — **issue #4**.
- **Multi-user** (families, small teams, a clinician sharing notes): needs real **per-device signing
  keys** so one device can't forge another user's epoch (see `docs/sync-epoch-design.md` §D-SE2).
  Deliberately out of v1 scope — single-user is a *chosen* boundary, not a dead end — **planned**.
- Published **bundle-format spec + a standalone decryptor** (recovery-code → plaintext SQLite, no
  Freehold runtime) so "self-custodied" is verifiable and provider-portable — **issue #6**.
- Publish `@freehold/db` to npm (the SDK lives in `packages/db`). (The bare `freehold` npm name is
  squatted by a dead 2022 package; the scope is ours.)
- BIP39 checksummed recovery phrases (currently Crockford-Base32).
- Broader PRF-stability matrix: iCloud Keychain, 1Password, mobile, roaming keys.
- "Adv Mode": chunk sharding of the encrypted DB across your own devices/peers.

## What sync does and doesn't protect

Freehold protects **confidentiality** from the sync path *unconditionally* — no server, relay, or
peer ever sees a key or plaintext. It does **not** guarantee **availability or freshness**: a
dishonest provider can withhold writes, serve a stale version, or partition your devices. The
anti-rollback epochs make such staleness **detectable and non-propagating** at the sync boundary,
but they can't force a bad provider to deliver your latest state. For a liveness guarantee, run a
provider you control or sync device-to-device. See `docs/sync-epoch-design.md` §2.1.

## License

MIT OR Apache-2.0, at your option.
