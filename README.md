# Freehold

**Own your data outright — passkey-unlocked, end-to-end-encrypted SQLite in the browser, with
server-blind sync and app-scoped disclosure.**

Your data lives encrypted in the browser's own storage. It unlocks with a hardware-bound passkey,
moves between your devices as a bundle with **no key inside**, and syncs through a relay that only
ever sees ciphertext. No server, relay, or app ever holds a key.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Status: security preview](https://img.shields.io/badge/status-0.x%20security%20preview-orange.svg)](SECURITY.md)
[![Crypto: audited primitives, no invention](https://img.shields.io/badge/crypto-audited%20primitives%2C%20used%20as--is-green.svg)](docs/supply-chain.md)

> Cloud storage is a **leasehold**: you occupy, someone else holds title.
> A **freehold** is property you own outright — no landlord, no lease, no one else's key.

---

## Why Freehold

- **You hold the only key.** A random 256-bit data key (DEK) encrypts every database block. It is
  unwrapped *inside a Web Worker* from your passkey's WebAuthn-PRF output, lives only in wasm memory,
  and is zeroized on lock. It is never persisted in the clear and never leaves the device.
- **Server-blind by construction.** Export, import, and sync move only sealed ciphertext plus
  non-secret lineage metadata. A relay cannot read, link across your databases, or forge your state.
- **No invented cryptography.** Only audited RustCrypto/dalek and WebCrypto primitives, used as-is:
  XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, Argon2id, Ed25519. Every security decision is
  [designed before it is built](docs/README.md).
- **Honest about its limits.** The design tells you exactly what it does *not* guarantee (availability,
  freshness against a fully-malicious provider, un-leaking already-exfiltrated data). Nothing is
  hand-waved. See [`SECURITY.md`](SECURITY.md) and [`docs/BUILD-NOTES.md`](docs/BUILD-NOTES.md).
- **Drops into any page.** No COOP/COEP headers required (`crossOriginIsolated` stays `false`). Pure
  ESM SDK with hand-written types — what you import is what runs.

## How it works

Freehold is built in layers, each one a security boundary that the layer above rides on:

```
┌──────────────────────────────────────────────────────────────────────┐
│  Your app                                                              │
│    @freehold/db  ──  one class: enroll · unlock · sql · export · sync  │
├──────────────────────────────────────────────────────────────────────┤
│  Device trust        per-device Ed25519 identity + vault-signed certs  │
│  Data custody        apps are custodians: grants · attestations        │
│  Sync                version-vector engine over a blind relay          │
├──────────────────────────────────────────────────────────────────────┤
│  Key envelope        N slots (passkey-PRF · recovery code · device),   │
│                      each wrapping the DEK; add/remove ≠ re-encrypt     │
│  Encrypting VFS      XChaCha20-Poly1305 block device below SQLite      │
│  Anti-rollback       double-buffered manifest + peer-attested epochs   │
├──────────────────────────────────────────────────────────────────────┤
│  Browser            OPFS (encrypted at rest) · WebAuthn · Web Worker   │
└──────────────────────────────────────────────────────────────────────┘
        Rust → Wasm core (crates/freehold)      Zero-dep JS SDK (packages/db)
```

- **Encrypting VFS** — every file SQLite touches (main DB, journal, temp) is encrypted below SQLite
  with per-DB HKDF subkeys. Survived three adversarial security-review passes and a crash-injection
  sweep; ~380 MB/s AEAD throughput.
- **Key envelope** — the DEK is wrapped once per unlock method. Any one method opens the vault; adding
  or revoking a method re-wraps the DEK but never re-encrypts the database. A DEK-keyed MAC + a
  generation floor stop a rolled-back envelope from re-planting a revoked slot.
- **Sync** — a version-vector engine reconciles sealed blobs through a relay that is blind by
  construction. Access is authorized statelessly: the bucket name is a cryptographic commitment to a
  DEK-derived key ([`D-RA1`](docs/relay-auth-design.md)), so there is no land-grab and no trust-on-
  first-use.
- **Data custody** — the direction the project is heading: *you* own the data and apps are
  **custodians** that request scoped disclosures — a signed [grant](docs/grant-token-design.md), a
  zero-PII [attestation](docs/vault-signing-design.md) ("18+ ✓"), or a borrow the app never keeps.
- **Device trust** — per-device Ed25519 identity and [vault-signed certificates](docs/device-trust-design.md)
  for the multi-device / peer-to-peer / self-hosted-relay world.

## Quickstart

Run the demo — **Node only, no Rust toolchain needed** (the built wasm is committed under
`examples/demo/pkg/`):

```bash
cd examples/demo
npm install
npm run dev
```

Open the printed `http://localhost:5173`:

- **`/`** — the VFS self-test suite (crypto / crash-safety / performance checks, in a worker).
- **`/passkey.html`** — enroll a passkey, add a recovery code and more passkeys, unlock by any method,
  revoke methods, and export/import the key-free bundle.
- **`/custody.html`** — the data-custody showcase: own the data, apps request tiered disclosures,
  revoke enforced at the broker.

WebAuthn needs a secure context (`localhost` qualifies) and a platform authenticator (Windows Hello /
Touch ID) or a security key supporting the WebAuthn `prf` extension.

### Use the SDK

```js
import { FreeholdVault } from '@freehold/db';

const vault = await FreeholdVault.open({
  wasmUrl: new URL('./pkg/freehold.js', import.meta.url), // your wasm-pack output
  rpName: 'My App',
});

await vault.enroll();                     // register passkey, init the empty vault
const code = await vault.addRecoveryCode(); // show ONCE, then forget

await vault.unlock();                     // one passkey ceremony opens a session…
await vault.sql('CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)');
await vault.sql('INSERT INTO notes(body) VALUES (?)', ['hello 🔐']); // …then no more prompts

const bytes = await vault.exportBundle(); // Uint8Array — a .freehold bundle, no key inside
```

See [`packages/db/README.md`](packages/db/README.md) for the full SDK reference (sessions, named
databases, sync, attestations).

### The two-device test

The whole point: unlock the same database on another device with no server ever seeing the key.

1. **Device A** (`/passkey.html`): *Enroll* → *Add recovery code* (write it down) → *Export bundle*
   (downloads `freehold-bundle.freehold` — envelope + encrypted image, **no key inside**).
2. Copy the `.freehold` file to **Device B** and *Import* it.
3. Unlock on B with the **synced passkey** (confirmed for Chrome + Google Password Manager) or the
   **recovery code** (device-independent by construction — always works).

## Build from source

Requires Rust, [`wasm-pack`](https://rustwasm.github.io/wasm-pack/), and clang/LLVM (the SQLite C
sources compile to wasm via `cc`):

```bash
wasm-pack build crates/freehold --target web --release --out-dir ../../examples/demo/pkg
cd examples/demo && npm install && npm run dev
```

Run the end-to-end suite (headless Chromium, virtual authenticator):

```bash
npm install && npx playwright test
```

Recover a bundle **without any Freehold runtime** — the standalone native decryptor turns a
`.freehold` bundle + recovery code into plaintext SQLite, so "self-custody" is verifiable:

```bash
# freehold-decrypt <bundle.freehold> <recovery-code> [out-dir]
cargo run -p freehold-decrypt -- freehold-bundle.freehold "your-recovery-code" ./recovered
```

It writes one `<name>.sqlite` per database — open the result with any `sqlite3`.

## Repository layout

| Path | What |
|---|---|
| `crates/freehold/` | The Rust → Wasm core: encrypting VFS, key envelope, sync, relay-auth, attestations, device certs. |
| `crates/freehold-decrypt/` | Standalone native decryptor (recovery code → plaintext SQLite; no Freehold/SQLite runtime). |
| `packages/db/` | `@freehold/db` — the zero-dependency, typed ESM SDK. |
| `server/relay-server.mjs` | The zero-dependency Node **blind relay** (Connect JSON + SSE; moves only sealed blobs). |
| `proto/` | Frozen `.proto` contracts for the sync and custody message families. |
| `examples/demo/` | Self-test harness + passkey and custody demos (Vite). |
| `examples/custody-app/` | A Quasar app built on the SDK — data custody in a real UI. |
| `tests/` | Playwright end-to-end specs (two-context sync, custody, rotation, attestations). |
| `docs/` | Design docs, reviews, and the audit-readiness packet — [start here](docs/README.md). |

## The pieces, and where each stands

| Layer | Status |
|---|---|
| **Freehold DB** — encrypting VFS, key envelope, DEK rotation, server-blind bundle, standalone decryptor | Working; three adversarial review passes; crash-injection clean. |
| **Freehold Sync** — version-vector engine, blind relay + `HttpRelay`, stateless relay auth (`D-RA1`) | Working; proven end-to-end over a real HTTP relay. |
| **Data custody** — signed grants (`D-DC3`), requester auth (`D-DC2`), zero-PII attestations | Reference implementation + E2E in the custody demo; [protocol documented](docs/data-custody-protocol.md). |
| **Device trust** — per-device identity + vault-signed certs (`D-DT1`) | Increment 1 built; pairing / continuous auth / revocation / federation / threshold recovery [designed and staged](docs/device-trust-design.md). |

## Security

**Status: pre-1.0 security preview — not yet externally audited.** Suitable for evaluation and
development; **not** yet for protecting secrets whose compromise you could not tolerate.

- Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md).
- The threat model, invariant ledger, and design→code map live in
  [`docs/audit-readiness.md`](docs/audit-readiness.md).
- What sync does and does **not** protect: Freehold guarantees *confidentiality* from the sync path
  unconditionally, but not *availability* or *freshness* against a fully-dishonest provider. The
  anti-rollback epochs make staleness **detectable and non-propagating**, not impossible. Run a relay
  you control, or sync device-to-device, for a liveness guarantee. See
  [`docs/sync-epoch-design.md`](docs/sync-epoch-design.md) §2.1.

## Roadmap

- **Device trust, remaining increments** — QR pairing, per-device revocation (CRL floored into the
  sync epoch), federated relays over gRPC/HTTP-2, threshold recovery.
- **External security audit + a real cross-browser/device pass** — the two headline gates for 1.0.
- **Publish `@freehold/db` to npm** (the `@freehold` scope is ours).
- **Broader PRF-stability matrix** — iCloud Keychain, 1Password, mobile, roaming keys.
- **BIP39 checksummed recovery phrases** (currently Crockford-Base32).

Full detail, with decision IDs, in the [design docs](docs/README.md); shipped work in
[`CHANGELOG.md`](CHANGELOG.md).

## Status & lineage

Research-grade, pre-release. Grown from the `enc-sahpool` prototype; all format identity strings were
rebranded at the fork (`freehold-*-v1`; magics: bundle `FREEHOLD`, envelope `FREEHENV`), so bundles or
databases created by the old prototype **do not open here** — re-enroll. The crypto is audited
RustCrypto used as-is; the design and its limits are documented honestly. Not yet independently
audited — don't bet lives on it.

## License

Licensed under either of **MIT** ([`LICENSE-MIT`](LICENSE-MIT)) or **Apache-2.0**
([`LICENSE-APACHE`](LICENSE-APACHE)), at your option.
