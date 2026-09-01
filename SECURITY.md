# Security Policy

## Status: pre-1.0 security preview — not yet externally audited

Freehold is passkey-unlocked, end-to-end-encrypted SQLite for the browser. The cryptographic design
is deliberate and conservative (see below), but **it has not undergone an external security audit.**
Treat the current `0.x` line as a **security preview**: suitable for evaluation and development, **not**
yet for protecting secrets whose compromise you could not tolerate. The `.freehold` bundle and key
envelope formats are frozen at v1/v3 respectively but may still change before 1.0.

## Reporting a vulnerability

Please report suspected vulnerabilities privately — do **not** open a public issue for a security bug.
Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability), or
email the maintainers. We aim to acknowledge within a few days. Coordinated disclosure is appreciated;
we will credit reporters who wish to be named.

## Security model (summary)

- **No server ever sees a key or plaintext.** A random 256-bit DEK encrypts every DB block; it is
  wrapped by per-method KEKs in a key envelope and never persisted in the clear. Sync/export move only
  ciphertext + non-secret lineage metadata.
- The DEK is unwrapped **inside a Web Worker** via a WebAuthn passkey's PRF output (or a recovery
  code), held only in wasm memory until lock, and zeroized on drop.
- Audited RustCrypto primitives, used as-is (XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, Argon2id).
  No invented cryptography.
- Anti-rollback: a DEK-keyed envelope MAC + generation floor, and a trusted-generation anchor for the
  DB image. DEK rotation cryptographically evicts a compromised device from future state.

See `docs/audit-readiness.md` for the full threat model, invariant ledger, and design→code map, and
`docs/design-spec.md` §17 for the normative guarantee list.

## Known limitations (honest, by design)

- **Not externally audited** (the headline gate before 1.0).
- **Rotation protects future state only** — it cannot un-leak data a compromised device already
  exfiltrated, nor re-encrypt old exported copies an attacker kept (they still open under the old DEK).
- **The local anchor is a backstop**, not a guarantee: an attacker who can rewrite *all* storage can
  also wipe it (that is deletion/DoS, not a confidentiality break); cross-device freshness is bound
  into the sync epoch.
- **The pool's registration data (holding the DEK) is a leaked `'static`** that survives until the
  worker is torn down; a locked session cannot reach it (no VFS, no handles).
- **Testing is single-browser** (headless Chromium) with a *virtual* authenticator; real
  Safari/iOS/Firefox behavior is not yet verified. There is currently no CI.
- Side channels (timing/cache) and the correctness of the browser's own WebAuthn/OPFS implementations
  are out of scope.

## Supported versions

Pre-1.0: only the latest `0.x` on `main` receives fixes. No LTS or backport guarantees yet.
