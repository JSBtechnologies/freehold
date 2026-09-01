---
slug: header-free-encrypted-vfs
artifact: supply-chain
version: 0.1
status: DRAFT 2026-08-31 — dependency inventory + honest cost/benefit for vendoring via nativelite.
created: 2026-08-31
kind: supply-chain-analysis
---

# Supply-chain inventory + vendoring analysis (nativelite hand-off)

Freehold's trust story is only as good as the code it's built from. This is the full dependency
inventory, what each package does, and — the part that actually matters — an honest read on **whether
vendoring/forking each one through nativelite is worth the effort.**

## TL;DR verdict
**Vendor selectively, not wholesale.** The win is concentrated:
- **Do it** — the Tier-1 crypto core (7 crates) + `getrandom` + `rsqlite-vfs`. Small, stable, audited,
  on the security path, and Tier-1 *is the entire standalone decryptor*. Cheap, high leverage.
- **Evaluate** — `sqlite-wasm-rs`. A real fork (maintaining a SQLite→wasm build); worth it only if you
  want to own the SQLite version + CVE cadence. Biggest lift by far.
- **Skip** — the `wasm-bindgen`/`js-sys`/`web-sys` family. Huge, fast-moving, toolchain-locked, and
  maintained by the Rust/Wasm working group (high trust). Poor effort-to-trust ratio.
- **Eliminate, don't vendor** — `tokio` (one mutex) and `thiserror` (a derive). Removing them shrinks
  the surface more cheaply than vendoring them.
- **Reality check** — vendoring is *defense-in-depth* against a vector Cargo already partly closes
  (see below). It ranks **below an external audit and real-device testing** for actual assurance.
  Don't let a vendoring project displace those.

## What Cargo already gives you (so we don't overstate the gain)
- **Source, not binaries.** crates.io distributes *source* crates that you compile locally — the
  npm-style "malicious prebuilt binary / postinstall script" vector largely does not apply.
- **`Cargo.lock` pins exact versions + SHA-256 checksums** of every crate, transitive included. A
  swapped/republished package fails the checksum. So day-to-day tamper protection mostly exists today.
- **Residual risks vendoring actually closes:** a malicious *new version* you upgrade into (typosquat
  / maintainer-account compromise), crates.io availability/yanking, and code that executes **at build
  time** (`build.rs`, proc-macros like `thiserror`/`wasm-bindgen`). These are the real reasons to
  vendor — provenance, offline reproducibility, and the ability to audit/patch — not "stop a binary
  swap," which the lockfile already handles.

## The inventory — role + nativelite action

### Tier 1 — crypto trust core · *pure Rust, vendor + reproducible-build (no fork)*
Audited RustCrypto (+ dalek), used unmodified. All of it except `ed25519-dalek` is also the **complete
dependency set of `freehold-decrypt`**, so vendoring that subset yields a fully self-hosted recovery
tool. **Clearly worth it.**

| Package | ver | Role in Freehold |
|---|---|---|
| `chacha20poly1305` | 0.10.1 | THE cipher — per-block DB encryption, envelope slot-wrapping, `seal_bytes`/`open_bytes` (epoch tokens, rotation intent). |
| `argon2` | 0.5.3 | Recovery-code KEK (`kek_from_recovery`); params are pinned in *our* code, not the crate. |
| `hkdf` | 0.12.4 | Every subkey — db/pool/anchor/epoch/sync keys, the MAC key, the passkey-PRF KEK, `sync_id`, the vault-identity signing seed. |
| `sha2` | 0.10.9 | SHA-256 backing HKDF, `file_id`, the Merkle root, the recovery checksum. ⚠️ pin the pure-Rust backend (not asm) for reproducibility. |
| `hmac` | 0.12.1 | The envelope-wide MAC (anti-rollback authenticator). |
| `ed25519-dalek` | 2.x | The vault-**identity** signing key (verifiable tier-2 attestations); DEK-derived seed, sign/verify only. Audited (Quarkslab, 2019). **`freehold` only — NOT in `freehold-decrypt`** (attestations never travel in a `.freehold` bundle). |
| `zeroize` | 1.9.0 | Wipes DEK/KEK/scratch (volatile writes + fences). Keep as-is; don't reimplement. |
| *transitive* | — | `subtle` (constant-time), `cpufeatures`, `digest`, `crypto-common`, `cipher`, `aead`, `poly1305`, `universal-hash`, `generic-array`, `typenum`, `base64ct`, `password-hash`, and (via dalek) `curve25519-dalek`, `ed25519`, `signature`, `curve25519-dalek-derive` … — vendor the closure. |

### Tier 1b — platform RNG · *vendor + pick the backend per target*
| `getrandom` | 0.2.17 | The only randomness source (nonces, DEK, salts, recovery entropy). A shim over the platform CSPRNG: `crypto.getRandomValues` on wasm (`js` feature), the OS on the native decryptor. nativelite's job is **backend selection per target**, not a fork. |

### Tier 2 — young / on the security path · *vendor WITH review (or fork)*
| `rsqlite-vfs` | 0.1.1 | The VFS trait layer (`SQLiteVfs`/`SQLiteIoMethods`/`VfsFile`/`VfsStore`) that lets `vfs.rs` register our encrypting block device with SQLite. `0.1.x`, single-maintainer, directly on the I/O path → read line-by-line + vendor. Small. **Worth it.** |

### Tier 3 — large C surface · *fork / rebuild*
| `sqlite-wasm-rs` | 0.5.5 | SQLite-compiled-to-wasm + the `WasmOsCallback` OS shim. **The fork.** Build SQLite from a pinned amalgamation with known flags → wasm; we need only core SQLite + the OS callback (not the `sqlite3mc` codec — unused). Biggest effort; **worth it only for SQLite version/CVE control + reproducibility.** |

### Tier 4 — standard glue · *mostly skip; two to eliminate*
| Package | ver | Role | Call |
|---|---|---|---|
| `wasm-bindgen` (+`-futures`) | 0.2.127 / 0.4.77 | The Rust↔JS boundary; every export + async bridging. Proc-macro **and** `wasm-bindgen-cli` must version-match. | **Skip** — huge, toolchain-locked, high-trust maintainers. |
| `js-sys` | 0.3.104 | JS built-ins we touch (`Object`/`Reflect`/`Uint8Array`/`JSON`/`Array`). | **Skip.** |
| `web-sys` | 0.3.104 | The OPFS surface (`FileSystemSyncAccessHandle`, `StorageManager`, dir handles). | **Skip** (feature-gated already). |
| `tokio` | 1.53.1 | **Only** `sync::Mutex` — one VFS registration guard. | **Eliminate**, don't vendor — huge crate for one mutex (contained refactor). |
| `thiserror` | 2.0.20 | Derive macro for error enums. | **Eliminate** if you want zero proc-macro surface (hand-write `Display`/`Error`). |
| `console_error_panic_hook` | 0.1.7 | Panics → `console.error`. | Already **gated out of prod** (`--no-default-features`). Lowest priority. |

### JS / npm
Nothing to hand off. The `@freehold/db` SDK ships **zero runtime dependencies** (only dev tooling:
`vite`, `@playwright/test`). Keep it that way — treat any future runtime dep as a security decision.

## A lighter alternative to forking everything
If the goal is provenance + reproducibility + tamper-detection (not maintaining forks), most of the
benefit is available far more cheaply than a fork-per-crate:
- **`cargo vendor`** into an in-tree `vendor/` + a committed `Cargo.lock` → offline, pinned, auditable
  builds without owning each crate.
- **`cargo audit`** (RUSTSEC) + **`cargo deny`** → CVE + license + duplicate gating.
- **Reproducible-build verification** (build twice, diff artifacts) as nativelite's actual job — prove
  the shipped wasm/binary corresponds to the pinned source, rather than re-hosting every dependency.
- **`cargo-crev`** review proofs for the handful of crates on the trust path.

This captures the real residual risks (new-version swaps, build-time code execution, availability)
with a maintenance cost closer to zero, and reserves true forks for the two crates that genuinely
warrant them (`rsqlite-vfs`, `sqlite-wasm-rs`).

## Where this sits against the other release gates
Ranked by assurance-per-effort for a pre-1.0 crypto product: **external audit > real-device/browser
testing > reproducible builds + `cargo audit`/`vendor` > selective vendoring of the crypto core >
wholesale forking.** Vendoring is worth doing at the top of that list (crypto core + the reproducible-
build harness); the wholesale fork is the least leverage and easiest to over-invest in.

## Cross-links
[[header-free-encrypted-vfs]] design-spec (trust boundary), [[bundle-format]] (the decryptor whose
whole dependency set is Tier 1), [[dek-rotation-design]].
