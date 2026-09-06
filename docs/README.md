# Freehold documentation

Design-first: every part of the security model is specified in a design doc, reviewed, and *then*
built. This is the map. Each doc states its decisions with stable IDs (e.g. `D-RA1`, `D-DT1`) that
the code and commit messages reference back to.

New here? Read [`design-spec.md`](design-spec.md) for the database core, then
[`data-custody-protocol.md`](data-custody-protocol.md) for where the project is headed. If you are
evaluating the crypto, start with [`audit-readiness.md`](audit-readiness.md).

---

## Core database

The passkey-unlocked, end-to-end-encrypted SQLite engine.

| Doc | What it specifies |
|---|---|
| [`design-spec.md`](design-spec.md) | The encrypting VFS, key envelope, and the normative §17 guarantee list (v1.1). |
| [`bundle-format.md`](bundle-format.md) | The `.freehold` server-blind bundle format (envelope + encrypted image, no key inside). |
| [`dek-rotation-design.md`](dek-rotation-design.md) | Physical re-encryption under a fresh DEK, crash-safe behind a two-store commit barrier — true device eviction. |
| [`convenience-tier-design.md`](convenience-tier-design.md) | Opt-in device-key auto-unlock (`KIND_DEVICE` slot, stripped from exports). |

## Sync & transport

Server-blind synchronization: a relay moves sealed blobs and never sees a key.

| Doc | What it specifies |
|---|---|
| [`sync-epoch-design.md`](sync-epoch-design.md) | Peer-attested anti-rollback — freshness that survives a dishonest provider. |
| [`transport-design.md`](transport-design.md) | The frozen relay `.proto` contract and the topology-vs-transport axes (Connect at the edge, gRPC/HTTP-2 relay↔relay, WebRTC direct). |
| [`relay-auth-design.md`](relay-auth-design.md) | `D-RA1` — stateless blind-relay authorization: `sync_id` is a commitment to a DEK-derived key; no land-grab, no TOFU. |

## Data custody

The direction: you own the vault; apps are *custodians* that request scoped disclosures.

| Doc | What it specifies |
|---|---|
| [`data-custody-protocol.md`](data-custody-protocol.md) | The custody model — owner-held data, tiered disclosure (custodian / attestation / borrow), the Local / Sync / Disclosure planes. |
| [`vault-signing-design.md`](vault-signing-design.md) | The vault Ed25519 identity and verifiable tier-2 attestations ("18+ ✓" with no PII on the wire). |
| [`requester-auth-design.md`](requester-auth-design.md) | `D-DC2` — apps authenticate with a key-committed `app_id`, not a phishable origin/name. |
| [`grant-token-design.md`](grant-token-design.md) | `D-DC3` — counterparty-verifiable grants: the vault signs the claim; anyone verifies against the pinned public key. |

## Device trust

Per-device identity for the multi-device / peer-to-peer / self-hosted-relay world.

| Doc | What it specifies |
|---|---|
| [`device-trust-design.md`](device-trust-design.md) | `D-DT1..6` — device certificates chaining to an independent vault trust key, QR pairing, continuous auth, two-tier revocation, federated relays, threshold recovery. Increment 1 (identity + certs) is built; the rest is staged. |

## Security & assurance

| Doc | What it records |
|---|---|
| [`audit-readiness.md`](audit-readiness.md) | The full threat model, invariant ledger, and design→code map — the entry point for a reviewer. |
| [`security-review.md`](security-review.md) · [`adversarial-review.md`](adversarial-review.md) | The internal review record (three adversarial passes on the VFS core). |
| [`BUILD-NOTES.md`](BUILD-NOTES.md) | The honest guarantee ledger: what is proven, what is a backstop, what is out of scope. |
| [`supply-chain.md`](supply-chain.md) | Dependency inventory and the "audited primitives, used as-is" discipline. |

---

## Conventions

- **No invented crypto.** Only audited RustCrypto / dalek and WebCrypto primitives, used as-is.
- **Design before code.** Anything touching the crypto/security model gets a design doc and sign-off
  first; the doc's decision IDs are load-bearing references in the code.
- **Honest limits.** Every doc states what it does *not* guarantee. See the `## Open questions` /
  `## Known limitations` sections.
