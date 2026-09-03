---
title: Freehold relay authentication (blind-relay access control)
status: BUILT 2026-09-02
depends-on: transport-design.md (the Connect Sync plane this authorizes), vault-signing-design.md (the
  audited Ed25519 primitive reused as-is), data-custody-protocol.md §2/§8 (blindness bound)
decisions: D-RA1 (sync_id is bound to the relay-auth public key → stateless authorization)
---

# Freehold relay authentication

## §1 — Problem: blindness ≠ authorization

The blind relay (transport-design.md, `server/relay-server.mjs`) proves a strong *confidentiality*
property: it only ever moves opaque sealed bytes under an opaque routing label, so losing its store
leaks ciphertext + labels and nothing else. But confidentiality says nothing about **access**. As
shipped for the transport increment the relay trusted *any* writer:

- anyone who learned a `sync_id` could **append** blobs — storage exhaustion, or poison blobs that a
  peer wastes work failing to AEAD-open;
- anyone could **enumerate/pull** a bucket (still ciphertext, but a metadata + resource leak).

This item closes that gap **without the relay ever seeing the DEK** and **without inventing crypto** —
it reuses the audited Ed25519 primitive already used for vault-identity attestations (attest.rs).

## §2 — The access contract (what the relay must enforce)

A bucket belongs to *whoever holds the DEK it was derived from*. The relay must let exactly those
devices push/list/get/subscribe on it, must not be forgeable by the relay operator, and must not learn
the DEK. Concretely, for every op the relay requires proof that the caller possesses the per-database
DEK-derived key that the bucket is named after — checked statelessly, with no per-bucket ownership
record to attack or lose.

## §3 — Design

### §3.1 Per-database relay-auth key (DEK-derived, unlinkable)

```
seed   = HKDF(DEK, "freehold-sync-relay-auth-v1" ‖ db_uuid)
sk     = Ed25519(seed)          pubkey = sk.public       (crates/freehold/src/relay_auth.rs)
```

Per-`db_uuid` (not one key per vault) so two databases of one vault present *different* public keys to
the relay — it cannot link a user's buckets by a shared key, matching the per-DB unlinkability
`sync_id` already gives. Deterministic across a user's devices (they share the DEK), held in
`Zeroizing`, re-derived on unlock, dropped on lock — identical lifecycle to the vault identity key. The
DEK never leaves the worker; only `pubkey` and per-op signatures cross out.

### §3.2 sync_id is BOUND to the public key — D-RA1 (stateless, no land-grab)

```
sync_id = SHA-256("freehold-sync-id-v1" ‖ pubkey)[..16]
```

The relay authorizes an op with a check needing **no state**:

1. the request carries `(pubkey, sig)`;
2. `sync_id == SHA-256(LABEL ‖ pubkey)[..16]` — the bucket name *commits* to the key; and
3. `sig` verifies over the canonical op message under `pubkey` (Ed25519 `verify_strict`).

Possession of the bucket therefore **is** possession of the DEK-derived key. There is no
trust-on-first-use window for a stranger to race: to present a `pubkey` hashing to a target `sync_id`
they would have to invert SHA-256. This is strictly stronger than a TOFU ownership record (which a
stranger who *observed* a `sync_id` could land-grab before the owner first connected) and needs no
per-bucket server state. `sync_id` stays 16 opaque bytes, deterministic across devices, unguessable,
and reveals nothing — it is now *additionally* a commitment to the key. (Its derivation moved from a
direct `HKDF(DEK, "sync-id-v1" ‖ db_uuid)` into `relay_auth`; pre-1.0, no deployed relay data moves.)

### §3.3 The signed message (domain-separated, length-prefixed)

```
msg = "freehold-relay-auth-v1" ‖ u8(method) ‖ sync_id(16) ‖ u32_LE(arg.len) ‖ arg
      method ∈ { 1 Push, 2 List, 3 Get, 4 Subscribe }
```

- A **Push** signs `arg = the exact sealed blob bytes`, so a captured Push signature cannot be replayed
  to store *different* bytes (a network attacker cannot substitute a poison blob under a valid sig).
- **Reads** (List/Get/Subscribe) sign `arg = empty`: they are idempotent, and binding the cursor adds
  nothing over the pubkey↔bucket commitment — so one read credential is reused across a sync pass
  (≤ 3 signatures per `sync()`: one List, one Get if anything is pulled, one Push).

Verification is **pure** (public key only, no DEK): the relay recomputes `msg` and checks Ed25519.
The construction mirrors attest.rs (same domain-separation discipline); the Rust `relay_auth` module
and `server/relay-server.mjs` build byte-identical messages, cross-checked by the E2E.

### §3.4 Rate limiting

A per-`pubkey` token bucket (`server/relay-server.mjs`) bounds an *authorized-but-misbehaving* device
(the signature check already stops unauthorized ones from consuming storage at all). Defaults are
generous (burst 500, 100/s refill) so dev/tests never trip them; a production relay tunes them and adds
a coarse per-connection/IP layer in front.

## §4 — What was built

| Piece | File | Role |
|---|---|---|
| Auth key + sign/verify + `sync_id` binding | `crates/freehold/src/relay_auth.rs` (new) | single source of truth; `self_check()` in `run_tests` |
| `sync_id` moved out of the crypto core | `crates/freehold/src/crypto.rs` | keeps the AEAD core scoped |
| wasm `session_relay_sign(db_uuid, method, arg)` | `crates/freehold/src/lib.rs`, `vfs.rs` | signs in the worker; DEK stays in the pool |
| `sync()` signs every op; `relayAuth()`/`syncId()` public API | `packages/db/index.js`, `index.d.ts` | auto-auth on the hot path; raw-op signing for custom relays |
| `HttpRelay` forwards `{pubkey,sig}` | `packages/db/relay-http.js`, `.d.ts` | Connect JSON fields |
| Stateless verify + `sync_id==H(pubkey)` + rate-limit | `server/relay-server.mjs` | Node built-in `crypto` only (zero-dep) |
| E2E: unsigned push rejected; authed Subscribe | `tests/sync-http-e2e.spec.js`, `examples/demo/sync-http-test.html` | proves enforcement |

## §5 — Blindness & unlinkability preserved

The relay still sees only: an opaque `sync_id`, opaque sealed blobs, and now an opaque per-DB `pubkey`
+ signatures. `pubkey` is a uniform Ed25519 point derived from `HKDF(DEK, …‖db_uuid)`; it reveals
nothing about the user or contents, and being per-DB it does **not** let the relay group a vault's
buckets. Verification uses only public values. The §2/§8 leakage bound of the data-custody protocol is
unchanged.

## §6 — Honest limits (residual)

- **Metadata still leaks** to the relay: bucket existence, blob count/sizes, and timing per `sync_id`.
  Authorization does not hide traffic analysis; that is the transport's stated bound.
- **A compromised DEK-holder** is authorized by construction (it *is* the vault). Rate limiting only
  bounds its request rate; there is no per-device revocation at the relay (all devices share the key).
  Device-scoped relay keys + a revocation list are a future item.
- **No requester/app authentication** — this authorizes the *sync* plane (a vault talking to its own
  buckets), NOT the *disclosure* plane (third-party apps). That is D-DC2 (manifest / app-key auth),
  tracked separately.
- **Reference store is in-memory**; a production relay swaps in durable storage behind the same checks.
- **`sync_id` is visible on the wire** (under TLS) to any DEK-holder that sends it; a passive relay-log
  observer sees `sync_id`+`pubkey` but cannot write (no private key) — the D-RA1 commitment is what
  makes observing a `sync_id` useless for hijacking.
