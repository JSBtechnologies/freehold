---
title: Freehold requester authentication (Disclosure-plane app identity)
status: BUILT (reference) 2026-09-02
depends-on: data-custody-protocol.md §5.1 (requester identity), relay-auth-design.md (the same
  pubkey↔id commitment pattern, on the Sync plane), vault-signing-design.md (Ed25519 discipline)
decisions: D-DC2 (apps authenticate with a key-committed app_id, not a phishable origin/name)
---

# Freehold requester authentication (D-DC2)

## §1 — Problem: a self-asserted app identity is phishable

The custody broker (data-custody-protocol.md, Local plane) mediates every third-party app's access to
the vault. But *which* app is asking was, until now, **self-asserted**: the host wired
`broker.connect(port, appId)` with a string, or in production the broker would trust the connecting
**origin**. Origin/name identity is phishable:

- a lookalike app (typosquatted origin, or a malicious app simply claiming `appId: "Notes"`) could
  **piggyback on another app's grants**, or
- **misrepresent itself in the consent prompt** ("Notes wants access") to harvest a grant under a
  trusted name.

Blindness and capability-scoping don't help here — the owner is about to *consent*; the question is
whether the identity they're consenting to is real.

## §2 — Design: an app_id that is a commitment to the app's key

Each app holds an **Ed25519 keypair** (WebCrypto; browser + Node — no invented crypto). Its identity is
a **commitment to the public key**, exactly like the relay-auth `sync_id` (D-RA1) on the Sync plane:

```
app_id = "app_" + base64url( SHA-256("freehold-app-id-v1" ‖ pubkey) )[..12 bytes]
```

The broker authenticates an app **statelessly, with no registry**, over a challenge-response handshake
on connect (`examples/demo/custody/app-identity.js`):

1. broker → app:  `{ challenge }`  (a fresh 32-byte nonce, bound to this connection — anti-replay);
2. app → broker:  `{ manifest = {app_id, name, pubkey, alg}, sig }` where
   `sig = Ed25519(app_key, "freehold-app-auth-v1" ‖ app_id ‖ challenge)`;
3. broker verifies, in order:
   - **`app_id == SHA-256(LABEL ‖ pubkey)[..12]`** — the id commits to the key (the anti-impersonation
     check: a forger claiming a victim's `app_id` with a *different* key fails here, because they can't
     invert SHA-256 to produce the committed pubkey); then
   - the **Ed25519 signature** over `(app_id ‖ challenge)` under `pubkey`.

Only on success does the broker **bind this port to the verified `app_id`** and register it. Every
later `request`/`call` uses that bound id — the broker **never** trusts an id in a message field. Grants
are recorded and enforced against the verified id, and the consent prompt shows the verified `app_id`
alongside the (advisory) self-asserted `name`.

## §3 — Why this is the right shape

- **No central registry / no CA.** The id *is* the key fingerprint; ownership is provable by signature.
  (A human-friendly directory mapping `name → app_id`, TOFU-pinned by the user or served from an app's
  `/.well-known`, can sit on top later — but is not required for the security property.)
- **Symmetry with the Sync plane.** Relay-auth binds `sync_id = H(relay_auth_pubkey)` (D-RA1); requester
  auth binds `app_id = H(app_pubkey)`. Same commitment discipline, same "possession of the key *is* the
  identity" guarantee, on both planes.
- **The consent gesture is meaningful.** The owner consents to a cryptographic identity, not a spoofable
  label; a lookalike cannot borrow a trusted app's name to obtain a grant.

## §4 — What was built (reference: the custody demo)

| Piece | File | Role |
|---|---|---|
| App identity + challenge/verify | `examples/demo/custody/app-identity.js` (new) | `generateAppIdentity`, `signChallenge`, `verifyHello`, `appIdFromPubkey` |
| Broker requires an authenticated handshake | `examples/demo/custody/broker.js` | `connect(port)` (no asserted id); binds the port to the verified `app_id` |
| App performs the handshake before requesting | `examples/demo/custody/app-client.js` | signs the challenge; `ready()` gates `request`/`call` |
| Host wiring + consent shows verified id | `examples/demo/custody/main.js` | per-app identities; revoke by verified id |
| E2E: full flow + impersonation rejected | `tests/custody-e2e.spec.js` | a forged manifest claiming a victim's id is refused (`authed:false`) |

## §5 — Scope & honest limits

- **This is the Disclosure plane** (third-party apps ↔ the vault broker). It is distinct from and
  complementary to Sync-plane **relay authentication** (a vault ↔ its own relay buckets, D-RA1).
- **Reference vs. showcase.** The mechanism + tests land in the custody *demo*, which the protocol docs
  treat as the reference implementation. The Quasar *showcase*
  (`examples/custody-app/`) runs same-origin/same-page today (its apps are trusted local components);
  adopting the identical handshake there is isolated UI plumbing (its broker + inline client + consent
  dialog), tracked as a follow-up — no protocol change.
- **Grant tokens are still symmetric** here (a broker-local grant id). Making a grant *counterparty-
  verifiable* (an Ed25519-signed `{claims, proof}`) is D-DC3, tracked separately.
- **Key custody for the app** is the app's problem (a real app persists its key in its own origin
  storage / a platform keystore). The broker only ever sees the public key + signatures.
- **No per-app key rotation / revocation-of-identity** yet: revoking a *grant* is supported; rotating an
  app's identity key (and re-pinning) is a future item.
