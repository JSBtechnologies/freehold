---
title: Freehold grant tokens (counterparty-verifiable grants)
status: BUILT (reference) 2026-09-02
depends-on: vault-signing-design.md (the Ed25519 attestation primitive reused as-is), requester-auth-design.md
  (the verified app_id a grant is bound to), data-custody-protocol.md §5.4/§6, custody-v1 proto `Grant`
decisions: D-DC3 (grant `proof` is an Ed25519 signature over the claims — not a broker-local / DEK-MAC token)
---

# Freehold grant tokens (D-DC3)

## §1 — Problem: a broker-local grant is only checkable by that broker

The custody broker records a grant as a random id (`g_…`) in the vault's own DB and enforces it on each
`call`. That is correct for the *broker↔app* loop, but the token is **symmetric**: only the broker that
minted it can validate it. The custody-v1 proto anticipated more — `Grant.proof` was documented as
"a DEK-MAC today, an Ed25519 signature once counterparty-verifiable grants are wanted (D-DC3)." This
item delivers that upgrade: a grant a **third party** can verify without the broker and without any
shared secret — e.g. an app proving to a payment processor that the owner authorized a tier-3 borrow.

## §2 — Design: the grant is a signed attestation over its claims

A grant token is the vault's **Ed25519 identity signature** over a canonical encoding of the grant —
reusing the audited attestation primitive (vault-signing-design.md), **no new crypto**:

```
claim = JSON{ v:"freehold-grant-v1", grantId, appId, tier, scopes(sorted), purpose, issuedAt, expiry }
proof = Ed25519(vault_identity, canonical_attestation(claim, audience = app_id, issuedAt, expiry))
token = { grantId, appId, tier, scopes, purpose, issuedAt, expiry, attestation:{claim,audience,…,publicKey,signature} }
```

- **`claims` = the canonical `claim` string**, **`proof` = the Ed25519 signature** — exactly the
  custody-v1 proto `Grant` fields (the proto is unchanged / still frozen, D-DC5).
- The **audience is the verified `app_id`** (D-DC2), so a token is bound to the app it was granted to
  and cannot be presented as another app's authorization.
- A fixed-key JSON claim with **sorted scopes** is deterministic: any verifier recomputes it byte-for-
  byte from the token's structured fields.

## §3 — Verification (counterparty-side, no DEK, no broker)

`verifyGrantToken(deps, token, expect)` (`examples/demo/custody/grant-token.js`) needs only the vault's
**pinned public key** and the pure `verifyAttestation` reference. It checks, in order:

1. `token.attestation.claim === canonicalGrantClaim(token)` — the signed claim must equal the claim
   recomputed from the presented fields, so **a valid signature cannot be re-paired with different
   claims** (tamper-evidence);
2. the requested `scope` (if any) is in `token.scopes`;
3. `audience == app_id`, the **signer is the pinned vault key**, the Ed25519 signature verifies, and the
   token is not expired.

Pinning the expected vault key in step 3 is essential: verifying only the key *embedded* in the token
would let anyone sign their own grant. A real remote party may run the same check with any Ed25519
library over the documented canonical message — the reference implementation just reuses the vault's
pure verify.

## §4 — What was built (reference: the custody demo)

| Piece | File | Role |
|---|---|---|
| Canonical claim + issue + verify | `examples/demo/custody/grant-token.js` (new) | `canonicalGrantClaim`, `issueGrantToken`, `verifyGrantToken` |
| Broker mints a token on grant | `examples/demo/custody/broker.js` | signs claims via `vault.attest`; returns the token to the app |
| App stores its token | `examples/demo/custody/app-client.js` | `client.grantToken` |
| Counterparty verify + E2E | `examples/demo/custody/main.js`, `tests/custody-e2e.spec.js` | verify with the pinned key; a tampered token is rejected |

## §5 — Scope & honest limits

- **Reference vs. showcase**: as with D-DC2, the mechanism + E2E land in the custody *demo* (the
  protocol reference); the Quasar showcase adopts the identical issue/verify as isolated follow-up.
- **Revocation is still broker-side**: a signed token proves *authorization at issue time*; it does not
  self-revoke. Short TTLs bound exposure (default 1 h); a counterparty needing live revocation still
  consults the broker/ledger (or a future short-lived re-issue / status endpoint). The vault's grant
  table + `revokeApp` remain the authority for the broker↔app loop.
- **No new key**: grant tokens are signed by the *same* DEK-derived vault identity key as tier-2
  attestations, domain-separated by the `freehold-grant-v1` claim label — a grant claim can never be
  mistaken for an `over18`-style attestation and vice-versa.
- **Purpose/scope semantics** are carried verbatim; the counterparty still applies its own policy
  (which scopes it accepts, acceptable TTL) on top of a cryptographically valid token.
