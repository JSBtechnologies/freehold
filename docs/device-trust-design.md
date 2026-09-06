---
title: Freehold device trust — identity, pairing, continuous auth, federation & threshold custody
status: Increment 1 (device identity + certs) implemented and reviewed; increments 2-6 (pairing, revocation, federation, threshold recovery) designed and staged. Hardened via 6-lens adversarial review.
depends-on: relay-auth-design.md (D-RA1 bucket auth), requester-auth-design.md (D-DC2 app identity),
  grant-token-design.md (D-DC3 signed-claim shape reused for certs), vault-signing-design.md
  (D-VS1 vault identity; D-VS2 the independent trust key this doc adopts as the device-cert root),
  dek-rotation-design.md (hard eviction; env/epoch binding), sync-epoch-design.md (epoch floor),
  transport-design.md (the Connect/relay wire)
decisions: D-DT1 device PKI · D-DT2 pairing handshake · D-DT3 continuous auth · D-DT4 revocation ·
  D-DT5 threshold recovery (post-1.0 gate) · D-DT6 federated-relay topology
hardening: reviewed across 6 expert lenses (prior-art, browser-platform, pragmatism/scope, crypto,
  invariants, protocol); 18 findings confirmed. This revision lands all six must-fix items and the
  hardened changes. See §10 for the resolution log.
---

# Freehold device trust

## §0 — Why this exists

Everything shipped so far authenticates *possession of the DEK* — a device is anonymous ("someone with
the key"). That is enough for one device, and for a vault talking to its own relay buckets (D-RA1). It is
**not** enough for the multi-device, peer-to-peer, self-hosted-relay world we want:

- adding a device today means shipping the `.freehold` bundle + a **recovery code** out of band —
  anyone who intercepts both becomes a full member, with no per-device consent and no MITM protection;
- there is no notion of *which* device did something — no per-device audit, and (see the honest caveat in
  §4) no per-device revocation stronger than rotating the whole DEK;
- a mesh of relays / P2P links has nothing to mutually authenticate with.

This doc gives devices a real **identity** (a keypair + a certificate that chains to an independent vault
**trust key**), a **pairing handshake** rooted in a human gesture on an already-trusted device,
**continuous** (not one-shot) auth, per-device **revocation** with an honest eviction boundary, and the
**federated blind-relay topology** the transport rides on — plus **threshold recovery** (post-1.0) so no
single device or relay holds the whole key. It reuses the audited Ed25519 / HKDF / XChaCha20-Poly1305
primitives already in the core — **no invented crypto**.

> **Trust-root decision (adopted).** Device certs chain to an **independent, non-DEK-derived Ed25519
> "vault trust key"** (§1), i.e. vault-signing D-VS2's already-named deferred upgrade — *not* to the
> DEK-derived vault identity (D-VS1). This is what lets a cert mean something beyond "a DEK-holder signed
> this" and lets it **survive DEK rotation**. The DEK-derived-interim alternative is documented in §1.4
> only as a rejected fallback.

## §1 — Device identity: a certificate chaining to an independent vault trust key (D-DT1)

### §1.1 The trust root is independent of the DEK

The device PKI is rooted in a **vault trust key** — a standalone Ed25519 keypair, generated once per
vault:

```
vault_trust_sk = a 32-byte CSPRNG seed (getrandom, fail-closed — same discipline as envelope::random_dek)
vault_trust_pk = Ed25519 public key of that seed
```

The private half is **never DEK-derived**. It is sealed as its **own envelope slot** under
`HKDF(DEK, "freehold-vault-trust-v1")` and carried in the `.freehold` bundle — exactly the upgrade
vault-signing-design D-VS2 already defers. Consequences that the *DEK-derived* framing could not deliver:

- **Certs survive DEK rotation.** The §4 hard-eviction path rotates the DEK; because certs chain to the
  trust key (which stays stable across DEK rotation — see §1.5), surviving certs still verify. Eviction
  becomes a **CRL entry**, not universal cert re-issuance.
- **"Issue a cert" is a distinct act from "hold the DEK."** A DEK-derived signer is byte-identical on
  every device (attest.rs), so a cert signed by it proves only DEK possession — precisely what D-RA1
  already proves per-op. Rooting in the trust key makes the cert a real, independent statement.

### §1.2 Membership model: per-device key + cross-sign (Matrix/Keybase)

Each device generates its **own** Ed25519 keypair on-device (§1.6); the private key never leaves it. Its
identity is a commitment to that key — the same discipline as `sync_id` (D-RA1) and `app_id` (D-DC2):

```
device_id = "dev_" + base64url( SHA-256("freehold-device-id-v1" ‖ device_pubkey) )[..12 bytes]
```

Membership follows the **Matrix/Keybase cross-signing** model, not a monolithic CA:

- each device **self-signs** its own key (proves possession);
- an **already-trusted device cross-signs** it — a **device certificate** chaining to the **vault trust
  key** binds the device key into the vault.

So each device key is its own identity, and revoking one device neither invalidates the root nor lets a
compromised DEK-holder mint a fresh keypair that bypasses the CRL (the cross-sign, not mere DEK
possession, is what admits a device).

### §1.3 Certificate encoding — reuse the attest / grant-token shape (no new signing surface)

The cert is a **grant-token-shaped object (D-DC3) minted through the existing `attest` path** — *not* a
new `canonical{…}` object, and there is no `attest_canonical` (it does not exist). `attest.rs` signs a
flat, domain-separated, length-prefixed message carrying **one** opaque UTF-8 claim string; grant-token
already solved binding several structured fields inside that single string. Reuse it verbatim:

```
cert.claim  = base64url-of a length-prefixed byte layout:
                domain "freehold-device-cert-v1"
                ‖ u16-len-prefixed { vault_trust_pubkey, device_id, device_pubkey,
                                     caps (sorted scope list), issued_at, expiry }
cert.proof  = attest( claim, audience = device_id, issued_at, expiry )   // signed by vault_trust_sk
```

- **Length-prefixed, never ad-hoc delimiters.** A field value could contain `|`/`=`; u16 length prefixes
  remove any canonicalization ambiguity (the same reason vault-signing §2 chose a flat string).
- **Recompute-and-byte-compare tamper check (grant-token step 1).** The verifier rebuilds the canonical
  claim from the cert's structured fields and requires **byte-equality** *before* trusting the signature.
- **`caps` is a sorted scope list** (grant-token's attenuable vocabulary), not a bare enum — so device
  authority and disclosure authority share one canonical, attenuable representation.

Verification (`verify_device_cert`, pure, no DEK) checks, in order: recompute-and-byte-compare;
`device_id == H(device_pubkey)`; Ed25519 signature via `attest::verify` (`verify_strict`) under the
**pinned `vault_trust_pubkey`**; validity window against a caller-supplied `now` (the core reads no
clock); `caps`.

`caps` distinguishes membership classes:

- **full member** — has the DEK (delivered via pairing, §2), reads/writes/syncs all vault data;
- **custodian / thin** — no DEK; only scoped disclosures through the broker/grant model (D-DC2/D-DC3).
  (Pairing your own devices issues *full member* certs; the thin class is the app-custody model.)

### §1.4 Rejected interim (documented, not adopted)

*DEK-derived-for-now:* sign certs with the existing DEK-derived vault identity (D-VS1) and defer the trust
key. **Rejected** because every cert would then be invalidated on the first DEK rotation (D-VS2) and would
assert nothing beyond DEK possession — forcing us to also strike the "vault is its own CA" framing and the
§0/§5 per-device-revocation / federation-trust claims. If ever taken as a stopgap it **must** be a
labeled, conscious interim with those claims removed. We are **not** taking it; §1.1 is the design.

### §1.5 Trust-key rotation boundary

The vault trust key stays **stable across DEK rotation** (so surviving certs still chain). DEK rotation
re-seals the trust-key slot under the new `HKDF(DEK,'freehold-vault-trust-v1')` but keeps the same
keypair. Rotating the trust key itself is a rare, separate ceremony (root compromise) that re-issues all
certs — out of scope for beta; noted in §8.

### §1.6 Device-key storage (browser reality)

The device Ed25519 **seed is generated in wasm and signs via `ed25519-dalek`** (same as
`attest.rs`/`relay_auth.rs`). At rest, the 32-byte seed is **wrapped under a per-origin non-extractable
AES-GCM `CryptoKey` in IndexedDB**, mirroring the shipped convenience-tier `enrollConvenience` /
`#deviceSecret` pattern (packages/db/index.js:322-329,359-367).

> We do **not** say "non-extractable WebCrypto signing key" — a `CryptoKey` cannot be handed to dalek, and
> §7.1 mandates wasm keygen + cert issuance via `attest`. The shipped pattern is a *secret wrapped under a
> non-extractable AES-GCM key*, not a non-extractable signing key.

Note: the Disclosure-plane app identity (D-DC2, `app-identity.js`) uses **WebCrypto Ed25519** by design;
adopting that for device keys is a *separate* decision that would move signing off dalek (gated on
`crypto.subtle` Ed25519 availability) and require non-extractable generation. We pick the **wasm/dalek +
AES-GCM-wrapped-seed** model for device keys; no "or" is left in the spec.

### §1.7 Two device-identity namespaces coexist by design

The already-shipped, non-secret **`syncDeviceId`** (random 16 bytes, the version-vector lineage component;
index.js, `sync_vv_increment`) and the new cert **`device_id = H(device_pubkey)`** are **two distinct,
coexisting identities** — the former is *sync lineage*, the latter is the *subject of certs/CRL/audit*.
**No migration for beta.** Open item (§8): CRL/audit key on `device_id` while VV lineage keys on
`syncDeviceId`, so any future cross-reference needs an explicit device-record mapping both ids.

## §2 — Pairing: add a device over an authenticated channel, rooted in consent (D-DT2)

Goal: get the DEK onto a new device **without ever exposing it in the clear**, issue its cert, and record
it — with a **human consent gesture on an already-trusted device** as the authorization root, and MITM
defeated by an out-of-band channel. The blind relay is the (blind) transport; a **pairing bucket** carries
only ciphertext.

**Key correction vs the earlier draft:** the device Ed25519 key is **signing-only**. We do **not** "wrap
the DEK to N's Ed25519 key" (Ed25519 is a signature scheme; it cannot receive a key-wrap without pulling
in X25519 — a new primitive §8 defers). Instead the DEK is **sealed under the one-time OOB channel key**,
and the new device then **self-enrolls its own durable local unlock**.

New device **N**, existing unlocked device **E**:

1. **N** generates `(device_pk_N, device_sk_N)`, a random `pairing_bucket`, and a high-entropy
   `pairing_secret` (32 bytes from `getRandomValues`). It shows a **QR (or its base64url text fallback)**
   carrying the full tuple `{ pairing_bucket, pairing_secret, device_pk_N }`. A human-typed short PIN is
   **out of scope** on this co-located path — any low-entropy/compared-string UX routes to the SAS/PAKE
   gate (D-DT2-remote, §7.7).
2. **E** ingests the pairing info out of band (scan the QR / paste the text). The **channel key** =
   `HKDF(pairing_secret, "freehold-pair-v1")`. The QR/code **is** the authenticated OOB channel — a
   middleman on the relay path cannot derive it.
3. **Consent.** E shows the owner: *"Add this device? (fingerprint of `device_pk_N`)"* → the owner
   approves with a **fresh passkey gesture**. This gesture, bound to `device_pk_N`, is the authorization —
   not a replayable bearer secret.
4. **E** does the privileged work: cross-signs and **issues a device cert** for `device_pk_N` (chaining to
   the vault trust key, §1); **seals `{ DEK, device_cert, sync bootstrap, membership head }`** under the
   channel key via the shipped **`Crypto::seal_bytes`** (XChaCha20-Poly1305, per-call 24-byte CSPRNG
   nonce, AAD domain-separated — the same path as `SyncBlob::seal`, run in wasm, **never** a fresh
   `crypto.subtle` AES-GCM construction); pushes the ciphertext to `pairing_bucket` on the relay.
5. **N** pulls from `pairing_bucket`, **unseals with the channel key** (not with `device_sk_N`), installs
   its cert, and then **enrolls its own durable local unlock the normal way** — `add_passkey(new_prf)` for
   a passkey slot, or `enroll_device` / a `KIND_DEVICE` slot keyed by N's own locally-generated 32-byte
   secret. N derives `sync_id` and joins the vault's sync bucket.
6. **E** broadcasts the updated **membership head** (append-only, hash-linked; §4) to the vault's sync
   bucket so every device converges on the new member list (rides the existing sync-epoch/version-vector
   machinery).

**Default is co-located** (QR = a direct visual channel, strongest MITM resistance). **Remote pairing**
(no camera) is a later increment behind its own gate — see §7.7 / D-DT2-remote — because it adds an
authenticated X25519 exchange with a **short-authentication-string (SAS)**, a genuine new primitive.

Properties: interception of relay traffic reveals nothing (sealed under a one-time OOB channel key); no
bundle+recovery-code-in-the-clear replay; consent is a fresh gesture bound to the specific device key; the
DEK is delivered sealed and the device's transport identity is independently revocable (§4).

## §3 — Continuous authentication (D-DT3)

Trust is a **heartbeat, not a one-time gate**. **Beta scope is deliberately small** (the channel-mutual
protocol moves to §5/§7.4–7.5, where a real peer channel exists):

**Beta continuous-auth = (1) + (2):**

1. **Per-op relay signatures (D-RA1, already shipped).** Every bucket op is an Ed25519 signature over a
   bound message; the bucket commits to the key (relay_auth.rs; relay-server.mjs verifies statelessly).
   §3 concedes what the review confirmed: this **already is** continuous proof of key possession per
   request — it is the beta's continuous-auth mechanism, no new protocol required.
2. **User passkey step-up**, implemented as a **policy check at the call site** (not a wire protocol),
   required only for **high-risk scopes**: pairing a new device, rotating the DEK, tier-3 disclosures.
   Routine sync needs only the automatic per-op key proof.

**Deferred to increments 4–5 (real peer channels):** device-cert **mutual** channel auth (certs chain to
the pinned vault trust key), a **periodic re-challenge** ("still me?" — sign a rotating nonce on an
interval), and **session rekey**. These had **no beta consumer** — §5 makes the browser always a client,
so the only beta network path is browser→relay — and a hand-rolled re-challenge/rekey loop is the most
bug-prone surface with zero shipped scaffolding. Moving it out is a de-risking, not a capability loss.

**Channel confidentiality & forward secrecy come from the transport, not a bespoke cipher.** When the
peer channels arrive (§5), confidentiality/FS come from the transport handshake — **WebRTC-DTLS** and
**gRPC/HTTP-2 TLS 1.3**, both keyed via ephemeral **ECDHE** — so a leaked long-term device key cannot
decrypt captured past traffic. The device cert binds to the transport at the **authentication layer only**
(DTLS fingerprint pin / mTLS); the re-challenge + rekey is an **app-layer liveness/authorization
heartbeat** on that already-forward-secret channel. Pin TLS 1.3 / DTLS 1.2+ with ECDHE and a bounded
session lifetime that triggers a transport re-handshake. We do **not** adopt Noise or a Double Ratchet
(redundant with the pinned transport; cuts against "audited primitives as-is").

Bucket authorization (D-RA1, "a DEK-holder may touch this bucket") and device identity (this cert, "which
device") **compose**: the relay/peer authorizes the bucket by the key commitment and identifies/audits the
device by its cert.

## §4 — Revocation: two tiers, with a freshness floor (D-DT4)

- **Soft (routine device removal):** revoke the device cert — publish a **vault-trust-key-signed
  revocation list** of `device_id`s — and remove its **envelope slot** (existing `remove_method` /
  `remove_slot`). The device can no longer unlock from a fresh envelope, and peers/relays reject its cert.
  Cheap, no re-encryption.
- **Hard (compromise / guaranteed eviction):** **rotate the DEK** (existing `rotate_dek`,
  dek-rotation-design.md) — re-wrap under surviving devices, re-encrypt. This is the only thing that
  evicts a device which already cached the DEK.

**Freshness floor (new work, not a free reuse).** The gossiped CRL alone has no monotonic floor, so a
blind/partitioned relay could suppress a revocation by serving a stale list. Fix:

- The **membership/CRL blob carries a monotonic `membership_generation`**, signed under the **vault trust
  key**, and that head generation is **carried into the sync-epoch token** (which today carries only
  `db_generation`), so peers **reject any membership/CRL view older than the highest they've seen** —
  reusing the `epoch_floor` / `seen_max` + `#bumpFloor` discipline.
- Membership is **append-only + hash-linked** (each entry references the prior head hash), so the head
  generation is meaningful and history is tamper-evident — giving §5 a well-defined "is this cert
  currently valid?" answer.
- This epoch-carriage binding is **NEW** work (a sibling of dek-rotation §7's pending
  `env_generation`↔epoch binding), stated as such — not claimed as free.

**Honest caveat (kept verbatim):** a **full-member device that already held the DEK still holds it** until
a rotation — soft revocation stops *future* re-derivation and peer acceptance, not a copy already in that
device's hands. This is intrinsic to any "data encrypted under one key" model; the two-tier design makes
the cost explicit. Equivocation scope for single-user v1: the hash-linked log's value is **detectability**,
bounded by that same "rotate to truly evict" limit; full Keybase-style multi-user key transparency belongs
with deferred cross-user federation (§5/§8).

## §5 — Topology: a federation of blind relays (D-DT6)

Transport and topology are independent axes; the same three-method relay contract (D-T1) serves all:

- **Roles, not tiers:** any *reachable* node can play the **relay** role — a home server, a cloud VM, an
  always-on desktop. Unreachable edge devices (browser tabs, phones) are **clients** that connect *out*.
- **The browser is never the networked relay.** In the "relay per machine" model the relay is a
  **separate local process** (native/desktop) and the browser hits `http://localhost` — browser stays a
  pure client. `InMemoryRelay` (in-page) is only for same-machine tab/worker sync.
- **Transport profiles** (same `.proto`, D-T2): **browser → relay** uses Connect / gRPC-Web (unary +
  server-streaming `Subscribe`); **native relay ↔ native relay** uses full **gRPC over HTTP/2**
  (multiplexing + bidi streaming for continuous anti-entropy); **browser ↔ device direct** (pure-web, no
  companion) uses **WebRTC** — with the fingerprint-attestation sub-protocol below (a leaked long-term key
  gives no MITM because the binding is signed live).
- **Topology is a spectrum, same code:** one home relay (a "star") → a cloud relay → a federated mesh.
  For the **single-user mesh (v1)**, per-bucket authority is **already enforced by D-RA1** (per-DB
  DEK-derived relay keys), so **no §5 change is needed for v1**. Cross-user federation trust — expressing
  a forwarding peer's authority as a **capability scoped to the specific buckets/`sync_id`s it forwards**
  (grant-token vocabulary), not "holds any valid cert" — is **deferred** (§8).

**WebRTC fingerprint binding is app-layer and explicit (increment 5 sub-protocol).** The Ed25519
device/vault cert **cannot** be the WebRTC DTLS X.509 transport cert — `RTCPeerConnection.generateCertificate()`
supports only RSASSA-PKCS1-v1.5 and ECDSA P-256, **not Ed25519** — and "DTLS fingerprint pinned via the
device cert" is **not** automatic. The sub-protocol:

1. each side `generateCertificate()` with **ECDSA P-256**;
2. read its DTLS **SHA-256 fingerprint**;
3. sign a domain-separated, length-prefixed `{peer_device_id, dtls_fp}` **channel-binding** with the
   Ed25519 device identity in wasm (reusing attest.rs discipline) and exchange it over the relay signaling
   channel;
4. before `setRemoteDescription`, parse the peer SDP `a=fingerprint`, verify the peer's signed binding
   **chains to a valid device cert under the pinned vault trust key** *and* equals that `a=fingerprint` —
   **reject on mismatch**.

The relay-as-signaling path is **untrusted**; this fingerprint-to-cert binding is a **design gate of
similar weight to D-DT2-remote** (§7.5).

## §6 — Threshold recovery (D-DT5) — post-1.0, behind its own gate

So no single device or relay holds the whole recovery secret: shard a **recovery KEK** with **textbook
Shamir over GF(256)** (a *vetted* implementation — **a NEW audited dependency**, *not* a homemade scheme;
this is where "no invented crypto" binds hardest), `t`-of-`n`. Shares distributed across the user's own
devices, optionally a trusted party (social recovery), and/or a relay-held share (**opt-in, never
default**). Recovery = collect ≥ `t` shares → reconstruct the recovery KEK → unwrap the DEK / re-admit a
device. It composes with the envelope as a new **threshold recovery method**. **Only the recovery secret
is sharded, never the live operational DEK.**

**Scope:** reclassified from a plain numbered increment to a **post-1.0 item behind its own
security-design gate (D-DT5-gate)** — exactly parallel to remote pairing — because a Shamir crate is a new
safety-critical dependency touching the recovery KEK, and beta durability is **already covered by the
shipped recovery-code path + re-pair** (§8). The `(vetted) Shamir` line is **removed** from §8's
"no-new-dependency reuse" list. Refinements to specify at that gate:

1. **No-new-primitive default:** attach a **per-share authenticator** (`H(share)` or a MAC/tag keyed from
   the recovery KEK via BLAKE3/HKDF) for corrupt-share detection + attribution on reconstruction.
   Feldman/Pedersen **VSS** is the stronger upgrade but introduces a prime-order-group primitive — its own
   gate.
2. **Bind each share to a holder** by encrypting it to that holder's **per-device identity key (D-DT1)**
   (not the convenience-tier `deviceKey`), reusing the wrap-to-device envelope path, so a leaked raw share
   is useless off-device and D-DT4 revocation also revokes that device's share.

The novel design work is the *system* (what is sharded, across whom, the threshold policy), not the
sharing math.

## §7 — Build increments

The **authentication piece** the roadmap wants before a beta is **1–3**; **4–7** are the topology/advanced
work that lands after release ("add more stuff / others can contribute").

1. **Device identity + certs** — on-device Ed25519 keypair; `device_id = H(device_pk)`; **trust-key slot**
   sealed under `HKDF(DEK,'freehold-vault-trust-v1')` in the bundle; device cert (issue + pure verify)
   chaining to the trust key via the **reused `attest` path** and grant-token claim shape. New wasm:
   device keygen + `session_issue_device_cert` + `verify_device_cert`. **This is the only increment
   detailed for build now — see §9.**
2. **Pairing handshake (co-located / QR)** — pairing bucket over the relay; QR-transported channel secret;
   consent gesture; **DEK sealed under the OOB channel key** (`seal_bytes`); cert issuance; **N
   self-enrolls its own local unlock**; membership broadcast. Reuses `seal_bytes` + relay + `add_passkey`/
   `enroll_device`. **No wrapping-to-device, no X25519.**
2b. **Soft-revoke (producer side)** — vault-trust-key-signed `device_id` **CRL with monotonic
   `membership_generation`** gossiped over the sync bucket + envelope slot removal via `remove_method`
   (envelope.rs `remove_slot`). Append-only + hash-linked membership head; head generation carried into
   the epoch token. The CRL-check-**on-connect** consumer lives in the deferred channel work (§7.4/7.5).
   Cheap, high-value for a multi-device beta.
3. **Passkey step-up policy gate** — the call-site policy check for high-risk scopes (pairing / DEK
   rotation / tier-3). (This is the *remaining* beta half of D-DT3; the channel-mutual protocol is **out**
   of beta — moved to 4/5.)
4. **Federation** — native relay ↔ relay over gRPC/HTTP-2; device-cert **mutual** channel auth +
   re-challenge + rekey (the deferred D-DT3 channel work); device-cert federation trust; anti-entropy
   gossip (Merkle-range set reconciliation; reuses the full-state-root machinery).
5. **WebRTC edge** — pure-browser direct links; relay signaling; the **ECDSA-P-256 + signed-binding
   fingerprint-attestation** sub-protocol (§5). Design gate.
6. *(reserved)* — advanced topology / anti-entropy hardening.
7. **Remote pairing (D-DT2-remote)** — SAS-verified exchange over **audited `x25519-dalek` in wasm**
   (not WebCrypto X25519); own gate (§7.7 below).

- **D-DT5-gate (post-1.0):** threshold recovery — Shamir shares as an envelope recovery method +
  reconstruction ceremony. New audited dependency; own gate (§6).

**§7.7 — Remote pairing SAS (specified now so the gate review is substantive).** After the X25519
exchange, both devices compute `SAS = truncate( HKDF/HMAC over a transcript hash binding BOTH ephemeral
public keys + the pairing/channel binding )`, rendered as 5–6 digits or an emoji set (a MAC of the **whole
key agreement**, not the raw DH output — Matrix SAS / Signal safety-number style). The owner **MUST
confirm equality on both screens BEFORE** E issues the cert and seals the DEK. Reuses HKDF/HMAC (already
audited) atop the already-gated X25519 — **no new primitive beyond X25519**. Rationale: an unauthenticated
blind-relay-brokered X25519 is textbook relay-in-the-middle without a transcript-bound SAS.

## §8 — Open questions / honest limits (for sign-off)

- **Soft-revoke ≠ eviction** until rotation (§4) — **accepted**, now with the two conditions that make it
  honest: (1) the CRL carries a monotonic `membership_generation` **floored into the sync epoch** (else a
  relay can suppress a revocation), and (2) certs chain to the **independent trust key** with per-device
  self-sign + cross-sign (else a compromised DEK-holder re-mints identity off the CRL). Both now in §1/§4.
- **Browser device-key durability** — the key is a **wasm/dalek seed wrapped under a non-extractable
  AES-GCM CryptoKey**; it dies if that CryptoKey is evicted. Triggers are **largely invisible and
  frequent**: WebKit/Safari ITP evicts all script-writable storage (IndexedDB/OPFS/the CryptoKey) **after
  7 days of no first-party interaction** (with `persist()` largely ignored), plus OS storage-pressure
  eviction, private/incognito mode, and clear-on-exit. Therefore: the **already-shipped recovery-code
  envelope method** (`needsBackup` / `hasRecoveryMethod` / `generateRecoveryCode`) is the **PRIMARY**
  browser-full-member durability guarantee; **re-pairing is a designed low-friction flow**, not an
  exception; surface `vault.persisted = false` to nudge a backup; state plainly that on Safari durability
  is *best-effort; assume it can vanish*. (A silently-evicted device losing its cached DEK is if anything
  **protective**, and is just the intrinsic soft-revoke≠eviction property — not a new vulnerability.)
- **Dual device identity** (`syncDeviceId` VV-lineage vs cert `device_id`) — documented as coexisting, no
  beta migration (§1.7); future cross-reference needs a device-record mapping both.
- **Verifiable multi-user key transparency** — the append-only hash-linked membership log gives
  single-user detectability now; full Keybase-style transparency is deferred with cross-user federation.
- **Trust-key rotation** (root compromise) — rare, re-issues all certs; out of scope for beta (§1.5).
- **Remote pairing** needs the SAS + X25519 — deferred to increment 7 behind its own gate (§7.7).
- **Threshold recovery (Shamir)** is a **NEW audited dependency**, post-1.0 behind D-DT5-gate (§6) — it is
  **not** a no-new-dependency reuse.
- **Relay-held Shamir share** is opt-in, never default.
- **Cross-user federation** trust policy is out of scope for v1 (single-user mesh first).
- **No new primitive in increments 1–5** — everything reuses Ed25519 / HKDF / XChaCha20-Poly1305. X25519
  enters only at increment 7 (remote pairing) and Shamir only at the post-1.0 D-DT5-gate, each gated
  separately. Sync/vault-plane asymmetric crypto is **dalek-in-wasm**; the Disclosure-plane app identity
  (D-DC2) uses WebCrypto Ed25519 by design; any new WebCrypto Ed25519/X25519 use must **feature-probe** for
  availability.

## §9 — Increment 1 build plan (device identity + certs)

Small, clean, `attest.rs`-reusing surface. Order:

1. **Trust key.** In `envelope.rs`, add a distinct **trust-key slot** sealed under
   `HKDF(DEK,'freehold-vault-trust-v1')`, carried in the bundle (D-VS2's named path). Generated once via
   `getrandom` (fail-closed, mirroring `envelope::random_dek`), stable across DEK rotation (§1.5).
2. **Device keygen** (`device.rs` new, or extend `attest.rs`): 32-byte CSPRNG seed via `getrandom`;
   `device_public_key(seed) -> [u8;32]` using `ed25519-dalek SigningKey::from_bytes` exactly as
   `relay_auth`/`attest`.
3. **`device_id`** = `"dev_" + base64url(SHA-256("freehold-device-id-v1" ‖ device_pubkey))[..12]` — pure,
   deterministic, with a pinned test vector (reuse `sha2::Sha256`).
4. **Canonical cert claim**: length-prefixed byte layout (domain `freehold-device-cert-v1` ‖ u16-len
   `{vault_trust_pubkey, device_id, device_pubkey, caps(sorted), issued_at, expiry}`), base64url into the
   UTF-8 claim slot. `build_device_cert_claim(fields) -> String` / `parse_device_cert_claim(&str) ->
   fields` with a round-trip test + grant-token's byte-equality tamper check.
5. **Issuance wasm export** `session_issue_device_cert(device_pubkey, caps, issued_at:f64, expiry:f64)` —
   inside `with_session`, build the claim and sign via `util.attest` (**same path as `session_attest`**)
   using the **vault trust key**. Returns the 64-byte signature + claim string for the SDK to assemble.
6. **Pure verifier** `verify_device_cert(vault_trust_pubkey, cert_claim, device_pubkey, sig, now)` —
   recompute-and-byte-compare; `device_id == H(device_pubkey)`; `attest::verify` (`verify_strict`);
   validity window; caps. No DEK, no session; mirrors `verify_attestation`.
7. **SDK** (`packages/db/index.js`): generate the device seed in wasm; wrap it under a per-origin
   non-extractable AES-GCM `CryptoKey` in IndexedDB exactly like `enrollConvenience`/`#deviceSecret`; store
   the cert (claim+sig) alongside; **`syncDeviceId` untouched** (§1.7).
8. **`self_check`** (feature `testing-api`): keygen determinism, `device_id` vector, cert issue/verify
   round-trip, tamper rejection (flip a field → verify=false), expiry rejection, wrong-trust-key
   rejection — mirroring `relay_auth::self_check`.

**Files:** `crates/freehold/src/device.rs` (new) or `attest.rs` (extend); `lib.rs` (exports + `self_check`
hook); `envelope.rs` (trust-key slot); `packages/db/index.js` (seed gen + AES-GCM wrap + cert storage);
`packages/db/index.d.ts` (types); this doc.

**Guardrails:** cert claim is a forgery surface → length-prefixed, verifier byte-compares before trusting
the sig. The device key is **signing-only** — no wrapping/KEM pulled into increment 1 (that's pairing,
sealed under the OOB channel key). Base64url alphabet/padding must match the SDK exactly or ids won't
round-trip across the wasm/JS boundary. If the seed is generated in wasm and returned for SDK wrapping it
briefly crosses the boundary as bytes — acceptable (same as the convenience-tier secret) but must be
wrapped immediately and never persisted in the clear.

## §10 — Decision summary & hardening resolution log

| ID | Decision (hardened) |
|----|---------------------|
| D-DT1 | Device identity = on-device Ed25519 keypair; membership = per-device self-sign + **cross-sign**, cert chaining to an **independent, non-DEK-derived vault trust key** (D-VS2's deferred upgrade), `device_id = H(device_pk)`. Cert = grant-token-shaped claim through the existing `attest` path (length-prefixed, recompute-and-byte-compare). Device seed = wasm/dalek, **AES-GCM-wrapped at rest**. `syncDeviceId` and `device_id` coexist, no migration. |
| D-DT2 | Pairing over a blind pairing-bucket; QR-transported one-time channel key (co-located default); **DEK sealed under the OOB channel key (`seal_bytes`)**, N **self-enrolls** its own local unlock; device key is **signing-only** (no wrap-to-pubkey, no X25519). Authorization = a fresh passkey **consent** gesture. Remote/SAS pairing deferred (D-DT2-remote, §7.7). |
| D-DT3 | **Beta continuous-auth = per-op relay signatures (D-RA1) + passkey step-up policy gate.** Device-cert-mutual channels + re-challenge + rekey **moved to increments 4/5** (no beta consumer). Channel FS comes from TLS 1.3/DTLS ECDHE; no Noise/Double-Ratchet. |
| D-DT4 | Two-tier revocation: soft (**vault-trust-key-signed CRL with monotonic `membership_generation` floored into the epoch**, append-only + hash-linked + envelope slot removal) for routine removal; DEK rotation for compromise. Soft-revoke ≠ eviction until rotation (explicit). Epoch-carriage is **new** work. |
| D-DT5 | Threshold **recovery** only; textbook Shamir `t`-of-`n` over GF(256) — a **NEW audited dependency, post-1.0 behind D-DT5-gate**. Per-share authenticator + share bound to device identity key. Never shard the live DEK; relay-held share opt-in. |
| D-DT6 | Federated blind-relay topology; relay is a role any reachable node plays (browser always a client); Connect at the edge, gRPC/HTTP-2 relay↔relay, WebRTC direct with an **explicit ECDSA-P-256 + signed-fingerprint-binding** sub-protocol (Ed25519 can't be the DTLS cert). Per-bucket authority already enforced by D-RA1 for v1; cross-user federation deferred. |

**Hardening resolution log** (18 confirmed findings → all landed):

- **PA-1 (critical) trust root** → §1.1/§1.2/§1.4 independent trust key + cross-sign; interim rejected and
  its honesty-strip documented.
- **PA-6/PRAG-4 cert encoding** → §1.3 reuse attest/grant-token length-prefixed claim + byte-compare.
- **PRAG-1 (high) wrap-to-Ed25519** → §2 deleted; DEK sealed under OOB channel key, N self-enrolls.
- **BPR-1 (high) device-key storage** → §1.6 wasm/dalek seed wrapped under non-extractable AES-GCM.
- **PRAG-2 (high) increment-3 scope** → §3/§7 channel-mutual+re-challenge+rekey moved to 4/5; beta = D-RA1
  + step-up gate.
- **BPR-2 (high) durability** → §8 recovery-code elevated to PRIMARY; 7-day WebKit eviction named; re-pair
  first-class.
- **PA-3 CRL rollback** → §4 monotonic `membership_generation` floored into epoch; append-only hash-link;
  new-work flagged.
- **BPR-3 WebRTC fingerprint** → §5 explicit ECDSA-P-256 + signed-binding sub-protocol (Ed25519 can't be
  DTLS cert).
- **PA-2 remote SAS** → §7.7 transcript-bound SAS specified for the gate.
- **PRAG-5 dual identity** → §1.7 documented, no migration.
- **PRAG-3 soft-revoke producer** → §7 increment 2b scheduled.
- **PRAG-6/PA-7 Shamir** → §6 post-1.0 gate; removed from "no-new-dependency" list; VSS/share-binding
  notes.
- **PA-4 channel FS** → §3 rely on TLS 1.3/DTLS ECDHE; no Noise.
- **PA-5 caps vocabulary** → §1.3 sorted scope list (grant-token vocabulary).
- **BPR-4 X25519/WebCrypto scope** → §8 scoped principle (sync-plane dalek; D-DC2 WebCrypto by design;
  feature-probe).
