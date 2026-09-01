---
slug: freehold-data-custody
artifact: data-custody-protocol
version: 0.1
status: DRAFT 2026-09-01 — design-before-code. Records the model + decisions D-DC1..6; awaiting sign-off before any build. Not yet implemented.
created: 2026-09-01
kind: protocol-design
depends-on: Freehold DB (envelope v3, per-DB HKDF subkeys, DEK rotation/eviction — shipped); Freehold Sync (version-vector engine over a blind relay — engine shipped, real transport pending); per-device SIGNING keys (#7 / sync-epoch §D-SE2 — NOT yet built; gates verifiable attestations)
---

# Freehold — data-custody protocol (v0.1, design-before-code)

> Inverts the app↔data relationship. Instead of an app holding your data on its servers (it owns it;
> you lease access), the data lives in a **Freehold vault on your own device**, sealed under your
> passkey, and apps **request scoped, revocable access or disclosure** to it. You own the data
> outright; the app is a **custodian/processor**, not an owner. This is the "leasehold → freehold"
> thesis applied to the app–data relationship itself.

## 1. The inversion (why this exists)
Today an app stores your PII/PHI on its backend. Consequences: when the app is breached *your* data
leaks; when you leave they keep it; when subpoenaed they must produce it. The app is the **data
controller** and bears the ownership *and* the liability.

Freehold moves the **custody root** to the user's device. Anything on a server becomes a derived,
revocable, minimized *working copy* — or a sealed backup the server cannot read. In GDPR terms this
**flips the user into the data controller and the app into a mere processor**, and it operationalizes
"data minimization" (GDPR) / "minimum necessary" (HIPAA) as protocol primitives rather than promises.
The builder pitch is concrete, not aspirational: **hold less, be liable for less.**

## 2. Roles & trust model
| Role | Holds | Sees | Trust placed in it |
|---|---|---|---|
| **Vault** (user's device) | the DEK (in a worker, passkey-unlocked), the plaintext DB, the grant ledger | everything (it's the owner's agent) | the user trusts their own vault |
| **App** (relying party) | its own data; a scoped, revocable **capability**; disclosed leaves (transiently) | only what a grant discloses | untrusted by default; authenticated per §5.1 |
| **Blind relay** (sync) | opaque ciphertext blobs + routing labels (`sync_id`) | **nothing in the clear** — ciphertext only | trusted for delivery only, never for confidentiality |
| **Verifier** (a remote server checking an attestation) | a vault public key | a signed claim ("18+ ✓"), never the PII | trusts the vault's signing key, not its word |

Invariant carried from Freehold DB: **no relay/server/app ever sees a key or plaintext it was not
explicitly granted.** The DEK never leaves the vault worker (as today).

## 3. The four disclosure tiers (the per-field question)
The design question is never "local vs. server." It is, per field: **why does the server need this,
and what is the least that satisfies it?** The answers form four tiers.

1. **Server never needs it (the bulk).** Notes, history, preferences, most of a record. → **Vault
   only.** Default; most of the bytes.
2. **Server needs a *fact*, not the data.** "18+", "card valid", "income > X", "is a patient of Dr. Y".
   → **Derived attestation.** The vault (or a trusted verifier) emits a signed claim; the raw PII is
   never transmitted. Strongest ownership-preserving tier — covers more cases than expected.
3. **Server needs it transiently (process-and-forget).** Charge a card, run KYC, send an SMS. →
   **Scoped, minimized, consented *disclosure* (a "borrow")** — a single-use, purpose-tagged slice with
   a non-retention receipt. Vault stays source of truth; server gets a lease on a leaf.
4. **Server is *legally required* to retain it (HIPAA chart, tax record).** → **Honest hard boundary.**
   The covered entity must hold a readable copy; you cannot make it purely user-held-and-encrypted.
   Freehold owns the **user's copy** and all **user-generated** data; the provider's legal record is
   genuinely the provider's. Where regs allow, the server's copy MAY be a sealed bundle it cannot read
   (retention-of-record without retention-of-*access*) — but do not oversell this.

> **DECISION D-DC1 (recommend): every field carries a tier tag in the schema.** Fulfillment (§5.5)
> dispatches on it. A field with no tier defaults to tier 1 (vault-only) — fail closed toward privacy.

## 4. The custody root vs. working copies
**The vault is the source of truth and custody root; everything else is a derived, revocable,
minimized copy — or a sealed backup no one else can read.** You hold the root and the keys; servers
hold leaves, briefly, for a stated purpose. Durability of the root is the encrypted-bundle / sync
backup story from Freehold DB (local-only data dies with the device; a sealed backup the server can't
read restores it without surrendering custody).

## 5. The request-and-consent flow
Think "OAuth, but for a *disclosure from a local vault* instead of an access token from a server." Six
beats.

### 5.1 Authenticate the requester
The vault must know *who is asking*. Two levels:
- **Origin-bound** (free, weak): the requesting web origin. Sufficient for same-user, same-machine
  broker use; **insufficient** against a lookalike origin phishing the vault.
- **Registered app identity** (strong): a signed app **manifest** (name, icon, declared scopes)
  keyed to a public key in an app directory; requests are signed by the app key. The vault pins the
  key on first grant (TOFU) and warns on change.

> **DECISION D-DC2 (recommend): ship origin-bound first, design the manifest/app-key path in from day
> one.** The consent UI shows the *authenticated* identity, never a self-asserted display name.

### 5.2 Scoped, purpose-tagged request
The app declares the **minimum**: `read profile.email, profile.shipping_addr — purpose "fulfill order
#123" — one-time`. Field-granular + machine-readable purpose + lifetime (one-time | standing+expiry).

### 5.3 Consent is a passkey gesture
The vault renders exactly what is asked and why; the user approves with WebAuthn. **Consent is itself
an authenticated act** — the same passkey that unlocks the vault signs the grant. Denials and
narrowings (grant a subset) are first-class.

### 5.4 The grant is a capability token
Signed by the vault, scoped to `(app_id, fields[], purpose, tier, issued_at, expiry, one_time|standing,
grant_id)`, revocable, and appended to a local **grant ledger**. This token is the load-bearing
"auth algo." Two issuance modes (see §6).

### 5.5 Fulfillment at the right tier
The vault returns the minimum for the field's tier (§3): raw scoped field (tier 3), derived
attestation (tier 2), or executes a query and returns results (custodian model, §5.7). A one-time
grant is consumed on fulfillment.

### 5.6 Receipt + revocation
Every disclosure lands in the local ledger — **who asked, what, when, why, which grant**. The user can
revoke a standing grant; future requests under it fail closed. Revocation of an *access* grant maps
onto Freehold's **eviction** primitives (drop the capability; DEK rotation is the nuclear option that
re-keys the namespace — the machinery you just hardened in [[dek-rotation-design]]).

### 5.7 Two flavors, one machinery
- **Access (custodian):** the app reads/writes data that lives in the *user's vault namespace* — a
  tenant operating on the owner's store. Results may be written back into the vault.
- **Disclosure (borrow):** the app has its *own* record elsewhere and pulls a field to **complete**
  it — use-and-(ideally-)forget. Same request/consent/capability path; the only difference is whether
  the result is persisted in the vault or handed out.

The SDK collapses to one app verb — `requestData(scope) → consent → capability → fulfillment` — and
one owner surface — *grant / narrow / deny / revoke*, plus the ledger view.

## 6. The capability token — symmetric now, signed later
There is a real crypto fork in what the auth layer can promise, and it lines up with an existing
milestone:

- **Within the user's own trust domain** (the vault issues capabilities its *own* broker enforces; the
  user trusts their own vault): a **symmetric, DEK-rooted** grant (MAC under an HKDF subkey of the DEK)
  is enough. **Ships now** on Freehold DB primitives. The showcase broker (§9) is its first
  implementation.
- **Third-party-verifiable** (a *remote* server checks "the vault really attested 18+" without trusting
  the vault's word; or a grant is verified by a counterparty): needs an **asymmetric vault signing
  keypair** (Ed25519; private key wrapped in the envelope like the DEK, public key registered). This is
  exactly the **per-device signing-keys work (#7 / [[sync-epoch-design]] §D-SE2)** currently out of v1
  scope.

> **DECISION D-DC3 (recommend): same protocol, swappable grant proof.** A grant is `{claims, proof}`
> where `proof` is a DEK-MAC now and an Ed25519 signature once #7 lands. Nothing above §6 changes when
> we upgrade — tier-2 verifiable attestations simply light up. Be explicit in docs/UX that until #7,
> attestations are trust-local, not remotely verifiable.
>
> **UPDATE 2026-09-01 — #7 SHIPPED for tier-2 attestations.** The asymmetric half is built: a
> DEK-derived **Ed25519 vault-identity** key signs tier-2 attestations, verifiable by a remote party
> against the vault public key with no DEK ([[vault-signing]] / `docs/vault-signing-design.md`). The
> showcase broker's `profile.attest.over18` now returns a **signed** attestation the relying party
> verifies against a pinned key. (Grant tokens themselves — §5.4 — remain DEK-MAC for now; the same
> `{claims, proof}` shape upgrades them the day we want counterparty-verifiable *grants*.)

## 7. Scoping mechanics on Freehold primitives
- **Per-app namespace** rides named DBs + per-DB HKDF subkeys (`K_db = HKDF(DEK, "vfs-db-v1"‖uuid)`):
  each app gets an isolated DB (`app:<id>`); it cannot address another app's or the user's core data.
- **Shared data** (e.g. a `profile` DB two apps may both read) is a *distinct* namespace the user
  grants access to explicitly — never ambient.
- **Field/row-level grants** within a shared DB are enforced by the **broker** (the vault mediates
  every query and filters to the grant), not by handing the app a key. The app never holds a key.
- **Revoke = eviction** (§5.6); optionally, on revoke, hand the user their app-namespace data back as a
  `.freehold` bundle ("you're leaving — here's your data").

## 8. Data-flow planes & transport
Three planes, three transports — do not conflate them.

| Plane | Path | Transport | Notes |
|---|---|---|---|
| **Local** | app ↔ vault, same device | `postMessage` / `MessageChannel`; extension port | no network; broker + consent live here |
| **Sync** | device ↔ device (same user) | **gRPC-Web via Connect** | blind relay; opaque `bytes` payload only |
| **Disclosure** | app/server ↔ vault (remote) | same protobuf contract | tier-2/3 grants + attestations |

> **DECISION D-DC4 (recommend): protobuf/Connect as the typed contract for the Sync + Disclosure
> planes; postMessage for the Local plane.** gRPC-Web (via **Connect** — connect-es client, tonic-style
> server) gives a versioned IDL, codegen for third-party SDKs, and cross-language servers. **Envoy is
> supported but not required**: Connect servers speak gRPC-Web natively, so a proxy is a deployment
> *option* (translate gRPC-Web ↔ native gRPC), not a dependency — a sync-server call, made later.
>
> Browser gRPC-Web has **no true bidi streaming** — a *browser-platform* limit, not a gRPC one: full
> gRPC does bidi over raw HTTP/2 frames + trailers, but browsers don't expose full-duplex streaming
> request bodies (Chromium-only, HTTP/2-only, half-duplex; absent in Safari/Firefox) or HTTP/2 trailers
> to JS, so the gRPC-Web spec supports only **unary + server-streaming**. Model sync as **unary "push
> blob" + server-streaming "receive updates"** (poll/long-poll fallback for restricted networks; a
> WebSocket transport is the escape hatch if a bidi channel is ever truly needed). The relay only ever
> handles an opaque `bytes ciphertext` field — a typed transport does **not** cost us the server-blind
> property (§2). The Local plane is in-process message passing; wrapping it in gRPC would add nothing.

> **DECISION D-DC5 (recommend): one `.proto` package for the whole family.** `DataRequest`, `Grant`,
> `Attestation`, `Disclosure`, plus the sync `PushBlob`/`Subscribe` RPCs — so an app integrates the
> custody protocol and sync against a single generated client. Ciphertext travels in `bytes`; the
> schema describes *envelopes and routing*, never plaintext fields.

## 9. The showcase = first implementation
Not a one-off demo — the first implementation of §5–6 on the Local plane (D-DC4), symmetric grants
(D-DC3). **Vault + consent broker + two apps sharing one user-owned dataset.** The four beats that make
the split *tangible* (directly answering "how does the split work IRL?"):
1. Unlock the vault with a passkey.
2. **App A** requests access → consent screen → grant → it works (custodian, tier-1 data).
3. **App B** requests the *same* profile → grant. Two independent apps on data **you** own; neither
   holds a server copy. Show a **tier-2 attestation** (App sends "18+ ✓"; DOB never transmitted) and a
   **tier-3 borrow** to a mock processor with a non-retention receipt.
4. **Revoke App B** live → it loses access instantly; your custody root is untouched; a receipt reads
   *"apps hold: 0 keys, 0 bytes of your data."*

## 10. Honest limits (state them up front)
- **Non-retention is trust, not math.** Once bytes reach a server (tier 3), nothing but
  contract/attestation/audit stops it keeping them — short of TEEs/confidential compute or real ZK.
  Freehold **minimizes** what's disclosed and makes disclosure **consented + auditable**; it does not
  prevent a malicious counterparty from keeping what you *chose* to send.
- **Tier 4 is a real boundary.** A provider's legally-required record is the provider's; user-custody
  owns the user's copy and user-generated data, not the covered entity's obligations.
- **Verifiable attestations gate on #7.** ~~Until the signing-key milestone, tier-2 claims are
  trust-local~~ **DONE (2026-09-01):** tier-2 claims are now Ed25519-signed by a DEK-derived vault
  identity and remotely verifiable (D-DC3 update; [[vault-signing]]). *Grant tokens* (§5.4) remain
  DEK-MAC until counterparty-verifiable grants are needed. Key **registration/PKI** is still out of
  scope — the verifier must obtain/pin the vault public key (TOFU or a directory).
- **Requester authentication is only as strong as §5.1.** Origin-only is phishable; the manifest/app-key
  path (D-DC2) is the real defense and must land before untrusted third-party apps are invited.
- **Availability.** Local-only data dies with the device; durability needs the sealed backup / sync
  story, which must not surrender custody (server holds ciphertext it can't read).
- **Not audited.** This protocol inherits Freehold's pre-1.0, un-audited status ([[audit-readiness]]).

## 11. Build order
1. **Design sign-off** (this note).
2. **Local broker + symmetric grants + ledger** (D-DC1/D-DC3/D-DC4 Local plane) — pure Freehold DB, no
   new backend. → the §9 showcase.
3. **`.proto` contract** for `DataRequest`/`Grant`/`Attestation`/`Disclosure` (D-DC5) — even before a
   server, to freeze the SDK surface.
4. **Real blind relay over Connect** (Sync plane) — finishes Freehold Sync's missing transport; unary
   push + server-streaming receive; opaque bytes.
5. **Manifest / app-key requester auth** (D-DC2) before opening to untrusted apps.
6. **Ed25519 vault signing keys (#7)** → verifiable tier-2 attestations light up (D-DC3), no protocol
   change above §6. ✅ **DONE 2026-09-01** ([[vault-signing]]).

## Cross-links
[[dek-rotation-design]] (revoke/eviction machinery this rides), [[sync-epoch-design]] (§D-SE2 signing
keys = the #7 gate; blind-relay freshness), [[bundle-format]] (the sealed working-copy / walk-away
bundle), [[audit-readiness]] (trust status + limits), Freehold DB design-spec (envelope v3, per-DB
subkeys, the DEK that roots every grant).
