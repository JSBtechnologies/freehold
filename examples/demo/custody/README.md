# Freehold data-custody showcase

**You own the data; apps are custodians.** The first implementation of
[`docs/data-custody-protocol.md`](../../../docs/data-custody-protocol.md) — Local plane, local grants.

Your data lives in a passkey-sealed Freehold vault **on your device**. Apps connect to a **broker**
and can only do two things: *request* a scoped, revocable grant (with your consent), and *call* a
fixed vocabulary of capabilities the owner granted. Apps never hold a key, never send SQL, and every
disclosure is written to a **ledger in the vault's own encrypted DB**.

## Run it

```bash
cd examples/demo && npm install && npm run dev
# open http://localhost:5173/custody.html  (needs a platform authenticator / passkey with PRF)
```

The four beats:

1. **Unlock** the vault with a passkey.
2. **App · Notes** requests access → you approve → it operates on its own data (**tier 1**, vault-only).
3. **App · Tasks** requests access, then to "complete an order" asks for the *minimum*:
   - **tier 2 — attestation:** `18+ ✓` (a yes/no; your date of birth never leaves the vault),
   - **tier 3 — disclosure:** the shipping address, handed to the app and **logged**,
   - **tier 3 — borrow:** email released to a mock processor ("AcmePay") for a one-off charge — the
     **app never receives the raw value**, only a receipt.
4. **Revoke** the Tasks app → it loses access immediately; your data stays with you. Revocation is
   enforced **at the broker**, not just the UI (the E2E proves a revoked grant is rejected).

## Files

| File | What |
|---|---|
| `broker.js` | the vault-side mediator: capability vocabulary, grant store, ledger, tiered fulfillment |
| `app-client.js` | the app side — holds only a `MessagePort`; `request()` + `call()`, nothing else |
| `main.js` | wires the vault + broker + consent UI + the two apps (each over its own `MessageChannel`) |
| `../custody.html` | the page |

E2E: `tests/custody-e2e.spec.js` (virtual authenticator).

## Honest scope of this first cut (what's real, what's next)

- **Real:** the request → consent → grant → tiered-fulfillment → ledger → revoke protocol, enforced by
  the broker against data sealed under the vault's DEK. Apps genuinely never touch the key or the DB —
  they hold only a message port.
- **Simplified here:** the apps run in the same page and reach the broker over `MessageChannel`. The
  transport (structured-clone messages, no shared refs) is the *same trust boundary* as the product's
  cross-origin `postMessage`/iframe form — that isolation is the next hardening step.
- **Deferred (per the protocol doc):** cross-origin/iframe app isolation and requester
  authentication (manifest/app-key, §5.1); the typed Connect/gRPC-Web contract for the Sync +
  Disclosure planes (§8); and **remotely-verifiable** attestations, which gate on the Ed25519
  vault-signing-key milestone (#7). Grants here are local/symmetric — the protocol upgrades to signed
  grants with no change above the token layer.
- Two SQLite files (`vault`, `profile`) to fit the session pool's slot budget; per-app *files* is the
  production form. Broker enforcement is identical either way.
