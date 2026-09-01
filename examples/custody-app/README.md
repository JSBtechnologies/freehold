# Freehold — your data, your terms

A **Quasar (Vue 3) SPA** showing the data-custody model as a real tool: a personal **data + consent
manager**. Your identity lives in a passkey-sealed Freehold vault on your device; real relying-party
apps request **scoped, revocable** access through a broker and can only touch what you grant. Every
disclosure is logged in a ledger you own. See [`docs/data-custody-protocol.md`](../../docs/data-custody-protocol.md).

## Run

```bash
cd examples/custody-app
npm install
npm run dev     # predev copies the wasm from ../demo/pkg → public/pkg, then starts Vite on :5179
```

Open http://localhost:5179 (needs a secure context + a passkey with the WebAuthn PRF extension).
If `../demo/pkg` is missing, build it first:
`cd crates/freehold && wasm-pack build --target web --release --out-dir ../../examples/demo/pkg`.

## What it shows

- **Your vault** — the data you own, with a badge on each field showing *how* it may be shared:
  `disclosable` (raw, tier 3), `attest only` (a fact, tier 2 — e.g. DOB → 18+), `borrow only`
  (released to a processor, tier 3 — e.g. the card, which no app ever sees).
- **Connected apps** — every app that asked for access, its granted capabilities, and a **Revoke** kill
  switch (enforced at the broker, not just the UI).
- **Activity** — the disclosure ledger: who asked what, when, why — sealed in your own vault.
- **Try an app** — two real relying parties over the broker (each holds only a `MessagePort`, never a
  key or the DB):
  - **BuyStuff** (checkout) — 18+ **attestation** (DOB withheld), shipping **disclosure**, card
    **borrow** to a processor (the app gets a receipt, never the number).
  - **Notes** (custodian) — reads/writes only its own data, sealed in your vault.

## Architecture

| Path | What |
|---|---|
| `src/freehold/store.js` | reactive singleton: opens the vault, drives unlock, hosts the broker, brokers app clients |
| `src/freehold/broker.js` | the vault-side mediator: capability vocabulary, grants, ledger, tiered fulfillment |
| `src/pages`, `src/components` | the Quasar UI (layout, unlock gate, vault, apps, activity, relying parties) |

The DEK never leaves the vault worker. Reloads re-derive the key from your passkey — nothing sensitive
is kept at rest. Apps reach the broker over `MessageChannel` (same trust boundary as the product's
cross-origin `postMessage`/Connect transport; that isolation is the documented next step). Two SQLite
files (`vault`, `profile`) to fit the session pool budget; per-app files is the production form.
