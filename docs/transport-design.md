---
slug: freehold-transport
artifact: transport-design
version: 0.1
status: BUILT 2026-09-02 — the Sync-plane blind-relay transport (D-DC4/D-DC5) is implemented and
  proven E2E (tests/sync-http-e2e.spec.js). Disclosure-plane messages are frozen in the .proto but the
  disclosure server is not yet built (still the Local-plane broker).
created: 2026-09-02
kind: transport-design
depends-on: Freehold Sync (version-vector engine over a pluggable BlindRelay — shipped); data-custody-protocol §8 (planes) / D-DC4 (Connect) / D-DC5 (one .proto family); envelope v3 + sync_key sealing (SyncBlob::seal — shipped)
---

# Freehold — transport design (Sync plane over a real blind relay)

> Finishes the one big open item from [[data-custody-protocol]] §11.4: the version-vector sync engine
> was proven only against a *mock* relay (`InMemoryRelay`). This gives it a **real wire** — a network
> transport that stays **blind by construction** — without changing any crypto.

## 1. What this is and is not
- **Is:** a typed, versioned wire contract (`.proto`) for the Sync plane, a reference **blind relay
  server** (opaque bytes only), and an `HttpRelay` SDK adapter that is a drop-in for `InMemoryRelay`.
- **Is not:** new crypto. The blob is sealed by the vault under a DEK subkey *before* it reaches the
  transport (`crates/freehold/src/sync.rs` `SyncBlob::seal`). The wire moves ciphertext + a routing
  label and nothing else. This is why the transport sits *below* the design-before-code crypto bar:
  it carries the security boundary, it does not define it.

## 2. The contract is the BlindRelay interface (already frozen)
The SDK's whole sync surface is three methods over an opaque `syncId` bucket (`index.d.ts BlindRelay`):
```
put(syncId, sealed): Promise<number>   // → arrival index (seq)
list(syncId, since):  Promise<number>  // → count of blobs at seq ≥ since
get(syncId, seq):     Promise<Uint8Array|null>
```
Any transport implements exactly these. `InMemoryRelay` (local/same-machine, tests) and now `HttpRelay`
(network) are the two implementations; `sync({ relay })` is unchanged. **DECISION D-T1: the transport
is an adapter, not a protocol change** — the reconcile/fork/anchor machinery never learns there is a
network.

## 3. Wire: Connect protocol, JSON codec, over HTTP/1.1 (D-DC4)
`proto/freehold/sync/v1/relay.proto` is the normative contract. `RelayService` = `PushBlob` /
`ListBlobs` / `GetBlob` (the three unary RPCs = the BlindRelay contract) + `Subscribe` (server-
streaming "receive updates"). Everything sensitive is an opaque `bytes` field.

- **Unary** = `POST /freehold.sync.v1.RelayService/<Method>`, JSON request/response body, Connect error
  envelope `{code,message}` with a mapped HTTP status. proto3-JSON maps `bytes`→base64 and
  `uint64`→decimal-string, which is exactly what `HttpRelay` emits/expects.
- **Streaming shape (D-DC4):** browser gRPC-Web has **no true bidi** — a browser-platform limit (no
  full-duplex request bodies, no HTTP/2 trailers to JS), not a gRPC one. So sync is modelled as **unary
  push + unary poll + server-streaming Subscribe**. `Subscribe` is delivered as SSE (one `data:{seq}`
  per arrival) and is **never load-bearing**: `sync()` converges on `list`/`get` alone (restricted
  networks, no-streaming proxies). Proven: the E2E asserts convergence on the poll path *and* a live
  Subscribe delivery.

> **DECISION D-T2: hand-implement the Connect JSON codec; keep @freehold/db dependency-free.** The
> `.proto` is the source of truth, but the server (`server/relay-server.mjs`, Node built-ins only) and
> the client (`packages/db/relay-http.js`, `fetch` only) implement the wire by hand. A `connect-es`
> client + `tonic`/`connect-go` server generated from the **same** `.proto` are drop-in replacements
> (binary codec, native gRPC-Web); **Envoy is a deployment option, not a dependency** — Connect servers
> speak gRPC-Web natively. We pay zero runtime deps now and keep the codegen door open.

## 4. Blindness (the load-bearing property)
The relay sees, per request: a 32-byte routing label `sync_id = HKDF(DEK, db_uuid)` and an opaque blob.
It cannot read, order-by, or interpret a blob; losing its entire store leaks *ciphertext + routing
labels* and nothing else ([[data-custody-protocol]] §2). The reference server enforces this **by
construction** — it holds base64 strings in a `Map` and copies them verbatim; there is no code path
that decodes a blob. `sync_id` reveals nothing about the user or contents, and devices that don't share
the DEK derive different labels (namespace isolation for free).

## 5. What was built
| Piece | File | Note |
|---|---|---|
| Wire contract | `proto/freehold/sync/v1/relay.proto` | `RelayService`; opaque `bytes` |
| Disclosure family (frozen, D-DC5) | `proto/freehold/custody/v1/custody.proto` | `DataRequest`/`Grant`/`Attestation`/`Disclosure`; messages only, server later |
| Blind relay server | `server/relay-server.mjs` | Node built-ins; JSON codec + SSE Subscribe; CORS; in-memory log |
| SDK adapter | `packages/db/relay-http.js` (+ `.d.ts`) | drop-in BlindRelay over `fetch`; `./relay-http` export |
| Harness | `examples/demo/sync-http-test.html` | `sync()` over `HttpRelay` |
| E2E | `tests/sync-http-e2e.spec.js` | two contexts converge over the real wire; stale; fork+preserve; Subscribe |

## 6. Honest limits / deferred
- **No relay auth yet.** The reference server is a single trust domain (dev / same-user). **Relay
  authentication** — rate-limiting and a `sync_id`-ownership proof so a stranger can't write to or
  enumerate your bucket — is the next transport item, and is *separate* from requester auth (D-DC2,
  Disclosure plane). Blindness ≠ authorization: a blind relay still needs to know *who may append to a
  bucket*. Until then, do not expose the relay to untrusted writers.
- **In-memory store.** The reference relay is dev-grade; a production relay swaps the `Map` for durable
  storage behind the same three writes. Blindness is unchanged.
- **Metadata.** The relay learns blob sizes, arrival times, and per-`sync_id` traffic volume — the
  usual encrypted-transport metadata surface. Padding / cover traffic is out of scope.
- **Disclosure plane server not built.** The custody messages are frozen (so the app SDK surface is
  stable) but disclosure still runs on the Local-plane broker (`examples/custody-app`); a remote
  Disclosure server reuses this same Connect stack when wanted.

## Cross-links
[[data-custody-protocol]] (§8 planes, D-DC4 Connect, D-DC5 one-.proto-family — this builds §11.4),
[[sync-epoch-design]] (blind-relay freshness / per-device epoch), [[vault-signing]] (the Attestation
message mirrors the shipped attest.rs), [[audit-readiness]] (pre-1.0, un-audited status).
