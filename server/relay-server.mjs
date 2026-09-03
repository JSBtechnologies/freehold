// Freehold blind relay — reference server for the Sync plane (proto/freehold/sync/v1/relay.proto).
//
// BLIND BY CONSTRUCTION: it stores, per routing label `sync_id`, an append-only log of opaque blobs
// and serves them back by arrival index. It never decodes a blob — the `blob`/`sync_id` fields are
// base64 strings it copies verbatim. Losing this database leaks ciphertext + routing labels and
// nothing else (data-custody-protocol §2). Zero dependencies: Node's built-in http + crypto only.
//
// AUTHORIZATION without ever seeing the DEK (docs/relay-auth-design.md): blindness protects contents,
// not access. Every request carries a per-DB Ed25519 `pubkey` + a `sig` over a canonical op message.
// The relay authorizes STATELESSLY — no per-bucket ownership record — by checking, for each op:
//   (1) `sync_id == SHA-256("freehold-sync-id-v1" ‖ pubkey)[..16]`  — the bucket commits to the key;
//   (2) `sig` verifies over `canonical(method, sync_id, arg)` under `pubkey` (Ed25519, verify only).
// Possession of the bucket therefore IS possession of the DEK-derived key; a stranger cannot claim an
// unused bucket (they cannot invert SHA-256 to present a matching pubkey) and cannot forge a write.
// A coarse per-`pubkey` token bucket bounds abuse by an authorized-but-misbehaving device.
//
// Wire: the Connect protocol, JSON codec, over HTTP/1.1. A unary RPC is `POST /<pkg>.<Svc>/<Method>`
// with a JSON request body and a JSON response body; errors are `{code,message}` with a mapped HTTP
// status (connectrpc.com/docs/protocol). proto3 JSON maps `bytes`->base64 and `uint64`->decimal
// string. The .proto is the normative contract; this server hand-implements it (no protobuf runtime),
// and a connect-es/tonic stack generated from the same .proto is a drop-in.
//
// Subscribe (server-streaming "receive updates") is delivered as Server-Sent Events: one `data: {seq}`
// line per newly-available index. Correctness never depends on it; ListBlobs/GetBlob is the poll path.
//
// Storage is in-memory (a reference/dev relay). A production relay swaps the Map for durable storage
// behind the same three writes; the blindness + authorization contracts are unchanged.

import http from 'node:http';
import crypto from 'node:crypto';

const SVC = '/freehold.sync.v1.RelayService/';

// sync_id (base64) -> { log: string[] (base64 blobs), waiters: Set<(seq)=>void> }
const buckets = new Map();
function bucket(syncId) {
  let b = buckets.get(syncId);
  if (!b) { b = { log: [], waiters: new Set() }; buckets.set(syncId, b); }
  return b;
}

// Reject absurd inputs early (a blind relay still bounds resource use). 8 MiB base64 ~= 6 MiB blob.
const MAX_BODY = 12 * 1024 * 1024;
const isB64 = (s) => typeof s === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(s) && s.length <= MAX_BODY;
const toU64 = (v) => { // proto3 JSON: uint64 as string or number
  const n = typeof v === 'string' ? Number(v) : v;
  return Number.isInteger(n) && n >= 0 ? n : null;
};

// ---- relay-auth (docs/relay-auth-design.md, mirrors crates/freehold/src/relay_auth.rs) ----
const SYNC_ID_LABEL = Buffer.from('freehold-sync-id-v1');
const MSG_DOMAIN = Buffer.from('freehold-relay-auth-v1');
const METHOD = { PushBlob: 1, ListBlobs: 2, GetBlob: 3, Subscribe: 4 };

// The bucket id committed to a pubkey: SHA-256(LABEL ‖ pubkey)[..16].
function bucketIdFor(pubkey) {
  return crypto.createHash('sha256').update(SYNC_ID_LABEL).update(pubkey).digest().subarray(0, 16);
}
// The exact bytes signed for an op: DOMAIN ‖ u8(method) ‖ sync_id(16) ‖ u32_LE(arg.len) ‖ arg.
function canonicalMessage(method, syncId, arg) {
  const len = Buffer.alloc(4);
  len.writeUInt32LE(arg.length, 0);
  return Buffer.concat([MSG_DOMAIN, Buffer.from([method]), syncId, len, arg]);
}
function ed25519Verify(pubkey, msg, sig) {
  try {
    const key = crypto.createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: pubkey.toString('base64url') },
      format: 'jwk',
    });
    return crypto.verify(null, msg, key, sig);
  } catch { return false; }
}

// A per-pubkey token bucket bounds an authorized device's request rate (production tunes these; the
// defaults are generous so tests/dev never trip them while still capping a runaway client).
const RATE = { refillPerSec: 100, burst: 500 };
const limiters = new Map(); // pubkey(b64) -> { tokens, last }
function rateOk(pubB64) {
  const now = Date.now();
  let b = limiters.get(pubB64);
  if (!b) { b = { tokens: RATE.burst, last: now }; limiters.set(pubB64, b); }
  b.tokens = Math.min(RATE.burst, b.tokens + ((now - b.last) / 1000) * RATE.refillPerSec);
  b.last = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}

// Authorize one op. Returns `null` on success or `[code, message, status]` on rejection. Reads
// (List/Get/Subscribe) sign an empty arg; a Push binds its exact blob bytes.
function authorize(methodName, msg) {
  const method = METHOD[methodName];
  if (!isB64(msg.syncId)) return ['invalid_argument', 'syncId must be base64', 400];
  if (!isB64(msg.pubkey) || !isB64(msg.sig)) return ['unauthenticated', 'missing relay-auth pubkey/sig', 401];
  const syncId = Buffer.from(msg.syncId, 'base64');
  const pubkey = Buffer.from(msg.pubkey, 'base64');
  const sig = Buffer.from(msg.sig, 'base64');
  if (syncId.length !== 16 || pubkey.length !== 32 || sig.length !== 64) {
    return ['unauthenticated', 'bad relay-auth field length', 401];
  }
  // (1) the bucket must commit to this key — no trust-on-first-use, no land-grab.
  if (!crypto.timingSafeEqual(bucketIdFor(pubkey), syncId)) {
    return ['permission_denied', 'sync_id is not the bucket for this key', 403];
  }
  // (2) the signature must authenticate the op. Push binds the blob; reads bind an empty arg.
  const arg = method === METHOD.PushBlob && isB64(msg.blob) ? Buffer.from(msg.blob, 'base64') : Buffer.alloc(0);
  if (!ed25519Verify(pubkey, canonicalMessage(method, syncId, arg), sig)) {
    return ['unauthenticated', 'relay-auth signature invalid', 401];
  }
  if (!rateOk(msg.pubkey)) return ['resource_exhausted', 'rate limit exceeded', 429];
  return null;
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Connect-Protocol-Version');
}
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(body);
}
function sendErr(res, code, message, status = 400) {
  sendJson(res, status, { code, message }); // Connect error envelope
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const handlers = {
  PushBlob(msg) {
    if (!isB64(msg.blob)) return { err: ['invalid_argument', 'blob must be base64'] };
    const b = bucket(msg.syncId);
    b.log.push(msg.blob);
    const seq = b.log.length - 1;
    for (const w of [...b.waiters]) { try { w(seq); } catch { /* waiter gone */ } }
    return { ok: { seq: String(seq) } };
  },
  ListBlobs(msg) {
    const since = toU64(msg.since ?? 0);
    if (since === null) return { err: ['invalid_argument', 'since must be a non-negative integer'] };
    const len = buckets.get(msg.syncId)?.log.length ?? 0;
    return { ok: { count: String(Math.max(0, len - since)) } };
  },
  GetBlob(msg) {
    const seq = toU64(msg.seq);
    if (seq === null) return { err: ['invalid_argument', 'seq must be a non-negative integer'] };
    const blob = buckets.get(msg.syncId)?.log[seq];
    return { ok: blob == null ? { blob: '', found: false } : { blob, found: true } };
  },
};

async function handleUnary(method, req, res) {
  let msg;
  try { msg = JSON.parse(await readBody(req) || '{}'); }
  catch { return sendErr(res, 'invalid_argument', 'request body must be JSON'); }
  const h = handlers[method];
  if (!h) return sendErr(res, 'unimplemented', `no method ${method}`, 404);
  const denied = authorize(method, msg);
  if (denied) return sendErr(res, denied[0], denied[1], denied[2]);
  const r = h(msg);
  if (r.err) return sendErr(res, r.err[0], r.err[1]);
  return sendJson(res, 200, r.ok);
}

// Server-streaming Subscribe as SSE. Emits already-available indices immediately, then one event per
// arrival, until the client disconnects. A blind push notification: only an integer index crosses.
async function handleSubscribe(req, res) {
  let msg;
  try { msg = JSON.parse(await readBody(req) || '{}'); }
  catch { return sendErr(res, 'invalid_argument', 'request body must be JSON'); }
  const denied = authorize('Subscribe', msg);
  if (denied) return sendErr(res, denied[0], denied[1], denied[2]);
  const since = toU64(msg.since ?? 0);
  if (since === null) return sendErr(res, 'invalid_argument', 'since must be a non-negative integer');

  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  const b = bucket(msg.syncId);
  const emit = (seq) => { try { res.write(`data: ${JSON.stringify({ seq: String(seq) })}\n\n`); } catch { /* closed */ } };
  for (let i = since; i < b.log.length; i++) emit(i); // catch up
  const waiter = (seq) => { if (seq >= since) emit(seq); };
  b.waiters.add(waiter);
  req.on('close', () => { b.waiters.delete(waiter); });
}

export function createRelayServer() {
  return http.createServer((req, res) => {
    cors(res);
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    if (req.method === 'GET' && req.url === '/healthz') return sendJson(res, 200, { ok: true });
    if (req.method !== 'POST' || !req.url.startsWith(SVC)) return sendErr(res, 'not_found', 'unknown route', 404);
    const method = req.url.slice(SVC.length);
    if (method === 'Subscribe') return handleSubscribe(req, res);
    return handleUnary(method, req, res);
  });
}

// Run directly: `node server/relay-server.mjs [port]`
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('relay-server.mjs')) {
  const port = Number(process.argv[2] || process.env.PORT || 5180);
  createRelayServer().listen(port, () => console.log(`freehold blind relay on :${port}`));
}
