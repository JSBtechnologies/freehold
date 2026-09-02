// Freehold blind relay — reference server for the Sync plane (proto/freehold/sync/v1/relay.proto).
//
// BLIND BY CONSTRUCTION: it stores, per routing label `sync_id`, an append-only log of opaque blobs
// and serves them back by arrival index. It never decodes a blob — the `blob`/`sync_id` fields are
// base64 strings it copies verbatim. Losing this database leaks ciphertext + routing labels and
// nothing else (data-custody-protocol §2). Zero dependencies: Node's built-in http only.
//
// Wire: the Connect protocol, JSON codec, over HTTP/1.1. A unary RPC is `POST /<pkg>.<Svc>/<Method>`
// with a JSON request body and a JSON response body; errors are `{code,message}` with a mapped HTTP
// status (connectrpc.com/docs/protocol). proto3 JSON maps `bytes`->base64 and `uint64`->decimal
// string, which is what the JS HttpRelay adapter emits/expects. The .proto is the normative contract;
// this server hand-implements it (no protobuf runtime), and a connect-es/tonic stack generated from
// the same .proto is a drop-in — binary codec + Envoy are deployment options, not requirements.
//
// Subscribe (server-streaming "receive updates") is delivered as Server-Sent Events: one `data: {seq}`
// line per newly-available index. Correctness never depends on it; ListBlobs/GetBlob is the poll path.
//
// Storage is in-memory (a reference/dev relay). A production relay swaps the Map for durable storage
// behind the same three writes; the blindness contract is unchanged. NO AUTH yet — a single trust
// domain / dev use; relay authentication (rate-limit + sync_id ownership proof) is a later item.

import http from 'node:http';

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
    if (!isB64(msg.syncId) || !isB64(msg.blob)) return { err: ['invalid_argument', 'syncId and blob must be base64'] };
    const b = bucket(msg.syncId);
    b.log.push(msg.blob);
    const seq = b.log.length - 1;
    for (const w of [...b.waiters]) { try { w(seq); } catch { /* waiter gone */ } }
    return { ok: { seq: String(seq) } };
  },
  ListBlobs(msg) {
    if (!isB64(msg.syncId)) return { err: ['invalid_argument', 'syncId must be base64'] };
    const since = toU64(msg.since ?? 0);
    if (since === null) return { err: ['invalid_argument', 'since must be a non-negative integer'] };
    const len = buckets.get(msg.syncId)?.log.length ?? 0;
    return { ok: { count: String(Math.max(0, len - since)) } };
  },
  GetBlob(msg) {
    if (!isB64(msg.syncId)) return { err: ['invalid_argument', 'syncId must be base64'] };
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
  if (!isB64(msg.syncId)) return sendErr(res, 'invalid_argument', 'syncId must be base64');
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
