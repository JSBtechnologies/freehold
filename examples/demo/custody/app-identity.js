// Cryptographic app identity for the data-custody Disclosure plane (docs/requester-auth-design.md,
// D-DC2). Origin- or name-asserted app identity is PHISHABLE: a lookalike app can claim another app's
// id to piggyback on its grants or misrepresent itself in the consent prompt. Instead an app proves
// possession of an Ed25519 key, and its `app_id` is a COMMITMENT to that key:
//
//     app_id = "app_" + base64url( SHA-256("freehold-app-id-v1" ‖ pubkey) )[..12 bytes]
//
// The broker authorizes an app statelessly, with NO registry: it checks (1) app_id == H(pubkey) and
// (2) an Ed25519 signature over a fresh broker challenge. A malicious app therefore cannot claim
// another app's id (it can't produce the committed pubkey) nor forge identity in the consent UI. This
// mirrors the relay-auth pubkey↔sync_id binding (D-RA1) on the Disclosure plane, and reuses WebCrypto
// Ed25519 (browser + Node) — no invented crypto. The self-asserted `name` is advisory (shown in
// consent), never load-bearing; the app_id is the verified identity.

const subtle = globalThis.crypto.subtle;
const te = (s) => new TextEncoder().encode(s);
const ID_LABEL = te('freehold-app-id-v1');
const AUTH_DOMAIN = te('freehold-app-auth-v1');

const concat = (...parts) => {
  let n = 0; for (const p of parts) n += p.length;
  const out = new Uint8Array(n); let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const b64url = (u8) => b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = (s) => { const t = atob(s); const a = new Uint8Array(t.length); for (let i = 0; i < t.length; i++) a[i] = t.charCodeAt(i); return a; };

/** The app_id committed to a raw 32-byte Ed25519 public key. */
export async function appIdFromPubkey(pubkey) {
  const d = new Uint8Array(await subtle.digest('SHA-256', concat(ID_LABEL, pubkey)));
  return 'app_' + b64url(d.slice(0, 12));
}

/** Mint a fresh app identity: an Ed25519 keypair, its committed app_id, and a self-certifying manifest
 *  (the app half keeps the private key; only the manifest + per-challenge signatures ever cross). */
export async function generateAppIdentity(name) {
  const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pubkey = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const appId = await appIdFromPubkey(pubkey);
  return { name, appId, pubkey, privateKey: kp.privateKey, manifest: { v: 1, alg: 'Ed25519', appId, name, pubkey: b64(pubkey) } };
}

// The exact bytes signed to authenticate: DOMAIN ‖ app_id ‖ challenge (domain-separated, bound to the
// claimed id so a signature for one identity can't be replayed as another).
const authMessage = (appId, challenge) => concat(AUTH_DOMAIN, te(appId), challenge);

/** App side: sign a broker challenge, returning the `hello` payload `{ manifest, sig }`. */
export async function signChallenge(identity, challenge) {
  const sig = new Uint8Array(await subtle.sign('Ed25519', identity.privateKey, authMessage(identity.appId, challenge)));
  return { manifest: identity.manifest, sig: b64(sig) };
}

/** Broker side: verify a `hello` against the `challenge` it issued. Returns the VERIFIED app_id, or
 *  null on any failure. Pure — public values only, no vault/DEK. Enforces app_id == H(pubkey) FIRST
 *  (the anti-impersonation commitment), then the Ed25519 signature over the challenge. */
export async function verifyHello(hello, challenge) {
  const m = hello && hello.manifest;
  if (!m || m.alg !== 'Ed25519' || typeof m.pubkey !== 'string' || typeof m.appId !== 'string' || typeof hello.sig !== 'string') return null;
  let pubkey, sig;
  try { pubkey = unb64(m.pubkey); sig = unb64(hello.sig); } catch { return null; }
  if (pubkey.length !== 32 || sig.length !== 64) return null;
  if (m.appId !== await appIdFromPubkey(pubkey)) return null; // (1) app_id must commit to the pubkey
  let key;
  try { key = await subtle.importKey('raw', pubkey, { name: 'Ed25519' }, false, ['verify']); } catch { return null; }
  const ok = await subtle.verify('Ed25519', key, sig, authMessage(m.appId, challenge)); // (2) signature
  return ok ? m.appId : null;
}

/** A fresh 32-byte broker challenge (anti-replay: each connection binds its own). */
export const randomChallenge = () => crypto.getRandomValues(new Uint8Array(32));

export const _b64 = b64;      // shared base64 helpers for the broker/app-client handshake framing
export const _unb64 = unb64;
