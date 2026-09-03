// The APP side of the data-custody protocol. Deliberately tiny and deliberately BLIND: an app is
// handed nothing but a MessagePort to the broker. It has no reference to the vault, the DEK, or the
// database — it can only authenticate itself, `request()` a grant, then `call()` capabilities the owner
// granted. This is the whole point: the app is a custodian, not an owner. (In the product this port is
// a cross-origin iframe/postMessage or a Connect RPC channel; here it is a MessageChannel to the same
// page's broker — the transport differs, the trust boundary is identical.)
//
// Requester auth (D-DC2, docs/requester-auth-design.md): before any request the app proves it IS its
// app_id by signing a broker challenge with its Ed25519 key. app_id is a commitment to that key, so
// the broker binds this port to a VERIFIED identity — the app can never claim another app's id.

import { signChallenge, _unb64 } from './app-identity.js';

export class AppClient {
  #port;
  #identity;
  #seq = 0;
  #pending = new Map();
  #readyResolve; #readyReject; #readyP;
  grantId = null;
  scopes = [];
  appId = null;
  grantToken = null; // D-DC3: the vault-signed, counterparty-verifiable token for this grant

  constructor(port, identity) {
    this.#port = port;
    this.#identity = identity;
    this.#readyP = new Promise((res, rej) => { this.#readyResolve = res; this.#readyReject = rej; });
    port.onmessage = (e) => this.#onMessage(e.data);
    port.start && port.start();
  }

  async #onMessage(m) {
    if (!m || typeof m !== 'object') return;
    if (m.t === 'challenge') {                       // broker handshake: prove our identity
      const hello = await signChallenge(this.#identity, _unb64(m.challenge));
      this.#port.postMessage({ t: 'hello', ...hello });
      return;
    }
    if (m.t === 'ready') { this.appId = m.appId; this.#readyResolve(true); return; }
    if (m.t === 'authfail') { this.#readyReject(new Error('app authentication rejected by broker')); return; }
    const p = this.#pending.get(m.rid);
    if (!p) return;
    this.#pending.delete(m.rid);
    p(m);
  }

  /** Resolves once the broker has verified this app's identity (or rejects if it refused). */
  ready() { return this.#readyP; }

  #send(msg) {
    return new Promise((resolve) => {
      const rid = ++this.#seq;
      this.#pending.set(rid, resolve);
      this.#port.postMessage({ ...msg, rid });
    });
  }

  /** Ask the owner to grant `scopes` for a stated `purpose`. Resolves true if granted. */
  async request(scopes, purpose) {
    await this.#readyP;
    const m = await this.#send({ t: 'request', scopes, purpose });
    if (m.t === 'grant') { this.grantId = m.grantId; this.scopes = m.scopes; this.grantToken = m.token || null; return true; }
    return false;
  }

  /** Invoke a granted capability. Throws if the owner revoked it or it was never granted. */
  async call(cap, args = {}) {
    await this.#readyP;
    if (!this.grantId) throw new Error('no grant — request() first');
    const m = await this.#send({ t: 'call', grantId: this.grantId, cap, args });
    if (!m.ok) throw new Error(m.error || 'call failed');
    return m.data;
  }

  get granted() { return !!this.grantId; }
}
