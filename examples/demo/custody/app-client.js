// The APP side of the data-custody protocol. Deliberately tiny and deliberately BLIND: an app is
// handed nothing but a MessagePort to the broker. It has no reference to the vault, the DEK, or the
// database — it can only `request()` a grant and then `call()` capabilities the owner granted. This is
// the whole point: the app is a custodian, not an owner. (In the product this port is a cross-origin
// iframe/postMessage or a Connect RPC channel; here it is a MessageChannel to the same page's broker —
// the transport differs, the trust boundary is identical: structured-clone messages, no shared refs.)

export class AppClient {
  #port;
  #seq = 0;
  #pending = new Map();
  grantId = null;
  scopes = [];

  constructor(port) {
    this.#port = port;
    port.onmessage = (e) => {
      const m = e.data;
      const p = this.#pending.get(m.rid);
      if (!p) return;
      this.#pending.delete(m.rid);
      p(m);
    };
    port.start && port.start();
  }

  #send(msg) {
    return new Promise((resolve) => {
      const rid = ++this.#seq;
      this.#pending.set(rid, resolve);
      this.#port.postMessage({ ...msg, rid });
    });
  }

  /** Ask the owner to grant `scopes` for a stated `purpose`. Resolves true if granted. */
  async request(scopes, purpose) {
    const m = await this.#send({ t: 'request', scopes, purpose });
    if (m.t === 'grant') { this.grantId = m.grantId; this.scopes = m.scopes; return true; }
    return false;
  }

  /** Invoke a granted capability. Throws if the owner revoked it or it was never granted. */
  async call(cap, args = {}) {
    if (!this.grantId) throw new Error('no grant — request() first');
    const m = await this.#send({ t: 'call', grantId: this.grantId, cap, args });
    if (!m.ok) throw new Error(m.error || 'call failed');
    return m.data;
  }

  get granted() { return !!this.grantId; }
}
