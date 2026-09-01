// Reactive singleton wrapping the Freehold vault + custody broker for the whole app. The DEK lives only
// in the worker (never here); this store holds reactive UI state and brokers app requests. One instance.
import { reactive } from 'vue';
import { FreeholdVault } from '../../../../packages/db/index.js';
import { CustodyBroker } from './broker.js';

// A per-app client the relying-party components use. Holds ONLY its MessagePort — no vault, no key.
class AppClient {
  #port; #seq = 0; #pending = new Map();
  grantId = null; scopes = [];
  constructor(port) {
    this.#port = port;
    port.onmessage = (e) => { const p = this.#pending.get(e.data.rid); if (p) { this.#pending.delete(e.data.rid); p(e.data); } };
    port.start && port.start();
  }
  #send(msg) { return new Promise((res) => { const rid = ++this.#seq; this.#pending.set(rid, res); this.#port.postMessage({ ...msg, rid }); }); }
  async request(scopes, purpose) { const m = await this.#send({ t: 'request', scopes, purpose }); if (m.t === 'grant') { this.grantId = m.grantId; this.scopes = m.scopes; return true; } return false; }
  async call(cap, args = {}) { if (!this.grantId) throw new Error('no grant — request() first'); const m = await this.#send({ t: 'call', grantId: this.grantId, cap, args }); if (!m.ok) throw new Error(m.error || 'call failed'); return m.data; }
  get granted() { return !!this.grantId; }
}

const state = reactive({
  status: 'boot',     // boot | no-vault | locked | unlocked | error
  busy: false,
  error: '',
  profile: {},
  apps: [],           // [{ app, scopes, active, purpose, last }]
  ledger: [],         // [{ ts, app, cap, tier, detail }]
  consent: null,      // { appId, scopes, purpose } while a dialog is pending
});

let vault = null;
let broker = null;
let consentResolve = null;
const clients = new Map();  // appId → AppClient

async function boot() {
  try {
    const wasmUrl = new URL('pkg/freehold.js', document.baseURI);
    vault = await FreeholdVault.open({ wasmUrl, rpName: 'Freehold' });
    state.status = (await vault.isEnrolled()) ? 'locked' : 'no-vault';
  } catch (e) { state.status = 'error'; state.error = e.message; }
}

async function enroll() {
  state.busy = true;
  try { await vault.enroll(); state.status = 'locked'; }
  catch (e) { state.error = e.message; } finally { state.busy = false; }
}

async function unlock() {
  state.busy = true;
  try {
    await vault.unlock();
    broker = new CustodyBroker(vault);
    await broker.init();
    broker.onConsent = (req) => new Promise((resolve) => { state.consent = req; consentResolve = resolve; });
    broker.onChange = () => { refresh(); };
    clients.clear();
    await refresh();
    state.status = 'unlocked';
  } catch (e) { state.error = e.message; } finally { state.busy = false; }
}

async function lock() {
  try { await vault.lock(); } catch { /* idempotent */ }
  broker = null; clients.clear();
  state.status = 'locked'; state.apps = []; state.ledger = []; state.profile = {};
}

async function refresh() {
  if (!broker) return;
  state.profile = await broker.profile();
  state.apps = await broker.apps();
  state.ledger = await broker.ledger();
}

// Get (or create) the client an app uses to talk to the broker. Each gets its own MessageChannel — the
// app half holds only port2; the broker keeps port1. Structured-clone boundary, no shared references.
function client(appId) {
  let c = clients.get(appId);
  if (!c) {
    const ch = new MessageChannel();
    broker.connect(ch.port1, appId);
    c = new AppClient(ch.port2);
    clients.set(appId, c);
  }
  return c;
}

function respondConsent(ok) {
  const r = consentResolve; consentResolve = null; state.consent = null;
  if (r) r(ok);
}

async function revokeApp(appId) {
  await broker.revokeApp(appId);
  const c = clients.get(appId);
  if (c) c.grantId = null;
}

async function setField(k, v) { await broker.setField(k, v); }

export function useFreehold() {
  return { state, boot, enroll, unlock, lock, refresh, client, respondConsent, revokeApp, setField };
}
