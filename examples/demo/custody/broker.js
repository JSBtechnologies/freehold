// The custody BROKER — the vault-side mediator for the data-custody protocol
// (docs/data-custody-protocol.md, Local plane, symmetric/local grants). It is the ONLY code that
// touches the vault. Apps connect over a MessagePort and can do exactly two things:
//   1. request({ scopes, purpose })  → a consent gesture → a stored, revocable GRANT
//   2. call(grantId, cap, args)      → the broker runs a fixed CAPABILITY, filtered to the grant
// Apps NEVER receive the DEK, NEVER hold a key, and NEVER send SQL — every query is one the broker
// owns. Every grant and every disclosure is written to an append-only LEDGER in the vault's OWN
// encrypted DB, so the audit trail is itself owned + sealed. Tiers (per §3 of the protocol):
//   tier 1  vault-only / custodian  — the app operates on ITS OWN namespace; nothing leaves the vault
//   tier 2  attestation             — a FACT is returned (e.g. over18), the underlying PII is withheld
//   tier 3  disclosure / borrow     — a minimized raw value leaves, logged + revocable

// Namespaces are SQLite files in the vault. The session pool has a fixed slot budget, so this
// showcase keeps to two files: `vault` (control plane + per-app tables) and `profile` (shared PII).
// Per-app SEPARATE files (app:<id>) is the production form — the broker enforcement is identical
// either way (it mediates every query; apps never hold a key or send SQL). See protocol §7.
import { verifyHello, randomChallenge, _b64 } from './app-identity.js';

const CONTROL_DB = 'vault';     // grants + ledger + per-app tables (notes, tasks)
const PROFILE_DB = 'profile';   // the user's shared PII (owned; apps only ever get scoped views)

const hex = (n) => [...crypto.getRandomValues(new Uint8Array(n))]
  .map((b) => b.toString(16).padStart(2, '0')).join('');

// Whole-year age from a 'YYYY-MM-DD' date of birth, computed HERE and never returned to any app.
function ageFrom(dob) {
  const d = new Date(dob + 'T00:00:00Z');
  if (Number.isNaN(d.getTime())) return null;
  const now = new Date();
  let age = now.getUTCFullYear() - d.getUTCFullYear();
  const m = now.getUTCMonth() - d.getUTCMonth();
  if (m < 0 || (m === 0 && now.getUTCDate() < d.getUTCDate())) age--;
  return age;
}

export class CustodyBroker {
  #vault;
  #ports = new Map();          // appId → MessagePort
  onConsent = async () => false; // set by the host UI: (req) => Promise<boolean>
  onChange = () => {};           // set by the host UI: fired after any grant/revoke/disclosure

  constructor(vault) {
    this.#vault = vault;
    this.caps = this.#buildCaps();
  }

  // Fields an app may EVER receive raw via profile.read. `dob` is deliberately ABSENT — the only way
  // to use it is the over18 attestation (tier 2), so raw date-of-birth never leaves the vault.
  static DISCLOSABLE = ['name', 'email', 'shipping_addr'];

  async init() {
    // Control plane: grants + append-only ledger, in the vault's own sealed DB.
    await this.#vault.sql(
      'CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, app TEXT, scopes TEXT, purpose TEXT, created TEXT, revoked INTEGER DEFAULT 0)',
      [], CONTROL_DB);
    await this.#vault.sql(
      'CREATE TABLE IF NOT EXISTS ledger(ts TEXT, app TEXT, cap TEXT, tier INTEGER, detail TEXT, grantid TEXT)',
      [], CONTROL_DB);
    // The user's shared profile (owned data). Seed a demo persona once.
    await this.#vault.sql('CREATE TABLE IF NOT EXISTS profile(k TEXT PRIMARY KEY, v TEXT)', [], PROFILE_DB);
    const have = await this.#vault.sql('SELECT COUNT(*) FROM profile', [], PROFILE_DB);
    if (Number(have[0][0]) === 0) {
      const seed = [
        ['name', 'Ada Lovelace'],
        ['email', 'ada@freehold.example'],
        ['dob', '1990-12-10'],
        ['shipping_addr', '12 Analytical Engine Way, London'],
      ];
      for (const [k, v] of seed) {
        await this.#vault.sql('INSERT INTO profile(k, v) VALUES(?, ?)', [k, v], PROFILE_DB);
      }
    }
    // Per-app custodian tables (broker-scoped; the production form gives each app its own file).
    await this.#vault.sql('CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)', [], CONTROL_DB);
    await this.#vault.sql('CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, done INTEGER DEFAULT 0)', [], CONTROL_DB);
  }

  // Attach the broker to an app's MessagePort. The app half never sees anything but this port. The app
  // must AUTHENTICATE first (D-DC2): the broker issues a challenge, the app returns a signed manifest,
  // and the broker binds this port to the VERIFIED app_id (app_id == H(pubkey) ∧ signature) — it never
  // trusts a self-asserted id in a later message. Until authenticated, request/call are ignored.
  connect(port) {
    let appId = null, appName = null;
    const challenge = randomChallenge();
    port.onmessage = async (e) => {
      const m = e.data;
      if (!m || typeof m !== 'object') return;
      if (!appId) {
        if (m.t !== 'hello') return; // must authenticate before anything else
        const verified = await verifyHello(m, challenge);
        if (!verified) { port.postMessage({ t: 'authfail' }); return; }
        appId = verified; appName = String(m.manifest.name || verified);
        this.#ports.set(appId, port);
        port.postMessage({ t: 'ready', appId, name: appName });
        return;
      }
      await this.#onMessage(appId, appName, port, m);
    };
    port.postMessage({ t: 'challenge', challenge: _b64(challenge) });
    port.start && port.start();
  }

  async #onMessage(appId, appName, port, m) {
    if (!m || typeof m !== 'object') return;
    if (m.t === 'request') {
      const approved = await this.onConsent({ appId, name: appName, scopes: m.scopes || [], purpose: m.purpose || '' });
      if (!approved) { port.postMessage({ t: 'denied', rid: m.rid }); return; }
      const grantId = await this.#recordGrant(appId, m.scopes || [], m.purpose || '');
      this.onChange();
      port.postMessage({ t: 'grant', rid: m.rid, grantId, scopes: m.scopes || [] });
    } else if (m.t === 'call') {
      try {
        const data = await this.#fulfill(appId, m.grantId, m.cap, m.args || {});
        this.onChange();
        port.postMessage({ t: 'result', rid: m.rid, ok: true, data });
      } catch (err) {
        port.postMessage({ t: 'result', rid: m.rid, ok: false, error: err && err.message ? err.message : String(err) });
      }
    }
  }

  async #recordGrant(appId, scopes, purpose) {
    const id = 'g_' + hex(6);
    await this.#vault.sql(
      'INSERT INTO grants(id, app, scopes, purpose, created, revoked) VALUES(?, ?, ?, ?, ?, 0)',
      [id, appId, JSON.stringify(scopes), purpose, new Date().toISOString()], CONTROL_DB);
    return id;
  }

  async #grant(grantId) {
    const rows = await this.#vault.sql(
      'SELECT app, scopes, purpose, revoked FROM grants WHERE id=?', [grantId], CONTROL_DB);
    if (!rows.length) return null;
    const [app, scopes, purpose, revoked] = rows[0];
    return { app, scopes: JSON.parse(scopes), purpose, revoked: Number(revoked) === 1 };
  }

  async revoke(grantId) {
    await this.#vault.sql('UPDATE grants SET revoked=1 WHERE id=?', [grantId], CONTROL_DB);
    this.onChange();
  }

  // Revoke every grant an app holds (the "kick the tenant out" button). The app's OWN namespace data
  // stays in the vault — you own it — the app just loses the door.
  async revokeApp(appId) {
    await this.#vault.sql('UPDATE grants SET revoked=1 WHERE app=?', [appId], CONTROL_DB);
    this.onChange();
  }

  async #fulfill(appId, grantId, cap, args) {
    const g = await this.#grant(grantId);
    if (!g) throw new Error('no such grant');
    if (g.app !== appId) throw new Error('grant does not belong to this app');
    if (g.revoked) throw new Error('access revoked by the owner');
    if (!g.scopes.includes(cap)) throw new Error(`capability "${cap}" not in this grant`);
    const c = this.caps[cap];
    if (!c) throw new Error(`unknown capability "${cap}"`);
    const { data, detail } = await c.run({ vault: this.#vault, appId, args });
    await this.#log(appId, cap, c.tier, detail, grantId);
    return data;
  }

  async #log(appId, cap, tier, detail, grantId) {
    await this.#vault.sql(
      'INSERT INTO ledger(ts, app, cap, tier, detail, grantid) VALUES(?, ?, ?, ?, ?, ?)',
      [new Date().toISOString(), appId, cap, tier, detail, grantId], CONTROL_DB);
  }

  async #profileField(k) {
    const rows = await this.#vault.sql('SELECT v FROM profile WHERE k=?', [k], PROFILE_DB);
    return rows.length ? rows[0][0] : null;
  }

  // ---- the capability vocabulary (the ONLY things an app can ever do) ----
  #buildCaps() {
    return {
      // tier 1 — custodian: the app operates on its OWN table; nothing leaves the vault.
      'notes.list': { tier: 1, run: async ({ vault }) => ({
        data: (await vault.sql('SELECT id, body FROM notes ORDER BY id DESC', [], CONTROL_DB)).map((r) => ({ id: r[0], body: r[1] })),
        detail: 'read own notes (vault-only)',
      }) },
      'notes.add': { tier: 1, run: async ({ vault, args }) => {
        await vault.sql('INSERT INTO notes(body) VALUES(?)', [String(args.body || '')], CONTROL_DB);
        return { data: { ok: true }, detail: 'wrote a note (vault-only)' };
      } },
      'tasks.list': { tier: 1, run: async ({ vault }) => ({
        data: (await vault.sql('SELECT id, title, done FROM tasks ORDER BY id DESC', [], CONTROL_DB)).map((r) => ({ id: r[0], title: r[1], done: Number(r[2]) === 1 })),
        detail: 'read own tasks (vault-only)',
      }) },
      'tasks.add': { tier: 1, run: async ({ vault, args }) => {
        await vault.sql('INSERT INTO tasks(title) VALUES(?)', [String(args.title || '')], CONTROL_DB);
        return { data: { ok: true }, detail: 'wrote a task (vault-only)' };
      } },

      // tier 2 — attestation: return the FACT, withhold the data. Raw DOB never leaves the vault.
      'profile.attest.over18': { tier: 2, run: async ({ args }) => {
        const age = ageFrom(await this.#profileField('dob'));
        const value = age != null && age >= 18;
        return { data: { claim: 'over18', value }, detail: `attested over18=${value} — DOB withheld` };
      } },

      // tier 3 — disclosure: a MINIMIZED raw field goes to the app, logged + revocable. `dob` can
      // never be requested here (not in DISCLOSABLE) — only the over18 fact above.
      'profile.read': { tier: 3, run: async ({ appId, args }) => {
        const fields = (args.fields || []).filter((f) => CustodyBroker.DISCLOSABLE.includes(f));
        if (!fields.length) throw new Error('no disclosable fields requested (dob is never raw-disclosable)');
        const out = {};
        for (const f of fields) out[f] = await this.#profileField(f);
        return { data: out, detail: `disclosed {${fields.join(', ')}} → ${appId}` };
      } },

      // tier 3 — borrow: release a field to an external PROCESSOR for a one-off op; the app itself
      // never receives the raw value, only a receipt. Models "charge this card / ship to this address"
      // without the app ever holding the PII.
      'profile.borrow': { tier: 3, run: async ({ args }) => {
        const field = String(args.field || '');
        const processor = String(args.processor || 'processor');
        if (!CustodyBroker.DISCLOSABLE.includes(field)) throw new Error(`field "${field}" is not borrowable`);
        const value = await this.#profileField(field);
        // "Send" to the processor (simulated). In a real deployment this is the tier-3 disclosure plane
        // (Connect/gRPC-Web); the value is released for THIS purpose and not returned to the app.
        const ref = 'rcpt_' + hex(4);
        return {
          data: { receipt: ref, processor, field, retainedByApp: false },
          detail: `released ${field} → ${processor} (receipt ${ref}); app did NOT receive the value`,
        };
      } },
    };
  }

  // ---- read models for the host UI ----
  async grants() {
    const rows = await this.#vault.sql('SELECT id, app, scopes, purpose, created, revoked FROM grants ORDER BY created DESC', [], CONTROL_DB);
    return rows.map((r) => ({ id: r[0], app: r[1], scopes: JSON.parse(r[2]), purpose: r[3], created: r[4], revoked: Number(r[5]) === 1 }));
  }

  async ledger() {
    const rows = await this.#vault.sql('SELECT ts, app, cap, tier, detail FROM ledger ORDER BY ts DESC, rowid DESC', [], CONTROL_DB);
    return rows.map((r) => ({ ts: r[0], app: r[1], cap: r[2], tier: Number(r[3]), detail: r[4] }));
  }

  async profile() {
    const rows = await this.#vault.sql('SELECT k, v FROM profile', [], PROFILE_DB);
    return Object.fromEntries(rows.map((r) => [r[0], r[1]]));
  }
}
