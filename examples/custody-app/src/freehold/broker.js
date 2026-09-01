// The custody BROKER — vault-side mediator for the data-custody protocol (docs/data-custody-protocol.md),
// Local plane, local grants. The ONLY code that touches the vault. Apps connect over a MessagePort and
// can do exactly two things: request({scopes,purpose}) → a consented, revocable GRANT; call(grantId,cap,
// args) → a fixed CAPABILITY, filtered to the grant. Apps never hold a key, never send SQL. Every grant
// and disclosure is written to a LEDGER in the vault's OWN encrypted DB. Tiers: 1 custodian (vault-only),
// 2 attestation (a fact; PII withheld), 3 disclosure/borrow (a minimized value leaves, logged+revocable).

const CONTROL_DB = 'vault';     // grants + ledger + per-app tables (notes)
const PROFILE_DB = 'profile';   // the user's owned identity data

const hex = (n) => [...crypto.getRandomValues(new Uint8Array(n))]
  .map((b) => b.toString(16).padStart(2, '0')).join('');

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
  onConsent = async () => false;   // set by the host: (req) => Promise<boolean>
  onChange = () => {};             // set by the host: fired after any grant/revoke/disclosure

  // Raw fields an app may EVER receive via profile.read. `dob` and `card` are ABSENT: DOB is only
  // usable through the over18 attestation, and the card is only usable through a borrow-to-processor —
  // so neither the raw birth date nor the card number is ever handed to an app.
  static DISCLOSABLE = ['name', 'email', 'shipping_addr'];
  static BORROWABLE = ['email', 'shipping_addr', 'card'];

  constructor(vault) { this.#vault = vault; this.caps = this.#buildCaps(); }

  async init() {
    await this.#vault.sql('CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, app TEXT, scopes TEXT, purpose TEXT, created TEXT, revoked INTEGER DEFAULT 0)', [], CONTROL_DB);
    await this.#vault.sql('CREATE TABLE IF NOT EXISTS ledger(ts TEXT, app TEXT, cap TEXT, tier INTEGER, detail TEXT, grantid TEXT)', [], CONTROL_DB);
    await this.#vault.sql('CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)', [], CONTROL_DB);
    await this.#vault.sql('CREATE TABLE IF NOT EXISTS profile(k TEXT PRIMARY KEY, v TEXT)', [], PROFILE_DB);
    const have = await this.#vault.sql('SELECT COUNT(*) FROM profile', [], PROFILE_DB);
    if (Number(have[0][0]) === 0) {
      for (const [k, v] of [
        ['name', 'Ada Lovelace'],
        ['email', 'ada@freehold.example'],
        ['dob', '1990-12-10'],
        ['shipping_addr', '12 Analytical Engine Way, London EC1'],
        ['card', '•••• •••• •••• 4242'],
      ]) await this.#vault.sql('INSERT INTO profile(k, v) VALUES(?, ?)', [k, v], PROFILE_DB);
    }
  }

  connect(port, appId) {
    port.onmessage = (e) => this.#onMessage(appId, port, e.data);
    port.start && port.start();
  }

  async #onMessage(appId, port, m) {
    if (!m || typeof m !== 'object') return;
    if (m.t === 'request') {
      const approved = await this.onConsent({ appId, scopes: m.scopes || [], purpose: m.purpose || '' });
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
    await this.#vault.sql('INSERT INTO grants(id, app, scopes, purpose, created, revoked) VALUES(?, ?, ?, ?, ?, 0)',
      [id, appId, JSON.stringify(scopes), purpose, new Date().toISOString()], CONTROL_DB);
    return id;
  }

  async #grant(grantId) {
    const rows = await this.#vault.sql('SELECT app, scopes, purpose, revoked FROM grants WHERE id=?', [grantId], CONTROL_DB);
    if (!rows.length) return null;
    const [app, scopes, purpose, revoked] = rows[0];
    return { app, scopes: JSON.parse(scopes), purpose, revoked: Number(revoked) === 1 };
  }

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
    await this.#vault.sql('INSERT INTO ledger(ts, app, cap, tier, detail, grantid) VALUES(?, ?, ?, ?, ?, ?)',
      [new Date().toISOString(), appId, cap, c.tier, detail, grantId], CONTROL_DB);
    return data;
  }

  async #field(k) {
    const rows = await this.#vault.sql('SELECT v FROM profile WHERE k=?', [k], PROFILE_DB);
    return rows.length ? rows[0][0] : null;
  }

  #buildCaps() {
    return {
      // tier 1 — custodian
      'notes.list': { tier: 1, run: async ({ vault }) => ({
        data: (await vault.sql('SELECT id, body FROM notes ORDER BY id DESC', [], CONTROL_DB)).map((r) => ({ id: r[0], body: r[1] })),
        detail: 'read own notes (vault-only)',
      }) },
      'notes.add': { tier: 1, run: async ({ vault, args }) => {
        await vault.sql('INSERT INTO notes(body) VALUES(?)', [String(args.body || '')], CONTROL_DB);
        return { data: { ok: true }, detail: 'wrote a note (vault-only)' };
      } },
      'notes.clear': { tier: 1, run: async ({ vault }) => {
        await vault.sql('DELETE FROM notes', [], CONTROL_DB);
        return { data: { ok: true }, detail: 'cleared own notes (vault-only)' };
      } },

      // tier 2 — attestation: return the FACT, withhold the data. The fact is SIGNED by the vault's
      // Ed25519 identity key and bound to the app's challenge (audience), so the app verifies it against
      // the vault's public key — not the broker's word (data-custody §6/D-DC3; docs/vault-signing-design).
      'profile.attest.over18': { tier: 2, run: async ({ vault, appId, args }) => {
        const age = ageFrom(await this.#field('dob'));
        const value = age != null && age >= 18;
        const audience = String(args.audience || appId);
        const attestation = await vault.attest(`profile.over18=${value}`, { audience });
        return {
          data: { claim: 'over18', value, attestation },
          detail: `attested over18=${value}, signed by your vault — DOB withheld`,
        };
      } },

      // tier 3 — disclosure: a minimized raw field goes to the app, logged + revocable.
      'profile.read': { tier: 3, run: async ({ appId, args }) => {
        const fields = (args.fields || []).filter((f) => CustodyBroker.DISCLOSABLE.includes(f));
        if (!fields.length) throw new Error('no disclosable fields (dob/card are never raw-disclosable)');
        const out = {};
        for (const f of fields) out[f] = await this.#field(f);
        return { data: out, detail: `disclosed {${fields.join(', ')}} → ${appId}` };
      } },

      // tier 3 — borrow: release a field to an external PROCESSOR for a one-off op. The app never
      // receives the raw value — only a receipt. Models "charge this card" without the app holding PII.
      'profile.borrow': { tier: 3, run: async ({ args }) => {
        const field = String(args.field || '');
        const processor = String(args.processor || 'processor');
        if (!CustodyBroker.BORROWABLE.includes(field)) throw new Error(`field "${field}" is not borrowable`);
        await this.#field(field); // read + release to the processor (simulated)
        const receipt = 'rcpt_' + hex(4);
        return {
          data: { receipt, processor, field, retainedByApp: false },
          detail: `released ${field} → ${processor} (receipt ${receipt}); app did NOT receive it`,
        };
      } },
    };
  }

  // ---- read models for the host UI ----
  async grants() {
    const rows = await this.#vault.sql('SELECT id, app, scopes, purpose, created, revoked FROM grants ORDER BY created DESC', [], CONTROL_DB);
    return rows.map((r) => ({ id: r[0], app: r[1], scopes: JSON.parse(r[2]), purpose: r[3], created: r[4], revoked: Number(r[5]) === 1 }));
  }

  // One row per app: its active scopes (union of non-revoked grants) and whether it currently has access.
  async apps() {
    const grants = await this.grants();
    const byApp = new Map();
    for (const g of grants) {
      const e = byApp.get(g.app) || { app: g.app, scopes: new Set(), active: false, purpose: g.purpose, last: g.created };
      if (!g.revoked) { g.scopes.forEach((s) => e.scopes.add(s)); e.active = true; }
      byApp.set(g.app, e);
    }
    return [...byApp.values()].map((e) => ({ app: e.app, scopes: [...e.scopes], active: e.active, purpose: e.purpose, last: e.last }));
  }

  async ledger() {
    const rows = await this.#vault.sql('SELECT ts, app, cap, tier, detail FROM ledger ORDER BY ts DESC, rowid DESC', [], CONTROL_DB);
    return rows.map((r) => ({ ts: r[0], app: r[1], cap: r[2], tier: Number(r[3]), detail: r[4] }));
  }

  async profile() {
    const rows = await this.#vault.sql('SELECT k, v FROM profile', [], PROFILE_DB);
    return Object.fromEntries(rows.map((r) => [r[0], r[1]]));
  }

  async setField(k, v) {
    await this.#vault.sql('INSERT INTO profile(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', [k, String(v)], PROFILE_DB);
    this.onChange();
  }
}
