// Freehold data-custody showcase — the first implementation of docs/data-custody-protocol.md on the
// Local plane with local/symmetric grants. The VAULT (this page) owns the data and hosts the broker;
// two APPS connect over MessageChannels and can only do what the owner grants. Vanilla DOM, zero deps.

import { FreeholdVault } from '../../../packages/db/index.js';
import { CustodyBroker } from './broker.js';
import { AppClient } from './app-client.js';
import { generateAppIdentity, signChallenge, _unb64 } from './app-identity.js';
import { verifyGrantToken } from './grant-token.js';

const $ = (id) => document.getElementById(id);
function log(msg) {
  const el = $('vault-log');
  el.textContent = new Date().toLocaleTimeString() + '  ' + msg + '\n' + el.textContent;
}

let vault = null;
let broker = null;
const apps = {};        // appId → { client, port(broker side kept by broker) }
let consentResolve = null;

// ---- vault lifecycle ----------------------------------------------------------------------------

async function boot() {
  try {
    const wasmUrl = new URL('./pkg/freehold.js', location.href);
    vault = await FreeholdVault.open({ wasmUrl, rpName: 'Freehold Custody' });
    log('vault worker up');
    $('enroll').disabled = false;
    if (await vault.isEnrolled()) { setState('locked'); $('unlock').disabled = false; }
  } catch (e) { log('boot failed: ' + e.message); }
}

function setState(s) {
  const pill = $('state-pill');
  pill.textContent = s;
  pill.className = 'pill ' + (s === 'unlocked' ? 'ok' : s === 'locked' ? 'warn' : 'bad');
}

async function enroll() {
  await vault.enroll(); // leaves the vault unlocked — no separate unlock gesture
  setState('unlocked');
  $('lock').disabled = false;
  $('unlock').disabled = true;
  await setupBrokerAndApps(); // rides the already-open session (no re-prompt)
  log('enrolled + unlocked — broker live; apps may request access');
}

async function unlock() {
  await vault.unlock();
  setState('unlocked');
  $('lock').disabled = false;
  $('unlock').disabled = true;
  await setupBrokerAndApps();
  log('unlocked — broker live; apps may request access');
}

async function lock() {
  await vault.lock();
  setState('locked');
  $('lock').disabled = true;
  $('unlock').disabled = false;
  setAppEnabled('Notes', false);
  setAppEnabled('Tasks', false);
  $('notes-request').disabled = true;
  $('tasks-request').disabled = true;
  log('locked — session torn down; grants persist, sealed');
}

async function reset() {
  if (vault) { try { await vault.lock(); } catch {} await vault.reset(); }
  log('device envelope forgotten — Enroll to start again');
  location.reload();
}

// ---- broker + consent + apps --------------------------------------------------------------------

async function setupBrokerAndApps() {
  broker = new CustodyBroker(vault);
  await broker.init();

  // Consent gesture: the passkey that unlocked the vault is the consent root; approving records the
  // grant in the vault's own sealed DB. (A per-grant re-assertion is a config option for higher-risk
  // scopes — see protocol §5.3.)
  broker.onConsent = (req) => new Promise((resolve) => {
    // Show the self-asserted name AND the cryptographically verified app_id (D-DC2): the name is
    // advisory, the app_id is what the grant is bound to and cannot be spoofed by a lookalike app.
    $('consent-text').innerHTML =
      `<b>${escapeHtml(req.name || req.appId)}</b> <span class="muted">(verified <code>${escapeHtml(req.appId)}</code>)</span>` +
      ` requests: <code>${req.scopes.map(escapeHtml).join('</code> <code>')}</code>` +
      `<br>purpose: <i>${escapeHtml(req.purpose || '—')}</i>`;
    $('consent').classList.add('show');
    consentResolve = (ok) => { $('consent').classList.remove('show'); consentResolve = null; resolve(ok); };
  });
  broker.onChange = () => { renderLedger(); };

  // Wire each app to the broker over its own MessageChannel (the app half holds only port2). Each app
  // has its own Ed25519 identity and authenticates to the broker before it can request anything.
  for (const name of ['Notes', 'Tasks']) {
    const identity = await generateAppIdentity(name);
    const ch = new MessageChannel();
    broker.connect(ch.port1);
    const client = new AppClient(ch.port2, identity);
    apps[name] = { client, identity };
    await client.ready(); // block until the broker verified this app's identity
  }

  await renderProfile();
  await renderLedger();
  $('notes-request').disabled = false;
  $('tasks-request').disabled = false;

  // Dev/E2E ONLY hook: drives a raw broker call with an explicit grantId, DELIBERATELY bypassing the
  // consent prompt (used to prove a REVOKED grant is rejected at the broker). Because it escapes the
  // consent gate it must NEVER exist in a real build, so it is gated twice: stripped from any
  // production bundle (import.meta.env.DEV) AND off by default in dev unless the page is opened with an
  // explicit `?e2e` flag. Merely loading the demo never exposes it.
  const dev = typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.DEV;
  const optedIn = new URLSearchParams(location.search).has('e2e');
  if (!(dev && optedIn)) return;
  window.__custody = {
    // Raw broker call bypassing the CONSENT prompt (the grant already exists) to prove a REVOKED grant
    // is rejected at the broker. It still AUTHENTICATES as the real app (D-DC2) — signing with that
    // app's identity — so the verified app_id matches the grant; only the revocation stops it.
    async brokerCall(appName, grantId, cap, args = {}) {
      const identity = apps[appName].identity;
      const ch = new MessageChannel();
      broker.connect(ch.port1);
      const c = new AppClient(ch.port2, identity);
      await c.ready();
      c.grantId = grantId;
      try { return { ok: true, data: await c.call(cap, args) }; }
      catch (e) { return { ok: false, error: e && e.message ? e.message : String(e) }; }
    },
    // Prove impersonation is IMPOSSIBLE: a forged manifest that CLAIMS a victim app's id but signs with
    // a different key is rejected, because app_id must equal H(pubkey). Resolves { authed:false }.
    async impersonate(appName) {
      const victimId = apps[appName].client.appId;
      const forged = await generateAppIdentity('EvilTwin');
      forged.appId = victimId;                                   // claim the victim's id...
      forged.manifest = { ...forged.manifest, appId: victimId, name: appName }; // ...but keep our key
      const ch = new MessageChannel();
      broker.connect(ch.port1);
      return new Promise((resolve) => {
        ch.port2.onmessage = async (e) => {
          const m = e.data;
          if (m.t === 'challenge') ch.port2.postMessage({ t: 'hello', ...(await signChallenge(forged, _unb64(m.challenge))) });
          else if (m.t === 'ready') resolve({ authed: true, appId: m.appId });
          else if (m.t === 'authfail') resolve({ authed: false });
        };
        ch.port2.start && ch.port2.start();
      });
    },
    tasksGrantId: () => apps.Tasks && apps.Tasks.client.grantId,
    // D-DC3: verify an app's grant TOKEN as a counterparty would — with ONLY the vault's pinned public
    // key + the pure verify, no DEK, no broker. `{ tamper }` mutates a field to prove tamper-evidence.
    async verifyGrant(appName, opts = {}) {
      const c = apps[appName].client;
      let token = c.grantToken;
      if (opts.tamper && token) token = { ...token, scopes: [...(token.scopes || []), 'profile.borrow'] };
      const vaultPublicKey = await vault.vaultPublicKey();
      return verifyGrantToken(
        { verifyAttestation: (att, expect) => vault.verifyAttestation(att, expect), vaultPublicKey },
        token, { scope: opts.scope });
    },
  };
}

$('consent-approve').onclick = () => consentResolve && consentResolve(true);
$('consent-deny').onclick = () => consentResolve && consentResolve(false);

// ---- App A: Notes (custodian) --------------------------------------------------------------------

async function notesRequest() {
  const ok = await apps.Notes.client.request(['notes.list', 'notes.add'], 'keep your private notes');
  if (!ok) { log('Notes: access denied'); return; }
  $('notes-status').textContent = 'granted'; $('notes-status').className = 'pill ok';
  setAppEnabled('Notes', true);
  await renderNotes();
}
async function noteAdd() {
  const body = $('note-input').value.trim();
  if (!body) return;
  await apps.Notes.client.call('notes.add', { body });
  $('note-input').value = '';
  await renderNotes();
}
async function renderNotes() {
  if (!apps.Notes.client.granted) return;
  const rows = await apps.Notes.client.call('notes.list');
  $('notes-list').innerHTML = rows.map((r) => `<li>${escapeHtml(r.body)}</li>`).join('') || '<li class="muted">no notes</li>';
}

// ---- App B: Tasks & Checkout (tiers 1·2·3) -------------------------------------------------------

async function tasksRequest() {
  const ok = await apps.Tasks.client.request(
    ['tasks.list', 'tasks.add', 'profile.attest.over18', 'profile.read', 'profile.borrow'],
    'run your tasks and complete an order');
  if (!ok) { log('Tasks: access denied'); return; }
  $('tasks-status').textContent = 'granted'; $('tasks-status').className = 'pill ok';
  setAppEnabled('Tasks', true);
  $('tasks-revoke').disabled = false;
  await renderTasks();
}
async function taskAdd() {
  const title = $('task-input').value.trim();
  if (!title) return;
  await apps.Tasks.client.call('tasks.add', { title });
  $('task-input').value = '';
  await renderTasks();
}
async function renderTasks() {
  if (!apps.Tasks.client.granted) return;
  const rows = await apps.Tasks.client.call('tasks.list');
  $('tasks-list').innerHTML = rows.map((r) => `<li>${escapeHtml(r.title)}</li>`).join('') || '<li class="muted">no tasks</li>';
}
async function tasksOver18() {
  const r = await apps.Tasks.client.call('profile.attest.over18');
  tasksOut(`18+ check → ${r.value ? '✓ verified' : '✗ no'}   (the app got a yes/no; your DOB never left the vault)`);
}
async function tasksShip() {
  const r = await apps.Tasks.client.call('profile.read', { fields: ['shipping_addr'] });
  tasksOut(`shipping address disclosed to app → ${r.shipping_addr}   (tier-3 disclosure, logged + revocable)`);
}
async function tasksPay() {
  const r = await apps.Tasks.client.call('profile.borrow', { field: 'email', processor: 'AcmePay' });
  tasksOut(`charged via ${r.processor} → receipt ${r.receipt}   (email released to the processor; the APP never received it — retainedByApp=${r.retainedByApp})`);
}
async function tasksRevoke() {
  await broker.revokeApp(apps.Tasks.client.appId);
  apps.Tasks.client.grantId = null;
  $('tasks-status').textContent = 'revoked'; $('tasks-status').className = 'pill bad';
  setAppEnabled('Tasks', false);
  $('tasks-revoke').disabled = true;
  tasksOut('access revoked — the app lost the door; your task data stays with you, in your vault.');
  log('Tasks revoked');
}
function tasksOut(s) { $('tasks-out').textContent = s; }

// ---- rendering ----------------------------------------------------------------------------------

async function renderProfile() {
  const p = await broker.profile();
  $('p-name').textContent = p.name || '—';
  $('p-email').textContent = p.email || '—';
  $('p-dob').textContent = p.dob || '—';
  $('p-ship').textContent = p.shipping_addr || '—';
}

async function renderLedger() {
  if (!broker) return;
  const rows = await broker.ledger();
  const body = $('ledger-body');
  if (!rows.length) { body.innerHTML = '<tr><td colspan="5" class="muted">no disclosures yet</td></tr>'; return; }
  body.innerHTML = rows.map((r) => {
    const t = new Date(r.ts).toLocaleTimeString();
    return `<tr><td>${t}</td><td>${escapeHtml(r.app)}</td>` +
      `<td class="tier tier${r.tier}">T${r.tier}</td><td><code>${escapeHtml(r.cap)}</code></td>` +
      `<td>${escapeHtml(r.detail)}</td></tr>`;
  }).join('');
}

function setAppEnabled(id, on) {
  if (id === 'Notes') {
    $('note-input').disabled = !on; $('note-add').disabled = !on;
  } else {
    for (const b of ['task-input', 'task-add', 'tasks-over18', 'tasks-ship', 'tasks-pay']) $(b).disabled = !on;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---- wire buttons -------------------------------------------------------------------------------
$('enroll').onclick = guard(enroll);
$('unlock').onclick = guard(unlock);
$('lock').onclick = guard(lock);
$('reset').onclick = guard(reset);
$('notes-request').onclick = guard(notesRequest);
$('note-add').onclick = guard(noteAdd);
$('tasks-request').onclick = guard(tasksRequest);
$('task-add').onclick = guard(taskAdd);
$('tasks-over18').onclick = guard(tasksOver18);
$('tasks-ship').onclick = guard(tasksShip);
$('tasks-pay').onclick = guard(tasksPay);
$('tasks-revoke').onclick = guard(tasksRevoke);

function guard(fn) {
  return async () => { try { await fn(); } catch (e) { log('✗ ' + (e && e.message ? e.message : String(e))); } };
}

boot();
