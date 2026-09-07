// Freehold device/browser test app — drives the REAL @freehold/db SDK against this platform's actual
// WebAuthn authenticator and OPFS (no virtual authenticator, unlike the Playwright specs). It exists
// to answer, on real hardware: does PRF+OPFS work here, and does the full lifecycle hold up? Vanilla
// DOM, zero dependencies (mirrors the SDK's own no-runtime-deps stance).

import { FreeholdVault } from '../../packages/db/index.js';

const $ = (id) => document.getElementById(id);
const logEl = $('log');
function log(msg, kind = '') {
  const t = new Date().toLocaleTimeString();
  const mark = kind === 'ok' ? '✅ ' : kind === 'bad' ? '❌ ' : kind === 'warn' ? '⚠️ ' : '';
  logEl.textContent += `${t}  ${mark}${msg}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}
// Wrap an async action so every failure surfaces in the log instead of a silent console throw.
function guard(fn) {
  return async (...a) => {
    try { await fn(...a); }
    catch (e) { log(e && e.message ? e.message : String(e), 'bad'); }
    finally { await refresh(); }
  };
}

let vault = null;

// Release the OPFS pool when this page is hidden (navigation / bfcache freeze) so another demo on the
// same origin can acquire it — a bfcached page otherwise keeps its worker holding the SAH handles and
// the next page hits createSyncAccessHandle InvalidStateError. Reload on bfcache restore to re-init.
window.addEventListener('pagehide', () => { try { vault && vault.close(); } catch {} });
window.addEventListener('pageshow', (e) => { if (e.persisted) location.reload(); });

// ---- capability preflight (the browser-matrix signal a tester needs first) ----
async function probe() {
  const box = $('caps');
  try {
    const caps = await FreeholdVault.capabilities(); // static: safe before open()
    const pill = (b) => `<span class="pill ${b ? 'ok' : 'bad'}">${b ? 'yes' : 'no'}</span>`;
    box.innerHTML = `
      <div class="row"><b>overall</b> ${pill(caps.ok)} ${caps.reason ? `<span class="muted">${caps.reason}</span>` : ''}</div>
      <table>
        ${Object.entries(caps).filter(([k]) => !['ok', 'reason'].includes(k))
          .map(([k, v]) => `<tr><td>${k}</td><td>${typeof v === 'boolean' ? pill(v) : `<code>${v}</code>`}</td></tr>`).join('')}
      </table>
      <p class="muted">${caps.ok ? 'This browser can run Freehold.' : 'This browser is missing a required capability — enroll is blocked.'}</p>`;
    return caps.ok;
  } catch (e) {
    box.innerHTML = `<span class="pill bad">preflight failed</span> <span class="muted">${e.message}</span>`;
    return false;
  }
}

// ---- one-time recovery-code display (mandatory-backup contract) ----
function showCode(code, title = 'Save your recovery code') {
  return new Promise((resolve) => {
    $('code-title').textContent = title;
    $('code-value').textContent = code;
    const dlg = $('code-dialog');
    $('code-copy').onclick = () => navigator.clipboard?.writeText(code).then(() => log('recovery code copied to clipboard'));
    $('code-done').onclick = () => { dlg.close(); resolve(); };
    dlg.showModal();
  });
}

// ---- state rendering ----
async function refresh() {
  const enrolled = vault ? await vault.isEnrolled() : false;
  const unlocked = vault ? await vault.isUnlocked() : false;
  const state = !vault ? 'not opened' : !enrolled ? 'not enrolled' : unlocked ? 'unlocked' : 'locked';
  const pill = $('state-pill');
  pill.textContent = state;
  pill.className = 'pill ' + (unlocked ? 'ok' : enrolled ? 'warn' : 'bad');

  // backup-owed signal (issue #2: enrollment is not "done" until a recovery method exists)
  const bp = $('backup-pill');
  if (enrolled && (await vault.needsBackup())) bp.innerHTML = '<span class="pill warn">backup owed — add a recovery code</span>';
  else bp.innerHTML = '';

  $('enroll').disabled = !vault || enrolled;
  $('unlock').disabled = !enrolled || unlocked;
  $('unlock-rec').disabled = !enrolled || unlocked;
  $('lock').disabled = !unlocked;
  // Envelope-only ops (a passkey assertion, no session) work while LOCKED — you should be able to
  // back up right after enroll. Data + rotation + export need a live session.
  for (const id of ['add-recovery', 'add-passkey', 'refresh-methods']) $(id).disabled = !enrolled;
  for (const id of ['note-add', 'note-refresh', 'rotate', 'export']) $(id).disabled = !unlocked;

  if (enrolled) await refreshMethods(); else $('methods').innerHTML = '';
  if (unlocked) await refreshNotes(); else $('notes').innerHTML = '';
}

async function refreshNotes() {
  try {
    await vault.sql('CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, body TEXT, at TEXT)');
    const rows = await vault.sql('SELECT id, body, at FROM notes ORDER BY id DESC LIMIT 50');
    $('notes').innerHTML = rows.length
      ? rows.map((r) => `<tr><td>${escapeHtml(r[0])}</td><td>${escapeHtml(r[1])}</td><td class="muted">${escapeHtml(r[2] ?? '')}</td></tr>`).join('')
      : '<tr><td colspan="3" class="muted">no notes yet</td></tr>';
  } catch (e) { log('notes: ' + e.message, 'bad'); }
}

async function refreshMethods() {
  const methods = await vault.listMethods();
  $('methods').innerHTML = methods.map((m) => `
    <tr><td>#${m.kekId}</td><td>${m.kind}</td>
    <td>${methods.length > 1 ? `<button data-kek="${m.kekId}" class="revoke danger">revoke</button>` : '<span class="muted">last method</span>'}</td></tr>`).join('');
  for (const b of document.querySelectorAll('.revoke')) {
    b.onclick = guard(async () => {
      log(`revoking method #${b.dataset.kek} (re-MACs the envelope under the DEK)…`);
      await vault.removeMethod(Number(b.dataset.kek));
      log(`method #${b.dataset.kek} revoked`, 'ok');
    });
  }
}

const escapeHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// ---- wire actions ----
$('enroll').onclick = guard(async () => {
  const { credId } = await vault.enroll();
  log(`enrolled + unlocked — passkey registered (credId ${credId.length} bytes), session open. ADD A RECOVERY CODE before you rely on this.`, 'ok');
});

$('unlock').onclick = guard(async () => {
  await vault.unlock();
  log('unlocked — session open (auto-locks after the SDK idle timeout)', 'ok');
});

$('unlock-rec').onclick = () => { $('rec-input').value = ''; $('rec-dialog').showModal(); };
$('rec-cancel').onclick = () => $('rec-dialog').close();
$('rec-go').onclick = guard(async () => {
  const code = $('rec-input').value.trim();
  $('rec-dialog').close();
  if (!code) return;
  // Advisory: warn on a likely-mistyped generated code, but still attempt (custom codes are valid).
  if (!(await vault.checkRecoveryCode(code))) {
    log('recovery code checksum did not match (a typo, or a custom code) — trying anyway', 'warn');
  }
  await vault.unlockWithRecovery(code);
  log('unlocked with recovery code', 'ok');
});

$('lock').onclick = guard(async () => { await vault.lock(); log('locked'); });

$('note-add').onclick = guard(async () => {
  const v = $('note-input').value.trim();
  if (!v) return;
  await vault.sql('INSERT INTO notes(body, at) VALUES (?, ?)', [v, new Date().toISOString()]);
  $('note-input').value = '';
  log('note saved (encrypted at rest)');
});
$('note-refresh').onclick = guard(refreshNotes);

$('add-recovery').onclick = guard(async () => {
  const code = await vault.addRecoveryCode();
  await showCode(code, 'Save your recovery code');
  log('recovery code added — backup satisfied', 'ok');
});

$('add-passkey').onclick = guard(async () => {
  const { credId } = await vault.addPasskey();
  log(`second passkey added (credId ${credId.length} bytes)`, 'ok');
});
$('refresh-methods').onclick = guard(refreshMethods);

$('rotate').onclick = guard(async () => {
  if (!confirm('Rotate the DEK? This re-encrypts every database, issues a NEW recovery code, and ORPHANS every other method (other passkeys + the current recovery code stop working). Continue?')) return;
  log('rotating DEK — staging shadow image + committing new envelope…');
  const newCode = await vault.rotateKey();
  await showCode(newCode, 'Rotation complete — save your NEW recovery code');
  log('DEK rotated: DB re-encrypted, old envelope refused, evicted methods orphaned. Re-admit a device by unlocking it with the new code + Add another passkey.', 'ok');
});

$('export').onclick = guard(async () => {
  const bytes = await vault.exportBundle();
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'vault.freehold'; a.click();
  URL.revokeObjectURL(url);
  log(`exported vault.freehold (${bytes.length} bytes) — no key inside; decrypt it with the recovery code + freehold-decrypt`, 'ok');
});

$('import').onclick = () => $('import-file').click();
$('import-file').onchange = guard(async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  const bytes = new Uint8Array(await file.arrayBuffer());
  await vault.importBundle(bytes);
  log(`imported ${file.name} (${bytes.length} bytes) — unlock with the synced passkey or a recovery code`, 'ok');
  e.target.value = '';
});

// ---- boot ----
(async () => {
  const ok = await probe();
  if (!ok) { log('capability preflight failed — this browser cannot run Freehold; enroll is disabled', 'warn'); await refresh(); return; }
  try {
    const wasmUrl = new URL('./pkg/freehold.js', location.href);
    vault = await FreeholdVault.open({ wasmUrl, rpName: 'Freehold Test App' });
    log('vault worker up — wasm core loaded', 'ok');
  } catch (e) {
    log('open() failed: ' + (e.message || e), 'bad');
  }
  await refresh();
})();
