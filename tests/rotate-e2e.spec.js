import { test, expect } from '@playwright/test';

// Proves issue #4 increment 2 end-to-end through the REAL SDK → worker → wasm path with a virtual
// authenticator: rotateKey() re-encrypts every DB under a fresh DEK′ and issues a new envelope that
// wraps DEK′ under ONLY this device's passkey + a freshly minted recovery code. Every other method is
// deliberately ORPHANED (D-RK1) — the operation that turns "revoke a slot" into true eviction of a
// device that already saw the key. We assert: data survives the rotation (the session comes back live
// under DEK′), the second passkey slot is gone, the OLD recovery code no longer opens, the NEW one
// does, and a trusted device is re-admitted by re-enrolling (unlock with the new code → addPasskey).

const PAGE = '/sync-test.html';

async function addVirtualAuthenticator(context, page) {
  const client = await context.newCDPSession(page);
  await client.send('WebAuthn.enable', { enableUI: false });
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  });
}

test('rotateKey(): re-encrypts under DEK′, orphans absent methods, data survives, old key evicted', async ({ browser }) => {
  test.setTimeout(120_000);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));
  await addVirtualAuthenticator(ctx, page);
  await page.goto(PAGE);
  await page.waitForFunction(() => !!window.FH);

  await page.evaluate(() => window.FH.open());
  await page.evaluate(() => window.FH.enroll());
  await page.evaluate(() => window.FH.unlock());

  // Real data must survive the physical re-encryption.
  await page.evaluate(() => window.FH.sql('CREATE TABLE t(v TEXT)', []));
  await page.evaluate(() => window.FH.sql("INSERT INTO t(v) VALUES ('survive-rotation')", []));

  // A device-independent recovery method (soon to be orphaned) + a second passkey (the slot rotation
  // evicts). After this the envelope holds 3 methods: passkey#0, recovery, passkey#2.
  const oldCode = await page.evaluate(() => window.FH.addRecoveryCode());
  await page.evaluate(() => window.FH.addPasskey());
  const before = await page.evaluate(() => window.FH.listMethods());
  expect(before.length).toBe(3);

  // ---- ROTATE ----
  const newCode = await page.evaluate(() => window.FH.rotateKey());
  expect(typeof newCode).toBe('string');
  expect(newCode).not.toBe(oldCode); // a fresh code, not the old one re-shown

  // rotateKey() re-unlock()s under DEK′ — the session is live and the data is intact (proves the
  // shadow image rolled forward and the manifest/plaintext carried across the re-key).
  expect(await page.evaluate(() => window.FH.isUnlocked())).toBe(true);
  const rows = await page.evaluate(() => window.FH.sql('SELECT v FROM t', []));
  expect(rows).toEqual([['survive-rotation']]);

  // The new envelope wraps DEK′ under ONLY this device's passkey + the new recovery code — exactly 2
  // methods. The previously-added second passkey slot is orphaned (D-RK1).
  const after = await page.evaluate(() => window.FH.listMethods());
  expect(after.length).toBe(2);
  expect(after.filter((m) => m.kind === 'passkey').length).toBe(1);
  expect(after.filter((m) => m.kind === 'recovery').length).toBe(1);

  // EVICTION: the OLD recovery code no longer opens the vault (its slot is gone and the DEK changed).
  await page.evaluate(() => window.FH.lock());
  const oldRejected = await page.evaluate(async (c) => {
    try { await window.FH.unlockWithRecovery(c); return false; } catch { return true; }
  }, oldCode);
  expect(oldRejected).toBe(true);
  expect(await page.evaluate(() => window.FH.isUnlocked())).toBe(false);

  // The NEW recovery code opens it, and the data is still there under DEK′.
  await page.evaluate((c) => window.FH.unlockWithRecovery(c), newCode);
  expect(await page.evaluate(() => window.FH.isUnlocked())).toBe(true);
  expect(await page.evaluate(() => window.FH.sql('SELECT v FROM t', []))).toEqual([['survive-rotation']]);

  // RE-ADMIT a trusted device: the recovery code is the bridge (device-independent). Unlocked via the
  // new code, addPasskey() re-enrolls a passkey — the supported path to bring an orphaned device back.
  await page.evaluate(() => window.FH.addPasskey());
  const readmitted = await page.evaluate(() => window.FH.listMethods());
  expect(readmitted.length).toBe(3);
  expect(readmitted.filter((m) => m.kind === 'passkey').length).toBe(2);

  await ctx.close();
});
