import { test, expect } from '@playwright/test';

// E2E for the convenience (device-key) tier — docs/convenience-tier-design.md. The headline property:
// a device-key vault AUTO-UNLOCKS on reload with NO passkey gesture, yet the key is never stored in the
// clear (wrapped under a non-extractable WebCrypto key). No virtual authenticator is used — the whole
// point is that convenience mode needs no WebAuthn. Also checks: a recovery code is minted for
// durability, the data survives a full worker teardown (simulated reload), and the recovery code opens
// the same vault (durability path).

test('convenience tier: device-key auto-unlock, no gesture, key never at rest in the clear', async ({ browser }) => {
  test.setTimeout(120_000);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));

  await page.goto('/convenience-test.html');
  await page.waitForFunction(() => window.fhReady === true, null, { timeout: 30_000 });
  await page.evaluate(() => window.fh.open());

  // Enroll a convenience vault (no passkey). A recovery code is minted by default (durability).
  const code = await page.evaluate(() => window.fh.enrollConvenience({ backup: true }));
  expect(code, 'a recovery code is minted for durability').toBeTruthy();
  expect(await page.evaluate(() => window.fh.isConvenience())).toBe(true);
  expect(await page.evaluate(() => window.fh.needsBackup()), 'backup satisfied by the recovery code').toBe(false);

  // The wrapped secret is stored, but the RAW secret is NOT recoverable from storage: the wrapping
  // CryptoKey is non-extractable, so exporting it throws.
  const keyGuard = await page.evaluate(async () => {
    const openReq = indexedDB.open('freehold');
    const db = await new Promise((res) => { openReq.onsuccess = () => res(openReq.result); });
    const key = await new Promise((res) => { const r = db.transaction('meta').objectStore('meta').get('deviceKey'); r.onsuccess = () => res(r.result); });
    const wrap = await new Promise((res) => { const r = db.transaction('meta').objectStore('meta').get('deviceWrap'); r.onsuccess = () => res(r.result); });
    let extractable = 'unknown', threw = false;
    try { extractable = key.extractable; await crypto.subtle.exportKey('raw', key); }
    catch { threw = true; }
    return { hasKey: !!key, hasWrap: !!wrap, extractable, exportThrew: threw };
  });
  expect(keyGuard.hasKey && keyGuard.hasWrap).toBe(true);
  expect(keyGuard.extractable, 'device key is non-extractable').toBe(false);
  expect(keyGuard.exportThrew, 'raw device key cannot be exported from storage').toBe(true);

  // Unlock with NO gesture, write data.
  await page.evaluate(() => window.fh.unlock());
  expect(await page.evaluate(() => window.fh.isUnlocked())).toBe(true);
  await page.evaluate(() => window.fh.sql('CREATE TABLE t(v TEXT)', [], 'app'));
  await page.evaluate(() => window.fh.sql("INSERT INTO t(v) VALUES('conv')", [], 'app'));

  // Simulate a RELOAD: tear the worker fully down (DEK zeroized/gone), reopen, auto-unlock — no prompt.
  await page.evaluate(() => window.fh.lock());
  await page.evaluate(() => window.fh.close());
  await page.evaluate(() => window.fh.open());
  await page.evaluate(() => window.fh.unlock());   // <-- device key auto-unlocks; zero user interaction
  const rows = await page.evaluate(() => window.fh.sql('SELECT v FROM t', [], 'app'));
  expect(rows, 'data survives a full teardown + auto-unlock').toEqual([['conv']]);

  // Durability: the minted recovery code opens the same vault too.
  await page.evaluate(() => window.fh.lock());
  await page.evaluate((c) => window.fh.unlockWithRecovery(c), code);
  expect(await page.evaluate(() => window.fh.isUnlocked())).toBe(true);
  expect(await page.evaluate(() => window.fh.sql('SELECT v FROM t', [], 'app'))).toEqual([['conv']]);

  await page.evaluate(() => window.fh.reset());
  expect(errors, 'no uncaught page errors').toEqual([]);
  await ctx.close();
});
