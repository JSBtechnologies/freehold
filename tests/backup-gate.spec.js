import { test, expect } from '@playwright/test';

// Proves issue #2: enrollment is NOT complete until a device-independent recovery method exists.
// After enroll() the vault reports needsBackup() === true (only this device's passkey can open it);
// once a recovery code is added, needsBackup() flips to false. The demo UI hangs its export gate on
// exactly this signal, so this is the behavioral contract behind the non-bypassable backup step.

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

test('backup gate: enroll owes a backup until a recovery code is added', async ({ browser }) => {
  test.setTimeout(120_000);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log('[pageerror]', e.message));
  await addVirtualAuthenticator(ctx, page);
  await page.goto(PAGE);
  await page.waitForFunction(() => !!window.FH);

  // Capability preflight must pass in this (supported) headless browser — regression guard for the
  // worker-only SyncAccessHandle probe that must NOT false-negative.
  const caps = await page.evaluate(() => window.FH.capabilities());
  expect(caps.ok).toBe(true);

  await page.evaluate(() => window.FH.open());
  await page.evaluate(() => window.FH.enroll());

  // Right after enroll: one passkey slot, no recovery — a backup is owed.
  expect(await page.evaluate(() => window.FH.hasRecoveryMethod())).toBe(false);
  expect(await page.evaluate(() => window.FH.needsBackup())).toBe(true);

  // Add the device-independent recovery method → backup satisfied.
  const code = await page.evaluate(() => window.FH.addRecoveryCode());
  expect(typeof code).toBe('string');
  expect(await page.evaluate(() => window.FH.hasRecoveryMethod())).toBe(true);
  expect(await page.evaluate(() => window.FH.needsBackup())).toBe(false);

  await ctx.close();
});
