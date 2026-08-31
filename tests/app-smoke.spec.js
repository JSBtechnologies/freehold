import { test, expect } from '@playwright/test';

// Smoke test for the device/browser test app (examples/demo/app.html). A virtual authenticator stands
// in for the real gesture so CI-less local runs still exercise the full wiring: preflight → open →
// enroll → mandatory recovery-code backup → unlock → write+read a note → lock. Proves the app's SDK
// wiring and DOM flow work; on real hardware the same buttons drive the platform authenticator.

async function addVirtualAuthenticator(context, page) {
  const client = await context.newCDPSession(page);
  await client.send('WebAuthn.enable', { enableUI: false });
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, hasPrf: true,
      automaticPresenceSimulation: true, isUserVerified: true,
    },
  });
}

test('test app: preflight → enroll → backup → unlock → note round-trips', async ({ browser }) => {
  test.setTimeout(120_000);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await addVirtualAuthenticator(ctx, page);

  await page.goto('/app.html');
  // Boots: preflight passes and the worker comes up.
  await expect(page.locator('#caps .pill.ok').first()).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#log')).toContainText('vault worker up', { timeout: 30_000 });

  // Enroll → backup owed.
  await page.click('#enroll');
  await expect(page.locator('#state-pill')).toHaveText('locked', { timeout: 15_000 });
  await expect(page.locator('#backup-pill')).toContainText('backup owed');

  // Add a recovery code → the one-time dialog appears → confirm → backup satisfied.
  await page.click('#add-recovery');
  await expect(page.locator('#code-dialog[open]')).toBeVisible({ timeout: 15_000 });
  await expect(page.locator('#code-value')).not.toBeEmpty();
  await page.click('#code-done');
  await expect(page.locator('#backup-pill')).toBeEmpty();

  // Unlock → write a note → it round-trips through encrypted SQLite.
  await page.click('#unlock');
  await expect(page.locator('#state-pill')).toHaveText('unlocked', { timeout: 15_000 });
  await page.fill('#note-input', 'hello from the test app');
  await page.click('#note-add');
  await expect(page.locator('#notes')).toContainText('hello from the test app', { timeout: 15_000 });

  // Methods list shows the two we created (a passkey + a recovery).
  await expect(page.locator('#methods')).toContainText('passkey');
  await expect(page.locator('#methods')).toContainText('recovery');

  // Lock tears the session down.
  await page.click('#lock');
  await expect(page.locator('#state-pill')).toHaveText('locked', { timeout: 15_000 });

  expect(errors, 'no uncaught page errors').toEqual([]);
  await ctx.close();
});
