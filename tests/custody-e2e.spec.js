import { test, expect } from '@playwright/test';

// E2E for the data-custody showcase (examples/demo/custody.html) — the first implementation of
// docs/data-custody-protocol.md (Local plane, local grants). A virtual authenticator stands in for the
// passkey gesture. Proves the four beats: unlock → App A (custodian) gets consented access → App B
// gets facts (tier-2 attestation, DOB withheld) + a tier-3 disclosure + a tier-3 borrow (app never
// receives the raw value) → revoke, and the revoked grant is REJECTED AT THE BROKER, not just the UI.

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

test('custody: own the data, apps are custodians (grant · tiers · revoke)', async ({ browser }) => {
  test.setTimeout(120_000);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await addVirtualAuthenticator(ctx, page);

  // `?e2e` opts into the dev-only broker test hook (window.__custody) — it is otherwise absent, even
  // in dev, and stripped entirely from any production build. See examples/demo/custody/main.js.
  await page.goto('/custody.html?e2e=1');
  await expect(page.locator('#vault-log')).toContainText('vault worker up', { timeout: 30_000 });

  // Beat 1 — unlock the vault with a passkey.
  await page.click('#enroll');
  await expect(page.locator('#state-pill')).toHaveText('locked', { timeout: 15_000 });
  await page.click('#unlock');
  await expect(page.locator('#state-pill')).toHaveText('unlocked', { timeout: 15_000 });
  await expect(page.locator('#p-name')).toHaveText('Ada Lovelace', { timeout: 15_000 });

  // Beat 2 — App A (Notes) requests access → consent → grant → operates on its OWN namespace.
  await page.click('#notes-request');
  await expect(page.locator('#consent')).toHaveClass(/show/, { timeout: 10_000 });
  await expect(page.locator('#consent-text')).toContainText('Notes');
  await page.click('#consent-approve');
  await expect(page.locator('#notes-status')).toHaveText('granted');
  await page.fill('#note-input', 'a note only I can read');
  await page.click('#note-add');
  await expect(page.locator('#notes-list')).toContainText('a note only I can read');

  // Beat 3 — App B (Tasks) requests access → consent → grant.
  await page.click('#tasks-request');
  await expect(page.locator('#consent')).toHaveClass(/show/, { timeout: 10_000 });
  await expect(page.locator('#consent-text')).toContainText('Tasks');
  await page.click('#consent-approve');
  await expect(page.locator('#tasks-status')).toHaveText('granted');

  // D-DC3 — the grant is counterparty-verifiable: verify Tasks' signed token with ONLY the vault's
  // pinned public key (no DEK, no broker), and prove a tampered token is rejected.
  const gv = await page.evaluate(() => window.__custody.verifyGrant('Tasks', { scope: 'profile.read' }));
  expect(gv.ok).toBe(true);
  const gvTamper = await page.evaluate(() => window.__custody.verifyGrant('Tasks', { tamper: true }));
  expect(gvTamper.ok).toBe(false);

  // tier 2 — attestation: the app gets a yes/no; DOB never leaves the vault.
  await page.click('#tasks-over18');
  await expect(page.locator('#tasks-out')).toContainText('verified');
  await expect(page.locator('#tasks-out')).toContainText('DOB never left');

  // tier 3 — disclosure: a minimized raw field goes to the app, logged.
  await page.click('#tasks-ship');
  await expect(page.locator('#tasks-out')).toContainText('Analytical Engine Way');

  // tier 3 — borrow: released to a processor; the APP never receives the raw value.
  await page.click('#tasks-pay');
  await expect(page.locator('#tasks-out')).toContainText('retainedByApp=false');

  // tier 1 — custodian: Tasks writes to its own namespace.
  await page.fill('#task-input', 'ship the anchor fix');
  await page.click('#task-add');
  await expect(page.locator('#tasks-list')).toContainText('ship the anchor fix');

  // The ledger (owned + sealed) recorded every tier.
  await expect(page.locator('#ledger-body')).toContainText('T2');
  await expect(page.locator('#ledger-body')).toContainText('T3');
  await expect(page.locator('#ledger-body')).toContainText('over18');

  // Beat 4 — revoke, and prove ENFORCEMENT at the broker (not just a disabled button).
  const grantId = await page.evaluate(() => window.__custody.tasksGrantId());
  expect(grantId).toBeTruthy();
  await page.click('#tasks-revoke');
  await expect(page.locator('#tasks-status')).toHaveText('revoked');
  const reply = await page.evaluate((gid) => window.__custody.brokerCall('Tasks', gid, 'profile.attest.over18'), grantId);
  expect(reply.ok).toBe(false);
  expect(reply.error).toContain('revoked');

  // Notes still works — revoking one app does not touch another's grant or the owner's data.
  await expect(page.locator('#notes-list')).toContainText('a note only I can read');

  // Requester auth (D-DC2): a lookalike app that CLAIMS Notes' verified id but signs with a different
  // key is rejected at the broker handshake — app_id is a commitment to the app's key, not a label.
  const imp = await page.evaluate(() => window.__custody.impersonate('Notes'));
  expect(imp.authed).toBe(false);

  expect(errors, 'no uncaught page errors').toEqual([]);
  await ctx.close();
});
