import { test, expect } from '@playwright/test';

// Committed E2E for the Quasar custody showcase (examples/custody-app), driven on :5179 in CONVENIENCE
// mode so no passkey / virtual authenticator is needed. Walks the whole custody story end to end:
// enroll a device-key vault -> auto-unlock -> BuyStuff checkout exercising tier-2 (a SIGNED attestation
// verified against the vault's key), tier-3 disclosure + borrow -> the disclosure ledger -> revoke.

test('custody app: convenience unlock, signed attestation + tiered disclosure, ledger, revoke', async ({ page }) => {
  test.setTimeout(120_000);
  const errors = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push('console.error: ' + m.text()); });

  await page.goto('/');

  // No vault yet -> enroll a convenience (device-key) vault: no passkey gesture.
  await page.getByRole('button', { name: /This device/i }).click();

  // The one-time recovery-code dialog appears; save + dismiss it.
  await expect(page.getByText('Save your recovery code')).toBeVisible();
  await page.getByRole('button', { name: /I've saved it/i }).click();

  // Unlocked: the mode-aware header chip reflects the convenience tier.
  await expect(page.getByText(/auto-unlock on this device/i)).toBeVisible();

  // Try an app -> BuyStuff checkout.
  await page.getByRole('link', { name: /Try an app/i }).click();
  await page.getByRole('button', { name: /Start checkout/i }).click();

  // Consent is an explicit act -> approve the grant.
  await expect(page.getByText('Consent requested')).toBeVisible();
  await page.getByRole('button', { name: /^Approve/ }).click();

  // Tier 2 — the FACT plus the cryptographic proof: the attestation is signed by the vault identity key
  // and verified against the pinned public key (the vault-signing work). DOB never leaves the vault.
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByText(/verified 18\+/i)).toBeVisible();
  await expect(page.getByText(/verified against your vault key/i)).toBeVisible();

  // Tier 3 — disclose (shipping) and borrow (charge the card via a processor; the app never sees it).
  await page.getByRole('button', { name: 'Share' }).click();
  await expect(page.getByText(/ship to:/i)).toBeVisible();
  await page.getByRole('button', { name: 'Pay' }).click();
  await expect(page.getByText(/charged via AcmePay/i)).toBeVisible();

  // The disclosure ledger recorded all three, in the user's own sealed vault.
  await page.getByRole('link', { name: /Activity/i }).click();
  await expect(page.getByText('profile.attest.over18').first()).toBeVisible();
  await expect(page.getByText('profile.read').first()).toBeVisible();
  await expect(page.getByText('profile.borrow').first()).toBeVisible();

  // Kill switch: revoke BuyStuff -> it loses access, the row flips to revoked.
  await page.getByRole('link', { name: /Connected apps/i }).click();
  await expect(page.getByText('BuyStuff').first()).toBeVisible();
  await page.getByRole('button', { name: 'Revoke' }).click();
  await expect(page.getByText('revoked').first()).toBeVisible();

  expect(errors, 'no page/console errors').toEqual([]);
});
