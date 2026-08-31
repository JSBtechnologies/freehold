import { test, expect } from '@playwright/test';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// GENERATOR (not part of the default suite's assertions): produces the golden `.freehold` fixture the
// standalone decryptor's NATIVE `cargo test -p freehold-decrypt` decrypts. It is skipped unless
// FH_GEN_FIXTURE=1 so ordinary runs don't rewrite the checked-in bytes. Regenerate with:
//   FH_GEN_FIXTURE=1 npx playwright test decrypt-fixture
// The recovery code + row below are FIXED and mirrored in the Rust test — change them in both places.

const CODE = 'FREEHOLD-DECRYPT-SELF-CUSTODY-01';
const ROW = 'self-custody-proof';
const PAGE = '/sync-test.html';

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

test('generate golden .freehold decrypt fixture', async ({ browser }) => {
  test.skip(!process.env.FH_GEN_FIXTURE, 'set FH_GEN_FIXTURE=1 to (re)generate the fixture');
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
  await page.evaluate((r) => window.FH.sql('CREATE TABLE t(v TEXT)', []).then(() =>
    window.FH.sql('INSERT INTO t(v) VALUES (?)', [r])), ROW);
  // Add the recovery method MID-SESSION, AFTER unlock — this is the case that used to omit the slot
  // from the bundle (session_export embedded the session's open-time envelope). Now exportBundle()
  // passes the current envelope, so the recovery slot IS in the bundle: the native decrypt test that
  // opens this fixture with the recovery code is the end-to-end regression proof of that fix.
  await page.evaluate((c) => window.FH.addRecoveryCode(c), CODE);
  const b64 = await page.evaluate(() => window.FH.exportBundleB64());

  const bytes = Buffer.from(b64, 'base64');
  const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'crates', 'freehold-decrypt', 'tests', 'fixtures');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'golden.freehold'), bytes);
  console.log(`wrote golden.freehold (${bytes.length} bytes); code="${CODE}" row="${ROW}"`);
  expect(bytes.length).toBeGreaterThan(4096); // a real image, not an empty bundle

  await ctx.close();
});
