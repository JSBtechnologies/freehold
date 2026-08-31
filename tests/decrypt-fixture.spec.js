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
  // Add the recovery method BEFORE unlock so the SESSION opens the envelope that already carries the
  // recovery slot — session_export() embeds the session's open-time envelope, so a code added
  // mid-session would not reach the bundle (see the note in docs/bundle-format.md / index.js).
  await page.evaluate((c) => window.FH.addRecoveryCode(c), CODE);
  await page.evaluate(() => window.FH.unlock());
  await page.evaluate((r) => window.FH.sql('CREATE TABLE t(v TEXT)', []).then(() =>
    window.FH.sql('INSERT INTO t(v) VALUES (?)', [r])), ROW);
  const b64 = await page.evaluate(() => window.FH.exportBundleB64());

  const bytes = Buffer.from(b64, 'base64');
  const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'crates', 'freehold-decrypt', 'tests', 'fixtures');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'golden.freehold'), bytes);
  console.log(`wrote golden.freehold (${bytes.length} bytes); code="${CODE}" row="${ROW}"`);
  expect(bytes.length).toBeGreaterThan(4096); // a real image, not an empty bundle

  await ctx.close();
});
