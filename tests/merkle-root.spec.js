import { test, expect } from '@playwright/test';

// freehold-vfs-merkle-root: headless load of the in-wasm run_tests() harness (the demo `/selftest.html`
// page runs run_tests() in a worker and writes the full report into <pre id="out">). We assert the whole
// suite passes AND that the new MK (full-state Merkle root) section is present and green.
test('run_tests(): full suite green incl. MK (full-state Merkle root) section', async ({ page }) => {
  test.setTimeout(120_000);
  const errors = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push('console.error: ' + m.text()); });

  await page.goto('/selftest.html');
  // The worker compiles + runs the full suite; wait until the terminal line appears (or a FAILED).
  await page.waitForFunction(() => {
    const t = document.getElementById('out')?.textContent || '';
    return t.includes('ALL MILESTONE-2+3 CHECKS PASSED') || t.startsWith('FAILED') ||
           t.startsWith('ERROR') || t.startsWith('WORKER ERROR');
  }, { timeout: 110_000 });

  const out = await page.evaluate(() => document.getElementById('out').textContent);
  console.log('\n===== run_tests() report =====\n' + out + '\n==============================\n');

  expect(out, 'suite must not fail').not.toContain('FAILED');
  expect(out).toContain('ALL MILESTONE-2+3 CHECKS PASSED');

  // The new MK section — all three sub-checks must be present.
  expect(out).toContain('MK(a) root round-trip');
  expect(out).toContain('MK(b) partial rollback');
  expect(out).toContain('open REFUSED by root check');
  expect(out).toContain('MK(c) legacy zero-root DB');

  // Envelope anti-rollback + DEK-rotation (issue #3/#4) sections must be present and green.
  expect(out).toContain('M3b. envelope v3 anti-rollback');
  expect(out).toContain('M3e. convenience device slot'); // D-CV5/6/7: device slot label + export strip
  expect(out).toContain('VS. vault signing'); // Ed25519 vault identity + verifiable tier-2 attestations
  expect(out).toContain('M3d. recovery-code checksum');
  expect(out).toContain('M3c. DEK rotation (envelope half)');
  expect(out).toContain('RK. DEK rotation (physical re-encryption)');
  expect(out).toContain('RK2. DEK rotation (crash-safe commit barrier)');
  expect(out).toContain('RK3. DEK rotation (anchor carry-forward)');
  expect(out).toContain('SE3c. cross-device envelope-rollback');

  // Existing security-critical sections must stay green (spot-check the load-bearing ones).
  expect(out).toContain('crash sweep'); // §14.8
  expect(out).toContain('whole-file rollback: open rejected'); // anti-rollback
  expect(out).toContain('11. perf:'); // perf section

  expect(errors, 'no page/console errors').toEqual([]);
});
