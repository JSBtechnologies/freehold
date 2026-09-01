import { test, expect } from '@playwright/test';

// E2E for verifiable tier-2 attestations (docs/vault-signing-design.md) across the real SDK→worker→wasm
// boundary. Uses the convenience (device-key) harness so no WebAuthn/virtual authenticator is needed —
// the signing key is DEK-derived and tier-independent. The whole attest→verify matrix runs inside ONE
// page.evaluate because an Attestation carries Uint8Arrays that don't cross the Playwright boundary
// cleanly; we return only booleans/reasons.

test('vault signing: a signed attestation verifies, and every tamper is rejected', async ({ browser }) => {
  test.setTimeout(120_000);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));

  await page.goto('/convenience-test.html');
  await page.waitForFunction(() => window.fhReady === true, null, { timeout: 30_000 });
  await page.evaluate(() => window.fh.open());
  await page.evaluate(() => window.fh.enrollConvenience({ backup: true }));
  await page.evaluate(() => window.fh.unlock());

  const r = await page.evaluate(async () => {
    const fh = window.fh;
    const out = {};
    const pk = await fh.vaultPublicKey();
    out.pkLen = pk.length; // Ed25519 public key = 32 bytes

    const att = await fh.attest('profile.over18=true', { audience: 'rp:test#1', ttlSeconds: 300 });
    out.sigLen = att.signature.length; // Ed25519 signature = 64 bytes

    // Happy path: right claim, right audience, right key.
    out.valid = await fh.verifyAttestation(att, { claim: 'profile.over18=true', audience: 'rp:test#1', publicKey: pk });
    // Expectation mismatches (fail before/at the signature check).
    out.wrongClaim = await fh.verifyAttestation(att, { claim: 'profile.over18=false' });
    out.wrongAud = await fh.verifyAttestation(att, { audience: 'rp:evil' });
    out.wrongKey = await fh.verifyAttestation(att, { publicKey: (() => { const w = new Uint8Array(pk); w[0] ^= 1; return w; })() });
    // Expired (now past expiry).
    out.expired = await fh.verifyAttestation(att, { now: (att.expiry + 10) * 1000 });
    // Tampered signature → the Ed25519 check itself fails.
    const bad = { ...att, signature: att.signature.slice() }; bad.signature[0] ^= 1;
    out.tampered = await fh.verifyAttestation(bad, {});
    // A second vault (fresh device / different DEK) produces a DIFFERENT identity key.
    return out;
  });

  expect(r.pkLen, 'Ed25519 public key is 32 bytes').toBe(32);
  expect(r.sigLen, 'Ed25519 signature is 64 bytes').toBe(64);
  expect(r.valid.ok, 'a well-formed attestation verifies').toBe(true);
  expect(r.wrongClaim.ok, 'claim mismatch rejected').toBe(false);
  expect(r.wrongAud.ok, 'audience mismatch rejected (anti-replay)').toBe(false);
  expect(r.wrongKey.ok, 'wrong public key rejected').toBe(false);
  expect(r.expired.ok, 'expired attestation rejected').toBe(false);
  expect(r.tampered.ok, 'tampered signature rejected').toBe(false);

  await page.evaluate(() => window.fh.reset());
  expect(errors, 'no uncaught page errors').toEqual([]);
  await ctx.close();
});
