import { test, expect } from '@playwright/test';

// End-to-end proof of @freehold/db sync() over the REAL network transport: HttpRelay -> the blind
// relay server (server/relay-server.mjs, :5180) speaking the Connect wire contract
// (proto/freehold/sync/v1/relay.proto). Unlike sync-e2e.spec.js (a Node-bridged in-memory relay),
// here two isolated browser contexts converge through an ACTUAL HTTP relay that only ever sees opaque
// base64 bytes. Same three semantics — convergence, stale, fork-with-loser-preservation — plus a
// server-streaming Subscribe check. The relay webServer is started by playwright.config.js.

const PAGE = '/sync-http-test.html';

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

test('sync() over a REAL HTTP blind relay: convergence, stale, fork; + server-streaming Subscribe', async ({ browser }) => {
  test.setTimeout(120_000);

  // ---- Device A: isolated context WITH a virtual authenticator ----
  const ctxA = await browser.newContext();
  const pageA = await ctxA.newPage();
  pageA.on('pageerror', (e) => console.log('[A pageerror]', e.message));
  await addVirtualAuthenticator(ctxA, pageA);
  await pageA.goto(PAGE);
  await pageA.waitForFunction(() => !!window.FH);
  console.log('[A] relay =', await pageA.evaluate(() => window.FH.relayUrl()));

  await pageA.evaluate(() => window.FH.open());
  await pageA.evaluate(() => window.FH.enroll());
  const R = await pageA.evaluate(() => window.FH.addRecoveryCode());
  expect(typeof R).toBe('string');
  await pageA.evaluate(() => window.FH.unlock());
  expect(await pageA.evaluate(() => window.FH.isUnlocked())).toBe(true);

  await pageA.evaluate(() => window.FH.sql("CREATE TABLE t(v TEXT)"));
  await pageA.evaluate(() => window.FH.sql("INSERT INTO t(v) VALUES ('from-A')"));

  // A syncs over the wire -> pushed.
  const repA1 = await pageA.evaluate(() => window.FH.sync());
  console.log('[A] sync#1', repA1);
  expect(repA1.pushed).toBe(true);

  const bundleB64 = await pageA.evaluate(() => window.FH.exportBundleB64());
  expect(bundleB64.length).toBeGreaterThan(0);

  // ---- Device B: second isolated context, NO authenticator ----
  const ctxB = await browser.newContext();
  const pageB = await ctxB.newPage();
  pageB.on('pageerror', (e) => console.log('[B pageerror]', e.message));
  await pageB.goto(PAGE);
  await pageB.waitForFunction(() => !!window.FH);

  await pageB.evaluate(() => window.FH.open());
  await pageB.evaluate((b64) => window.FH.importBundleB64(b64), bundleB64);
  await pageB.evaluate((code) => window.FH.unlockWithRecovery(code), R);
  expect(await pageB.evaluate(() => window.FH.isUnlocked())).toBe(true);

  // CONVERGENCE: B pulls A's blob over the wire and applies it.
  const repB1 = await pageB.evaluate(() => window.FH.sync());
  console.log('[B] sync#1', repB1);
  expect(repB1.applied).toBeGreaterThanOrEqual(1);
  const bRows1 = await pageB.evaluate(() => window.FH.sql("SELECT v FROM t"));
  expect(bRows1.flat()).toContain('from-A');

  // STALE: B syncs again — no spurious apply/fork.
  const repB2 = await pageB.evaluate(() => window.FH.sync());
  console.log('[B] sync#2 (stale)', repB2);
  expect(repB2.forks).toBe(0);
  expect(repB2.applied).toBe(0);

  // Drain to common ground before forking.
  await pageA.evaluate(() => window.FH.sync());
  await pageA.evaluate(() => window.FH.sync());
  await pageB.evaluate(() => window.FH.sync());

  // FORK: both edit divergently, both push before pulling -> concurrent vectors over the real relay.
  await pageA.evaluate(() => window.FH.sql("INSERT INTO t(v) VALUES ('a2')"));
  await pageB.evaluate(() => window.FH.sql("INSERT INTO t(v) VALUES ('b2')"));
  const fA1 = await pageA.evaluate(() => window.FH.syncPushNoPull());
  const fB1 = await pageB.evaluate(() => window.FH.syncPushNoPull());
  const fA2 = await pageA.evaluate(() => window.FH.sync());
  const fB2 = await pageB.evaluate(() => window.FH.sync());
  await pageA.evaluate(() => window.FH.sync());
  await pageB.evaluate(() => window.FH.sync());
  await pageA.evaluate(() => window.FH.sync());

  const forksA = await pageA.evaluate(() => window.FH.takenForks());
  const forksB = await pageB.evaluate(() => window.FH.takenForks());
  const totalForkReports = fA1.forks + fA2.forks + fB1.forks + fB2.forks;
  console.log('[fork] reports =', totalForkReports, 'onFork A/B =', forksA.length, forksB.length);
  expect(totalForkReports).toBeGreaterThanOrEqual(1);
  expect(forksA.length + forksB.length).toBeGreaterThanOrEqual(1);

  // Both devices converge to the IDENTICAL winning row-set over the wire.
  const rowsA = (await pageA.evaluate(() => window.FH.sql("SELECT v FROM t ORDER BY v"))).flat();
  const rowsB = (await pageB.evaluate(() => window.FH.sql("SELECT v FROM t ORDER BY v"))).flat();
  console.log('[fork] final A', rowsA, 'B', rowsB);
  expect(rowsA).toEqual(rowsB);

  // The preserved loser is openable.
  const listA = await pageA.evaluate(() => window.FH.listForks());
  const listB = await pageB.evaluate(() => window.FH.listForks());
  const any = listA.length ? { page: pageA, list: listA } : { page: pageB, list: listB };
  expect(any.list.length).toBeGreaterThanOrEqual(1);
  const imgLen = await any.page.evaluate((id) => window.FH.openForkImageLen(id), any.list[0].id);
  expect(imgLen).toBeGreaterThan(0);

  // ---- Relay AUTH: an unsigned push is rejected (blindness ≠ access, docs/relay-auth-design.md) ----
  // A fresh 16-byte db_uuid the vault never syncs → its own bucket, authenticated by the vault's key.
  const dbUuidB64 = await pageA.evaluate(() => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))));
  const blobB64 = btoa('opaque-sealed-bytes');
  const unsigned = await pageA.evaluate(({ id, blob }) => window.FH.rawPutUnsigned(id, blob), { id: dbUuidB64, blob: blobB64 });
  console.log('[auth] unsigned push =', unsigned);
  expect(unsigned).toContain('REJECTED');

  // ---- Server-streaming Subscribe: a blind push notification carries ONLY an arrival index ----
  // Authenticated Subscribe on the (empty) bucket, then an authenticated push -> deterministic seq 0.
  const seqPromise = pageA.evaluate((id) => window.FH.subscribeOnceAuthed(id, 0), dbUuidB64);
  await pageA.waitForTimeout(300); // let the SSE stream attach before we push
  await pageA.evaluate(({ id, blob }) => window.FH.rawPutAuthed(id, blob), { id: dbUuidB64, blob: blobB64 });
  const gotSeq = await seqPromise;
  console.log('[subscribe] delivered seq =', gotSeq);
  expect(gotSeq).toBe(0);

  await pageA.evaluate(() => window.FH.close());
  await pageB.evaluate(() => window.FH.close());
  await ctxA.close();
  await ctxB.close();
});
