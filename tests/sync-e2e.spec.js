import { test, expect } from '@playwright/test';

// End-to-end proof of the REAL @freehold/db sync() multi-device semantics, headless, no hardware:
//  - Device A: an isolated browser context with a WebAuthn VIRTUAL AUTHENTICATOR (via CDP) — it can
//    enroll() a passkey and addRecoveryCode().
//  - Device B: a second isolated context with NO authenticator — it gets the DEK by importing A's
//    bundle and unlockWithRecovery().
//  - Relay: a single in-memory log held HERE in Node (identical semantics to relay-mem.js),
//    bridged into each page via page.exposeFunction, so the two separate JS realms share one relay.

const PAGE = '/sync-test.html';

// ---- Node-side shared relay: a direct twin of packages/db/relay-mem.js InMemoryRelay ----
function makeRelay() {
  const logs = new Map(); // syncIdHex -> Array<base64 string>
  const hexOfB64 = (b64) => {
    const buf = Buffer.from(b64, 'base64');
    return buf.toString('hex');
  };
  const logFor = (b64) => {
    const k = hexOfB64(b64);
    let l = logs.get(k);
    if (!l) { l = []; logs.set(k, l); }
    return l;
  };
  return {
    put(syncIdB64, sealedB64) {
      const l = logFor(syncIdB64);
      l.push(sealedB64);
      return l.length - 1;
    },
    list(syncIdB64, since = 0) {
      return Math.max(0, logFor(syncIdB64).length - since);
    },
    get(syncIdB64, seq) {
      const b = logFor(syncIdB64)[seq];
      return b == null ? null : b;
    },
    _dump() { return [...logs.entries()].map(([k, v]) => [k, v.length]); },
  };
}

// Add a virtual authenticator to a context's page via CDP (ctap2 + internal + resident key + UV).
async function addVirtualAuthenticator(context, page) {
  const client = await context.newCDPSession(page);
  await client.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
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
  return { client, authenticatorId };
}

test('sync() multi-device: convergence, stale, fork with loser preservation', async ({ browser }) => {
  test.setTimeout(120_000);
  const relay = makeRelay();

  // Bridge the shared Node relay into a page as window.__relayPut/List/Get.
  const wire = async (page) => {
    await page.exposeFunction('__relayPut', (syncIdB64, sealedB64) => relay.put(syncIdB64, sealedB64));
    await page.exposeFunction('__relayList', (syncIdB64, since) => relay.list(syncIdB64, since));
    await page.exposeFunction('__relayGet', (syncIdB64, seq) => relay.get(syncIdB64, seq));
  };

  // ---- Device A: isolated context WITH a virtual authenticator ----
  const ctxA = await browser.newContext();
  const pageA = await ctxA.newPage();
  pageA.on('console', (m) => console.log('[A console]', m.type(), m.text()));
  pageA.on('pageerror', (e) => console.log('[A pageerror]', e.message));
  await addVirtualAuthenticator(ctxA, pageA);
  await wire(pageA);
  await pageA.goto(PAGE);
  await pageA.waitForFunction(() => !!window.FH);

  const supported = await pageA.evaluate(() => window.FH.isSupported());
  console.log('[A] isSupported =', supported);

  await pageA.evaluate(() => window.FH.open());
  await pageA.evaluate(() => window.FH.enroll());
  const R = await pageA.evaluate(() => window.FH.addRecoveryCode());
  console.log('[A] recovery code =', R);
  expect(typeof R).toBe('string');
  expect(R.length).toBeGreaterThan(0);

  // enroll() leaves the vault LOCKED (it re-inits the pool). Open a session before SQL.
  await pageA.evaluate(() => window.FH.unlock());
  expect(await pageA.evaluate(() => window.FH.isUnlocked())).toBe(true);

  await pageA.evaluate(() => window.FH.sql("CREATE TABLE t(v TEXT)"));
  await pageA.evaluate(() => window.FH.sql("INSERT INTO t(v) VALUES ('from-A')"));

  // STEP 3: A syncs -> pushed === true
  const repA1 = await pageA.evaluate(() => window.FH.sync());
  console.log('[A] sync#1', repA1);
  expect(repA1.pushed).toBe(true);

  const bundleB64 = await pageA.evaluate(() => window.FH.exportBundleB64());
  expect(bundleB64.length).toBeGreaterThan(0);

  // ---- Device B: second isolated context, NO authenticator ----
  const ctxB = await browser.newContext();
  const pageB = await ctxB.newPage();
  pageB.on('console', (m) => console.log('[B console]', m.type(), m.text()));
  pageB.on('pageerror', (e) => console.log('[B pageerror]', e.message));
  await wire(pageB);
  await pageB.goto(PAGE);
  await pageB.waitForFunction(() => !!window.FH);

  await pageB.evaluate(() => window.FH.open());
  await pageB.evaluate((b64) => window.FH.importBundleB64(b64), bundleB64);
  await pageB.evaluate((code) => window.FH.unlockWithRecovery(code), R);
  expect(await pageB.evaluate(() => window.FH.isUnlocked())).toBe(true);

  // STEP 4: B syncs -> applied >= 1 and SELECT returns from-A (CONVERGENCE)
  const repB1 = await pageB.evaluate(() => window.FH.sync());
  console.log('[B] sync#1', repB1);
  expect(repB1.applied).toBeGreaterThanOrEqual(1);
  const bRows1 = await pageB.evaluate(() => window.FH.sql("SELECT v FROM t"));
  console.log('[B] rows after converge', bRows1);
  expect(bRows1.flat()).toContain('from-A');

  // STEP 5: STALE — B syncs again against an already-seen/older state: no spurious apply/fork.
  const repB2 = await pageB.evaluate(() => window.FH.sync());
  console.log('[B] sync#2 (stale check)', repB2);
  expect(repB2.forks).toBe(0);
  // B just pushed in sync#1; pulling its own/older blobs must not re-apply foreign state.
  expect(repB2.applied).toBe(0);

  // Let A drain anything pending so both are on common ground before the fork.
  const repA2 = await pageA.evaluate(() => window.FH.sync());
  console.log('[A] sync#2 (drain)', repA2);
  const repA3 = await pageA.evaluate(() => window.FH.sync());
  const repB3 = await pageB.evaluate(() => window.FH.sync());
  console.log('[A] sync#3', repA3, '[B] sync#3', repB3);

  // ---- STEP 6: FORK. Both edit divergently with NO sync in between. ----
  await pageA.evaluate(() => window.FH.sql("INSERT INTO t(v) VALUES ('a2')"));
  await pageB.evaluate(() => window.FH.sql("INSERT INTO t(v) VALUES ('b2')"));

  // Both PUSH their divergent state before pulling the other (each increments its OWN VV component
  // from the common base) → the two pushed vectors are CONCURRENT. Then normal syncs pull the
  // peer's now-concurrent blob and MUST classify it as a fork.
  const fA1 = await pageA.evaluate(() => window.FH.syncPushNoPull()); // A pushes a2, no pull
  const fB1 = await pageB.evaluate(() => window.FH.syncPushNoPull()); // B pushes b2, no pull
  const fA2 = await pageA.evaluate(() => window.FH.sync()); // A pulls b2 → FORK
  const fB2 = await pageB.evaluate(() => window.FH.sync()); // B pulls a2 → FORK
  const fA3 = await pageA.evaluate(() => window.FH.sync()); // converge
  const fB3 = await pageB.evaluate(() => window.FH.sync()); // converge
  const fA4 = await pageA.evaluate(() => window.FH.sync()); // converge
  console.log('[fork] A', fA1, fA2, fA3, fA4, '| B', fB1, fB2, fB3);

  const forksA = await pageA.evaluate(() => window.FH.takenForks());
  const forksB = await pageB.evaluate(() => window.FH.takenForks());
  console.log('[fork] onFork A', forksA, 'B', forksB);
  const totalForkReports = fA1.forks + fA2.forks + fA3.forks + fA4.forks + fB1.forks + fB2.forks + fB3.forks;
  console.log('[fork] total report.forks =', totalForkReports);

  // A fork must have been detected somewhere.
  expect(totalForkReports).toBeGreaterThanOrEqual(1);
  expect(forksA.length + forksB.length).toBeGreaterThanOrEqual(1);

  // BOTH devices converge to the IDENTICAL winning row-set.
  const rowsA = (await pageA.evaluate(() => window.FH.sql("SELECT v FROM t ORDER BY v"))).flat();
  const rowsB = (await pageB.evaluate(() => window.FH.sql("SELECT v FROM t ORDER BY v"))).flat();
  console.log('[fork] final rowsA', rowsA, 'rowsB', rowsB);
  expect(rowsA).toEqual(rowsB);

  // The preserved loser is listable, and openFork() returns a non-empty image.
  const listA = await pageA.evaluate(() => window.FH.listForks());
  const listB = await pageB.evaluate(() => window.FH.listForks());
  console.log('[fork] listForks A', listA, 'B', listB);
  const anyList = listA.length ? { page: pageA, list: listA } : { page: pageB, list: listB };
  expect(anyList.list.length).toBeGreaterThanOrEqual(1);
  const forkId = anyList.list[0].id;
  const imgLen = await anyList.page.evaluate((id) => window.FH.openForkImageLen(id), forkId);
  console.log('[fork] openFork image length', imgLen);
  expect(imgLen).toBeGreaterThan(0);

  await pageA.evaluate(() => window.FH.close());
  await pageB.evaluate(() => window.FH.close());
  await ctxA.close();
  await ctxB.close();
});
