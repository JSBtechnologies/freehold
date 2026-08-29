// Runs the freehold Milestone-1 wasm in a DEDICATED worker (SAHPool requires a Worker + secure
// context; header-free means NO COOP/COEP headers are needed to load this).
import init, { run_tests } from './pkg/freehold.js';

self.onmessage = async () => {
  try {
    await init();
    const report = await run_tests();
    self.postMessage({ ok: true, report });
  } catch (e) {
    self.postMessage({ ok: false, error: String(e && e.stack ? e.stack : e) });
  }
};
