import { defineConfig } from '@playwright/test';

// Headless E2E for Freehold. Two dev servers, two projects:
//  - `demo` (:5178, cwd examples/demo) serves the SDK + wasm test harnesses for the core specs
//    (run_tests, rotate, sync, backup, convenience, attest, custody, decrypt-fixture).
//  - `custody-app` (:5179, cwd examples/custody-app) serves the real Quasar showcase for its own spec.
const DEMO_PORT = 5178;
const APP_PORT = 5179;
const RELAY_PORT = 5180; // the blind relay server (server/relay-server.mjs) for sync-http-e2e

export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: { headless: true },
  projects: [
    {
      name: 'demo',
      use: { baseURL: `http://localhost:${DEMO_PORT}` },
      testIgnore: '**/custody-app-e2e.spec.js',
    },
    {
      name: 'custody-app',
      use: { baseURL: `http://localhost:${APP_PORT}` },
      testMatch: '**/custody-app-e2e.spec.js',
    },
  ],
  webServer: [
    {
      command: `npm run dev -- --port ${DEMO_PORT} --strictPort`,
      cwd: 'examples/demo',
      url: `http://localhost:${DEMO_PORT}/sync-test.html`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      // The blind relay server (opaque bytes only) for the real-transport sync spec.
      command: `node server/relay-server.mjs ${RELAY_PORT}`,
      url: `http://localhost:${RELAY_PORT}/healthz`,
      reuseExistingServer: !process.env.CI,
      timeout: 30_000,
    },
    {
      // vite.config.js already pins port 5179 + strictPort; predev copies the fresh wasm pkg in.
      command: 'npm run dev',
      cwd: 'examples/custody-app',
      url: `http://localhost:${APP_PORT}/`,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  ],
});
