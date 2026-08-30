import { defineConfig } from '@playwright/test';

// Headless E2E for the @freehold/db sync() orchestration. One vite dev server (cwd examples/demo)
// serves the real SDK + wasm; the spec spins up two ISOLATED browser contexts as two "devices".
const PORT = 5178;

export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: `http://localhost:${PORT}`,
    headless: true,
  },
  webServer: {
    command: 'npm run dev -- --port ' + PORT + ' --strictPort',
    cwd: 'examples/demo',
    url: `http://localhost:${PORT}/sync-test.html`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
