import { defineConfig } from 'vite';

// The demo imports the @freehold/db SDK straight from ../../packages/db (no npm link, no build
// step) — allow Vite's dev server to serve files from the repo root via /@fs.
export default defineConfig({
  server: { fs: { allow: ['../..'] } },
});
