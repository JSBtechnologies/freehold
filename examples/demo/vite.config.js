import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';

// The demo imports the @freehold/db SDK straight from ../../packages/db (no npm link, no build step)
// — allow Vite's dev server to serve files from the repo root via /@fs.
//
// `base`: the dev server (and the Playwright E2E harness) serve at the root, so specs can navigate to
// `/selftest.html`, `/custody.html`, etc. The production BUILD targets GitHub Pages project hosting at
// `/freehold/`, so assets and cross-page links resolve under that path.
const page = (p) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig(({ command }) => ({
  base: command === 'build' ? '/freehold/' : '/',
  server: { fs: { allow: ['../..'] } },
  build: {
    target: 'es2022',
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        index: page('./index.html'),
        docs: page('./docs.html'),
        passkey: page('./passkey.html'),
        custody: page('./custody.html'),
        app: page('./app.html'),
        selftest: page('./selftest.html'),
      },
    },
  },
}));
