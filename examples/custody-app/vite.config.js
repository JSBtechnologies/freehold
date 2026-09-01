import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';
import vue from '@vitejs/plugin-vue';
import { quasar, transformAssetUrls } from '@quasar/vite-plugin';

const projectRoot = fileURLToPath(new URL('.', import.meta.url));

// Vue 3 + Quasar SPA. The @freehold/db SDK is imported straight from ../../packages/db (no npm link),
// so allow the dev server to serve the repo root. The freehold wasm is copied into public/pkg by
// `copy-pkg.js` (predev/prebuild) and served statically at /pkg — the SDK worker loads it from there.
export default defineConfig({
  plugins: [
    vue({ template: { transformAssetUrls } }),
    quasar({ sassVariables: 'src/quasar-variables.sass' }),
  ],
  server: { fs: { allow: ['../..'] }, port: 5179, strictPort: true },
  worker: { format: 'es' },
  // Quasar's index.sass does `@import 'src/quasar-variables.sass'` — put the project root on sass's
  // load path so that (root-relative) import resolves from node_modules/quasar.
  css: { preprocessorOptions: { sass: { loadPaths: [projectRoot] }, scss: { loadPaths: [projectRoot] } } },
});
