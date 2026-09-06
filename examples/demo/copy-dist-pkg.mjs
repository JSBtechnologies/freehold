// After `vite build`, copy the prebuilt wasm-pack `pkg/` verbatim into `dist/pkg/` so pages that load
// the wasm glue at runtime (e.g. custody/main.js via `new URL('./pkg/freehold.js', location.href)`)
// resolve it under the site base. Cross-platform (Node fs) so it runs the same on Windows and CI.
import { cp, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const src = here + 'pkg';
const dest = here + 'dist/pkg';

try {
  await access(src);
} catch {
  console.error(`[build] wasm pkg not found at ${src} — build it first:\n` +
    `  wasm-pack build ../../crates/freehold --target web --release --out-dir ../demo/pkg`);
  process.exit(1);
}

await cp(src, dest, { recursive: true });
console.log(`[build] copied pkg -> dist/pkg`);
