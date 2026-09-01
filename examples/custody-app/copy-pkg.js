// Copy the built freehold wasm (../demo/pkg) into public/pkg so Vite serves it statically at /pkg.
// Keeps the 2 MB wasm out of this example's git history (see .gitignore) while staying self-contained.
import { cpSync, existsSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, '..', 'demo', 'pkg');
const dst = join(here, 'public', 'pkg');

if (!existsSync(src)) {
  console.error(`[copy-pkg] wasm not found at ${src}\n  build it first: cd crates/freehold && wasm-pack build --target web --release --out-dir ../../examples/demo/pkg`);
  process.exit(1);
}
mkdirSync(dirname(dst), { recursive: true });
cpSync(src, dst, { recursive: true });
console.log(`[copy-pkg] ${src} → ${dst}`);
