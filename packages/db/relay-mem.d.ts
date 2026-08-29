import type { BlindRelay } from './index.js';

/** The reference in-memory BlindRelay: a per-syncId append-only log of sealed blobs, for local /
 *  same-machine sync and tests. Blind by construction — it only stores/serves opaque bytes. */
export declare class InMemoryRelay implements BlindRelay {
  put(syncId: Uint8Array, sealed: Uint8Array): Promise<number>;
  list(syncId: Uint8Array, since?: number): Promise<number>;
  get(syncId: Uint8Array, seq: number): Promise<Uint8Array | null>;
}
