import type { BlindRelay, RelayAuth } from './index.js';

/** The network BlindRelay: talks the Connect wire contract (proto/freehold/sync/v1/relay.proto) to a
 *  blind relay server over HTTP. A drop-in for InMemoryRelay — same three methods, everything on the
 *  wire is opaque base64 `bytes`; the relay never sees keys or plaintext. */
export declare class HttpRelay implements BlindRelay {
  /**
   * @param baseUrl Relay origin, e.g. "http://localhost:5180".
   * @param opts.fetch Injectable fetch (tests / non-browser hosts); defaults to globalThis.fetch.
   */
  constructor(baseUrl: string, opts?: { fetch?: typeof fetch });
  put(syncId: Uint8Array, sealed: Uint8Array, auth?: RelayAuth): Promise<number>;
  list(syncId: Uint8Array, since?: number, auth?: RelayAuth): Promise<number>;
  get(syncId: Uint8Array, seq: number, auth?: RelayAuth): Promise<Uint8Array | null>;
  /**
   * Optional low-latency "receive updates" over the server-streaming Subscribe RPC (SSE). Calls
   * `onSeq(seq)` per arrival index ≥ `since`; returns an unsubscribe function. Never required for
   * correctness — sync() converges on the poll path (list/get) alone.
   */
  subscribe(
    syncId: Uint8Array,
    since: number,
    onSeq: (seq: number) => void,
    opts?: { signal?: AbortSignal; auth?: RelayAuth },
  ): Promise<() => void>;
}
