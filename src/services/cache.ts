import type { AddressIntelResponse } from "../types";

/** Positive cache TTL: 1 hour. Address reputation changes slowly, so a long
 * TTL sharply cuts upstream GoPlus calls (unlike token liquidity data). */
const CACHE_TTL_SECONDS = 3600;

/** Negative cache TTL: 30 seconds (GoPlus 429/5xx) */
const NEGATIVE_CACHE_TTL_SECONDS = 30;

/** Cache key: addr:{chainIdOrGlobal}:{normalizedAddress} */
function cacheKey(chainId: string | null, address: string): string {
  return `addr:${chainId ?? "global"}:${address}`;
}

interface PositiveCacheEntry {
  type: "ok";
  data: AddressIntelResponse;
  storedAt: number; // epoch ms
}

interface NegativeCacheEntry {
  type: "upstream_degraded";
  reason: string;
  storedAt: number;
}

type CacheEntry = PositiveCacheEntry | NegativeCacheEntry;

export interface CacheHit {
  hit: true;
  entry: PositiveCacheEntry;
  ageSeconds: number;
}

export interface CacheNegativeHit {
  hit: true;
  negative: true;
  reason: string;
}

export interface CacheMiss {
  hit: false;
}

export type CacheResult = CacheHit | CacheNegativeHit | CacheMiss;

export async function cacheGet(
  kv: KVNamespace,
  chainId: string | null,
  address: string,
): Promise<CacheResult> {
  const raw = await kv.get(cacheKey(chainId, address), "text");
  if (!raw) {
    return { hit: false };
  }

  let entry: CacheEntry;
  try {
    entry = JSON.parse(raw) as CacheEntry;
  } catch {
    return { hit: false };
  }

  if (entry.type === "upstream_degraded") {
    return { hit: true, negative: true, reason: entry.reason };
  }

  const ageSeconds = Math.floor((Date.now() - entry.storedAt) / 1000);
  return { hit: true, entry, ageSeconds };
}

export async function cachePut(
  kv: KVNamespace,
  chainId: string | null,
  address: string,
  data: AddressIntelResponse,
): Promise<void> {
  const entry: PositiveCacheEntry = { type: "ok", data, storedAt: Date.now() };
  await kv.put(cacheKey(chainId, address), JSON.stringify(entry), {
    expirationTtl: CACHE_TTL_SECONDS,
  });
}

export async function cacheNegativePut(
  kv: KVNamespace,
  chainId: string | null,
  address: string,
  reason: string,
): Promise<void> {
  const entry: NegativeCacheEntry = {
    type: "upstream_degraded",
    reason,
    storedAt: Date.now(),
  };
  await kv.put(cacheKey(chainId, address), JSON.stringify(entry), {
    expirationTtl: NEGATIVE_CACHE_TTL_SECONDS,
  });
}
