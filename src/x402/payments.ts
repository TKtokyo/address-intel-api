import { x402ResourceServer } from "@x402/core/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import { bazaarResourceServerExtension } from "@x402/extensions/bazaar";
import { createSIWxResourceServerExtension } from "@x402/extensions/sign-in-with-x";
import { createFacilitatorConfig } from "@coinbase/x402";
import type { FacilitatorConfig } from "@x402/core/http";
import type { Env } from "../types";
import { KVSIWxStorage } from "./siwx";

// ─── Service-level Bazaar metadata (shared by HTTP route and MCP tool) ─────

export const SERVICE_NAME = "Address Intel API";
export const SERVICE_TAGS = ["security", "wallet", "risk", "aml", "evm"];

// ─── Pricing (single source of truth for REST route and MCP tool) ──────────

export const PRICE_CHECK = "$0.005";

// ─── USDC payment requirements ─────────────────────────────────────────────

interface UsdcInfo {
  address: string;
  name: string;
  version: string;
}

// USDC contract metadata per supported network. Values must match what
// @x402/hono resolves on-chain, so the manifest's accepts[] is byte-identical
// to the middleware-emitted PAYMENT-REQUIRED payload.
const USDC_BY_NETWORK: Record<string, UsdcInfo> = {
  "eip155:8453": {
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    name: "USD Coin",
    version: "2",
  },
  "eip155:84532": {
    address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    name: "USDC",
    version: "2",
  },
};

// "$0.005" -> "5000" (USDC has 6 decimals). BigInt-based so no float drift.
export function usdToUsdcBaseUnits(price: string): string {
  const match = /^\$(\d+)(?:\.(\d{1,6}))?$/.exec(price);
  if (!match) throw new Error(`Invalid price format: ${price}`);
  const whole = BigInt(match[1]);
  const frac = (match[2] ?? "").padEnd(6, "0");
  return (whole * 1_000_000n + BigInt(frac || "0")).toString();
}

export interface PaymentRequirement {
  scheme: "exact";
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: { name: string; version: string };
}

export function buildAccepts(price: string, env: Env): PaymentRequirement[] {
  const usdc = USDC_BY_NETWORK[env.X402_NETWORK];
  if (!usdc) {
    throw new Error(`Unsupported X402_NETWORK: ${env.X402_NETWORK}`);
  }
  return [
    {
      scheme: "exact",
      network: env.X402_NETWORK,
      amount: usdToUsdcBaseUnits(price),
      asset: usdc.address,
      payTo: env.PAY_TO_ADDRESS,
      maxTimeoutSeconds: 300,
      extra: { name: usdc.name, version: usdc.version },
    },
  ];
}

// ─── Shared x402 resource server ───────────────────────────────────────────
//
// One x402ResourceServer per isolate, shared by the HTTP payment middleware
// and the MCP payment wrapper. Rebuilt only if env values change.

let cachedServer: x402ResourceServer | null = null;
let cachedServerKey = "";

export function envCacheKey(env: Env): string {
  return [
    env.X402_NETWORK,
    env.PAY_TO_ADDRESS,
    env.FACILITATOR_URL,
    env.CDP_API_KEY_ID ?? "",
    // Secret included so a rotation with an unchanged key ID doesn't leave
    // long-lived isolates holding a stale facilitator client (auth failures).
    // The key stays in isolate memory only and is never logged.
    env.CDP_API_KEY_SECRET ?? "",
    env.PUBLIC_ORIGIN ?? "",
    env.SIWX_SESSION_TTL_SECONDS ?? "",
  ].join("|");
}

/** SIWx session length: how long a paid wallet can re-read the same address
 * check free. Default 1h — matches the positive cache TTL, so a session
 * only ever re-serves data the wallet already bought. */
export function siwxSessionTtlSeconds(env: Env): number {
  const parsed = parseInt(env.SIWX_SESSION_TTL_SECONDS ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 3600;
}

export function getResourceServer(env: Env): x402ResourceServer {
  const key = envCacheKey(env);
  if (cachedServer && cachedServerKey === key) {
    return cachedServer;
  }

  // Use CDP facilitator config when keys are available (mainnet),
  // otherwise use simple URL config (testnet)
  let facilitatorConfig: FacilitatorConfig;
  if (env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET) {
    facilitatorConfig = createFacilitatorConfig(
      env.CDP_API_KEY_ID,
      env.CDP_API_KEY_SECRET,
    );
  } else {
    facilitatorConfig = { url: env.FACILITATOR_URL };
  }
  const facilitatorClient = new HTTPFacilitatorClient(facilitatorConfig);

  const server = new x402ResourceServer(facilitatorClient);
  registerExactEvmScheme(server);
  server.registerExtension(bazaarResourceServerExtension);

  // SIWx sessions: a settled payment lets the same wallet re-read the same
  // address check without paying again (KV-backed, TTL-bound).
  server.registerExtension(
    createSIWxResourceServerExtension({
      storage: new KVSIWxStorage(env.ADDRESS_CACHE, siwxSessionTtlSeconds(env)),
      origin: env.PUBLIC_ORIGIN ?? "http://localhost:8787",
    }),
  );

  cachedServer = server;
  cachedServerKey = key;
  return server;
}
