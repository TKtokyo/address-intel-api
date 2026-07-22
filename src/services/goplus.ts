import type {
  GoPlusAddressData,
  GoPlusAddressResponse,
  GoPlusFetchResult,
  AddressFlagInfo,
  AddressIntelResponse,
  AddressSecurityResult,
} from "../types";
import { calculateAddressRisk } from "./scoring";
import { generateSummary } from "./summary";
import { cacheGet, cachePut, cacheNegativePut } from "./cache";

const GOPLUS_BASE = "https://api.gopluslabs.io/api/v1/address_security";

export const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;

/**
 * chainId allowlist (major GoPlus-supported EVM chains). Bounding this
 * matters because each (address, chainId) pair is a distinct cache key and
 * a distinct upstream call — an unbounded chainId would let one paid SIWx
 * session enumerate arbitrary values and drain upstream quota for free.
 */
export const SUPPORTED_CHAIN_IDS = [
  "1", // Ethereum
  "10", // Optimism
  "56", // BNB Chain
  "137", // Polygon
  "250", // Fantom
  "324", // zkSync Era
  "8453", // Base
  "42161", // Arbitrum
  "43114", // Avalanche
];

/**
 * Fetch address security data from GoPlus.
 * chainId is optional: without it GoPlus returns cross-chain reputation.
 */
export async function fetchGoPlusAddress(
  address: string,
  chainId: string | null,
  apiKey?: string,
): Promise<GoPlusFetchResult> {
  const url = new URL(`${GOPLUS_BASE}/${address}`);
  if (chainId) {
    url.searchParams.set("chain_id", chainId);
  }

  const headers: Record<string, string> = {};
  if (apiKey && apiKey !== "placeholder") {
    headers["Authorization"] = apiKey;
  }

  let response: Response;
  try {
    response = await fetch(url.toString(), { headers });
  } catch (err) {
    return {
      status: "error",
      httpStatus: 0,
      message: err instanceof Error ? err.message : "Network error",
    };
  }

  if (response.status === 429) {
    return { status: "rate_limited", retryAfter: 30 };
  }
  if (!response.ok) {
    return { status: "error", httpStatus: response.status };
  }

  const body = (await response.json()) as GoPlusAddressResponse;
  if (body.code !== 1) {
    return {
      status: "error",
      httpStatus: response.status,
      message: body.message || "GoPlus returned non-OK code",
    };
  }
  if (!body.result || Object.keys(body.result).length === 0) {
    return { status: "not_found" };
  }
  return { status: "ok", data: body.result };
}

/** Convert GoPlus "0"/"1" string to boolean; null when the field is missing
 * or empty (both mean "no data", which must never read as "checked clean"). */
function flag(value: string | undefined): boolean | null {
  if (value === undefined || value === null || value === "") return null;
  return value === "1";
}

export function mapFlags(data: GoPlusAddressData): AddressFlagInfo {
  return {
    sanctioned: flag(data.sanctioned),
    stealing_attack: flag(data.stealing_attack),
    phishing_activities: flag(data.phishing_activities),
    blackmail_activities: flag(data.blackmail_activities),
    cybercrime: flag(data.cybercrime),
    money_laundering: flag(data.money_laundering),
    financial_crime: flag(data.financial_crime),
    darkweb_transactions: flag(data.darkweb_transactions),
    honeypot_related_address: flag(data.honeypot_related_address),
    malicious_mining_activities: flag(data.malicious_mining_activities),
    fake_token: flag(data.fake_token),
    fake_standard_interface: flag(data.fake_standard_interface),
    fake_kyc: flag(data.fake_kyc),
    gas_abuse: flag(data.gas_abuse),
    malicious_contracts_created: parseInt(
      data.number_of_malicious_contracts_created ?? "0",
      10,
    ) || 0,
    mixer: flag(data.mixer),
    blacklist_doubt: flag(data.blacklist_doubt),
    reinit: flag(data.reinit),
  };
}

/**
 * Full pipeline: cache check → GoPlus fetch → map → score → summarize →
 * cache write. Shared by the REST route and the MCP tool.
 */
export async function fetchAddressSecurity(
  address: string,
  chainId: string | null,
  apiKey: string | undefined,
  kv: KVNamespace,
  waitUntil?: (p: Promise<unknown>) => void,
): Promise<AddressSecurityResult> {
  const normalized = address.toLowerCase();

  const cached = await cacheGet(kv, chainId, normalized);
  if (cached.hit) {
    if ("negative" in cached) {
      return { status: "rate_limited" };
    }
    return {
      status: "success",
      data: {
        ...cached.entry.data,
        cached: true,
        data_age_seconds: cached.ageSeconds,
      },
    };
  }

  const result = await fetchGoPlusAddress(normalized, chainId, apiKey);

  if (result.status === "rate_limited") {
    await cacheNegativePut(kv, chainId, normalized, "rate_limited");
    return { status: "rate_limited" };
  }
  if (result.status === "error") {
    if (result.httpStatus >= 500 || result.httpStatus === 0) {
      await cacheNegativePut(
        kv,
        chainId,
        normalized,
        `error_${result.httpStatus}`,
      );
    }
    return { status: "error", message: result.message || "upstream_unavailable" };
  }
  if (result.status === "not_found") {
    return { status: "not_found" };
  }

  const data = result.data;
  const scoring = calculateAddressRisk(data);
  const response: AddressIntelResponse = {
    address: normalized,
    chain_id: chainId,
    is_contract:
      data.contract_address === undefined || data.contract_address === ""
        ? null
        : data.contract_address === "1",
    risk_score: scoring.score,
    risk_level: scoring.level,
    flags: mapFlags(data),
    adverse_findings: scoring.flags,
    summary: generateSummary(scoring, data),
    data_source: data.data_source || null,
    cached: false,
    data_age_seconds: 0,
  };

  const cachePromise = cachePut(kv, chainId, normalized, response);
  if (waitUntil) {
    waitUntil(cachePromise);
  } else {
    await cachePromise;
  }

  return { status: "success", data: response };
}
