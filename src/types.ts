export interface Env {
  FACILITATOR_URL: string;
  X402_NETWORK: string;
  PAY_TO_ADDRESS: string;
  GOPLUS_API_KEY: string;
  ADDRESS_CACHE: KVNamespace;
  // CDP keys for mainnet facilitator (optional, testnet needs no auth)
  CDP_API_KEY_ID?: string;
  CDP_API_KEY_SECRET?: string;
  DISABLE_PAYWALL?: string;
  // Public browser-visible origin, used for SIWx domain/URI binding.
  PUBLIC_ORIGIN?: string;
  // SIWx session length in seconds (default 3600): how long a wallet that
  // paid for an address check can re-read it without paying again.
  SIWX_SESSION_TTL_SECONDS?: string;
}

// --- GoPlus address_security API types ---

/** Raw GoPlus address_security response fields (all "0"/"1" strings unless noted). */
export interface GoPlusAddressData {
  // CRITICAL-tier flags: confirmed malicious history
  sanctioned?: string;
  stealing_attack?: string;
  phishing_activities?: string;
  blackmail_activities?: string;
  cybercrime?: string;
  money_laundering?: string;
  financial_crime?: string;
  darkweb_transactions?: string;

  // HIGH-tier flags: strong adverse indicators
  honeypot_related_address?: string;
  malicious_mining_activities?: string;
  fake_token?: string;
  fake_standard_interface?: string;
  fake_kyc?: string;
  gas_abuse?: string;
  /** Count as numeric string, e.g. "0" or "3". */
  number_of_malicious_contracts_created?: string;

  // CAUTION-tier flags: suspicion, not confirmation
  mixer?: string;
  blacklist_doubt?: string;
  reinit?: string;

  // Informational
  contract_address?: string;
  data_source?: string;
}

export interface GoPlusAddressResponse {
  code: number;
  message: string;
  result: GoPlusAddressData | null;
}

export type GoPlusFetchResult =
  | { status: "ok"; data: GoPlusAddressData }
  | { status: "not_found" }
  | { status: "rate_limited"; retryAfter: number }
  | { status: "error"; httpStatus: number; message?: string };

// --- Scoring types ---

export type RiskLevel = "CRITICAL" | "HIGH" | "MODERATE" | "LOW";

export interface ScoringResult {
  score: number;
  level: RiskLevel;
  /** Human-readable adverse findings, empty when no flags hit. */
  flags: string[];
  /** Raw flag keys that hit, grouped by tier (machine-readable). */
  flagged: {
    critical: string[];
    high: string[];
    caution: string[];
  };
}

// --- API response types ---

export interface AddressFlagInfo {
  sanctioned: boolean | null;
  stealing_attack: boolean | null;
  phishing_activities: boolean | null;
  blackmail_activities: boolean | null;
  cybercrime: boolean | null;
  money_laundering: boolean | null;
  financial_crime: boolean | null;
  darkweb_transactions: boolean | null;
  honeypot_related_address: boolean | null;
  malicious_mining_activities: boolean | null;
  fake_token: boolean | null;
  fake_standard_interface: boolean | null;
  fake_kyc: boolean | null;
  gas_abuse: boolean | null;
  malicious_contracts_created: number;
  mixer: boolean | null;
  blacklist_doubt: boolean | null;
  reinit: boolean | null;
}

export interface AddressIntelResponse {
  address: string;
  /** CAIP-agnostic: GoPlus address reputation is largely cross-chain; a
   * chain_id is echoed when the caller scoped the lookup. */
  chain_id: string | null;
  is_contract: boolean | null;
  risk_score: number;
  risk_level: RiskLevel;
  flags: AddressFlagInfo;
  adverse_findings: string[];
  summary: string;
  data_source: string | null;
  cached: boolean;
  data_age_seconds: number;
}

export type AddressSecurityResult =
  | { status: "success"; data: AddressIntelResponse }
  | { status: "not_found" }
  | { status: "rate_limited" }
  | { status: "error"; message: string };
