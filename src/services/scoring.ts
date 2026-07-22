import type { GoPlusAddressData, ScoringResult, RiskLevel } from "../types";

/**
 * Tiered address risk assessment.
 *
 * Unlike token scoring (gradual deductions), address reputation is largely
 * binary: one confirmed malicious-history flag makes the counterparty
 * unsafe regardless of everything else. So flags are grouped into tiers and
 * the verdict is driven by the worst tier hit:
 *
 *   CRITICAL flag hit → score 0,  level CRITICAL  (confirmed malicious history)
 *   HIGH flag hit     → score ≤40, level HIGH     (strong adverse indicators)
 *   CAUTION flag hit  → score ≤75, level MODERATE (suspicion, not confirmation)
 *   nothing hit       → score 100, level LOW      (no adverse records — NOT a
 *                                                  guarantee of safety)
 *
 * Field absence (GoPlus omits fields it has no data for) never counts
 * against an address; it is surfaced separately by the mapper.
 */

const CRITICAL_FLAGS: Array<{ key: keyof GoPlusAddressData; label: string }> = [
  { key: "sanctioned", label: "Sanctioned address" },
  { key: "stealing_attack", label: "Involved in stealing attacks" },
  { key: "phishing_activities", label: "Phishing activities" },
  { key: "blackmail_activities", label: "Blackmail activities" },
  { key: "cybercrime", label: "Cybercrime involvement" },
  { key: "money_laundering", label: "Money laundering" },
  { key: "financial_crime", label: "Financial crime" },
  { key: "darkweb_transactions", label: "Darkweb transactions" },
];

const HIGH_FLAGS: Array<{ key: keyof GoPlusAddressData; label: string }> = [
  { key: "honeypot_related_address", label: "Honeypot-related address" },
  { key: "malicious_mining_activities", label: "Malicious mining activities" },
  { key: "fake_token", label: "Fake token issuance" },
  { key: "fake_standard_interface", label: "Fake standard interface" },
  { key: "fake_kyc", label: "Fake KYC" },
  { key: "gas_abuse", label: "Gas abuse" },
];

const CAUTION_FLAGS: Array<{ key: keyof GoPlusAddressData; label: string }> = [
  { key: "mixer", label: "Mixer usage" },
  { key: "blacklist_doubt", label: "Suspected blacklist association" },
  { key: "reinit", label: "Redeployable contract (reinit)" },
];

const HIGH_DEDUCTION = 40;
const CAUTION_DEDUCTION = 15;

export function calculateAddressRisk(data: GoPlusAddressData): ScoringResult {
  const flags: string[] = [];
  const flagged = {
    critical: [] as string[],
    high: [] as string[],
    caution: [] as string[],
  };

  for (const { key, label } of CRITICAL_FLAGS) {
    if (data[key] === "1") {
      flagged.critical.push(key);
      flags.push(label);
    }
  }
  for (const { key, label } of HIGH_FLAGS) {
    if (data[key] === "1") {
      flagged.high.push(key);
      flags.push(label);
    }
  }
  const maliciousContracts = parseInt(
    data.number_of_malicious_contracts_created ?? "0",
    10,
  );
  if (Number.isFinite(maliciousContracts) && maliciousContracts > 0) {
    flagged.high.push("number_of_malicious_contracts_created");
    flags.push(`Created ${maliciousContracts} malicious contract(s)`);
  }
  for (const { key, label } of CAUTION_FLAGS) {
    if (data[key] === "1") {
      flagged.caution.push(key);
      flags.push(label);
    }
  }

  let score: number;
  let level: RiskLevel;

  if (flagged.critical.length > 0) {
    score = 0;
    level = "CRITICAL";
  } else if (flagged.high.length > 0) {
    score = Math.max(5, 60 - HIGH_DEDUCTION * (flagged.high.length - 1));
    level = "HIGH";
  } else if (flagged.caution.length > 0) {
    score = Math.max(55, 90 - CAUTION_DEDUCTION * flagged.caution.length);
    level = "MODERATE";
  } else {
    score = 100;
    level = "LOW";
  }

  return { score, level, flags, flagged };
}
