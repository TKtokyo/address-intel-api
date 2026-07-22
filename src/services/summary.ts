import type { GoPlusAddressData, ScoringResult } from "../types";

/**
 * Template-based summary generation (no LLM).
 *
 * Wording is deliberate on the clean path: "no adverse records" is a
 * statement about GoPlus's data, never a guarantee of safety — new scam
 * addresses have clean histories by definition.
 */
export function generateSummary(
  result: ScoringResult,
  data: GoPlusAddressData,
): string {
  const parts: string[] = [];

  switch (result.level) {
    case "CRITICAL":
      parts.push(
        "CRITICAL risk. This address has confirmed malicious history — do not transact.",
      );
      break;
    case "HIGH":
      parts.push(
        "HIGH risk. Strong adverse indicators found — transacting is not recommended.",
      );
      break;
    case "MODERATE":
      parts.push(
        "MODERATE risk. Suspicious associations found — verify the counterparty before transacting.",
      );
      break;
    case "LOW":
      parts.push(
        "No adverse records found in security databases. Note: a clean history does not guarantee safety — newly created scam addresses have no records yet.",
      );
      break;
  }

  if (result.flags.length > 0) {
    parts.push(`Findings: ${result.flags.join(", ")}.`);
  }

  if (data.contract_address === "1") {
    parts.push("This address is a smart contract.");
  }

  return parts.join(" ");
}
