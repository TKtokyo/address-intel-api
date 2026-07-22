export const OPENAPI_SPEC = {
  openapi: "3.0.0",
  info: {
    title: "Address Intel API",
    version: "0.1.0",
    description:
      "Counterparty risk checks for EVM addresses. Returns confirmed malicious-history flags (sanctions, phishing, stealing, money laundering, and 14 more signals), a tiered risk score (0-100), risk level (CRITICAL/HIGH/MODERATE/LOW), and a plain-language summary. x402 v2 micropayments on Base mainnet: sign the payment from the 402 response's PAYMENT-REQUIRED header and retry with the PAYMENT-SIGNATURE header. Wallets that paid can re-read the same address check free for 1 hour via the SIGN-IN-WITH-X header. MCP streamable-http endpoint at /mcp exposes the same check as a paid tool (in-protocol x402 payment).",
    contact: {
      url: "https://address-intel-api.tatsu77.workers.dev/llms.txt",
    },
  },
  servers: [
    {
      url: "https://address-intel-api.tatsu77.workers.dev",
      description: "Production (Base mainnet)",
    },
  ],
  paths: {
    "/api/v1/address/{address}": {
      get: {
        summary: "EVM Address Risk Check",
        description:
          "Counterparty risk check for any EVM address. Call BEFORE sending funds to or transacting with an unknown address. risk_level can be used directly as an if-condition: CRITICAL = confirmed malicious history, do not transact; HIGH = strong adverse indicators; MODERATE = suspicious associations, verify first; LOW = no adverse records (NOT a safety guarantee — fresh scam addresses have clean histories). Requires x402 payment of $0.005 USDC on Base mainnet.",
        parameters: [
          {
            name: "address",
            in: "path",
            required: true,
            description: "EVM address to check (0x-prefixed, 40 hex chars)",
            schema: { type: "string", pattern: "^0x[a-fA-F0-9]{40}$" },
          },
          {
            name: "chainId",
            in: "query",
            required: false,
            description:
              "Optional chain ID to scope the lookup (e.g. '1' Ethereum, '8453' Base). Omit for cross-chain reputation.",
            schema: { type: "string" },
          },
        ],
        responses: {
          "200": {
            description: "Address risk assessment",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    address: { type: "string" },
                    chain_id: { type: "string", nullable: true },
                    is_contract: { type: "boolean", nullable: true },
                    risk_score: {
                      type: "number",
                      description:
                        "0-100. 0 = confirmed malicious, 100 = no adverse records.",
                    },
                    risk_level: {
                      type: "string",
                      enum: ["CRITICAL", "HIGH", "MODERATE", "LOW"],
                    },
                    flags: {
                      type: "object",
                      description:
                        "Full boolean flag map (18 signals: sanctioned, phishing_activities, stealing_attack, money_laundering, mixer, etc.). null = no data for that signal.",
                    },
                    adverse_findings: {
                      type: "array",
                      items: { type: "string" },
                      description: "Human-readable list of flagged findings.",
                    },
                    summary: { type: "string" },
                    data_source: { type: "string", nullable: true },
                    cached: { type: "boolean" },
                    data_age_seconds: { type: "number" },
                  },
                },
              },
            },
          },
          "400": { description: "Invalid address or chainId format." },
          "402": {
            description:
              "Payment required (x402 v2). Payment requirements are in the PAYMENT-REQUIRED response header (base64 JSON, mirrored in the body's accepts[]). Sign and retry with the PAYMENT-SIGNATURE request header. Wallets that already paid may instead present a SIGN-IN-WITH-X header.",
          },
          "404": { description: "No security data available for this address." },
          "429": { description: "Upstream rate limited. Retry in 30 seconds. Not charged." },
          "503": { description: "Upstream unavailable. Not charged." },
        },
        "x-x402": {
          price: "$0.005 USDC",
          network: "base",
          facilitator: "Coinbase CDP",
        },
      },
    },
  },
} as const;
