import { Hono } from "hono";
import { paymentMiddleware } from "@x402/hono";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { declareSIWxExtension } from "@x402/extensions/sign-in-with-x";
import type { RoutesConfig } from "@x402/core/server";
import type { Env } from "./types";
import {
  fetchAddressSecurity,
  ADDRESS_PATTERN,
  SUPPORTED_CHAIN_IDS,
} from "./services/goplus";
import {
  handleMcpRequest,
  MCP_TOOLS,
  buildMcpDiscoveryExtension,
} from "./mcp/server";
import { OPENAPI_SPEC } from "./openapi";
import { VERSION } from "./version";
import {
  buildAccepts,
  getResourceServer,
  envCacheKey,
  siwxSessionTtlSeconds,
  SERVICE_NAME,
  SERVICE_TAGS,
  PRICE_CHECK,
} from "./x402/payments";

// ─── Route definition (single source of truth) ─────────────────────────────
//
// ADDRESS_ROUTE drives both the payment middleware and the .well-known/x402
// manifest, so the route URL, price, and discovery metadata cannot drift.

// Known-clean sample (Vitalik's address) so x402scan validation hits a real
// path that returns 402.
const SAMPLE_ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

const ADDRESS_ROUTE = {
  method: "GET" as const,
  middlewarePattern: "GET /api/v1/address/:address",
  resourcePath: `/api/v1/address/${SAMPLE_ADDRESS}`,
  price: PRICE_CHECK,
  resourceName: "EVM Address Risk Check",
  description:
    "Counterparty risk check for any EVM address: confirmed malicious-history flags (sanctions, phishing, stealing, laundering), tiered risk score, and plain-language summary",
  inputExample: { address: SAMPLE_ADDRESS },
  inputSchema: {
    type: "object",
    properties: {
      address: {
        type: "string",
        pattern: "^0x[a-fA-F0-9]{40}$",
        description: "EVM address to check",
      },
      chainId: {
        type: "string",
        enum: SUPPORTED_CHAIN_IDS,
        description:
          "Optional query param: chain ID to scope the lookup (e.g. '1', '8453'). Omit for cross-chain reputation.",
      },
    },
    required: ["address"],
  },
  outputExample: {
    address: SAMPLE_ADDRESS.toLowerCase(),
    chain_id: null,
    is_contract: false,
    risk_score: 100,
    risk_level: "LOW",
    flags: { sanctioned: false, phishing_activities: false, mixer: false },
    adverse_findings: [],
    data_source: null,
    summary:
      "No adverse records found in security databases. Note: a clean history does not guarantee safety — newly created scam addresses have no records yet.",
    cached: false,
    data_age_seconds: 0,
  },
  outputSchema: {
    type: "object",
    properties: {
      address: { type: "string" },
      chain_id: { type: ["string", "null"] },
      is_contract: { type: ["boolean", "null"] },
      risk_score: {
        type: "number",
        minimum: 0,
        maximum: 100,
        description: "Risk score (0 = confirmed malicious, 100 = no adverse records)",
      },
      risk_level: {
        type: "string",
        enum: ["CRITICAL", "HIGH", "MODERATE", "LOW"],
      },
      flags: { type: "object" },
      adverse_findings: { type: "array", items: { type: "string" } },
      summary: { type: "string" },
      cached: { type: "boolean" },
      data_age_seconds: { type: "number" },
    },
    required: [
      "address",
      "risk_score",
      "risk_level",
      "flags",
      "adverse_findings",
      "summary",
    ],
  },
};

// Bumped when the route schema or pricing changes.
const RESOURCES_LAST_UPDATED = "2026-07-22T00:00:00Z";

function buildDiscoveryExtension() {
  return declareDiscoveryExtension({
    input: ADDRESS_ROUTE.inputExample,
    inputSchema: ADDRESS_ROUTE.inputSchema,
    output: {
      example: ADDRESS_ROUTE.outputExample,
      schema: ADDRESS_ROUTE.outputSchema,
    },
  });
}

// ─── HTTP App ───────────────────────────────────────────────────────────────

const app = new Hono<{ Bindings: Env }>();

// Security headers
app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Cache-Control", "no-store");
  c.header("X-Frame-Options", "DENY");
});

// Error handler — generic message only, details stay in logs
app.onError((err, c) => {
  console.error("Unhandled error:", err.message, err.stack);
  return c.json(
    { error: "internal_error", message: "An unexpected error occurred." },
    500,
  );
});

// Health check (unprotected)
app.get("/health", (c) => c.json({ status: "ok", version: VERSION }));

// API info
app.get("/", (c) =>
  c.json({
    name: SERVICE_NAME,
    version: VERSION,
    description:
      "EVM address counterparty risk checks via x402 micropayments",
    endpoints: {
      check: "GET /api/v1/address/{address}?chainId=optional",
    },
    price: { check: PRICE_CHECK },
    example: `/api/v1/address/${SAMPLE_ADDRESS}`,
    x402: true,
    siwx: `Paid wallets can re-read the same address check free for ${siwxSessionTtlSeconds(c.env)}s via SIGN-IN-WITH-X`,
    mcp: {
      endpoint: "/mcp",
      transport: "streamable-http",
      tools: MCP_TOOLS.map((t) => t.name),
      payment: "x402 in-protocol (params._meta['x402/payment'])",
    },
  }),
);

// OpenAPI spec (unprotected)
app.get("/openapi.json", (c) =>
  c.json(OPENAPI_SPEC, 200, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  }),
);

// llms.txt (unprotected)
app.get("/llms.txt", (c) => {
  const body = `# Address Intel API
> Counterparty risk checks for EVM addresses — confirmed malicious-history flags, tiered risk scoring, and plain-language summaries via x402 micropayments.

## When to use this API

Call this BEFORE sending funds to, approving, or transacting with an address you don't fully trust:
- "Is it safe to pay this address?" — this is the right tool.
- Screening counterparties in automated payment flows (x402 agents paying unknown services).
- Checking a token deployer or contract owner address during due diligence.

## Endpoint

### GET /api/v1/address/{address}?chainId={optional}

**Paywall**: x402 v2 — ${PRICE_CHECK} USDC on Base mainnet. Sign the requirements from the 402 response's PAYMENT-REQUIRED header and retry with the PAYMENT-SIGNATURE header. A wallet that paid can re-read the same address check free for 1 hour via the SIGN-IN-WITH-X header.

**Response fields**:
- risk_level: CRITICAL | HIGH | MODERATE | LOW — use directly as an if-condition:
  - CRITICAL: confirmed malicious history (sanctions, phishing, stealing, laundering). DO NOT transact.
  - HIGH: strong adverse indicators (fake tokens, honeypot ties, malicious contracts). Avoid.
  - MODERATE: suspicious associations (mixer use, suspected blacklists). Verify counterparty first.
  - LOW: no adverse records. IMPORTANT: this is "no records", not "guaranteed safe" — fresh scam addresses have clean histories.
- risk_score: 0-100 (0 = confirmed malicious).
- adverse_findings: human-readable list of everything that was flagged.
- flags: full boolean flag map (18 signals) for custom logic.

## Machine-readable API spec
- OpenAPI 3.0: https://address-intel-api.tatsu77.workers.dev/openapi.json

## Discovery
- x402 manifest: https://address-intel-api.tatsu77.workers.dev/.well-known/x402

## MCP
- Streamable HTTP: https://address-intel-api.tatsu77.workers.dev/mcp
- Paid tool with in-protocol x402 payment: check_address (${PRICE_CHECK}). x402-aware MCP clients (@x402/mcp) pay automatically via params._meta["x402/payment"].

## Related services (same operator)
- Token Intel API — EVM token security analysis: https://token-intel-api.tatsu77.workers.dev/llms.txt
`;
  return c.text(body, 200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
  });
});

// x402 discovery (unprotected)
app.get("/.well-known/x402", (c) => {
  const baseUrl = new URL(c.req.url).origin;
  const resources = [
    {
      resource: `${baseUrl}${ADDRESS_ROUTE.resourcePath}`,
      type: "http",
      x402Version: 2,
      accepts: buildAccepts(ADDRESS_ROUTE.price, c.env),
      lastUpdated: RESOURCES_LAST_UPDATED,
      description: ADDRESS_ROUTE.description,
      mimeType: "application/json",
      serviceName: SERVICE_NAME,
      tags: SERVICE_TAGS,
      extensions: buildDiscoveryExtension(),
      metadata: {
        method: ADDRESS_ROUTE.method,
        name: ADDRESS_ROUTE.resourceName,
        description: ADDRESS_ROUTE.description,
        inputSchema: ADDRESS_ROUTE.inputSchema,
        outputExample: ADDRESS_ROUTE.outputExample,
      },
    },
    ...MCP_TOOLS.map((tool) => ({
      resource: `mcp://tool/${tool.name}`,
      type: "mcp",
      x402Version: 2,
      accepts: buildAccepts(tool.price, c.env),
      lastUpdated: RESOURCES_LAST_UPDATED,
      description: tool.description,
      mimeType: "application/json",
      serviceName: SERVICE_NAME,
      tags: SERVICE_TAGS,
      extensions: buildMcpDiscoveryExtension(tool),
      metadata: {
        transport: "streamable-http",
        endpoint: `${baseUrl}/mcp`,
        toolName: tool.name,
        inputSchema: tool.inputSchema,
      },
    })),
  ];

  return c.json(
    {
      x402Version: 2,
      resourceServer: baseUrl,
      facilitator: c.env.FACILITATOR_URL,
      network: c.env.X402_NETWORK,
      openapi: `${baseUrl}/openapi.json`,
      resources,
    },
    200,
    { "Access-Control-Allow-Origin": "*" },
  );
});

// MCP server endpoint (paid tool execution via @x402/mcp)
app.all("/mcp", (c) =>
  handleMcpRequest(c.req.raw, c.env, (p) => c.executionCtx.waitUntil(p)),
);

// ─── x402 paywall middleware (memoized per isolate) ─────────────────────────

let cachedMiddleware: ReturnType<typeof paymentMiddleware> | null = null;
let cachedMiddlewareKey = "";

function getPaymentMiddleware(env: Env): ReturnType<typeof paymentMiddleware> {
  const key = envCacheKey(env);
  if (cachedMiddleware && cachedMiddlewareKey === key) {
    return cachedMiddleware;
  }

  const server = getResourceServer(env);
  const network = env.X402_NETWORK as `eip155:${string}`;
  const payTo = env.PAY_TO_ADDRESS as `0x${string}`;

  const accepts = buildAccepts(ADDRESS_ROUTE.price, env);
  const routes: RoutesConfig = {
    [ADDRESS_ROUTE.middlewarePattern]: {
      accepts: {
        scheme: "exact",
        network,
        price: ADDRESS_ROUTE.price,
        payTo,
      },
      serviceName: SERVICE_NAME,
      tags: SERVICE_TAGS,
      description: ADDRESS_ROUTE.description,
      mimeType: "application/json",
      extensions: {
        ...buildDiscoveryExtension(),
        // SIWx sessions: address reputation changes slowly, so a paid wallet
        // re-reading the same address within the cache window (1h) gets it
        // free — the session TTL matches the positive cache TTL.
        ...declareSIWxExtension({
          statement:
            "Sign in to Address Intel API to re-read address checks you already paid for.",
        }),
      },
      unpaidResponseBody: () => ({
        contentType: "application/json",
        body: {
          x402Version: 2,
          accepts,
          error:
            "Payment required: send an x402 payment via the PAYMENT-SIGNATURE header (requirements in the PAYMENT-REQUIRED header and accepts[] above).",
        },
      }),
    },
  };

  cachedMiddleware = paymentMiddleware(routes, server);
  cachedMiddlewareKey = key;
  return cachedMiddleware;
}

app.use("/api/v1/*", async (c, next) => {
  if (c.env.DISABLE_PAYWALL === "true") {
    return next();
  }
  return getPaymentMiddleware(c.env)(c, next);
});

// ─── Protected route ────────────────────────────────────────────────────────

app.get("/api/v1/address/:address", async (c) => {
  const requestId = crypto.randomUUID().slice(0, 8);
  const rawAddress = c.req.param("address");
  const chainIdParam = c.req.query("chainId");
  const chainId = chainIdParam ? chainIdParam : null;

  if (!ADDRESS_PATTERN.test(rawAddress)) {
    return c.json(
      { error: "invalid_address", message: "Invalid EVM address format." },
      400,
    );
  }
  if (chainId !== null && !SUPPORTED_CHAIN_IDS.includes(chainId)) {
    return c.json(
      {
        error: "invalid_chain",
        message: `Unsupported chainId. Allowed: ${SUPPORTED_CHAIN_IDS.join(", ")} (or omit for cross-chain reputation).`,
      },
      400,
    );
  }

  const t0 = Date.now();
  const result = await fetchAddressSecurity(
    rawAddress,
    chainId,
    c.env.GOPLUS_API_KEY,
    c.env.ADDRESS_CACHE,
    (p) => c.executionCtx.waitUntil(p),
  );
  const tTotal = Date.now() - t0;

  switch (result.status) {
    case "rate_limited":
      console.log(`[${requestId}] ${rawAddress} rate_limited t=${tTotal}ms`);
      return c.json(
        {
          error: "upstream_throttled",
          message: "Data source rate limited. Please retry in 30 seconds.",
        },
        429,
      );
    case "error":
      console.error(
        `[${requestId}] ${rawAddress} error msg=${result.message} t=${tTotal}ms`,
      );
      return c.json(
        {
          error: "upstream_unavailable",
          message: "Security data source temporarily unavailable.",
        },
        503,
      );
    case "not_found":
      console.log(`[${requestId}] ${rawAddress} not_found t=${tTotal}ms`);
      return c.json(
        {
          error: "no_data",
          message: "No security data available for this address.",
        },
        404,
      );
    case "success":
      console.log(
        `[${requestId}] ${rawAddress} level=${result.data.risk_level} cached=${result.data.cached} t=${tTotal}ms`,
      );
      return c.json(result.data);
  }
});

export default app;
