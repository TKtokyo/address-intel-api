/**
 * Lightweight stateless MCP server with x402 paid tool execution.
 *
 * Implements the MCP Streamable HTTP transport (JSON-RPC 2.0) directly.
 * initialize + tools/list are free; tools/call executes with in-protocol
 * x402 payment (see token-intel-api / polymarket-scan-api for the same
 * pattern and flow documentation).
 */

import { createPaymentWrapper } from "@x402/mcp";
import type { MCPToolCallback, WrappedToolResult, ToolResult } from "@x402/mcp";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import type { Env } from "../types";
import {
  fetchAddressSecurity,
  ADDRESS_PATTERN,
  SUPPORTED_CHAIN_IDS,
} from "../services/goplus";
import {
  getResourceServer,
  buildAccepts,
  SERVICE_NAME,
  SERVICE_TAGS,
  PRICE_CHECK,
} from "../x402/payments";
import { VERSION } from "../version";

// ─── JSON-RPC types ──────────────────────────────────────────────

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

// ─── MCP protocol constants ──────────────────────────────────────

const PROTOCOL_VERSION = "2025-06-18";
const SERVER_INFO = {
  name: SERVICE_NAME,
  version: VERSION,
};

// ─── Tool definitions ───────────────────────────────────────────

export interface McpToolDef {
  name: string;
  description: string;
  price: string;
  inputSchema: Record<string, unknown>;
  outputExample: unknown;
}

export const MCP_TOOLS: McpToolDef[] = [
  {
    name: "check_address",
    description:
      `Counterparty risk check for any EVM address. Returns confirmed malicious-history flags (sanctions, phishing, stealing, money laundering, etc.), a tiered risk score (0-100), risk level (CRITICAL/HIGH/MODERATE/LOW), and a plain-language summary. Use before sending funds to or transacting with an unknown address. Paid tool: ${PRICE_CHECK} USDC per call via x402 (payment handled in-protocol; x402-aware MCP clients pay automatically).`,
    price: PRICE_CHECK,
    inputSchema: {
      type: "object" as const,
      properties: {
        address: {
          type: "string",
          description: "EVM address to check (0x-prefixed, 40 hex chars)",
          pattern: "^0x[a-fA-F0-9]{40}$",
        },
        chainId: {
          type: "string",
          enum: SUPPORTED_CHAIN_IDS,
          description:
            "Optional chain ID to scope the lookup (e.g. '1' Ethereum, '8453' Base). Omit for cross-chain reputation.",
        },
      },
      required: ["address"],
    },
    outputExample: {
      address: "0x...",
      risk_score: 100,
      risk_level: "LOW",
      summary:
        "No adverse records found in security databases. Note: a clean history does not guarantee safety.",
      adverse_findings: [],
    },
  },
];

/** Bazaar discovery payload for the MCP tool (shared with the manifest). */
export function buildMcpDiscoveryExtension(
  tool: McpToolDef,
): Record<string, unknown> {
  return declareDiscoveryExtension({
    toolName: tool.name,
    description: tool.description,
    transport: "streamable-http",
    inputSchema: tool.inputSchema,
    output: { example: tool.outputExample },
  });
}

// ─── Tool handler ────────────────────────────────────────────────

function textResult(payload: unknown, isError = false): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(payload) }],
    structuredContent: payload as Record<string, unknown>,
    isError,
  };
}

function makeCheckAddressHandler(
  env: Env,
  waitUntil?: (p: Promise<unknown>) => void,
) {
  return async (args: Record<string, unknown>): Promise<ToolResult> => {
    const rawAddress = String(args.address ?? "");
    const chainId =
      args.chainId === undefined || args.chainId === null
        ? null
        : String(args.chainId);

    if (!ADDRESS_PATTERN.test(rawAddress)) {
      return textResult(
        { error: "invalid_address", message: "Invalid EVM address format." },
        true,
      );
    }
    if (chainId !== null && !SUPPORTED_CHAIN_IDS.includes(chainId)) {
      return textResult(
        {
          error: "invalid_chain",
          message: `Unsupported chainId. Allowed: ${SUPPORTED_CHAIN_IDS.join(", ")} (or omit for cross-chain reputation).`,
        },
        true,
      );
    }

    const result = await fetchAddressSecurity(
      rawAddress,
      chainId,
      env.GOPLUS_API_KEY,
      env.ADDRESS_CACHE,
      waitUntil,
    );

    switch (result.status) {
      case "success":
        return textResult(result.data);
      case "not_found":
        return textResult(
          {
            error: "no_data",
            message: "No security data available for this address.",
          },
          true,
        );
      case "rate_limited":
        return textResult(
          {
            error: "upstream_throttled",
            message: "Data source rate limited. Please retry in 30 seconds.",
          },
          true,
        );
      case "error":
        return textResult(
          {
            error: "upstream_unavailable",
            message: "Security data source temporarily unavailable.",
          },
          true,
        );
    }
  };
}

// ─── Paid tool dispatch ──────────────────────────────────────────

function buildToolCallbacks(
  env: Env,
  waitUntil?: (p: Promise<unknown>) => void,
): Record<string, MCPToolCallback> {
  const handlers: Record<
    string,
    (args: Record<string, unknown>) => Promise<ToolResult>
  > = {
    check_address: makeCheckAddressHandler(env, waitUntil),
  };

  // Local dev: skip payment entirely when DISABLE_PAYWALL is set.
  if (env.DISABLE_PAYWALL === "true") {
    const passthrough: Record<string, MCPToolCallback> = {};
    for (const [name, handler] of Object.entries(handlers)) {
      passthrough[name] = async (callArgs) =>
        (await handler(callArgs)) as WrappedToolResult;
    }
    return passthrough;
  }

  const server = getResourceServer(env);
  const callbacks: Record<string, MCPToolCallback> = {};
  for (const tool of MCP_TOOLS) {
    const paid = createPaymentWrapper(server, {
      accepts: buildAccepts(tool.price, env) as never,
      resource: {
        url: `mcp://tool/${tool.name}`,
        description: tool.description,
        mimeType: "application/json",
        serviceName: SERVICE_NAME,
        tags: SERVICE_TAGS,
      },
      extensions: buildMcpDiscoveryExtension(tool),
    });
    callbacks[tool.name] = paid(handlers[tool.name]);
  }
  return callbacks;
}

// ─── JSON-RPC method dispatcher ──────────────────────────────────

async function handleJsonRpcRequest(
  req: JsonRpcRequest,
  env: Env,
  waitUntil?: (p: Promise<unknown>) => void,
): Promise<JsonRpcResponse | null> {
  const { method, id, params } = req;

  if (id === undefined || id === null) {
    return null;
  }

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
        },
      };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          tools: MCP_TOOLS.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        },
      };

    case "tools/call": {
      const p = (params ?? {}) as {
        name?: string;
        arguments?: Record<string, unknown>;
        _meta?: Record<string, unknown>;
      };
      const toolName = p.name;
      if (!toolName || !MCP_TOOLS.some((t) => t.name === toolName)) {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "Unknown tool." },
        };
      }

      const callbacks = buildToolCallbacks(env, waitUntil);
      try {
        const result = await callbacks[toolName](p.arguments ?? {}, {
          _meta: p._meta,
        });
        return { jsonrpc: "2.0", id, result };
      } catch (err) {
        console.error(
          `MCP tools/call ${toolName} failed:`,
          err instanceof Error ? err.message : err,
        );
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32603, message: "Tool execution failed." },
        };
      }
    }

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: "Method not supported." },
      };
  }
}

// ─── CORS + HTTP handler ─────────────────────────────────────────

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-session-id",
  "Access-Control-Max-Age": "86400",
};

function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    headers.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export async function handleMcpRequest(
  request: Request,
  env: Env,
  waitUntil?: (p: Promise<unknown>) => void,
): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  if (request.method === "GET") {
    return withCors(
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "SSE transport not supported. Use POST with JSON-RPC.",
          },
        }),
        {
          status: 405,
          headers: { "Content-Type": "application/json", Allow: "POST, OPTIONS" },
        },
      ),
    );
  }
  if (request.method === "DELETE") {
    return withCors(new Response(null, { status: 204 }));
  }
  if (request.method !== "POST") {
    return withCors(
      new Response(null, { status: 405, headers: { Allow: "POST, OPTIONS" } }),
    );
  }

  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return withCors(
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Content-Type must be application/json" },
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      ),
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return withCors(
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      ),
    );
  }

  if (Array.isArray(body)) {
    const responses: JsonRpcResponse[] = [];
    for (const req of body as JsonRpcRequest[]) {
      const resp = await handleJsonRpcRequest(req, env, waitUntil);
      if (resp) responses.push(resp);
    }
    if (responses.length === 0) {
      return withCors(new Response(null, { status: 204 }));
    }
    return withCors(
      new Response(JSON.stringify(responses), {
        headers: { "Content-Type": "application/json" },
      }),
    );
  }

  const resp = await handleJsonRpcRequest(body as JsonRpcRequest, env, waitUntil);
  if (!resp) {
    return withCors(new Response(null, { status: 204 }));
  }
  return withCors(
    new Response(JSON.stringify(resp), {
      headers: { "Content-Type": "application/json" },
    }),
  );
}
