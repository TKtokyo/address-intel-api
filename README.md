# Address Intel API

x402-powered paid API that returns counterparty risk checks for any EVM address: confirmed malicious-history flags, tiered risk scoring, and plain-language summaries.

**Production:** `https://address-intel-api.tatsu77.workers.dev`

## Why

Agents (and humans) transact with addresses they've never seen. This API answers "is it safe to pay this address?" in one call, priced for machine consumption ($0.005 USDC via x402). Data: GoPlus Security `address_security` (sources include SlowMist, BlockSec).

## API

### `GET /api/v1/address/{address}?chainId={optional}`

**Payment:** $0.005 USDC via x402 v2 on Base mainnet. Sign the requirements from the 402 response's `PAYMENT-REQUIRED` header and retry with the `PAYMENT-SIGNATURE` header. A wallet that paid can re-read the same address check free for 1 hour via `SIGN-IN-WITH-X` (matches the cache TTL, so sessions only re-serve data the wallet already bought).

| Parameter | Description |
|---|---|
| `address` | EVM address (`^0x[a-fA-F0-9]{40}$`) |
| `chainId` | Optional query param to scope the lookup (e.g. `1`, `8453`). Omit for cross-chain reputation. |

**Response (200):**

```json
{
  "address": "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
  "chain_id": null,
  "is_contract": false,
  "risk_score": 0,
  "risk_level": "CRITICAL",
  "flags": { "sanctioned": true, "stealing_attack": true, "...": "18 signals total" },
  "adverse_findings": ["Sanctioned address", "Involved in stealing attacks"],
  "summary": "CRITICAL risk. This address has confirmed malicious history — do not transact. ...",
  "data_source": "SlowMist,BlockSec",
  "cached": false,
  "data_age_seconds": 0
}
```

**Risk levels** (tiered, not deduction-based — one confirmed malicious flag is disqualifying):

| Level | Trigger | Meaning |
|---|---|---|
| `CRITICAL` (score 0) | Any confirmed malicious-history flag: sanctioned, stealing, phishing, blackmail, cybercrime, laundering, financial crime, darkweb | Do not transact |
| `HIGH` (score ≤60) | Strong adverse indicators: honeypot ties, fake tokens/KYC/interface, gas abuse, malicious contracts created | Avoid |
| `MODERATE` (score ≤90) | Suspicion, not confirmation: mixer use, suspected blacklists, reinit | Verify counterparty first |
| `LOW` (score 100) | No adverse records | **Not a safety guarantee** — fresh scam addresses have clean histories |

**Errors:** `400` invalid input / `402` payment required / `404` no data / `429` upstream throttled / `503` upstream down. Failed requests are never charged (payment cancels instead of settling).

### MCP: `POST /mcp` (streamable HTTP)

Paid tool `check_address` ($0.005) with in-protocol x402 payment — x402-aware MCP clients (`@x402/mcp`) pay automatically via `params._meta["x402/payment"]`. `initialize` and `tools/list` are free.

### Free discovery

`GET /.well-known/x402` (2 resources: http + mcp) / `GET /openapi.json` / `GET /llms.txt` / `GET /health`

## Development

```bash
npm install
npm run dev          # local dev (uses .dev.vars)
npm run typecheck
npx wrangler deploy --env production   # mainnet (requires secrets below)
```

### Environment

| Variable | Where | Description |
|---|---|---|
| `PAY_TO_ADDRESS` | Wrangler secret | EOA to receive USDC |
| `GOPLUS_API_KEY` | Wrangler secret | GoPlus API key (optional; higher rate limits) |
| `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` | Wrangler secret (production) | Coinbase Developer Platform keys |
| `PUBLIC_ORIGIN` | wrangler.toml vars | Public origin for SIWx domain binding |
| `SIWX_SESSION_TTL_SECONDS` | wrangler.toml vars (optional) | SIWx re-read window, default 3600 |

## Architecture

```
Cloudflare Workers (Hono)
  ├── x402 v2 Payment Middleware (@x402/hono, memoized per isolate)
  ├── Paid MCP tool (@x402/mcp createPaymentWrapper)
  ├── SIWx sessions (KV, 1h, nonce replay protection)
  ├── Bazaar Discovery (serviceName/tags + schemas, manifest = middleware)
  ├── Cache (Cloudflare KV, 1h TTL — address reputation moves slowly)
  └── GoPlus address_security → tiered scoring → template summary
```

Sibling services sharing this architecture: [token-intel-api](https://token-intel-api.tatsu77.workers.dev/llms.txt) (EVM token security), [polymarket-scan-api](https://polymarket-scan-api.tatsu77.workers.dev/llms.txt) (Polymarket liquidity anomalies).

## License

MIT
