# X402 Token Safety Oracle

Multi-chain token safety analysis API with x402 micropayment support.

## Supported Chains

- Solana
- Ethereum (ERC-20)
- Base
- Arbitrum
- Polygon

## Features

- Token safety scoring (0-100)
- Rug pull risk assessment (0-100)
- Honeypot detection
- Holder distribution analysis
- Liquidity checks
- Token age verification
- Contract verification checks (EVM chains)
- x402 micropayment support

## API Endpoints

### GET /health
Health check endpoint

### POST /check
Check token safety

Request body:
```json
{
  "token_address": "string",
  "chain": "solana|ethereum|base|arbitrum|polygon",
  "pool_address": "string (optional)",
  "dex": "string (optional)",
  "metadata": {
    "holder_count": 1000,
    "liquidity_usd": 50000,
    "age_minutes": 30,
    "name": "TokenName",
    "is_verified": true,
    "has_mint_function": false,
    "has_burn_function": false,
    "owner_renounced": true
  }
}
```

Response:
```json
{
  "safe": true,
  "safety_score": 85,
  "rug_pull_risk": 15,
  "is_honeypot": false,
  "recommendation": "SAFE - Low risk, recommended for trading",
  "checks": {
    "holder_count": 1000,
    "holder_distribution": "PASS",
    "liquidity_usd": 50000,
    "liquidity_check": "PASS",
    "age_minutes": 30,
    "age_check": "PASS",
    "name_check": "PASS",
    "honeypot_check": "PASS"
  },
  "chain": "solana",
  "token_address": "...",
  "timestamp": 1699564800
}
```

### GET /chains
Get list of supported chains

### GET /
API documentation

## Deployment

### Railway

1. Connect repository to Railway
2. Set environment variables:
   - `FREE_MODE=true` (for testing)
   - `X402_PRICE_PER_CHECK=0.01` (optional)
   - `X402_PAYMENT_TOKEN=USDC` (optional)

### Local Development

```bash
pip install -r requirements.txt
python app.py
```

## X402 Micropayments

When `FREE_MODE=false`, the API requires x402 payment proof in the Authorization header:

```
Authorization: Bearer <payment_proof>
```

If payment verification fails, the API returns HTTP 402 with payment details.

## License

MIT
