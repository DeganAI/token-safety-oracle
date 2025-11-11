#!/usr/bin/env python3
"""
X402 Token Safety Oracle v3.0
Multi-chain token safety analysis with LIVE DATA from DexScreener + GoPlusLabs
Supports: Solana, Ethereum, Base, Arbitrum, Polygon
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time
import hashlib
import requests
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
import json
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Configuration
X402_PRICE_PER_CHECK = float(os.getenv("X402_PRICE_PER_CHECK", "0.01"))
X402_PAYMENT_TOKEN = os.getenv("X402_PAYMENT_TOKEN", "USDC")
FREE_MODE = True  # Private API for internal bots
PORT = int(os.getenv("PORT", "8000"))

# API Configuration
DEXSCREENER_API = "https://api.dexscreener.com/latest/dex"
GOPLUS_API = "https://api.gopluslabs.io/api/v1"

# In-memory cache (5 minute TTL)
CACHE = {}
CACHE_TTL = 300  # 5 minutes

# Chain configurations
SUPPORTED_CHAINS = {
    "solana": {
        "chain_id": "solana-mainnet",
        "name": "Solana",
        "goplus_id": "1",  # Solana on GoPlus
        "rpc_url": os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"),
    },
    "ethereum": {
        "chain_id": 1,
        "name": "Ethereum",
        "goplus_id": "1",  # Ethereum on GoPlus
        "rpc_url": os.getenv("ETH_RPC_URL", "https://eth.llamarpc.com"),
    },
    "base": {
        "chain_id": 8453,
        "name": "Base",
        "goplus_id": "8453",  # Base on GoPlus
        "rpc_url": os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
    },
    "arbitrum": {
        "chain_id": 42161,
        "name": "Arbitrum",
        "goplus_id": "42161",  # Arbitrum on GoPlus
        "rpc_url": os.getenv("ARB_RPC_URL", "https://arb1.arbitrum.io/rpc"),
    },
    "polygon": {
        "chain_id": 137,
        "name": "Polygon",
        "goplus_id": "137",  # Polygon on GoPlus
        "rpc_url": os.getenv("POLYGON_RPC_URL", "https://polygon-rpc.com"),
    }
}

@dataclass
class SafetyCheckResult:
    """Token safety check result"""
    safe: bool
    safety_score: int  # 0-100
    rug_pull_risk: int  # 0-100
    is_honeypot: bool
    recommendation: str
    checks: Dict[str, Any]
    chain: str
    token_address: str
    metadata: Dict[str, Any]
    data_source: str  # "live" or "metadata"


def get_cache_key(chain: str, token_address: str) -> str:
    """Generate cache key"""
    return f"{chain}:{token_address}"


def get_from_cache(key: str) -> Optional[Dict]:
    """Get data from cache if not expired"""
    if key in CACHE:
        data, timestamp = CACHE[key]
        if time.time() - timestamp < CACHE_TTL:
            return data
        else:
            del CACHE[key]
    return None


def set_cache(key: str, data: Dict):
    """Set data in cache"""
    CACHE[key] = (data, time.time())


def fetch_dexscreener_data(token_address: str) -> Optional[Dict]:
    """
    Fetch token data from DexScreener
    Returns: {liquidity_usd, age_minutes, holder_count (estimate), volume_24h, price}
    """
    try:
        url = f"{DEXSCREENER_API}/tokens/{token_address}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()

            if data and 'pairs' in data and len(data['pairs']) > 0:
                # Get the most liquid pair
                pair = max(data['pairs'], key=lambda x: float(x.get('liquidity', {}).get('usd', 0)))

                # Calculate age in minutes
                created_at = pair.get('pairCreatedAt', 0)
                age_minutes = (time.time() * 1000 - created_at) / 60000 if created_at else 0

                return {
                    "liquidity_usd": float(pair.get('liquidity', {}).get('usd', 0)),
                    "age_minutes": age_minutes,
                    "volume_24h": float(pair.get('volume', {}).get('h24', 0)),
                    "price_usd": float(pair.get('priceUsd', 0)),
                    "price_change_24h": float(pair.get('priceChange', {}).get('h24', 0)),
                    "txns_24h": pair.get('txns', {}).get('h24', {}).get('buys', 0) + pair.get('txns', {}).get('h24', {}).get('sells', 0),
                    "dex": pair.get('dexId', 'unknown'),
                    "pair_address": pair.get('pairAddress', ''),
                }
    except Exception as e:
        print(f"DexScreener fetch error: {e}")

    return None


def fetch_goplus_security(chain: str, token_address: str) -> Optional[Dict]:
    """
    Fetch security data from GoPlusLabs
    Returns: Security analysis including honeypot detection
    """
    try:
        chain_id = SUPPORTED_CHAINS[chain]["goplus_id"]
        url = f"{GOPLUS_API}/token_security/{chain_id}"
        params = {"contract_addresses": token_address}

        response = requests.get(url, params=params, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data and 'result' in data and token_address.lower() in data['result']:
                return data['result'][token_address.lower()]
    except Exception as e:
        print(f"GoPlus fetch error: {e}")

    return None


def analyze_token_safety(chain: str, token_address: str, live_data: Dict, security_data: Optional[Dict], metadata: Dict) -> SafetyCheckResult:
    """
    Analyze token safety using live data + security analysis + metadata
    """
    checks = {}
    safety_score = 100
    rug_risk = 0
    data_source = "live" if live_data else "metadata"

    # Use live data if available, otherwise fall back to metadata
    liquidity_usd = live_data.get("liquidity_usd") if live_data else metadata.get("liquidity_usd", 0)
    age_minutes = live_data.get("age_minutes") if live_data else metadata.get("age_minutes", 0)
    volume_24h = live_data.get("volume_24h", 0) if live_data else metadata.get("volume_24h", 0)

    # Token name from metadata or security data
    token_name = metadata.get("name", "").lower()
    if security_data and 'token_name' in security_data:
        token_name = security_data['token_name'].lower()

    checks["token_name"] = token_name
    checks["data_source"] = data_source

    # 1. LIQUIDITY CHECK
    checks["liquidity_usd"] = liquidity_usd
    if liquidity_usd < 1000:
        safety_score -= 30
        rug_risk += 30
        checks["liquidity_check"] = "FAIL - Very low liquidity (< $1K)"
    elif liquidity_usd < 10000:
        safety_score -= 15
        rug_risk += 15
        checks["liquidity_check"] = "WARNING - Low liquidity (< $10K)"
    else:
        checks["liquidity_check"] = "PASS"

    # 2. AGE CHECK
    checks["age_minutes"] = age_minutes
    if age_minutes < 2:
        safety_score -= 25
        rug_risk += 25
        checks["age_check"] = "FAIL - Very new token (< 2 min, high risk)"
    elif age_minutes < 30:
        safety_score -= 10
        rug_risk += 10
        checks["age_check"] = "WARNING - New token (< 30 min)"
    else:
        checks["age_check"] = "PASS"

    # 3. VOLUME CHECK (if available)
    if volume_24h > 0:
        checks["volume_24h"] = volume_24h
        if volume_24h < 100:
            safety_score -= 10
            rug_risk += 10
            checks["volume_check"] = "WARNING - Very low volume"
        else:
            checks["volume_check"] = "PASS"

    # 4. GOPLUS SECURITY CHECKS
    is_honeypot = False
    if security_data:
        checks["goplus_available"] = True

        # Honeypot check
        if security_data.get('is_honeypot') == '1':
            is_honeypot = True
            safety_score = min(safety_score, 10)
            rug_risk = max(rug_risk, 90)
            checks["honeypot_check"] = "FAIL - Confirmed honeypot"
        else:
            checks["honeypot_check"] = "PASS"

        # Buy/Sell tax check
        buy_tax = float(security_data.get('buy_tax', 0))
        sell_tax = float(security_data.get('sell_tax', 0))
        checks["buy_tax"] = f"{buy_tax}%"
        checks["sell_tax"] = f"{sell_tax}%"

        if sell_tax > 50:
            safety_score -= 30
            rug_risk += 30
            checks["tax_check"] = "FAIL - Excessive sell tax"
        elif sell_tax > 10 or buy_tax > 10:
            safety_score -= 10
            rug_risk += 10
            checks["tax_check"] = "WARNING - High tax"
        else:
            checks["tax_check"] = "PASS"

        # Mint function check
        if security_data.get('is_mintable') == '1':
            safety_score -= 10
            rug_risk += 10
            checks["mint_check"] = "WARNING - Token is mintable"
        else:
            checks["mint_check"] = "PASS"

        # Owner check
        if security_data.get('owner_address') and security_data.get('owner_address') != '0x0000000000000000000000000000000000000000':
            safety_score -= 5
            rug_risk += 5
            checks["ownership_check"] = "WARNING - Ownership not renounced"
        else:
            checks["ownership_check"] = "PASS"

        # Holder count from GoPlus
        holder_count = int(security_data.get('holder_count', 0))
        if holder_count > 0:
            checks["holder_count"] = holder_count
            if holder_count < 50:
                safety_score -= 20
                rug_risk += 20
                checks["holder_distribution"] = "FAIL - Too few holders"
            elif holder_count < 100:
                safety_score -= 10
                rug_risk += 10
                checks["holder_distribution"] = "WARNING - Low holder count"
            else:
                checks["holder_distribution"] = "PASS"
    else:
        checks["goplus_available"] = False
        # Fallback to metadata holder count
        holder_count = metadata.get("holder_count", 0)
        if holder_count > 0:
            checks["holder_count"] = holder_count
            if holder_count < 100:
                safety_score -= 20
                rug_risk += 20
                checks["holder_distribution"] = "FAIL - Too few holders"
            else:
                checks["holder_distribution"] = "PASS"

    # 5. NAME CHECK - Scam keywords
    scam_keywords = ["test", "fake", "scam", "rug", "honeypot", "xxx", "pump"]
    if any(keyword in token_name for keyword in scam_keywords):
        safety_score -= 30
        rug_risk += 30
        checks["name_check"] = "FAIL - Suspicious name"
    else:
        checks["name_check"] = "PASS"

    # 6. FINAL HONEYPOT DETERMINATION
    if not is_honeypot:
        # Heuristic: Low liquidity + new + few holders = likely honeypot
        if liquidity_usd < 500 and age_minutes < 5 and checks.get("holder_count", 1000) < 50:
            is_honeypot = True
            safety_score = min(safety_score, 20)
            rug_risk = max(rug_risk, 80)
            if checks.get("honeypot_check") == "PASS":
                checks["honeypot_check"] = "FAIL - Likely honeypot (heuristic)"

    # Ensure bounds
    safety_score = max(0, min(100, safety_score))
    rug_risk = max(0, min(100, rug_risk))

    # Generate recommendation
    if safety_score >= 80:
        recommendation = "SAFE - Low risk, recommended for trading"
    elif safety_score >= 60:
        recommendation = "MODERATE - Some risks, trade with caution"
    elif safety_score >= 40:
        recommendation = "RISKY - High risk, not recommended"
    else:
        recommendation = "DANGEROUS - Very high risk, avoid trading"

    return SafetyCheckResult(
        safe=safety_score >= 60,
        safety_score=safety_score,
        rug_pull_risk=rug_risk,
        is_honeypot=is_honeypot,
        recommendation=recommendation,
        checks=checks,
        chain=chain,
        token_address=token_address,
        metadata=metadata,
        data_source=data_source
    )


def verify_x402_payment(payment_proof: Optional[str]) -> bool:
    """Verify x402 payment proof"""
    if FREE_MODE:
        return True

    if not payment_proof:
        return False

    return payment_proof.startswith("Bearer ")


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "token-safety-oracle",
        "version": "3.0.0",
        "free_mode": FREE_MODE,
        "supported_chains": len(SUPPORTED_CHAINS),
        "chain_ids": list(SUPPORTED_CHAINS.keys()),
        "features": {
            "live_data": True,
            "dexscreener": True,
            "goplus_security": True,
            "cache_ttl": CACHE_TTL
        }
    })


@app.route('/check', methods=['POST'])
def check_token_safety():
    """
    Check token safety with LIVE DATA

    Request body:
    {
        "token_address": "string",
        "chain": "solana|ethereum|base|arbitrum|polygon",
        "metadata": {
            "name": "string (optional)",
            "holder_count": int (optional, will use live data if available),
            "liquidity_usd": float (optional, will use live data if available),
            "age_minutes": float (optional, will use live data if available)
        }
    }
    """

    # Check x402 payment
    payment_proof = request.headers.get("Authorization")
    if not verify_x402_payment(payment_proof):
        return jsonify({
            "error": "Payment required",
            "message": "Valid x402 payment proof required",
            "price": X402_PRICE_PER_CHECK,
            "token": X402_PAYMENT_TOKEN
        }), 402

    # Parse request
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        token_address = data.get("token_address")
        chain = data.get("chain", "").lower()
        metadata = data.get("metadata", {})

        if not token_address:
            return jsonify({"error": "token_address is required"}), 400

        if chain not in SUPPORTED_CHAINS:
            return jsonify({
                "error": f"Unsupported chain: {chain}",
                "supported_chains": list(SUPPORTED_CHAINS.keys())
            }), 400

    except Exception as e:
        return jsonify({"error": f"Invalid request: {str(e)}"}), 400

    # Check cache
    cache_key = get_cache_key(chain, token_address)
    cached = get_from_cache(cache_key)
    if cached:
        cached["from_cache"] = True
        return jsonify(cached)

    # Fetch live data
    try:
        # Fetch from DexScreener
        dex_data = fetch_dexscreener_data(token_address)

        # Fetch from GoPlus (parallel would be better but sequential is fine)
        security_data = fetch_goplus_security(chain, token_address)

        # Analyze safety
        result = analyze_token_safety(chain, token_address, dex_data, security_data, metadata)

        response = {
            "safe": result.safe,
            "safety_score": result.safety_score,
            "rug_pull_risk": result.rug_pull_risk,
            "is_honeypot": result.is_honeypot,
            "recommendation": result.recommendation,
            "checks": result.checks,
            "chain": result.chain,
            "token_address": result.token_address,
            "data_source": result.data_source,
            "timestamp": time.time(),
            "from_cache": False,
            "x402": {
                "price": X402_PRICE_PER_CHECK,
                "token": X402_PAYMENT_TOKEN,
                "free_mode": FREE_MODE
            }
        }

        # Cache the result
        set_cache(cache_key, response)

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": f"Safety check failed: {str(e)}"}), 500


@app.route('/chains', methods=['GET'])
def get_supported_chains():
    """Get list of supported chains"""
    chains = []
    for chain_key, chain_info in SUPPORTED_CHAINS.items():
        chains.append({
            "key": chain_key,
            "name": chain_info["name"],
            "chain_id": chain_info["chain_id"]
        })
    return jsonify({"chains": chains})


@app.route('/', methods=['GET'])
def index():
    """API documentation"""
    return jsonify({
        "service": "x402 Token Safety Oracle",
        "version": "3.0.0",
        "description": "Multi-chain token safety analysis with LIVE DATA from DexScreener + GoPlusLabs",
        "endpoints": {
            "/health": "Health check",
            "/check": "Check token safety (POST) - Uses LIVE blockchain data",
            "/chains": "Get supported chains",
            "/": "This documentation"
        },
        "supported_chains": list(SUPPORTED_CHAINS.keys()),
        "features": {
            "live_data": "DexScreener for liquidity, volume, age",
            "security_analysis": "GoPlusLabs for honeypot detection, tax analysis",
            "caching": f"{CACHE_TTL}s TTL for faster responses"
        },
        "x402": {
            "enabled": not FREE_MODE,
            "price_per_check": X402_PRICE_PER_CHECK,
            "payment_token": X402_PAYMENT_TOKEN
        },
        "documentation": "https://github.com/DeganAI/token-safety-oracle"
    })


if __name__ == '__main__':
    print("=" * 60)
    print("🔒 X402 TOKEN SAFETY ORACLE v3.0")
    print("=" * 60)
    print(f"Version: 3.0.0 - LIVE DATA ENABLED")
    print(f"Free Mode: {FREE_MODE}")
    print(f"Data Sources: DexScreener + GoPlusLabs")
    print(f"Cache TTL: {CACHE_TTL}s")
    print(f"Supported chains: {', '.join(SUPPORTED_CHAINS.keys())}")
    print(f"Port: {PORT}")
    print("=" * 60)

    app.run(host='0.0.0.0', port=PORT, debug=False)
