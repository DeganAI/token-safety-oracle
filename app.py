#!/usr/bin/env python3
"""
X402 Token Safety Oracle
Multi-chain token safety analysis API with x402 micropayment support
Supports: Solana, Ethereum, Base, Arbitrum, Polygon
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time
import hashlib
import requests
from typing import Dict, Any, Optional
from dataclasses import dataclass
import json

app = Flask(__name__)
CORS(app)

# Configuration
X402_PRICE_PER_CHECK = float(os.getenv("X402_PRICE_PER_CHECK", "0.01"))
X402_PAYMENT_TOKEN = os.getenv("X402_PAYMENT_TOKEN", "USDC")
# Private API for internal bots - always free mode
FREE_MODE = True
PORT = int(os.getenv("PORT", "8000"))

# Chain configurations
SUPPORTED_CHAINS = {
    "solana": {
        "chain_id": "solana-mainnet",
        "name": "Solana",
        "rpc_url": os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"),
    },
    "ethereum": {
        "chain_id": 1,
        "name": "Ethereum",
        "rpc_url": os.getenv("ETH_RPC_URL", "https://eth.llamarpc.com"),
    },
    "base": {
        "chain_id": 8453,
        "name": "Base",
        "rpc_url": os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
    },
    "arbitrum": {
        "chain_id": 42161,
        "name": "Arbitrum",
        "rpc_url": os.getenv("ARB_RPC_URL", "https://arb1.arbitrum.io/rpc"),
    },
    "polygon": {
        "chain_id": 137,
        "name": "Polygon",
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


def verify_x402_payment(payment_proof: Optional[str]) -> bool:
    """Verify x402 payment proof"""
    if FREE_MODE:
        return True

    if not payment_proof:
        return False

    # TODO: Implement actual x402 payment verification
    # For now, accept any proof in free mode
    return payment_proof.startswith("Bearer ")


def check_solana_token(token_address: str, pool_address: str, metadata: Dict[str, Any]) -> SafetyCheckResult:
    """
    Check Solana token safety
    Uses heuristics based on metadata and on-chain data
    """
    checks = {}
    safety_score = 100
    rug_risk = 0

    # Check holder count
    holder_count = metadata.get("holder_count", 0)
    checks["holder_count"] = holder_count
    if holder_count < 100:
        safety_score -= 20
        rug_risk += 20
        checks["holder_distribution"] = "FAIL - Too few holders"
    else:
        checks["holder_distribution"] = "PASS"

    # Check liquidity
    liquidity_usd = metadata.get("liquidity_usd", 0)
    checks["liquidity_usd"] = liquidity_usd
    if liquidity_usd < 10000:
        safety_score -= 15
        rug_risk += 15
        checks["liquidity_check"] = "FAIL - Low liquidity"
    else:
        checks["liquidity_check"] = "PASS"

    # Check token age
    age_minutes = metadata.get("age_minutes", 0)
    checks["age_minutes"] = age_minutes
    if age_minutes < 2:
        safety_score -= 25
        rug_risk += 25
        checks["age_check"] = "FAIL - Very new token (high risk)"
    elif age_minutes < 30:
        safety_score -= 10
        rug_risk += 10
        checks["age_check"] = "WARNING - New token"
    else:
        checks["age_check"] = "PASS"

    # Check for known scam patterns
    token_name = metadata.get("name", "").lower()
    checks["token_name"] = token_name

    scam_keywords = ["test", "fake", "scam", "rug", "honeypot", "xxx"]
    if any(keyword in token_name for keyword in scam_keywords):
        safety_score -= 30
        rug_risk += 30
        checks["name_check"] = "FAIL - Suspicious name"
    else:
        checks["name_check"] = "PASS"

    # Determine if likely honeypot
    is_honeypot = rug_risk > 50 and holder_count < 50
    if is_honeypot:
        safety_score = min(safety_score, 30)
        rug_risk = max(rug_risk, 70)
        checks["honeypot_check"] = "FAIL - Likely honeypot"
    else:
        checks["honeypot_check"] = "PASS"

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
        chain="solana",
        token_address=token_address,
        metadata=metadata
    )


def check_evm_token(chain: str, token_address: str, pool_address: str, metadata: Dict[str, Any]) -> SafetyCheckResult:
    """
    Check EVM-based token safety (Ethereum, Base, Arbitrum, Polygon)
    Uses similar heuristics adapted for EVM chains
    """
    checks = {}
    safety_score = 100
    rug_risk = 0

    # Check holder count
    holder_count = metadata.get("holder_count", 0)
    checks["holder_count"] = holder_count
    if holder_count < 100:
        safety_score -= 20
        rug_risk += 20
        checks["holder_distribution"] = "FAIL - Too few holders"
    else:
        checks["holder_distribution"] = "PASS"

    # Check liquidity
    liquidity_usd = metadata.get("liquidity_usd", 0)
    checks["liquidity_usd"] = liquidity_usd
    if liquidity_usd < 10000:
        safety_score -= 15
        rug_risk += 15
        checks["liquidity_check"] = "FAIL - Low liquidity"
    else:
        checks["liquidity_check"] = "PASS"

    # Check token age
    age_minutes = metadata.get("age_minutes", 0)
    checks["age_minutes"] = age_minutes
    if age_minutes < 2:
        safety_score -= 25
        rug_risk += 25
        checks["age_check"] = "FAIL - Very new token (high risk)"
    elif age_minutes < 30:
        safety_score -= 10
        rug_risk += 10
        checks["age_check"] = "WARNING - New token"
    else:
        checks["age_check"] = "PASS"

    # Check contract verification
    is_verified = metadata.get("is_verified", False)
    checks["contract_verified"] = is_verified
    if not is_verified:
        safety_score -= 15
        rug_risk += 15
        checks["verification_check"] = "FAIL - Contract not verified"
    else:
        checks["verification_check"] = "PASS"

    # Check for mint/burn functions
    has_mint = metadata.get("has_mint_function", False)
    has_burn = metadata.get("has_burn_function", False)
    checks["has_mint_function"] = has_mint
    checks["has_burn_function"] = has_burn

    if has_mint:
        safety_score -= 10
        rug_risk += 10
        checks["mint_check"] = "WARNING - Mint function exists"
    else:
        checks["mint_check"] = "PASS"

    # Check for owner renounced
    owner_renounced = metadata.get("owner_renounced", False)
    checks["owner_renounced"] = owner_renounced
    if not owner_renounced:
        safety_score -= 5
        rug_risk += 5
        checks["ownership_check"] = "WARNING - Ownership not renounced"
    else:
        checks["ownership_check"] = "PASS"

    # Check for known scam patterns
    token_name = metadata.get("name", "").lower()
    checks["token_name"] = token_name

    scam_keywords = ["test", "fake", "scam", "rug", "honeypot", "xxx"]
    if any(keyword in token_name for keyword in scam_keywords):
        safety_score -= 30
        rug_risk += 30
        checks["name_check"] = "FAIL - Suspicious name"
    else:
        checks["name_check"] = "PASS"

    # Determine if likely honeypot
    is_honeypot = rug_risk > 50 and holder_count < 50
    if is_honeypot:
        safety_score = min(safety_score, 30)
        rug_risk = max(rug_risk, 70)
        checks["honeypot_check"] = "FAIL - Likely honeypot"
    else:
        checks["honeypot_check"] = "PASS"

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
        metadata=metadata
    )


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "token-safety-oracle",
        "version": "2.0.0",
        "free_mode": FREE_MODE,
        "supported_chains": len(SUPPORTED_CHAINS),
        "chain_ids": list(SUPPORTED_CHAINS.keys())
    })


@app.route('/check', methods=['POST'])
def check_token_safety():
    """
    Check token safety

    Request body:
    {
        "token_address": "string",
        "chain": "solana|ethereum|base|arbitrum|polygon",
        "pool_address": "string (optional)",
        "dex": "string (optional)",
        "metadata": {
            "holder_count": int,
            "liquidity_usd": float,
            "age_minutes": float,
            "name": string (optional),
            "is_verified": bool (optional, EVM only),
            "has_mint_function": bool (optional, EVM only),
            "has_burn_function": bool (optional, EVM only),
            "owner_renounced": bool (optional, EVM only)
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
        pool_address = data.get("pool_address", "")
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

    # Perform safety check
    try:
        if chain == "solana":
            result = check_solana_token(token_address, pool_address, metadata)
        else:
            result = check_evm_token(chain, token_address, pool_address, metadata)

        return jsonify({
            "safe": result.safe,
            "safety_score": result.safety_score,
            "rug_pull_risk": result.rug_pull_risk,
            "is_honeypot": result.is_honeypot,
            "recommendation": result.recommendation,
            "checks": result.checks,
            "chain": result.chain,
            "token_address": result.token_address,
            "timestamp": time.time(),
            "x402": {
                "price": X402_PRICE_PER_CHECK,
                "token": X402_PAYMENT_TOKEN,
                "free_mode": FREE_MODE
            }
        })

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
        "version": "2.0.0",
        "description": "Multi-chain token safety analysis with x402 micropayment support",
        "endpoints": {
            "/health": "Health check",
            "/check": "Check token safety (POST)",
            "/chains": "Get supported chains",
            "/": "This documentation"
        },
        "supported_chains": list(SUPPORTED_CHAINS.keys()),
        "x402": {
            "enabled": not FREE_MODE,
            "price_per_check": X402_PRICE_PER_CHECK,
            "payment_token": X402_PAYMENT_TOKEN
        },
        "documentation": "https://github.com/DeganAI/token-safety-oracle"
    })


if __name__ == '__main__':
    print("=" * 60)
    print("🔒 X402 TOKEN SAFETY ORACLE")
    print("=" * 60)
    print(f"Version: 2.0.0")
    print(f"Free Mode: {FREE_MODE}")
    print(f"Price per check: {X402_PRICE_PER_CHECK} {X402_PAYMENT_TOKEN}")
    print(f"Supported chains: {', '.join(SUPPORTED_CHAINS.keys())}")
    print(f"Port: {PORT}")
    print("=" * 60)

    app.run(host='0.0.0.0', port=PORT, debug=False)
