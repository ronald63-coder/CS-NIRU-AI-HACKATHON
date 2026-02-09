# agent/decisions.py
"""Policy engine — decides block/ask/monitor"""

import os
import aiohttp
from typing import Tuple
from datetime import datetime

API_URL = os.getenv("AGENT_API_URL", "http://localhost:8000")


async def decide(threat: dict, session: aiohttp.ClientSession) -> Tuple[str, str]:
    """
    Returns: (action, reason)
    Actions: AUTO-BLOCK, AWAIT-HUMAN, MONITOR
    """
    level = threat.get("threat_level", "low")
    conf = threat.get("confidence", 0.0)
    username = threat.get("username", "unknown")
    
    # POLICY 1: Critical + high confidence = auto-block
    if level == "critical" and conf > 0.85:
        success = await execute_block(username, session)
        if success:
            return "AUTO-BLOCKED", f"Critical threat with {conf:.1%} confidence"
        return "BLOCK-FAILED", "API error during block"
    
    # POLICY 2: High/medium + decent confidence = ask human
    if level in ("high", "medium") and conf > 0.6:
        return "AWAITING-HUMAN", f"{level} risk, human verification required"
    
    # POLICY 3: Low risk = monitor only
    return "MONITORED", f"Low risk ({conf:.1%}), no action needed"


async def execute_block(username: str, session: aiohttp.ClientSession) -> bool:
    """Call backend to block user"""
    try:
        async with session.post(
            f"{API_URL}/unblock-user",  # or /block-user if you create it
            params={"username": username}
        ) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"Block failed: {e}")
        return False


def simswap_risk(event: dict) -> float:
    """Calculate SIM-swap risk score (0-1)"""
    score = 0.0
    
    # Time check
    hour = datetime.fromisoformat(event.get("timestamp", "2024-01-01T12:00:00")).hour
    if hour < 5 or hour > 22:
        score += 0.30
    
    # Location anomaly
    shop = event.get("shop_code", "")
    if "KIS" in shop or "MOM" in shop:  # Kisumu, Mombasa vs Nairobi norm
        score += 0.25
    
    # Velocity (multiple swaps)
    if event.get("swap_count", 0) > 1:
        score += 0.35
    
    return min(score, 1.0)