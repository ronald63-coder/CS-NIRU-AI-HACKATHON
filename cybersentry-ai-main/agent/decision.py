# agent/decision.py
"""Policy engine — decides block/ask/monitor"""

import os
import aiohttp
from typing import Tuple
from datetime import datetime

API_URL = os.getenv("AGENT_API_URL", "http://localhost:8000")

async def decide(threat: dict, session: aiohttp.ClientSession) -> Tuple[str, str]:
    """
    Returns: (action, reason)
    Valid actions: AUTO-BLOCKED, AWAITING-HUMAN, MONITORED, IGNORED
    """
    level = threat.get("threat_level", "low")
    verdict = threat.get("verdict", "unknown")
    risk_score = threat.get("risk_score", 0)
    conf = threat.get("confidence", 0.0)
    username = threat.get("username", "unknown")
    
    # Convert to float if string
    if isinstance(conf, str):
        try:
            conf = float(conf)
        except:
            conf = 0.0
    
    # Convert risk_score to int if string
    if isinstance(risk_score, str):
        try:
            risk_score = int(risk_score)
        except:
            risk_score = 0
    
    print(f"🔍 Decision input - Level: {level}, Verdict: {verdict}, Risk: {risk_score}, Conf: {conf:.2f}")
    
    # POLICY 1: Critical + high confidence = auto-block
    if level == "critical" and conf > 0.7:
        success = await execute_block(username, session)
        if success:
            return "AUTO-BLOCKED", f"Critical threat with {conf:.0%} confidence"
        else:
            return "MONITORED", "Block attempt failed, escalating to monitoring"
    
    # POLICY 2: High threat = auto-block
    if level == "high":
        success = await execute_block(username, session)
        if success:
            return "AUTO-BLOCKED", f"High threat detected"
        else:
            return "MONITORED", "Block attempt failed, monitoring"
    
    # POLICY 3: Medium threat + good confidence = ask human
    if level == "medium" and conf > 0.5:
        return "AWAITING-HUMAN", f"Medium risk ({conf:.0%}), needs human review"
    
    # POLICY 4: Medium threat + low confidence = monitor
    if level == "medium":
        return "MONITORED", f"Medium risk ({conf:.0%}), low confidence"
    
    # POLICY 5: Low risk + high confidence = ignore
    if level == "low" and conf > 0.8:
        return "IGNORED", f"Low risk ({conf:.0%}), safe to pass"
    
    # POLICY 6: Low risk + low confidence = monitor
    if level == "low":
        return "MONITORED", f"Low risk ({conf:.0%}), monitoring"
    
    # Default
    return "MONITORED", f"Default action for {level} risk"

async def execute_block(username: str, session: aiohttp.ClientSession) -> bool:
    """Call backend to block user"""
    try:
        async with session.post(
            f"{API_URL}/block-user",
            params={"username": username, "reason": "Auto-blocked by agent"},
            timeout=5
        ) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"Block failed: {e}")
        return False

def simswap_risk(event: dict) -> float:
    """Calculate SIM-swap risk score (0-1)"""
    score = 0.0
    
    # Time check
    try:
        hour = datetime.fromisoformat(event.get("timestamp", "2024-01-01T12:00:00")).hour
        if hour < 5 or hour > 22:
            score += 0.30
    except:
        pass
    
    # Location anomaly
    shop = event.get("shop_code", "")
    if "KIS" in shop or "MOM" in shop:
        score += 0.25
    
    # Velocity (multiple swaps)
    if event.get("swap_count", 0) > 1:
        score += 0.35
    
    return min(score, 1.0)