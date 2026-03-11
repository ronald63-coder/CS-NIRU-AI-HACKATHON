# agent/agent_main.py
"""Async agent loop — polls threats and orchestrates response"""

import asyncio
import aiohttp
import os
from datetime import datetime
from typing import Dict, Any

from agent.decision import decide
from agent.comms.whatsapp import send_whatsapp
from agent.comms.voice import call_customer
from agent.utils import console, SeenCache

API_URL = os.getenv("AGENT_API_URL", "http://localhost:8000")
INTERVAL = int(os.getenv("POLL_INTERVAL", "10"))

seen = SeenCache()


async def poll_threats(session: aiohttp.ClientSession) -> list:
    """Fetch new threats from backend"""
    try:
        async with session.get(f"{API_URL}/threat-history") as resp:
            if resp.status == 200:
                data = await resp.json()
                threats = data.get("threat_history", [])
                console(f"[dim]Fetched {len(threats)} threats from API[/dim]")
                return threats
            return []
    except Exception as e:
        console(f"[red]API error: {e}[/red]")
        return []


async def handle_threat(threat: Dict[str, Any], session: aiohttp.ClientSession):
    """Process single threat through decision engine"""
    # Create a unique ID for this threat
    tid = threat.get("id") or f"{threat.get('timestamp')}_{threat.get('username')}_{threat.get('filename', 'unknown')}"
    
    if seen.already(tid):
        return
    
    threat_level = threat.get("threat_level", "low")
    username = threat.get("username", "unknown")
    verdict = threat.get("verdict", "unknown")
    risk_score = threat.get("risk_score", 0)
    
    seen.add(tid)
    console(f"[cyan]New threat: {username} | {threat_level.upper()} | {verdict} | Risk: {risk_score}[/cyan]")
    
    # Decision
    action, reason = await decide(threat, session)
    
    # Notify based on action
    if action in ["AUTO-BLOCKED", "AWAITING-HUMAN"]:
        await notify_human(threat, action, reason)
    
    # Log
    action_colors = {
        "AUTO-BLOCKED": "red",
        "AWAITING-HUMAN": "yellow",
        "MONITORED": "blue",
        "IGNORED": "dim"
    }
    color = action_colors.get(action, "green")
    console(f"[{color}]Action: {action} | {reason}[/{color}]")


async def notify_human(threat: Dict[str, Any], action: str, reason: str):
    """Send WhatsApp + voice alert"""
    username = threat.get("username", "unknown")
    level = threat.get("threat_level", "unknown")
    conf = threat.get("confidence", 0.0)
    verdict = threat.get("verdict", "unknown")
    risk_score = threat.get("risk_score", 0)
    
    # WhatsApp message
    msg = (
        f"🚨 *CyberSentry Security Alert*\n\n"
        f"👤 User: *{username}*\n"
        f"⚠️ Threat Level: *{level.upper()}*\n"
        f"🔍 Verdict: *{verdict.replace('_', ' ').upper()}*\n"
        f"📊 Risk Score: *{risk_score}/100*\n"
        f"🎯 Action: *{action}*\n\n"
        f"📝 Reason: {reason}\n\n"
        f"Reply *YES* to unblock, *NO* to keep blocked."
    )
    
    try:
        await send_whatsapp(msg)
        console(f"[green]WhatsApp alert sent for {username}[/green]")
    except Exception as e:
        console(f"[yellow]WhatsApp failed: {e}[/yellow]")
    
    # Voice call for critical/blocked
    if level in ["critical", "high"] or action == "AUTO-BLOCKED":
        try:
            msisdn = threat.get("msisdn") or os.getenv("TWILIO_TO")
            if msisdn:
                # Remove whatsapp: prefix if present
                if msisdn.startswith("whatsapp:"):
                    msisdn = msisdn.replace("whatsapp:", "")
                await call_customer(msisdn, level)
                console(f"[green]Voice call initiated for {username}[/green]")
        except Exception as e:
            console(f"[yellow]Voice call failed: {e}[/yellow]")


async def main():
    """Main agent loop"""
    console("[bold green]🛡️ CyberSentry-Agent started[/bold green]")
    console(f"[dim]Monitoring {API_URL} every {INTERVAL}s[/dim]\n")
    
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                threats = await poll_threats(session)
                
                for threat in threats:
                    await handle_threat(threat, session)
                
                await asyncio.sleep(INTERVAL)
            except KeyboardInterrupt:
                break
            except Exception as e:
                console(f"[red]Error in main loop: {e}[/red]")
                await asyncio.sleep(INTERVAL)