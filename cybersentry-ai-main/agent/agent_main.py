# agent/agent_main.py
"""Async agent loop — polls threats and orchestrates response"""

import asyncio
import aiohttp
import os
from datetime import datetime
from typing import Dict, Any

from .decisions import decide
from .comms.whatsapp import send_whatsapp
from .comms.voice import call_customer
from .utils import console, SeenCache

API_URL = os.getenv("AGENT_API_URL", "http://localhost:8000")
INTERVAL = int(os.getenv("POLL_INTERVAL", "10"))

seen = SeenCache()


async def poll_threats(session: aiohttp.ClientSession) -> list:
    """Fetch new threats from backend"""
    try:
        async with session.get(f"{API_URL}/threat-history") as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("threat_history", [])
            return []
    except Exception as e:
        console(f"[red]API error: {e}[/red]")
        return []


async def handle_threat(threat: Dict[str, Any], session: aiohttp.ClientSession):
    """Process single threat through decision engine"""
    tid = threat.get("id") or f"{threat.get('timestamp')}_{threat.get('username')}"
    
    if seen.already(tid):
        return
    
    seen.add(tid)
    console(f"[cyan]New threat: {threat.get('username')} | {threat.get('threat_level')}[/cyan]")
    
    # Decision
    action, reason = await decide(threat, session)
    
    # Notify
    await notify_human(threat, action, reason)
    
    # Log
    console(f"[green]Action: {action} | {reason}[/green]")


async def notify_human(threat: Dict[str, Any], action: str, reason: str):
    """Send WhatsApp + voice alert"""
    username = threat.get("username", "unknown")
    level = threat.get("threat_level", "unknown")
    conf = threat.get("confidence", 0.0)
    
    # WhatsApp message
    msg = (
        f"🛡️ *CyberSentry Agent Alert*\n\n"
        f"User: *{username}*\n"
        f"Threat: *{level.upper()}*\n"
        f"Confidence: *{conf:.1%}*\n"
        f"Action: *{action}*\n\n"
        f"Reply *YES* to unblock, *NO* to keep blocked."
    )
    
    try:
        await send_whatsapp(msg)
    except Exception as e:
        console(f"[yellow]WhatsApp failed: {e}[/yellow]")
    
    # Voice call for critical
    if level == "critical" and conf > 0.85:
        try:
            msisdn = threat.get("msisdn") or os.getenv("TWILIO_TO")
            if msisdn:
                await call_customer(msisdn, level)
        except Exception as e:
            console(f"[yellow]Voice call failed: {e}[/yellow]")


async def main():
    """Main agent loop"""
    console("[bold green]🛡️ CyberSentry-Agent started[/bold green]")
    console(f"[dim]Monitoring {API_URL} every {INTERVAL}s[/dim]\n")
    
    async with aiohttp.ClientSession() as session:
        while True:
            threats = await poll_threats(session)
            
            for threat in threats:
                await handle_threat(threat, session)
            
            await asyncio.sleep(INTERVAL)