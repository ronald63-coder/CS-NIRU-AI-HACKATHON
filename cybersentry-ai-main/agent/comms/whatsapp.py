# agent/comms/whatsapp.py
"""Twilio WhatsApp integration"""

import os
from typing import Optional

# Try async Twilio
try:
    from twilio.rest import Client
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False


async def send_whatsapp(body: str, to: Optional[str] = None) -> str:
    """
    Send WhatsApp message via Twilio
    Requires: TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM in env
    """
    if not TWILIO_AVAILABLE:
        print(f"[WhatsApp MOCK] Would send: {body[:80]}...")
        return "mock_sent"
    
    sid = os.getenv("TWILIO_SID")
    token = os.getenv("TWILIO_TOKEN")
    from_num = os.getenv("TWILIO_FROM")
    to_num = to or os.getenv("TWILIO_TO")
    
    if not all([sid, token, from_num, to_num]):
        raise ValueError("Missing Twilio credentials")
    
    client = Client(sid, token)
    
    message = client.messages.create(
        body=body,
        from_=from_num,
        to=to_num
    )
    
    return message.sid


def format_swahili_alert(username: str, threat: str, action: str) -> str:
    """Generate Swahili notification"""
    return (
        f"🛡️ *CyberSentry*\n\n"
        f"Habari, tumegundua tishio la usalama.\n"
        f"Mtumiaji: *{username}*\n"
        f"Tishio: *{threat}*\n"
        f"Hatua: *{action}*\n\n"
        f"Jibu *NDIYO* ikiwa ni wewe, au *HAPANA* kama sio wewe."
    )