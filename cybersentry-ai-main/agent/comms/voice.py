# agent/comms/voice.py
"""Twilio voice calls with Swahili/English support"""

import os
from typing import Optional

try:
    from twilio.rest import Client
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False


async def call_customer(msisdn: str, risk_level: str, language: Optional[str] = None) -> str:
    """
    Initiate voice call with appropriate message
    language: 'sw' (Swahili), 'en' (English), or auto from env
    """
    if not TWILIO_AVAILABLE:
        print(f"[Voice MOCK] Would call {msisdn} about {risk_level}")
        return "mock_call"
    
    # Auto-detect language
    lang = language or os.getenv("DEFAULT_LANG", "en")
    
    # Message templates
    messages = {
        "sw": {
            "critical": (
                "Habari. Hapa CyberSentry. Tuna tishio kubwa la usalama kwenye akaunti yako. "
                "Tafadhali thibitisha ikiwa wewe ndiye unafanya mabadiliko. "
                "Bonyeza moja kwa ndiyo, mbili kwa hapana."
            ),
            "high": (
                "Habari kutoka CyberSentry. Tumegundua shughuli isiyo ya kawaida. "
                "Tafadhali angalia ujumbe wako wa WhatsApp."
            )
        },
        "en": {
            "critical": (
                "Hello. This is CyberSentry security. We have detected critical suspicious activity "
                "on your account. Please confirm if this is you. Press one for yes, two for no."
            ),
            "high": (
                "Hello from CyberSentry. We detected unusual activity. "
                "Please check your WhatsApp message."
            )
        }
    }
    
    msg = messages.get(lang, messages["en"]).get(risk_level, messages["en"]["high"])
    
    # Build TwiML
    twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <Response>
        <Say language="{lang}" voice="woman">{msg}</Say>
        <Gather numDigits="1" action="/voice_response" method="POST"/>
    </Response>"""
    
    # Make call
    client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))
    
    call = client.calls.create(
        twiml=twiml,
        to=f"+{msisdn}" if not msisdn.startswith("+") else msisdn,
        from_=os.getenv("TWILIO_VOICE_FROM", os.getenv("TWILIO_FROM"))
    )
    
    return call.sid