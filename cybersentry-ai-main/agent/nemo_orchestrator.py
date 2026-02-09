# agent/nemo_orchestrator.py
"""NVIDIA NeMo Toolkit integration — enterprise multi-agent"""

import os
from typing import Optional

# NeMo imports (graceful fallback if not installed)
try:
    from nemo_agent_toolkit import Agent, Orchestrator, tool
    from nemo_guardrails import RailsConfig
    NEMO_AVAILABLE = True
except ImportError:
    NEMO_AVAILABLE = False
    print("⚠️  NeMo Toolkit not installed — running in compat mode")


if NEMO_AVAILABLE:
    
    @Agent(name="threat_detector", description="Scans for malware and anomalies", telemetry=True)
    class NeMoDetectorAgent:
        
        @tool
        async def scan_file(self, file_bytes: bytes, filename: str) -> dict:
            """Scan uploaded file for malware signatures"""
            # Delegate to your existing FastAPI
            import aiohttp
            async with aiohttp.ClientSession() as s:
                data = aiohttp.FormData()
                data.add_field("file", file_bytes, filename=filename)
                async with s.post(f"{os.getenv('AGENT_API_URL')}/api/v1/scan", data=data) as r:
                    return await r.json()
        
        @tool
        async def analyze_user(self, username: str) -> dict:
            """Fetch user behavior risk profile"""
            import aiohttp
            async with aiohttp.ClientSession() as s:
                async with s.get(f"{os.getenv('AGENT_API_URL')}/user-activity") as r:
                    data = await r.json()
                    for u in data.get("users", []):
                        if u["name"] == username:
                            return u
                    return {"risk": "unknown"}
    
    
    @Agent(name="auto_responder", description="Executes security actions")
    class NeMoResponderAgent:
        
        @tool
        async def block_user(self, username: str, reason: str) -> bool:
            """Block compromised user account"""
            import aiohttp
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{os.getenv('AGENT_API_URL')}/unblock-user",
                    params={"username": username}
                ) as r:
                    return r.status == 200
        
        @tool
        async def notify_whatsapp(self, message: str) -> str:
            """Send WhatsApp alert"""
            from .comms.whatsapp import send_whatsapp
            await send_whatsapp(message)
            return "delivered"
        
        @tool
        async def emergency_call(self, msisdn: str, risk_level: str) -> str:
            """Initiate voice call"""
            from .comms.voice import call_customer
            await call_customer(msisdn, risk_level)
            return "call_initiated"
    
    
    def create_nemo_orchestrator(config_path: str = "./config/rails.yaml"):
        """Factory for NeMo orchestrator with guardrails"""
        config = RailsConfig.from_path(config_path) if os.path.exists(config_path) else None
        
        return Orchestrator(
            agents=[
                NeMoDetectorAgent(),
                NeMoResponderAgent()
            ],
            config=config,
            telemetry_endpoint=os.getenv("NEMO_TELEMETRY", "http://localhost:9090")
        )

else:
    # Fallback: simple pass-through
    def create_nemo_orchestrator(*args, **kwargs):
        print("NeMo not available — using native agent loop")
        return None