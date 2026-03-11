#!/usr/bin/env python3
"""
Netguardian-Agent — One-click starter
=====================================
Usage:  python run_agent.py
Requires: .agent.env with secrets
"""

import os
import sys
import asyncio
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Load environment
env_path = Path(__file__).parent / ".agent.env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and '=' in line and not line.startswith('#'):
                key, val = line.strip().split('=', 1)
                os.environ[key.strip()] = val.strip()
                env_loaded = True

    if env_loaded:
            print("✅ Environment loaded from .agent.env")
else:
    print("❌  .agent.env not found. Copy from .agent.env.template")
    

# Start agent
try:
    from agent.agent_main import main
    print("✅ Agent modules loaded successfully")
except ImportError as e:
    print(f"❌ Failed to import agent modules: {e}")
    print("\nMake sure you have the required dependencies installed:")
    print("pip install aiohttp rich python-dotenv twilio")
    sys.exit(1)
if __name__ == "__main__":
    try:
        print("🛡️  Netguardian-Agent starting...")
        print(f"   API: {os.getenv('AGENT_API_URL', 'http://localhost:8000')}")
        print(f"   Poll: {os.getenv('POLL_INTERVAL', '10')}s")
        print("   Press Ctrl+C to stop\n")
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user")
        sys.exit(1)