#!/usr/bin/env python3
"""
CyberSentry-Agent — One-click starter
=====================================
Usage:  python run_agent.py
Requires: .agent.env with secrets
"""

import os
import sys
import asyncio
from pathlib import Path

# Load environment
env_path = Path(__file__).parent / ".agent.env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, val = line.strip().split('=', 1)
                os.environ[key] = val
else:
    print("❌  .agent.env not found. Copy from .agent.env.template")
    sys.exit(1)

# Start agent
from agent.agent_main import main

if __name__ == "__main__":
    try:
        print("🛡️  CyberSentry-Agent starting...")
        print(f"   API: {os.getenv('AGENT_API_URL', 'http://localhost:8000')}")
        print(f"   Poll: {os.getenv('POLL_INTERVAL', '10')}s")
        print("   Press Ctrl+C to stop\n")
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user")