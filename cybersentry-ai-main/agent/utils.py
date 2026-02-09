# agent/utils.py
"""Shared utilities"""

from datetime import datetime
from typing import Set


class SeenCache:
    """Deduplicate processed threats"""
    
    def __init__(self, max_size: int = 10000):
        self.cache: Set[str] = set()
        self.max_size = max_size
    
    def already(self, tid: str) -> bool:
        return tid in self.cache
    
    def add(self, tid: str):
        self.cache.add(tid)
        # Prevent unbounded growth
        if len(self.cache) > self.max_size:
            # Clear oldest 20% (simplistic)
            self.cache = set(list(self.cache)[int(self.max_size * 0.2):])


def console(message: str):
    """Rich console output with fallback"""
    try:
        from rich.console import Console
        Console().print(message)
    except ImportError:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")


def generate_hash(data: dict) -> str:
    """Create simple content hash for audit trail"""
    import hashlib
    import json
    content = json.dumps(data, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]