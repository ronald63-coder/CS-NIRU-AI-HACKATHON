from datetime import datetime, timedelta
from typing import Set, Dict, Any

class AutoBlocker:
    """Automatically block users based on threat level"""
    
    def __init__(self):
        self.blocked_users: Set[str] = set()
        self.block_history: Dict[str, Dict] = {}
    
    def block_user(self, username: str, reason: str, duration_hours: int = 24) -> Dict[str, Any]:
        """Block a user"""
        unblock_time = datetime.now() + timedelta(hours=duration_hours)
        
        block_record = {
            "username": username,
            "reason": reason,
            "blocked_at": datetime.now().isoformat(),
            "unblock_at": unblock_time.isoformat(),
            "duration_hours": duration_hours
        }
        
        self.blocked_users.add(username)
        self.block_history[username] = block_record
        
        print(f"🚨 USER BLOCKED: {username}")
        print(f"   Reason: {reason}")
        print(f"   Unblock at: {unblock_time}")
        
        return block_record
    
    def unblock_user(self, username: str) -> bool:
        """Unblock a user"""
        if username in self.blocked_users:
            self.blocked_users.remove(username)
            print(f"✅ USER UNBLOCKED: {username}")
            return True
        return False
    
    def is_blocked(self, username: str) -> bool:
        """Check if user is blocked"""
        return username in self.blocked_users
    
    def get_blocked_users(self) -> list:
        """Get list of blocked users"""
        return list(self.blocked_users)