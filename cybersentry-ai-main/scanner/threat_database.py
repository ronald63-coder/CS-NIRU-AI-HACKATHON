# scanner/threat_database.py
"""Threat database management"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

DB_PATH = Path("data/cybersentry.db")

def init_database():
    """Initialize SQLite database with schema"""
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                filename TEXT,
                verdict TEXT,
                risk_score INTEGER,
                threat_level TEXT,
                confidence REAL,
                detection_reasons TEXT,
                action_taken TEXT,
                resolved INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Agent logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agent_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT,
                message TEXT,
                threat_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (threat_id) REFERENCES threats(id)
            )
        ''')
        
        # User blocks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                reason TEXT,
                blocked_at TEXT NOT NULL,
                unblock_at TEXT,
                duration_hours INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indices for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_username ON threats(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_agents_severity ON agent_logs(severity)')
        
        conn.commit()
        conn.close()
        
        print(f"✅ Database initialized at {DB_PATH}")
        return True
    
    except Exception as e:
        print(f"❌ Database init error: {e}")
        return False

def log_threat_event(event_data: Dict[str, Any]) -> int:
    """Log threat event to database and return threat ID"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threats
            (timestamp, username, filename, verdict, risk_score, 
             threat_level, confidence, detection_reasons, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event_data.get('timestamp', datetime.now().isoformat()),
            event_data.get('username', 'unknown'),
            event_data.get('filename', 'unknown'),
            event_data.get('verdict', 'unknown'),
            int(event_data.get('risk_score', 0)),
            event_data.get('threat_level', 'low'),
            float(event_data.get('confidence', 0.0)),
            json.dumps(event_data.get('detection_reasons', [])),
            event_data.get('action_taken', 'PENDING')
        ))
        
        threat_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return threat_id
    
    except Exception as e:
        print(f"❌ Database error: {e}")
        return -1

def log_agent_action(threat_id: int, severity: str, message: str):
    """Log agent action"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO agent_logs (timestamp, severity, message, threat_id)
            VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            severity,
            message,
            threat_id
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ Agent log error: {e}")

def get_threat_history(limit: int = 100) -> List[Dict]:
    """Get recent threat history"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threats
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        threats = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return threats
    except Exception as e:
        print(f"❌ Query error: {e}")
        return []

def get_unresolved_threats() -> List[Dict]:
    """Get unresolved threats for human review"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threats
            WHERE resolved = 0 AND threat_level IN ('high', 'critical')
            ORDER BY timestamp DESC
        ''')
        
        threats = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return threats
    except Exception as e:
        print(f"❌ Query error: {e}")
        return []

def block_user(username: str, reason: str, duration_hours: int = 24) -> bool:
    """Block user"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        from datetime import timedelta
        unblock_at = (datetime.now() + timedelta(hours=duration_hours)).isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO user_blocks
            (username, reason, blocked_at, unblock_at, duration_hours)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            username,
            reason,
            datetime.now().isoformat(),
            unblock_at,
            duration_hours
        ))
        
        conn.commit()
        conn.close()
        
        return True
    except Exception as e:
        print(f"❌ Block error: {e}")
        return False

def is_user_blocked(username: str) -> bool:
    """Check if user is blocked"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 1 FROM user_blocks
            WHERE username = ? AND unblock_at > datetime('now')
        ''', (username,))
        
        result = cursor.fetchone() is not None
        conn.close()
        return result
    except Exception as e:
        print(f"❌ Query error: {e}")
        return False

def unblock_user(username: str) -> bool:
    """Unblock user"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM user_blocks WHERE username = ?', (username,))
        
        conn.commit()
        conn.close()
        
        return True
    except Exception as e:
        print(f"❌ Unblock error: {e}")
        return False