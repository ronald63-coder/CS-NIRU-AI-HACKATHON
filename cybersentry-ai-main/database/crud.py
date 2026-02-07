import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path("cybersentry.db")

def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Threats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT,
            threat_level TEXT,
            file_name TEXT,
            verdict TEXT,
            confidence REAL,
            risk_score INTEGER,
            details TEXT,
            action_taken TEXT
        )
    ''')
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            risk_profile TEXT,
            last_login TEXT,
            login_count INTEGER DEFAULT 0,
            blocked INTEGER DEFAULT 0
        )
    ''')
    
    # System logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            severity TEXT,
            message TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"✅ Database initialized at {DB_PATH}")

def log_threat(threat_data: dict):
    """Log a threat to database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO threats 
        (timestamp, username, threat_level, file_name, verdict, confidence, risk_score, details, action_taken)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        threat_data.get('timestamp', datetime.now().isoformat()),
        threat_data.get('username'),
        threat_data.get('threat_level', 'medium'),
        threat_data.get('file_name'),
        threat_data.get('verdict'),
        threat_data.get('confidence', 0.0),
        threat_data.get('risk_score', 0),
        json.dumps(threat_data.get('details', {})),
        threat_data.get('action_taken', 'detected')
    ))
    
    conn.commit()
    conn.close()
    
    # Also log to system logs
    log_system_event(
        event_type="THREAT_DETECTED",
        severity=threat_data.get('threat_level', 'medium'),
        message=f"Threat detected for {threat_data.get('username')} - {threat_data.get('verdict')}"
    )

def get_threats(limit: int = 50):
    """Get recent threats"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM threats 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    # Convert to dict
    threats = []
    for row in rows:
        threat = dict(row)
        # Parse JSON details
        if threat['details']:
            try:
                threat['details'] = json.loads(threat['details'])
            except:
                pass
        threats.append(threat)
    
    return threats

def log_system_event(event_type: str, severity: str, message: str):
    """Log system event"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO system_logs (timestamp, event_type, severity, message)
        VALUES (?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(),
        event_type,
        severity,
        message
    ))
    
    conn.commit()
    conn.close()