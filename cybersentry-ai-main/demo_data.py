# demo_data.py
"""Create demo threat data for dashboard showcase"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path("data/cybersentry.db")

def create_demo_threats():
    """Pre-populate database with demo threats"""
    
    demo_threats = [
        {
            "username": "demo_attacker",
            "filename": "malware.exe",
            "verdict": "malicious",
            "risk_score": 92,
            "threat_level": "critical",
            "confidence": 0.98,
            "detection_reasons": "YARA match: Trojan.Emotet, High entropy, Suspicious imports",
            "action_taken": "AUTO-BLOCKED"
        },
        {
            "username": "suspicious_user",
            "filename": "invoice_2024.pdf",
            "verdict": "suspicious",
            "risk_score": 65,
            "threat_level": "high",
            "confidence": 0.72,
            "detection_reasons": "Embedded macro detected, Obfuscated code found",
            "action_taken": "AUTO-BLOCKED"
        },
        {
            "username": "normal_user",
            "filename": "document.docx",
            "verdict": "benign",
            "risk_score": 15,
            "threat_level": "low",
            "confidence": 0.95,
            "detection_reasons": "Standard Office format, No suspicious patterns detected",
            "action_taken": "IGNORED"
        },
        {
            "username": "bob_wilson",
            "filename": "config.exe",
            "verdict": "suspicious",
            "risk_score": 58,
            "threat_level": "medium",
            "confidence": 0.65,
            "detection_reasons": "Packed binary detected, Zero imports (suspicious)",
            "action_taken": "AWAITING-HUMAN"
        },
        {
            "username": "ronny_ogeya",
            "filename": "setup.msi",
            "verdict": "malicious",
            "risk_score": 88,
            "threat_level": "critical",
            "confidence": 0.91,
            "detection_reasons": "VirusTotal: 23 vendors flag as malware, YARA: Trojan.Emotet",
            "action_taken": "AUTO-BLOCKED"
        },
        {
            "username": "purity_kerubo",
            "filename": "report.xlsx",
            "verdict": "benign",
            "risk_score": 8,
            "threat_level": "low",
            "confidence": 0.98,
            "detection_reasons": "Standard spreadsheet, No threats detected",
            "action_taken": "IGNORED"
        },
        {
            "username": "brightone_omondi",
            "filename": "update.zip",
            "verdict": "suspicious",
            "risk_score": 72,
            "threat_level": "high",
            "confidence": 0.80,
            "detection_reasons": "Password-protected archive, Multiple executables inside",
            "action_taken": "AUTO-BLOCKED"
        }
    ]
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        for i, threat in enumerate(demo_threats):
            # Create with different timestamps (most recent first)
            timestamp = (datetime.now() - timedelta(hours=i)).isoformat()
            
            cursor.execute('''
                INSERT INTO threats
                (timestamp, username, filename, verdict, risk_score, 
                 threat_level, confidence, detection_reasons, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                threat['username'],
                threat['filename'],
                threat['verdict'],
                threat['risk_score'],
                threat['threat_level'],
                threat['confidence'],
                threat['detection_reasons'],
                threat['action_taken']
            ))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Created {len(demo_threats)} demo threats")
        print(f"📍 Database: {DB_PATH}")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    create_demo_threats()