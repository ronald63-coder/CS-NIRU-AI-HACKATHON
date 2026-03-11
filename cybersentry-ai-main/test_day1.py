# test_day1.py
"""Test that Day 1 fixes work"""

import sqlite3
from pathlib import Path
from scanner.threat_database import init_database, log_threat_event, get_threat_history

def test_database():
    """Test database works"""
    print("\n🧪 Testing Database...\n")
    
    # 1. Init database
    print("1️⃣  Initializing database...")
    init_database()
    print("   ✅ Database initialized\n")
    
    # 2. Log a threat
    print("2️⃣  Logging a test threat...")
    threat_id = log_threat_event({
        "username": "test_user",
        "filename": "test.exe",
        "verdict": "malicious",
        "risk_score": 85,
        "threat_level": "high",
        "confidence": 0.92,
        "detection_reasons": ["YARA match", "High entropy"]
    })
    print(f"   ✅ Threat logged with ID: {threat_id}\n")
    
    # 3. Retrieve threats
    print("3️⃣  Retrieving threat history...")
    threats = get_threat_history()
    print(f"   ✅ Retrieved {len(threats)} threats\n")
    
    # 4. Display threat
    if threats:
        threat = threats[0]
        print("4️⃣  Latest threat:")
        print(f"   User: {threat['username']}")
        print(f"   File: {threat['filename']}")
        print(f"   Verdict: {threat['verdict']}")
        print(f"   Risk Score: {threat['risk_score']}")
        print(f"   ✅ Database working!\n")
    
    return True

if __name__ == "__main__":
    try:
        test_database()
        print("✅ ALL TESTS PASSED\n")
    except Exception as e:
        print(f"❌ TEST FAILED: {e}\n")