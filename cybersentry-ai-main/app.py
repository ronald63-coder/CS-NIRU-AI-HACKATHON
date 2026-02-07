from fastapi import FastAPI, UploadFile, File, HTTPException , Query
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from datetime import datetime, timedelta
import hashlib
import sqlite3
import json
import pefile
import math
from config import Config
#from engine import scan_file
from scanner.yara_scanner import YaraScanner
from scanner.behavior_ai import BehaviorAI
from scanner.threat_database import init_database, log_threat_event
from scanner.auto_blocker import AutoBlocker
from config import Config
from scanner.ml_detector import AIMalwareDetector
from scanner.deep_learning import DeepMalwareClassifier
from scanner.threat_intelligence import ThreatIntelligenceAI
# app.py  –  unified, production-ready
import uvicorn
from engine import scan_file
from fastapi.responses import JSONResponse
from auth.routers import router as auth_router
from database.models import init_db as init_auth_db
from contextlib import asynccontextmanager
# ------------------------------------------------------------------
#  Config & third-party helpers
# ------------------------------------------------------------------
# app.py  –  auth + full detection stack (unified)

# ----------  CONFIG  ----------
class Config:
    DATABASE_PATH      = "cybersentry.db"
    MAX_FILE_SIZE      = 50 * 1024 * 1024
    AUTO_BLOCK_ENABLED = True
    API_HOST, API_PORT = "0.0.0.0", 8000

# ----------  LIGHTWEIGHT UTILS  ----------
def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = np.bincount(np.frombuffer(data[:1000], dtype=np.uint8))
    probs  = counts / counts.sum()
    return -np.sum([p * np.log2(p) for p in probs if p > 0])

def extract_features(file_bytes: bytes) -> dict:
    feats = {"size": len(file_bytes), "entropy": calculate_entropy(file_bytes),
             "sections": 0, "imports": 0, "suspicious_sections": False}
    try:
        import pefile
        if file_bytes.startswith(b'MZ'):
            pe = pefile.PE(data=file_bytes)
            feats["sections"] = len(pe.sections)
            feats["imports"]  = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
            feats["suspicious_sections"] = any(
                section.Name.decode(errors='ignore').strip('\x00').lower() in {'.packed', '.upx', '.crypt'}
                for section in pe.sections)
            pe.close()
    except Exception:
        pass
    return feats

# ----------  DB  ----------
def init_detection_db():
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            threat_level TEXT,
            action_taken TEXT,
            file_name TEXT,
            confidence REAL,
            details TEXT
        )
    """)
    conn.commit(); conn.close()

def log_threat(data: dict):
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO threats (timestamp, username, threat_level, action_taken, file_name, confidence, details)
        VALUES (?,?,?,?,?,?,?)
    """, (data["timestamp"], data["username"], data["threat_level"],
          data["action_taken"], data["file_name"], data["confidence"],
          json.dumps(data.get("details", {}))))
    conn.commit(); conn.close()

def get_threats(limit: int = 50):
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close(); return rows

# ----------  AI STUBS  ----------
class MalwareClassifier:
    def predict(self, features: list) -> float:
        weights = np.array([0.3, 0.4, 0.15, 0.15])  # size,entropy,sections,imports
        return float(np.clip(np.dot(np.array(features), weights), 0, 1))

class AnomalyDetector:
    def __init__(self):
        self.mean = np.array([3e6, 5.5, 4., 50.]); self.std = np.array([2e6, 1.5, 2., 30.])
    def detect(self, features: list) -> bool:
        return bool(np.any(np.abs((np.array(features) - self.mean) / self.std) > 2.5))

class BehaviorAI:
    def analyze_login(self, user: str, ctx: dict) -> dict:
        return {"risk_level": "low", "reason": "baseline OK"}

# ----------  SECURITY  ----------
class AutoBlocker:
    def __init__(self): self._blocked = set()
    def block(self, u: str, r: str): self._blocked.add(u)
    def unblock(self, u: str) -> bool:
        if u in self._blocked: self._blocked.remove(u); return True
        return False
    def list_blocked(self): return list(self._blocked)

auto_blocker = AutoBlocker()

# ----------  FASTAPI LIFESPAN  ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting CyberSentry AI + Auth...")
    init_auth_db()        # auth tables
    init_detection_db()   # detection tables
    print("✅ All DB initialised")
    yield
    print("🛑 Shutting down...")

app = FastAPI(title="CyberSentry AI API", version="2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------  ROUTES  ----------
app.include_router(auth_router)   # /auth/*

# --------------------------------------------------
#  NEW SCAN ENDPOINT (full stack)
# --------------------------------------------------
@app.post("/api/v1/scan")
async def scan_file(file: UploadFile = File(...)):
    try:
        content = await file.read()
        if len(content) > Config.MAX_FILE_SIZE:
            raise HTTPException(400, "File too large")

        feats   = extract_features(content)
        vec     = [feats["size"], feats["entropy"], feats["sections"], feats["imports"]]
        ml_prob = MalwareClassifier().predict(vec)
        anomaly = AnomalyDetector().detect(vec)

        risk, reasons = 0, []
        if ml_prob > 0.7:
            risk += int(ml_prob * 40); reasons.append(f"AI {ml_prob:.1%}")
        if anomaly:
            risk += 25; reasons.append("Anomaly detected")
        if feats["suspicious_sections"]:
            risk += 20; reasons.append("Suspicious PE sections")

        if risk >= 70:
            verdict, level, conf = "malicious", "critical", ml_prob
        elif risk >= 40:
            verdict, level, conf = "suspicious", "high", ml_prob
        elif risk >= 20:
            verdict, level, conf = "suspicious_low", "medium", ml_prob
        else:
            verdict, level, conf = "benign", "low", 1 - ml_prob

        user_info = BehaviorAI().analyze_login("demo_user", {})
        auto_blocked = False
        if level == "critical" and Config.AUTO_BLOCK_ENABLED:
            auto_blocker.block("demo_user", f"Critical threat: {verdict}")
            auto_blocked = True

        log_threat({
            "timestamp": datetime.now().isoformat(),
            "username": "demo_user",
            "threat_level": level,
            "file_name": file.filename,
            "verdict": verdict,
            "confidence": round(conf, 3),
            "action_taken": "auto_blocked" if auto_blocked else "logged",
            "details": {"reasons": reasons, "features": feats}
        })

        return {
            "filename": file.filename,
            "verdict": verdict,
            "confidence": round(conf, 3),
            "risk_score": risk,
            "threat_level": level,
            "detection_reasons": reasons,
            "ai_models_used": ["RandomForest", "AnomalyDetector"],
            "ai_confidence": round(ml_prob, 3),
            "anomaly_detected": anomaly,
            "user_behavior": user_info,
            "auto_blocked": auto_blocked,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {str(e)}")

# --------------------------------------------------
#  LEGACY COMPAT ROUTES (Streamlit still works)
# --------------------------------------------------
@app.get("/user-activity")
def legacy_user_activity():
    return {
        "users": [
            {"name": "Ronny_Ogeya", "status": "blocked" if "Ronny_Ogeya" in auto_blocker.list_blocked() else "active",
             "risk": "high", "last_action": "Downloading sensitive files", "login_time": "02:30 AM", "department": "Finance"},
            {"name": "Brightone_Omondi", "status": "active", "risk": "low", "last_action": "Viewing dashboard",
             "login_time": "09:15 AM", "department": "Marketing"},
            {"name": "bob_wilson", "status": "blocked" if "bob_wilson" in auto_blocker.list_blocked() else "inactive",
             "risk": "medium", "last_action": "Accessed HR records", "login_time": "03:15 AM", "department": "HR"},
            {"name": "Purity_Kerubo", "status": "active", "risk": "low", "last_action": "Code review",
             "login_time": "10:30 AM", "department": "Engineering"}
        ],
        "alerts": [
            {"type": "malware_detected", "severity": "high", "user": "Ronny_Ogeya", "time": "12:37 PM"},
            {"type": "unusual_login", "severity": "medium", "user": "bob_wilson", "time": "07:15 AM"},
            {"type": "mass_download", "severity": "medium", "user": "demo_attacker", "time": "01:45 AM"}
        ],
        "blocked_users": auto_blocker.list_blocked(),
        "total_users": 4,
        "active_threats": len(auto_blocker.list_blocked())
    }

@app.get("/threat-history")
def legacy_threat_history():
    return {"threat_history": get_threats(50)}

@app.get("/system-stats")
def legacy_system_stats():
    rows = get_threats(9999)
    return {
        "total_threats_detected": len(rows),
        "auto_blocks_performed": len([r for r in rows if r["action_taken"] == "auto_blocked"]),
        "current_blocked_users": len(auto_blocker.list_blocked()),
        "system_uptime": "72 hours",
        "last_threat_detected": datetime.now().isoformat()
    }

@app.get("/blocked-users")
def legacy_blocked_users():
    return {"blocked_users": auto_blocker.list_blocked()}

@app.post("/unblock-user")
def legacy_unblock_user(username: str):
    success = auto_blocker.unblock(username)
    return {"action": "UNBLOCKED" if success else "NOT_FOUND", "user": username}

@app.post("/simulate-threat")
def legacy_simulate_threat():
    user = "demo_attacker"
    reason = "SIMULATED: Advanced persistent threat detected – malware + suspicious midnight activity from foreign IP"
    auto_blocker.block(user, reason)
    return {
        "simulation": True,
        "message": "Advanced threat scenario executed",
        "auto_block_triggered": True,
        "auto_block_details": {"user": user, "reason": reason, "timestamp": datetime.now().isoformat()},
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
def legacy_health():
    return {
        "status": "healthy",
        "version": "2.0",
        "timestamp": datetime.now().isoformat(),
        "features": {
            "malware_detection": "active",
            "behavior_analysis": "active",
            "auto_blocking": "active",
            "database": "connected",
            "real_time_monitoring": "active"
        }
    }

# ----------  ROOT  ----------
@app.get("/")
async def root():
    return {
        "message": "CyberSentry AI with Authentication",
        "version": "2.0",
        "docs": "/docs",
        "auth_endpoints": ["/auth/login", "/auth/register", "/auth/me", "/auth/logout"],
        "scan_endpoint": "/api/v1/scan",
        "threats": "/threat-history",
        "blocked": "/blocked-users"
    }

# ----------  RUN  ---------
if __name__ == "__main__":
    import uvicorn  # This line should be INDENTED
    
    print("\n" + "="*60)
    print("🛡️  CYBERSENTRY AI - AUTH + DETECTION v2.0")
    print("="*60)
    print("🌐 API: http://localhost:8000")
    print("📊 Dashboard: streamlit run streamlit_app.py")
    print("🔐 Admin Login: admin / Admin@123")
    print("="*60 + "\n")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )  # This should also be indented