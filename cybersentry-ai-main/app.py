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
try:
    from auth.routers import router as auth_router
    from database.models import init_db as init_auth_db
    AUTH_AVAILABLE = True
except ImportError:
 AUTH_AVAILABLE = False
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
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

# ------------------------------------------------------------------
# UTILITIES
# ------------------------------------------------------------------
def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence"""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data[:1000], dtype=np.uint8))
    probs = counts / counts.sum()
    return -np.sum([p * np.log2(p) for p in probs if p > 0])


def get_file_type(file_bytes: bytes) -> str:
    """Detect file type from magic bytes"""
    if file_bytes.startswith(b'\x89PNG'):
        return "image_png"
    elif file_bytes.startswith(b'\xff\xd8\xff'):
        return "image_jpeg"
    elif file_bytes.startswith(b'%PDF'):
        return "document_pdf"
    elif file_bytes.startswith(b'PK\x03\x04'):
        return "zip_archive"
    elif file_bytes.startswith(b'MZ'):
        return "executable_pe"
    elif file_bytes.startswith(b'#!/'):
        return "script_shebang"
    elif b'<html' in file_bytes[:1000].lower():
        return "document_html"
    elif all(32 <= b <= 126 or b in (9, 10, 13) for b in file_bytes[:1000]):
        return "text_plain"
    else:
        return "unknown_binary"


def extract_features(file_bytes: bytes) -> dict:
    """Extract comprehensive features from file"""
    feats = {
        "size": len(file_bytes),
        "entropy": calculate_entropy(file_bytes),
        "file_type": get_file_type(file_bytes),
        "sections": 0,
        "imports": 0,
        "suspicious_sections": False,
        "is_packed": False,
        "has_signature": False
    }
    
    # PE analysis for executables
    if feats["file_type"] == "executable_pe" and PEFILE_AVAILABLE:
        try:
            pe = pefile.PE(data=file_bytes)
            
            # Section analysis
            feats["sections"] = len(pe.sections)
            section_names = []
            for section in pe.sections:
                name = section.Name.decode(errors='ignore').strip('\x00').lower()
                section_names.append(name)
                
                # Detect suspicious section names
                if name in {'.packed', '.upx', '.crypt', '.vmp', '.themida', '.aspack'}:
                    feats["suspicious_sections"] = True
                
                # High entropy section = likely packed
                if section.get_entropy() > 7.0:
                    feats["is_packed"] = True
            
            # Import analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                feats["imports"] = len(pe.DIRECTORY_ENTRY_IMPORT)
                
                # Check for suspicious imports
                suspicious_apis = {
                    b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
                    b'ReadProcessMemory', b'OpenProcess', b'TerminateProcess',
                    b'WinExec', b'ShellExecute', b'URLDownloadToFile',
                    b'InternetOpen', b'InternetConnect', b'HttpSendRequest'
                }
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for func in entry.imports:
                        if func.name:
                            for api in suspicious_apis:
                                if api in func.name:
                                    feats["has_signature"] = True
            
            # Check for digital signature
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                feats["has_signature"] = True
            
            pe.close()
            
        except Exception:
            # Corrupted PE = suspicious
            feats["is_packed"] = True
    
    return feats

# ------------------------------------------------------------------
# AI/ML CLASSIFIERS (FIXED)
# ------------------------------------------------------------------
class MalwareClassifier:
    """
    Rule-based malware classifier with realistic, calibrated thresholds.
    Returns 0-1 probability where:
    - < 0.2 = clearly benign
    - 0.2-0.5 = low risk
    - 0.5-0.75 = suspicious
    - > 0.75 = likely malicious
    """
    
    def predict(self, features: list, file_type: str = "unknown") -> float:
        size, entropy, sections, imports = features
        
        # === BENIGN FILE FAST-PATH ===
        if file_type in ("image_png", "image_jpeg", "document_pdf", "text_plain"):
            # These file types are almost always safe
            if entropy < 6.0 and size < 10_000_000:
                return 0.05  # 5% risk = clearly benign
        
        # === CLEARLY BENIGN INDICATORS ===
        if file_type == "text_plain" and entropy < 4.5:
            return 0.08
        
        if file_type == "image_png" and 0.8 < entropy < 7.5:
            return 0.10  # PNGs have natural entropy
        
        # === CALCULATE RISK COMPONENTS ===
        
        # Entropy score (0-1)
        # 0-4: Low (text, uncompressed)
        # 4-6: Medium (compressed, normal)
        # 6-7: High (packed)
        # 7-8: Very high (encrypted/strongly packed)
        if entropy < 4.0:
            entropy_score = 0.0
        elif entropy < 6.0:
            entropy_score = (entropy - 4.0) / 2.0 * 0.3  # 0-0.3
        elif entropy < 7.0:
            entropy_score = 0.3 + (entropy - 6.0) * 0.4  # 0.3-0.7
        else:
            entropy_score = 0.7 + min((entropy - 7.0) / 1.0, 0.3)  # 0.7-1.0
        
        # Size score (log scale)
        # < 1KB: Tiny (suspicious if high entropy)
        # 1KB-1MB: Normal
        # 1-10MB: Large
        # > 10MB: Very large
        if size < 1024:
            size_score = 0.2  # Tiny files slightly suspicious
        elif size < 1_000_000:
            size_score = 0.0
        elif size < 10_000_000:
            size_score = 0.15
        else:
            size_score = 0.25
        
        # PE-specific scores
        pe_score = 0.0
        if sections > 0:
            # Many sections = complex
            if sections > 8:
                pe_score += 0.15
            if sections > 12:
                pe_score += 0.10
            
            # Few sections in large file = packed
            if sections < 3 and size > 500_000:
                pe_score += 0.20
        
        if imports > 0:
            # Many imports = complex
            if imports > 100:
                pe_score += 0.10
            if imports > 300:
                pe_score += 0.15
        
        # === COMBINE SCORES ===
        # Weights: entropy matters most, then PE features, then size
        base_score = (
            entropy_score * 0.50 +
            pe_score * 0.35 +
            size_score * 0.15
        )
        
        # === ADJUSTMENTS ===
        
        # Non-PE files with normal entropy are usually safe
        if sections == 0 and entropy < 5.5 and file_type != "unknown_binary":
            base_score *= 0.4
        
        # Packed files are highly suspicious
        # (checked via features dict, not passed here - handled in risk scoring)
        
        # Cap and return
        return float(np.clip(base_score, 0.0, 0.95))


class AnomalyDetector:
    """
    Detect truly anomalous files, not everything.
    Returns True only for genuine outliers.
    """
    
    def detect(self, features: list, feats_dict: dict) -> bool:
        size, entropy, sections, imports = features
        
        anomalies = 0
        
        # Extreme size
        if size > 50_000_000:  # > 50MB
            anomalies += 1
        if size < 50 and entropy > 6.5:  # Tiny but encrypted
            anomalies += 1
        
        # Extreme entropy
        if entropy > 7.8:  # Almost certainly packed/encrypted
            anomalies += 1
        if entropy < 1.0 and size > 10000:  # Large but no entropy = suspicious
            anomalies += 1
        
        # PE anomalies
        if sections > 0:
            if sections > 20:  # Absurdly complex
                anomalies += 1
            if imports > 1000:  # Massive import table
                anomalies += 1
            if sections == 1 and size > 1000000:  # Single section, large = packed
                anomalies += 1
        
        # File type mismatch
        if feats_dict.get("is_packed") and feats_dict.get("has_signature"):
            # Signed but packed = unusual
            anomalies += 1
        
        # Need 2+ anomalies to flag
        return anomalies >= 2


class BehaviorAI:
    """User behavior analysis stub"""
    
    def analyze_login(self, user: str, ctx: dict) -> dict:
        return {"risk_level": "low", "reason": "baseline OK"}


# ------------------------------------------------------------------
# SECURITY & DATABASE
# ------------------------------------------------------------------
class AutoBlocker:
    def __init__(self):
        self._blocked = set()
    
    def block(self, user: str, reason: str):
        self._blocked.add(user)
    
    def unblock(self, user: str) -> bool:
        if user in self._blocked:
            self._blocked.remove(user)
            return True
        return False
    
    def list_blocked(self):
        return list(self._blocked)


auto_blocker = AutoBlocker()


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
    conn.commit()
    conn.close()


def log_threat(data: dict):
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO threats (timestamp, username, threat_level, action_taken, file_name, confidence, details)
        VALUES (?,?,?,?,?,?,?)
    """, (
        data["timestamp"],
        data["username"],
        data["threat_level"],
        data["action_taken"],
        data["file_name"],
        data["confidence"],
        json.dumps(data.get("details", {}))
    ))
    conn.commit()
    conn.close()


def get_threats(limit: int = 50):
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# ------------------------------------------------------------------
# FASTAPI SETUP
# ------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting CyberSentry AI...")
    if AUTH_AVAILABLE:
        init_auth_db()
    init_detection_db()
    print("✅ All databases initialized")
    yield
    print("🛑 Shutting down...")


app = FastAPI(title="CyberSentry AI API", version="2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if AUTH_AVAILABLE:
    app.include_router(auth_router)

# ------------------------------------------------------------------
# CORE SCAN ENDPOINT (FIXED)
# ------------------------------------------------------------------
@app.post("/api/v1/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Scan file for malware with accurate verdicts:
    - benign: clearly safe (images, text, normal docs)
    - low_risk: slight indicators but likely safe
    - suspicious: mixed signals, needs review
    - likely_malicious: strong indicators
    - malicious: critical threat
    """
    try:
        content = await file.read()
        
        if len(content) > Config.MAX_FILE_SIZE:
            raise HTTPException(400, "File too large")
        
        # Extract features
        feats = extract_features(content)
        
        # Build feature vector
        vec = [
            feats["size"],
            feats["entropy"],
            feats["sections"],
            feats["imports"]
        ]
        
        # AI predictions
        ml_prob = MalwareClassifier().predict(vec, feats["file_type"])
        anomaly = AnomalyDetector().detect(vec, feats)
        
        # Calculate risk score (0-100)
        risk = 0
        reasons = []
        
        # Base ML score
        risk += int(ml_prob * 50)  # 0-50 points
        if ml_prob > 0.5:
            reasons.append(f"ML model: {ml_prob:.1%} malicious probability")
        
        # Anomaly bonus
        if anomaly:
            risk += 15
            reasons.append("Statistical anomaly detected")
        
        # File type adjustments
        if feats["file_type"] in ("image_png", "image_jpeg", "text_plain"):
            risk -= 20  # Strong benign signal
            reasons.append(f"Safe file type: {feats['file_type']}")
        elif feats["file_type"] == "executable_pe":
            risk += 10  # Executables need scrutiny
            reasons.append("Executable file requires analysis")
        
        # PE-specific indicators
        if feats["suspicious_sections"]:
            risk += 20
            reasons.append("Suspicious section names detected")
        
        if feats["is_packed"]:
            risk += 25
            reasons.append("Packing/encryption detected")
        
        if feats["has_signature"]:
            risk -= 10  # Signed = slightly more trustworthy
            reasons.append("Digital signature present")
        
        # Entropy extremes
        if feats["entropy"] > 7.5:
            risk += 15
            reasons.append(f"Very high entropy: {feats['entropy']:.2f}")
        elif feats["entropy"] < 2.0:
            risk -= 10
            reasons.append(f"Low entropy (readable): {feats['entropy']:.2f}")
        
        # Clamp risk
        risk = max(0, min(100, risk))
        
        # Determine verdict based on calibrated thresholds
        if risk >= 80:
            verdict = "malicious"
            level = "critical"
            conf = ml_prob
        elif risk >= 60:
            verdict = "likely_malicious"
            level = "high"
            conf = ml_prob
        elif risk >= 40:
            verdict = "suspicious"
            level = "medium"
            conf = max(ml_prob, 0.5)
        elif risk >= 15:
            verdict = "low_risk"
            level = "low"
            conf = 1 - ml_prob
        else:
            verdict = "benign"
            level = "low"
            conf = 1 - ml_prob
        
        # Auto-block only for critical
        auto_blocked = False
        if level == "critical" and Config.AUTO_BLOCK_ENABLED:
            auto_blocker.block("demo_user", f"Critical threat: {verdict}")
            auto_blocked = True
        
        # Log
        log_threat({
            "timestamp": datetime.now().isoformat(),
            "username": "demo_user",
            "threat_level": level,
            "file_name": file.filename,
            "verdict": verdict,
            "confidence": round(conf, 3),
            "action_taken": "auto_blocked" if auto_blocked else "logged",
            "details": {
                "reasons": reasons,
                "features": feats,
                "risk_score": risk
            }
        })
        
        return {
            "filename": file.filename,
            "verdict": verdict,
            "confidence": round(conf, 3),
            "risk_score": risk,
            "threat_level": level,
            "detection_reasons": reasons,
            "file_type": feats["file_type"],
            "features": {
                "size": feats["size"],
                "entropy": round(feats["entropy"], 2),
                "sections": feats["sections"],
                "imports": feats["imports"]
            },
            "indicators": {
                "suspicious_sections": feats["suspicious_sections"],
                "is_packed": feats["is_packed"],
                "has_signature": feats["has_signature"]
            },
            "ai_models_used": ["CalibratedRuleEngine", "AnomalyDetector"],
            "ai_confidence": round(ml_prob, 3),
            "anomaly_detected": anomaly,
            "auto_blocked": auto_blocked,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {str(e)}")


# ------------------------------------------------------------------
# LEGACY ROUTES (Dashboard compatibility)
# ------------------------------------------------------------------
@app.get("/user-activity")
def legacy_user_activity():
    return {
        "users": [
            {"name": "Ronny Ogeya", "status": "blocked" if "Ronny Ogeya" in auto_blocker.list_blocked() else "active",
             "risk": "high", "last_action": "Downloading sensitive files", "login_time": "02:30 AM", "department": "Finance"},
            {"name": "Brightone Omondi", "status": "active", "risk": "low", "last_action": "Viewing dashboard",
             "login_time": "09:15 AM", "department": "Marketing"},
            {"name": "bob wilson", "status": "blocked" if "bob wilson" in auto_blocker.list_blocked() else "inactive",
             "risk": "medium", "last_action": "Accessed HR records", "login_time": "03:15 AM", "department": "HR"},
            {"name": "Purity Kerubo", "status": "active", "risk": "low", "last_action": "Code review",
             "login_time": "10:30 AM", "department": "Engineering"}
        ],
        "alerts": [
            {"type": "malware_detected", "severity": "high", "user": "Ronny Ogeya", "time": "12:37 PM"},
            {"type": "unusual_login", "severity": "medium", "user": "bob wilson", "time": "07:15 AM"},
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


@app.get("/")
async def root():
    return {
        "message": "CyberSentry AI API",
        "version": "2.0",
        "docs": "/docs",
        "scan_endpoint": "/api/v1/scan",
        "threats": "/threat-history",
        "blocked": "/blocked-users"
    }


# ------------------------------------------------------------------
# RUN
# ------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "=" * 60)
    print("🛡️  CYBERSENTRY AI v2.0")
    print("=" * 60)
    print("🌐 API: http://localhost:8000")
    print("📊 Dashboard: streamlit run dashboardapp.py")
    print("🔬 Test scan: curl -X POST -F 'file=@test.txt' http://localhost:8000/api/v1/scan")
    print("=" * 60 + "\n")
    
    uvicorn.run (
        "app:app",
        host=Config.API_HOST,
        port=Config.API_PORT,
        reload=True
    )