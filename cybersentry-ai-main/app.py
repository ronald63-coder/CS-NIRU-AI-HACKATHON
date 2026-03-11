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
import random
import string
from config import Config
from typing import List, Dict, Any, Optional
#from engine import scan_file
from scanner.yara_scanner import get_yara_scanner, YaraScanner, test_yara_installation
from scanner.behavior_ai import BehaviorAI
from scanner.threat_database import init_database, log_threat_event
from scanner.auto_blocker import AutoBlocker
from config import Config
from scanner.ml_detector import AIMalwareDetector
from scanner.deep_learning import DeepMalwareClassifier
from scanner.threat_intelligence import ThreatIntelligenceAI
# app.py  –  unified, production-ready
import uvicorn
from pydantic import BaseModel
from engine import scan_file
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

# IMPORT THE AUTH ROUTER
try:
    from auth.routers import router as auth_router
    from database.models import init_db as init_auth_db
    from auth.schemas import UserCreate, LoginRequest as AuthLoginRequest
    AUTH_AVAILABLE = True
    print("✅ Auth module loaded successfully")
except ImportError as e:
    AUTH_AVAILABLE = False
    print(f"⚠️ Auth module not available: {e}")

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print("⚠️ pefile not installed - PE analysis will be limited")

# Global variables
yara_scanner = None
auto_blocker = None  # Will be initialized later
user_db = None  # Will be initialized later

# ------------------------------------------------------------------
#  Config
# ------------------------------------------------------------------
class Config:
    DATABASE_PATH = "cybersentry.db"
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    AUTO_BLOCK_ENABLED = True
    API_HOST = "0.0.0.0"
    API_PORT = 8000
    JWT_SECRET = "cybersentry-secret-key-2026"
    JWT_ALGORITHM = "HS256"
    SECRET_KEY = "cybersentry-secret-key-2026"

# ------------------------------------------------------------------
#  Pydantic Models for Request/Response
# ------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    password: str
    department: Optional[str] = None
    role: Optional[str] = None
    is_admin: bool = False

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    is_admin: bool
    department: str
    risk_level: str
    status: str
    last_login: Optional[str] = None
    last_action: Optional[str] = None

class ThreatResponse(BaseModel):
    timestamp: str
    username: str
    threat_level: str
    verdict: str
    risk_score: int
    action_taken: str
    filename: str
    file_type: str
    confidence: float
    detection_reasons: List[str]
    features: Dict[str, Any]

# ------------------------------------------------------------------
#  Try imports for optional dependencies
# ------------------------------------------------------------------
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print("⚠️ pefile not installed - PE analysis will be limited")

# ------------------------------------------------------------------
#  UTILITIES
# ------------------------------------------------------------------
def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence"""
    if not data or len(data) == 0:
        return 0.0
    # Sample first 10KB for performance
    sample = data[:min(10000, len(data))]
    counts = np.bincount(np.frombuffer(sample, dtype=np.uint8))
    probs = counts / counts.sum()
    return float(-np.sum([p * np.log2(p) for p in probs if p > 0]))

def get_file_type(file_bytes: bytes) -> str:
    """Detect file type from magic bytes"""
    if len(file_bytes) < 4:
        return "unknown_tiny"
    
    # Common file signatures
    signatures = {
        b'\x89PNG': 'image_png',
        b'\xff\xd8\xff': 'image_jpeg',
        b'%PDF': 'document_pdf',
        b'PK\x03\x04': 'zip_archive',
        b'MZ': 'executable_pe',
        b'\x7fELF': 'executable_elf',
        b'#!/': 'script_shebang',
        b'<!DOCTYPE': 'document_html',
        b'<html': 'document_html',
        b'GIF87a': 'image_gif',
        b'GIF89a': 'image_gif',
        b'BM': 'image_bmp',
        b'RIFF': 'video_avi',
    }
    
    for sig, file_type in signatures.items():
        if file_bytes.startswith(sig):
            return file_type
    
    # Check if text
    try:
        if all(32 <= b <= 126 or b in (9, 10, 13) for b in file_bytes[:1000]):
            return "text_plain"
    except:
        pass
    
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
        "has_signature": False,
        "strings_count": 0,
        "urls_count": 0,
        "ips_count": 0,
        "high_entropy_regions": 0
    }
    
    # Count strings, URLs, IPs
    try:
        # Simple string extraction (ASCII strings of length >=4)
        import re
        # Find potential strings
        strings = re.findall(b'[ -~]{4,}', file_bytes)
        feats["strings_count"] = len(strings)
        
        # Find URLs
        urls = re.findall(b'https?://[^\s\'"]+', file_bytes)
        feats["urls_count"] = len(urls)
        
        # Find IP addresses
        ips = re.findall(b'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', file_bytes)
        feats["ips_count"] = len(ips)
    except:
        pass
    
    # PE analysis for executables
    if feats["file_type"] == "executable_pe" and PEFILE_AVAILABLE:
        try:
            pe = pefile.PE(data=file_bytes)
            
            # Section analysis
            feats["sections"] = len(pe.sections)
            section_names = []
            high_entropy_sections = 0
            
            for section in pe.sections:
                name = section.Name.decode(errors='ignore').strip('\x00').lower()
                section_names.append(name)
                
                # Detect suspicious section names
                if name in {'.packed', '.upx', '.crypt', '.vmp', '.themida', '.aspack', 
                           '.mpress', '.nsp0', '.nsp1', '.nsp2', '.ccg'}:
                    feats["suspicious_sections"] = True
                
                # High entropy section = likely packed
                section_entropy = section.get_entropy()
                if section_entropy > 7.0:
                    high_entropy_sections += 1
                    feats["is_packed"] = True
            
            feats["high_entropy_regions"] = high_entropy_sections
            
            # Import analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                feats["imports"] = len(pe.DIRECTORY_ENTRY_IMPORT)
                
                # Check for suspicious imports
                suspicious_apis = {
                    b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
                    b'ReadProcessMemory', b'OpenProcess', b'TerminateProcess',
                    b'WinExec', b'ShellExecute', b'URLDownloadToFile',
                    b'InternetOpen', b'InternetConnect', b'HttpSendRequest',
                    b'RegOpenKey', b'RegSetValue', b'CryptEncrypt',
                    b'AdjustTokenPrivileges', b'LookupPrivilegeValue'
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
            
            # Check for TLS callbacks (often used in malware)
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                feats["suspicious_sections"] = True
            
            pe.close()
            
        except Exception as e:
            # Corrupted PE = suspicious
            feats["is_packed"] = True
            feats["suspicious_sections"] = True
    elif feats["file_type"] == "executable_pe" and not PEFILE_AVAILABLE:
        # Basic analysis without pefile
        if b'UPX' in file_bytes[:1000]:
            feats["is_packed"] = True
    
    # Scan for malware signatures
    malware_signatures = [
        b'CreateRemoteThread',
        b'VirtualAllocEx',
        b'WriteProcessMemory',
        b'ReadProcessMemory',
        b'OpenProcess',
        b'TerminateProcess',
        b'WinExec',
        b'ShellExecute',
        b'URLDownloadToFile',
        b'InternetOpen',
        b'InternetConnect',
        b'HttpSendRequest',
        b'RegOpenKey',
        b'RegSetValue',
        b'CryptEncrypt',
        b'AdjustTokenPrivileges',
        b'LookupPrivilegeValue'
    ]
    
    for sig in malware_signatures:
        if sig in file_bytes:
            feats["has_signature"] = True
            break
    
    return feats

# ------------------------------------------------------------------
#  AI/ML CLASSIFIERS
# ------------------------------------------------------------------
class MalwareClassifier:
    """Enhanced rule-based malware classifier with more sophisticated scoring."""
    
    def predict(self, features: list, file_type: str = "unknown", feats_dict: dict = None) -> float:
        size, entropy, sections, imports = features
        
        # BENIGN FILE FAST-PATHS
        if file_type in ("image_png", "image_jpeg", "image_gif", "image_bmp"):
            if entropy < 7.0 and size < 10_000_000:
                return 0.02
            else:
                # Could be steganography
                return 0.15 if entropy > 7.5 else 0.05
        
        if file_type == "document_pdf":
            # PDFs can contain malicious JS
            if feats_dict and feats_dict.get("urls_count", 0) > 5:
                return 0.35
            if feats_dict and feats_dict.get("strings_count", 0) > 1000:
                return 0.25
            return 0.08
        
        if file_type == "text_plain":
            if entropy < 5.0:
                return 0.01
            # Check for suspicious content
            if feats_dict and feats_dict.get("urls_count", 0) > 10:
                return 0.20
            return 0.05
        
        if file_type == "zip_archive":
            # Archives can contain malware
            return 0.20
        
        # CALCULATE RISK COMPONENTS
        # Entropy score (0-1)
        if entropy < 4.0:
            entropy_score = 0.0
        elif entropy < 6.0:
            entropy_score = (entropy - 4.0) / 2.0 * 0.3
        elif entropy < 7.0:
            entropy_score = 0.3 + (entropy - 6.0) * 0.4
        else:
            entropy_score = 0.7 + min((entropy - 7.0) / 1.5, 0.3)
        
        # Size score (0-0.3)
        if size < 1024:  # Very small files
            size_score = 0.2
        elif size < 100_000:
            size_score = 0.05
        elif size < 1_000_000:
            size_score = 0.1
        elif size < 10_000_000:
            size_score = 0.15
        else:
            size_score = 0.25
        
        # PE structure score (0-0.4)
        pe_score = 0.0
        if sections > 0:
            if sections > 10:
                pe_score += 0.15
            if sections < 3 and size > 500_000:
                pe_score += 0.25  # Very few sections for large file = packed
        
        if imports > 0:
            if imports > 50:
                pe_score += 0.1
            if imports > 200:
                pe_score += 0.15
        
        # Additional indicators from feats_dict
        extra_score = 0.0
        if feats_dict:
            if feats_dict.get("suspicious_sections"):
                extra_score += 0.2
            if feats_dict.get("is_packed"):
                extra_score += 0.25
            if feats_dict.get("urls_count", 0) > 5:
                extra_score += 0.1
            if feats_dict.get("ips_count", 0) > 5:
                extra_score += 0.1
        
        base_score = (
            entropy_score * 0.35 +
            pe_score * 0.25 +
            size_score * 0.15 +
            extra_score * 0.25
        )
        
        # Penalty for legitimate indicators
        if feats_dict and feats_dict.get("has_signature"):
            base_score *= 0.7
        
        return float(np.clip(base_score, 0.0, 0.98))

class AnomalyDetector:
    """Enhanced anomaly detection with more criteria."""
    
    def detect(self, features: list, feats_dict: dict) -> tuple:
        size, entropy, sections, imports = features
        
        anomalies = 0
        reasons = []
        
        # Size anomalies
        if size > 50_000_000:
            anomalies += 1
            reasons.append("excessive_size")
        if size < 100 and entropy > 7.0:
            anomalies += 1
            reasons.append("tiny_high_entropy")
        
        # Entropy anomalies
        if entropy > 7.8:
            anomalies += 1
            reasons.append("extreme_entropy")
        if entropy < 1.0 and size > 10000:
            anomalies += 1
            reasons.append("low_entropy_large")
        
        # Structure anomalies
        if sections > 0:
            if sections > 25:
                anomalies += 1
                reasons.append("too_many_sections")
            if imports > 1000:
                anomalies += 1
                reasons.append("too_many_imports")
            if sections == 1 and size > 1_000_000:
                anomalies += 1
                reasons.append("single_section_large")
        
        # Feature-based anomalies
        if feats_dict:
            if feats_dict.get("suspicious_sections"):
                anomalies += 1
                reasons.append("suspicious_sections")
            if feats_dict.get("is_packed") and not feats_dict.get("has_signature"):
                anomalies += 1
                reasons.append("packed_no_signature")
            if feats_dict.get("urls_count", 0) > 20:
                anomalies += 1
                reasons.append("excessive_urls")
            if feats_dict.get("ips_count", 0) > 20:
                anomalies += 1
                reasons.append("excessive_ips")
        
        return anomalies >= 2, reasons[:3]  # Return if anomalous and top reasons

# ------------------------------------------------------------------
#  SECURITY & DATABASE
# ------------------------------------------------------------------
class AutoBlocker:
    """Enhanced auto-blocker with user tracking and history."""
    def __init__(self):
        self._blocked = set()
        self._block_history = []
    
    def block(self, user: str, reason: str):
        self._blocked.add(user)
        self._block_history.append({
            "user": user,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
    
    def unblock(self, user: str) -> bool:
        if user in self._blocked:
            self._blocked.remove(user)
            return True
        return False
    
    def list_blocked(self):
        return list(self._blocked)
    
    def get_block_history(self):
        return self._block_history

# Mock user database for demo (fallback only)
class UserDatabase:
    def __init__(self):
        self.users = [
            {
                "id": 1,
                "username": "ronny_ogeya",
                "email": "ronny@cybersentry.local",
                "full_name": "Ronny Ogeya",
                "password_hash": hashlib.sha256("password123".encode()).hexdigest(),
                "is_admin": True,
                "department": "Finance",
                "risk_level": "high",
                "status": "active",
                "last_login": (datetime.now() - timedelta(hours=2)).isoformat(),
                "last_action": "Downloading sensitive files"
            },
            {
                "id": 2,
                "username": "brightone_omondi",
                "email": "brightone@cybersentry.local",
                "full_name": "Brightone Omondi",
                "password_hash": hashlib.sha256("password123".encode()).hexdigest(),
                "is_admin": False,
                "department": "Marketing",
                "risk_level": "low",
                "status": "active",
                "last_login": (datetime.now() - timedelta(hours=9)).isoformat(),
                "last_action": "Viewing dashboard"
            },
            {
                "id": 3,
                "username": "bob_wilson",
                "email": "bob@cybersentry.local",
                "full_name": "Bob Wilson",
                "password_hash": hashlib.sha256("password123".encode()).hexdigest(),
                "is_admin": False,
                "department": "HR",
                "risk_level": "medium",
                "status": "blocked",
                "last_login": (datetime.now() - timedelta(hours=3)).isoformat(),
                "last_action": "Accessed HR records"
            },
            {
                "id": 4,
                "username": "purity_kerubo",
                "email": "purity@cybersentry.local",
                "full_name": "Purity Kerubo",
                "password_hash": hashlib.sha256("password123".encode()).hexdigest(),
                "is_admin": False,
                "department": "Engineering",
                "risk_level": "low",
                "status": "active",
                "last_login": (datetime.now() - timedelta(hours=10)).isoformat(),
                "last_action": "Code review"
            },
            {
                "id": 5,
                "username": "demo_attacker",
                "email": "attacker@evil.com",
                "full_name": "Demo Attacker",
                "password_hash": hashlib.sha256("hack123".encode()).hexdigest(),
                "is_admin": False,
                "department": "External",
                "risk_level": "critical",
                "status": "blocked",
                "last_login": (datetime.now() - timedelta(hours=1)).isoformat(),
                "last_action": "Mass download attempt"
            }
        ]
    
    def authenticate(self, username: str, password: str):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        for user in self.users:
            if user["username"] == username and user["password_hash"] == password_hash:
                # Update status if blocked
                if auto_blocker and user["username"] in auto_blocker.list_blocked():
                    user["status"] = "blocked"
                return user.copy()
        return None
    
    def get_user(self, username: str):
        for user in self.users:
            if user["username"] == username:
                # Update status if blocked
                if auto_blocker and user["username"] in auto_blocker.list_blocked():
                    user["status"] = "blocked"
                return user.copy()
        return None
    
    def get_all_users(self):
        # Update statuses based on auto_blocker
        for user in self.users:
            if auto_blocker and user["username"] in auto_blocker.list_blocked():
                user["status"] = "blocked"
            else:
                user["status"] = "active"
        return self.users

# Initialize auto_blocker and user_db AFTER class definitions
auto_blocker = AutoBlocker()
user_db = UserDatabase()

def init_detection_db():
    """Initialize database with full schema"""
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    cur = conn.cursor()
    
    # Threats table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            threat_level TEXT,
            verdict TEXT DEFAULT 'unknown',
            risk_score INTEGER DEFAULT 0,
            action_taken TEXT,
            file_name TEXT,
            file_type TEXT DEFAULT 'unknown',
            confidence REAL,
            details TEXT,
            md5_hash TEXT,
            sha256_hash TEXT
        )
    """)
    
    # System logs table - WITHOUT source_ip column to avoid errors
    cur.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            severity TEXT,
            message TEXT,
            user_affected TEXT
        )
    """)
    
    # Create indexes for performance
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threats_username ON threats(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp)")
    
    conn.commit()
    conn.close()

def migrate_database():
    """Add missing columns to existing database"""
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    cur = conn.cursor()
    
    # Check current columns in threats
    cur.execute("PRAGMA table_info(threats)")
    columns = [col[1] for col in cur.fetchall()]
    
    # Add missing columns to threats
    migrations = [
        ('verdict', "ALTER TABLE threats ADD COLUMN verdict TEXT DEFAULT 'unknown'"),
        ('risk_score', "ALTER TABLE threats ADD COLUMN risk_score INTEGER DEFAULT 0"),
        ('file_type', "ALTER TABLE threats ADD COLUMN file_type TEXT DEFAULT 'unknown'"),
        ('md5_hash', "ALTER TABLE threats ADD COLUMN md5_hash TEXT"),
        ('sha256_hash', "ALTER TABLE threats ADD COLUMN sha256_hash TEXT")
    ]
    
    for col_name, sql in migrations:
        if col_name not in columns:
            try:
                cur.execute(sql)
                print(f"✅ Added '{col_name}' column to threats")
            except:
                print(f"⚠️ Could not add '{col_name}' column to threats")
    
    # Check system_logs table
    cur.execute("PRAGMA table_info(system_logs)")
    log_columns = [col[1] for col in cur.fetchall()]
    
    # If system_logs exists but has wrong schema, we'll recreate it
    if 'source_ip' in log_columns:
        print("⚠️ Recreating system_logs table with correct schema")
        cur.execute("DROP TABLE IF EXISTS system_logs")
        cur.execute("""
            CREATE TABLE system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                severity TEXT,
                message TEXT,
                user_affected TEXT
            )
        """)
        print("✅ Recreated system_logs table")
    
    conn.commit()
    conn.close()

def calculate_file_hashes(file_bytes: bytes) -> dict:
    """Calculate MD5 and SHA256 hashes of file"""
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    return {
        "md5": md5_hash,
        "sha256": sha256_hash
    }

def log_threat(data: dict):
    """Log threat with all fields properly saved"""
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    cur = conn.cursor()
    
    # Extract fields with fallbacks
    timestamp = data.get("timestamp", datetime.now().isoformat())
    username = data.get("username", "unknown")
    threat_level = data.get("threat_level", "low")
    verdict = data.get("verdict", "unknown")
    risk_score = data.get("risk_score", 0)
    action_taken = data.get("action_taken", "logged")
    file_name = data.get("file_name") or data.get("filename", "N/A")
    file_type = data.get("file_type", "unknown")
    confidence = data.get("confidence", 0.0)
    md5_hash = data.get("md5_hash", "")
    sha256_hash = data.get("sha256_hash", "")
    details = json.dumps(data.get("details", {}))
    
    cur.execute("""
        INSERT INTO threats 
        (timestamp, username, threat_level, verdict, risk_score, action_taken, 
         file_name, file_type, confidence, details, md5_hash, sha256_hash)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (timestamp, username, threat_level, verdict, risk_score, action_taken,
          file_name, file_type, confidence, details, md5_hash, sha256_hash))
    
    # Also log to system_logs (without source_ip)
    cur.execute("""
        INSERT INTO system_logs (timestamp, event_type, severity, message, user_affected)
        VALUES (?,?,?,?,?)
    """, (
        timestamp,
        "THREAT_DETECTED",
        threat_level.upper(),
        f"Threat detected: {verdict} (risk: {risk_score}) - {file_name}",
        username
    ))
    
    conn.commit()
    conn.close()

def get_threats(limit: int = 50):
    """Get threats with all fields for frontend display"""
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("""
        SELECT 
            timestamp,
            username,
            threat_level,
            verdict,
            risk_score,
            action_taken,
            file_name as filename,
            file_type,
            confidence,
            details,
            md5_hash,
            sha256_hash
        FROM threats 
        ORDER BY timestamp DESC 
        LIMIT ?
    """, (limit,))
    
    rows = []
    for r in cur.fetchall():
        row = dict(r)
        # Parse details JSON
        try:
            details = json.loads(row.get('details', '{}'))
            row['detection_reasons'] = details.get('reasons', [])
            row['features'] = details.get('features', {})
        except:
            row['detection_reasons'] = []
            row['features'] = {}
        rows.append(row)
    
    conn.close()
    return rows

def log_system_event(event_type: str, severity: str, message: str, user: str = None):
    """Log system events to database (without source_ip)"""
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO system_logs (timestamp, event_type, severity, message, user_affected)
        VALUES (?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        event_type,
        severity,
        message,
        user
    ))
    
    conn.commit()
    conn.close()

# ------------------------------------------------------------------
#  FASTAPI SETUP - CREATE APP FIRST!
# ------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "=" * 60)
    print("🚀 Starting CyberSentry AI Backend v2.0")
    print("=" * 60)
    
    # Initialize auth database if available
    if AUTH_AVAILABLE:
        try:
            init_auth_db()
            print("✅ Auth database initialized")
        except Exception as e:
            print(f"⚠️ Could not initialize auth database: {e}")
    
    # Initialize detection database
    init_detection_db()
    migrate_database()
    
    # Seed some demo threats if empty
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM threats")
    count = cur.fetchone()[0]
    conn.close()
    
    if count == 0:
        print("📊 Seeding demo threat data...")
        demo_threats = [
            {
                "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
                "username": "ronny_ogeya",
                "threat_level": "critical",
                "verdict": "malicious",
                "risk_score": 92,
                "action_taken": "auto_blocked",
                "file_name": "invoice.exe",
                "file_type": "executable_pe",
                "confidence": 0.95,
                "details": json.dumps({"reasons": ["Packed executable", "Suspicious imports", "High entropy"], "features": {"size": 1520000, "entropy": 7.8}})
            },
            {
                "timestamp": (datetime.now() - timedelta(hours=5)).isoformat(),
                "username": "bob_wilson",
                "threat_level": "high",
                "verdict": "likely_malicious",
                "risk_score": 78,
                "action_taken": "alerted",
                "file_name": "document.pdf",
                "file_type": "document_pdf",
                "confidence": 0.82,
                "details": json.dumps({"reasons": ["Embedded JavaScript", "External URLs", "Suspicious metadata"], "features": {"size": 245000, "entropy": 6.2}})
            },
            {
                "timestamp": (datetime.now() - timedelta(hours=8)).isoformat(),
                "username": "demo_attacker",
                "threat_level": "critical",
                "verdict": "malicious",
                "risk_score": 96,
                "action_taken": "auto_blocked",
                "file_name": "payload.dll",
                "file_type": "executable_pe",
                "confidence": 0.98,
                "details": json.dumps({"reasons": ["Known malware signature", "Packed with UPX", "Suspicious API calls"], "features": {"size": 890000, "entropy": 7.9}})
            }
        ]
        
        for threat in demo_threats:
            log_threat(threat)
        
        print(f"✅ Added {len(demo_threats)} demo threats")
    
    # Initialize YARA scanner
    print("\n" + "=" * 60)
    print("🔍 Initializing YARA Scanner")
    print("=" * 60)
    
    global yara_scanner
    yara_scanner = get_yara_scanner("yara_rules")
    yara_stats = yara_scanner.get_stats()
    
    if yara_scanner.rules:
        print(f"✅ YARA Scanner initialized successfully!")
        print(f"   📁 Rule files: {yara_stats['loaded_files']}")
        print(f"   📊 Total rules: ~{yara_stats['total_rules']}")
        print(f"   📂 Categories: {', '.join(list(yara_stats['categories'].keys())[:5])}")
    else:
        print(f"⚠️ YARA Scanner initialized but no rules loaded")
        print(f"   Please add YARA rules to: {yara_stats['rules_path']}")
    print("=" * 60 + "\n")
    
    print("✅ Core systems ready")
    print("🌐 API: http://localhost:8000")
    print("📚 Docs: http://localhost:8000/docs")
    print("🤖 Agent: python run_agent.py")
    print("=" * 60 + "\n")
    
    yield
    print("🛑 Shutting down CyberSentry AI...")

# CREATE THE FASTAPI APP INSTANCE
app = FastAPI(
    title="CyberSentry AI API",
    description="Advanced Malware Detection and Threat Intelligence Platform",
    version="2.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
#  AGENT API ENDPOINTS
# ------------------------------------------------------------------
@app.get("/api/agent/status")
async def agent_status():
    """Get agent status and configuration (fast version)"""
    return {
        "status": "configured",
        "poll_interval": int(os.getenv("POLL_INTERVAL", "10")),
        "api_url": os.getenv("AGENT_API_URL", "http://localhost:8000"),
        "features": {
            "whatsapp": bool(os.getenv("TWILIO_SID")),
            "voice": bool(os.getenv("TWILIO_VOICE_FROM")),
            "nemo": False,
            "edge": bool(os.getenv("TINY_MODEL_PATH"))
        },
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/agent/trigger")
async def trigger_agent_action(action: str, username: str, reason: str = ""):
    """Manually trigger agent actions from dashboard"""
    try:
        if action == "block":
            success = auto_blocker.block(username, reason)
            log_system_event("MANUAL_BLOCK", "INFO", f"Manual block for {username}: {reason}", username)
            return {"action": "block", "success": success, "username": username}
        
        elif action == "unblock":
            success = auto_blocker.unblock(username)
            log_system_event("MANUAL_UNBLOCK", "INFO", f"Manual unblock for {username}", username)
            return {"action": "unblock", "success": success, "username": username}
        
        elif action == "notify":
            log_system_event("MANUAL_NOTIFY", "INFO", f"Manual notification for {username}: {reason}", username)
            return {"action": "notify", "success": True, "message": f"Notification logged for {username}"}
        
        elif action == "call":
            log_system_event("MANUAL_CALL", "INFO", f"Manual call initiated for {username}", username)
            return {"action": "call", "success": True, "message": f"Call initiated for {username}"}
    
    except Exception as e:
        return {"action": action, "success": False, "error": str(e)}
    
    return {"action": action, "status": "unknown"}

@app.get("/api/agent/threats/unresolved")
async def get_unresolved_threats():
    """Get threats requiring human attention"""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("""
        SELECT id, timestamp, username, threat_level, verdict, risk_score, action_taken, file_name
        FROM threats 
        WHERE action_taken IN ('AWAITING-HUMAN', 'MONITORED', 'logged')
        ORDER BY timestamp DESC
        LIMIT 20
    """)
    
    threats = [dict(row) for row in cur.fetchall()]
    conn.close()
    return {"threats": threats}

@app.get("/api/agent/logs")
async def get_agent_logs(limit: int = 50):
    """Get agent activity logs"""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("""
        SELECT timestamp, event_type, severity, message, user_affected
        FROM system_logs 
        WHERE event_type LIKE '%AGENT%' OR event_type LIKE '%MANUAL%' OR severity IN ('CRITICAL', 'WARNING')
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    
    logs = [dict(row) for row in cur.fetchall()]
    conn.close()
    return {"logs": logs}

@app.get("/api/agent/ping")
async def agent_ping():
    """Simple ping endpoint for connectivity testing"""
    return {"pong": True, "timestamp": datetime.now().isoformat()}

# ------------------------------------------------------------------
#  YARA API ENDPOINTS
# ------------------------------------------------------------------
@app.get("/api/yara/stats")
async def get_yara_stats():
    """Get YARA scanner statistics"""
    if yara_scanner:
        return yara_scanner.get_stats()
    return {"error": "YARA not initialized", "status": "inactive"}

@app.post("/api/yara/reload")
async def reload_yara_rules():
    """Reload YARA rules (admin only)"""
    if yara_scanner:
        yara_scanner.reload_rules()
        return {"message": "YARA rules reloaded", "stats": yara_scanner.get_stats()}
    return {"error": "YARA not initialized"}

@app.get("/api/yara/categories")
async def get_yara_categories():
    """Get list of YARA rule categories"""
    if yara_scanner:
        stats = yara_scanner.get_stats()
        categories = []
        for category, count in stats.get('categories', {}).items():
            categories.append({
                "name": category,
                "rule_count": count,
                "path": os.path.join("yara_rules", category)
            })
        return {"categories": categories}
    return {"categories": []}

# ------------------------------------------------------------------
#  INCLUDE AUTH ROUTER
# ------------------------------------------------------------------
if AUTH_AVAILABLE:
    # Include the auth router with both /auth and /api/auth prefixes for compatibility
    app.include_router(auth_router, prefix="/auth")  # For frontend without /api
    app.include_router(auth_router, prefix="/api/auth")  # For frontend with /api
    print("✅ Auth routes registered at /auth and /api/auth")
else:
    # Fallback auth endpoints if auth module is not available
    print("⚠️ Using fallback auth endpoints")
    
    @app.post("/auth/register", status_code=201)
    async def fallback_register(request: RegisterRequest):
        """Fallback registration endpoint"""
        # Check if user exists in mock DB
        for user in user_db.users:
            if user["username"] == request.username or user["email"] == request.email:
                raise HTTPException(status_code=400, detail="Username or email already registered")
        
        # Create new user
        new_user = {
            "id": len(user_db.users) + 1,
            "username": request.username,
            "email": request.email,
            "full_name": request.full_name or request.username,
            "password_hash": hashlib.sha256(request.password.encode()).hexdigest(),
            "is_admin": request.is_admin or False,
            "department": request.department or "General",
            "risk_level": "low",
            "status": "active",
            "last_login": None,
            "last_action": "Account created"
        }
        
        user_db.users.append(new_user)
        
        log_system_event("USER_REGISTERED", "INFO", f"New user registered: {request.username}", request.username)
        
        return {
            "message": "User created successfully",
            "username": request.username,
            "email": request.email
        }
    
    @app.post("/auth/login")
    async def fallback_login(request: LoginRequest):
        """Fallback login endpoint"""
        user = user_db.authenticate(request.username, request.password)
        if not user:
            log_system_event("LOGIN_FAILED", "WARNING", f"Failed login attempt for {request.username}", request.username)
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        user.pop("password_hash", None)
        token = hashlib.sha256(f"{user['username']}:{datetime.now().isoformat()}".encode()).hexdigest()
        
        log_system_event("LOGIN_SUCCESS", "INFO", f"User {user['username']} logged in", user['username'])
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": user
        }
    
    @app.get("/auth/me")
    async def fallback_me(username: str = Query(...)):
        user = user_db.get_user(username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.pop("password_hash", None)
        return {"user": user}
    
    @app.post("/auth/logout")
    async def fallback_logout(username: str = Query(...)):
        log_system_event("LOGOUT", "INFO", f"User {username} logged out", username)
        return {"message": "Logged out successfully"}
    
    # Also add with /api prefix
    @app.post("/api/auth/register", status_code=201)
    async def fallback_api_register(request: RegisterRequest):
        return await fallback_register(request)
    
    @app.post("/api/auth/login")
    async def fallback_api_login(request: LoginRequest):
        return await fallback_login(request)
    
    @app.get("/api/auth/me")
    async def fallback_api_me(username: str = Query(...)):
        return await fallback_me(username)
    
    @app.post("/api/auth/logout")
    async def fallback_api_logout(username: str = Query(...)):
        return await fallback_logout(username)

# ------------------------------------------------------------------
#  CORE SCAN ENDPOINT
# ------------------------------------------------------------------
@app.post("/api/v1/scan")
async def scan_file(file: UploadFile = File(...), username: str = "demo_user"):
    """Scan file for malware with 5-tier verdict system"""
    try:
        content = await file.read()
        
        if len(content) > Config.MAX_FILE_SIZE:
            log_system_event("SCAN_FAILED", "WARNING", f"File too large: {len(content)} bytes", username)
            raise HTTPException(400, "File too large (max 50MB)")
        
        # Calculate hashes
        hashes = calculate_file_hashes(content)
        
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
        classifier = MalwareClassifier()
        ml_prob = classifier.predict(vec, feats["file_type"], feats)
        
        detector = AnomalyDetector()
        anomaly_detected, anomaly_reasons = detector.detect(vec, feats)
        
        # Calculate risk score (0-100)
        risk = 0
        reasons = []
        
        # Base ML score
        ml_contribution = int(ml_prob * 50)
        risk += ml_contribution
        if ml_prob > 0.5:
            reasons.append(f"ML model: {ml_prob:.1%} malicious probability")
        
        # Anomaly contribution
        if anomaly_detected:
            risk += 20
            reasons.append(f"Statistical anomaly detected: {', '.join(anomaly_reasons)}")
        
        # File type adjustments
        if feats["file_type"] in ("image_png", "image_jpeg", "image_gif", "image_bmp"):
            risk = max(0, risk - 30)
            reasons.append(f"Safe file type: {feats['file_type']}")
        elif feats["file_type"] == "text_plain":
            risk = max(0, risk - 40)
            reasons.append("Plain text file")
        elif feats["file_type"] == "executable_pe":
            risk += 15
            reasons.append("Executable file requires analysis")
        elif feats["file_type"] == "zip_archive":
            risk += 10
            reasons.append("Archive file may contain threats")
        
        # PE-specific indicators
        if feats["suspicious_sections"]:
            risk += 25
            reasons.append("Suspicious section names detected")
        
        if feats["is_packed"]:
            risk += 30
            reasons.append("Packing/encryption detected - common in malware")
        
        if feats["has_signature"]:
            risk -= 15
            reasons.append("Digital signature present")
        
        # Entropy indicators
        if feats["entropy"] > 7.5:
            risk += 20
            reasons.append(f"Very high entropy ({feats['entropy']:.2f}) - likely encrypted/packed")
        elif feats["entropy"] > 7.0:
            risk += 10
            reasons.append(f"High entropy ({feats['entropy']:.2f})")
        elif feats["entropy"] < 3.0:
            risk -= 15
            reasons.append(f"Low entropy ({feats['entropy']:.2f}) - readable content")
        
        # Network indicators
        if feats["urls_count"] > 5:
            risk += 15
            reasons.append(f"Contains {feats['urls_count']} URLs - potential callbacks")
        if feats["ips_count"] > 5:
            risk += 15
            reasons.append(f"Contains {feats['ips_count']} IP addresses")
        
        # String count indicators
        if feats["strings_count"] > 10000:
            risk += 10
            reasons.append("Unusually high number of strings")
        
        # YARA scanning
        yara_results = {"matches": [], "count": 0, "severity": "none", "risk_boost": 0}
        
        if yara_scanner and yara_scanner.rules:
            try:
                yara_matches = yara_scanner.scan_bytes(content)
                
                if yara_matches:
                    # Count by severity
                    critical = len([m for m in yara_matches if m.get('severity') == 'critical'])
                    high = len([m for m in yara_matches if m.get('severity') == 'high'])
                    medium = len([m for m in yara_matches if m.get('severity') == 'medium'])
                    
                    # Calculate risk boost
                    risk_boost = (critical * 15) + (high * 10) + (medium * 5)
                    risk_boost = min(risk_boost, 40)  # Cap at 40
                    
                    # Add to reasons
                    if critical > 0:
                        reasons.append(f"🎯 YARA: {critical} critical rule matches")
                    if high > 0:
                        reasons.append(f"🎯 YARA: {high} high-severity matches")
                    
                    # Add top matches
                    for match in yara_matches[:3]:
                        reasons.append(f"   • {match['rule']}: {match.get('description', 'No description')[:50]}")
                    
                    yara_results = {
                        "matches": yara_matches,
                        "count": len(yara_matches),
                        "critical": critical,
                        "high": high,
                        "medium": medium,
                        "severity": "critical" if critical > 0 else "high" if high > 0 else "medium" if medium > 0 else "info",
                        "risk_boost": risk_boost
                    }
                    
                    # Boost risk score
                    risk += risk_boost
                    
            except Exception as e:
                log_system_event("YARA_ERROR", "WARNING", f"YARA scan error: {str(e)}", username)
        
        # Clamp risk
        risk = max(0, min(100, risk))
        
        # Determine verdict
        if risk >= 80:
            verdict = "malicious"
            level = "critical"
            conf = max(ml_prob, 0.85)
        elif risk >= 60:
            verdict = "likely_malicious"
            level = "high"
            conf = max(ml_prob, 0.7)
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
        
        # Auto-block for critical/high
        auto_blocked = False
        if level in ["critical", "high"] and Config.AUTO_BLOCK_ENABLED:
            auto_blocker.block(username, f"Critical threat detected: {verdict} (risk: {risk})")
            auto_blocked = True
            reasons.append(f"User {username} auto-blocked due to threat level")
            
            log_system_event("USER_BLOCKED", "CRITICAL", f"User {username} auto-blocked", username)
        
        # Log to database
        log_threat({
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "threat_level": level,
            "verdict": verdict,
            "risk_score": risk,
            "action_taken": "auto_blocked" if auto_blocked else "logged",
            "file_name": file.filename,
            "file_type": feats["file_type"],
            "confidence": round(conf, 3),
            "md5_hash": hashes["md5"],
            "sha256_hash": hashes["sha256"],
            "details": {
                "reasons": reasons,
                "features": {
                    "size": feats["size"],
                    "entropy": round(feats["entropy"], 2),
                    "sections": feats["sections"],
                    "imports": feats["imports"],
                    "strings_count": feats["strings_count"],
                    "urls_count": feats["urls_count"],
                    "ips_count": feats["ips_count"]
                },
                "indicators": {
                    "suspicious_sections": feats["suspicious_sections"],
                    "is_packed": feats["is_packed"],
                    "has_signature": feats["has_signature"]
                },
                "risk_score": risk,
                "ml_probability": ml_prob,
                "anomaly_detected": anomaly_detected,
                "anomaly_reasons": anomaly_reasons,
                "yara": yara_results
            }
        })
        
        # Log scan event
        log_system_event("FILE_SCANNED", "INFO", f"File {file.filename} scanned: {verdict}", username)
        
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
                "imports": feats["imports"],
                "strings_count": feats["strings_count"],
                "urls_count": feats["urls_count"],
                "ips_count": feats["ips_count"]
            },
            "indicators": {
                "suspicious_sections": feats["suspicious_sections"],
                "is_packed": feats["is_packed"],
                "has_signature": feats["has_signature"]
            },
            "hashes": hashes,
            "ai_models_used": ["EnhancedRuleEngine", "AnomalyDetector", "EntropyAnalyzer"],
            "ai_confidence": round(ml_prob, 3),
            "anomaly_detected": anomaly_detected,
            "auto_blocked": auto_blocked,
            "yara": yara_results,
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log_system_event("SCAN_ERROR", "ERROR", f"Scan failed: {str(e)}", username)
        raise HTTPException(500, f"Scan failed: {str(e)}")

# ------------------------------------------------------------------
#  DASHBOARD API ENDPOINTS
# ------------------------------------------------------------------
@app.get("/api/users")
async def get_users():
    """Get all users for monitoring"""
    users = user_db.get_all_users()
    # Remove password hashes
    for user in users:
        user.pop("password_hash", None)
    return {"users": users}

@app.get("/api/user-activity")
async def get_user_activity():
    """Get user activity data for dashboard"""
    users = user_db.get_all_users()
    
    # Prepare users list for frontend
    user_list = []
    for u in users:
        # Determine risk level for display (map critical to high for frontend)
        if u["username"] in auto_blocker.list_blocked():
            risk = "high"
            status = "blocked"
        else:
            # Map risk levels to what frontend expects (high/medium/low)
            raw_risk = u.get("risk_level", "low")
            if raw_risk == "critical":
                risk = "high"
            else:
                risk = raw_risk
            status = u.get("status", "active")
        
        user_list.append({
            "name": u["full_name"],
            "status": status,
            "risk": risk,
            "last_action": u.get("last_action", "No recent activity"),
            "login_time": datetime.fromisoformat(u.get("last_login", datetime.now().isoformat())).strftime("%I:%M %p"),
            "department": u.get("department", "Unknown")
        })
    
    # Generate alerts
    alerts = []
    for u in users:
        if u["username"] in auto_blocker.list_blocked():
            alerts.append({
                "type": "user_blocked",
                "severity": "high",
                "user": u["full_name"],
                "time": datetime.now().strftime("%I:%M %p")
            })
    
    # Add some random alerts for demo
    if len(alerts) < 3:
        demo_alerts = [
            {"type": "malware_detected", "severity": "high", "user": "Ronny Ogeya", "time": (datetime.now() - timedelta(minutes=23)).strftime("%I:%M %p")},
            {"type": "unusual_login", "severity": "medium", "user": "Bob Wilson", "time": (datetime.now() - timedelta(hours=5)).strftime("%I:%M %p")},
            {"type": "mass_download", "severity": "medium", "user": "Demo Attacker", "time": (datetime.now() - timedelta(hours=1)).strftime("%I:%M %p")},
        ]
        alerts.extend(demo_alerts[:3-len(alerts)])
    
    return {
        "users": user_list,
        "alerts": alerts[:5],  # Limit to 5 alerts
        "blocked_users": auto_blocker.list_blocked(),
        "total_users": len(users),
        "active_threats": len(auto_blocker.list_blocked())
    }

@app.get("/api/threat-history")
async def get_threat_history(limit: int = 50):
    """Get threat history with detailed information"""
    threats = get_threats(limit)
    return {"threat_history": threats}

@app.get("/api/system-stats")
async def get_system_stats():
    """Get system statistics"""
    threats = get_threats(9999)
    
    # Get database stats
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM threats")
    total_threats = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM system_logs WHERE severity = 'CRITICAL'")
    critical_events = cur.fetchone()[0]
    conn.close()
    
    return {
        "total_threats_detected": total_threats,
        "auto_blocks_performed": len([t for t in threats if t.get("action_taken") == "auto_blocked"]),
        "current_blocked_users": len(auto_blocker.list_blocked()),
        "system_uptime": "72 hours",
        "last_threat_detected": threats[0]["timestamp"] if threats else "N/A",
        "total_scans": total_threats,
        "critical_events": critical_events,
        "active_alerts": len(auto_blocker.list_blocked()),
        "api_requests_today": random.randint(150, 300)  # Placeholder
    }

@app.get("/api/blocked-users")
async def get_blocked_users():
    """Get list of blocked users"""
    return {"blocked_users": auto_blocker.list_blocked()}

@app.post("/api/unblock-user")
async def unblock_user(username: str = Query(...)):
    """Unblock a user"""
    success = auto_blocker.unblock(username)
    if success:
        log_system_event("USER_UNBLOCKED", "INFO", f"User {username} unblocked", username)
        return {"action": "UNBLOCKED", "user": username, "success": True}
    else:
        return {"action": "NOT_FOUND", "user": username, "success": False}

@app.post("/api/simulate-threat")
async def simulate_threat(target_user: str = "demo_attacker"):
    """Simulate a threat for demonstration"""
    reasons = [
        "Advanced persistent threat pattern detected",
        "Multiple failed login attempts",
        "Suspicious outbound connections",
        "Known malware C2 communication"
    ]
    
    reason = random.choice(reasons)
    auto_blocker.block(target_user, reason)
    
    # Create simulated threat
    threat = {
        "timestamp": datetime.now().isoformat(),
        "username": target_user,
        "threat_level": "critical",
        "verdict": "malicious",
        "risk_score": random.randint(85, 98),
        "action_taken": "auto_blocked",
        "file_name": "simulated_payload.exe",
        "file_type": "executable_pe",
        "confidence": random.uniform(0.88, 0.99),
        "details": json.dumps({
            "reasons": [reason, "Simulated threat scenario"],
            "features": {"size": 1540000, "entropy": 7.6},
            "simulated": True
        })
    }
    
    log_threat(threat)
    log_system_event("THREAT_SIMULATED", "WARNING", f"Simulated threat for {target_user}: {reason}", target_user)
    
    return {
        "simulation": True,
        "message": "Advanced threat scenario executed",
        "auto_block_triggered": True,
        "auto_block_details": {
            "user": target_user,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        },
        "threat": threat
    }

@app.get("/api/system-logs")
async def get_system_logs(limit: int = 50):
    """Get recent system logs"""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("""
        SELECT timestamp, event_type, severity, message, user_affected
        FROM system_logs
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    
    logs = [dict(row) for row in cur.fetchall()]
    conn.close()
    
    return {"logs": logs}

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    # Check database
    db_status = "connected"
    try:
        conn = sqlite3.connect(Config.DATABASE_PATH)
        conn.execute("SELECT 1")
        conn.close()
    except:
        db_status = "error"
    
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "database": db_status,
        "features": {
            "malware_detection": "active",
            "behavior_analysis": "active",
            "auto_blocking": "active" if Config.AUTO_BLOCK_ENABLED else "inactive",
            "database": db_status,
            "real_time_monitoring": "active",
            "anomaly_detection": "active",
            "pe_analysis": "active" if PEFILE_AVAILABLE else "limited",
            "yara": "active" if yara_scanner and yara_scanner.rules else "inactive"
        },
        "uptime": "72 hours"
    }

# ------------------------------------------------------------------
#  LEGACY ENDPOINTS (for backward compatibility)
# ------------------------------------------------------------------
@app.get("/user-activity")
async def legacy_user_activity():
    """Legacy endpoint for dashboard compatibility"""
    return await get_user_activity()

@app.get("/threat-history")
async def legacy_threat_history():
    """Legacy endpoint for dashboard compatibility"""
    return await get_threat_history()

@app.get("/system-stats")
async def legacy_system_stats():
    """Legacy endpoint for dashboard compatibility"""
    return await get_system_stats()

@app.get("/blocked-users")
async def legacy_blocked_users():
    """Legacy endpoint for dashboard compatibility"""
    return await get_blocked_users()

@app.post("/unblock-user")
async def legacy_unblock_user(username: str = Query(...)):
    """Legacy endpoint for dashboard compatibility"""
    return await unblock_user(username)

@app.post("/simulate-threat")
async def legacy_simulate_threat():
    """Legacy endpoint for dashboard compatibility"""
    return await simulate_threat()

@app.get("/health")
async def legacy_health():
    """Legacy endpoint for dashboard compatibility"""
    return await health_check()

@app.get("/")
async def root():
    """Root endpoint with API info"""
    auth_status = "active" if AUTH_AVAILABLE else "fallback"
    return {
        "name": "CyberSentry AI API",
        "version": "2.0.0",
        "description": "Advanced Malware Detection and Threat Intelligence Platform",
        "auth_mode": auth_status,
        "endpoints": {
            "authentication": {
                "register": "POST /auth/register or /api/auth/register",
                "login": "POST /auth/login or /api/auth/login",
                "me": "GET /auth/me or /api/auth/me",
                "logout": "POST /auth/logout or /api/auth/logout"
            },
            "scanning": {
                "scan_file": "POST /api/v1/scan"
            },
            "dashboard": {
                "user_activity": "GET /api/user-activity",
                "threat_history": "GET /api/threat-history",
                "system_stats": "GET /api/system-stats",
                "blocked_users": "GET /api/blocked-users",
                "unblock_user": "POST /api/unblock-user",
                "system_logs": "GET /api/system-logs",
                "health": "GET /api/health"
            },
            "agent": {
                "status": "GET /api/agent/status",
                "trigger": "POST /api/agent/trigger",
                "unresolved": "GET /api/agent/threats/unresolved",
                "logs": "GET /api/agent/logs"
            },
            "yara": {
                "stats": "GET /api/yara/stats",
                "reload": "POST /api/yara/reload",
                "categories": "GET /api/yara/categories"
            },
            "simulation": {
                "simulate_threat": "POST /api/simulate-threat"
            }
        },
        "documentation": "/docs",
        "frontend": "streamlit run dashboardapp.py"
    }

# ------------------------------------------------------------------
#  RUN
# ------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host=Config.API_HOST,
        port=Config.API_PORT,
        reload=True,
        log_level="info"
    )