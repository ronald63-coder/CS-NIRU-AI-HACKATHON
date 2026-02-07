import os
import yara
import lief
import magic
import hashlib
import pefile
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any
from config import Config

class YaraScanner:
    def __init__(self):
        self.rules_dir = Path(Config.YARA_RULES_DIR)
        self.compiled_rules = self.rules_dir / "compiled.yarc"
        self.rules = None
        self._compile_rules_once()
    
    def _compile_rules_once(self):
        """Compile YARA rules once for efficiency"""
        try:
            if self.compiled_rules.exists():
                self.rules = yara.load(str(self.compiled_rules))
                return
            
            # Ensure rules directory exists
            self.rules_dir.mkdir(exist_ok=True)
            
            # Get all YARA files
            rule_files = list(self.rules_dir.glob("*.yar"))
            if not rule_files:
                # Create default rule file if none exists
                default_rule = self.rules_dir / "default.yar"
                default_rule.write_text("""
rule demo_rule {
    strings:
        $s1 = "DEMO_MALWARE"
        $s2 = "SUSPICIOUS_STRING"
    condition:
        any of them
}
                """)
                rule_files = [default_rule]
            
            # Compile rules
            rule_paths = {p.stem: str(p) for p in rule_files}
            self.rules = yara.compile(filepaths=rule_paths)
            self.rules.save(str(self.compiled_rules))
            
        except Exception as e:
            print(f"Warning: YARA rule compilation failed: {e}")
            self.rules = None
    
    def extract_file_features(self, file_bytes: bytes) -> Dict[str, Any]:
        """Extract comprehensive file features"""
        features = {
            "basic": {},
            "pe": {},
            "indicators": {}
        }
        
        # Basic file info
        features["basic"]["size"] = len(file_bytes)
        features["basic"]["sha256"] = hashlib.sha256(file_bytes).hexdigest()
        features["basic"]["md5"] = hashlib.md5(file_bytes).hexdigest()
        
        # Magic/File type
        try:
            features["basic"]["file_type"] = magic.from_buffer(file_bytes)
        except:
            features["basic"]["file_type"] = "Unknown"
        
        # Calculate entropy
        features["basic"]["entropy"] = self._calculate_entropy(file_bytes)
        
        # Check if it's a PE file
        if file_bytes[:2] == b"MZ":
            features["basic"]["is_executable"] = True
            pe_features = self._analyze_pe_file(file_bytes)
            features["pe"] = pe_features
            
            # Additional indicators
            if pe_features.get("suspicious_sections", 0) > 0:
                features["indicators"]["suspicious_sections"] = True
            
            if pe_features.get("import_count", 0) == 0:
                features["indicators"]["no_imports"] = True
                
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if len(data) == 0:
            return 0.0
        counts = np.bincount(np.frombuffer(data[:10000], dtype=np.uint8))
        probabilities = counts / len(data[:10000])
        entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
        return float(entropy)
    
    def _analyze_pe_file(self, data: bytes) -> Dict[str, Any]:
        """Analyze PE file structure"""
        pe_info = {"is_pe": True}
        
        try:
            pe = pefile.PE(data=data)
            
            # Basic info
            pe_info["sections"] = len(pe.sections)
            pe_info["imports"] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
            pe_info["exports"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
            
            # Check for suspicious sections
            suspicious_names = ['.packed', '.upx', '.crypt', '.aspack', '.themida']
            pe_info["suspicious_sections"] = 0
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if any(name in section_name.lower() for name in suspicious_names):
                    pe_info["suspicious_sections"] += 1
            
            # Check for suspicious imports
            suspicious_apis = [
                "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                "LoadLibraryA", "GetProcAddress", "URLDownloadToFile"
            ]
            
            suspicious_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and any(api in imp.name.decode() for api in suspicious_apis):
                            suspicious_imports.append(imp.name.decode())
            
            pe_info["suspicious_imports"] = suspicious_imports
            
            pe.close()
            
        except Exception as e:
            pe_info["error"] = str(e)
            pe_info["is_pe"] = False
        
        return pe_info
    
    def scan_file(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Complete file scan with YARA and feature analysis"""
        # Run YARA scan
        yara_matches = []
        if self.rules:
            try:
                matches = self.rules.match(data=file_bytes)
                yara_matches = [{"rule": m.rule, "tags": m.tags} for m in matches]
            except Exception as e:
                print(f"YARA scan error: {e}")
        
        # Extract features
        features = self.extract_file_features(file_bytes)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(features, yara_matches)
        
        # Determine verdict
        verdict, confidence = self._determine_verdict(risk_score, features, yara_matches)
        
        return {
            "filename": filename,
            "verdict": verdict,
            "confidence": confidence,
            "risk_score": risk_score,
            "yara_matches": yara_matches,
            "features": features,
            "timestamp": datetime.now().isoformat()
        }
    
    def _calculate_risk_score(self, features: Dict, yara_matches: List) -> int:
        """Calculate comprehensive risk score"""
        score = 0
        
        # YARA matches
        score += len(yara_matches) * 10
        
        # File size heuristic
        file_size = features.get("basic", {}).get("size", 0)
        if file_size > 10_000_000:  # Over 10MB
            score += 15
        elif file_size < 100:  # Very small
            score += 10
        
        # Entropy check
        entropy = features.get("basic", {}).get("entropy", 0)
        if entropy > 7.0:
            score += 25
        
        # PE-specific checks
        if features.get("pe", {}).get("is_pe", False):
            pe = features["pe"]
            
            if pe.get("suspicious_sections", 0) > 0:
                score += 20
            
            if pe.get("imports", 0) == 0:
                score += 15
            
            if len(pe.get("suspicious_imports", [])) > 0:
                score += len(pe["suspicious_imports"]) * 5
        
        return score
    
    def _determine_verdict(self, risk_score: int, features: Dict, yara_matches: List) -> Tuple[str, float]:
        """Determine final verdict based on risk score"""
        if risk_score >= 70:
            return "malicious", min(0.95, 0.7 + risk_score / 200.0)
        elif risk_score >= 40:
            return "suspicious", min(0.8, 0.5 + risk_score / 200.0)
        elif risk_score >= 20:
            return "suspicious_low", min(0.6, 0.3 + risk_score / 200.0)
        else:
            return "benign", max(0.8, 1.0 - risk_score / 200.0)