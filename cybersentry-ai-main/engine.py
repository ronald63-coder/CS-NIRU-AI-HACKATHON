import os, yara, lief, magic, hashlib, requests
from pathlib import Path

RULES_DIR = Path("rules")
COMPILED = RULES_DIR / "compiled.yarc"

def compile_rules_once():
    if COMPILED.exists():
        return yara.load(str(COMPILED))
    rule_files = {p.stem: str(p) for p in RULES_DIR.glob("*.yar")}
    rules = yara.compile(filepaths=rule_files)
    rules.save(str(COMPILED))
    return rules

def vt_hash_lookup(sha256: str) -> dict:
    """VirusTotal public API (no key → 4 lookups/min)."""
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    # insert your key here when you have one
    # headers = {"x-apikey": os.getenv("VT_KEY")}
    # r = requests.get(url, headers=headers, timeout=6)
    # return r.json() if r.status_code == 200 else {}
    return {}   # stub for now

def pe_features(data: bytes) -> dict:
    feats = {}
    try:
        binary = lief.PE.parse(list(data))
        feats["is_pe"] = True
        feats["sections"] = len(binary.sections)
        feats["imports"]  = len(binary.imports)
        feats["exports"]  = len(binary.export_table.entries) if binary.export_table else 0
        feats["relocations"] = len(binary.relocations)
        feats["suspicious_sections"] = any(s.name in {b".packed", b".upx", b".crypt"} for s in binary.sections)
        # packer detector (very light)
        feats["compile_stamp"] = binary.header.time_date_stamps
        binary = None   # free memory
    except Exception:
        feats["is_pe"] = False
    return feats

def scan_file(file_bytes: bytes, filename: str) -> dict:
    rules = compile_rules_once()
    matches = rules.match(data=file_bytes)

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    vt = vt_hash_lookup(sha256)

    features = pe_features(file_bytes) if file_bytes[:2] == b"MZ" else {}

    # scoring
    risk_score  = len(matches) * 10                    # YARA hit
    risk_score += features.get("suspicious_sections", 0) * 20
    if features.get("imports", 0) == 0 and features.get("is_pe"):
        risk_score += 15                               # no imports ≈ packed
    if vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 5:
        risk_score += 40

    verdict = "malicious" if risk_score >= 60 else "suspicious" if risk_score >= 30 else "benign"
    confidence = min(0.95, 0.60 + risk_score / 150)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk_score,
        "detection_reasons": [m.rule for m in matches] + (
            ["VirusTotal malicious ≥5"] if vt else []) + (
            ["Suspicious section names"] if features.get("suspicious_sections") else []),
        "yara_matches": [m.rule for m in matches],
        "vt_info": vt,
        "features": features
    }