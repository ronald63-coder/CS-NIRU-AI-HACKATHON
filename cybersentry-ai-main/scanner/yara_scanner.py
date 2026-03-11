# scanner/yara_scanner.py
"""YARA rule scanner for malware detection - Production Ready"""

import os
import yara
import hashlib
import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import json

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class YaraScanner:
    """YARA rule scanner with automatic rule compilation and caching"""
    
    def __init__(self, rules_path: str = "yara_rules"):
        """
        Initialize YARA scanner with rules from specified path
        
        Args:
            rules_path: Path to YARA rules directory
        """
        self.rules_path = os.path.abspath(rules_path)
        self.rules = None
        self.compiled_rules_file = "compiled_yara_rules.yarc"
        self.stats = {
            "total_rules": 0,
            "loaded_files": 0,
            "failed_files": 0,
            "categories": {},
            "last_loaded": None,
            "scan_count": 0,
            "total_matches": 0,
            "avg_scan_time_ms": 0
        }
        self.scan_times = []
        
        # Load rules
        self._load_rules()
    
    def _load_rules(self):
        """Load and compile YARA rules with caching"""
        start_time = time.time()
        
        try:
            # Check if rules path exists
            if not os.path.exists(self.rules_path):
                logger.error(f"❌ Rules path does not exist: {self.rules_path}")
                print(f"\n⚠️  WARNING: YARA rules folder not found at: {self.rules_path}")
                print(f"    Please create the folder and add YARA rules")
                return
            
            # Try to load compiled rules first (faster)
            if os.path.exists(self.compiled_rules_file):
                try:
                    self.rules = yara.load(self.compiled_rules_file)
                    logger.info(f"✅ Loaded compiled rules from cache")
                    self._update_stats_from_rules()
                    return
                except:
                    logger.info("⚠️ Could not load compiled rules, recompiling...")
            
            # Look for index file first (recommended)
            index_file = os.path.join(self.rules_path, "index.yar")
            
            if os.path.exists(index_file):
                logger.info(f"📖 Compiling rules from index: {index_file}")
                self.rules = yara.compile(filepath=index_file)
                self.stats["loaded_files"] = 1
                logger.info(f"✅ YARA rules compiled successfully from index")
                
                # Save compiled rules for faster loading next time
                try:
                    self.rules.save(self.compiled_rules_file)
                    logger.info(f"💾 Saved compiled rules to cache")
                except:
                    pass
                
            else:
                # Compile all .yar and .yara files recursively
                logger.info(f"🔍 Scanning for rule files in: {self.rules_path}")
                rule_files = []
                
                for ext in ['*.yar', '*.yara']:
                    rule_files.extend(Path(self.rules_path).rglob(ext))
                
                if rule_files:
                    # Create namespaces for each file (use relative path)
                    namespaces = {}
                    for rule_file in rule_files:
                        # Use relative path as namespace to avoid conflicts
                        rel_path = str(rule_file.relative_to(self.rules_path))
                        namespaces[rel_path] = str(rule_file)
                        
                        # Count by category (first folder name)
                        category = rule_file.parent.name
                        self.stats["categories"][category] = self.stats["categories"].get(category, 0) + 1
                    
                    # Compile all rules
                    self.rules = yara.compile(filepaths=namespaces)
                    self.stats["loaded_files"] = len(rule_files)
                    logger.info(f"✅ Compiled {len(rule_files)} YARA rule files")
                    
                    # Save compiled rules
                    try:
                        self.rules.save(self.compiled_rules_file)
                        logger.info(f"💾 Saved compiled rules to cache")
                    except:
                        pass
                    
                    # Count total rules (approximate)
                    self._count_rules_in_files(rule_files)
                else:
                    logger.warning("⚠️ No YARA rule files found")
                    print(f"\n⚠️  No YARA rules found in: {self.rules_path}")
                    print(f"    Please add .yar files to the rules folder")
                    self.rules = None
            
            self.stats["last_loaded"] = datetime.now().isoformat()
            load_time = (time.time() - start_time) * 1000
            logger.info(f"⏱️  Rules loaded in {load_time:.2f}ms")
            
        except yara.SyntaxError as e:
            logger.error(f"❌ YARA syntax error: {e}")
            print(f"\n❌ YARA Syntax Error: {e}")
            print(f"   Please check your rule files for errors")
            self.rules = None
        except Exception as e:
            logger.error(f"❌ Failed to load YARA rules: {e}")
            self.rules = None
    
    def _count_rules_in_files(self, rule_files):
        """Count total rules across files"""
        total = 0
        for rule_file in rule_files[:20]:  # Sample first 20 files
            try:
                with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Count "rule " occurrences as a rough estimate
                    total += content.count('rule ')
            except:
                pass
        
        # Extrapolate
        if rule_files:
            self.stats["total_rules"] = int((total / min(20, len(rule_files))) * len(rule_files))
    
    def _update_stats_from_rules(self):
        """Update stats from loaded rules"""
        if self.rules:
            # This is tricky - yara doesn't expose rule count directly
            # We'll approximate based on known structure
            self.stats["loaded_files"] = 1
            self.stats["total_rules"] = 1000  # Rough estimate
            self.stats["categories"] = {"rules": 1}
    
    def scan_file(self, file_path: str, timeout: int = 30) -> List[Dict[str, Any]]:
        """
        Scan a file with YARA rules
        
        Args:
            file_path: Path to file to scan
            timeout: Scan timeout in seconds
            
        Returns:
            List of matches with rule names and metadata
        """
        self.stats["scan_count"] += 1
        start_time = time.time()
        
        if not self.rules:
            logger.debug("⚠️ No YARA rules loaded, skipping scan")
            return []
        
        if not os.path.exists(file_path):
            logger.error(f"❌ File not found: {file_path}")
            return []
        
        try:
            matches = self.rules.match(file_path, timeout=timeout)
            results = self._process_matches(matches)
            
            # Update stats
            scan_time = (time.time() - start_time) * 1000
            self.scan_times.append(scan_time)
            self.scan_times = self.scan_times[-100:]  # Keep last 100
            self.stats["avg_scan_time_ms"] = sum(self.scan_times) / len(self.scan_times)
            self.stats["total_matches"] += len(results)
            
            if results:
                logger.info(f"🔍 YARA found {len(results)} matches in {file_path} ({scan_time:.2f}ms)")
            
            return results
            
        except yara.TimeoutError:
            logger.error(f"⏱️ YARA scan timeout for {file_path}")
            return [{"error": "Scan timeout", "rule": "TIMEOUT"}]
        except Exception as e:
            logger.error(f"❌ YARA scan failed: {e}")
            return [{"error": str(e), "rule": "ERROR"}]
    
    def scan_bytes(self, data: bytes, timeout: int = 30) -> List[Dict[str, Any]]:
        """
        Scan bytes data with YARA rules
        
        Args:
            data: Bytes to scan
            timeout: Scan timeout in seconds
            
        Returns:
            List of matches with rule names and metadata
        """
        self.stats["scan_count"] += 1
        start_time = time.time()
        
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(data=data, timeout=timeout)
            results = self._process_matches(matches)
            
            # Update stats
            scan_time = (time.time() - start_time) * 1000
            self.scan_times.append(scan_time)
            self.scan_times = self.scan_times[-100:]
            self.stats["avg_scan_time_ms"] = sum(self.scan_times) / len(self.scan_times)
            self.stats["total_matches"] += len(results)
            
            return results
            
        except yara.TimeoutError:
            logger.error("⏱️ YARA scan timeout for data scan")
            return [{"error": "Scan timeout", "rule": "TIMEOUT"}]
        except Exception as e:
            logger.error(f"❌ YARA scan failed: {e}")
            return [{"error": str(e), "rule": "ERROR"}]
    
    def _process_matches(self, matches) -> List[Dict[str, Any]]:
        """Process YARA matches into a clean format"""
        results = []
        
        for match in matches:
            # Extract metadata
            meta = match.meta
            severity = self._get_severity_from_meta(meta)
            
            result = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": meta,
                "severity": severity,
                "strings": [],
                "description": meta.get('description', 'No description'),
                "author": meta.get('author', 'Unknown'),
                "reference": meta.get('reference', ''),
                "date": meta.get('date', '')
            }
            
            # Add string match info (limit to 10 to avoid huge output)
            for i, string in enumerate(match.strings[:10]):
                result["strings"].append({
                    "identifier": string.identifier,
                    "instances": len(string.instances),
                    "data": string.instances[0].matched_data[:50].decode(errors='ignore') if string.instances else ''
                })
            
            results.append(result)
        
        return results
    
    def _get_severity_from_meta(self, meta: Dict) -> str:
        """Determine severity from rule metadata"""
        # Check for explicit severity
        if 'severity' in meta:
            severity = str(meta['severity']).lower()
            if severity in ['critical', 'high', 'medium', 'low']:
                return severity
        
        # Check for threat level
        if 'threat_level' in meta:
            level = str(meta['threat_level']).lower()
            if level in ['critical', 'high', 'medium', 'low']:
                return level
        
        # Check tags for severity indicators
        tags = meta.get('tags', [])
        if isinstance(tags, list):
            if 'critical' in tags or 'ransomware' in tags:
                return 'critical'
            if 'high' in tags or 'trojan' in tags:
                return 'high'
            if 'medium' in tags or 'malware' in tags:
                return 'medium'
        
        # Default
        return 'info'
    
    def scan_batch(self, file_paths: List[str], max_workers: int = 4) -> List[Dict]:
        """
        Scan multiple files in parallel
        
        Args:
            file_paths: List of file paths to scan
            max_workers: Number of parallel workers
            
        Returns:
            List of results for each file
        """
        import concurrent.futures
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(self.scan_file, path): path for path in file_paths}
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    matches = future.result()
                    results.append({
                        "file": file_path,
                        "matches": matches,
                        "match_count": len(matches),
                        "status": "success"
                    })
                except Exception as e:
                    results.append({
                        "file": file_path,
                        "error": str(e),
                        "status": "error"
                    })
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        return {
            **self.stats,
            "rules_path": self.rules_path,
            "rules_loaded": self.rules is not None,
            "cache_file_exists": os.path.exists(self.compiled_rules_file)
        }
    
    def reload_rules(self):
        """Force reload of YARA rules"""
        self._load_rules()


# Singleton instance for reuse
_yara_scanner = None


def get_yara_scanner(rules_path: str = "yara_rules") -> YaraScanner:
    """Get or create YARA scanner singleton"""
    global _yara_scanner
    if _yara_scanner is None:
        _yara_scanner = YaraScanner(rules_path)
    return _yara_scanner


def test_yara_installation():
    """Test function to verify YARA is working"""
    print("\n🔍 Testing YARA Installation")
    print("=" * 60)
    
    # Check yara-python version
    print(f"📦 yara-python version: {yara.__version__}")
    
    # Initialize scanner
    scanner = get_yara_scanner()
    stats = scanner.get_stats()
    
    if scanner.rules:
        print(f"✅ YARA rules loaded successfully!")
        print(f"   📁 Rule files: {stats['loaded_files']}")
        print(f"   📊 Total rules: ~{stats['total_rules']}")
        print(f"   📂 Categories: {', '.join(list(stats['categories'].keys())[:5])}")
        
        # Test with EICAR string
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        matches = scanner.scan_bytes(eicar)
        if matches:
            print(f"   🎯 EICAR test: DETECTED ({len(matches)} matches)")
        else:
            print(f"   ℹ️  EICAR test: No matches (expected if no EICAR rule)")
    else:
        print(f"❌ YARA rules not loaded")
        print(f"   Please add rules to: {stats['rules_path']}")
    
    print("=" * 60)
    return scanner.rules is not None


if __name__ == "__main__":
    # Run test when script is executed directly
    test_yara_installation()