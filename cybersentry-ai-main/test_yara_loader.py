#!/usr/bin/env python3
"""
Complete YARA Scanner Test Script
Tests all functionality of the YARA scanner without running the full backend
"""

import os
import sys
import json
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 70)
print("🛡️  CYBERSENTRY AI - YARA SCANNER COMPLETE TEST")
print("=" * 70)

# Test 1: Check yara-python installation
print("\n📦 TEST 1: Checking yara-python installation")
print("-" * 50)
try:
    import yara
    print(f"✅ YARA Python version: {yara.__version__}")
    print(f"✅ YARA lib version: {yara.YARA_VERSION}")
except ImportError as e:
    print(f"❌ Failed to import yara: {e}")
    print("   Run: pip install yara-python")
    sys.exit(1)

# Test 2: Import our scanner
print("\n🔧 TEST 2: Importing YARA scanner")
print("-" * 50)
try:
    from scanner.yara_scanner import get_yara_scanner, YaraScanner, test_yara_installation
    print("✅ Successfully imported YARA scanner")
except ImportError as e:
    print(f"❌ Failed to import scanner: {e}")
    print("   Check that scanner/yara_scanner.py exists")
    sys.exit(1)

# Test 3: Run installation test
print("\n🔍 TEST 3: Running YARA installation test")
print("-" * 50)
test_yara_installation()

# Test 4: Initialize scanner
print("\n🚀 TEST 4: Initializing YARA scanner")
print("-" * 50)
try:
    scanner = get_yara_scanner("yara_rules")
    stats = scanner.get_stats()
    
    print(f"✅ Scanner initialized")
    print(f"   Rules loaded: {stats['loaded_files'] > 0}")
    print(f"   Rule files: {stats['loaded_files']}")
    print(f"   Total rules (approx): {stats['total_rules']}")
    print(f"   Categories found: {len(stats.get('categories', {}))}")
    
    if stats['loaded_files'] > 0:
        print(f"\n📂 Categories:")
        for category, count in list(stats.get('categories', {}).items())[:10]:
            print(f"   • {category}: {count} files")
        if len(stats.get('categories', {})) > 10:
            print(f"   ... and {len(stats.get('categories', {})) - 10} more")
    else:
        print("⚠️ No rules loaded - check your yara_rules folder")
        
except Exception as e:
    print(f"❌ Failed to initialize scanner: {e}")

# Test 5: Test with EICAR test string
print("\n🦠 TEST 5: Testing with EICAR test string")
print("-" * 50)

# EICAR test string - standard antivirus test file
eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

print(f"   Testing with EICAR string ({len(eicar)} bytes)")
start_time = time.time()
matches = scanner.scan_bytes(eicar)
scan_time = (time.time() - start_time) * 1000

if matches:
    print(f"✅ YARA detected the test string!")
    print(f"   Found {len(matches)} matches in {scan_time:.2f}ms")
    for i, match in enumerate(matches[:3]):  # Show first 3 matches
        print(f"\n   Match {i+1}:")
        print(f"      Rule: {match.get('rule', 'Unknown')}")
        print(f"      Severity: {match.get('severity', 'unknown')}")
        print(f"      Description: {match.get('description', 'No description')[:100]}")
else:
    print(f"ℹ️ No matches found for EICAR (scan took {scan_time:.2f}ms)")
    print("   This is normal if your rules don't include EICAR detection")

# Test 6: Test with a simple text file
print("\n📄 TEST 6: Testing with simple text content")
print("-" * 50)

test_text = b"This is a completely safe text file with no malware. The quick brown fox jumps over the lazy dog."
print(f"   Testing with safe text ({len(test_text)} bytes)")

matches = scanner.scan_bytes(test_text)
if matches:
    print(f"⚠️ Found {len(matches)} matches in safe text (possible false positives)")
    for match in matches[:2]:
        print(f"   • {match.get('rule')}")
else:
    print(f"✅ No matches found - text appears clean")

# Test 7: Test with PE file signature (MZ header)
print("\n💾 TEST 7: Testing with PE file header")
print("-" * 50)

# Minimal PE header (just MZ marker)
pe_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
print(f"   Testing with PE header ({len(pe_header)} bytes)")

matches = scanner.scan_bytes(pe_header)
if matches:
    print(f"✅ Found {len(matches)} matches in PE header")
    for match in matches[:3]:
        print(f"   • {match.get('rule')} ({match.get('severity', 'unknown')})")
else:
    print(f"ℹ️ No matches found for PE header")

# Test 8: Test batch scanning
print("\n📚 TEST 8: Testing batch scanning (multiple files)")
print("-" * 50)

# Create temporary test files
import tempfile
test_files = []

for i in range(5):
    fd, path = tempfile.mkstemp(suffix='.txt')
    with os.fdopen(fd, 'w') as f:
        f.write(f"Test file {i} with {'malicious' if i % 2 == 0 else 'safe'} content")
    test_files.append(path)
    print(f"   Created test file: {os.path.basename(path)}")

print(f"\n   Scanning {len(test_files)} files in batch mode...")
start_time = time.time()
batch_results = scanner.scan_batch(test_files, max_workers=3)
batch_time = (time.time() - start_time) * 1000

print(f"   Batch scan completed in {batch_time:.2f}ms")
print(f"   Results:")

for result in batch_results:
    status = "✅ Clean" if result['match_count'] == 0 else f"⚠️ {result['match_count']} matches"
    print(f"   • {os.path.basename(result['file'])}: {status}")

# Clean up temp files
for path in test_files:
    try:
        os.unlink(path)
    except:
        pass

# Test 9: Test scanner statistics
print("\n📊 TEST 9: Scanner statistics")
print("-" * 50)

stats = scanner.get_stats()
print(f"   Total scans performed: {stats.get('scan_count', 0)}")
print(f"   Total matches found: {stats.get('total_matches', 0)}")
print(f"   Average scan time: {stats.get('avg_scan_time_ms', 0):.2f}ms")
print(f"   Rules loaded: {stats.get('loaded_files', 0)} files")
print(f"   Cache file exists: {stats.get('cache_file_exists', False)}")

# Test 10: Test error handling
print("\n⚠️ TEST 10: Testing error handling")
print("-" * 50)

# Test with non-existent file
print("   Testing with non-existent file...")
matches = scanner.scan_file("nonexistent_file_123456789.exe")
if matches and matches[0].get('error'):
    print(f"   ✅ Proper error: {matches[0].get('error')}")
else:
    print("   ⚠️ Unexpected result from non-existent file")

# Test with empty bytes
print("   Testing with empty bytes...")
matches = scanner.scan_bytes(b'')
print(f"   ✅ Scan completed with empty input")

# Test 11: Performance benchmark
print("\n⚡ TEST 11: Performance benchmark")
print("-" * 50)

# Generate test data of different sizes
test_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB

for size in test_sizes:
    test_data = os.urandom(size)  # Random data
    start_time = time.time()
    matches = scanner.scan_bytes(test_data)
    scan_time = (time.time() - start_time) * 1000
    print(f"   {size:6d} bytes: {scan_time:6.2f}ms ({len(test_data)/1024:.1f}KB)")

# Test 12: Memory usage check
print("\n💾 TEST 12: Memory usage")
print("-" * 50)

import psutil
process = psutil.Process()
memory_info = process.memory_info()
print(f"   RSS Memory: {memory_info.rss / 1024 / 1024:.2f} MB")
print(f"   VMS Memory: {memory_info.vms / 1024 / 1024:.2f} MB")

# Summary
print("\n" + "=" * 70)
print("📋 TEST SUMMARY")
print("=" * 70)

if scanner.rules:
    print(f"\n✅ YARA Scanner is READY for production!")
    print(f"\n   📁 Rule files: {stats.get('loaded_files', 0)}")
    print(f"   📊 Total rules: ~{stats.get('total_rules', 0)}")
    print(f"   📂 Categories: {len(stats.get('categories', {}))}")
    print(f"   ⚡ Avg scan time: {stats.get('avg_scan_time_ms', 0):.1f}ms")
    
    print(f"\n🎯 Next steps:")
    print(f"   1. Start your backend: python app.py")
    print(f"   2. Start your dashboard: streamlit run dashboardapp.py")
    print(f"   3. Upload a file to test the full integration")
else:
    print(f"\n⚠️ YARA Scanner initialized but NO RULES LOADED")
    print(f"\n   Please check your yara_rules folder:")
    print(f"   Path: {os.path.abspath('yara_rules')}")
    print(f"\n   To fix:")
    print(f"   1. Make sure the folder exists")
    print(f"   2. Add YARA rules (.yar files) to the folder")
    print(f"   3. Run this test again")

print("\n" + "=" * 70)