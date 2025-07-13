#!/usr/bin/env python3
"""
Test script to verify bug fix for /scan endpoint
Tests all provided sample files to ensure proper detection
"""

import requests
import json
import os
from pathlib import Path

BACKEND_URL = "https://c443dcf5-03e8-4540-a57c-a46af7d38732.preview.emergentagent.com/api"

def test_file_scanning(filename, expected_status, description):
    """Test a specific file and verify expected status"""
    print(f"\n=== Testing: {filename} ===")
    print(f"Description: {description}")
    print(f"Expected status: {expected_status}")
    
    filepath = f"/app/test_files/{filename}"
    
    try:
        with open(filepath, 'rb') as f:
            files = {'files': (filename, f, 'application/octet-stream')}
            response = requests.post(f"{BACKEND_URL}/scan", files=files, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            scan_result = result["results"][0]
            actual_status = scan_result["status"]
            matches = scan_result["matches"]
            
            print(f"Actual status: {actual_status}")
            print(f"Matches: {matches}")
            
            # Check if status matches expectation
            if isinstance(expected_status, list):
                status_ok = actual_status in expected_status
            else:
                status_ok = actual_status == expected_status
            
            if status_ok:
                print("✅ PASS - Status matches expectation")
                return True
            else:
                print(f"❌ FAIL - Expected {expected_status}, got {actual_status}")
                return False
        else:
            print(f"❌ HTTP Error: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

def main():
    """Run all test cases"""
    print("🧪 Testing EDR-Safe Scanner Bug Fix")
    print("=" * 50)
    
    test_cases = [
        ("benign-text.txt", "clean", "Plain ASCII text"),
        ("suspicious-powershell.txt", ["suspicious", "bad"], "PowerShell -Enc pattern"),
        ("bad-mimikatz.txt", ["suspicious", "bad"], "mimikatz indicator"),
        ("packed-marker.bin", ["suspicious", "bad"], "MZ + UPX! header"),
        ("encoded-script.ps1", ["suspicious", "bad"], "Embedded base64 PE header"),
        ("mixed-good-and-bad.txt", ["suspicious", "bad"], "Contains obfuscated PS")
    ]
    
    results = []
    
    for filename, expected_status, description in test_cases:
        success = test_file_scanning(filename, expected_status, description)
        results.append((filename, success))
    
    # Summary
    print("\n" + "=" * 50)
    print("🎯 TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for filename, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {filename}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED - Bug fix successful!")
    else:
        print("⚠️  Some tests failed - needs investigation")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
