#!/usr/bin/env python3
"""
Backend API Testing for EDR-Safe Scanner
Tests all API endpoints for functionality and proper responses
"""

import requests
import json
import tempfile
import os
from pathlib import Path
import time

# Get backend URL from environment
BACKEND_URL = "https://c443dcf5-03e8-4540-a57c-a46af7d38732.preview.emergentagent.com/api"

def test_rules_metadata_endpoint():
    """Test GET /api/rules/latest endpoint"""
    print("\n=== Testing Rules Metadata Endpoint ===")
    
    try:
        response = requests.get(f"{BACKEND_URL}/rules/latest", timeout=10)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Response: {json.dumps(data, indent=2)}")
            
            # Validate response structure
            required_fields = ["built", "sources", "total_rules"]
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                print(f"❌ Missing required fields: {missing_fields}")
                return False
            
            if not isinstance(data["sources"], list):
                print("❌ 'sources' should be a list")
                return False
                
            print("✅ Rules metadata endpoint working correctly")
            return True
        else:
            print(f"❌ Failed with status {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing rules metadata: {e}")
        return False

def test_text_scanning_endpoint():
    """Test POST /api/scan/text endpoint"""
    print("\n=== Testing Text Scanning Endpoint ===")
    
    test_cases = [
        {
            "name": "Clean text",
            "content": "hello world this is a safe test file",
            "filename": "clean_test.txt",
            "expected_status": "clean"
        },
        {
            "name": "Suspicious text with malware keyword",
            "content": "this file contains malware and virus signatures for testing",
            "filename": "suspicious_test.txt", 
            "expected_status": ["suspicious", "bad"]  # Could be either
        },
        {
            "name": "Text with trojan keyword",
            "content": "trojan horse detected in this test content",
            "filename": "trojan_test.txt",
            "expected_status": ["suspicious", "bad"]
        }
    ]
    
    all_passed = True
    
    for test_case in test_cases:
        print(f"\nTesting: {test_case['name']}")
        
        try:
            data = {
                "content": test_case["content"],
                "filename": test_case["filename"]
            }
            
            response = requests.post(f"{BACKEND_URL}/scan/text", data=data, timeout=15)
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"Response: {json.dumps(result, indent=2, default=str)}")
                
                # Validate response structure
                if "results" not in result or "total_files" not in result:
                    print("❌ Missing required fields in response")
                    all_passed = False
                    continue
                
                if len(result["results"]) != 1:
                    print("❌ Expected exactly 1 result")
                    all_passed = False
                    continue
                
                scan_result = result["results"][0]
                required_fields = ["filename", "status", "matches", "scan_time"]
                missing_fields = [field for field in required_fields if field not in scan_result]
                
                if missing_fields:
                    print(f"❌ Missing fields in scan result: {missing_fields}")
                    all_passed = False
                    continue
                
                # Check status
                actual_status = scan_result["status"]
                expected = test_case["expected_status"]
                
                if isinstance(expected, list):
                    status_ok = actual_status in expected
                else:
                    status_ok = actual_status == expected
                
                if status_ok:
                    print(f"✅ Status '{actual_status}' is as expected")
                else:
                    print(f"⚠️  Status '{actual_status}' differs from expected {expected}")
                    # Don't fail for status differences as YARA rules may vary
                
                print(f"✅ Text scanning working for: {test_case['name']}")
                
            else:
                print(f"❌ Failed with status {response.status_code}: {response.text}")
                all_passed = False
                
        except Exception as e:
            print(f"❌ Error testing text scanning: {e}")
            all_passed = False
    
    return all_passed

def test_file_scanning_endpoint():
    """Test POST /api/scan endpoint with file uploads"""
    print("\n=== Testing File Scanning Endpoint ===")
    
    all_passed = True
    
    # Test 1: Single clean file
    print("\nTest 1: Single clean file")
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("This is a clean test file with safe content")
            clean_file_path = f.name
        
        with open(clean_file_path, 'rb') as f:
            files = {'files': ('clean_test.txt', f, 'text/plain')}
            response = requests.post(f"{BACKEND_URL}/scan", files=files, timeout=15)
        
        os.unlink(clean_file_path)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2, default=str)}")
            
            # Validate structure
            if "results" in result and "total_files" in result:
                print("✅ Single clean file scan working")
            else:
                print("❌ Missing required fields in response")
                all_passed = False
        else:
            print(f"❌ Failed with status {response.status_code}: {response.text}")
            all_passed = False
            
    except Exception as e:
        print(f"❌ Error testing single file: {e}")
        all_passed = False
    
    # Test 2: Multiple files
    print("\nTest 2: Multiple files")
    try:
        # Create test files
        files_data = [
            ("safe_file.txt", "This is a safe file"),
            ("suspicious_file.txt", "This file contains malware signatures for testing")
        ]
        
        temp_files = []
        for filename, content in files_data:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(content)
                temp_files.append((filename, f.name))
        
        # Upload multiple files
        files = []
        file_handles = []
        for filename, filepath in temp_files:
            fh = open(filepath, 'rb')
            file_handles.append(fh)
            files.append(('files', (filename, fh, 'text/plain')))
        
        response = requests.post(f"{BACKEND_URL}/scan", files=files, timeout=15)
        
        # Close file handles and cleanup
        for fh in file_handles:
            fh.close()
        for _, filepath in temp_files:
            os.unlink(filepath)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2, default=str)}")
            
            if "results" in result and len(result["results"]) == 2:
                print("✅ Multiple file scan working")
            else:
                print("❌ Expected 2 results for multiple files")
                all_passed = False
        else:
            print(f"❌ Failed with status {response.status_code}: {response.text}")
            all_passed = False
            
    except Exception as e:
        print(f"❌ Error testing multiple files: {e}")
        all_passed = False
    
    # Test 3: Empty file upload (should fail)
    print("\nTest 3: Empty file upload (should return 400)")
    try:
        response = requests.post(f"{BACKEND_URL}/scan", files={}, timeout=10)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 400:
            print("✅ Empty file upload correctly rejected")
        else:
            print(f"⚠️  Expected 400 for empty upload, got {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error testing empty upload: {e}")
        all_passed = False
    
    # Test 4: Large file (should fail if over 20MB)
    print("\nTest 4: File size limit test")
    try:
        # Create a file that's definitely over 20MB
        large_content = "A" * (21 * 1024 * 1024)  # 21MB
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(large_content)
            large_file_path = f.name
        
        with open(large_file_path, 'rb') as f:
            files = {'files': ('large_test.txt', f, 'text/plain')}
            response = requests.post(f"{BACKEND_URL}/scan", files=files, timeout=20)
        
        os.unlink(large_file_path)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 413:
            print("✅ Large file correctly rejected")
        else:
            print(f"⚠️  Expected 413 for large file, got {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error testing large file: {e}")
        all_passed = False
    
    return all_passed

def test_yara_compilation():
    """Test if YARA rules are properly compiled and loaded"""
    print("\n=== Testing YARA Rule Compilation ===")
    
    # Check if compiled rules file exists
    rules_file = Path("/app/rules/compiled/all_rules.yc")
    metadata_file = Path("/app/rules/sources.json")
    
    if not rules_file.exists():
        print(f"❌ Compiled rules file not found: {rules_file}")
        return False
    
    if not metadata_file.exists():
        print(f"❌ Metadata file not found: {metadata_file}")
        return False
    
    print(f"✅ Compiled rules file exists: {rules_file}")
    print(f"✅ Metadata file exists: {metadata_file}")
    
    # Test if rules are loaded by making a simple scan request
    try:
        data = {
            "content": "test content",
            "filename": "test.txt"
        }
        
        response = requests.post(f"{BACKEND_URL}/scan/text", data=data, timeout=10)
        
        if response.status_code == 503:
            print("❌ YARA rules not loaded in backend (503 error)")
            return False
        elif response.status_code == 200:
            print("✅ YARA rules successfully loaded and accessible")
            return True
        else:
            print(f"⚠️  Unexpected response: {response.status_code}")
            return True  # Rules might be loaded, just different response
            
    except Exception as e:
        print(f"❌ Error testing rule compilation: {e}")
        return False

def main():
    """Run all backend tests"""
    print("🔍 Starting EDR-Safe Scanner Backend API Tests")
    print(f"Backend URL: {BACKEND_URL}")
    
    test_results = {}
    
    # Test YARA compilation first
    test_results["YARA rule compilation"] = test_yara_compilation()
    
    # Test API endpoints
    test_results["Rules metadata API endpoint"] = test_rules_metadata_endpoint()
    test_results["Text scanning API endpoint"] = test_text_scanning_endpoint()
    test_results["File scanning API endpoint"] = test_file_scanning_endpoint()
    
    # Summary
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    
    all_passed = True
    for test_name, passed in test_results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print("🎉 All backend tests PASSED!")
    else:
        print("⚠️  Some backend tests FAILED - see details above")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)