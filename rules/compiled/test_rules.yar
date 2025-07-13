rule test_suspicious_file {
    meta:
        description = "Test rule for suspicious patterns"
        source = "Test"
        
    strings:
        $s1 = "malware" nocase
        $s2 = "virus" nocase
        $s3 = "trojan" nocase
        
    condition:
        any of them
}

rule test_safe_file {
    meta:
        description = "Test rule for safe patterns"
        source = "Test"
        
    strings:
        $s1 = "hello world" nocase
        $s2 = "safe file" nocase
        
    condition:
        any of them
}
