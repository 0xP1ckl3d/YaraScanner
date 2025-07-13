rule enhanced_mimikatz_detection
{
    meta:
        description = "Enhanced Mimikatz Detection"
        source = "EDR-Safe Enhanced"
        
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa::logonpasswords" nocase
        $s3 = "lsadump::sam" nocase
        $s4 = "privilege::debug" nocase
        $s5 = "crypto::capi" nocase
        $s6 = "kerberos::golden" nocase
        
    condition:
        any of them
}

rule enhanced_powershell_obfuscation
{
    meta:
        description = "Enhanced PowerShell Obfuscation Detection"
        source = "EDR-Safe Enhanced"
        
    strings:
        $enc1 = "powershell" nocase
        $enc2 = "-enc" nocase
        $enc3 = "-encodedcommand" nocase
        $enc4 = "-e " nocase
        $hidden1 = "-w hidden" nocase
        $hidden2 = "-windowstyle hidden" nocase
        $bypass1 = "-ep bypass" nocase
        $bypass2 = "-executionpolicy bypass" nocase
        $download = "downloadstring" nocase
        $iex = "iex" nocase
        $invoke = "invoke-expression" nocase
        
    condition:
        ($enc1 and ($enc2 or $enc3 or $enc4)) or
        ($hidden1 or $hidden2) or
        ($bypass1 or $bypass2) or
        ($download and $iex) or
        ($invoke and $download)
}

rule upx_packer_detection
{
    meta:
        description = "UPX Packer Detection"
        source = "EDR-Safe Enhanced"
        
    strings:
        $upx1 = "UPX!" 
        $upx2 = "UPX0"
        $upx3 = "UPX1"
        $mz = { 4D 5A }
        
    condition:
        $mz at 0 and any of ($upx*)
}

rule base64_pe_detection
{
    meta:
        description = "Base64 Encoded PE Detection"
        source = "EDR-Safe Enhanced"
        
    strings:
        $pe_b64_1 = "TVqQAAMAAAAEAAAA" // PE header in base64
        $pe_b64_2 = "TVpQAAIAAAAEAA8A" // Alternative PE header
        $pe_b64_3 = "TVqAAAEAAAAEABAA" // Another variant
        $convert = "FromBase64String" nocase
        
    condition:
        any of ($pe_b64_*) or $convert
}

rule suspicious_patterns
{
    meta:
        description = "Suspicious Patterns Detection"
        source = "EDR-Safe Enhanced"
        
    strings:
        $malware = "malware" nocase
        $virus = "virus" nocase
        $trojan = "trojan" nocase
        $backdoor = "backdoor" nocase
        $payload = "payload" nocase
        $exploit = "exploit" nocase
        $shellcode = "shellcode" nocase
        $dropper = "dropper" nocase
        
    condition:
        any of them
}

rule powershell_execution_policy_bypass
{
    meta:
        description = "PowerShell Execution Policy Bypass"
        source = "EDR-Safe Enhanced"
        
    strings:
        $bypass1 = "-ExecutionPolicy Bypass" nocase
        $bypass2 = "-ep bypass" nocase
        $bypass3 = "-ex bypass" nocase
        $noprofile = "-nop" nocase
        $noprofile2 = "-noprofile" nocase
        
    condition:
        any of ($bypass*) or any of ($noprofile*)
}

rule powershell_hidden_window
{
    meta:
        description = "PowerShell Hidden Window Execution"
        source = "EDR-Safe Enhanced"
        
    strings:
        $hidden1 = "-WindowStyle Hidden" nocase
        $hidden2 = "-w hidden" nocase
        $hidden3 = "-win hidden" nocase
        
    condition:
        any of them
}

rule encoded_powershell_command
{
    meta:
        description = "Encoded PowerShell Command"
        source = "EDR-Safe Enhanced"
        
    strings:
        $powershell = "powershell" nocase
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc" nocase
        $enc3 = "-e " nocase
        
    condition:
        $powershell and any of ($enc*)
}

rule malicious_download_execute
{
    meta:
        description = "Malicious Download and Execute Pattern"
        source = "EDR-Safe Enhanced"
        
    strings:
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $webclient = "Net.WebClient" nocase
        $execute = "IEX" nocase
        $invoke = "Invoke-Expression" nocase
        
    condition:
        (any of ($download*) or $webclient) and (any of ($execute*) or $invoke)
}

rule obfuscated_powershell
{
    meta:
        description = "Obfuscated PowerShell Patterns"
        source = "EDR-Safe Enhanced"
        
    strings:
        $obfus1 = "powershell -w hidden -nop" nocase
        $obfus2 = "powershell.exe -exec bypass" nocase
        $obfus3 = "IEX ((new-object" nocase
        $obfus4 = "FromBase64String" nocase
        
    condition:
        any of them
}
