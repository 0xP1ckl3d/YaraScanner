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

rule webshell_detection
{
    meta:
        description = "Webshell Detection"
        source = "EDR-Safe Enhanced"
        
    strings:
        $php1 = "<?php" nocase
        $eval1 = "eval(" nocase
        $post = "$_POST[" nocase
        $get = "$_GET[" nocase
        $system = "system(" nocase
        $shell_exec = "shell_exec(" nocase
        
    condition:
        ($php1 and ($eval1 or $system or $shell_exec)) or
        (($post or $get) and ($eval1 or $system))
}

rule vbs_malicious_patterns
{
    meta:
        description = "VBS Malicious Patterns"
        source = "EDR-Safe Enhanced"
        
    strings:
        $create1 = "CreateObject(" nocase
        $wscript = "Wscript.Shell" nocase
        $cmd = "cmd.exe" nocase
        $powershell = "powershell.exe" nocase
        $bypass = "ExecutionPolicy Bypass" nocase
        
    condition:
        $create1 and ($wscript or $cmd or $powershell or $bypass)
}
