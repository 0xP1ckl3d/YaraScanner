#!/usr/bin/env python3
"""
Proper YARA Rule Compilation for EDR-Safe Scanner
This script compiles comprehensive rules from all sources
"""

import os
import glob
import yaml
import yara
import re
from pathlib import Path

def create_enhanced_sigma_rules():
    """Create enhanced rules for common threats"""
    rules = []
    
    # Enhanced mimikatz detection
    rules.append("""
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
        $s7 = "sid::patch" nocase
        
    condition:
        any of them
}
""")

    # Enhanced PowerShell detection
    rules.append("""
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
        $nop = "-nop" nocase
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
""")

    # UPX Packer detection
    rules.append("""
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
""")

    # Base64 PE detection
    rules.append("""
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
        $decode = "base64" nocase
        
    condition:
        any of ($pe_b64_*) or ($convert and $decode)
}
""")

    # Generic malicious patterns
    rules.append("""
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
""")

    return rules

def compile_comprehensive_rules():
    """Compile all available YARA rules"""
    print("=== Starting Comprehensive YARA Rule Compilation ===")
    
    all_rules = []
    
    # Add our enhanced detection rules
    enhanced_rules = create_enhanced_sigma_rules()
    all_rules.extend(enhanced_rules)
    print(f"Added {len(enhanced_rules)} enhanced detection rules")
    
    # Collect native YARA rules from repositories
    yara_patterns = [
        '/app/rules/yara/yara-rules/malware/*.yar',
        '/app/rules/yara/yara-rules/utils/*.yar', 
        '/app/rules/yara/yara-rules/packers/*.yar',
        '/app/rules/yara/100days-2025/*/*.yar'
    ]
    
    yara_files = []
    for pattern in yara_patterns:
        yara_files.extend(glob.glob(pattern))
    
    print(f"Found {len(yara_files)} YARA rule files")
    
    # Process YARA files
    loaded_count = 0
    for yara_file in yara_files:
        try:
            with open(yara_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Basic validation
            if 'rule ' in content and '{' in content and 'condition:' in content:
                # Clean up content - remove problematic imports/includes
                cleaned_content = re.sub(r'import\s+"[^"]*"', '', content)
                cleaned_content = re.sub(r'include\s+"[^"]*"', '', cleaned_content)
                
                all_rules.append(cleaned_content)
                loaded_count += 1
                
        except Exception as e:
            print(f"Warning: Failed to load {yara_file}: {e}")
            continue
    
    print(f"Successfully loaded {loaded_count} YARA rule files")
    
    # Process Sigma rules (basic conversion for key indicators)
    sigma_files = []
    for pattern in ['/app/rules/sigma/**/rules*/**/*.yml']:
        found = glob.glob(pattern, recursive=True)
        sigma_files.extend([f for f in found if '/.github/' not in f])
    
    print(f"Found {len(sigma_files)} Sigma rule files")
    
    # Convert some key Sigma rules
    sigma_converted = 0
    for sigma_file in sigma_files[:50]:  # Process subset for performance
        try:
            with open(sigma_file, 'r', encoding='utf-8') as f:
                sigma_data = yaml.safe_load(f)
            
            if not sigma_data or 'title' not in sigma_data:
                continue
                
            # Look for specific high-value indicators
            detection = sigma_data.get('detection', {})
            title = sigma_data.get('title', '')
            
            # Convert rules with mimikatz, powershell, or encoding patterns
            if any(keyword in str(detection).lower() or keyword in title.lower() 
                   for keyword in ['mimikatz', 'powershell', 'encoded', 'obfuscat', 'malware']):
                
                rule_name = f"sigma_{re.sub(r'[^a-zA-Z0-9_]', '_', title).lower()}"[:50]
                
                # Extract string patterns
                keywords = []
                def extract_strings(obj):
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            if key not in ['condition', 'timeframe']:
                                extract_strings(value)
                    elif isinstance(obj, list):
                        for item in obj:
                            extract_strings(item)
                    elif isinstance(obj, str) and len(obj) > 2:
                        if not obj.startswith('1 of') and '|' not in obj[:10]:
                            keywords.append(obj)
                
                extract_strings(detection)
                
                if keywords:
                    strings_section = []
                    for i, keyword in enumerate(keywords[:8]):
                        escaped = keyword.replace('"', '\\"').replace('\\', '\\\\')
                        if 3 < len(escaped) < 100 and not escaped.startswith('*'):
                            strings_section.append(f'        $s{i} = "{escaped}" nocase')
                    
                    if strings_section:
                        desc = sigma_data.get('description', '')[:100].replace('"', '\\"')
                        yara_rule = f"""rule {rule_name} {{
    meta:
        description = "{desc}"
        source = "Sigma: {title[:50]}"
        
    strings:
{chr(10).join(strings_section)}
        
    condition:
        any of them
}}"""
                        all_rules.append(yara_rule)
                        sigma_converted += 1
                        
        except Exception as e:
            continue
    
    print(f"Converted {sigma_converted} Sigma rules to YARA")
    
    # Combine all rules
    print(f"Compiling {len(all_rules)} total rules...")
    combined_rules = '\n\n'.join(all_rules)
    
    # Save for debugging
    os.makedirs('/app/rules/compiled', exist_ok=True)
    with open('/app/rules/compiled/comprehensive_rules.yar', 'w') as f:
        f.write(combined_rules)
    
    # Compile rules
    try:
        compiled = yara.compile(source=combined_rules)
        compiled.save('/app/rules/compiled/all_rules.yc')
        
        print(f"✅ Successfully compiled {len(all_rules)} rules!")
        return True
        
    except yara.SyntaxError as e:
        print(f"❌ YARA syntax error: {e}")
        return False
    except Exception as e:
        print(f"❌ Compilation error: {e}")
        return False

if __name__ == "__main__":
    success = compile_comprehensive_rules()
    exit(0 if success else 1)