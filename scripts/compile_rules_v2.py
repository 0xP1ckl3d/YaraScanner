#!/usr/bin/env python3
"""
Enhanced Modular YARA Rule Compilation System v2
- Deduplicates rules based on content hash
- Compiles into specialized bundles (pe.yc, scripts.yc, webshells.yc, generic.yc)
- Tracks memory usage and statistics
- Supports local rule overlays
"""

import os
import sys
import glob
import hashlib
import json
import re
import yara
import psutil
from pathlib import Path
from collections import defaultdict
import tempfile

class YARARuleCompiler:
    def __init__(self):
        self.rules_dir = Path("/app/rules")
        self.compiled_dir = self.rules_dir / "compiled"
        self.local_dir = self.rules_dir / "local"
        self.compiled_dir.mkdir(exist_ok=True)
        self.local_dir.mkdir(exist_ok=True)
        
        # Rule categorization patterns
        self.bundle_patterns = {
            'pe': [
                r'import\s+"pe"',
                r'pe\.',
                r'PE\d*Header',
                r'MZ|DOS_Stub',
                r'ImportTable|ExportTable',
                r'FileAlignment|SectionAlignment',
                r'IMAGE_NT_HEADERS'
            ],
            'scripts': [
                r'powershell',
                r'javascript|jscript',
                r'vbscript|vbs',
                r'python|perl',
                r'shell|bash|cmd',
                r'macro|office',
                r'encoded|obfuscat',
                r'-enc|-decode'
            ],
            'webshells': [
                r'webshell',
                r'<?php|<%|asp',
                r'eval\s*\(',
                r'base64_decode',
                r'shell_exec|system\(',
                r'backdoor.*web',
                r'upload.*shell'
            ]
        }
        
        # Helper plaintext rules
        self.helper_rules = {
            'generic': [
                '''rule _plain_mimikatz {
    meta:
        description = "Plain mimikatz detection"
        source = "EDR-Safe Helper"
    strings:
        $ = /mimikatz(\.exe)?/ nocase ascii wide
    condition:
        $
}''',
                '''rule _plain_upx {
    meta:
        description = "Plain UPX detection"
        source = "EDR-Safe Helper"
    strings:
        $ = "UPX!"
    condition:
        $
}''',
                '''rule _plain_powershell_enc {
    meta:
        description = "Plain PowerShell encoded command detection"
        source = "EDR-Safe Helper"
    strings:
        $ = /powershell\.exe\s+-[Ee]nc/ nocase ascii
    condition:
        $
}''',
                '''rule _plain_suspicious_extensions {
    meta:
        description = "Suspicious file extensions in content"
        source = "EDR-Safe Helper"
    strings:
        $scr = ".scr" nocase
        $pif = ".pif" nocase
        $com = ".com" nocase
        $bat = ".bat" nocase
        $cmd = ".cmd" nocase
    condition:
        any of them
}''',
                '''rule _plain_malware_keywords {
    meta:
        description = "Common malware keywords"
        source = "EDR-Safe Helper"
    strings:
        $virus = "virus" nocase
        $trojan = "trojan" nocase
        $malware = "malware" nocase
        $backdoor = "backdoor" nocase
        $keylogger = "keylogger" nocase
        $rootkit = "rootkit" nocase
    condition:
        any of them
}'''
            ]
        }
        
        self.rule_hashes = set()
        self.duplicate_count = 0
        
    def log(self, message):
        """Timestamp logging"""
        import datetime
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{timestamp} - {message}")
        
    def get_memory_usage_mb(self):
        """Get current RSS memory usage in MB"""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
        
    def hash_rule_content(self, rule_content):
        """Create hash of rule content for deduplication"""
        # Extract strings and condition sections for comparison
        strings_match = re.search(r'strings:\s*(.*?)\s*condition:', rule_content, re.DOTALL | re.IGNORECASE)
        condition_match = re.search(r'condition:\s*(.*?)\s*}', rule_content, re.DOTALL | re.IGNORECASE)
        
        if strings_match and condition_match:
            # Sort strings for consistent hashing
            strings_section = strings_match.group(1).strip()
            condition_section = condition_match.group(1).strip()
            
            # Normalize whitespace and sort string definitions
            string_lines = [line.strip() for line in strings_section.split('\n') if line.strip() and '$' in line]
            string_lines.sort()
            
            content_to_hash = '\n'.join(string_lines) + '\n' + condition_section
            return hashlib.md5(content_to_hash.encode()).hexdigest()
        
        # Fallback to simple rule name hash
        rule_match = re.search(r'rule\s+([a-zA-Z_][a-zA-Z0-9_]*)', rule_content)
        if rule_match:
            return hashlib.md5(rule_match.group(1).encode()).hexdigest()
        
        return hashlib.md5(rule_content.encode()).hexdigest()
        
    def is_duplicate_rule(self, rule_content):
        """Check if rule is duplicate based on content hash"""
        rule_hash = self.hash_rule_content(rule_content)
        if rule_hash in self.rule_hashes:
            self.duplicate_count += 1
            return True
        self.rule_hashes.add(rule_hash)
        return False
        
    def categorize_rule(self, rule_content, filename=""):
        """Categorize rule into appropriate bundle"""
        content_lower = rule_content.lower()
        filename_lower = filename.lower()
        
        # Check PE bundle patterns
        for pattern in self.bundle_patterns['pe']:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return 'pe'
                
        # Check scripts bundle patterns  
        for pattern in self.bundle_patterns['scripts']:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return 'scripts'
                
        # Check webshells bundle patterns
        for pattern in self.bundle_patterns['webshells']:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return 'webshells'
                
        # Check filename-based categorization
        if any(term in filename_lower for term in ['webshell', 'web', 'php', 'asp']):
            return 'webshells'
        if any(term in filename_lower for term in ['pe', 'executable', 'binary']):
            return 'pe'
        if any(term in filename_lower for term in ['script', 'powershell', 'js', 'vbs']):
            return 'scripts'
            
        return 'generic'
        
    def collect_yara_files(self):
        """Collect all YARA files from repositories"""
        yara_files = []
        
        # Collection patterns for different repositories
        patterns = [
            '/app/rules/yara/yara-rules/**/*.yar',
            '/app/rules/yara/yara-rules/**/*.yara',
            '/app/rules/yara/100days-2025/**/*.yar',
            '/app/rules/yara/signature-base/**/*.yar',
            '/app/rules/yara/malware-research/**/*.yar',
            '/app/rules/yara/yara_signatures/**/*.yar',
            '/app/rules/yara/boxer/**/*.yar',
            '/app/rules/yara/protections-artifacts/yara/**/*.yar',
            '/app/rules/yara/yara-forge/**/*.yar'
        ]
        
        for pattern in patterns:
            found_files = glob.glob(pattern, recursive=True)
            yara_files.extend(found_files)
            
        # Add local rules if they exist
        local_patterns = ['/app/rules/local/*.yar', '/app/rules/local/*.yara']
        for pattern in local_patterns:
            yara_files.extend(glob.glob(pattern))
            
        self.log(f"Found {len(yara_files)} YARA rule files")
        return yara_files
        
    def process_yara_file(self, filepath):
        """Process a single YARA file and extract rules"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Skip files with problematic imports/includes or known issues
            if any(skip in content.lower() for skip in ['cuckoo', 'private rule', 'global rule']):
                return []
                
            # Skip files with imports other than standard ones
            if re.search(r'import\s+["\'](?!pe|math|hash|elf|dotnet)["\']', content):
                return []
                
            # Clean up content - remove problematic imports/includes
            content = re.sub(r'include\s+["\'][^"\']*["\']', '', content)
            content = re.sub(r'import\s+["\'](?!pe|math|hash|elf|dotnet)[^"\']*["\']', '', content)
            
            # Split into individual rules - improved parsing
            rules = []
            
            # Find rule boundaries more accurately
            rule_starts = []
            for match in re.finditer(r'^\s*rule\s+[a-zA-Z_][a-zA-Z0-9_]*\s*[:{]', content, re.MULTILINE | re.IGNORECASE):
                rule_starts.append(match.start())
            
            # Extract each rule
            for i, start in enumerate(rule_starts):
                # Find the end of this rule
                end = rule_starts[i + 1] if i + 1 < len(rule_starts) else len(content)
                
                # Extract rule content
                rule_content = content[start:end].strip()
                
                # Validate rule structure
                if self.validate_rule_structure(rule_content):
                    if not self.is_duplicate_rule(rule_content):
                        rules.append(rule_content)
                        
            return rules
            
        except Exception as e:
            self.log(f"Warning: Failed to process {filepath}: {e}")
            return []
    
    def validate_rule_structure(self, rule_content):
        """Validate that rule has proper structure"""
        # Must have rule declaration
        if not re.search(r'rule\s+[a-zA-Z_][a-zA-Z0-9_]*', rule_content, re.IGNORECASE):
            return False
            
        # Must have condition section
        if 'condition:' not in rule_content.lower():
            return False
            
        # Check for balanced braces
        open_braces = rule_content.count('{')
        close_braces = rule_content.count('}')
        if open_braces != close_braces or open_braces == 0:
            return False
            
        # Ensure rule ends with }
        if not rule_content.strip().endswith('}'):
            return False
            
        # Check for incomplete strings section
        strings_match = re.search(r'strings:\s*(.*?)\s*condition:', rule_content, re.DOTALL | re.IGNORECASE)
        if strings_match:
            strings_section = strings_match.group(1).strip()
            # Check for incomplete string definitions
            if strings_section and not re.search(r'\$\w+\s*=.*(?:"[^"]*"|/[^/]*/|\{[^}]*\})', strings_section):
                return False
                
        return True
            
    def compile_bundle(self, bundle_name, rules):
        """Compile rules into a specific bundle"""
        if not rules:
            self.log(f"No rules for {bundle_name} bundle")
            return False
            
        self.log(f"Compiling {bundle_name} bundle with {len(rules)} rules...")
        
        # Add helper rules for generic bundle
        if bundle_name == 'generic':
            rules.extend(self.helper_rules['generic'])
            
        combined_rules = '\n\n'.join(rules)
        
        try:
            # Test compilation first
            compiled = yara.compile(source=combined_rules)
            
            # Save compiled bundle
            bundle_path = self.compiled_dir / f"{bundle_name}.yc"
            compiled.save(str(bundle_path))
            
            self.log(f"✅ {bundle_name}.yc compiled successfully ({len(rules)} rules)")
            return True
            
        except yara.SyntaxError as e:
            self.log(f"❌ YARA syntax error in {bundle_name}: {e}")
            
            # Save problematic rules for debugging
            debug_path = self.compiled_dir / f"{bundle_name}_debug.yar"
            with open(debug_path, 'w') as f:
                f.write(combined_rules)
            
            return False
        except Exception as e:
            self.log(f"❌ Compilation error for {bundle_name}: {e}")
            return False
            
    def create_weekly_cron(self):
        """Create weekly cron job for rule refresh"""
        cron_script = '''#!/bin/bash
# Weekly rule refresh for EDR-Safe Scanner
# Runs every Monday at 3:00 AM AEST

set -e

echo "$(date): Starting weekly rule refresh..."

# Navigate to rules directory
cd /app

# Run rule fetching
if /app/scripts/fetch_rules.sh; then
    echo "$(date): Rule fetching completed"
    
    # Run rule compilation  
    if python3 /app/scripts/compile_rules_v2.py; then
        echo "$(date): Rule compilation completed"
        
        # Restart application
        supervisorctl restart backend
        echo "$(date): Application restarted successfully"
    else
        echo "$(date): ERROR - Rule compilation failed"
        exit 1
    fi
else
    echo "$(date): ERROR - Rule fetching failed"
    exit 1
fi

echo "$(date): Weekly refresh completed successfully"
'''
        
        # Create cron script
        cron_script_path = Path("/app/scripts/weekly_refresh.sh")
        with open(cron_script_path, 'w') as f:
            f.write(cron_script)
        os.chmod(cron_script_path, 0o755)
        
        # Install cron job
        cron_entry = "0 3 * * 1 root /app/scripts/weekly_refresh.sh >> /var/log/rule_refresh.log 2>&1\n"
        
        try:
            # Add to crontab
            with open("/etc/crontab", "a") as f:
                f.write(cron_entry)
            self.log("✅ Weekly cron job installed")
        except Exception as e:
            self.log(f"Warning: Could not install cron job: {e}")
            
    def compile_all_bundles(self):
        """Main compilation process"""
        self.log("=== Starting Enhanced YARA Compilation v2 ===")
        
        start_memory = self.get_memory_usage_mb()
        self.log(f"Starting memory usage: {start_memory:.1f} MB")
        
        # Collect all YARA files
        yara_files = self.collect_yara_files()
        
        # Process files and categorize rules
        bundles = defaultdict(list)
        total_rules = 0
        
        for filepath in yara_files:
            rules = self.process_yara_file(filepath)
            total_rules += len(rules)
            
            for rule in rules:
                category = self.categorize_rule(rule, filepath)
                bundles[category].append(rule)
                
        self.log(f"Processed {total_rules} unique rules (skipped {self.duplicate_count} duplicates)")
        self.log(f"Bundle distribution:")
        for bundle, rules in bundles.items():
            self.log(f"  {bundle}: {len(rules)} rules")
            
        # Compile each bundle
        compiled_bundles = {}
        for bundle_name, rules in bundles.items():
            if rules:  # Only compile non-empty bundles
                success = self.compile_bundle(bundle_name, rules)
                compiled_bundles[bundle_name] = len(rules) if success else 0
                
        # Update metadata with compilation stats
        self.update_compilation_stats(compiled_bundles, total_rules)
        
        # Create weekly cron job
        self.create_weekly_cron()
        
        final_memory = self.get_memory_usage_mb()
        self.log(f"Final memory usage: {final_memory:.1f} MB")
        self.log(f"Memory increase: {final_memory - start_memory:.1f} MB")
        
        # Validate memory constraint
        if final_memory > 1800:  # 1.8GB threshold
            self.log(f"⚠️  WARNING: Memory usage {final_memory:.1f}MB exceeds 1.8GB threshold!")
            return False
            
        self.log("=== Enhanced compilation completed successfully ===")
        return True
        
    def update_compilation_stats(self, compiled_bundles, total_rules):
        """Update sources.json with compilation statistics"""
        sources_file = self.rules_dir / "sources.json"
        
        try:
            if sources_file.exists():
                with open(sources_file, 'r') as f:
                    data = json.load(f)
            else:
                data = {"sources": []}
                
            # Add compilation metadata
            data.update({
                "compilation": {
                    "bundles": compiled_bundles,
                    "total_unique_rules": total_rules,
                    "duplicates_removed": self.duplicate_count,
                    "memory_usage_mb": self.get_memory_usage_mb()
                }
            })
            
            with open(sources_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            self.log(f"Warning: Could not update compilation stats: {e}")

def main():
    """Main entry point"""
    compiler = YARARuleCompiler()
    success = compiler.compile_all_bundles()
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())