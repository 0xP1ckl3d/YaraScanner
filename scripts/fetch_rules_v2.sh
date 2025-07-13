#!/bin/bash
set -e

echo "=== EDR-Safe Scanner Enhanced Rule Fetching v2 Started ==="

# Create rules directory structure
mkdir -p /app/rules/{sigma,yara,compiled,local}
cd /app/rules

# Function to log with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Function to clone or update repo with error handling
clone_or_update() {
    local repo_url="$1"
    local target_dir="$2"
    local branch="${3:-main}"
    
    if [ ! -d "$target_dir" ]; then
        log "Cloning $repo_url to $target_dir..."
        if git clone --depth 1 --branch "$branch" "$repo_url" "$target_dir" 2>/dev/null || \
           git clone --depth 1 "$repo_url" "$target_dir" 2>/dev/null; then
            log "✅ Successfully cloned $repo_url"
        else
            log "⚠️  Failed to clone $repo_url - skipping"
            return 1
        fi
    else
        log "Updating $target_dir..."
        cd "$target_dir"
        if git pull origin "$branch" 2>/dev/null || git pull origin master 2>/dev/null || git pull 2>/dev/null; then
            log "✅ Successfully updated $target_dir"
        else
            log "⚠️  Failed to update $target_dir - using existing"
        fi
        cd - > /dev/null
    fi
    return 0
}

# Initialize sources metadata
cat > /app/rules/sources.json << 'EOF'
{
  "built": "",
  "sources": [],
  "counts": {}
}
EOF

log "Starting enhanced rule collection..."

# 1. Fetch SigmaHQ Sigma rules
clone_or_update "https://github.com/SigmaHQ/sigma.git" "sigma/sigma" "main"
SIGMA_COMMIT=$(cd sigma/sigma 2>/dev/null && git rev-parse HEAD 2>/dev/null || echo "unknown")
log "SigmaHQ commit: $SIGMA_COMMIT"

# 2. Fetch Yara-Rules
clone_or_update "https://github.com/Yara-Rules/rules.git" "yara/yara-rules" "master"
YARA_RULES_COMMIT=$(cd yara/yara-rules 2>/dev/null && git rev-parse HEAD 2>/dev/null || echo "unknown")
log "Yara-Rules commit: $YARA_RULES_COMMIT"

# 3. Fetch 100DaysofYARA 2025
clone_or_update "https://github.com/100DaysofYARA/2025.git" "yara/100DaysofYARA-2025" "main"
YARA_100DAYS_COMMIT=$(cd yara/100DaysofYARA-2025 2>/dev/null && git rev-parse HEAD 2>/dev/null || echo "unknown")
log "100DaysofYARA commit: $YARA_100DAYS_COMMIT"

# 4. Fetch Neo23x0 signature-base
clone_or_update "https://github.com/Neo23x0/signature-base.git" "yara/signature-base" "master"
SIGNATURE_BASE_COMMIT=$(cd yara/signature-base 2>/dev/null && git rev-parse HEAD 2>/dev/null || echo "unknown")
log "signature-base commit: $SIGNATURE_BASE_COMMIT"

# 5. Fetch Mandiant malware-research (if available)
MANDIANT_COMMIT="not_available"
if clone_or_update "https://github.com/mandiant/malware-research.git" "yara/malware-research" "master"; then
    MANDIANT_COMMIT=$(cd yara/malware-research 2>/dev/null && git rev-parse HEAD 2>/dev/null || echo "unknown")
    log "malware-research commit: $MANDIANT_COMMIT"
fi

# 6. Fetch 0x4E0x650x6F yara_signatures (if available)
YARA_SIGS_COMMIT="not_available"
if clone_or_update "https://github.com/0x4E0x650x6F/yara_signatures.git" "yara/yara_signatures" "main" || \
   clone_or_update "https://github.com/0x4E0x650x6F/yara_signatures.git" "yara/yara_signatures" "master"; then
    YARA_SIGS_COMMIT=$(cd yara/yara_signatures 2>/dev/null && git rev-parse HEAD 2>/dev/null || echo "unknown")
    log "yara_signatures commit: $YARA_SIGS_COMMIT"
fi

# 7. Fetch ninoseki boxer (if available)
BOXER_COMMIT="not_available"
if clone_or_update "https://github.com/ninoseki/boxer.git" "yara/boxer" "main" || \
   clone_or_update "https://github.com/ninoseki/boxer.git" "yara/boxer" "master"; then
    BOXER_COMMIT=$(cd yara/boxer 2>/dev/null && git rev-parse HEAD 2>/dev/null || echo "unknown")
    log "boxer commit: $BOXER_COMMIT"
fi

# 8. Fetch Elastic protections-artifacts
clone_or_update "https://github.com/elastic/protections-artifacts.git" "yara/protections-artifacts" "main"
ELASTIC_COMMIT=$(cd yara/protections-artifacts 2>/dev/null && git rev-parse HEAD 2>/dev/null || echo "unknown")
log "protections-artifacts commit: $ELASTIC_COMMIT"

# 9. Fetch YARA Forge bundle (optional)
log "Fetching YARA Forge bundle..."
if [ ! -f "yara/yara-forge-full.zip" ]; then
    wget -O yara/yara-forge-full.zip https://yarahq.github.io/full.zip || log "Warning: YARA Forge download failed"
fi
if [ -f "yara/yara-forge-full.zip" ]; then
    cd yara && unzip -o yara-forge-full.zip -d yara-forge/ > /dev/null 2>&1 && cd ..
fi

# Count rules
cd /app/rules
SIGMA_COUNT=$(find sigma/ -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l)
YARA_COUNT=$(find yara/ -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l)

log "Found $SIGMA_COUNT Sigma rules and $YARA_COUNT YARA rules"

# Export variables for Python script
export SIGMA_COMMIT YARA_RULES_COMMIT YARA_100DAYS_COMMIT SIGNATURE_BASE_COMMIT
export MANDIANT_COMMIT YARA_SIGS_COMMIT BOXER_COMMIT ELASTIC_COMMIT
export SIGMA_COUNT YARA_COUNT

# Generate comprehensive metadata file
python3 << 'EOF'
import json
import os
from datetime import datetime

# Get commit variables from environment, with fallbacks
sigma_commit = os.environ.get('SIGMA_COMMIT', 'unknown')
yara_rules_commit = os.environ.get('YARA_RULES_COMMIT', 'unknown')
yara_100days_commit = os.environ.get('YARA_100DAYS_COMMIT', 'unknown')
signature_base_commit = os.environ.get('SIGNATURE_BASE_COMMIT', 'unknown')
mandiant_commit = os.environ.get('MANDIANT_COMMIT', 'not_available')
yara_sigs_commit = os.environ.get('YARA_SIGS_COMMIT', 'not_available')
boxer_commit = os.environ.get('BOXER_COMMIT', 'not_available')
elastic_commit = os.environ.get('ELASTIC_COMMIT', 'unknown')

# Get rule counts
sigma_count = int(os.environ.get('SIGMA_COUNT', '0'))
yara_count = int(os.environ.get('YARA_COUNT', '0'))

sources_data = {
    "built": datetime.now().isoformat(),
    "sources": [
        {"repo": "SigmaHQ/sigma", "commit": sigma_commit, "type": "sigma"},
        {"repo": "Yara-Rules/rules", "commit": yara_rules_commit, "type": "yara"},
        {"repo": "100DaysofYARA/2025", "commit": yara_100days_commit, "type": "yara"},
        {"repo": "Neo23x0/signature-base", "commit": signature_base_commit, "type": "yara"},
        {"repo": "elastic/protections-artifacts", "commit": elastic_commit, "type": "yara"},
    ],
    "counts": {
        "sigma_rules": sigma_count,
        "yara_rules": yara_count,
        "total_sources": 5
    }
}

# Add optional sources if available
if mandiant_commit != 'not_available':
    sources_data["sources"].append({"repo": "mandiant/malware-research", "commit": mandiant_commit, "type": "yara"})
    sources_data["counts"]["total_sources"] += 1

if yara_sigs_commit != 'not_available':
    sources_data["sources"].append({"repo": "0x4E0x650x6F/yara_signatures", "commit": yara_sigs_commit, "type": "yara"})
    sources_data["counts"]["total_sources"] += 1

if boxer_commit != 'not_available':
    sources_data["sources"].append({"repo": "ninoseki/boxer", "commit": boxer_commit, "type": "yara"})
    sources_data["counts"]["total_sources"] += 1

# Add YARA Forge if downloaded
if os.path.exists('/app/rules/yara/yara-forge-full.zip'):
    sources_data["sources"].append({"repo": "yarahq.github.io", "type": "bundle"})
    sources_data["counts"]["total_sources"] += 1

with open('/app/rules/sources.json', 'w') as f:
    json.dump(sources_data, f, indent=2)
EOF

log "=== Enhanced rule fetching completed ==="
log "Metadata saved to /app/rules/sources.json"
log "Total sources: 9"
log "Rules collected: $SIGMA_COUNT Sigma + $YARA_COUNT YARA"