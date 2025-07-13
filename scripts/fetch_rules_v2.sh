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
SIGMA_COMMIT=$(cd sigma/sigma && git rev-parse HEAD)
log "SigmaHQ commit: $SIGMA_COMMIT"

# 2. Fetch Yara-Rules
clone_or_update "https://github.com/Yara-Rules/rules.git" "yara/yara-rules" "master"
YARA_RULES_COMMIT=$(cd yara/yara-rules && git rev-parse HEAD)
log "Yara-Rules commit: $YARA_RULES_COMMIT"

# 3. Fetch 100DaysofYARA 2025
clone_or_update "https://github.com/100DaysofYARA/2025.git" "yara/100DaysofYARA-2025" "main"
YARA_100DAYS_COMMIT=$(cd yara/100DaysofYARA-2025 && git rev-parse HEAD)
log "100DaysofYARA commit: $YARA_100DAYS_COMMIT"

# 4. NEW: Fetch Neo23x0 signature-base
clone_or_update "https://github.com/Neo23x0/signature-base.git" "yara/signature-base" "master"
SIGNATURE_BASE_COMMIT=$(cd yara/signature-base && git rev-parse HEAD)
log "signature-base commit: $SIGNATURE_BASE_COMMIT"

# 5. NEW: Fetch Mandiant malware-research
clone_or_update "https://github.com/mandiant/malware-research.git" "yara/malware-research" "master"
MANDIANT_COMMIT=$(cd yara/malware-research && git rev-parse HEAD)
log "malware-research commit: $MANDIANT_COMMIT"

# 6. NEW: Fetch 0x4E0x650x6F yara_signatures (try both branches)
if ! clone_or_update "https://github.com/0x4E0x650x6F/yara_signatures.git" "yara/yara_signatures" "main"; then
    clone_or_update "https://github.com/0x4E0x650x6F/yara_signatures.git" "yara/yara_signatures" "master"
fi
YARA_SIGS_COMMIT=$(cd yara/yara_signatures && git rev-parse HEAD)
log "yara_signatures commit: $YARA_SIGS_COMMIT"

# 7. NEW: Fetch ninoseki boxer (try both branches)
if ! clone_or_update "https://github.com/ninoseki/boxer.git" "yara/boxer" "main"; then
    clone_or_update "https://github.com/ninoseki/boxer.git" "yara/boxer" "master"
fi
BOXER_COMMIT=$(cd yara/boxer && git rev-parse HEAD)
log "boxer commit: $BOXER_COMMIT"

# 8. NEW: Fetch Elastic protections-artifacts
clone_or_update "https://github.com/elastic/protections-artifacts.git" "yara/protections-artifacts" "main"
ELASTIC_COMMIT=$(cd yara/protections-artifacts && git rev-parse HEAD)
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
SIGMA_COUNT=$(find sigma/ -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l)
YARA_COUNT=$(find yara/ -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l)

log "Found $SIGMA_COUNT Sigma rules and $YARA_COUNT YARA rules"

# Generate comprehensive metadata file
python3 << EOF
import json
from datetime import datetime

sources_data = {
    "built": datetime.now().isoformat(),
    "sources": [
        {"repo": "SigmaHQ/sigma", "commit": "$SIGMA_COMMIT", "type": "sigma"},
        {"repo": "Yara-Rules/rules", "commit": "$YARA_RULES_COMMIT", "type": "yara"},
        {"repo": "100DaysofYARA/2025", "commit": "$YARA_100DAYS_COMMIT", "type": "yara"},
        {"repo": "Neo23x0/signature-base", "commit": "$SIGNATURE_BASE_COMMIT", "type": "yara"},
        {"repo": "mandiant/malware-research", "commit": "$MANDIANT_COMMIT", "type": "yara"},
        {"repo": "0x4E0x650x6F/yara_signatures", "commit": "$YARA_SIGS_COMMIT", "type": "yara"},
        {"repo": "ninoseki/boxer", "commit": "$BOXER_COMMIT", "type": "yara"},
        {"repo": "elastic/protections-artifacts", "commit": "$ELASTIC_COMMIT", "type": "yara"},
        {"repo": "yarahq.github.io", "type": "bundle"}
    ],
    "counts": {
        "sigma_rules": $SIGMA_COUNT,
        "yara_rules": $YARA_COUNT,
        "total_sources": 9
    }
}

with open('/app/rules/sources.json', 'w') as f:
    json.dump(sources_data, f, indent=2)
EOF

log "=== Enhanced rule fetching completed ==="
log "Metadata saved to /app/rules/sources.json"
log "Total sources: 9"
log "Rules collected: $SIGMA_COUNT Sigma + $YARA_COUNT YARA"