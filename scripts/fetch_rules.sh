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

# Initialize sources metadata
cat > /app/rules/sources.json << 'EOF'
{
  "built": "",
  "sources": [],
  "counts": {}
}
EOF

SOURCES_JSON="/app/rules/sources.json"

# Function to update sources metadata
update_source() {
    local repo_name="$1"
    local commit_hash="$2"
    local repo_type="$3"
    
    python3 << EOF
import json
import sys

try:
    with open('$SOURCES_JSON', 'r') as f:
        data = json.load(f)
    
    # Update or add source
    source_entry = {
        "repo": "$repo_name",
        "commit": "$commit_hash",
        "type": "$repo_type"
    }
    
    # Check if source already exists and update it
    updated = False
    for i, source in enumerate(data["sources"]):
        if source.get("repo") == "$repo_name":
            data["sources"][i] = source_entry
            updated = True
            break
    
    if not updated:
        data["sources"].append(source_entry)
    
    with open('$SOURCES_JSON', 'w') as f:
        json.dump(data, f, indent=2)
        
except Exception as e:
    print(f"Error updating sources: {e}", file=sys.stderr)
    sys.exit(1)
EOF
}

# 1. Fetch SigmaHQ Sigma rules (for logging pipeline)
log "Fetching SigmaHQ Sigma rules..."
if [ ! -d "sigma/sigma" ]; then
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git sigma/sigma
else
    cd sigma/sigma && git pull origin main && cd ../..
fi
SIGMA_COMMIT=$(cd sigma/sigma && git rev-parse HEAD)
update_source "SigmaHQ/sigma" "$SIGMA_COMMIT" "sigma"
log "SigmaHQ commit: $SIGMA_COMMIT"

# 2. Fetch Yara-Rules
log "Fetching Yara-Rules repository..."
if [ ! -d "yara/yara-rules" ]; then
    git clone --depth 1 https://github.com/Yara-Rules/rules.git yara/yara-rules
else
    cd yara/yara-rules && git pull origin master && cd ../..
fi
YARA_RULES_COMMIT=$(cd yara/yara-rules && git rev-parse HEAD)
update_source "Yara-Rules/rules" "$YARA_RULES_COMMIT" "yara"
log "Yara-Rules commit: $YARA_RULES_COMMIT"

# 3. Fetch 100DaysofYARA 2025
log "Fetching 100DaysofYARA 2025..."
if [ ! -d "yara/100days-2025" ]; then
    git clone --depth 1 https://github.com/100DaysofYARA/2025.git yara/100days-2025
else
    cd yara/100days-2025 && git pull origin main && cd ../..
fi
YARA_100DAYS_COMMIT=$(cd yara/100days-2025 && git rev-parse HEAD)
update_source "100DaysofYARA/2025" "$YARA_100DAYS_COMMIT" "yara"
log "100DaysofYARA commit: $YARA_100DAYS_COMMIT"

# 4. NEW: Fetch Neo23x0 signature-base
log "Fetching Neo23x0 signature-base..."
if [ ! -d "yara/signature-base" ]; then
    git clone --depth 1 https://github.com/Neo23x0/signature-base.git yara/signature-base
else
    cd yara/signature-base && git pull origin master && cd ../..
fi
SIGNATURE_BASE_COMMIT=$(cd yara/signature-base && git rev-parse HEAD)
update_source "Neo23x0/signature-base" "$SIGNATURE_BASE_COMMIT" "yara"
log "signature-base commit: $SIGNATURE_BASE_COMMIT"

# 5. NEW: Fetch Mandiant malware-research
log "Fetching Mandiant malware-research..."
if [ ! -d "yara/malware-research" ]; then
    git clone --depth 1 https://github.com/mandiant/malware-research.git yara/malware-research
else
    cd yara/malware-research && git pull origin master && cd ../..
fi
MANDIANT_COMMIT=$(cd yara/malware-research && git rev-parse HEAD)
update_source "mandiant/malware-research" "$MANDIANT_COMMIT" "yara"
log "malware-research commit: $MANDIANT_COMMIT"

# 6. NEW: Fetch 0x4E0x650x6F yara_signatures
log "Fetching 0x4E0x650x6F yara_signatures..."
if [ ! -d "yara/yara_signatures" ]; then
    git clone --depth 1 https://github.com/0x4E0x650x6F/yara_signatures.git yara/yara_signatures
else
    cd yara/yara_signatures && git pull origin main && cd ../..
fi
YARA_SIGS_COMMIT=$(cd yara/yara_signatures && git rev-parse HEAD)
update_source "0x4E0x650x6F/yara_signatures" "$YARA_SIGS_COMMIT" "yara"
log "yara_signatures commit: $YARA_SIGS_COMMIT"

# 7. NEW: Fetch ninoseki boxer
log "Fetching ninoseki boxer..."
if [ ! -d "yara/boxer" ]; then
    git clone --depth 1 https://github.com/ninoseki/boxer.git yara/boxer
else
    cd yara/boxer && git pull origin main 2>/dev/null || git pull origin master && cd ../..
fi
BOXER_COMMIT=$(cd yara/boxer && git rev-parse HEAD)
update_source "ninoseki/boxer" "$BOXER_COMMIT" "yara"
log "boxer commit: $BOXER_COMMIT"

# 8. NEW: Fetch Elastic protections-artifacts
log "Fetching Elastic protections-artifacts..."
if [ ! -d "yara/protections-artifacts" ]; then
    git clone --depth 1 https://github.com/elastic/protections-artifacts.git yara/protections-artifacts
else
    cd yara/protections-artifacts && git pull origin main && cd ../..
fi
ELASTIC_COMMIT=$(cd yara/protections-artifacts && git rev-parse HEAD)
update_source "elastic/protections-artifacts" "$ELASTIC_COMMIT" "yara"
log "protections-artifacts commit: $ELASTIC_COMMIT"

# 9. Fetch YARA Forge bundle (optional)
log "Fetching YARA Forge bundle..."
if [ ! -f "yara/yara-forge-full.zip" ]; then
    wget -O yara/yara-forge-full.zip https://yarahq.github.io/full.zip || log "Warning: YARA Forge download failed"
fi
if [ -f "yara/yara-forge-full.zip" ]; then
    cd yara && unzip -o yara-forge-full.zip -d yara-forge/ && cd ..
    update_source "yarahq.github.io" "latest" "bundle"
fi

# 10. Optional: Fetch YARAify rules if API key provided
if [ ! -z "$YARAIFY_KEY" ]; then
    log "Fetching YARAify rules with provided API key..."
    curl -H "Authorization: Bearer $YARAIFY_KEY" \
         "https://yaraify-api.abuse.ch/download/yaraify-rules.zip" \
         -o yara/yaraify-rules.zip || log "Warning: YARAify download failed"
    if [ -f "yara/yaraify-rules.zip" ]; then
        cd yara && unzip -o yaraify-rules.zip -d yaraify/ && cd ..
        update_source "YARAify" "latest" "commercial"
    fi
else
    log "No YARAIFY_KEY provided, skipping YARAify rules"
fi

# Count rules
SIGMA_COUNT=$(find sigma/ -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l)
YARA_COUNT=$(find yara/ -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l)

log "Found $SIGMA_COUNT Sigma rules and $YARA_COUNT YARA rules"

# Update final metadata
python3 << EOF
import json
from datetime import datetime

try:
    with open('$SOURCES_JSON', 'r') as f:
        data = json.load(f)
    
    data["built"] = datetime.now().isoformat()
    data["counts"] = {
        "sigma_rules": $SIGMA_COUNT,
        "yara_rules": $YARA_COUNT
    }
    
    with open('$SOURCES_JSON', 'w') as f:
        json.dump(data, f, indent=2)
        
except Exception as e:
    print(f"Error updating final metadata: {e}")
EOF

log "=== Enhanced rule fetching completed ==="
log "Metadata saved to /app/rules/sources.json"
log "Found repositories: $(python3 -c "import json; print(len(json.load(open('$SOURCES_JSON'))['sources']))")"