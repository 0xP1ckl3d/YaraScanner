#!/bin/bash
set -e

echo "=== EDR-Safe Scanner Rule Fetching Started ==="

# Create rules directory structure
mkdir -p /app/rules/{sigma,yara,compiled}
cd /app/rules

# Function to log with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# 1. Fetch SigmaHQ Sigma rules
log "Fetching SigmaHQ Sigma rules..."
if [ ! -d "sigma/sigma" ]; then
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git sigma/sigma
else
    cd sigma/sigma && git pull origin main && cd ../..
fi
SIGMA_COMMIT=$(cd sigma/sigma && git rev-parse HEAD)
log "SigmaHQ commit: $SIGMA_COMMIT"

# 2. Fetch Yara-Rules
log "Fetching Yara-Rules repository..."
if [ ! -d "yara/yara-rules" ]; then
    git clone --depth 1 https://github.com/Yara-Rules/rules.git yara/yara-rules
else
    cd yara/yara-rules && git pull origin master && cd ../..
fi
YARA_RULES_COMMIT=$(cd yara/yara-rules && git rev-parse HEAD)
log "Yara-Rules commit: $YARA_RULES_COMMIT"

# 3. Fetch 100DaysofYARA 2025
log "Fetching 100DaysofYARA 2025..."
if [ ! -d "yara/100days-2025" ]; then
    git clone --depth 1 https://github.com/100DaysofYARA/2025.git yara/100days-2025
else
    cd yara/100days-2025 && git pull origin main && cd ../..
fi
YARA_100DAYS_COMMIT=$(cd yara/100days-2025 && git rev-parse HEAD)
log "100DaysofYARA commit: $YARA_100DAYS_COMMIT"

# 4. Fetch YARA Forge bundle
log "Fetching YARA Forge bundle..."
if [ ! -f "yara/yara-forge-full.zip" ]; then
    wget -O yara/yara-forge-full.zip https://yarahq.github.io/full.zip || log "Warning: YARA Forge download failed"
fi
if [ -f "yara/yara-forge-full.zip" ]; then
    cd yara && unzip -o yara-forge-full.zip -d yara-forge/ && cd ..
fi

# 5. Optional: Fetch YARAify rules if API key provided
if [ ! -z "$YARAIFY_KEY" ]; then
    log "Fetching YARAify rules with provided API key..."
    curl -H "Authorization: Bearer $YARAIFY_KEY" \
         "https://yaraify-api.abuse.ch/download/yaraify-rules.zip" \
         -o yara/yaraify-rules.zip || log "Warning: YARAify download failed"
    if [ -f "yara/yaraify-rules.zip" ]; then
        cd yara && unzip -o yaraify-rules.zip -d yaraify/ && cd ..
    fi
else
    log "No YARAIFY_KEY provided, skipping YARAify rules"
fi

# Count rules before compilation
SIGMA_COUNT=$(find sigma/ -name "*.yml" -o -name "*.yaml" | wc -l)
YARA_COUNT=$(find yara/ -name "*.yar" -o -name "*.yara" | wc -l)

log "Found $SIGMA_COUNT Sigma rules and $YARA_COUNT YARA rules"

# Generate metadata file
cat > /app/rules/sources.json << EOF
{
  "built": "$(date -Iseconds)",
  "sources": [
    {"repo": "SigmaHQ/sigma", "commit": "$SIGMA_COMMIT"},
    {"repo": "Yara-Rules/rules", "commit": "$YARA_RULES_COMMIT"},
    {"repo": "100DaysofYARA/2025", "commit": "$YARA_100DAYS_COMMIT"},
    {"repo": "yarahq.github.io", "type": "bundle"},
    {"repo": "YARAify", "enabled": $([ ! -z "$YARAIFY_KEY" ] && echo "true" || echo "false")}
  ],
  "counts": {
    "sigma_rules": $SIGMA_COUNT,
    "yara_rules": $YARA_COUNT
  }
}
EOF

log "=== Rule fetching completed ==="
log "Metadata saved to /app/rules/sources.json"