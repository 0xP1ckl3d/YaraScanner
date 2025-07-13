#!/bin/bash
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
