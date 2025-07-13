#!/usr/bin/env python3
"""
Weekly Rule Refresh Worker
Replaces system cron with a dedicated Python worker for rule updates
"""

import time
import datetime
import subprocess
import logging
import os
import signal
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/rule_refresh.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RefreshWorker:
    def __init__(self):
        self.running = True
        self.refresh_interval = 7 * 24 * 60 * 60  # 7 days in seconds
        self.check_interval = 60 * 60  # Check every hour
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        
    def should_refresh(self):
        """Check if it's time for weekly refresh (Monday 3:00 AM AEST)"""
        now = datetime.datetime.now()
        
        # Check if it's Monday and around 3:00 AM (2:55-3:05 AM window)
        if now.weekday() == 0 and 2 <= now.hour <= 3:
            return True
            
        # Also check if sources.json is older than 7 days
        sources_file = Path("/app/rules/sources.json")
        if sources_file.exists():
            mtime = datetime.datetime.fromtimestamp(sources_file.stat().st_mtime)
            age_days = (now - mtime).days
            if age_days >= 7:
                logger.info(f"Rules are {age_days} days old, triggering refresh")
                return True
        
        return False
        
    def run_refresh(self):
        """Execute the rule refresh process"""
        logger.info("Starting weekly rule refresh...")
        
        try:
            # Run rule fetching
            logger.info("Fetching latest rules...")
            result = subprocess.run(
                ['/app/scripts/fetch_rules_v2.sh'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Rule fetching failed: {result.stderr}")
                return False
                
            logger.info("Rule fetching completed successfully")
            
            # Run rule compilation
            logger.info("Compiling rules...")
            result = subprocess.run(
                ['python3', '/app/scripts/compile_rules_v2.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Rule compilation failed: {result.stderr}")
                return False
                
            logger.info("Rule compilation completed successfully")
            
            # Restart backend to reload rules
            logger.info("Restarting backend service...")
            result = subprocess.run(
                ['supervisorctl', 'restart', 'backend'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.warning(f"Backend restart failed: {result.stderr}")
            else:
                logger.info("Backend restarted successfully")
            
            logger.info("Weekly rule refresh completed successfully")
            return True
            
        except subprocess.TimeoutExpired as e:
            logger.error(f"Rule refresh timeout: {e}")
            return False
        except Exception as e:
            logger.error(f"Rule refresh error: {e}")
            return False
            
    def run(self):
        """Main worker loop"""
        logger.info("Starting rule refresh worker...")
        logger.info(f"Refresh interval: {self.refresh_interval/3600/24:.1f} days")
        
        last_refresh_check = 0
        
        while self.running:
            try:
                current_time = time.time()
                
                # Check for refresh only once per hour
                if current_time - last_refresh_check >= self.check_interval:
                    last_refresh_check = current_time
                    
                    if self.should_refresh():
                        success = self.run_refresh()
                        if success:
                            # Mark successful refresh by updating timestamp
                            sources_file = Path("/app/rules/sources.json")
                            if sources_file.exists():
                                sources_file.touch()
                        else:
                            logger.error("Rule refresh failed, will retry next cycle")
                
                # Sleep for a short interval before checking again
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Worker error: {e}")
                time.sleep(300)  # Sleep 5 minutes on error
                
        logger.info("Rule refresh worker stopped")

def main():
    """Main entry point"""
    # Ensure we're running as root for supervisor control
    if os.geteuid() != 0:
        logger.warning("Running as non-root user, some operations may fail")
    
    worker = RefreshWorker()
    worker.run()

if __name__ == "__main__":
    main()