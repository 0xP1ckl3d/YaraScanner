from fastapi import FastAPI, APIRouter, File, UploadFile, HTTPException, Form
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import json
import yara
import tempfile
import aiofiles
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime
import subprocess
import asyncio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="EDR-Safe Scanner", description="Local YARA/Sigma rule scanner")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Global YARA rules object
compiled_rules = None
rules_metadata = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ScanResult(BaseModel):
    filename: str
    status: str  # "clean", "suspicious", "bad"
    matches: List[str]
    scan_time: datetime = Field(default_factory=datetime.utcnow)

class ScanResponse(BaseModel):
    results: List[ScanResult]
    total_files: int
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

class RulesInfo(BaseModel):
    built: str
    sources: List[Dict[str, Any]]
    total_rules: Optional[int] = None

async def load_yara_rules():
    """Load compiled YARA rules from file"""
    global compiled_rules, rules_metadata
    
    rules_file = Path("/app/rules/compiled/all_rules.yc")
    metadata_file = Path("/app/rules/sources.json")
    
    try:
        if rules_file.exists():
            logger.info(f"Loading YARA rules from {rules_file}")
            compiled_rules = yara.load(str(rules_file))
            logger.info("YARA rules loaded successfully")
        else:
            logger.warning(f"Compiled rules file not found at {rules_file}")
            
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                rules_metadata = json.load(f)
                logger.info("Rules metadata loaded successfully")
        else:
            logger.warning(f"Rules metadata file not found at {metadata_file}")
            
    except Exception as e:
        logger.error(f"Error loading YARA rules: {e}")
        compiled_rules = None
        rules_metadata = None

async def compile_sigma_to_yara():
    """Convert Sigma rules to YARA and compile everything"""
    logger.info("Starting Sigma to YARA conversion...")
    
    try:
        # Create Python script for Sigma conversion
        conversion_script = """
import os
import glob
from pathlib import Path
from pysigma.backends.yara import YaraBackend
from pysigma.processing.resolver import ProcessingPipelineResolver
from pysigma.rule import SigmaRule
import yara
import tempfile

def convert_sigma_to_yara():
    backend = YaraBackend()
    yara_rules = []
    
    # Find all Sigma YAML files
    sigma_files = []
    for pattern in ['/app/rules/sigma/**/*.yml', '/app/rules/sigma/**/*.yaml']:
        sigma_files.extend(glob.glob(pattern, recursive=True))
    
    print(f"Found {len(sigma_files)} Sigma files to convert")
    
    converted_count = 0
    for sigma_file in sigma_files:
        try:
            with open(sigma_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse Sigma rule
            sigma_rule = SigmaRule.from_yaml(content)
            
            # Convert to YARA
            yara_rule = backend.convert(sigma_rule)
            if yara_rule:
                yara_rules.extend(yara_rule)
                converted_count += 1
                
        except Exception as e:
            print(f"Warning: Failed to convert {sigma_file}: {e}")
            continue
    
    print(f"Successfully converted {converted_count} Sigma rules to YARA")
    return yara_rules

def compile_all_rules():
    print("Converting Sigma rules to YARA...")
    sigma_yara_rules = convert_sigma_to_yara()
    
    # Collect all YARA rule files
    yara_files = []
    for pattern in ['/app/rules/yara/**/*.yar', '/app/rules/yara/**/*.yara']:
        yara_files.extend(glob.glob(pattern, recursive=True))
    
    print(f"Found {len(yara_files)} YARA rule files")
    
    # Read all YARA files
    all_rules_content = []
    
    # Add converted Sigma rules
    for rule in sigma_yara_rules:
        all_rules_content.append(str(rule))
    
    # Add native YARA rules
    for yara_file in yara_files:
        try:
            with open(yara_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                all_rules_content.append(content)
        except Exception as e:
            print(f"Warning: Failed to read {yara_file}: {e}")
    
    # Combine all rules
    combined_rules = '\\n\\n'.join(all_rules_content)
    
    print(f"Compiling {len(all_rules_content)} rule sets...")
    
    # Compile rules
    try:
        compiled = yara.compile(source=combined_rules)
        
        # Save compiled rules
        os.makedirs('/app/rules/compiled', exist_ok=True)
        compiled.save('/app/rules/compiled/all_rules.yc')
        
        print(f"Successfully compiled rules to /app/rules/compiled/all_rules.yc")
        return True
        
    except yara.SyntaxError as e:
        print(f"YARA syntax error during compilation: {e}")
        return False
    except Exception as e:
        print(f"Error during compilation: {e}")
        return False

if __name__ == "__main__":
    success = compile_all_rules()
    exit(0 if success else 1)
"""
        
        # Write and execute conversion script
        script_path = "/tmp/convert_rules.py"
        with open(script_path, 'w') as f:
            f.write(conversion_script)
        
        # Run the conversion
        process = await asyncio.create_subprocess_exec(
            'python3', script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            logger.info("Sigma to YARA conversion completed successfully")
            logger.info(stdout.decode())
            return True
        else:
            logger.error(f"Conversion failed: {stderr.decode()}")
            return False
            
    except Exception as e:
        logger.error(f"Error in Sigma conversion: {e}")
        return False

@api_router.post("/scan", response_model=ScanResponse)
async def scan_files(files: List[UploadFile] = File(...)):
    """Scan uploaded files against YARA rules"""
    
    if not compiled_rules:
        raise HTTPException(status_code=503, detail="YARA rules not loaded. Please rebuild rules.")
    
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    
    # Check total size limit (20MB)
    total_size = 0
    for file in files:
        if hasattr(file, 'size') and file.size:
            total_size += file.size
    
    if total_size > 20 * 1024 * 1024:  # 20MB
        raise HTTPException(status_code=413, detail="Total file size exceeds 20MB limit")
    
    results = []
    
    for file in files:
        try:
            # Read file content
            content = await file.read()
            
            # Reset file pointer for potential re-reading
            await file.seek(0)
            
            # Scan with YARA
            matches = compiled_rules.match(data=content)
            
            # Determine status based on matches
            if not matches:
                status = "clean"
                match_names = []
            elif len(matches) <= 2:
                status = "suspicious"
                match_names = [match.rule for match in matches]
            else:
                status = "bad"
                match_names = [match.rule for match in matches]
            
            results.append(ScanResult(
                filename=file.filename or "unknown",
                status=status,
                matches=match_names
            ))
            
        except Exception as e:
            logger.error(f"Error scanning file {file.filename}: {e}")
            results.append(ScanResult(
                filename=file.filename or "unknown",
                status="error",
                matches=[f"Scan error: {str(e)}"]
            ))
    
    return ScanResponse(
        results=results,
        total_files=len(files)
    )

@api_router.post("/scan/text")
async def scan_text(content: str = Form(...), filename: str = Form(default="text_input")):
    """Scan raw text content against YARA rules"""
    
    if not compiled_rules:
        raise HTTPException(status_code=503, detail="YARA rules not loaded. Please rebuild rules.")
    
    if not content:
        raise HTTPException(status_code=400, detail="No content provided")
    
    try:
        # Scan with YARA
        matches = compiled_rules.match(data=content.encode('utf-8'))
        
        # Determine status based on matches
        if not matches:
            status = "clean"
            match_names = []
        elif len(matches) <= 2:
            status = "suspicious"
            match_names = [match.rule for match in matches]
        else:
            status = "bad"
            match_names = [match.rule for match in matches]
        
        result = ScanResult(
            filename=filename,
            status=status,
            matches=match_names
        )
        
        return ScanResponse(
            results=[result],
            total_files=1
        )
        
    except Exception as e:
        logger.error(f"Error scanning text content: {e}")
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")

@api_router.get("/rules/latest", response_model=RulesInfo)
async def get_rules_info():
    """Get information about loaded rules"""
    
    if not rules_metadata:
        raise HTTPException(status_code=404, detail="Rules metadata not available")
    
    # Filter out YARAify if not enabled
    sources = rules_metadata.get("sources", [])
    if not os.getenv("YARAIFY_KEY"):
        sources = [s for s in sources if s.get("repo") != "YARAify"]
    
    total_rules = None
    if compiled_rules:
        # Count rules in compiled object (this is approximate)
        total_rules = rules_metadata.get("counts", {}).get("sigma_rules", 0) + \
                     rules_metadata.get("counts", {}).get("yara_rules", 0)
    
    return RulesInfo(
        built=rules_metadata.get("built", "unknown"),
        sources=sources,
        total_rules=total_rules
    )

@api_router.post("/admin/refresh")
async def refresh_rules(admin_token: str = Form(...)):
    """Rebuild and reload YARA rules (admin only)"""
    
    expected_token = os.getenv("ADMIN_TOKEN")
    if not expected_token:
        raise HTTPException(status_code=404, detail="Admin functionality not enabled")
    
    if admin_token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid admin token")
    
    try:
        logger.info("Starting admin rule refresh...")
        
        # Run rule fetching script
        process = await asyncio.create_subprocess_exec(
            '/bin/bash', '/app/scripts/fetch_rules.sh',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "YARAIFY_KEY": os.getenv("YARAIFY_KEY", "")}
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Rule fetching failed: {stderr.decode()}")
            raise HTTPException(status_code=500, detail="Rule fetching failed")
        
        # Convert and compile rules
        success = await compile_sigma_to_yara()
        if not success:
            raise HTTPException(status_code=500, detail="Rule compilation failed")
        
        # Reload rules
        await load_yara_rules()
        
        if not compiled_rules:
            raise HTTPException(status_code=500, detail="Failed to load compiled rules")
        
        logger.info("Admin rule refresh completed successfully")
        
        return {"status": "success", "message": "Rules refreshed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during rule refresh: {e}")
        raise HTTPException(status_code=500, detail=f"Rule refresh failed: {str(e)}")

# Startup event to load rules
@app.on_event("startup")
async def startup_event():
    logger.info("Starting EDR-Safe Scanner...")
    await load_yara_rules()
    
    if not compiled_rules:
        logger.warning("No compiled rules found. Run rule compilation first.")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()