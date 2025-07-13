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
import magic
import psutil
import zipfile
import shutil
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime
import subprocess
import asyncio
import re

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="EDR-Safe Scanner v2", description="Enhanced local YARA/Sigma rule scanner with modular bundles")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Global YARA rules objects for modular loading
compiled_bundles = {
    'generic': None,
    'scripts': None, 
    'pe': None,
    'webshells': None
}
rules_metadata = None

# Security configuration
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
MAX_EXTRACTED_SIZE = 30 * 1024 * 1024  # 30MB for zip extraction
MAX_ARCHIVE_DEPTH = 3
TEMP_SCAN_DIR = Path("/tmp/edrscan")

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
    bundle_used: Optional[str] = None

class ScanResponse(BaseModel):
    results: List[ScanResult]
    total_files: int
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

class RulesInfo(BaseModel):
    built: str
    sources: List[Dict[str, Any]]
    total_rules: Optional[int] = None

class RulesStats(BaseModel):
    built: str
    bundle_counts: Dict[str, int]
    total_rules: int
    rss_mb: float
    local_count: Optional[int] = None

def get_memory_usage_mb():
    """Get current RSS memory usage in MB"""
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024

def detect_file_type(content: bytes, filename: str = "") -> str:
    """Detect file type to determine which bundle to use"""
    try:
        # Use python-magic for MIME type detection
        mime_type = magic.from_buffer(content, mime=True)
        filename_lower = filename.lower()
        
        # PE/executable files
        if content.startswith(b'MZ') or 'application/x-executable' in mime_type or 'application/x-dosexec' in mime_type:
            return 'pe'
            
        # Script files based on content or filename
        script_extensions = ['.ps1', '.vbs', '.js', '.py', '.pl', '.sh', '.bat', '.cmd']
        if any(ext in filename_lower for ext in script_extensions):
            return 'scripts'
        
        # Check content for script indicators
        try:
            content_str = content.decode('utf-8', errors='ignore')[:2000].lower()
            script_indicators = ['powershell', 'javascript', 'vbscript', 'python', '#!/bin/', 'createobject', 'wscript']
            if any(indicator in content_str for indicator in script_indicators):
                return 'scripts'
        except:
            pass
            
        # Webshell files
        web_extensions = ['.php', '.asp', '.jsp', '.aspx']
        if any(ext in filename_lower for ext in web_extensions):
            return 'webshells'
            
        # Check for web content
        try:
            content_str = content.decode('utf-8', errors='ignore')[:2000].lower()
            web_indicators = ['<?php', '<%', 'eval(', 'shell_exec', '$_post', '$_get']
            if any(indicator in content_str for indicator in web_indicators):
                return 'webshells'
        except:
            pass
            
        return 'generic'
        
    except Exception as e:
        logger.warning(f"File type detection failed: {e}")
        return 'generic'  # Fallback

async def load_yara_bundle(bundle_name: str):
    """Load a specific YARA bundle on demand"""
    if compiled_bundles[bundle_name] is not None:
        return compiled_bundles[bundle_name]
        
    bundle_file = Path(f"/app/rules/compiled/{bundle_name}.yc")
    
    try:
        if bundle_file.exists():
            logger.info(f"Loading YARA bundle: {bundle_name}")
            compiled_bundles[bundle_name] = yara.load(str(bundle_file))
            return compiled_bundles[bundle_name]
        else:
            logger.warning(f"Bundle file not found: {bundle_file}")
            
    except Exception as e:
        logger.error(f"Error loading YARA bundle {bundle_name}: {e}")
        
    return None

async def load_yara_rules():
    """Load YARA rules metadata"""
    global rules_metadata
    
    metadata_file = Path("/app/rules/sources.json")
    
    try:
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                rules_metadata = json.load(f)
                logger.info("Rules metadata loaded successfully")
        else:
            logger.warning(f"Rules metadata file not found at {metadata_file}")
            
    except Exception as e:
        logger.error(f"Error loading rules metadata: {e}")
        rules_metadata = None

def setup_temp_directory():
    """Setup secure temporary directory for scanning"""
    TEMP_SCAN_DIR.mkdir(exist_ok=True, mode=0o700)

def clean_temp_file(filepath: Path):
    """Securely clean up temporary file"""
    try:
        if filepath.exists():
            filepath.unlink()
    except Exception as e:
        logger.warning(f"Failed to clean temp file {filepath}: {e}")

def validate_filename(filename: str) -> str:
    """Validate and sanitize filename to prevent path traversal"""
    # Remove path separators and normalize
    safe_name = os.path.basename(filename)
    safe_name = re.sub(r'[^\w\-_\.]', '_', safe_name)
    return safe_name[:100]  # Limit length

async def extract_and_scan_archive(content: bytes, filename: str) -> List[ScanResult]:
    """Extract and scan archive contents with security checks"""
    results = []
    temp_dir = None
    
    try:
        # Create temporary directory for extraction
        temp_dir = TEMP_SCAN_DIR / str(uuid.uuid4())
        temp_dir.mkdir(mode=0o700)
        
        # Save archive to temp file
        archive_path = temp_dir / "archive.zip"
        with open(archive_path, 'wb') as f:
            f.write(content)
        
        # Extract with security checks
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            total_extracted = 0
            depth_count = 0
            
            for member in zip_ref.namelist():
                # Check for path traversal
                if '..' in member or member.startswith('/'):
                    continue
                    
                # Check extraction depth
                if member.count('/') > MAX_ARCHIVE_DEPTH:
                    continue
                    
                # Extract member
                try:
                    member_data = zip_ref.read(member)
                    total_extracted += len(member_data)
                    
                    # Check total extracted size
                    if total_extracted > MAX_EXTRACTED_SIZE:
                        logger.warning("Archive extraction size limit exceeded")
                        break
                        
                    # Scan extracted file
                    member_filename = os.path.basename(member)
                    scan_result = await scan_content(member_data, f"{filename}:{member_filename}")
                    results.append(scan_result)
                    
                except Exception as e:
                    logger.warning(f"Failed to extract member {member}: {e}")
                    continue
                    
    except zipfile.BadZipFile:
        # Not a valid zip file, scan as regular content
        return [await scan_content(content, filename)]
    except Exception as e:
        logger.error(f"Archive extraction failed: {e}")
        # Fallback to regular scanning
        return [await scan_content(content, filename)]
    finally:
        # Cleanup
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    return results

async def scan_content(content: bytes, filename: str) -> ScanResult:
    """Scan content with appropriate YARA bundle"""
    try:
        # Detect file type and select bundle
        file_type = detect_file_type(content, filename)
        
        # Load appropriate bundle
        bundle = await load_yara_bundle(file_type)
        
        if bundle is None:
            # Fallback to generic bundle
            bundle = await load_yara_bundle('generic')
            
        if bundle is None:
            return ScanResult(
                filename=filename,
                status="error",
                matches=["No YARA bundles available"],
                bundle_used=None
            )
        
        # Scan with YARA
        matches = bundle.match(data=content)
        
        # Determine status based on matches and rule severity
        if not matches:
            status = "clean"
            match_names = []
        else:
            match_names = [match.rule for match in matches]
            
            # Enhanced status classification
            high_severity_indicators = [
                'mimikatz', 'bad', 'malware', 'trojan', 'backdoor', 'dropper', 'exploit'
            ]
            
            # Check rule names for severity indicators
            rule_text = ' '.join(match_names).lower()
            
            # Count high severity matches
            high_severity_count = sum(1 for indicator in high_severity_indicators 
                                    if indicator in rule_text)
            
            # Determine final status
            if high_severity_count >= 1 or len(matches) >= 4:
                status = "bad"
            elif len(matches) >= 1:
                status = "suspicious"
            else:
                status = "clean"
        
        return ScanResult(
            filename=filename,
            status=status,
            matches=match_names,
            bundle_used=file_type
        )
        
    except Exception as e:
        logger.error(f"Error scanning content for {filename}: {e}")
        return ScanResult(
            filename=filename,
            status="error",
            matches=[f"Scan error: {str(e)}"],
            bundle_used=None
        )

@api_router.post("/scan", response_model=ScanResponse)
async def scan_files(files: List[UploadFile] = File(...)):
    """Scan uploaded files against YARA rules using dynamic bundle selection"""
    
    if not files:
        raise HTTPException(status_code=422, detail="No files provided")
    
    # Check total size limit
    total_size = 0
    for file in files:
        if hasattr(file, 'size') and file.size:
            total_size += file.size
    
    if total_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Total file size exceeds 20MB limit")
    
    results = []
    
    for file in files:
        temp_file = None
        try:
            # Validate filename
            safe_filename = validate_filename(file.filename or "unknown")
            
            # Read file content
            content = await file.read()
            
            # Reset file pointer
            await file.seek(0)
            
            # Create secure temporary file
            temp_file = TEMP_SCAN_DIR / f"{uuid.uuid4()}_{safe_filename}"
            with open(temp_file, 'wb') as f:
                f.write(content)
            temp_file.chmod(0o600)
            
            # Check if it's an archive (zip file)
            if safe_filename.lower().endswith('.zip') or content.startswith(b'PK'):
                archive_results = await extract_and_scan_archive(content, safe_filename)
                results.extend(archive_results)
            else:
                # Regular file scanning
                scan_result = await scan_content(content, safe_filename)
                results.append(scan_result)
            
        except Exception as e:
            logger.error(f"Error processing file {file.filename}: {e}")
            results.append(ScanResult(
                filename=validate_filename(file.filename or "unknown"),
                status="error",
                matches=[f"Processing error: {str(e)}"]
            ))
        finally:
            # Cleanup temporary file
            if temp_file:
                clean_temp_file(temp_file)
    
    return ScanResponse(
        results=results,
        total_files=len(files)
    )

@api_router.post("/scan/text")
async def scan_text(content: str = Form(...), filename: str = Form(default="text_input")):
    """Scan raw text content against YARA rules"""
    
    if not content:
        raise HTTPException(status_code=400, detail="No content provided")
    
    try:
        # Validate filename
        safe_filename = validate_filename(filename)
        
        # Scan text content
        scan_result = await scan_content(content.encode('utf-8'), safe_filename)
        
        return ScanResponse(
            results=[scan_result],
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
    
    # Calculate total rules from compilation data
    total_rules = None
    compilation_data = rules_metadata.get("compilation", {})
    if compilation_data:
        bundle_counts = compilation_data.get("bundles", {})
        total_rules = sum(bundle_counts.values())
    
    return RulesInfo(
        built=rules_metadata.get("built", "unknown"),
        sources=sources,
        total_rules=total_rules
    )

@api_router.get("/rules/stats", response_model=RulesStats)
async def get_rules_stats():
    """Get comprehensive statistics about rules and system performance"""
    
    if not rules_metadata:
        raise HTTPException(status_code=404, detail="Rules metadata not available")
    
    # Get bundle counts from compilation data
    compilation_data = rules_metadata.get("compilation", {})
    bundle_counts = compilation_data.get("bundles", {})
    
    # Count local rules if any
    local_count = 0
    local_dir = Path("/app/rules/local")
    if local_dir.exists():
        local_files = list(local_dir.glob("*.yar")) + list(local_dir.glob("*.yara"))
        local_count = len(local_files)
    
    # Calculate total rules
    total_rules = sum(bundle_counts.values()) + local_count
    
    return RulesStats(
        built=rules_metadata.get("built", "unknown"),
        bundle_counts=bundle_counts,
        total_rules=total_rules,
        rss_mb=get_memory_usage_mb(),
        local_count=local_count if local_count > 0 else None
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
            '/bin/bash', '/app/scripts/fetch_rules_v2.sh',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "YARAIFY_KEY": os.getenv("YARAIFY_KEY", "")}
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Rule fetching failed: {stderr.decode()}")
            raise HTTPException(status_code=500, detail="Rule fetching failed")
        
        # Run rule compilation
        process = await asyncio.create_subprocess_exec(
            'python3', '/app/scripts/compile_rules_v2.py',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Rule compilation failed: {stderr.decode()}")
            raise HTTPException(status_code=500, detail="Rule compilation failed")
        
        # Clear bundle cache to force reload
        for bundle_name in compiled_bundles:
            compiled_bundles[bundle_name] = None
        
        # Reload metadata
        await load_yara_rules()
        
        logger.info("Admin rule refresh completed successfully")
        
        return {"status": "success", "message": "Rules refreshed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during rule refresh: {e}")
        raise HTTPException(status_code=500, detail=f"Rule refresh failed: {str(e)}")

# Startup event to setup environment
@app.on_event("startup")
async def startup_event():
    logger.info("Starting EDR-Safe Scanner v2...")
    setup_temp_directory()
    await load_yara_rules()
    
    # Preload generic bundle for faster initial scans
    await load_yara_bundle('generic')
    
    if not rules_metadata:
        logger.warning("No rules metadata loaded. Run rule compilation first.")

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
    
    # Cleanup temp directory
    if TEMP_SCAN_DIR.exists():
        shutil.rmtree(TEMP_SCAN_DIR, ignore_errors=True)