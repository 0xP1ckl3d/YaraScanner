# EDR-Safe Scanner v2

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/react-18.0+-61dafb.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)

**EDR-Safe Scanner** is a comprehensive, offline malware detection system that combines YARA and Sigma rules for local threat analysis. Built for security professionals who need reliable, air-gapped malware scanning capabilities.

## 🚀 Features

### Core Capabilities
- **🔒 100% Offline Operation** - No data leaves your environment
- **🎯 Multi-Engine Detection** - YARA + Sigma rule integration with **9,000+ compiled rules**
- **📦 Modular Architecture** - Specialized detection bundles (PE, Scripts, Webshells, Generic)
- **⚡ High Performance** - <100ms scan times, <2GB memory usage
- **🌐 Modern React UI** - Professional dashboard with Infotrust branding
- **📊 Real-time Monitoring** - Live memory usage and rule statistics

### Security Features
- **🛡️ Secure File Handling** - Path traversal protection, zip bomb prevention
- **🔐 Archive Analysis** - Intelligent extraction with safety limits
- **📏 Size Limits** - 20MB upload limit with configurable thresholds
- **🧹 Auto Cleanup** - Secure temporary file management with janitor thread
- **🔍 Content Validation** - MIME type detection and validation

### Detection Coverage
- **💻 Executables** - PE files, packed binaries (UPX detection)
- **📜 Scripts** - PowerShell, VBS, JavaScript, Python, Shell scripts
- **🌐 Webshells** - PHP, ASP, JSP backdoors and shells
- **🎭 Obfuscation** - Base64 encoding, command obfuscation
- **🔧 Tools** - Mimikatz, credential dumpers, offensive tools

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Rule Management](#rule-management)
- [API Documentation](#api-documentation)
- [Security Considerations](#security-considerations)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## 🚀 Quick Start

### Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/edr-safe-scanner.git
cd edr-safe-scanner

# Start with Docker Compose
docker-compose up -d

# Access the scanner
open http://localhost:3000
```

The scanner will automatically:
1. Fetch YARA/Sigma rules from 8+ public repositories
2. Compile rules into optimized detection bundles
3. Start the React web interface and FastAPI server

## 🛠️ Installation

### Option 1: Docker Deployment (Recommended)

**Prerequisites:**
- Docker 20.0+
- Docker Compose 2.0+
- 4GB RAM minimum
- 2GB disk space (thanks to multi-stage build)

```bash
# Clone repository
git clone https://github.com/your-org/edr-safe-scanner.git
cd edr-safe-scanner

# Copy environment templates
cp backend/.env.template backend/.env
cp frontend/.env.template frontend/.env

# Edit configuration if needed
nano backend/.env

# Start services
docker-compose up -d

# View logs
docker-compose logs -f edr-scanner

# Check status
docker-compose ps
```

### Multi-Stage Docker Build

The application uses an optimized multi-stage Docker build:

- **Frontend Builder Stage**: Compiles React app
- **Rule Builder Stage**: Fetches and compiles YARA/Sigma rules
- **Production Stage**: Minimal runtime image (<450MB)

### Option 2: Manual Installation

**Prerequisites:**
- Python 3.12+
- Node.js 20+
- Git
- 4GB RAM minimum

#### Backend Setup

```bash
# Clone repository
git clone https://github.com/your-org/edr-safe-scanner.git
cd edr-safe-scanner

# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y libmagic1 libmagic-dev git wget

# Setup Python environment
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure environment
cp .env.template .env
nano .env  # Edit configuration
```

#### Frontend Setup

```bash
# Install Node.js dependencies
cd ../frontend
yarn install

# Configure environment
cp .env.template .env
nano .env  # Set REACT_APP_BACKEND_URL

# Build production version
yarn build
```

#### Rule Setup

```bash
# Return to project root
cd ..

# Make scripts executable
chmod +x scripts/*.sh scripts/*.py

# Fetch and compile rules (takes 2-5 minutes)
./scripts/fetch_rules_v2.sh
python3 scripts/compile_rules_v2.py

# Verify rule compilation
ls -la rules/compiled/
```

#### Start Services

```bash
# Start backend (in one terminal)
cd backend
source venv/bin/activate
python -m uvicorn server:app --host 0.0.0.0 --port 8001

# Start frontend (in another terminal)
cd frontend
npx serve -s build -l 3000

# Access scanner
open http://localhost:3000
```

## ⚙️ Configuration

### Environment Variables

#### Backend Configuration (`backend/.env`)

```bash
# Security
ADMIN_TOKEN=your-secure-admin-token  # Optional: enables /admin/refresh
FRONTEND_ORIGIN=http://localhost:3000  # CORS configuration

# External Services (Optional)
YARAIFY_KEY=your-api-key  # Premium YARAify rules

# Application
ENVIRONMENT=production
LOG_LEVEL=INFO
```

#### Frontend Configuration (`frontend/.env`)

```bash
# API Endpoint
REACT_APP_BACKEND_URL=http://localhost:8001
```

### Advanced Configuration

#### Memory Optimization

```bash
# For systems with limited memory
export YARA_MAX_RULES=5000  # Limit rule count
export YARA_MAX_MEMORY=1024  # Max memory in MB
```

#### Rule Source Configuration

Edit `scripts/fetch_rules_v2.sh` to customize rule sources:

```bash
# Add custom repositories
clone_or_update "https://github.com/your-org/custom-rules.git" "yara/custom" "main"

# Disable specific sources
# Comment out lines for unwanted repositories
```

## 📖 Usage

### Web Interface

1. **Access Dashboard**: Navigate to `http://localhost:3000`
2. **View Statistics**: Check rule counts and memory usage in header
3. **File Analysis**: 
   - Upload files (max 20MB total)
   - Drag-and-drop supported
   - Archive extraction automatic
4. **Text Analysis**: Paste suspicious content for analysis
5. **Results**: View detailed scan results with rule matches

### API Usage

#### Scan Files

```bash
curl -X POST "http://localhost:8001/api/scan" \
  -F "files=@suspicious_file.exe" \
  -F "files=@script.ps1"
```

#### Scan Text Content

```bash
curl -X POST "http://localhost:8001/api/scan/text" \
  -F "content=powershell -enc ZXZpbCBjb2Rl" \
  -F "filename=suspicious.ps1"
```

#### Get Statistics

```bash
curl "http://localhost:8001/api/rules/stats" | jq .
```

### Command Line Tools

#### Manual Rule Update

```bash
# Fetch latest rules
./scripts/fetch_rules_v2.sh

# Recompile rules
python3 scripts/compile_rules_v2.py

# Restart services (Docker)
docker-compose restart edr-scanner
```

#### Security Review

```bash
# Run security validation
python3 scripts/security_review.py
```

## 📚 Rule Management

### Rule Sources

The scanner automatically fetches rules from:

| Source | Type | Count | Description |
|--------|------|-------|-------------|
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | Sigma | 3,800+ | Official Sigma rules |
| [Yara-Rules](https://github.com/Yara-Rules/rules) | YARA | 1,200+ | Community YARA rules |
| [100 Days of YARA](https://github.com/100DaysofYARA/2025) | YARA | 100+ | Daily YARA challenges |
| [Neo23x0 Signature Base](https://github.com/Neo23x0/signature-base) | YARA | 800+ | Professional rule sets |
| [Elastic Protections](https://github.com/elastic/protections-artifacts) | YARA | 400+ | Elastic Security rules |
| [YARA Forge](https://yarahq.github.io/) | YARA | 2,000+ | Curated rule collection |

**Current Total: 8,908 compiled rules**

### Weekly Auto-Update

The scanner includes an automatic weekly refresh system:

- **Refresh Worker**: Dedicated Python worker replaces cron
- **Schedule**: Every Monday at 3:00 AM AEST
- **Process**: Fetch latest rules → Compile → Restart backend
- **Logging**: Comprehensive logging to `/var/log/rule_refresh.log`

### Adding Custom Rules

#### Local YARA Rules

```bash
# Place custom YARA rules in local directory
mkdir -p rules/local
cat > rules/local/custom_rule.yar << 'EOF'
rule Custom_Malware_Detection
{
    meta:
        description = "Custom malware detection rule"
        author = "Your Name"
        
    strings:
        $sig1 = "malicious_string" nocase
        $sig2 = { 6D 61 6C 77 61 72 65 }  // "malware" in hex
        
    condition:
        any of them
}
EOF

# Recompile rules
python3 scripts/compile_rules_v2.py
```

### Rule Bundle Management

The scanner organizes rules into specialized bundles:

#### Bundle Types

- **`generic.yc`** - General malware patterns, helper rules (4,851 rules)
- **`scripts.yc`** - PowerShell, VBS, JavaScript, Python scripts (1,688 rules)
- **`pe.yc`** - PE executables, packed binaries, DLLs (2,059 rules)
- **`webshells.yc`** - Web-based backdoors and shells (310 rules)

#### Bundle Selection Logic

```python
# File type detection determines bundle usage
def detect_file_type(content, filename):
    if content.startswith(b'MZ'):  # PE header
        return 'pe'
    elif '.ps1' in filename or 'powershell' in content:
        return 'scripts'
    elif '.php' in filename or '<?php' in content:
        return 'webshells'
    else:
        return 'generic'
```

## 📡 API Documentation

### Endpoints

#### `POST /api/scan`
Upload and scan files

**Request:**
```bash
curl -X POST "http://localhost:8001/api/scan" \
  -F "files=@file1.exe" \
  -F "files=@file2.ps1"
```

**Response:**
```json
{
  "results": [
    {
      "filename": "file1.exe",
      "status": "bad",
      "matches": ["mimikatz_detection", "credential_dumper"],
      "scan_time": "2024-01-15T10:30:00Z",
      "bundle_used": "pe"
    }
  ],
  "total_files": 1,
  "scan_id": "uuid-here"
}
```

#### `POST /api/scan/text`
Scan text content

#### `GET /api/rules/stats`
Get rule statistics and system info

**Response:**
```json
{
  "built": "2024-01-15T09:00:00Z",
  "bundle_counts": {
    "generic": 4851,
    "scripts": 1688,
    "pe": 2059,
    "webshells": 310
  },
  "total_rules": 8908,
  "rss_mb": 83.7,
  "local_count": 5
}
```

#### `GET /api/rules/latest`
Get rule source information

#### `POST /api/admin/refresh`
Refresh rules (requires admin token)

## 🔒 Security Considerations

### Security Features

✅ **Input Validation**
- File size limits (20MB default)
- Filename sanitization (path traversal prevention)
- MIME type validation
- Archive extraction limits

✅ **Secure Processing**
- Temporary file isolation (`/tmp/edrscan/`)
- Janitor thread for automatic cleanup
- No file persistence beyond scan duration
- UUID-based temporary filenames with 0600 permissions

✅ **Network Security**
- Environment-based CORS configuration
- No outbound connections during runtime
- All rule fetching at build/update time only
- Complete air-gap operation support

✅ **Memory Protection**
- Memory usage monitoring (<2GB limit)
- Bundle-based loading (on-demand)
- Automatic garbage collection
- Resource exhaustion prevention

### Deployment Security

```bash
# Use non-root user (recommended)
docker run --user 1000:1000 edr-scanner

# Restrict network access
docker run --network none edr-scanner  # Air-gapped mode

# Set resource limits
docker run --memory=2g --cpus=2 edr-scanner
```

## 🧪 Development

### Prerequisites

- Python 3.12+
- Node.js 20+
- Git
- Docker (optional)

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/your-org/edr-safe-scanner.git
cd edr-safe-scanner

# Backend development setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Frontend development setup
cd ../frontend
yarn install

# Start development servers
# Terminal 1: Backend
cd backend && python -m uvicorn server:app --reload --port 8001

# Terminal 2: Frontend  
cd frontend && yarn start
```

### Running Tests

```bash
# Backend integration tests
cd tests
python test_scanner_enhanced_v2.py

# Security tests
python scripts/security_review.py
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Areas for Contribution

- 🔍 New detection rules (YARA/Sigma)
- 🚀 Performance optimizations
- 🎨 UI/UX improvements
- 📚 Documentation enhancements
- 🧪 Additional test cases
- 🔒 Security hardening

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **SigmaHQ** - For the excellent Sigma rule format and community rules
- **YARA** - For the powerful pattern matching engine
- **Rule Contributors** - All the security researchers contributing to open-source rule sets
- **Security Community** - For continuous feedback and improvements

---

**Built with ❤️ for the cybersecurity community**

*EDR-Safe Scanner v2 - Bringing enterprise-grade malware detection to everyone*