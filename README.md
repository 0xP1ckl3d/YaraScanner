# EDR-Safe Scanner v2

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/react-18.0+-61dafb.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)

**EDR-Safe Scanner** is a comprehensive, offline malware detection system that combines YARA and Sigma rules for local threat analysis. Built for security professionals who need reliable, air-gapped malware scanning capabilities.

## 🚀 Features

### Core Capabilities
- **🔒 100% Offline Operation** - No data leaves your environment
- **🎯 Multi-Engine Detection** - YARA + Sigma rule integration
- **📦 Modular Architecture** - Specialized detection bundles (PE, Scripts, Webshells, Generic)
- **⚡ High Performance** - <100ms scan times, <2GB memory usage
- **🌐 Modern Web Interface** - Professional React-based dashboard
- **📊 Real-time Monitoring** - Live memory usage and rule statistics

### Security Features
- **🛡️ Secure File Handling** - Path traversal protection, zip bomb prevention
- **🔐 Archive Analysis** - Intelligent extraction with safety limits
- **📏 Size Limits** - 20MB upload limit with configurable thresholds
- **🧹 Auto Cleanup** - Secure temporary file management
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
3. Start the web interface and API server

## 🛠️ Installation

### Option 1: Docker Deployment (Recommended)

**Prerequisites:**
- Docker 20.0+
- Docker Compose 2.0+
- 4GB RAM minimum
- 10GB disk space

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

### Option 2: Manual Installation

**Prerequisites:**
- Python 3.11+
- Node.js 18+
- MongoDB 7.0+
- Git
- 4GB RAM minimum

#### Backend Setup

```bash
# Clone repository
git clone https://github.com/your-org/edr-safe-scanner.git
cd edr-safe-scanner

# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y libmagic1 libmagic-dev git wget unzip

# Setup Python environment
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure environment
cp .env.template .env
nano .env  # Edit configuration

# Setup MongoDB
# Install MongoDB 7.0+ and start service
sudo systemctl start mongod
```

#### Frontend Setup

```bash
# Install Node.js dependencies
cd ../frontend
npm install

# Configure environment
cp .env.template .env
nano .env  # Set REACT_APP_BACKEND_URL

# Build production version
npm run build
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
# Database
MONGO_URL=mongodb://localhost:27017
DB_NAME=edr_scanner

# Security
ADMIN_TOKEN=your-secure-admin-token  # Optional: enables /admin/refresh

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

#### Custom Sigma Rules

```bash
# Add Sigma rules (will be converted to YARA)
mkdir -p rules/sigma/custom
cat > rules/sigma/custom/custom_rule.yml << 'EOF'
title: Custom PowerShell Detection
description: Detects suspicious PowerShell activity
author: Your Name
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4103
        Message|contains:
            - 'Invoke-Expression'
            - 'DownloadString'
    condition: selection
EOF

# Recompile rules
python3 scripts/compile_rules_v2.py
```

#### Private Rule Repositories

```bash
# Add private repository to fetch script
# Edit scripts/fetch_rules_v2.sh

# Add authentication if needed
git clone https://username:token@github.com/org/private-rules.git yara/private
```

### Rule Bundle Management

The scanner organizes rules into specialized bundles:

#### Bundle Types

- **`generic.yc`** - General malware patterns, helper rules
- **`scripts.yc`** - PowerShell, VBS, JavaScript, Python scripts  
- **`pe.yc`** - PE executables, packed binaries, DLLs
- **`webshells.yc`** - Web-based backdoors and shells

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

**Request:**
```bash
curl -X POST "http://localhost:8001/api/scan/text" \
  -F "content=powershell -enc ZXZpbCBjb2Rl" \
  -F "filename=suspicious.ps1"
```

#### `GET /api/rules/stats`
Get rule statistics and system info

**Response:**
```json
{
  "built": "2024-01-15T09:00:00Z",
  "bundle_counts": {
    "generic": 5318,
    "scripts": 1726,
    "pe": 2106,
    "webshells": 45
  },
  "total_rules": 9195,
  "rss_mb": 83.7,
  "local_count": 5
}
```

#### `GET /api/rules/latest`
Get rule source information

#### `POST /api/admin/refresh`
Refresh rules (requires admin token)

**Request:**
```bash
curl -X POST "http://localhost:8001/api/admin/refresh" \
  -F "admin_token=your-admin-token"
```

### Status Codes

- `200` - Success
- `400` - Bad request (invalid parameters)
- `413` - Payload too large (>20MB)
- `422` - Validation error
- `500` - Internal server error
- `503` - Service unavailable (rules not loaded)

### Rate Limiting

- **File scans**: No built-in rate limiting
- **Concurrent uploads**: Limited by `--workers 2` setting
- **Memory protection**: Automatic cleanup prevents exhaustion

## 🔒 Security Considerations

### Security Features

✅ **Input Validation**
- File size limits (20MB default)
- Filename sanitization (path traversal prevention)
- MIME type validation
- Archive extraction limits

✅ **Secure Processing**
- Temporary file isolation (`/tmp/edrscan/`)
- Automatic cleanup after scanning
- No file persistence beyond scan duration
- UUID-based temporary filenames with 0600 permissions

✅ **Network Security**
- No outbound connections during runtime
- All rule fetching at build/update time only
- No telemetry or analytics
- Complete air-gap operation support

✅ **Memory Protection**
- Memory usage monitoring (<2GB limit)
- Bundle-based loading (on-demand)
- Automatic garbage collection
- Resource exhaustion prevention

### Security Best Practices

#### Deployment Security

```bash
# Use non-root user (recommended)
docker run --user 1000:1000 edr-scanner

# Restrict network access
docker run --network none edr-scanner  # Air-gapped mode

# Mount read-only volumes
docker run -v /rules:/app/rules:ro edr-scanner

# Set resource limits
docker run --memory=2g --cpus=2 edr-scanner
```

#### File Handling Security

- Files are processed in isolated temporary directories
- No file contents are logged or persisted
- Archive extraction has depth and size limits
- Malicious filenames are sanitized automatically

#### Network Security

- No external API calls during scanning
- Rule updates only at deployment/maintenance windows
- Support for completely offline operation
- No user data transmission

### Known Limitations

⚠️ **Performance Limits**
- 20MB maximum file size per upload
- 30MB maximum archive extraction size
- 2GB RAM usage limit

⚠️ **Detection Limits**
- Static analysis only (no dynamic execution)
- YARA/Sigma rule dependent detection
- No machine learning or behavioral analysis

## 🧪 Development

### Prerequisites

- Python 3.11+
- Node.js 18+
- MongoDB 7.0+
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
pip install -r requirements-dev.txt  # If you create dev requirements

# Frontend development setup
cd ../frontend
npm install
npm install --save-dev @testing-library/react @testing-library/jest-dom

# Start development servers
# Terminal 1: Backend
cd backend && python -m uvicorn server:app --reload --port 8001

# Terminal 2: Frontend  
cd frontend && npm start

# Terminal 3: MongoDB
mongod --dbpath ./data/db
```

### Running Tests

```bash
# Backend tests
cd backend
python -m pytest tests/ -v

# Frontend tests
cd frontend
npm test

# Integration tests
cd tests
python test_scanner_enhanced_v2.py

# Security tests
python scripts/security_review.py
```

### Code Style

```bash
# Python formatting
cd backend
black .
isort .
flake8 .

# JavaScript formatting
cd frontend
npm run lint
npm run format
```

### Adding New Features

1. **New Detection Rules**: Add to `rules/local/` directory
2. **New Bundles**: Modify `scripts/compile_rules_v2.py`
3. **New Endpoints**: Add to `backend/server.py`
4. **UI Changes**: Modify `frontend/src/App.js`

### Performance Optimization

```bash
# Profile memory usage
python -m memory_profiler backend/server.py

# Profile rule compilation
python -m cProfile scripts/compile_rules_v2.py

# Optimize bundle loading
# Monitor bundle-specific performance in logs
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Quick Contribution Guide

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

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

## 📞 Support

- **Documentation**: Check this README and inline code comments
- **Issues**: Open a GitHub issue for bugs or feature requests
- **Security Issues**: Email security@your-domain.com for responsible disclosure
- **Discussions**: Use GitHub Discussions for questions and community support

---

**Built with ❤️ for the cybersecurity community**

*EDR-Safe Scanner v2 - Bringing enterprise-grade malware detection to everyone*