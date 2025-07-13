# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-01-15

### Added
- **Modular Bundle Architecture** - Dynamic rule loading with specialized bundles (PE, Scripts, Webshells, Generic)
- **Enhanced UI with Infotrust Branding** - Professional dashboard with real-time statistics
- **Advanced Security Hardening** - Path traversal protection, zip bomb prevention, secure file handling
- **Expanded Rule Sources** - Integration with 8+ public repositories (9,000+ rules)
- **Archive Analysis** - Intelligent zip extraction with safety controls
- **Real-time Monitoring** - RSS memory usage and live rule statistics
- **Weekly Auto-Updates** - Automated rule refresh system with cron scheduling
- **Comprehensive API** - RESTful endpoints with detailed documentation
- **Enhanced Testing Suite** - 15 test cases covering security and functionality

### Security
- **File Size Limits** - 20MB upload limit with proper enforcement
- **Filename Sanitization** - Prevention of path traversal attacks
- **Archive Security** - Zip bomb protection and extraction limits
- **Memory Protection** - 2GB RAM limit with monitoring
- **Secure Temp Storage** - UUID-based filenames with restricted permissions
- **No Outbound Traffic** - Complete offline operation during runtime

### Performance
- **Sub-100ms Scans** - Optimized scanning performance
- **Memory Efficient** - <100MB typical memory usage
- **Bundle Optimization** - On-demand rule loading
- **Deduplication** - Intelligent rule deduplication (39% reduction)

### Changed
- **Complete Frontend Rewrite** - Modern React interface with professional styling
- **Enhanced Detection Logic** - Improved status classification (clean/suspicious/bad)
- **Better Error Handling** - Comprehensive error messages and validation
- **Improved Documentation** - Detailed setup and usage instructions

### Fixed
- **Critical Detection Bug** - Fixed issue where all files returned "clean" status
- **Rule Compilation Issues** - Robust rule processing with error recovery
- **Memory Leaks** - Proper resource cleanup and garbage collection

## [1.0.0] - 2024-01-01

### Added
- Initial release
- Basic YARA rule scanning
- Simple web interface
- File upload functionality
- Basic rule compilation

### Security
- File upload validation
- Basic input sanitization

---

## Version History

- **v2.0.0** - Complete rewrite with enterprise features
- **v1.0.0** - Initial proof-of-concept release