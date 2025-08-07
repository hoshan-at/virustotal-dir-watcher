## VirusTotal Directory Watcher

**⚠️ Personal Project Warning**: This was built for my personal use case and hasn't been thoroughly tested in production environments. Use at your own risk.

A Python-based file monitoring tool that automatically scans files using the VirusTotal API. Watches specified directories for changes and scans new/modified files, with rate limiting and hash-based deduplication to avoid redundant scans.

### Features
- Real-time directory monitoring with file system events
- VirusTotal API integration with retry logic
- Rate limiting to respect API quotas
- Hash-based duplicate detection
- Malicious file quarantine/deletion
- Persistent scan history database
- Comprehensive logging

