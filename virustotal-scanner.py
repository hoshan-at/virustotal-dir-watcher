#!/usr/bin/env python3
"""
Enhanced VirusTotal Directory Scanner
Monitors directories for file changes and scans them using VirusTotal API
"""

import os
import sys
import time
import json
import hashlib
import logging
import threading
import queue
import signal
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque
from typing import Optional, Set, Dict, Tuple, List
from dataclasses import dataclass, field
from enum import Enum

import vt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

# ============================================================================
# Configuration
# ============================================================================

@dataclass
class Config:
    """Configuration settings for the scanner"""
    api_key: str = ""
    watch_directories: list = field(default_factory=lambda: ["/srv/syncthing/sync"])
    log_directory: str = "/opt/virustotal"
    scan_log_file: str = "/opt/virustotal/scanned_hashes.json"
    
    # Rate limiting
    api_requests_per_minute: int = 4
    api_timeout: int = 300  # seconds
    
    # File handling
    max_file_size_mb: int = 650  # VT limit is 650MB
    settle_time_seconds: int = 10
    quarantine_directory: str = "/opt/virustotal/quarantine"
    delete_malicious: bool = False  # Set to True to delete instead of quarantine
    
    # Exclusions
    excluded_extensions: Set[str] = field(default_factory=lambda: {
        '.tmp', '.temp', '.part', '.download', '.crdownload', '.lock'
    })
    excluded_patterns: Set[str] = field(default_factory=lambda: {
        '~*', '.*', 'Thumbs.db', 'desktop.ini'
    })
    
    # Logging
    log_level: str = "INFO"
    log_rotation_size_mb: int = 10
    log_rotation_count: int = 5
    
    @classmethod
    def from_file(cls, config_file: str) -> 'Config':
        """Load configuration from JSON file"""
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                data = json.load(f)
                return cls(**data)
        return cls()
    
    def validate(self) -> bool:
        """Validate configuration settings"""
        if not self.api_key or len(self.api_key) != 64:
            logging.error("Invalid or missing API key")
            return False
        
        for directory in self.watch_directories:
            if not os.path.exists(directory):
                logging.error(f"Watch directory does not exist: {directory}")
                return False
        
        # Create necessary directories
        os.makedirs(self.log_directory, exist_ok=True)
        if not self.delete_malicious:
            os.makedirs(self.quarantine_directory, exist_ok=True)
        
        return True


class ScanResult(Enum):
    """Possible scan results"""
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class FileInfo:
    """Information about a file to be scanned"""
    path: str
    hash: str
    size: int
    modified_time: float
    scan_result: Optional[ScanResult] = None
    vt_stats: Optional[Dict] = None
    error_message: Optional[str] = None


# ============================================================================
# Enhanced VirusTotal Client
# ============================================================================

class EnhancedVTClient:
    """Enhanced VirusTotal client with retry logic and better error handling"""
    
    def __init__(self, api_key: str, timeout: int = 300):
        self.api_key = api_key
        self.timeout = timeout
        self.client = None
        self._connect()
    
    def _connect(self):
        """Establish connection to VT API"""
        try:
            if self.client:
                self.client.close()
            self.client = vt.Client(self.api_key, timeout=self.timeout)
        except Exception as e:
            logging.error(f"Failed to connect to VT API: {e}")
            raise
    
    def scan_file(self, file_info: FileInfo, max_retries: int = 3) -> ScanResult:
        """Scan a file with retry logic"""
        for attempt in range(max_retries):
            try:
                # First, check if we already have a report
                try:
                    file_report = self.client.get_object(f"/files/{file_info.hash}")
                    stats = file_report.last_analysis_stats
                    file_info.vt_stats = stats
                    logging.info(f"Found existing VT report for '{os.path.basename(file_info.path)}'")
                    return self._evaluate_stats(stats)
                
                except vt.error.APIError as e:
                    if e.code != "NotFoundError":
                        raise
                    
                    # File not found, upload it
                    logging.info(f"Uploading '{os.path.basename(file_info.path)}' for analysis...")
                    
                    # Check file size
                    if file_info.size > 650 * 1024 * 1024:  # 650MB limit
                        logging.warning(f"File too large for VT: {file_info.path}")
                        file_info.error_message = "File too large for VirusTotal"
                        return ScanResult.SKIPPED
                    
                    with open(file_info.path, "rb") as f:
                        analysis = self.client.scan_file(f, wait_for_completion=True)
                        stats = analysis.stats
                        file_info.vt_stats = stats
                        return self._evaluate_stats(stats)
            
            except FileNotFoundError:
                logging.warning(f"File disappeared: {file_info.path}")
                file_info.error_message = "File not found"
                return ScanResult.ERROR
            
            except vt.error.APIError as e:
                logging.error(f"VT API error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    file_info.error_message = str(e)
                    return ScanResult.ERROR
            
            except Exception as e:
                logging.error(f"Unexpected error scanning file: {e}")
                file_info.error_message = str(e)
                return ScanResult.ERROR
        
        return ScanResult.ERROR
    
    def _evaluate_stats(self, stats: Dict) -> ScanResult:
        """Evaluate VT analysis statistics"""
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        logging.info(f"Analysis stats - Malicious: {malicious}, Suspicious: {suspicious}, "
                    f"Undetected: {stats.get('undetected', 0)}")
        
        if malicious > 0:
            return ScanResult.MALICIOUS
        elif suspicious > 2:  # More than 2 suspicious detections
            return ScanResult.SUSPICIOUS
        else:
            return ScanResult.CLEAN
    
    def close(self):
        """Close VT client connection"""
        if self.client:
            self.client.close()


# ============================================================================
# Token Bucket Rate Limiter
# ============================================================================

class TokenBucket:
    """Improved token bucket implementation for rate limiting"""
    
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
    
    def consume(self, tokens: int = 1, timeout: float = None) -> bool:
        """Try to consume tokens from the bucket"""
        start_time = time.time()
        
        while not self.stop_event.is_set():
            with self.lock:
                self._refill()
                
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    logging.debug(f"Token consumed. Remaining: {self.tokens}/{self.capacity}")
                    return True
            
            if timeout and (time.time() - start_time) >= timeout:
                return False
            
            time.sleep(0.1)
        
        return False
    
    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill
        tokens_to_add = elapsed * self.refill_rate
        
        if tokens_to_add > 0:
            self.tokens = min(self.capacity, self.tokens + tokens_to_add)
            self.last_refill = now
    
    def stop(self):
        """Stop the token bucket"""
        self.stop_event.set()


# ============================================================================
# Hash Database
# ============================================================================

class HashDatabase:
    """Manages the database of scanned file hashes"""
    
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.data = self._load()
        self.lock = threading.Lock()
    
    def _load(self) -> Dict:
        """Load hash database from file"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                # Try to migrate from old format (plain text with hashes)
                logging.info("Attempting to migrate from old hash log format...")
                return self._migrate_from_old_format()
            except Exception as e:
                logging.error(f"Failed to load hash database: {e}")
                return {"hashes": {}, "statistics": {}}
        
        # Check for old format file
        old_log = self.db_file.replace('.json', '.log')
        if os.path.exists(old_log):
            logging.info(f"Found old hash log at {old_log}, migrating...")
            return self._migrate_from_old_format()
        
        return {"hashes": {}, "statistics": {}}
    
    def _migrate_from_old_format(self) -> Dict:
        """Migrate from old plain text hash log to new JSON format"""
        data = {"hashes": {}, "statistics": {"migrated": 0}}
        
        # Try both possible locations
        old_files = [
            self.db_file.replace('.json', '.log'),
            '/opt/virustotal/scanned_hashes.log'
        ]
        
        for old_file in old_files:
            if os.path.exists(old_file):
                try:
                    with open(old_file, 'r') as f:
                        for line in f:
                            hash_val = line.strip()
                            if hash_val and len(hash_val) == 64:  # SHA256 hash
                                data["hashes"][hash_val] = {
                                    "result": "clean",
                                    "timestamp": datetime.now().isoformat(),
                                    "metadata": {"migrated": True}
                                }
                                data["statistics"]["migrated"] += 1
                    
                    logging.info(f"Migrated {data['statistics']['migrated']} hashes from old format")
                    # Rename old file to backup
                    os.rename(old_file, old_file + '.backup')
                    break
                except Exception as e:
                    logging.error(f"Failed to migrate from {old_file}: {e}")
        
        return data
    
    def save(self):
        """Save hash database to file"""
        try:
            with self.lock:
                with open(self.db_file, 'w') as f:
                    json.dump(self.data, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save hash database: {e}")
    
    def add_hash(self, file_hash: str, result: ScanResult, metadata: Dict = None):
        """Add a hash to the database"""
        with self.lock:
            # Convert any non-serializable objects to regular dicts
            clean_metadata = {}
            if metadata:
                for key, value in metadata.items():
                    if hasattr(value, '__dict__'):
                        # Convert VT objects to dict
                        clean_metadata[key] = dict(value)
                    elif isinstance(value, dict):
                        # Recursively clean nested dicts
                        clean_metadata[key] = {k: dict(v) if hasattr(v, '__dict__') else v 
                                              for k, v in value.items()}
                    else:
                        clean_metadata[key] = value
            
            self.data["hashes"][file_hash] = {
                "result": result.value,
                "timestamp": datetime.now().isoformat(),
                "metadata": clean_metadata
            }
            
            # Update statistics
            if "statistics" not in self.data:
                self.data["statistics"] = {}
            
            stats = self.data["statistics"]
            stats[result.value] = stats.get(result.value, 0) + 1
            stats["total_scanned"] = stats.get("total_scanned", 0) + 1
    
    def has_hash(self, file_hash: str) -> bool:
        """Check if hash exists in database"""
        return file_hash in self.data["hashes"]
    
    def get_hash_info(self, file_hash: str) -> Optional[Dict]:
        """Get information about a hash"""
        return self.data["hashes"].get(file_hash)
    
    def cleanup_old_entries(self, days: int = 30):
        """Remove entries older than specified days"""
        cutoff = datetime.now() - timedelta(days=days)
        with self.lock:
            to_remove = []
            for hash_val, info in self.data["hashes"].items():
                try:
                    timestamp = datetime.fromisoformat(info["timestamp"])
                    if timestamp < cutoff:
                        to_remove.append(hash_val)
                except:
                    pass
            
            for hash_val in to_remove:
                del self.data["hashes"][hash_val]
            
            if to_remove:
                logging.info(f"Cleaned up {len(to_remove)} old hash entries")


# ============================================================================
# File Handler
# ============================================================================

class FileHandler:
    """Handles file operations"""
    
    def __init__(self, config: Config):
        self.config = config
    
    @staticmethod
    def calculate_hash(file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logging.error(f"Failed to hash {file_path}: {e}")
            return None
    
    def should_scan_file(self, file_path: str) -> bool:
        """Determine if a file should be scanned"""
        path = Path(file_path)
        
        # Check if file exists and is a regular file
        if not path.exists() or not path.is_file():
            return False
        
        # Check excluded extensions
        if path.suffix.lower() in self.config.excluded_extensions:
            return False
        
        # Check excluded patterns
        for pattern in self.config.excluded_patterns:
            if path.match(pattern):
                return False
        
        # Check if it's the scan log file itself
        if str(path) == self.config.scan_log_file:
            return False
        
        return True
    
    def quarantine_file(self, file_path: str) -> bool:
        """Move file to quarantine directory"""
        try:
            quarantine_path = os.path.join(
                self.config.quarantine_directory,
                datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + os.path.basename(file_path)
            )
            os.rename(file_path, quarantine_path)
            logging.info(f"Quarantined file: {file_path} -> {quarantine_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to quarantine {file_path}: {e}")
            return False
    
    def handle_malicious_file(self, file_info: FileInfo):
        """Handle a malicious file based on configuration"""
        if self.config.delete_malicious:
            try:
                os.remove(file_info.path)
                logging.warning(f"DELETED malicious file: {file_info.path}")
            except Exception as e:
                logging.error(f"Failed to delete malicious file: {e}")
        else:
            self.quarantine_file(file_info.path)


# ============================================================================
# Directory Scanner
# ============================================================================

class DirectoryScanner:
    """Main scanner orchestrator"""
    
    def __init__(self, config: Config):
        self.config = config
        self.stop_event = threading.Event()
        self.scan_queue = queue.Queue()
        self.file_handler = FileHandler(config)
        self.hash_db = HashDatabase(config.scan_log_file)
        self.vt_client = EnhancedVTClient(config.api_key, config.api_timeout)
        self.token_bucket = TokenBucket(
            config.api_requests_per_minute,
            config.api_requests_per_minute / 60.0
        )
        self.is_scanning = False
        self.scan_lock = threading.Lock()
        self.stats = {
            "files_scanned": 0,
            "malicious_found": 0,
            "errors": 0,
            "start_time": datetime.now()
        }
    
    def scan_directory(self, directory: str) -> List[FileInfo]:
        """Scan a directory and return list of files to process"""
        files_to_scan = []
        
        for root, _, files in os.walk(directory):
            for filename in files:
                file_path = os.path.join(root, filename)
                
                if not self.file_handler.should_scan_file(file_path):
                    continue
                
                try:
                    stat = os.stat(file_path)
                    file_hash = self.file_handler.calculate_hash(file_path)
                    
                    if not file_hash:
                        continue
                    
                    # Check if already scanned
                    if self.hash_db.has_hash(file_hash):
                        hash_info = self.hash_db.get_hash_info(file_hash)
                        # Skip clean files entirely
                        if hash_info["result"] == "clean":
                            logging.debug(f"Skipping known clean file: {filename}")
                            continue
                        # Skip known malicious files
                        elif hash_info["result"] == "malicious":
                            logging.debug(f"Skipping known malicious file: {filename}")
                            continue
                        # Only re-scan errors and suspicious files
                        elif hash_info["result"] not in ["error", "suspicious"]:
                            continue
                        logging.info(f"Will re-scan previously {hash_info['result']} file: {filename}")
                    
                    files_to_scan.append(FileInfo(
                        path=file_path,
                        hash=file_hash,
                        size=stat.st_size,
                        modified_time=stat.st_mtime
                    ))
                    
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")
        
        return files_to_scan
    
    def process_file(self, file_info: FileInfo):
        """Process a single file through VirusTotal"""
        logging.info(f"Processing: {os.path.basename(file_info.path)}")
        
        # Check if we already know this file
        if self.hash_db.has_hash(file_info.hash):
            hash_info = self.hash_db.get_hash_info(file_info.hash)
            if hash_info["result"] == "clean":
                logging.debug(f"Skipping known clean file: {os.path.basename(file_info.path)}")
                return  # Skip API call entirely
            elif hash_info["result"] == "malicious":
                logging.warning(f"Known malicious file found again: {file_info.path}")
                self.file_handler.handle_malicious_file(file_info)
                return
        
        # Wait for rate limit token
        if not self.token_bucket.consume(1, timeout=60):
            logging.warning("Timeout waiting for rate limit token")
            file_info.scan_result = ScanResult.ERROR
            file_info.error_message = "Rate limit timeout"
            return
        
        # Scan the file
        result = self.vt_client.scan_file(file_info)
        file_info.scan_result = result
        
        # Update statistics
        self.stats["files_scanned"] += 1
        
        # Handle result
        if result == ScanResult.MALICIOUS:
            self.stats["malicious_found"] += 1
            logging.warning(f"MALICIOUS FILE DETECTED: {file_info.path}")
            self.file_handler.handle_malicious_file(file_info)
        elif result == ScanResult.SUSPICIOUS:
            logging.warning(f"SUSPICIOUS FILE: {file_info.path}")
        elif result == ScanResult.ERROR:
            self.stats["errors"] += 1
        
        # Save to database (convert vt_stats if present)
        metadata = {
            "path": file_info.path, 
            "size": file_info.size
        }
        if file_info.vt_stats:
            # Convert VT stats to plain dict
            metadata["vt_stats"] = dict(file_info.vt_stats) if hasattr(file_info.vt_stats, '__dict__') else file_info.vt_stats
        
        self.hash_db.add_hash(file_info.hash, result, metadata)
    
    def scan_cycle(self, do_rescan=True):
        """
        Perform a complete scan cycle
        
        Args:
            do_rescan: If True, immediately rescan directories after completing the first scan
        """
        with self.scan_lock:
            self.is_scanning = True
        
        try:
            logging.info("=== Starting scan cycle ===")
            
            # Keep scanning until no new files are found
            scan_iteration = 0
            total_files_processed = 0
            
            while True:
                scan_iteration += 1
                all_files = []
                
                if scan_iteration > 1:
                    logging.info(f"=== Starting rescan (iteration {scan_iteration}) ===")
                
                for directory in self.config.watch_directories:
                    files = self.scan_directory(directory)
                    all_files.extend(files)
                    if files:
                        logging.info(f"Found {len(files)} files to scan in {directory}")
                
                if not all_files:
                    if scan_iteration == 1:
                        logging.info("No new files to scan")
                    else:
                        logging.info(f"No new files found in rescan iteration {scan_iteration}")
                    break
                
                logging.info(f"Processing {len(all_files)} files in iteration {scan_iteration}...")
                total_files_processed += len(all_files)
                
                # Process files
                for file_info in all_files:
                    if self.stop_event.is_set():
                        break
                    self.process_file(file_info)
                
                # Save database after each iteration
                self.hash_db.save()
                
                # Only do one rescan if do_rescan is True
                if not do_rescan or scan_iteration >= 2:
                    break
                
                # Small delay before rescan to let filesystem settle
                time.sleep(2)
            
            if total_files_processed > 0:
                logging.info(f"Total files processed across all iterations: {total_files_processed}")
            
            # Log statistics
            self.log_statistics()
            
        finally:
            with self.scan_lock:
                self.is_scanning = False
            logging.info("=== Scan cycle complete, returning to listening mode ===")
    
    def log_statistics(self):
        """Log current statistics"""
        runtime = datetime.now() - self.stats["start_time"]
        logging.info(f"Statistics - Files: {self.stats['files_scanned']}, "
                    f"Malicious: {self.stats['malicious_found']}, "
                    f"Errors: {self.stats['errors']}, "
                    f"Runtime: {runtime}")
    
    def run(self):
        """Main run loop"""
        logging.info("Scanner starting...")
        
        # Initial scan with rescan
        self.scan_cycle(do_rescan=True)
        
        # Set up file system watcher
        observer = Observer()
        event_handler = ScanEventHandler(self)
        
        for directory in self.config.watch_directories:
            observer.schedule(event_handler, directory, recursive=True)
        
        observer.start()
        logging.info(f"Watching directories: {', '.join(self.config.watch_directories)}")
        logging.info("Now in listening mode - waiting for file changes...")
        
        # Main loop
        while not self.stop_event.is_set():
            try:
                # Wait for scan trigger
                trigger = self.scan_queue.get(timeout=60)
                
                if trigger is None:
                    break
                
                # Drain queue to handle burst of changes
                time.sleep(self.config.settle_time_seconds)
                while not self.scan_queue.empty():
                    try:
                        self.scan_queue.get_nowait()
                    except queue.Empty:
                        break
                
                # Perform scan with rescan
                self.scan_cycle(do_rescan=True)
                
                # Periodic cleanup
                if self.stats["files_scanned"] % 100 == 0:
                    self.hash_db.cleanup_old_entries()
                
            except queue.Empty:
                # Periodic maintenance
                self.hash_db.save()
            except Exception as e:
                logging.error(f"Error in main loop: {e}", exc_info=True)
        
        # Cleanup
        logging.info("Shutting down...")
        observer.stop()
        observer.join()
        self.vt_client.close()
        self.token_bucket.stop()
        self.hash_db.save()
        logging.info("Scanner stopped")
    
    def stop(self):
        """Stop the scanner"""
        self.stop_event.set()
        self.scan_queue.put(None)


# ============================================================================
# File System Event Handler
# ============================================================================

class ScanEventHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def __init__(self, scanner: DirectoryScanner):
        self.scanner = scanner
    
    def on_any_event(self, event: FileSystemEvent):
        """Handle any file system event"""
        # Ignore events during scanning
        with self.scanner.scan_lock:
            if self.scanner.is_scanning:
                return
        
        # Only handle file events
        if not event.is_directory:
            # Check if this is a file we care about
            path = event.dest_path if hasattr(event, 'dest_path') else event.src_path
            if self.scanner.file_handler.should_scan_file(path):
                logging.debug(f"File event detected: {path}")
                self.scanner.scan_queue.put(path)


# ============================================================================
# Main Entry Point
# ============================================================================

def setup_logging(config: Config):
    """Set up logging configuration"""
    from logging.handlers import RotatingFileHandler
    
    log_file = os.path.join(config.log_directory, "vt_scanner.log")
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=config.log_rotation_size_mb * 1024 * 1024,
        backupCount=config.log_rotation_count
    )
    file_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.log_level))
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="VirusTotal Directory Scanner")
    parser.add_argument(
        "--config",
        default="/opt/virustotal/config.json",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--api-key",
        help="VirusTotal API key (overrides config file)"
    )
    parser.add_argument(
        "--watch-dir",
        action="append",
        help="Directory to watch (can be specified multiple times)"
    )
    parser.add_argument(
        "--delete-malicious",
        action="store_true",
        help="Delete malicious files instead of quarantining"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = Config.from_file(args.config)
    
    # Override with command line arguments
    if args.api_key:
        config.api_key = args.api_key
    if args.watch_dir:
        config.watch_directories = args.watch_dir
    if args.delete_malicious:
        config.delete_malicious = True
    
    # Try environment variable for API key
    if not config.api_key:
        config.api_key = os.environ.get("VT_API_KEY", "")
    
    # Set up logging
    setup_logging(config)
    
    # Validate configuration
    if not config.validate():
        logging.critical("Invalid configuration. Exiting.")
        sys.exit(1)
    
    # Create scanner
    scanner = DirectoryScanner(config)
    
    # Set up signal handlers
    def signal_handler(signum, frame):
        logging.info(f"Received signal {signal.strsignal(signum)}")
        scanner.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run scanner
    try:
        scanner.run()
    except Exception as e:
        logging.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    
    logging.info("Scanner terminated")


if __name__ == "__main__":
    main()
