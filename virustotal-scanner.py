#!/usr/bin/env python3
"""
Enhanced VirusTotal Directory Scanner with Continuous Parallel Processing
Monitors directories for file changes and scans them using VirusTotal API
Supports continuous processing with up to 4 parallel threads
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
from collections import defaultdict
from typing import Optional, Set, Dict, Tuple, List, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future
import traceback

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
    
    # Rate limiting and parallelism
    api_requests_per_minute: int = 4
    api_timeout: int = 300  # seconds
    max_parallel_uploads: int = 4  # Maximum number of parallel upload threads
    
    # File handling
    max_file_size_mb: int = 650  # VT limit is 650MB
    settle_time_seconds: int = 10  # Time to wait for file to settle
    quarantine_directory: str = "/opt/virustotal/quarantine"
    delete_malicious: bool = False  # Set to True to delete instead of quarantine
    
    # Queue management
    max_queue_size: int = 1000  # Maximum files in processing queue
    batch_check_interval: int = 5  # Seconds between checking for settled files
    
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
    hash: Optional[str] = None
    size: Optional[int] = None
    modified_time: Optional[float] = None
    first_seen_time: float = field(default_factory=time.time)
    scan_result: Optional[ScanResult] = None
    vt_stats: Optional[Dict] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    
    def __hash__(self):
        """Make FileInfo hashable based on path"""
        return hash(self.path)
    
    def __eq__(self, other):
        """Equality based on path"""
        if isinstance(other, FileInfo):
            return self.path == other.path
        return False


# ============================================================================
# Thread-Safe VT Client Pool
# ============================================================================

class VTClientPool:
    """Thread-safe pool of VT clients for parallel operations"""
    
    def __init__(self, api_key: str, timeout: int = 300, pool_size: int = 4):
        self.api_key = api_key
        self.timeout = timeout
        self.pool_size = pool_size
        self._lock = threading.Lock()
        self._closed = False
        self._thread_locals = threading.local()
        self._all_clients = []  # Keep track of all created clients
        self._clients_lock = threading.Lock()
    
    def _get_or_create_client(self) -> vt.Client:
        """Get or create a client for the current thread"""
        # Use thread-local storage to ensure each thread has its own client
        if not hasattr(self._thread_locals, 'client'):
            # Create a new client without timeout (we'll handle timeout ourselves)
            client = vt.Client(self.api_key)
            self._thread_locals.client = client
            
            # Keep track of all clients for cleanup
            with self._clients_lock:
                self._all_clients.append(client)
        
        return self._thread_locals.client
    
    def acquire(self, timeout: Optional[float] = None) -> vt.Client:
        """Acquire a client for the current thread"""
        if self._closed:
            raise RuntimeError("Client pool is closed")
        
        return self._get_or_create_client()
    
    def release(self, client: vt.Client):
        """Release a client (no-op for thread-local clients)"""
        # No-op since we're using thread-local storage
        pass
    
    def close(self):
        """Close all clients in the pool"""
        self._closed = True
        
        # Close all tracked clients
        with self._clients_lock:
            for client in self._all_clients:
                try:
                    client.close()
                except Exception as e:
                    logging.debug(f"Error closing client: {e}")
            self._all_clients.clear()


# ============================================================================
# Enhanced VirusTotal Client
# ============================================================================

class EnhancedVTClient:
    """Enhanced VirusTotal client with retry logic and thread safety"""
    
    def __init__(self, client_pool: VTClientPool):
        self.client_pool = client_pool
    
    def scan_file(self, file_info: FileInfo, max_retries: int = 3) -> ScanResult:
        """Scan a file with retry logic using a client from the pool"""
        client = None
        
        try:
            # Acquire a client from the pool
            client = self.client_pool.acquire(timeout=30)
            
            # Ensure we have the file hash
            if not file_info.hash:
                file_info.hash = FileHandler.calculate_hash(file_info.path)
                if not file_info.hash:
                    file_info.error_message = "Failed to calculate file hash"
                    return ScanResult.ERROR
            
            for attempt in range(max_retries):
                try:
                    # First, check if we already have a report
                    try:
                        file_report = client.get_object(f"/files/{file_info.hash}")
                        stats = file_report.last_analysis_stats
                        file_info.vt_stats = stats
                        logging.info(f"[Thread-{threading.current_thread().ident}] Found existing VT report for '{os.path.basename(file_info.path)}'")
                        return self._evaluate_stats(stats)
                    
                    except vt.error.APIError as e:
                        if e.code != "NotFoundError":
                            raise
                        
                        # File not found, upload it
                        logging.info(f"[Thread-{threading.current_thread().ident}] Uploading '{os.path.basename(file_info.path)}' for analysis...")
                        
                        # Get file size if not already set
                        if file_info.size is None:
                            try:
                                file_info.size = os.path.getsize(file_info.path)
                            except:
                                file_info.error_message = "Failed to get file size"
                                return ScanResult.ERROR
                        
                        # Check file size
                        if file_info.size > 650 * 1024 * 1024:  # 650MB limit
                            logging.warning(f"File too large for VT: {file_info.path}")
                            file_info.error_message = "File too large for VirusTotal"
                            return ScanResult.SKIPPED
                        
                        with open(file_info.path, "rb") as f:
                            # Upload file without wait_for_completion to avoid timeout issues
                            analysis = client.scan_file(f)
                            
                            # Manually poll for completion
                            analysis_id = analysis.id
                            max_wait = 300  # 5 minutes max wait
                            poll_interval = 5  # Check every 5 seconds
                            waited = 0
                            
                            logging.debug(f"[Thread-{threading.current_thread().ident}] Waiting for analysis {analysis_id}")
                            
                            while waited < max_wait:
                                time.sleep(poll_interval)
                                waited += poll_interval
                                
                                try:
                                    analysis_report = client.get_object(f"/analyses/{analysis_id}")
                                    status = getattr(analysis_report, 'status', 'unknown')
                                    
                                    if status == "completed":
                                        stats = analysis_report.stats
                                        file_info.vt_stats = stats
                                        return self._evaluate_stats(stats)
                                    elif status in ["queued", "in-progress"]:
                                        logging.debug(f"[Thread-{threading.current_thread().ident}] Analysis status: {status}, waiting...")
                                        continue
                                    else:
                                        logging.warning(f"Unknown analysis status: {status}")
                                        break
                                except vt.error.APIError as poll_error:
                                    logging.error(f"Error polling analysis status: {poll_error}")
                                    if "NotFoundError" in str(poll_error):
                                        # Analysis might not be ready yet
                                        continue
                                    break
                            
                            # If we got here, analysis timed out or failed
                            logging.warning(f"Analysis timed out or failed for {file_info.path}")
                            file_info.error_message = "Analysis timeout"
                            return ScanResult.ERROR
                
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
                    logging.error(f"Unexpected error scanning file (attempt {attempt + 1}/{max_retries}): {e}")
                    logging.debug(f"Traceback: {traceback.format_exc()}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                    else:
                        file_info.error_message = str(e)
                        return ScanResult.ERROR
            
            return ScanResult.ERROR
        
        except Exception as e:
            logging.error(f"Critical error in scan_file: {e}")
            return ScanResult.ERROR
        
        finally:
            # Always release the client back to the pool
            if client:
                self.client_pool.release(client)
    
    def _evaluate_stats(self, stats: Dict) -> ScanResult:
        """Evaluate VT analysis statistics"""
        # Handle both dict and object types for stats
        if hasattr(stats, '__dict__'):
            stats = dict(stats)
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        logging.info(f"[Thread-{threading.current_thread().ident}] Analysis stats - Malicious: {malicious}, Suspicious: {suspicious}, "
                    f"Undetected: {stats.get('undetected', 0)}")
        
        if malicious > 0:
            return ScanResult.MALICIOUS
        elif suspicious > 2:  # More than 2 suspicious detections
            return ScanResult.SUSPICIOUS
        else:
            return ScanResult.CLEAN


# ============================================================================
# Token Bucket Rate Limiter
# ============================================================================

class TokenBucket:
    """Token bucket implementation for rate limiting"""
    
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.waiting_threads = 0
    
    def consume(self, tokens: int = 1, timeout: float = None) -> bool:
        """Try to consume tokens from the bucket"""
        start_time = time.time()
        
        with self.lock:
            self.waiting_threads += 1
        
        try:
            while not self.stop_event.is_set():
                with self.lock:
                    self._refill()
                    
                    if self.tokens >= tokens:
                        self.tokens -= tokens
                        logging.debug(f"Token consumed by Thread-{threading.current_thread().ident}. "
                                    f"Remaining: {self.tokens:.2f}/{self.capacity}, "
                                    f"Waiting threads: {self.waiting_threads - 1}")
                        return True
                
                if timeout and (time.time() - start_time) >= timeout:
                    return False
                
                # Adaptive sleep based on expected refill time
                with self.lock:
                    tokens_needed = tokens - self.tokens
                    time_to_refill = tokens_needed / self.refill_rate
                    sleep_time = min(0.5, max(0.1, time_to_refill))
                
                time.sleep(sleep_time)
            
            return False
        finally:
            with self.lock:
                self.waiting_threads -= 1
    
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
# Thread-Safe Hash Database
# ============================================================================

class HashDatabase:
    """Manages the database of scanned file hashes"""
    
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.data = self._load()
        self.lock = threading.Lock()
        self._save_counter = 0
        self._save_interval = 10  # Save every N updates
    
    def _load(self) -> Dict:
        """Load hash database from file"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logging.info("Attempting to migrate from old hash log format...")
                return self._migrate_from_old_format()
            except Exception as e:
                logging.error(f"Failed to load hash database: {e}")
        
        return {"hashes": {}, "statistics": {}}
    
    def _migrate_from_old_format(self) -> Dict:
        """Migrate from old plain text hash log to new JSON format"""
        data = {"hashes": {}, "statistics": {"migrated": 0}}
        
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
                            if hash_val and len(hash_val) == 64:
                                data["hashes"][hash_val] = {
                                    "result": "clean",
                                    "timestamp": datetime.now().isoformat(),
                                    "metadata": {"migrated": True}
                                }
                                data["statistics"]["migrated"] += 1
                    
                    logging.info(f"Migrated {data['statistics']['migrated']} hashes from old format")
                    os.rename(old_file, old_file + '.backup')
                    break
                except Exception as e:
                    logging.error(f"Failed to migrate from {old_file}: {e}")
        
        return data
    
    def save(self, force: bool = False):
        """Save hash database to file"""
        try:
            with self.lock:
                if not force:
                    self._save_counter += 1
                    if self._save_counter < self._save_interval:
                        return
                    self._save_counter = 0
                
                with open(self.db_file, 'w') as f:
                    json.dump(self.data, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save hash database: {e}")
    
    def add_hash(self, file_hash: str, result: ScanResult, metadata: Dict = None):
        """Add a hash to the database"""
        with self.lock:
            clean_metadata = {}
            if metadata:
                for key, value in metadata.items():
                    if hasattr(value, '__dict__'):
                        clean_metadata[key] = dict(value)
                    elif isinstance(value, dict):
                        clean_metadata[key] = {k: dict(v) if hasattr(v, '__dict__') else v 
                                              for k, v in value.items()}
                    else:
                        clean_metadata[key] = value
            
            self.data["hashes"][file_hash] = {
                "result": result.value,
                "timestamp": datetime.now().isoformat(),
                "metadata": clean_metadata
            }
            
            if "statistics" not in self.data:
                self.data["statistics"] = {}
            
            stats = self.data["statistics"]
            stats[result.value] = stats.get(result.value, 0) + 1
            stats["total_scanned"] = stats.get("total_scanned", 0) + 1
        
        # Periodic save
        self.save(force=False)
    
    def has_hash(self, file_hash: str) -> bool:
        """Check if hash exists in database"""
        with self.lock:
            return file_hash in self.data["hashes"]
    
    def get_hash_info(self, file_hash: str) -> Optional[Dict]:
        """Get information about a hash"""
        with self.lock:
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
        
        if not path.exists() or not path.is_file():
            return False
        
        if path.suffix.lower() in self.config.excluded_extensions:
            return False
        
        for pattern in self.config.excluded_patterns:
            if path.match(pattern):
                return False
        
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
# Continuous File Processor
# ============================================================================

class ContinuousFileProcessor:
    """Manages continuous file processing with multiple worker threads"""
    
    def __init__(self, config: Config, hash_db: HashDatabase, vt_client: EnhancedVTClient,
                 token_bucket: TokenBucket, file_handler: FileHandler):
        self.config = config
        self.hash_db = hash_db
        self.vt_client = vt_client
        self.token_bucket = token_bucket
        self.file_handler = file_handler
        
        # Queues
        self.pending_files = {}  # path -> FileInfo, for files waiting to settle
        self.pending_lock = threading.Lock()
        
        self.processing_queue = queue.Queue(maxsize=config.max_queue_size)
        self.currently_processing = set()  # Paths currently being processed
        self.processing_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            "files_queued": 0,
            "files_processed": 0,
            "files_clean": 0,
            "files_malicious": 0,
            "files_suspicious": 0,
            "files_error": 0,
            "files_skipped": 0,
            "start_time": datetime.now()
        }
        self.stats_lock = threading.Lock()
        
        # Control
        self.stop_event = threading.Event()
        self.executor = ThreadPoolExecutor(
            max_workers=config.max_parallel_uploads,
            thread_name_prefix="VTWorker"
        )
        
        # Start the settling checker thread
        self.settling_thread = threading.Thread(target=self._settling_checker, daemon=True)
        self.settling_thread.start()
        
        # Start worker threads
        self.workers = []
        for i in range(config.max_parallel_uploads):
            worker = threading.Thread(target=self._worker, daemon=True, name=f"VTWorker-{i}")
            worker.start()
            self.workers.append(worker)
    
    def add_file(self, file_path: str):
        """Add a file to be processed"""
        if not self.file_handler.should_scan_file(file_path):
            return
        
        # Check if already processing
        with self.processing_lock:
            if file_path in self.currently_processing:
                logging.debug(f"File already being processed: {file_path}")
                return
        
        # Add to pending files with timestamp
        with self.pending_lock:
            if file_path not in self.pending_files:
                self.pending_files[file_path] = FileInfo(path=file_path)
                logging.debug(f"File added to pending queue: {file_path}")
                
                with self.stats_lock:
                    self.stats["files_queued"] += 1
            else:
                # Update timestamp for existing pending file
                self.pending_files[file_path].first_seen_time = time.time()
    
    def _settling_checker(self):
        """Background thread that moves settled files to processing queue"""
        while not self.stop_event.is_set():
            try:
                current_time = time.time()
                files_to_process = []
                
                with self.pending_lock:
                    for path, file_info in list(self.pending_files.items()):
                        # Check if file has settled
                        if current_time - file_info.first_seen_time >= self.config.settle_time_seconds:
                            # Verify file still exists
                            if os.path.exists(path):
                                files_to_process.append(file_info)
                            del self.pending_files[path]
                
                # Add settled files to processing queue
                for file_info in files_to_process:
                    try:
                        # Calculate hash and get file info
                        file_info.hash = self.file_handler.calculate_hash(file_info.path)
                        if not file_info.hash:
                            logging.warning(f"Failed to hash file: {file_info.path}")
                            continue
                        
                        # Check if we already know this file
                        if self._check_known_file(file_info):
                            continue
                        
                        # Get file stats
                        try:
                            stat = os.stat(file_info.path)
                            file_info.size = stat.st_size
                            file_info.modified_time = stat.st_mtime
                        except:
                            continue
                        
                        # Add to processing queue
                        with self.processing_lock:
                            if file_info.path not in self.currently_processing:
                                self.currently_processing.add(file_info.path)
                                self.processing_queue.put(file_info, block=False)
                                logging.info(f"File queued for processing: {os.path.basename(file_info.path)}")
                            
                    except queue.Full:
                        logging.warning(f"Processing queue full, dropping file: {file_info.path}")
                        with self.processing_lock:
                            self.currently_processing.discard(file_info.path)
                    except Exception as e:
                        logging.error(f"Error queuing file {file_info.path}: {e}")
                
                # Sleep before next check
                time.sleep(self.config.batch_check_interval)
                
            except Exception as e:
                logging.error(f"Error in settling checker: {e}")
                time.sleep(1)
    
    def _check_known_file(self, file_info: FileInfo) -> bool:
        """Check if we already know this file and handle accordingly"""
        if self.hash_db.has_hash(file_info.hash):
            hash_info = self.hash_db.get_hash_info(file_info.hash)
            result = hash_info["result"]
            
            if result == "clean":
                logging.debug(f"Skipping known clean file: {os.path.basename(file_info.path)}")
                return True
            elif result == "malicious":
                logging.warning(f"Known malicious file detected: {file_info.path}")
                file_info.scan_result = ScanResult.MALICIOUS
                self.file_handler.handle_malicious_file(file_info)
                return True
            elif result == "suspicious":
                logging.info(f"Re-scanning suspicious file: {os.path.basename(file_info.path)}")
                return False
            elif result == "error":
                # Retry errors
                return False
        
        return False
    
    def _worker(self):
        """Worker thread that processes files from the queue"""
        thread_name = threading.current_thread().name
        logging.info(f"{thread_name} started")
        
        while not self.stop_event.is_set():
            try:
                # Get file from queue with timeout
                try:
                    file_info = self.processing_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                logging.info(f"[{thread_name}] Processing: {os.path.basename(file_info.path)}")
                
                # Process the file
                try:
                    # Wait for rate limit token
                    if not self.token_bucket.consume(1, timeout=60):
                        logging.warning(f"[{thread_name}] Rate limit timeout for {file_info.path}")
                        file_info.scan_result = ScanResult.ERROR
                        file_info.error_message = "Rate limit timeout"
                    else:
                        # Scan the file
                        file_info.scan_result = self.vt_client.scan_file(file_info)
                    
                    # Handle result
                    self._handle_scan_result(file_info)
                    
                    # Update statistics
                    with self.stats_lock:
                        self.stats["files_processed"] += 1
                        if file_info.scan_result == ScanResult.CLEAN:
                            self.stats["files_clean"] += 1
                        elif file_info.scan_result == ScanResult.MALICIOUS:
                            self.stats["files_malicious"] += 1
                        elif file_info.scan_result == ScanResult.SUSPICIOUS:
                            self.stats["files_suspicious"] += 1
                        elif file_info.scan_result == ScanResult.ERROR:
                            self.stats["files_error"] += 1
                        elif file_info.scan_result == ScanResult.SKIPPED:
                            self.stats["files_skipped"] += 1
                    
                    # Log progress periodically
                    if self.stats["files_processed"] % 10 == 0:
                        self.log_statistics()
                    
                except Exception as e:
                    logging.error(f"[{thread_name}] Error processing {file_info.path}: {e}")
                    logging.debug(traceback.format_exc())
                
                finally:
                    # Remove from currently processing set
                    with self.processing_lock:
                        self.currently_processing.discard(file_info.path)
                    
                    # Mark task as done
                    self.processing_queue.task_done()
                
            except Exception as e:
                logging.error(f"[{thread_name}] Worker error: {e}")
                time.sleep(1)
        
        logging.info(f"{thread_name} stopped")
    
    def _handle_scan_result(self, file_info: FileInfo):
        """Handle the result of a file scan"""
        if file_info.scan_result == ScanResult.MALICIOUS:
            logging.warning(f"MALICIOUS FILE DETECTED: {file_info.path}")
            self.file_handler.handle_malicious_file(file_info)
        elif file_info.scan_result == ScanResult.SUSPICIOUS:
            logging.warning(f"SUSPICIOUS FILE: {file_info.path}")
        elif file_info.scan_result == ScanResult.ERROR:
            logging.error(f"Error scanning {file_info.path}: {file_info.error_message}")
        
        # Save to database
        if file_info.hash:
            metadata = {
                "path": file_info.path,
                "size": file_info.size,
                "error": file_info.error_message
            }
            if file_info.vt_stats:
                metadata["vt_stats"] = dict(file_info.vt_stats) if hasattr(file_info.vt_stats, '__dict__') else file_info.vt_stats
            
            self.hash_db.add_hash(file_info.hash, file_info.scan_result, metadata)
    
    def scan_directory(self, directory: str):
        """Scan a directory and queue all files for processing"""
        logging.info(f"Scanning directory: {directory}")
        files_found = 0
        
        for root, _, files in os.walk(directory):
            for filename in files:
                file_path = os.path.join(root, filename)
                
                if not self.file_handler.should_scan_file(file_path):
                    continue
                
                # Quick check if we already know this file
                try:
                    file_hash = self.file_handler.calculate_hash(file_path)
                    if file_hash and self.hash_db.has_hash(file_hash):
                        hash_info = self.hash_db.get_hash_info(file_hash)
                        if hash_info["result"] in ["clean", "malicious"]:
                            continue
                    
                    self.add_file(file_path)
                    files_found += 1
                    
                except Exception as e:
                    logging.error(f"Error checking {file_path}: {e}")
        
        if files_found > 0:
            logging.info(f"Found {files_found} files to scan in {directory}")
    
    def log_statistics(self):
        """Log current statistics"""
        with self.stats_lock:
            runtime = datetime.now() - self.stats["start_time"]
            
            with self.pending_lock:
                pending_count = len(self.pending_files)
            
            with self.processing_lock:
                processing_count = len(self.currently_processing)
            
            queue_size = self.processing_queue.qsize()
            
            logging.info(
                f"Stats - Processed: {self.stats['files_processed']}, "
                f"Clean: {self.stats['files_clean']}, "
                f"Malicious: {self.stats['files_malicious']}, "
                f"Errors: {self.stats['files_error']} | "
                f"Queue: {queue_size}, Processing: {processing_count}, "
                f"Pending: {pending_count} | "
                f"Runtime: {runtime}"
            )
    
    def stop(self):
        """Stop the processor"""
        logging.info("Stopping continuous processor...")
        self.stop_event.set()
        
        # Wait for settling thread
        if self.settling_thread.is_alive():
            self.settling_thread.join(timeout=5)
        
        # Wait for worker threads
        for worker in self.workers:
            if worker.is_alive():
                worker.join(timeout=5)
        
        # Final statistics
        self.log_statistics()
        
        # Save database
        self.hash_db.save(force=True)


# ============================================================================
# Directory Scanner
# ============================================================================

class DirectoryScanner:
    """Main scanner orchestrator with continuous processing"""
    
    def __init__(self, config: Config):
        self.config = config
        self.stop_event = threading.Event()
        
        # Initialize components
        self.file_handler = FileHandler(config)
        self.hash_db = HashDatabase(config.scan_log_file)
        
        # Create VT client pool
        self.vt_client_pool = VTClientPool(
            config.api_key,
            config.api_timeout,
            config.max_parallel_uploads
        )
        self.vt_client = EnhancedVTClient(self.vt_client_pool)
        
        # Rate limiting
        self.token_bucket = TokenBucket(
            config.api_requests_per_minute,
            config.api_requests_per_minute / 60.0
        )
        
        # Continuous processor
        self.processor = ContinuousFileProcessor(
            config, self.hash_db, self.vt_client,
            self.token_bucket, self.file_handler
        )
    
    def run(self):
        """Main run loop"""
        logging.info(f"Scanner starting with {self.config.max_parallel_uploads} parallel threads...")
        logging.info("Continuous processing mode enabled")
        
        # Initial directory scan
        logging.info("Performing initial directory scan...")
        for directory in self.config.watch_directories:
            self.processor.scan_directory(directory)
        
        # Set up file system watcher
        observer = Observer()
        event_handler = ScanEventHandler(self.processor)
        
        for directory in self.config.watch_directories:
            observer.schedule(event_handler, directory, recursive=True)
        
        observer.start()
        logging.info(f"Watching directories: {', '.join(self.config.watch_directories)}")
        logging.info("Scanner running - processing files continuously...")
        
        # Main loop
        try:
            while not self.stop_event.is_set():
                time.sleep(30)  # Wake up periodically
                
                # Periodic maintenance
                self.processor.log_statistics()
                self.hash_db.save(force=False)
                
                # Cleanup old entries monthly
                if datetime.now().day == 1 and datetime.now().hour == 0:
                    self.hash_db.cleanup_old_entries()
        
        except KeyboardInterrupt:
            logging.info("Received interrupt signal")
        
        finally:
            # Cleanup
            logging.info("Shutting down...")
            
            # Stop observer
            observer.stop()
            observer.join()
            
            # Stop processor
            self.processor.stop()
            
            # Close VT client pool
            try:
                self.vt_client_pool.close()
            except Exception as e:
                logging.error(f"Error closing VT client pool: {e}")
            
            # Stop token bucket
            self.token_bucket.stop()
            
            # Final save
            self.hash_db.save(force=True)
            
            logging.info("Scanner stopped")
    
    def stop(self):
        """Stop the scanner"""
        self.stop_event.set()


# ============================================================================
# File System Event Handler
# ============================================================================

class ScanEventHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def __init__(self, processor: ContinuousFileProcessor):
        self.processor = processor
        self.recent_events = {}  # Path -> timestamp, for deduplication
        self.event_lock = threading.Lock()
    
    def _should_process_event(self, path: str) -> bool:
        """Check if we should process this event (deduplication)"""
        current_time = time.time()
        
        with self.event_lock:
            # Clean old events
            self.recent_events = {
                p: t for p, t in self.recent_events.items()
                if current_time - t < 2
            }
            
            # Check if we've seen this recently
            if path in self.recent_events:
                return False
            
            self.recent_events[path] = current_time
            return True
    
    def on_any_event(self, event: FileSystemEvent):
        """Handle any file system event"""
        # Only handle file events
        if event.is_directory:
            return
        
        # Get the relevant path
        path = event.dest_path if hasattr(event, 'dest_path') else event.src_path
        
        # Deduplicate events
        if not self._should_process_event(path):
            return
        
        # Add to processor
        logging.debug(f"File event: {event.event_type} - {path}")
        self.processor.add_file(path)


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
    parser = argparse.ArgumentParser(description="VirusTotal Directory Scanner with Continuous Processing")
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
    parser.add_argument(
        "--max-threads",
        type=int,
        default=4,
        help="Maximum number of parallel upload threads (default: 4, max: 4)"
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
    if args.max_threads:
        config.max_parallel_uploads = min(args.max_threads, 4)
    
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
