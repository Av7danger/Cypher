import os
import hashlib
import json
import time
import threading
import logging


class FileIntegrityChecker:
    """Tool for monitoring and verifying file integrity by detecting changes using hash comparison."""
    
    def __init__(self):
        # Configure logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Initialize monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.stop_monitoring_flag = threading.Event()
        
        # Database of file hashes
        self.integrity_db = {}
        self.db_lock = threading.Lock()
        
        # Default hash algorithm
        self.hash_algorithm = 'sha256'
        
        # Available hash algorithms
        self.available_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
    
    def set_hash_algorithm(self, algorithm):
        """
        Set the hash algorithm to use for integrity checks.
        
        Args:
            algorithm: Hash algorithm name ('md5', 'sha1', 'sha256', 'sha512')
            
        Returns:
            Boolean indicating success
        """
        if algorithm.lower() in self.available_algorithms:
            self.hash_algorithm = algorithm.lower()
            return True
        return False
    
    def calculate_file_hash(self, file_path):
        """
        Calculate hash for a single file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file hash information or error
        """
        try:
            if not os.path.isfile(file_path):
                return {'error': f'File not found: {file_path}'}
                
            # Get file information
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            file_modified = file_stat.st_mtime
            
            # Calculate hash
            hash_func = self.available_algorithms[self.hash_algorithm]()
            
            with open(file_path, 'rb') as f:
                # Read the file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            
            file_hash = hash_func.hexdigest()
            
            return {
                'file_path': file_path,
                'hash': file_hash,
                'algorithm': self.hash_algorithm,
                'size': file_size,
                'last_modified': file_modified,
                'last_checked': time.time()
            }
            
        except PermissionError:
            return {'error': f'Permission denied: {file_path}'}
        except Exception as e:
            return {'error': f'Error calculating hash: {str(e)}'}
    
    def add_file(self, file_path):
        """
        Add a file to the integrity database.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file hash information or error
        """
        result = self.calculate_file_hash(file_path)
        
        if 'error' not in result:
            with self.db_lock:
                self.integrity_db[file_path] = result
            
        return result
    
    def add_directory(self, directory_path, recursive=True, file_patterns=None):
        """
        Add all files in a directory to the integrity database.
        
        Args:
            directory_path: Path to the directory
            recursive: Whether to include subdirectories
            file_patterns: List of file patterns to include (e.g., ['*.txt', '*.py'])
            
        Returns:
            Dictionary with summary information
        """
        if not os.path.isdir(directory_path):
            return {'error': f'Directory not found: {directory_path}'}
            
        # Build list of files to check
        files_to_check = []
        
        try:
            if recursive:
                for root, _, files in os.walk(directory_path):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        # Check if file matches pattern
                        if file_patterns:
                            if self._match_file_pattern(filename, file_patterns):
                                files_to_check.append(file_path)
                        else:
                            files_to_check.append(file_path)
            else:
                for filename in os.listdir(directory_path):
                    file_path = os.path.join(directory_path, filename)
                    if os.path.isfile(file_path):
                        # Check if file matches pattern
                        if file_patterns:
                            if self._match_file_pattern(filename, file_patterns):
                                files_to_check.append(file_path)
                        else:
                            files_to_check.append(file_path)
        except PermissionError:
            return {'error': f'Permission denied: {directory_path}'}
        except Exception as e:
            return {'error': f'Error scanning directory: {str(e)}'}
        
        # Calculate hashes for each file
        added_count = 0
        error_count = 0
        error_files = []
        
        for file_path in files_to_check:
            result = self.add_file(file_path)
            if 'error' in result:
                error_count += 1
                error_files.append({
                    'file': file_path,
                    'error': result['error']
                })
            else:
                added_count += 1
        
        return {
            'directory': directory_path,
            'files_added': added_count,
            'errors': error_count,
            'error_details': error_files if error_files else None,
            'recursive': recursive,
            'file_patterns': file_patterns
        }
    
    def verify_file(self, file_path):
        """
        Verify a file's integrity against the stored hash.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with verification results
        """
        with self.db_lock:
            if file_path not in self.integrity_db:
                return {'error': f'File not in integrity database: {file_path}'}
        
        # Get stored hash information
        stored_info = self.integrity_db[file_path]
        stored_hash = stored_info['hash']
        stored_algorithm = stored_info['algorithm']
        
        # Set hash algorithm temporarily to match stored hash
        current_algorithm = self.hash_algorithm
        self.hash_algorithm = stored_algorithm
        
        # Calculate current hash
        current_info = self.calculate_file_hash(file_path)
        
        # Restore original hash algorithm
        self.hash_algorithm = current_algorithm
        
        if 'error' in current_info:
            return {
                'file_path': file_path,
                'verified': False,
                'error': current_info['error']
            }
        
        # Compare hashes
        current_hash = current_info['hash']
        is_match = stored_hash == current_hash
        
        # Check for file modifications
        size_changed = stored_info['size'] != current_info['size']
        time_changed = stored_info['last_modified'] != current_info['last_modified']
        
        result = {
            'file_path': file_path,
            'verified': is_match,
            'stored_hash': stored_hash,
            'current_hash': current_hash,
            'algorithm': stored_algorithm,
            'size_changed': size_changed,
            'last_modified_changed': time_changed,
            'last_checked': time.time()
        }
        
        # Update stored information if verification succeeded
        if is_match:
            with self.db_lock:
                self.integrity_db[file_path]['last_checked'] = time.time()
        
        return result
    
    def verify_all(self):
        """
        Verify all files in the integrity database.
        
        Returns:
            Dictionary with verification summary
        """
        with self.db_lock:
            files_to_check = list(self.integrity_db.keys())
        
        if not files_to_check:
            return {'message': 'No files in integrity database'}
        
        results = {
            'verified_count': 0,
            'modified_count': 0,
            'error_count': 0,
            'modified_files': [],
            'error_files': [],
            'total_files': len(files_to_check)
        }
        
        for file_path in files_to_check:
            result = self.verify_file(file_path)
            
            if 'error' in result:
                results['error_count'] += 1
                results['error_files'].append({
                    'file': file_path,
                    'error': result['error']
                })
            elif not result.get('verified', False):
                results['modified_count'] += 1
                results['modified_files'].append({
                    'file': file_path,
                    'current_hash': result.get('current_hash'),
                    'stored_hash': result.get('stored_hash'),
                    'size_changed': result.get('size_changed', False),
                    'last_modified_changed': result.get('last_modified_changed', False)
                })
            else:
                results['verified_count'] += 1
        
        return results
    
    def start_monitoring(self, interval=300, callback=None):
        """
        Start monitoring files in the integrity database at regular intervals.
        
        Args:
            interval: Time in seconds between integrity checks
            callback: Function to call with verification results
            
        Returns:
            Dictionary with monitoring status
        """
        if self.is_monitoring:
            return {'error': 'Monitoring already active'}
            
        # Reset stop flag
        self.stop_monitoring_flag.clear()
        
        # Create and start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self._monitoring_worker,
            args=(interval, callback)
        )
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.is_monitoring = True
        
        return {
            'status': 'started',
            'interval': interval,
            'files_monitored': len(self.integrity_db)
        }
    
    def stop_monitoring(self):
        """
        Stop the ongoing file integrity monitoring.
        
        Returns:
            Dictionary with monitoring status
        """
        if not self.is_monitoring:
            return {'status': 'not_monitoring'}
            
        # Signal the monitoring thread to stop
        self.stop_monitoring_flag.set()
        
        # Wait for the thread to exit
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
            self.monitor_thread = None
        
        self.is_monitoring = False
        
        return {'status': 'stopped'}
    
    def _monitoring_worker(self, interval, callback):
        """
        Worker function for the monitoring thread.
        
        Args:
            interval: Time in seconds between integrity checks
            callback: Function to call with verification results
        """
        while not self.stop_monitoring_flag.is_set():
            # Verify all files
            results = self.verify_all()
            
            # Log any modified files
            if results.get('modified_count', 0) > 0:
                self.logger.warning(f"Detected {results['modified_count']} modified files!")
                for modified_file in results.get('modified_files', []):
                    self.logger.warning(f"Modified file: {modified_file['file']}")
            
            # Call the callback if provided
            if callback and callable(callback):
                try:
                    callback(results)
                except Exception as e:
                    self.logger.error(f"Error in monitoring callback: {str(e)}")
            
            # Wait for the next interval or until stop flag is set
            self.stop_monitoring_flag.wait(interval)
    
    def _match_file_pattern(self, filename, patterns):
        """
        Check if a filename matches any of the provided patterns.
        
        Args:
            filename: The filename to check
            patterns: List of patterns to match against
            
        Returns:
            Boolean indicating if the file matches any pattern
        """
        import fnmatch
        
        for pattern in patterns:
            if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                return True
        return False
    
    def save_database(self, file_path):
        """
        Save the integrity database to a file.
        
        Args:
            file_path: Path to save the database file
            
        Returns:
            Dictionary with save status
        """
        try:
            with self.db_lock:
                # Convert to serializable format
                db_copy = dict(self.integrity_db)
            
            with open(file_path, 'w') as f:
                json.dump(db_copy, f, indent=2)
                
            return {
                'status': 'saved',
                'file_path': file_path,
                'entries': len(db_copy)
            }
            
        except Exception as e:
            return {'error': f'Error saving database: {str(e)}'}
    
    def load_database(self, file_path):
        """
        Load the integrity database from a file.
        
        Args:
            file_path: Path to the database file
            
        Returns:
            Dictionary with load status
        """
        try:
            if not os.path.isfile(file_path):
                return {'error': f'Database file not found: {file_path}'}
                
            with open(file_path, 'r') as f:
                loaded_db = json.load(f)
                
            with self.db_lock:
                self.integrity_db = loaded_db
                
            return {
                'status': 'loaded',
                'file_path': file_path,
                'entries': len(loaded_db)
            }
            
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON format in database file'}
        except Exception as e:
            return {'error': f'Error loading database: {str(e)}'}
    
    def remove_file(self, file_path):
        """
        Remove a file from the integrity database.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with removal status
        """
        with self.db_lock:
            if file_path not in self.integrity_db:
                return {'error': f'File not in integrity database: {file_path}'}
                
            del self.integrity_db[file_path]
            
        return {
            'status': 'removed',
            'file_path': file_path
        }
    
    def clear_database(self):
        """
        Clear the entire integrity database.
        
        Returns:
            Dictionary with clear status
        """
        with self.db_lock:
            count = len(self.integrity_db)
            self.integrity_db.clear()
            
        return {
            'status': 'cleared',
            'entries_removed': count
        }