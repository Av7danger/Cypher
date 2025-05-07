import psutil
import time
import threading
import platform
import datetime
import logging


class ProcessMonitor:
    """Monitor system processes and detect anomalies based on CPU/memory usage."""
    
    def __init__(self):
        # Configure logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.stop_monitoring_flag = threading.Event()
        
        # Store process data
        self.process_data = {}
        self.process_history = {}
        self.data_lock = threading.Lock()
        
        # System information
        self.system = platform.system().lower()
        
        # Default thresholds for anomaly detection
        self.thresholds = {
            'cpu_percent': 80.0,  # CPU usage percentage
            'memory_percent': 80.0,  # Memory usage percentage
            'high_io_rate': 10.0,  # MB/s
            'new_process': True,  # Flag new processes
            'exited_process': True,  # Flag exited processes
            'sudden_cpu_increase': 30.0,  # Percentage increase
            'sudden_memory_increase': 30.0,  # Percentage increase
            'thread_count': 200,  # High thread count
        }
    
    def set_threshold(self, threshold_name, value):
        """
        Set a threshold for anomaly detection.
        
        Args:
            threshold_name: Name of the threshold to set
            value: New threshold value
            
        Returns:
            Dictionary with threshold update status
        """
        if threshold_name not in self.thresholds:
            return {'error': f'Unknown threshold: {threshold_name}'}
            
        # Validate the value type
        if isinstance(self.thresholds[threshold_name], bool) and not isinstance(value, bool):
            return {'error': f'Threshold {threshold_name} requires a boolean value'}
            
        if isinstance(self.thresholds[threshold_name], (int, float)) and not isinstance(value, (int, float)):
            return {'error': f'Threshold {threshold_name} requires a numeric value'}
        
        # Update the threshold
        self.thresholds[threshold_name] = value
        
        return {
            'status': 'updated',
            'threshold': threshold_name,
            'value': value
        }
    
    def get_thresholds(self):
        """
        Get current anomaly detection thresholds.
        
        Returns:
            Dictionary with current thresholds
        """
        return dict(self.thresholds)
    
    def get_process_list(self):
        """
        Get a list of all running processes.
        
        Returns:
            List of dictionaries with process information
        """
        process_list = []
        
        try:
            for process in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = process.info
                    
                    # Add additional info as needed
                    try:
                        proc_info['create_time'] = datetime.datetime.fromtimestamp(
                            process.create_time()
                        ).strftime("%Y-%m-%d %H:%M:%S")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_info['create_time'] = "Unknown"
                        
                    try:
                        proc_info['cmdline'] = ' '.join(process.cmdline())
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_info['cmdline'] = "Access Denied"
                        
                    try:
                        proc_info['status'] = process.status()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_info['status'] = "Unknown"
                    
                    process_list.append(proc_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process no longer exists or access denied
                    continue
        
        except Exception as e:
            return {'error': f"Error getting process list: {str(e)}"}
        
        return process_list
    
    def get_process_details(self, pid):
        """
        Get detailed information about a specific process.
        
        Args:
            pid: Process ID
            
        Returns:
            Dictionary with detailed process information
        """
        try:
            # Check if process exists
            if not psutil.pid_exists(pid):
                return {'error': f'Process with PID {pid} does not exist'}
            
            # Get process
            process = psutil.Process(pid)
            
            # Basic info
            info = {
                'pid': pid,
                'name': process.name(),
                'status': process.status(),
                'created': datetime.datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                'cpu_percent': process.cpu_percent(interval=0.1),
                'memory_percent': process.memory_percent(),
                'memory_info': dict(process.memory_info()._asdict()),
                'username': process.username(),
            }
            
            # Optional info (may raise exceptions)
            try:
                info['exe'] = process.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info['exe'] = "Access Denied"
            
            try:
                info['cmdline'] = process.cmdline()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info['cmdline'] = ["Access Denied"]
            
            try:
                info['cwd'] = process.cwd()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info['cwd'] = "Access Denied"
            
            try:
                info['open_files'] = [f._asdict() for f in process.open_files()]
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info['open_files'] = "Access Denied"
            
            try:
                info['connections'] = [c._asdict() for c in process.connections()]
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info['connections'] = "Access Denied"
            
            try:
                info['threads'] = [t._asdict() for t in process.threads()]
                info['num_threads'] = len(info['threads'])
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info['threads'] = "Access Denied"
                info['num_threads'] = "Unknown"
            
            try:
                info['environ'] = process.environ()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info['environ'] = "Access Denied"
            
            return info
            
        except psutil.NoSuchProcess:
            return {'error': f'Process with PID {pid} no longer exists'}
        except psutil.AccessDenied:
            return {'error': f'Access denied for process with PID {pid}'}
        except Exception as e:
            return {'error': f'Error getting process details: {str(e)}'}
    
    def get_system_info(self):
        """
        Get information about the system.
        
        Returns:
            Dictionary with system information
        """
        try:
            # CPU info
            cpu_count = psutil.cpu_count(logical=False)
            cpu_count_logical = psutil.cpu_count(logical=True)
            cpu_percent = psutil.cpu_percent(interval=0.1, percpu=True)
            cpu_freq = psutil.cpu_freq()
            
            # Memory info
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk info
            disks = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total_size': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
                except (PermissionError, FileNotFoundError):
                    # Some mountpoints may not be accessible
                    pass
            
            # Network info
            net_io = psutil.net_io_counters()
            net_if = psutil.net_if_stats()
            net_addrs = psutil.net_if_addrs()
            
            # Boot time
            boot_time = datetime.datetime.fromtimestamp(
                psutil.boot_time()
            ).strftime("%Y-%m-%d %H:%M:%S")
            
            return {
                'system': {
                    'platform': platform.platform(),
                    'system': platform.system(),
                    'release': platform.release(),
                    'version': platform.version(),
                    'processor': platform.processor(),
                    'boot_time': boot_time,
                },
                'cpu': {
                    'physical_cores': cpu_count,
                    'logical_cores': cpu_count_logical,
                    'usage_percent': cpu_percent,
                    'frequency': {
                        'current': cpu_freq.current if cpu_freq else None,
                        'min': cpu_freq.min if cpu_freq and hasattr(cpu_freq, 'min') else None,
                        'max': cpu_freq.max if cpu_freq and hasattr(cpu_freq, 'max') else None
                    }
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'used': memory.used,
                    'free': memory.free,
                    'percent': memory.percent,
                    'swap': {
                        'total': swap.total,
                        'used': swap.used,
                        'free': swap.free,
                        'percent': swap.percent
                    }
                },
                'disks': disks,
                'network': {
                    'io_counters': {
                        'bytes_sent': net_io.bytes_sent,
                        'bytes_recv': net_io.bytes_recv,
                        'packets_sent': net_io.packets_sent,
                        'packets_recv': net_io.packets_recv,
                        'errin': net_io.errin,
                        'errout': net_io.errout,
                        'dropin': net_io.dropin,
                        'dropout': net_io.dropout
                    },
                    'interfaces': {
                        name: {
                            'isup': stats.isup,
                            'duplex': stats.duplex,
                            'speed': stats.speed,
                            'mtu': stats.mtu,
                            'addresses': [addr._asdict() for addr in net_addrs.get(name, [])]
                        } for name, stats in net_if.items()
                    }
                }
            }
            
        except Exception as e:
            return {'error': f'Error getting system information: {str(e)}'}
    
    def start_monitoring(self, interval=5.0, callback=None):
        """
        Start monitoring processes for anomalies.
        
        Args:
            interval: Time in seconds between checks
            callback: Function to call with anomaly events
            
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
            'interval': interval
        }
    
    def stop_monitoring(self):
        """
        Stop monitoring processes.
        
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
            interval: Time in seconds between checks
            callback: Function to call with anomaly events
        """
        # Initialize process data
        self._refresh_process_data()
        
        # Start monitoring loop
        while not self.stop_monitoring_flag.is_set():
            # Check current processes and detect anomalies
            anomalies = self._check_processes()
            
            # Call the callback if provided and anomalies found
            if callback and callable(callback) and anomalies:
                try:
                    callback(anomalies)
                except Exception as e:
                    self.logger.error(f"Error in monitoring callback: {str(e)}")
            
            # Wait for the next interval or until stop flag is set
            self.stop_monitoring_flag.wait(interval)
    
    def _refresh_process_data(self):
        """Refresh the list of running processes."""
        with self.data_lock:
            new_data = {}
            
            for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pid = process.info['pid']
                    
                    # Get detailed process info
                    proc_info = {
                        'pid': pid,
                        'name': process.info['name'],
                        'cpu_percent': process.info['cpu_percent'],
                        'memory_percent': process.info['memory_percent'],
                        'timestamp': time.time()
                    }
                    
                    # Try to get additional info
                    try:
                        proc_info['create_time'] = process.create_time()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_info['create_time'] = None
                        
                    try:
                        proc_info['num_threads'] = process.num_threads()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_info['num_threads'] = None
                        
                    try:
                        io_counters = process.io_counters()
                        proc_info['io_read_bytes'] = io_counters.read_bytes
                        proc_info['io_write_bytes'] = io_counters.write_bytes
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                        proc_info['io_read_bytes'] = None
                        proc_info['io_write_bytes'] = None
                    
                    # Add to new data
                    new_data[pid] = proc_info
                    
                    # Add to history
                    if pid not in self.process_history:
                        self.process_history[pid] = []
                    
                    # Keep history limited
                    if len(self.process_history[pid]) >= 10:
                        self.process_history[pid].pop(0)
                    
                    self.process_history[pid].append(proc_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process no longer exists or access denied
                    continue
            
            # Store the old data for comparison
            old_data = self.process_data
            self.process_data = new_data
            
            return old_data, new_data
    
    def _check_processes(self):
        """
        Check for process anomalies.
        
        Returns:
            List of anomaly events
        """
        old_data, new_data = self._refresh_process_data()
        anomalies = []
        
        # Check for new processes
        if self.thresholds['new_process']:
            for pid in new_data:
                if pid not in old_data:
                    # New process detected
                    anomalies.append({
                        'type': 'new_process',
                        'severity': 'info',
                        'timestamp': time.time(),
                        'pid': pid,
                        'name': new_data[pid]['name'],
                        'details': {
                            'cpu_percent': new_data[pid]['cpu_percent'],
                            'memory_percent': new_data[pid]['memory_percent'],
                            'create_time': new_data[pid]['create_time']
                        }
                    })
        
        # Check for exited processes
        if self.thresholds['exited_process']:
            for pid in old_data:
                if pid not in new_data:
                    # Process exited
                    anomalies.append({
                        'type': 'exited_process',
                        'severity': 'info',
                        'timestamp': time.time(),
                        'pid': pid,
                        'name': old_data[pid]['name'],
                        'details': {
                            'last_cpu_percent': old_data[pid]['cpu_percent'],
                            'last_memory_percent': old_data[pid]['memory_percent']
                        }
                    })
        
        # Check for high CPU usage
        for pid, proc_info in new_data.items():
            # High CPU usage
            if proc_info['cpu_percent'] >= self.thresholds['cpu_percent']:
                anomalies.append({
                    'type': 'high_cpu_usage',
                    'severity': 'warning',
                    'timestamp': time.time(),
                    'pid': pid,
                    'name': proc_info['name'],
                    'details': {
                        'cpu_percent': proc_info['cpu_percent'],
                        'threshold': self.thresholds['cpu_percent']
                    }
                })
            
            # High memory usage
            if proc_info['memory_percent'] >= self.thresholds['memory_percent']:
                anomalies.append({
                    'type': 'high_memory_usage',
                    'severity': 'warning',
                    'timestamp': time.time(),
                    'pid': pid,
                    'name': proc_info['name'],
                    'details': {
                        'memory_percent': proc_info['memory_percent'],
                        'threshold': self.thresholds['memory_percent']
                    }
                })
            
            # High thread count
            if proc_info['num_threads'] and proc_info['num_threads'] >= self.thresholds['thread_count']:
                anomalies.append({
                    'type': 'high_thread_count',
                    'severity': 'warning',
                    'timestamp': time.time(),
                    'pid': pid,
                    'name': proc_info['name'],
                    'details': {
                        'thread_count': proc_info['num_threads'],
                        'threshold': self.thresholds['thread_count']
                    }
                })
            
            # Sudden increases (only for existing processes)
            if pid in old_data:
                # CPU usage spike
                old_cpu = old_data[pid]['cpu_percent']
                new_cpu = proc_info['cpu_percent']
                
                if (old_cpu > 0 and 
                    new_cpu - old_cpu >= self.thresholds['sudden_cpu_increase'] and
                    new_cpu >= 10.0):  # Ignore very small values
                    anomalies.append({
                        'type': 'cpu_usage_spike',
                        'severity': 'warning',
                        'timestamp': time.time(),
                        'pid': pid,
                        'name': proc_info['name'],
                        'details': {
                            'old_cpu_percent': old_cpu,
                            'new_cpu_percent': new_cpu,
                            'increase': new_cpu - old_cpu,
                            'threshold': self.thresholds['sudden_cpu_increase']
                        }
                    })
                
                # Memory usage spike
                old_mem = old_data[pid]['memory_percent']
                new_mem = proc_info['memory_percent']
                
                if (old_mem > 0 and 
                    new_mem - old_mem >= self.thresholds['sudden_memory_increase'] and
                    new_mem >= 1.0):  # Ignore very small values
                    anomalies.append({
                        'type': 'memory_usage_spike',
                        'severity': 'warning',
                        'timestamp': time.time(),
                        'pid': pid,
                        'name': proc_info['name'],
                        'details': {
                            'old_memory_percent': old_mem,
                            'new_memory_percent': new_mem,
                            'increase': new_mem - old_mem,
                            'threshold': self.thresholds['sudden_memory_increase']
                        }
                    })
                
                # High I/O rate
                if (proc_info['io_read_bytes'] is not None and 
                    old_data[pid]['io_read_bytes'] is not None):
                    io_read_diff = proc_info['io_read_bytes'] - old_data[pid]['io_read_bytes']
                    io_write_diff = proc_info['io_write_bytes'] - old_data[pid]['io_write_bytes']
                    
                    # Calculate MB/s
                    time_diff = proc_info['timestamp'] - old_data[pid]['timestamp']
                    if time_diff > 0:
                        io_read_rate = io_read_diff / time_diff / (1024 * 1024)  # MB/s
                        io_write_rate = io_write_diff / time_diff / (1024 * 1024)  # MB/s
                        
                        if (io_read_rate >= self.thresholds['high_io_rate'] or 
                            io_write_rate >= self.thresholds['high_io_rate']):
                            anomalies.append({
                                'type': 'high_io_rate',
                                'severity': 'warning',
                                'timestamp': time.time(),
                                'pid': pid,
                                'name': proc_info['name'],
                                'details': {
                                    'read_rate_mbs': io_read_rate,
                                    'write_rate_mbs': io_write_rate,
                                    'threshold': self.thresholds['high_io_rate']
                                }
                            })
        
        return anomalies
    
    def kill_process(self, pid):
        """
        Kill a process by PID.
        
        Args:
            pid: Process ID to kill
            
        Returns:
            Dictionary with kill status
        """
        try:
            # Check if process exists
            if not psutil.pid_exists(pid):
                return {'error': f'Process with PID {pid} does not exist'}
            
            # Get process
            process = psutil.Process(pid)
            
            # Kill the process
            process.kill()
            
            return {
                'status': 'killed',
                'pid': pid,
                'name': process.name()
            }
            
        except psutil.NoSuchProcess:
            return {'error': f'Process with PID {pid} no longer exists'}
        except psutil.AccessDenied:
            return {'error': f'Access denied when trying to kill process with PID {pid}'}
        except Exception as e:
            return {'error': f'Error killing process: {str(e)}'}
    
    def search_processes(self, query):
        """
        Search for processes matching a name or command line.
        
        Args:
            query: Search query string
            
        Returns:
            List of matching processes
        """
        matches = []
        query = query.lower()
        
        try:
            for process in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    # Check if process name matches
                    if query in process.info['name'].lower():
                        matches.append(process.info)
                        continue
                    
                    # Check if command line contains the query
                    cmdline = process.info.get('cmdline', [])
                    if cmdline:
                        cmdline_str = ' '.join(cmdline).lower()
                        if query in cmdline_str:
                            matches.append(process.info)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process no longer exists or access denied
                    continue
                    
        except Exception as e:
            return {'error': f'Error searching processes: {str(e)}'}
        
        return matches