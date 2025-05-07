import psutil
import time
import threading

class BandwidthMonitor:
    def __init__(self):
        self.monitoring = False
        self.interface_stats = {}
        self.monitor_thread = None
        self.callback = None
        
    def start_monitoring(self, update_interval=1.0, callback=None):
        """
        Start monitoring bandwidth usage across all network interfaces.
        
        Args:
            update_interval: Time between measurements in seconds
            callback: Function to call with updated stats
        """
        if self.monitoring:
            return False
            
        self.monitoring = True
        self.callback = callback
        
        # Start monitoring in a background thread
        self.monitor_thread = threading.Thread(target=self._monitor_bandwidth, args=(update_interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        return True
        
    def stop_monitoring(self):
        """Stop the bandwidth monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
            self.monitor_thread = None
    
    def _monitor_bandwidth(self, interval):
        """Monitor bandwidth usage in the background."""
        prev_counters = psutil.net_io_counters(pernic=True)
        
        while self.monitoring:
            time.sleep(interval)
            
            # Get updated counters
            cur_counters = psutil.net_io_counters(pernic=True)
            
            # Calculate bandwidth for each interface
            for interface, counters in cur_counters.items():
                # Skip interfaces that don't exist in the previous sample
                if interface not in prev_counters:
                    continue
                    
                # Calculate bytes per second (bandwidth)
                prev = prev_counters[interface]
                
                # Calculate download (received) bandwidth
                bytes_recv = counters.bytes_recv - prev.bytes_recv
                download_speed = bytes_recv / interval  # bytes per second
                
                # Calculate upload (sent) bandwidth
                bytes_sent = counters.bytes_sent - prev.bytes_sent
                upload_speed = bytes_sent / interval  # bytes per second
                
                # Update stats
                self.interface_stats[interface] = {
                    'download_bytes': download_speed,
                    'upload_bytes': upload_speed,
                    'download': self._format_speed(download_speed),
                    'upload': self._format_speed(upload_speed),
                    'total_recv': counters.bytes_recv,
                    'total_sent': counters.bytes_sent,
                }
            
            # Update previous counters
            prev_counters = cur_counters
            
            # Call the callback if provided
            if self.callback:
                self.callback(self.interface_stats)
    
    def get_stats(self):
        """Get the current bandwidth statistics."""
        return self.interface_stats
    
    def _format_speed(self, bytes_per_sec):
        """Format speed in human-readable format."""
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.1f} B/s"
        elif bytes_per_sec < 1024 * 1024:
            return f"{bytes_per_sec / 1024:.1f} KB/s"
        elif bytes_per_sec < 1024 * 1024 * 1024:
            return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"
        else:
            return f"{bytes_per_sec / (1024 * 1024 * 1024):.1f} GB/s"