import threading
import subprocess
import sys
import os

# Try to import nmap, but handle the case when it's not installed or when the nmap program is missing
try:
    import nmap
    has_nmap_lib = True
except ImportError:
    has_nmap_lib = False

# Also check if the nmap executable is installed
def is_nmap_installed():
    try:
        # Try to run nmap --version
        if sys.platform == 'win32':  # Windows
            with open(os.devnull, 'w') as DEVNULL:
                subprocess.check_call(['where', 'nmap'], stdout=DEVNULL, stderr=DEVNULL)
        else:  # Unix-like
            with open(os.devnull, 'w') as DEVNULL:
                subprocess.check_call(['which', 'nmap'], stdout=DEVNULL, stderr=DEVNULL)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

has_nmap_exe = is_nmap_installed()

class NmapScanner:
    def __init__(self):
        self.scanner = None
        self.scan_results = {}
        self.current_scan = None
        
        # Only initialize the scanner if both the library and executable are available
        if has_nmap_lib and has_nmap_exe:
            try:
                self.scanner = nmap.PortScanner()
            except Exception:
                # Handle any initialization errors
                pass
        
    def scan(self, target, ports=None, arguments="-sV", callback=None):
        """
        Scan a target using Nmap
        
        Args:
            target: IP address, hostname, or network range (CIDR)
            ports: String of ports to scan (e.g., '22-25,80,443')
            arguments: Nmap arguments to use
            callback: Function to call when scan completes
            
        Returns:
            Dictionary with scan results or error message
        """
        # Check if nmap is available
        if not has_nmap_lib:
            return {"error": "Python-nmap library is not installed. Please install it with: pip install python-nmap"}
        
        if not has_nmap_exe:
            return {"error": "Nmap program is not installed or not in PATH. Please install it: https://nmap.org/download.html"}
        
        if not self.scanner:
            return {"error": "Failed to initialize Nmap scanner"}
        
        # Format the port string
        port_str = ports if ports else "1-1024"
        
        # Start the scan in a separate thread to avoid blocking
        self.current_scan = threading.Thread(
            target=self._do_scan,
            args=(target, port_str, arguments, callback)
        )
        self.current_scan.daemon = True
        self.current_scan.start()
        
        return {"status": "scanning", "target": target}
    
    def _do_scan(self, target, ports, arguments, callback):
        """Perform the actual Nmap scan in a background thread."""
        try:
            # Run the scan
            self.scanner.scan(target, ports, arguments)
            
            # Process the results
            self.scan_results = {}
            
            # Get all scanned hosts
            for host in self.scanner.all_hosts():
                host_data = {
                    "hostname": self._get_hostname(host),
                    "state": self.scanner[host].state(),
                    "protocols": {}
                }
                
                # Get information for each protocol scanned (usually just tcp)
                for proto in self.scanner[host].all_protocols():
                    host_data["protocols"][proto] = {}
                    
                    # Get all port data
                    ports_dict = self.scanner[host][proto]
                    for port in ports_dict.keys():
                        port_data = ports_dict[port]
                        host_data["protocols"][proto][port] = {
                            "state": port_data["state"],
                            "service": port_data.get("name", "unknown"),
                            "product": port_data.get("product", ""),
                            "version": port_data.get("version", ""),
                            "extrainfo": port_data.get("extrainfo", "")
                        }
                
                self.scan_results[host] = host_data
                
            # Call the callback if provided
            if callback:
                callback(self.scan_results)
                
        except Exception as e:
            self.scan_results = {"error": str(e)}
            if callback:
                callback(self.scan_results)
    
    def _get_hostname(self, host):
        """Get the hostname for an IP address from Nmap results."""
        if host in self.scanner.all_hosts():
            if 'hostnames' in self.scanner[host] and self.scanner[host]['hostnames']:
                for hostname in self.scanner[host]['hostnames']:
                    if 'name' in hostname and hostname['name']:
                        return hostname['name']
        return ""
    
    def get_results(self):
        """Get the results of the most recent scan."""
        return self.scan_results
    
    def is_scanning(self):
        """Check if a scan is currently in progress."""
        return self.current_scan is not None and self.current_scan.is_alive()
    
    def cancel_scan(self):
        """Cancel the current scan (not fully supported by python-nmap)."""
        # python-nmap doesn't support cancellation, but we can set flags to inform the UI
        self.current_scan = None
        return True