import subprocess
import platform
import re
import socket
import struct
import threading
import time

class ARPScanner:
    def __init__(self):
        self.system = platform.system().lower()
        self.devices = {}
        
    def scan_network(self, network_cidr):
        """
        Scan the local network for devices using ARP.
        
        Args:
            network_cidr: Network to scan in CIDR notation (e.g., '192.168.1.0/24')
        
        Returns:
            Dictionary of IP addresses and MAC addresses found
        """
        self.devices = {}
        
        try:
            # Parse CIDR notation to get network range
            ip, subnet = network_cidr.split('/')
            subnet = int(subnet)
            
            # Convert IP to integer
            ip_int = self._ip_to_int(ip)
            
            # Calculate first and last IP in range
            mask = (1 << 32 - subnet) - 1
            network = ip_int & ~mask
            broadcast = network | mask
            
            # Limit scanning to a reasonable range to avoid performance issues
            if broadcast - network > 1024:
                return {"error": "Network range too large. Please use a subnet of at least /22."}
            
            # Create threads for scanning
            threads = []
            for ip_int in range(network + 1, broadcast):
                target_ip = self._int_to_ip(ip_int)
                thread = threading.Thread(target=self._scan_ip, args=(target_ip,))
                thread.daemon = True
                threads.append(thread)
                thread.start()
                
                # Limit concurrent threads to avoid overloading the system
                if len(threads) >= 20:
                    for t in threads:
                        t.join(0.1)
                    threads = [t for t in threads if t.is_alive()]
            
            # Wait for all threads to complete
            for t in threads:
                t.join()
                
            return self.devices
            
        except Exception as e:
            return {"error": f"Error during network scan: {str(e)}"}
    
    def _scan_ip(self, ip):
        """Scan a single IP address using ARP."""
        try:
            # Use platform-specific commands to get MAC address
            if self.system == "windows":
                # Use ARP command on Windows
                output = subprocess.check_output(["arp", "-a", ip], universal_newlines=True)
                # Parse output for MAC address
                match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', output)
                if match:
                    mac = match.group(1)
                    # Get hostname if possible
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "Unknown"
                    
                    self.devices[ip] = {"mac": mac, "hostname": hostname}
            else:
                # Use ping and ARP on Linux/macOS
                # First ping to populate ARP cache
                subprocess.call(["ping", "-c", "1", "-W", "1", ip], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # Then check ARP cache
                output = subprocess.check_output(["arp", "-n", ip], universal_newlines=True)
                # Parse output for MAC address
                match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', output)
                if match:
                    mac = match.group(1)
                    # Get hostname if possible
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "Unknown"
                    
                    self.devices[ip] = {"mac": mac, "hostname": hostname}
        except:
            # If any error occurs, just skip this IP
            pass
    
    def _ip_to_int(self, ip):
        """Convert an IP address to an integer."""
        return struct.unpack('!I', socket.inet_aton(ip))[0]
    
    def _int_to_ip(self, ip_int):
        """Convert an integer to an IP address."""
        return socket.inet_ntoa(struct.pack('!I', ip_int))