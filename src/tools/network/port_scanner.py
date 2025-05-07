import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    """Port scanner utility to scan for open ports on a target."""
    
    def __init__(self):
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 115: "SFTP", 135: "RPC",
            139: "NETBIOS", 143: "IMAP", 194: "IRC", 443: "HTTPS", 445: "SMB",
            1433: "MSSQL", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL",
            5900: "VNC", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
        }
        self.max_threads = 500  # Increased for better performance
    
    def check_port(self, target, port, timeout=1):
        """Check if a specific port is open on the target."""
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Attempt to connect to the target and port
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Try to get service name
                service = "Unknown"
                try:
                    service = socket.getservbyport(port)
                except (socket.error, OSError):
                    # If service name isn't found in system database,
                    # check our common ports dictionary
                    service = self.common_ports.get(port, "Unknown")
                
                sock.close()
                return port, service, True
            
            sock.close()
            return port, None, False
        except (socket.timeout, socket.error, OSError) as e:
            return port, None, False
    
    def scan(self, target, start_port, end_port, timeout=1, progress_callback=None, batch_size=50):
        """
        Scan a range of ports on the target.
        
        Args:
            target: Target hostname or IP address
            start_port: Starting port number
            end_port: Ending port number
            timeout: Socket timeout in seconds
            progress_callback: Optional callback function to report progress
            batch_size: Size of port batches to scan (for better performance)
            
        Returns:
            Dictionary of open ports and their services or error message
        """
        try:
            # Validate target - try to resolve hostname to IP
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {"error": f"Could not resolve hostname: {target}"}
            
            open_ports = {}
            
            # Reduce socket timeout for faster scanning of closed ports
            # Most closed ports respond very quickly with rejection
            adjusted_timeout = min(0.5, timeout)
            
            # Process ports in batches for better memory management
            port_range = list(range(start_port, end_port + 1))
            total_ports = len(port_range)
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                for port_batch in [port_range[i:i + batch_size] for i in range(0, total_ports, batch_size)]:
                    # Submit all port checking tasks for this batch
                    futures = {
                        executor.submit(self.check_port, target_ip, port, adjusted_timeout): port
                        for port in port_batch
                    }
                    
                    # Process completed futures
                    for future in as_completed(futures):
                        port, service, is_open = future.result()
                        
                        # Report progress if callback is provided
                        if progress_callback:
                            if is_open:
                                open_ports[port] = service
                            progress_callback(port, service, is_open)
                        elif is_open:
                            open_ports[port] = service
            
            return open_ports
            
        except Exception as e:
            return {"error": str(e)}
    
    def scan_single_port(self, target_ip, port, timeout=1):
        """Scan a single port on the specified target IP."""
        try:
            ip = socket.gethostbyname(target_ip)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
