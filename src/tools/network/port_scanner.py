import socket
import threading

class PortScanner:
    def __init__(self):
        self.open_ports = {}
        
    def scan(self, target_ip, start_port, end_port, timeout=1):
        """Scan a range of ports on the specified target IP."""
        self.open_ports = {}
        
        try:
            # Resolve hostname to IP if needed
            ip = socket.gethostbyname(target_ip)
            
            # Scan ports in the specified range
            for port in range(start_port, end_port + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except (socket.error, OSError):
                        service = 'unknown'
                    self.open_ports[port] = service
                sock.close()
                
            return self.open_ports
            
        except socket.gaierror:
            return {'error': f'Hostname {target_ip} could not be resolved'}
        except socket.error:
            return {'error': f'Could not connect to {target_ip}'}
    
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
