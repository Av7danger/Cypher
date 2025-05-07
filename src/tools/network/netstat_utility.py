import subprocess
import platform
import re
import socket

class NetstatUtility:
    def __init__(self):
        self.system = platform.system().lower()
        
    def get_connections(self):
        """Get all network connections and listening ports."""
        try:
            # Execute the appropriate netstat command based on OS
            if self.system == "windows":
                command = ["netstat", "-ano"]
            else:  # Linux, macOS, etc.
                command = ["netstat", "-tuln"]
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                return f"Error getting network connections: {stderr}"
            
            # Parse the netstat output
            return self._parse_netstat_output(stdout)
            
        except Exception as e:
            return f"An error occurred: {str(e)}"
    
    def _parse_netstat_output(self, output):
        """Parse the netstat command output into a structured format."""
        lines = output.strip().split('\n')
        connections = []
        
        # Skip header lines
        data_lines = []
        capture = False
        for line in lines:
            if not capture and ("Proto" in line or "Active Connections" in line):
                capture = True
                continue
            if capture and line.strip():
                data_lines.append(line)
        
        # Parse each connection line
        for line in data_lines:
            parts = line.split()
            if not parts or len(parts) < 4:
                continue
                
            # Parse differently based on OS
            if self.system == "windows":
                # Windows format: Proto, Local Address, Foreign Address, State, PID
                if len(parts) >= 5:
                    proto = parts[0]
                    local_address = parts[1]
                    foreign_address = parts[2]
                    state = parts[3] if parts[3] != "LISTENING" else "LISTEN"
                    pid = parts[4]
                    
                    # Try to get process name
                    process_name = "Unknown"
                    try:
                        ps_output = subprocess.check_output(["tasklist", "/fi", f"pid eq {pid}"], universal_newlines=True)
                        match = re.search(r'(\w+\.exe)', ps_output)
                        if match:
                            process_name = match.group(1)
                    except:
                        pass
                    
                    connections.append({
                        "protocol": proto,
                        "local_address": local_address,
                        "foreign_address": foreign_address,
                        "state": state,
                        "pid": pid,
                        "process": process_name
                    })
            else:
                # Linux/macOS format: Proto, Recv-Q, Send-Q, Local Address, Foreign Address, State
                if len(parts) >= 6:
                    proto = parts[0]
                    local_address = parts[3]
                    foreign_address = parts[4]
                    state = parts[5] if len(parts) > 5 else "UNKNOWN"
                    
                    connections.append({
                        "protocol": proto,
                        "local_address": local_address,
                        "foreign_address": foreign_address,
                        "state": state
                    })
        
        return connections
    
    def get_listening_ports(self):
        """Get only the listening ports."""
        connections = self.get_connections()
        
        if isinstance(connections, str):  # Error message
            return connections
            
        listening = []
        for conn in connections:
            if isinstance(conn, dict) and conn.get("state") in ["LISTEN", "LISTENING"]:
                listening.append(conn)
                
        return listening
    
    def get_formatted_output(self):
        """Get a formatted string output of all connections."""
        connections = self.get_connections()
        
        if isinstance(connections, str):  # Error message
            return connections
            
        if not connections:
            return "No active connections found."
            
        result = []
        result.append("Protocol  Local Address           Foreign Address         State           Process")
        result.append("-" * 80)
        
        for conn in connections:
            if isinstance(conn, dict):
                local = conn.get("local_address", "").ljust(22)
                foreign = conn.get("foreign_address", "").ljust(22)
                state = conn.get("state", "").ljust(15)
                proto = conn.get("protocol", "").ljust(9)
                process = f"{conn.get('pid', '')} ({conn.get('process', '')})" if conn.get('pid') else ""
                
                result.append(f"{proto}{local}{foreign}{state}{process}")
        
        return "\n".join(result)