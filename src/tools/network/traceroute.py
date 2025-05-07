import subprocess
import platform
import re
import ipaddress

class Traceroute:
    def __init__(self):
        self.system = platform.system().lower()
        
    def trace(self, target, max_hops=30, timeout=5):
        """Trace the network path to a target host."""
        try:
            # Adjust command based on operating system
            if self.system == "windows":
                command = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout * 1000), target]
            else:  # Linux, macOS, etc.
                command = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), target]
            
            # Execute the traceroute command
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0 and stderr:
                return f"Error tracing route to {target}: {stderr}"
            
            # Parse and format the results
            return self._parse_traceroute_results(stdout)
            
        except Exception as e:
            return f"An error occurred: {str(e)}"
    
    def _parse_traceroute_results(self, output):
        """Parse and format traceroute command output."""
        lines = output.strip().split('\n')
        formatted_output = []
        
        # Skip the first line (header)
        for line in lines[1:]:
            # Clean up the line
            line = line.strip()
            if not line:
                continue
                
            # Try to extract hop number and IP address
            try:
                if self.system == "windows":
                    # Windows format
                    if "Request timed out" in line:
                        hop_match = re.search(r'^\s*(\d+)', line)
                        if hop_match:
                            hop_num = hop_match.group(1)
                            formatted_output.append(f"Hop {hop_num}: Request timed out")
                    else:
                        # Try to extract hop number and IP
                        match = re.search(r'^\s*(\d+)\s+(?:(?:<\d+\s+ms\s+){1,3})\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            hop_num, ip = match.groups()
                            formatted_output.append(f"Hop {hop_num}: {ip}")
                else:
                    # Linux/macOS format
                    if "* * *" in line:
                        hop_match = re.search(r'^\s*(\d+)', line)
                        if hop_match:
                            hop_num = hop_match.group(1)
                            formatted_output.append(f"Hop {hop_num}: Request timed out")
                    else:
                        match = re.search(r'^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            hop_num, ip = match.groups()
                            formatted_output.append(f"Hop {hop_num}: {ip}")
            except:
                # If parsing fails, add the raw line
                formatted_output.append(line)
        
        return "\n".join(formatted_output) if formatted_output else output