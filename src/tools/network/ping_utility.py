import subprocess
import platform
import re

class PingUtility:
    def __init__(self):
        self.system = platform.system().lower()
        
    def ping(self, target, count=4):
        """Ping a target host and return the results."""
        try:
            # Adjust command based on operating system
            if self.system == "windows":
                command = ["ping", "-n", str(count), target]
            else:  # Linux, macOS, etc.
                command = ["ping", "-c", str(count), target]
            
            # Execute the ping command
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                return f"Error pinging {target}: {stderr}"
            
            # Parse and format the results
            return self._parse_ping_results(stdout)
            
        except Exception as e:
            return f"An error occurred: {str(e)}"
    
    def _parse_ping_results(self, output):
        """Parse and format ping command output."""
        # Extract statistics (varies by OS)
        if self.system == "windows":
            # Parse Windows ping output
            try:
                stats = re.search(r'Packets: Sent = (\d+), Received = (\d+), Lost = (\d+) \((\d+)% loss\)', output)
                if stats:
                    sent, received, lost, loss_percent = stats.groups()
                    
                times = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
                if times:
                    min_time, max_time, avg_time = times.groups()
                    
                result = (
                    f"Ping Statistics:\n"
                    f"Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({loss_percent}% loss)\n"
                    f"Approximate Round Trip Times:\n"
                    f"Minimum = {min_time}ms, Maximum = {max_time}ms, Average = {avg_time}ms"
                )
                return result
            except:
                # If parsing fails, return the raw output
                return output
        else:
            # Parse Linux/macOS ping output
            try:
                stats = re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received, (\d+)% packet loss', output)
                if stats:
                    transmitted, received, loss_percent = stats.groups()
                
                times = re.search(r'min/avg/max(?:/mdev)? = ([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))? ms', output)
                if times:
                    min_time, avg_time, max_time = times.groups()[:3]
                    
                result = (
                    f"Ping Statistics:\n"
                    f"Packets: Sent = {transmitted}, Received = {received}, Lost = {int(transmitted) - int(received)} ({loss_percent}% loss)\n"
                    f"Approximate Round Trip Times:\n"
                    f"Minimum = {min_time}ms, Maximum = {max_time}ms, Average = {avg_time}ms"
                )
                return result
            except:
                # If parsing fails, return the raw output
                return output