import os
import platform
import subprocess

class PingUtility:
    """Ping utility to measure network response time and check connectivity."""

    def __init__(self):
        self.os_name = platform.system().lower()

    def ping(self, target, count=4):
        """
        Ping a target to check connectivity and measure response time.

        Args:
            target: The target hostname or IP address to ping.
            count: Number of ping requests to send.

        Returns:
            A dictionary with the ping results or an error message.
        """
        try:
            if self.os_name == "windows":
                command = ["ping", "-n", str(count), target]
            else:
                command = ["ping", "-c", str(count), target]

            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode == 0:
                return {"success": result.stdout}
            else:
                return {"error": result.stderr.strip()}

        except Exception as e:
            return {"error": str(e)}