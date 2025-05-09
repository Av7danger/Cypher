#!/usr/bin/env python3
"""Wireless network scanner implementation for the Cypher Security Toolkit."""
import os
import sys
import time
import re
import subprocess
import platform
from typing import List, Dict, Optional, Union, Any

class WirelessScanner:
    """Scanner for wireless networks."""
    
    def __init__(self):
        """Initialize the wireless scanner."""
        self.os_type = platform.system().lower()
        self.last_results = []
    
    def get_interfaces(self) -> List[str]:
        """Get available wireless interfaces.
        
        Returns:
            List of wireless interface names
        """
        interfaces = []
        
        try:
            if self.os_type == 'windows':
                # On Windows, use netsh to get wireless interfaces
                output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], 
                                                text=True, stderr=subprocess.PIPE)
                
                # Extract interface names
                for line in output.split('\n'):
                    if 'Name' in line and ':' in line:
                        interface = line.split(':', 1)[1].strip()
                        interfaces.append(interface)
            
            elif self.os_type == 'linux':
                # On Linux, check /proc/net/wireless or use iwconfig
                if os.path.exists('/proc/net/wireless'):
                    with open('/proc/net/wireless', 'r') as f:
                        for line in f:
                            if ':' in line:
                                interface = line.split(':', 1)[0].strip()
                                interfaces.append(interface)
                
                # Fallback to iwconfig
                if not interfaces:
                    try:
                        output = subprocess.check_output(['iwconfig'], 
                                                        text=True, stderr=subprocess.PIPE)
                        
                        for line in output.split('\n'):
                            if 'IEEE 802.11' in line:
                                interface = line.split(' ', 1)[0].strip()
                                interfaces.append(interface)
                    except (subprocess.SubprocessError, FileNotFoundError):
                        pass
            
            elif self.os_type == 'darwin':  # macOS
                # On macOS, use airport utility
                airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
                
                if os.path.exists(airport_path):
                    try:
                        output = subprocess.check_output([airport_path, '-I'], 
                                                       text=True, stderr=subprocess.PIPE)
                        
                        for line in output.split('\n'):
                            if 'AirPort' in line and ':' in line:
                                interface = line.split(':', 1)[1].strip()
                                interfaces.append(interface)
                    except subprocess.SubprocessError:
                        pass
                
                # Fallback to networksetup
                if not interfaces:
                    try:
                        output = subprocess.check_output(['networksetup', '-listallhardwareports'], 
                                                       text=True, stderr=subprocess.PIPE)
                        
                        wifi_section = False
                        for line in output.split('\n'):
                            if 'Wi-Fi' in line or 'AirPort' in line:
                                wifi_section = True
                            elif wifi_section and 'Device' in line and ':' in line:
                                interface = line.split(':', 1)[1].strip()
                                interfaces.append(interface)
                                wifi_section = False
                    except subprocess.SubprocessError:
                        pass
        
        except Exception as e:
            print(f"Error getting wireless interfaces: {e}")
        
        return interfaces
    
    def scan(self, interface: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan for wireless networks.
        
        Args:
            interface: Wireless interface to use (None for default)
            
        Returns:
            List of dictionaries with network information
        """
        networks = []
        
        try:
            if self.os_type == 'windows':
                networks = self._scan_windows()
            elif self.os_type == 'linux':
                networks = self._scan_linux(interface)
            elif self.os_type == 'darwin':  # macOS
                networks = self._scan_macos(interface)
            
            self.last_results = networks
        except Exception as e:
            print(f"Error scanning for wireless networks: {e}")
        
        return networks
    
    def _scan_windows(self) -> List[Dict[str, Any]]:
        """Scan for wireless networks on Windows.
        
        Returns:
            List of dictionaries with network information
        """
        networks = []
        
        try:
            # Get network list using netsh
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], 
                                           text=True, stderr=subprocess.PIPE)
            
            # Parse output
            current_network = {}
            current_bssid = None
            
            for line in output.split('\n'):
                line = line.strip()
                
                # New network
                if line.startswith('SSID'):
                    if current_network and 'ssid' in current_network:
                        networks.append(current_network)
                    
                    current_network = {'bssids': []}
                    ssid_match = re.search(r'SSID \d+ : (.+)', line)
                    if ssid_match:
                        current_network['ssid'] = ssid_match.group(1)
                
                # Network information
                elif ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    
                    if key == 'bssid':
                        current_bssid = {'bssid': value}
                        current_network['bssids'].append(current_bssid)
                    elif key == 'signal':
                        if current_bssid:
                            # Convert signal strength to percentage (on Windows it's already %)
                            signal_match = re.search(r'(\d+)%', value)
                            if signal_match:
                                current_bssid['signal'] = int(signal_match.group(1))
                    elif key == 'channel':
                        if current_bssid:
                            current_bssid['channel'] = value
                    elif key == 'radio_type':
                        if current_bssid:
                            current_bssid['standard'] = value
                    elif key == 'authentication':
                        current_network['security'] = value
                    elif key == 'encryption':
                        current_network['encryption'] = value
            
            # Add the last network
            if current_network and 'ssid' in current_network:
                networks.append(current_network)
            
            # Post-process to simplify for display
            for network in networks:
                # Get best signal strength and channel from BSSIDs
                best_signal = -1
                channel = ''
                for bssid in network.get('bssids', []):
                    if bssid.get('signal', 0) > best_signal:
                        best_signal = bssid.get('signal', 0)
                        channel = bssid.get('channel', '')
                
                network['signal'] = best_signal
                network['channel'] = channel
                
                # Combine security and encryption
                security = network.get('security', '')
                encryption = network.get('encryption', '')
                if security and encryption and encryption != 'None':
                    network['security_full'] = f"{security}/{encryption}"
                else:
                    network['security_full'] = security
        
        except Exception as e:
            print(f"Error scanning for wireless networks on Windows: {e}")
        
        return networks
    
    def _scan_linux(self, interface: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan for wireless networks on Linux.
        
        Args:
            interface: Wireless interface to use
            
        Returns:
            List of dictionaries with network information
        """
        networks = []
        
        try:
            # Try using iw
            try:
                if not interface:
                    # Get first wireless interface
                    interfaces = self.get_interfaces()
                    if interfaces:
                        interface = interfaces[0]
                    else:
                        return networks
                
                # Scan using iw
                output = subprocess.check_output(['sudo', 'iw', 'dev', interface, 'scan'], 
                                               text=True, stderr=subprocess.PIPE)
                
                # Parse output
                current_network = {}
                
                for line in output.split('\n'):
                    line = line.strip()
                    
                    # New network
                    if line.startswith('BSS'):
                        if current_network and 'bssid' in current_network:
                            networks.append(current_network)
                        
                        current_network = {}
                        bssid_match = re.search(r'BSS ([\da-fA-F:]+)', line)
                        if bssid_match:
                            current_network['bssid'] = bssid_match.group(1)
                    
                    # SSID
                    elif 'SSID:' in line:
                        ssid_match = re.search(r'SSID: (.+)', line)
                        if ssid_match:
                            current_network['ssid'] = ssid_match.group(1)
                    
                    # Signal strength
                    elif 'signal:' in line:
                        signal_match = re.search(r'signal: (-?\d+\.\d+) dBm', line)
                        if signal_match:
                            # Convert dBm to percentage (approximate)
                            dbm = float(signal_match.group(1))
                            if dbm <= -100:
                                percentage = 0
                            elif dbm >= -50:
                                percentage = 100
                            else:
                                percentage = 2 * (dbm + 100)
                            
                            current_network['signal'] = int(percentage)
                            current_network['signal_dbm'] = dbm
                    
                    # Channel
                    elif 'DS Parameter set:' in line and 'channel' in line:
                        channel_match = re.search(r'channel (\d+)', line)
                        if channel_match:
                            current_network['channel'] = channel_match.group(1)
                    
                    # Frequency
                    elif 'freq:' in line:
                        freq_match = re.search(r'freq: (\d+)', line)
                        if freq_match:
                            current_network['frequency'] = freq_match.group(1)
                    
                    # Security
                    elif 'capability:' in line:
                        if 'Privacy' in line:
                            current_network['security'] = 'WEP'  # Default, will be updated
                        else:
                            current_network['security'] = 'Open'
                    
                    # WPA
                    elif 'RSN:' in line or 'WPA:' in line:
                        if 'RSN:' in line:
                            current_network['security'] = 'WPA2'
                        else:
                            current_network['security'] = 'WPA'
                        
                        # Look for authentication and encryption in next few lines
                        auth_type = 'Unknown'
                        cipher_type = 'Unknown'
                        
                        for _ in range(5):  # Check next few lines
                            if 'Authentication suites:' in line:
                                if 'PSK' in line:
                                    auth_type = 'PSK'
                                elif 'EAP' in line:
                                    auth_type = 'EAP'
                            
                            if 'Pairwise ciphers:' in line:
                                if 'CCMP' in line:
                                    cipher_type = 'CCMP'
                                elif 'TKIP' in line:
                                    cipher_type = 'TKIP'
                            
                            line = next(output.split('\n'), '').strip()
                        
                        current_network['security_full'] = f"{current_network['security']}-{auth_type}/{cipher_type}"
                
                # Add the last network
                if current_network and 'bssid' in current_network:
                    networks.append(current_network)
                
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                print(f"Error using iw: {e}")
                
                # Fallback to iwlist
                try:
                    if not interface:
                        # Get first wireless interface
                        interfaces = self.get_interfaces()
                        if interfaces:
                            interface = interfaces[0]
                        else:
                            return networks
                    
                    # Scan using iwlist
                    output = subprocess.check_output(['sudo', 'iwlist', interface, 'scan'], 
                                                   text=True, stderr=subprocess.PIPE)
                    
                    # Parse output
                    current_network = {}
                    
                    for line in output.split('\n'):
                        line = line.strip()
                        
                        # New network
                        if 'Cell' in line and 'Address:' in line:
                            if current_network and 'bssid' in current_network:
                                networks.append(current_network)
                            
                            current_network = {}
                            bssid_match = re.search(r'Address: ([\da-fA-F:]+)', line)
                            if bssid_match:
                                current_network['bssid'] = bssid_match.group(1)
                        
                        # SSID
                        elif 'ESSID:' in line:
                            ssid_match = re.search(r'ESSID:"(.+)"', line)
                            if ssid_match:
                                current_network['ssid'] = ssid_match.group(1)
                        
                        # Signal strength
                        elif 'Quality' in line and 'Signal level' in line:
                            quality_match = re.search(r'Quality=(\d+)/(\d+)', line)
                            signal_match = re.search(r'Signal level=(-?\d+) dBm', line)
                            
                            if quality_match:
                                # Calculate percentage from quality
                                quality = int(quality_match.group(1))
                                max_quality = int(quality_match.group(2))
                                percentage = (quality / max_quality) * 100
                                current_network['signal'] = int(percentage)
                            
                            if signal_match:
                                current_network['signal_dbm'] = float(signal_match.group(1))
                        
                        # Channel
                        elif 'Channel:' in line:
                            channel_match = re.search(r'Channel:(\d+)', line)
                            if channel_match:
                                current_network['channel'] = channel_match.group(1)
                        
                        # Frequency
                        elif 'Frequency:' in line:
                            freq_match = re.search(r'Frequency:([\d.]+) GHz', line)
                            if freq_match:
                                freq_ghz = float(freq_match.group(1))
                                current_network['frequency'] = int(freq_ghz * 1000)
                        
                        # Security
                        elif 'Encryption key:' in line:
                            if 'on' in line.lower():
                                current_network['security'] = 'WEP'  # Default, will be updated
                            else:
                                current_network['security'] = 'Open'
                        
                        # WPA/WPA2
                        elif 'IE: IEEE 802.11i/WPA2' in line:
                            current_network['security'] = 'WPA2'
                        elif 'IE: WPA Version 1' in line:
                            current_network['security'] = 'WPA'
                    
                    # Add the last network
                    if current_network and 'bssid' in current_network:
                        networks.append(current_network)
                    
                except (subprocess.SubprocessError, FileNotFoundError) as e:
                    print(f"Error using iwlist: {e}")
                    
        except Exception as e:
            print(f"Error scanning for wireless networks on Linux: {e}")
        
        return networks
    
    def _scan_macos(self, interface: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan for wireless networks on macOS.
        
        Args:
            interface: Wireless interface to use
            
        Returns:
            List of dictionaries with network information
        """
        networks = []
        
        try:
            # Use airport utility
            airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
            
            if os.path.exists(airport_path):
                cmd = [airport_path, '-s']
                if interface:
                    cmd.extend(['-I', interface])
                
                output = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
                
                # Parse output
                lines = output.strip().split('\n')
                if len(lines) < 2:
                    return networks
                
                # Skip header line
                for line in lines[1:]:
                    parts = re.split(r'\s+', line.strip(), maxsplit=8)
                    if len(parts) >= 9:
                        network = {
                            'ssid': parts[0],
                            'bssid': parts[1],
                            'signal': int(parts[2]),  # RSSI converted to percentage
                            'channel': parts[3],
                            'security': parts[6]
                        }
                        
                        # Convert RSSI to percentage
                        rssi = int(parts[2])
                        if rssi <= -100:
                            percentage = 0
                        elif rssi >= -50:
                            percentage = 100
                        else:
                            percentage = 2 * (rssi + 100)
                        
                        network['signal'] = int(percentage)
                        network['signal_dbm'] = rssi
                        
                        networks.append(network)
        
        except Exception as e:
            print(f"Error scanning for wireless networks on macOS: {e}")
        
        return networks
    
    def get_security_rating(self, security: str) -> tuple:
        """Get a security rating for the network's security type.
        
        Args:
            security: Security type string
            
        Returns:
            Tuple of (rating, description) where rating is 0-5 (5 is best)
        """
        security = security.lower()
        
        if 'open' in security or security == '':
            return (0, "Insecure - Open network with no encryption")
        
        elif 'wep' in security:
            return (1, "Very Poor - WEP encryption is easily cracked")
        
        elif 'wpa-psk' in security or 'wpa1' in security or security == 'wpa':
            return (2, "Poor - WPA1 is vulnerable to offline attacks")
        
        elif 'wpa2-psk' in security or ('wpa2' in security and 'tkip' in security):
            return (3, "Moderate - WPA2 with TKIP has known vulnerabilities")
        
        elif 'wpa2' in security and 'ccmp' in security:
            return (4, "Good - WPA2 with AES/CCMP is reasonably secure")
        
        elif 'wpa3' in security:
            return (5, "Excellent - WPA3 provides best available security")
        
        else:
            # Unknown or unrecognized security type
            if 'wpa2' in security:
                return (3, "Moderate - WPA2 with unknown encryption")
            else:
                return (2, "Unknown security rating")

if __name__ == '__main__':
    # Simple command-line test
    scanner = WirelessScanner()
    
    interfaces = scanner.get_interfaces()
    print(f"Available wireless interfaces: {interfaces}")
    
    if interfaces:
        print(f"Scanning for wireless networks using {interfaces[0]}...")
        networks = scanner.scan(interfaces[0])
        
        print("\nFound wireless networks:")
        print("-" * 80)
        print(f"{'SSID':<30} {'Security':<15} {'Signal':<8} {'Channel':<8} {'BSSID':<17}")
        print("-" * 80)
        
        for network in networks:
            ssid = network.get('ssid', '<Hidden>')
            security = network.get('security_full', network.get('security', 'Unknown'))
            signal = f"{network.get('signal', 0)}%"
            channel = network.get('channel', 'N/A')
            bssid = network.get('bssid', 'N/A')
            
            print(f"{ssid:<30} {security:<15} {signal:<8} {channel:<8} {bssid:<17}")
            
            rating, desc = scanner.get_security_rating(security)
            print(f"  Security Rating: {rating}/5 - {desc}")
    else:
        print("No wireless interfaces found.")