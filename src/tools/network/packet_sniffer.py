#!/usr/bin/env python3
"""Packet sniffer implementation for the Cypher Security Toolkit."""
import os
import sys
import time
import socket
import struct
import threading
import binascii
from typing import Dict, List, Tuple, Optional, Union
import textwrap

class PacketSniffer:
    """Packet sniffer to capture and analyze network traffic."""
    
    def __init__(self, interface: Optional[str] = None):
        """Initialize the packet sniffer.
        
        Args:
            interface: Network interface to sniff on (None for auto-detect)
        """
        self.interface = interface
        self.socket = None
        self.running = False
        self.packets = []
        self.callback = None
        self.filter_protocols = []  # Optional protocol filters (e.g., 'TCP', 'UDP', 'ICMP')
        self.filter_ips = []  # Optional IP address filters
        self.filter_ports = []  # Optional port filters
        
        # Protocol mappings
        self.protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP'
        }
    
    def start(self, callback=None, timeout: Optional[int] = None):
        """Start packet capture.
        
        Args:
            callback: Function to call for each packet (receives packet dict)
            timeout: Capture duration in seconds (None for indefinite)
        """
        if self.running:
            return
        
        self.callback = callback
        self.running = True
        self.packets = []
        
        try:
            # Create raw socket
            if os.name == 'nt':  # Windows
                # On Windows, we need to use a different approach
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                
                if not self.interface:
                    # Try to get the hostname as a reasonable default
                    host = socket.gethostname()
                    self.socket.bind((host, 0))
                else:
                    self.socket.bind((self.interface, 0))
                
                # Include IP headers
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                # Receive all packets
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Unix/Linux
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                
                if self.interface:
                    self.socket.bind((self.interface, 0))
            
            # Start capture thread
            self.capture_thread = threading.Thread(target=self._capture_packets, args=(timeout,))
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            return True
        except socket.error as e:
            print(f"Error creating socket: {e}")
            self.running = False
            return False
        except Exception as e:
            print(f"Error starting sniffer: {e}")
            self.running = False
            return False
    
    def stop(self):
        """Stop packet capture."""
        self.running = False
        if self.socket:
            if os.name == 'nt':
                # Disable promiscuous mode on Windows
                try:
                    self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except:
                    pass
            
            self.socket.close()
            self.socket = None
    
    def set_filter(self, protocols=None, ips=None, ports=None):
        """Set capture filters.
        
        Args:
            protocols: List of protocols to capture ('TCP', 'UDP', 'ICMP')
            ips: List of IP addresses to capture
            ports: List of ports to capture
        """
        self.filter_protocols = protocols or []
        self.filter_ips = ips or []
        self.filter_ports = ports or []
    
    def _capture_packets(self, timeout):
        """Internal method to capture packets in a thread."""
        start_time = time.time()
        
        while self.running:
            # Check timeout
            if timeout and time.time() - start_time >= timeout:
                self.running = False
                break
            
            try:
                # Receive packet
                raw_packet = self.socket.recvfrom(65535)[0]
                
                # Parse packet
                packet = self._parse_packet(raw_packet)
                
                # Apply filters
                if self._apply_filters(packet):
                    self.packets.append(packet)
                    
                    # Call callback if provided
                    if self.callback:
                        self.callback(packet)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error capturing packet: {e}")
                continue
    
    def _parse_packet(self, data):
        """Parse a raw packet.
        
        Args:
            data: Raw packet data
            
        Returns:
            Dict with parsed packet information
        """
        packet = {
            'timestamp': time.time(),
            'raw': data,
            'eth': {},
            'ip': {},
            'protocol': None,
            'protocol_data': {}
        }
        
        # Parse based on OS
        if os.name == 'nt':  # Windows (starts with IP header)
            self._parse_ip_packet(packet, data, 0)
        else:  # Unix/Linux (starts with Ethernet header)
            # Parse Ethernet header
            eth_length = 14
            eth_header = data[:eth_length]
            
            packet['eth'] = {
                'dest_mac': ':'.join(f'{b:02x}' for b in eth_header[0:6]),
                'src_mac': ':'.join(f'{b:02x}' for b in eth_header[6:12]),
                'protocol': socket.ntohs(struct.unpack('!H', eth_header[12:14])[0])
            }
            
            # Check if it's an IP packet (EtherType 0x0800)
            if packet['eth']['protocol'] == 8:
                self._parse_ip_packet(packet, data, eth_length)
        
        return packet
    
    def _parse_ip_packet(self, packet, data, offset):
        """Parse the IP portion of a packet.
        
        Args:
            packet: Packet dict to update
            data: Raw packet data
            offset: Offset where IP header starts
        """
        # Parse IP header
        ip_header = data[offset:offset+20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        iph_length = ihl * 4
        
        packet['ip'] = {
            'version': version,
            'header_length': ihl,
            'ttl': iph[5],
            'protocol': iph[6],
            'src': socket.inet_ntoa(iph[8]),
            'dest': socket.inet_ntoa(iph[9])
        }
        
        # Get protocol name
        protocol = iph[6]
        packet['protocol'] = self.protocols.get(protocol, str(protocol))
        
        # Parse protocol-specific data
        proto_offset = offset + iph_length
        
        if protocol == 6:  # TCP
            self._parse_tcp_packet(packet, data, proto_offset)
        elif protocol == 17:  # UDP
            self._parse_udp_packet(packet, data, proto_offset)
        elif protocol == 1:  # ICMP
            self._parse_icmp_packet(packet, data, proto_offset)
    
    def _parse_tcp_packet(self, packet, data, offset):
        """Parse the TCP portion of a packet."""
        tcp_header = data[offset:offset+20]
        
        if len(tcp_header) < 20:
            return
        
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        
        packet['protocol_data'] = {
            'src_port': tcph[0],
            'dest_port': tcph[1],
            'sequence': tcph[2],
            'acknowledgement': tcph[3],
            'header_length': (tcph[4] >> 4) * 4,
            'flags': {
                'fin': (tcph[5] & 1) != 0,
                'syn': (tcph[5] & 2) != 0,
                'rst': (tcph[5] & 4) != 0,
                'psh': (tcph[5] & 8) != 0,
                'ack': (tcph[5] & 16) != 0,
                'urg': (tcph[5] & 32) != 0
            },
            'window_size': tcph[6],
            'checksum': tcph[7],
            'urgent_pointer': tcph[8]
        }
        
        # Get payload data
        header_size = offset + packet['protocol_data']['header_length']
        
        if header_size < len(data):
            packet['data'] = data[header_size:]
            
            # Try to decode as text (but safely)
            try:
                packet['text'] = packet['data'].decode('utf-8', errors='replace')
            except:
                packet['text'] = None
    
    def _parse_udp_packet(self, packet, data, offset):
        """Parse the UDP portion of a packet."""
        udp_header = data[offset:offset+8]
        
        if len(udp_header) < 8:
            return
        
        udph = struct.unpack('!HHHH', udp_header)
        
        packet['protocol_data'] = {
            'src_port': udph[0],
            'dest_port': udph[1],
            'length': udph[2],
            'checksum': udph[3]
        }
        
        # Get payload data
        header_size = offset + 8
        
        if header_size < len(data):
            packet['data'] = data[header_size:]
            
            # Try to decode as text (but safely)
            try:
                packet['text'] = packet['data'].decode('utf-8', errors='replace')
            except:
                packet['text'] = None
    
    def _parse_icmp_packet(self, packet, data, offset):
        """Parse the ICMP portion of a packet."""
        icmp_header = data[offset:offset+4]
        
        if len(icmp_header) < 4:
            return
        
        icmph = struct.unpack('!BBH', icmp_header)
        
        packet['protocol_data'] = {
            'type': icmph[0],
            'code': icmph[1],
            'checksum': icmph[2]
        }
        
        # Map ICMP type to human-readable description
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded'
        }
        
        packet['protocol_data']['type_name'] = icmp_types.get(
            icmph[0], f'Unknown Type ({icmph[0]})'
        )
    
    def _apply_filters(self, packet):
        """Apply filters to determine if a packet should be kept."""
        # Protocol filter
        if self.filter_protocols and packet['protocol'] not in self.filter_protocols:
            return False
        
        # IP filter
        if self.filter_ips:
            src_ip = packet.get('ip', {}).get('src')
            dest_ip = packet.get('ip', {}).get('dest')
            
            if not any(ip in [src_ip, dest_ip] for ip in self.filter_ips):
                return False
        
        # Port filter (TCP/UDP only)
        if self.filter_ports and packet['protocol'] in ['TCP', 'UDP']:
            src_port = packet.get('protocol_data', {}).get('src_port')
            dest_port = packet.get('protocol_data', {}).get('dest_port')
            
            if not any(port in [src_port, dest_port] for port in self.filter_ports):
                return False
        
        return True
    
    def get_available_interfaces(self):
        """Get a list of available network interfaces.
        
        Returns:
            List of interface names
        """
        interfaces = []
        
        try:
            # Try using the preferred method for getting interfaces
            if os.name == 'nt':  # Windows
                # On Windows, use socket.gethostbyname_ex
                host = socket.gethostname()
                ips = socket.gethostbyname_ex(host)[2]
                interfaces = ips
            else:
                # On Unix/Linux, use the socket library
                # Import these modules inside the function to avoid scope issues
                import fcntl
                import struct
                import array
                
                # Get list of interfaces
                max_possible = 128  # arbitrary. raise if needed.
                bytes = max_possible * 32
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                names = array.array('B', b'\0' * bytes)
                outbytes = struct.unpack('iL', fcntl.ioctl(
                    s.fileno(),
                    0x8912,  # SIOCGIFCONF
                    struct.pack('iL', bytes, names.buffer_info()[0])
                ))[0]
                
                namestr = names.tobytes()
                interfaces = [namestr[i:i+32].split(b'\0')[0].decode('utf-8') for i in range(0, outbytes, 32)]
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            
            # Fallback for all platforms
            interfaces.append("Default")
        
        return interfaces
    
    def format_packet(self, packet, include_data=False):
        """Format a packet as a human-readable string.
        
        Args:
            packet: Parsed packet dict
            include_data: Whether to include packet data
            
        Returns:
            Formatted string
        """
        lines = []
        
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet['timestamp']))
        lines.append(f"Packet captured at {timestamp}")
        
        # Ethernet info (if available)
        if packet.get('eth'):
            lines.append(f"Ethernet Frame:")
            lines.append(f"  Source MAC: {packet['eth'].get('src_mac', 'Unknown')}")
            lines.append(f"  Destination MAC: {packet['eth'].get('dest_mac', 'Unknown')}")
        
        # IP info
        if packet.get('ip'):
            lines.append(f"IP Packet:")
            lines.append(f"  Source IP: {packet['ip'].get('src', 'Unknown')}")
            lines.append(f"  Destination IP: {packet['ip'].get('dest', 'Unknown')}")
            lines.append(f"  Protocol: {packet.get('protocol', 'Unknown')}")
            lines.append(f"  TTL: {packet['ip'].get('ttl', 'Unknown')}")
        
        # Protocol-specific info
        proto_data = packet.get('protocol_data', {})
        
        if packet.get('protocol') == 'TCP':
            lines.append(f"TCP Segment:")
            lines.append(f"  Source Port: {proto_data.get('src_port', 'Unknown')}")
            lines.append(f"  Destination Port: {proto_data.get('dest_port', 'Unknown')}")
            lines.append(f"  Sequence Number: {proto_data.get('sequence', 'Unknown')}")
            
            # Display flags
            flags = proto_data.get('flags', {})
            flag_str = ' '.join(flag.upper() for flag, value in flags.items() if value)
            lines.append(f"  Flags: {flag_str}")
            
        elif packet.get('protocol') == 'UDP':
            lines.append(f"UDP Segment:")
            lines.append(f"  Source Port: {proto_data.get('src_port', 'Unknown')}")
            lines.append(f"  Destination Port: {proto_data.get('dest_port', 'Unknown')}")
            lines.append(f"  Length: {proto_data.get('length', 'Unknown')}")
            
        elif packet.get('protocol') == 'ICMP':
            lines.append(f"ICMP Packet:")
            lines.append(f"  Type: {proto_data.get('type_name', 'Unknown')}")
            lines.append(f"  Code: {proto_data.get('code', 'Unknown')}")
        
        # Payload data
        if include_data and packet.get('data'):
            lines.append(f"Payload Data:")
            
            if packet.get('text'):
                # Show decoded text if available and printable
                text = packet['text']
                if any(32 <= ord(c) <= 126 for c in text):  # Check if has printable chars
                    # Format and truncate if needed
                    if len(text) > 1000:
                        text = text[:1000] + "... (truncated)"
                    
                    # Wrap text for display
                    wrapped = textwrap.fill(text, width=80, initial_indent='  ', subsequent_indent='  ')
                    lines.append(wrapped)
                else:
                    lines.append("  [Binary data]")
            else:
                # Show hex dump
                hex_dump = ' '.join(f"{b:02x}" for b in packet['data'][:64])
                if len(packet['data']) > 64:
                    hex_dump += " ... (truncated)"
                lines.append(f"  Hex: {hex_dump}")
        
        return '\n'.join(lines)


if __name__ == '__main__':
    # Simple command-line test
    import argparse
    
    parser = argparse.ArgumentParser(description='Simple Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='Capture timeout in seconds (0 for indefinite)')
    parser.add_argument('-p', '--protocol', help='Protocol filter (TCP, UDP, ICMP)')
    args = parser.parse_args()
    
    sniffer = PacketSniffer(args.interface)
    
    if args.protocol:
        sniffer.set_filter(protocols=[args.protocol.upper()])
    
    print(f"Available interfaces: {sniffer.get_available_interfaces()}")
    print(f"Starting packet capture on interface: {args.interface or 'default'}")
    print(f"Duration: {args.timeout} seconds (Ctrl+C to stop)")
    print("Waiting for packets...")
    
    # Define a callback to print packets as they arrive
    def packet_callback(packet):
        print("\n" + "=" * 70)
        print(sniffer.format_packet(packet, include_data=True))
    
    # Start sniffing
    sniffer.start(callback=packet_callback, timeout=args.timeout or None)
    
    try:
        # Keep main thread alive until timeout or Ctrl+C
        while sniffer.running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        
    print("\nPacket capture complete.")
    print(f"Captured {len(sniffer.packets)} packets.")