#!/usr/bin/env python3
import sys
import time
import os
from src.tools.network.port_scanner import PortScanner
from src.tools.network.ping_utility import PingUtility
from src.tools.network.traceroute import Traceroute
from src.tools.network.arp_scanner import ARPScanner
from src.tools.network.netstat_utility import NetstatUtility
from src.tools.network.bandwidth_monitor import BandwidthMonitor
from src.tools.network.nmap_scanner import NmapScanner
from src.tools.network.packet_sniffer import PacketSniffer
from src.tools.network.wireless_scanner import WirelessScanner

def handle_network_commands(args):
    """Handle network module commands."""
    if not args.command:
        print("Error: You must specify a network command. Use 'network --help' for more information.")
        sys.exit(1)
    
    # Port Scanner
    if args.command == 'portscan':
        scanner = PortScanner()
        
        # Parse port range
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        else:
            start_port = end_port = int(args.ports)
        
        print(f"Scanning {args.target} for open ports ({start_port}-{end_port})...")
        
        # Create a progress display function
        total_ports = end_port - start_port + 1
        scanned_ports = 0
        open_ports = {}
        
        def progress_callback(port, service, is_open):
            nonlocal scanned_ports, open_ports
            scanned_ports += 1
            
            # Update progress every 50 ports or when an open port is found
            if is_open or scanned_ports % 50 == 0 or scanned_ports == total_ports:
                if is_open:
                    open_ports[port] = service
                percent = (scanned_ports / total_ports) * 100
                print(f"\rProgress: {scanned_ports}/{total_ports} ports scanned ({percent:.1f}%) - {len(open_ports)} open ports found", end="")
                sys.stdout.flush()
        
        # Run the scan with the progress callback
        start_time = time.time()
        results = scanner.scan(args.target, start_port, end_port, timeout=args.timeout, progress_callback=progress_callback)
        scan_time = time.time() - start_time
        
        print()  # New line after progress
        
        if "error" in results:
            print(f"Error: {results['error']}")
            sys.exit(1)
        
        if not results:
            print(f"No open ports found on {args.target} in range {start_port}-{end_port}")
        else:
            print(f"\nOpen ports on {args.target} (scan completed in {scan_time:.2f} seconds):")
            print("-" * 40)
            print(f"{'PORT':<10} {'SERVICE':<30}")
            print("-" * 40)
            
            for port, service in sorted(results.items()):
                print(f"{port:<10} {service:<30}")
    
    # Ping Utility
    elif args.command == 'ping':
        ping = PingUtility()
        print(f"Pinging {args.target} with {args.count} packets...")
        results = ping.ping(args.target, args.count)
        
        if "error" in results:
            print(f"Error: {results['error']}")
            sys.exit(1)
        
        print(f"\nPing results for {args.target}:")
        print(f"Packets sent: {results['sent']}")
        print(f"Packets received: {results['received']}")
        print(f"Packet loss: {results['loss']}%")
        
        if results['times']:
            print(f"Minimum RTT: {min(results['times']):.2f} ms")
            print(f"Maximum RTT: {max(results['times']):.2f} ms")
            print(f"Average RTT: {sum(results['times']) / len(results['times']):.2f} ms")
    
    # Traceroute
    elif args.command == 'traceroute':
        traceroute = Traceroute()
        print(f"Tracing route to {args.target}...")
        results = traceroute.trace(args.target, args.max_hops)
        
        if "error" in results:
            print(f"Error: {results['error']}")
            sys.exit(1)
        
        print(f"\nTraceroute to {args.target}:")
        print("-" * 60)
        print(f"{'HOP':<5} {'IP':<20} {'RTT (ms)':<15} {'HOSTNAME':<20}")
        print("-" * 60)
        
        for hop in results:
            print(f"{hop['hop']:<5} {hop['ip']:<20} {hop['rtt']:<15.2f} {hop['hostname']:<20}")
    
    # ARP Scanner
    elif args.command == 'arpscan':
        scanner = ARPScanner()
        print(f"Scanning network {args.range} for devices...")
        results = scanner.scan(args.range)
        
        if "error" in results:
            print(f"Error: {results['error']}")
            sys.exit(1)
        
        print(f"\nDevices found on network {args.range}:")
        print("-" * 40)
        print(f"{'IP':<20} {'MAC':<20}")
        print("-" * 40)
        
        for device in results:
            print(f"{device['ip']:<20} {device['mac']:<20}")
    
    # Netstat Utility
    elif args.command == 'netstat':
        netstat = NetstatUtility()
        print("Retrieving network connections...")
        connections = netstat.get_connections()
        
        print("\nActive network connections:")
        print("-" * 80)
        print(f"{'PROTO':<10} {'LOCAL ADDRESS':<25} {'REMOTE ADDRESS':<25} {'STATE':<15}")
        print("-" * 80)
        
        for conn in connections:
            print(f"{conn['proto']:<10} {conn['local_address']:<25} {conn['remote_address']:<25} {conn['state']:<15}")
    
    # Bandwidth Monitor
    elif args.command == 'bandwidth':
        monitor = BandwidthMonitor()
        interface = args.interface
        
        if not interface:
            # Get default interface if not specified
            interfaces = monitor.get_interfaces()
            if interfaces:
                interface = interfaces[0]['name']
                print(f"Using default interface: {interface}")
            else:
                print("Error: No network interfaces found.")
                sys.exit(1)
        
        print(f"Monitoring bandwidth on {interface} for {args.duration} seconds...")
        results = monitor.monitor(interface, args.duration)
        
        print(f"\nBandwidth usage on {interface}:")
        print("-" * 60)
        print(f"{'TIMESTAMP':<25} {'RX (KB/s)':<15} {'TX (KB/s)':<15}")
        print("-" * 60)
        
        for sample in results:
            print(f"{sample['timestamp']:<25} {sample['rx_kbps']:<15.2f} {sample['tx_kbps']:<15.2f}")
        
        if results:
            avg_rx = sum(s['rx_kbps'] for s in results) / len(results)
            avg_tx = sum(s['tx_kbps'] for s in results) / len(results)
            print(f"\nAverage RX: {avg_rx:.2f} KB/s")
            print(f"Average TX: {avg_tx:.2f} KB/s")
    
    # Nmap Scanner
    elif args.command == 'nmap':
        scanner = NmapScanner()
        print(f"Running Nmap scan on {args.target} with arguments '{args.arguments}'...")
        
        try:
            results = scanner.scan(args.target, args.arguments)
            
            if "error" in results:
                print(f"Error: {results['error']}")
                if "not installed" in results["error"]:
                    print("Please install Nmap: https://nmap.org/download.html")
                sys.exit(1)
            
            print("\nNmap scan results:")
            print(results['output'])
            
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    
    # Packet Sniffer
    elif args.command == 'sniff':
        sniffer = PacketSniffer(args.interface)
        
        # Set up filters if provided
        protocols = []
        if args.protocol:
            protocols = [args.protocol.upper()]
        
        ips = []
        if args.ip_address:
            ips = [args.ip_address]
        
        ports = []
        if args.port:
            ports = [args.port]
        
        if protocols or ips or ports:
            sniffer.set_filter(protocols=protocols, ips=ips, ports=ports)
            filter_msg = []
            if protocols:
                filter_msg.append(f"protocol={protocols[0]}")
            if ips:
                filter_msg.append(f"IP={ips[0]}")
            if ports:
                filter_msg.append(f"port={ports[0]}")
            filter_str = ", ".join(filter_msg)
            print(f"Filters applied: {filter_str}")
        
        # Set up output file if provided
        output_file = None
        if args.output:
            try:
                output_file = open(args.output, 'w')
                print(f"Saving output to {args.output}")
            except Exception as e:
                print(f"Warning: Could not open output file: {str(e)}")
                output_file = None
        
        # Set up callback to print packets
        def packet_callback(packet):
            formatted = sniffer.format_packet(packet, include_data=True)
            print("\n" + "=" * 70)
            print(formatted)
            
            # Save to file if needed
            if output_file:
                output_file.write("=" * 70 + "\n")
                output_file.write(formatted + "\n")
                output_file.flush()
        
        # Get available interfaces
        interfaces = sniffer.get_available_interfaces()
        if interfaces:
            print(f"Available interfaces: {', '.join(interfaces)}")
        
        # Start sniffing
        print(f"Starting packet capture on interface: {args.interface or 'default'}")
        print(f"Duration: {args.time} seconds (Ctrl+C to stop)")
        print("Waiting for packets...")
        
        # Start the sniffer
        sniffer.start(callback=packet_callback, timeout=args.time if args.time > 0 else None)
        
        try:
            # Keep main thread alive until timeout or Ctrl+C
            while sniffer.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nStopping packet capture...")
        finally:
            sniffer.stop()
            if output_file:
                output_file.close()
            
        print("\nPacket capture complete.")
        print(f"Captured {len(sniffer.packets)} packets.")
        
        if output_file:
            print(f"Results saved to {args.output}")
    
    # Wireless Scanner
    elif args.command == 'wifi':
        scanner = WirelessScanner()
        interfaces = scanner.get_interfaces()
        
        if not interfaces:
            print("Error: No wireless interfaces found.")
            sys.exit(1)
        
        interface = args.interface
        if not interface:
            # Use first available interface
            interface = interfaces[0]
            print(f"Using default wireless interface: {interface}")
        elif interface not in interfaces:
            print(f"Warning: Specified interface '{interface}' not found in available interfaces ({', '.join(interfaces)})")
            print(f"Attempting to use it anyway...")
        
        print(f"Scanning for wireless networks using interface '{interface}'...")
        networks = scanner.scan(interface)
        
        if not networks:
            print("No wireless networks found.")
            sys.exit(0)
        
        print(f"\nFound {len(networks)} wireless networks:")
        print("-" * 80)
        print(f"{'SSID':<30} {'Security':<20} {'Signal':<8} {'Channel':<8} {'BSSID':<17}")
        print("-" * 80)
        
        for network in networks:
            ssid = network.get('ssid', '<Hidden>')
            security = network.get('security_full', network.get('security', 'Unknown'))
            signal = f"{network.get('signal', 0)}%"
            channel = network.get('channel', 'N/A')
            bssid = network.get('bssid', 'N/A')
            
            print(f"{ssid:<30} {security:<20} {signal:<8} {channel:<8} {bssid:<17}")
            
            # Show security rating if requested
            if args.rate:
                rating, desc = scanner.get_security_rating(security)
                print(f"  Security Rating: {rating}/5 - {desc}")
    
    else:
        print(f"Error: Unknown network command '{args.command}'")
        sys.exit(1)