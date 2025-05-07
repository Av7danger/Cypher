#!/usr/bin/env python3
import argparse
import sys
from src.cli.network_commands import handle_network_commands
from src.cli.crypto_commands import handle_crypto_commands
from src.cli.system_commands import handle_system_commands
from src.cli.web_domain_commands import handle_web_domain_commands
from src.cli.web_pentest_commands import handle_web_pentest_commands
from src.cli.pentest_commands import handle_pentest_commands

def parse_arguments():
    """Parse command line arguments for the Cypher CLI."""
    parser = argparse.ArgumentParser(
        description='Cypher Security Toolkit CLI',
        epilog='Use %(prog)s <module> --help to see help for specific modules'
    )
    
    # Create subparsers for different tool categories
    subparsers = parser.add_subparsers(dest='module', help='Tool module to use')
    
    # Network Tools
    network_parser = subparsers.add_parser('network', help='Network security tools')
    network_subparsers = network_parser.add_subparsers(dest='command', help='Network command to run')
    
    # Port Scanner
    port_scanner = network_subparsers.add_parser('portscan', help='Scan ports on a target')
    port_scanner.add_argument('target', help='Target hostname or IP address')
    port_scanner.add_argument('-p', '--ports', help='Port range (e.g., 1-1000) or single port', default='1-1000')
    port_scanner.add_argument('-t', '--timeout', type=float, help='Connection timeout in seconds', default=1.0)
    
    # Ping Utility
    ping = network_subparsers.add_parser('ping', help='Ping a host')
    ping.add_argument('target', help='Target hostname or IP address')
    ping.add_argument('-c', '--count', type=int, help='Number of packets to send', default=4)
    
    # Traceroute
    traceroute = network_subparsers.add_parser('traceroute', help='Trace route to host')
    traceroute.add_argument('target', help='Target hostname or IP address')
    traceroute.add_argument('-m', '--max-hops', type=int, help='Maximum number of hops', default=30)
    
    # ARP Scanner
    arp_scanner = network_subparsers.add_parser('arpscan', help='Scan local network using ARP')
    arp_scanner.add_argument('-r', '--range', help='IP range to scan (e.g., 192.168.1.0/24)', required=True)
    
    # Netstat
    netstat = network_subparsers.add_parser('netstat', help='Show network connections')
    
    # Bandwidth Monitor
    bandwidth = network_subparsers.add_parser('bandwidth', help='Monitor network bandwidth')
    bandwidth.add_argument('-i', '--interface', help='Network interface to monitor')
    bandwidth.add_argument('-d', '--duration', type=int, help='Monitoring duration in seconds', default=10)
    
    # Nmap Scanner (if available)
    nmap = network_subparsers.add_parser('nmap', help='Run Nmap scan')
    nmap.add_argument('target', help='Target hostname or IP address')
    nmap.add_argument('-a', '--arguments', help='Additional Nmap arguments', default='-sV')
    
    # Crypto Tools
    crypto_parser = subparsers.add_parser('crypto', help='Cryptography tools')
    crypto_subparsers = crypto_parser.add_subparsers(dest='command', help='Crypto command to run')
    
    # File Encryption
    encrypt = crypto_subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt.add_argument('file', help='File to encrypt')
    encrypt.add_argument('-o', '--output', help='Output file')
    encrypt.add_argument('-p', '--password', help='Encryption password')
    
    decrypt = crypto_subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt.add_argument('file', help='File to decrypt')
    decrypt.add_argument('-o', '--output', help='Output file')
    decrypt.add_argument('-p', '--password', help='Decryption password')
    
    # Hash Generator
    hash_gen = crypto_subparsers.add_parser('hash', help='Generate file or text hash')
    hash_gen.add_argument('input', help='File path or text to hash')
    hash_gen.add_argument('-a', '--algorithm', help='Hash algorithm (md5, sha1, sha256, etc.)', default='sha256')
    hash_gen.add_argument('-f', '--is-file', action='store_true', help='Input is a file path')
    
    # Password Strength 
    password = crypto_subparsers.add_parser('password', help='Check password strength')
    password.add_argument('password', help='Password to check')
    
    # System Tools
    system_parser = subparsers.add_parser('system', help='System security tools')
    system_subparsers = system_parser.add_subparsers(dest='command', help='System command to run')
    
    # Process Monitor
    process = system_subparsers.add_parser('processes', help='List and monitor processes')
    
    # File Integrity Checker
    integrity = system_subparsers.add_parser('integrity', help='Check file integrity')
    integrity.add_argument('file', help='File to check')
    integrity.add_argument('-b', '--baseline', help='Create baseline hash')
    
    # Web & Domain Tools
    web_domain_parser = subparsers.add_parser('webdomain', help='Web and domain tools')
    web_domain_subparsers = web_domain_parser.add_subparsers(dest='command', help='Web/domain command to run')
    
    # DNS Lookup
    dns = web_domain_subparsers.add_parser('dns', help='Perform DNS lookup')
    dns.add_argument('domain', help='Domain to lookup')
    dns.add_argument('-t', '--type', help='Record type (A, AAAA, MX, etc.)', default='A')
    
    # Whois Lookup
    whois = web_domain_subparsers.add_parser('whois', help='Perform WHOIS lookup')
    whois.add_argument('domain', help='Domain to lookup')
    
    # Web Pentest Tools
    web_pentest_parser = subparsers.add_parser('webpentest', help='Web penetration testing tools')
    web_pentest_subparsers = web_pentest_parser.add_subparsers(dest='command', help='Web pentest command to run')
    
    # HTTP Header Analyzer
    headers = web_pentest_subparsers.add_parser('headers', help='Analyze HTTP headers')
    headers.add_argument('url', help='URL to analyze')
    
    # Subdomain Scanner
    subdomains = web_pentest_subparsers.add_parser('subdomains', help='Scan for subdomains')
    subdomains.add_argument('domain', help='Domain to scan')
    
    # XSS Scanner
    xss = web_pentest_subparsers.add_parser('xss', help='Scan for XSS vulnerabilities')
    xss.add_argument('url', help='URL to scan')
    
    # Pentest Tools
    pentest_parser = subparsers.add_parser('pentest', help='Advanced penetration testing tools')
    pentest_subparsers = pentest_parser.add_subparsers(dest='command', help='Pentest command to run')
    
    # SQL Injection Scanner
    sqli = pentest_subparsers.add_parser('sqli', help='Scan for SQL injection vulnerabilities')
    sqli.add_argument('url', help='URL to scan')
    
    return parser.parse_args()

def run_cli():
    """Run the Cypher CLI with the provided arguments."""
    args = parse_arguments()
    
    if not args.module:
        print("Error: You must specify a module. Use --help for more information.")
        sys.exit(1)
    
    # Route to the appropriate module handler
    if args.module == 'network':
        handle_network_commands(args)
    elif args.module == 'crypto':
        handle_crypto_commands(args)
    elif args.module == 'system':
        handle_system_commands(args)
    elif args.module == 'webdomain':
        handle_web_domain_commands(args)
    elif args.module == 'webpentest':
        handle_web_pentest_commands(args)
    elif args.module == 'pentest':
        handle_pentest_commands(args)
    else:
        print(f"Error: Unknown module '{args.module}'")
        sys.exit(1)

if __name__ == '__main__':
    run_cli()