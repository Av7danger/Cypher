#!/usr/bin/env python3
import sys
from src.tools.web_domain.dns_lookup import DNSLookup
from src.tools.web_domain.whois_lookup import WhoisLookup

def handle_web_domain_commands(args):
    """Handle web and domain module commands."""
    if not args.command:
        print("Error: You must specify a web/domain command. Use 'webdomain --help' for more information.")
        sys.exit(1)
    
    # DNS Lookup
    if args.command == 'dns':
        dns = DNSLookup()
        
        print(f"Performing DNS lookup for {args.domain} ({args.type} records)...")
        results = dns.lookup(args.domain, args.type)
        
        if "error" in results:
            print(f"Error: {results['error']}")
            sys.exit(1)
        
        print(f"\nDNS lookup results for {args.domain} ({args.type}):")
        print("-" * 70)
        
        if not results['records']:
            print(f"No {args.type} records found for {args.domain}")
        else:
            for i, record in enumerate(results['records'], 1):
                print(f"Record {i}:")
                for key, value in record.items():
                    print(f"  {key}: {value}")
                if i < len(results['records']):
                    print()
    
    # WHOIS Lookup
    elif args.command == 'whois':
        whois = WhoisLookup()
        
        print(f"Performing WHOIS lookup for {args.domain}...")
        results = whois.lookup(args.domain)
        
        if "error" in results:
            print(f"Error: {results['error']}")
            sys.exit(1)
        
        print(f"\nWHOIS lookup results for {args.domain}:")
        print("-" * 70)
        
        for key, value in results.items():
            if key != "raw" and value:  # Skip 'raw' data and empty fields
                print(f"{key.replace('_', ' ').capitalize()}: {value}")
        
        # Print raw data if available and verbose mode
        # if "raw" in results and args.verbose:
        #     print("\nRaw WHOIS data:")
        #     print(results["raw"])
    
    else:
        print(f"Error: Unknown web domain command '{args.command}'")
        sys.exit(1)