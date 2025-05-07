#!/usr/bin/env python3
import sys
from src.tools.system.process_monitor import ProcessMonitor
from src.tools.system.file_integrity_checker import FileIntegrityChecker

def handle_system_commands(args):
    """Handle system module commands."""
    if not args.command:
        print("Error: You must specify a system command. Use 'system --help' for more information.")
        sys.exit(1)
    
    # Process Monitor
    if args.command == 'processes':
        monitor = ProcessMonitor()
        
        print("Retrieving running processes...")
        processes = monitor.get_processes()
        
        print("\nRunning processes:")
        print("-" * 90)
        print(f"{'PID':<10} {'NAME':<30} {'CPU %':<10} {'MEMORY %':<10} {'USERNAME':<15}")
        print("-" * 90)
        
        for proc in sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:50]:  # Show top 50 CPU users
            print(f"{proc['pid']:<10} {proc['name'][:28]:<30} {proc['cpu_percent']:<10.1f} {proc['memory_percent']:<10.1f} {proc['username'][:13]:<15}")
        
        print("\nShowing top 50 processes by CPU usage. Total processes:", len(processes))
    
    # File Integrity Checker
    elif args.command == 'integrity':
        checker = FileIntegrityChecker()
        
        if args.baseline:
            # Create baseline hash
            print(f"Creating baseline hash for {args.file}...")
            result = checker.create_baseline(args.file, args.baseline)
            
            if "error" in result:
                print(f"Error: {result['error']}")
                sys.exit(1)
            
            print(f"Baseline hash created and saved to {args.baseline}")
            print(f"Hash value (SHA-256): {result['hash']}")
        else:
            # Check file integrity against previous baseline
            print(f"Checking integrity of {args.file}...")
            result = checker.check_integrity(args.file)
            
            if "error" in result:
                print(f"Error: {result['error']}")
                sys.exit(1)
            
            print("\nFile integrity check results:")
            print(f"Current hash: {result['current_hash']}")
            
            if result['match']:
                print("INTEGRITY CHECK: PASSED ✓")
                print("The file has not been modified since the baseline was created.")
            else:
                print("INTEGRITY CHECK: FAILED ✗")
                print("The file has been modified since the baseline was created!")
                print(f"Expected hash: {result['baseline_hash']}")
    
    else:
        print(f"Error: Unknown system command '{args.command}'")
        sys.exit(1)