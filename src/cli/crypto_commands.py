#!/usr/bin/env python3
import sys
import getpass
from src.tools.crypto.file_encryption import FileEncryption
from src.tools.crypto.hash_generator import HashGenerator
from src.tools.crypto.password_strength import PasswordStrength

def handle_crypto_commands(args):
    """Handle cryptography module commands."""
    if not args.command:
        print("Error: You must specify a crypto command. Use 'crypto --help' for more information.")
        sys.exit(1)
    
    # File Encryption
    if args.command == 'encrypt':
        encryptor = FileEncryption()
        
        # Get the password if not provided
        password = args.password
        if not password:
            password = getpass.getpass("Enter encryption password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Error: Passwords do not match.")
                sys.exit(1)
        
        # Determine output filename if not provided
        output = args.output if args.output else f"{args.file}.encrypted"
        
        print(f"Encrypting {args.file} to {output}...")
        
        try:
            result = encryptor.encrypt_file(args.file, output, password)
            
            if result.get("success"):
                print(f"File encrypted successfully and saved to {output}")
            else:
                print(f"Error: {result.get('error', 'Unknown error')}")
                sys.exit(1)
                
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    
    # File Decryption
    elif args.command == 'decrypt':
        encryptor = FileEncryption()
        
        # Get the password if not provided
        password = args.password
        if not password:
            password = getpass.getpass("Enter decryption password: ")
        
        # Determine output filename if not provided
        output = args.output
        if not output:
            if args.file.endswith('.encrypted'):
                output = args.file[:-10]  # Remove .encrypted extension
            else:
                output = f"{args.file}.decrypted"
        
        print(f"Decrypting {args.file} to {output}...")
        
        try:
            result = encryptor.decrypt_file(args.file, output, password)
            
            if result.get("success"):
                print(f"File decrypted successfully and saved to {output}")
            else:
                print(f"Error: {result.get('error', 'Unknown error')}")
                sys.exit(1)
                
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    
    # Hash Generator
    elif args.command == 'hash':
        generator = HashGenerator()
        
        try:
            if args.is_file:
                print(f"Generating {args.algorithm} hash for file {args.input}...")
                result = generator.hash_file(args.input, args.algorithm)
            else:
                print(f"Generating {args.algorithm} hash for text input...")
                result = generator.hash_text(args.input, args.algorithm)
            
            if "error" in result:
                print(f"Error: {result['error']}")
                sys.exit(1)
            
            print(f"\n{args.algorithm.upper()} Hash:")
            print(result['hash'])
            
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    
    # Password Strength Checker
    elif args.command == 'password':
        checker = PasswordStrength()
        
        try:
            print("Analyzing password strength...")
            result = checker.check_strength(args.password)
            
            if "error" in result:
                print(f"Error: {result['error']}")
                sys.exit(1)
            
            print("\nPassword Strength Analysis:")
            print(f"Score: {result['score']}/4")
            print(f"Strength: {result['strength']}")
            print("\nDetails:")
            
            for key, value in result['details'].items():
                if key != 'suggestions':
                    print(f"- {key.replace('_', ' ').capitalize()}: {value}")
            
            if result['details'].get('suggestions'):
                print("\nSuggestions:")
                for suggestion in result['details']['suggestions']:
                    print(f"- {suggestion}")
            
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    
    else:
        print(f"Error: Unknown crypto command '{args.command}'")
        sys.exit(1)