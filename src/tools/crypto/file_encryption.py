import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization


class FileEncryptionTool:
    """Tool for encrypting and decrypting files using various encryption methods."""
    
    def __init__(self):
        self.encryption_methods = {
            'aes': self._encrypt_file_aes,
            'rsa': self._encrypt_file_rsa
        }
        
        self.decryption_methods = {
            'aes': self._decrypt_file_aes,
            'rsa': self._decrypt_file_rsa
        }
    
    def get_available_methods(self):
        """Return a list of available encryption methods."""
        return list(self.encryption_methods.keys())
    
    def encrypt_file(self, file_path, password=None, method='aes'):
        """
        Encrypt a file using the specified encryption method.
        
        Args:
            file_path: Path to the file to encrypt
            password: Password or key for encryption (required for AES)
            method: Encryption method to use (default: aes)
            
        Returns:
            Dictionary with encryption status and output file path
        """
        # Check if the file exists
        if not os.path.isfile(file_path):
            return {'error': f'File not found: {file_path}'}
        
        # Check if the method is supported
        if method.lower() not in self.encryption_methods:
            return {
                'error': f'Unsupported encryption method: {method}',
                'supported_methods': self.get_available_methods()
            }
        
        # Generate the output file path
        output_path = f"{file_path}.encrypted"
        
        # Call the appropriate encryption method
        try:
            result = self.encryption_methods[method.lower()](
                file_path, output_path, password
            )
            
            if 'error' in result:
                return result
                
            return {
                'success': True,
                'method': method,
                'input_file': file_path,
                'output_file': output_path,
                **result
            }
            
        except Exception as e:
            return {'error': f'Error encrypting file: {str(e)}'}
    
    def decrypt_file(self, file_path, password=None, method='aes'):
        """
        Decrypt a file using the specified decryption method.
        
        Args:
            file_path: Path to the encrypted file
            password: Password or key for decryption (required for AES)
            method: Decryption method to use (default: aes)
            
        Returns:
            Dictionary with decryption status and output file path
        """
        # Check if the file exists
        if not os.path.isfile(file_path):
            return {'error': f'File not found: {file_path}'}
        
        # Check if the method is supported
        if method.lower() not in self.decryption_methods:
            return {
                'error': f'Unsupported decryption method: {method}',
                'supported_methods': self.get_available_methods()
            }
        
        # Generate the output file path
        if file_path.endswith('.encrypted'):
            output_path = file_path[:-10]  # Remove .encrypted extension
        else:
            output_path = f"{file_path}.decrypted"
        
        # Call the appropriate decryption method
        try:
            result = self.decryption_methods[method.lower()](
                file_path, output_path, password
            )
            
            if 'error' in result:
                return result
                
            return {
                'success': True,
                'method': method,
                'input_file': file_path,
                'output_file': output_path,
                **result
            }
            
        except Exception as e:
            return {'error': f'Error decrypting file: {str(e)}'}
    
    def _generate_key_from_password(self, password):
        """Generate a Fernet key from a password using PBKDF2."""
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        # Use a fixed salt for reproducibility (in production, use a random salt and store it)
        salt = b'cybersecurity_toolkit_salt'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _encrypt_file_aes(self, input_path, output_path, password):
        """Encrypt a file using AES encryption via Fernet."""
        if not password:
            return {'error': 'Password is required for AES encryption'}
            
        # Generate key from password
        key = self._generate_key_from_password(password)
        fernet = Fernet(key)
        
        try:
            # Read the file
            with open(input_path, 'rb') as file:
                file_data = file.read()
            
            # Encrypt the data
            encrypted_data = fernet.encrypt(file_data)
            
            # Write the encrypted data to the output file
            with open(output_path, 'wb') as file:
                file.write(encrypted_data)
                
            return {
                'encryption_type': 'AES',
                'file_size': os.path.getsize(input_path),
                'encrypted_size': os.path.getsize(output_path)
            }
            
        except Exception as e:
            # Clean up if necessary
            if os.path.exists(output_path):
                os.remove(output_path)
            raise e
    
    def _decrypt_file_aes(self, input_path, output_path, password):
        """Decrypt a file using AES decryption via Fernet."""
        if not password:
            return {'error': 'Password is required for AES decryption'}
            
        # Generate key from password
        key = self._generate_key_from_password(password)
        fernet = Fernet(key)
        
        try:
            # Read the encrypted file
            with open(input_path, 'rb') as file:
                encrypted_data = file.read()
            
            # Decrypt the data
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except Exception:
                return {'error': 'Invalid password or corrupted file'}
            
            # Write the decrypted data to the output file
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)
                
            return {
                'encryption_type': 'AES',
                'encrypted_size': os.path.getsize(input_path),
                'decrypted_size': os.path.getsize(output_path)
            }
            
        except Exception as e:
            # Clean up if necessary
            if os.path.exists(output_path):
                os.remove(output_path)
            raise e
    
    def generate_rsa_key_pair(self, key_size=2048):
        """
        Generate a new RSA key pair.
        
        Args:
            key_size: Size of the RSA key in bits (default: 2048)
            
        Returns:
            Dictionary with private and public keys in PEM format
        """
        try:
            # Generate a private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            
            # Get the public key
            public_key = private_key.public_key()
            
            # Serialize the private key to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize the public key to PEM format
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                'private_key': private_pem.decode('utf-8'),
                'public_key': public_pem.decode('utf-8'),
                'key_size': key_size
            }
            
        except Exception as e:
            return {'error': f'Error generating RSA key pair: {str(e)}'}
    
    def _encrypt_file_rsa(self, input_path, output_path, public_key_pem):
        """Encrypt a file using RSA encryption (hybrid encryption for large files)."""
        if not public_key_pem:
            return {'error': 'Public key is required for RSA encryption'}
            
        try:
            # Convert the PEM encoded key to a public key object
            if isinstance(public_key_pem, str):
                public_key_pem = public_key_pem.encode('utf-8')
                
            public_key = serialization.load_pem_public_key(public_key_pem)
            
            # For RSA, we use hybrid encryption (AES + RSA)
            # Generate a random AES key
            aes_key = Fernet.generate_key()
            fernet = Fernet(aes_key)
            
            # Read the file
            with open(input_path, 'rb') as file:
                file_data = file.read()
            
            # Encrypt the data with AES
            encrypted_data = fernet.encrypt(file_data)
            
            # Encrypt the AES key with RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Write the encrypted key length, encrypted key, and encrypted data
            with open(output_path, 'wb') as file:
                key_length = len(encrypted_key).to_bytes(4, byteorder='big')
                file.write(key_length)
                file.write(encrypted_key)
                file.write(encrypted_data)
                
            return {
                'encryption_type': 'RSA-Hybrid',
                'file_size': os.path.getsize(input_path),
                'encrypted_size': os.path.getsize(output_path)
            }
            
        except Exception as e:
            # Clean up if necessary
            if os.path.exists(output_path):
                os.remove(output_path)
            raise e
    
    def _decrypt_file_rsa(self, input_path, output_path, private_key_pem):
        """Decrypt a file using RSA decryption (hybrid decryption for large files)."""
        if not private_key_pem:
            return {'error': 'Private key is required for RSA decryption'}
            
        try:
            # Convert the PEM encoded key to a private key object
            if isinstance(private_key_pem, str):
                private_key_pem = private_key_pem.encode('utf-8')
                
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            
            # Read the encrypted file
            with open(input_path, 'rb') as file:
                # Read the encrypted key length
                key_length_bytes = file.read(4)
                key_length = int.from_bytes(key_length_bytes, byteorder='big')
                
                # Read the encrypted key
                encrypted_key = file.read(key_length)
                
                # Read the encrypted data
                encrypted_data = file.read()
            
            # Decrypt the AES key with RSA
            try:
                aes_key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception:
                return {'error': 'Invalid private key or corrupted file'}
            
            # Decrypt the data with AES
            fernet = Fernet(aes_key)
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except Exception:
                return {'error': 'Corrupted encrypted data'}
            
            # Write the decrypted data to the output file
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)
                
            return {
                'encryption_type': 'RSA-Hybrid',
                'encrypted_size': os.path.getsize(input_path),
                'decrypted_size': os.path.getsize(output_path)
            }
            
        except Exception as e:
            # Clean up if necessary
            if os.path.exists(output_path):
                os.remove(output_path)
            raise e

# Create an alias for compatibility with CLI code
FileEncryption = FileEncryptionTool