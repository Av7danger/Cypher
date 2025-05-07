import hashlib
import base64
import os


class HashGenerator:
    """Tool for generating various cryptographic hashes."""
    
    def __init__(self):
        # Dictionary of supported hash algorithms and their methods
        self.hash_algorithms = {
            'md5': self._md5_hash,
            'sha1': self._sha1_hash,
            'sha224': self._sha224_hash,
            'sha256': self._sha256_hash,
            'sha384': self._sha384_hash,
            'sha512': self._sha512_hash,
            'blake2b': self._blake2b_hash,
            'blake2s': self._blake2s_hash,
        }
    
    def get_available_algorithms(self):
        """Return a list of available hash algorithms."""
        return list(self.hash_algorithms.keys())
    
    def generate_hash(self, data, algorithm='sha256'):
        """
        Generate a hash of the input data using the specified algorithm.
        
        Args:
            data: Input data as string or bytes
            algorithm: Hash algorithm to use (default: sha256)
            
        Returns:
            Hexadecimal representation of the hash
        """
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Check if the algorithm is supported
        if algorithm.lower() not in self.hash_algorithms:
            return {
                'error': f'Unsupported hash algorithm: {algorithm}',
                'supported_algorithms': self.get_available_algorithms()
            }
            
        # Generate the hash using the selected algorithm
        try:
            hash_hex = self.hash_algorithms[algorithm.lower()](data)
            return {
                'algorithm': algorithm,
                'hash': hash_hex,
                'input_length': len(data)
            }
        except Exception as e:
            return {'error': f'Error generating hash: {str(e)}'}
    
    def generate_file_hash(self, file_path, algorithm='sha256'):
        """
        Generate a hash of a file using the specified algorithm.
        
        Args:
            file_path: Path to the file to hash
            algorithm: Hash algorithm to use (default: sha256)
            
        Returns:
            Hexadecimal representation of the file hash
        """
        # Check if the file exists
        if not os.path.isfile(file_path):
            return {'error': f'File not found: {file_path}'}
            
        # Check if the algorithm is supported
        if algorithm.lower() not in self.hash_algorithms:
            return {
                'error': f'Unsupported hash algorithm: {algorithm}',
                'supported_algorithms': self.get_available_algorithms()
            }
            
        # Generate the file hash
        try:
            hash_func = getattr(hashlib, algorithm.lower())
            h = hash_func()
            
            # Read the file in chunks to handle large files
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    h.update(chunk)
            
            return {
                'algorithm': algorithm,
                'hash': h.hexdigest(),
                'file_path': file_path,
                'file_size': os.path.getsize(file_path)
            }
        except Exception as e:
            return {'error': f'Error generating file hash: {str(e)}'}
    
    # Individual hash algorithm methods
    def _md5_hash(self, data):
        return hashlib.md5(data).hexdigest()
        
    def _sha1_hash(self, data):
        return hashlib.sha1(data).hexdigest()
        
    def _sha224_hash(self, data):
        return hashlib.sha224(data).hexdigest()
        
    def _sha256_hash(self, data):
        return hashlib.sha256(data).hexdigest()
        
    def _sha384_hash(self, data):
        return hashlib.sha384(data).hexdigest()
        
    def _sha512_hash(self, data):
        return hashlib.sha512(data).hexdigest()
        
    def _blake2b_hash(self, data):
        return hashlib.blake2b(data).hexdigest()
        
    def _blake2s_hash(self, data):
        return hashlib.blake2s(data).hexdigest()