import os
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class RSA_AES_Encryptor:
    """RSA+AES hybrid encryption - consistent with Framework 1 & 2"""
    
    def __init__(self, private_key_path=None, public_key_path=None):
        self.private_key = None
        self.public_key = None
        
        if private_key_path:
            self.load_private_key(private_key_path)
        if public_key_path:
            self.load_public_key(public_key_path)
    
    def generate_keys(self, private_key_path='keys/private_key.pem', 
                      public_key_path='keys/public_key.pem'):
        """Generate RSA key pair (2048-bit)"""
        os.makedirs('keys', exist_ok=True)
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        public_key = private_key.public_key()
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        self.private_key = private_key
        self.public_key = public_key
        return True
    
    def load_private_key(self, path):
        with open(path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    
    def load_public_key(self, path):
        with open(path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
    
    def encrypt_with_aes(self, data):
        """Encrypt data using AES-256-GCM"""
        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(12)   # 96-bit IV for GCM
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        
        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }
    
    def decrypt_with_aes(self, encrypted_package):
        """Decrypt AES-256-GCM encrypted data"""
        key = base64.b64decode(encrypted_package['key'])
        iv = base64.b64decode(encrypted_package['iv'])
        tag = base64.b64decode(encrypted_package['tag'])
        encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data.decode('utf-8')
    
    def encrypt_with_rsa(self, aes_key):
        """Encrypt AES key with RSA public key"""
        encrypted_key = self.public_key.encrypt(
            aes_key.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode('utf-8')
    
    def decrypt_with_rsa(self, encrypted_key_b64):
        """Decrypt AES key with RSA private key"""
        encrypted_key = base64.b64decode(encrypted_key_b64)
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key.decode('utf-8')
    
    def encrypt_resource(self, resource_data):
        """Complete hybrid encryption: RSA(AES_key) + AES(resource_data)"""
        aes_package = self.encrypt_with_aes(resource_data)
        encrypted_aes_key = self.encrypt_with_rsa(aes_package['key'])
        
        return {
            'encrypted_key': encrypted_aes_key,
            'encrypted_data': aes_package['encrypted_data'],
            'iv': aes_package['iv'],
            'tag': aes_package['tag']
        }
    
    def decrypt_resource(self, encrypted_package):
        """Complete hybrid decryption"""
        aes_key = self.decrypt_with_rsa(encrypted_package['encrypted_key'])
        return self.decrypt_with_aes({
            'key': aes_key,
            'encrypted_data': encrypted_package['encrypted_data'],
            'iv': encrypted_package['iv'],
            'tag': encrypted_package['tag']
        })