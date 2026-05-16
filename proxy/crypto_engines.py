"""
Crypto Engine Abstraction Layer
Supports both PQC (Kyber) and RSA encryption methods
"""
import base64
from abc import ABC, abstractmethod

try:
    from pqcrypto.kem.kyber512 import (
        generate_keypair as pq_generate_keypair,
        encrypt as pq_encrypt,
        decrypt as pq_decrypt
    )
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    print("[WARNING] PQC crypto not available. Install pqcrypto package.")

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


class CryptoEngine(ABC):
    """Abstract base class for crypto engines"""
    
    @abstractmethod
    def generate_keypair(self):
        """Generate a keypair for this crypto method"""
        pass
    
    @abstractmethod
    def encrypt(self, data, pub_key):
        """Encrypt data using public key"""
        pass
    
    @abstractmethod
    def decrypt(self, data, sec_key):
        """Decrypt data using secret key"""
        pass
    
    @abstractmethod
    def serialize_public_key(self, pub_key):
        """Serialize public key for transmission"""
        pass
    
    @abstractmethod
    def deserialize_public_key(self, serialized_key):
        """Deserialize public key from received data"""
        pass
    
    @abstractmethod
    def get_name(self):
        """Get the name of this crypto method"""
        pass


class PQCKyberEngine(CryptoEngine):
    """Post-Quantum Cryptography using Kyber512"""
    
    def __init__(self):
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC crypto not available. Install pqcrypto package.")
    
    def generate_keypair(self):
        """Generate Kyber512 keypair"""
        public_key, secret_key = pq_generate_keypair()
        return public_key, secret_key
    
    def encrypt(self, data, pub_key):
        """Encrypt data using Kyber public key (KEM + AES hybrid)"""
        if isinstance(data, str):
            data = data.encode()
        
        # Kyber is a KEM, so we encapsulate to get shared secret
        ciphertext, shared_secret = pq_encrypt(pub_key)
        
        # Use shared secret for AES encryption (hybrid encryption)
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from Crypto.Hash import SHA256
        
        # Derive AES key from shared secret
        aes_key = SHA256.new(shared_secret).digest()[:32]
        
        # Encrypt data with AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher_aes.iv
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # Combine: KEM ciphertext + IV + encrypted data
        return ciphertext + iv + encrypted_data
    
    def decrypt(self, encrypted_data, sec_key):
        """Decrypt data using Kyber secret key (KEM + AES hybrid)"""
        # Kyber512 ciphertext is 768 bytes
        kem_ciphertext_size = 768
        kem_ciphertext = encrypted_data[:kem_ciphertext_size]
        iv = encrypted_data[kem_ciphertext_size:kem_ciphertext_size + 16]
        encrypted_payload = encrypted_data[kem_ciphertext_size + 16:]
        
        # Decapsulate to get shared secret
        shared_secret = pq_decrypt(kem_ciphertext, sec_key)
        
        # Derive AES key from shared secret
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        from Crypto.Hash import SHA256
        
        aes_key = SHA256.new(shared_secret).digest()[:32]
        
        # Decrypt data with AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = cipher_aes.decrypt(encrypted_payload)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        
        return unpadded_data
    
    def serialize_public_key(self, pub_key):
        """Serialize Kyber public key to hex string"""
        if isinstance(pub_key, bytes):
            return pub_key.hex()
        return pub_key
    
    def deserialize_public_key(self, serialized_key):
        """Deserialize Kyber public key from hex string"""
        if isinstance(serialized_key, str):
            return bytes.fromhex(serialized_key)
        return serialized_key
    
    def get_name(self):
        return "Kyber"


class RSAEngine(CryptoEngine):
    """RSA encryption engine (classical cryptography)"""
    
    def __init__(self, key_size=2048):
        self.key_size = key_size
    
    def generate_keypair(self):
        """Generate RSA keypair"""
        key = RSA.generate(self.key_size)
        private_key = key.export_key(format='PEM')
        public_key = key.publickey().export_key(format='PEM')
        return public_key, private_key
    
    def encrypt(self, data, pub_key):
        """Encrypt data using RSA public key"""
        if isinstance(data, str):
            data = data.encode()
        
        # RSA can only encrypt small amounts, so we use hybrid encryption
        # Generate a random AES key
        aes_key = get_random_bytes(32)
        
        # Encrypt the data with AES
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher_aes.iv
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # Encrypt the AES key with RSA
        rsa_key = RSA.import_key(pub_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)
        
        # Combine: encrypted_key + iv + encrypted_data
        return encrypted_key + iv + encrypted_data
    
    def decrypt(self, encrypted_data, sec_key):
        """Decrypt data using RSA secret key"""
        # Extract components
        rsa_key = RSA.import_key(sec_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        
        # RSA key size determines the encrypted key length
        key_size_bytes = rsa_key.size_in_bytes()
        encrypted_key = encrypted_data[:key_size_bytes]
        iv = encrypted_data[key_size_bytes:key_size_bytes + 16]
        encrypted_payload = encrypted_data[key_size_bytes + 16:]
        
        # Decrypt AES key
        aes_key = cipher_rsa.decrypt(encrypted_key)
        
        # Decrypt data with AES
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = cipher_aes.decrypt(encrypted_payload)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        
        return unpadded_data
    
    def serialize_public_key(self, pub_key):
        """Serialize RSA public key to PEM string"""
        if isinstance(pub_key, bytes):
            return pub_key.decode('utf-8')
        return pub_key
    
    def deserialize_public_key(self, serialized_key):
        """Deserialize RSA public key from PEM string"""
        if isinstance(serialized_key, bytes):
            return serialized_key.decode('utf-8')
        return serialized_key
    
    def get_name(self):
        return "RSA"


def create_crypto_engine(crypto_name):
    """Factory function to create appropriate crypto engine"""
    crypto_name = crypto_name.lower()
    
    if crypto_name in ["kyber", "pqc", "pqckyber"]:
        if not PQC_AVAILABLE:
            print("[WARNING] PQC not available, falling back to RSA")
            return RSAEngine()
        return PQCKyberEngine()
    elif crypto_name == "rsa":
        return RSAEngine()
    else:
        raise ValueError(f"Unknown crypto method: {crypto_name}")

