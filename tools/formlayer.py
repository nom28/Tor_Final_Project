# from scapy.all import *
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class FormLayer:
    f = None

    def __init__(self):
        self.key = Fernet.generate_key()
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, data):
        self.f = Fernet(self.key)
        encrypted_data = self.f.encrypt(bytes(data, 'utf-8'))

        encrypted_key = self.public_key.encrypt(
            self.key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        product = encrypted_key + encrypted_data

        return product

    def decrypt(self, encrypted_data):
        encrypted_key = encrypted_data[:256]
        decrypted_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_data = encrypted_data[256:]

        return self.f.decrypt(encrypted_data)