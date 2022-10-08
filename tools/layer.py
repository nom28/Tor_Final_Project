from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


class Layer:
    f = None

    def __init__(self):
        self.key = Fernet.generate_key()
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def store_keys(self, sufix):
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open('private_key'+sufix+'.pem', 'wb') as f:
            f.write(pem)

        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('public_key'+sufix+'.pem', 'wb') as f:
            f.write(pem)

    def change_keys(self, sufix):
        with open('private_key'+sufix+'.pem', 'rb') as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        with open('public_key'+sufix+'.pem', 'rb') as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

    def encrypt(self, data):
        self.f = Fernet(self.key)
        encrypted_data = self.f.encrypt(data)

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
        f = Fernet(decrypted_key)
        return f.decrypt(encrypted_data)
