import random

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

        with open('keys\\private_key'+sufix+'.pem', 'wb') as f:
            f.write(pem)

        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('keys\\public_key'+sufix+'.pem', 'wb') as f:
            f.write(pem)

    def change_keys(self, sufix, self_key):
        if self_key:
            with open('keys\\private_key'+sufix+'.pem', 'rb') as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            with open('keys\\public_key'+sufix+'.pem', 'rb') as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )

    def encrypt(self, data, session_id=b"", ip="127.0.0.1", port="55556"):
        # could be possible to move data in heading to the payload.
        self.f = Fernet(self.key)
        encrypted_data = self.f.encrypt(data)

        hex_ip = self.ip_to_hex(ip).encode('utf-8')
        heading = self.key+hex_ip+port.encode('utf-8')+session_id

        encrypted_heading = self.public_key.encrypt(
            heading,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        product = encrypted_heading + encrypted_data

        return product

    def b_encrypt(self, data, session_id=b""):
        # could be possible to move data in heading to the payload.
        self.f = Fernet(self.key)
        encrypted_data = self.f.encrypt(data)

        heading = self.key+session_id

        encrypted_heading = self.public_key.encrypt(
            heading,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        product = encrypted_heading + encrypted_data

        return product

    def decrypt(self, encrypted_data):
        encrypted_heading = encrypted_data[:256]
        decrypted_heading = self.private_key.decrypt(
            encrypted_heading,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_key = decrypted_heading[:44]
        decrypted_heading = decrypted_heading[44:]

        decrypted_ip = self.hex_to_ip(decrypted_heading[:8])
        decrypted_heading = decrypted_heading[8:]

        decrypted_port = int(decrypted_heading[:5])
        decrypted_heading = decrypted_heading[5:]

        decrypted_session_id = decrypted_heading

        encrypted_data = encrypted_data[256:]
        f = Fernet(decrypted_key)
        return [decrypted_ip, decrypted_port, decrypted_session_id, f.decrypt(encrypted_data)]

    def b_decrypt(self, encrypted_data):
        encrypted_heading = encrypted_data[:256]
        decrypted_heading = self.private_key.decrypt(
            encrypted_heading,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_key = decrypted_heading[:44]
        decrypted_heading = decrypted_heading[44:]

        decrypted_session_id = decrypted_heading

        encrypted_data = encrypted_data[256:]
        f = Fernet(decrypted_key)
        print(decrypted_key)
        print(encrypted_data)
        return [decrypted_session_id, f.decrypt(encrypted_data)]

    @staticmethod
    def ip_to_hex(ip):
        ip = ip.split('.')
        hex_ip = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, ip))
        return hex_ip

    @staticmethod
    def hex_to_ip(hex_ip):
        octets = [hex_ip[i:i + 2] for i in range(0, len(hex_ip), 2)]
        ip = [int(i, 16) for i in octets]
        ip = '.'.join(str(i) for i in ip)
        return ip


if __name__ == '__main__':
    l = Layer()
    session_id = random.randbytes(20)

    x = l.encrypt(b"hey sir", session_id)
    # x = l.encrypt(b":)", "255.255.255.255", "00080")
    result = l.decrypt(x)
    print(result)