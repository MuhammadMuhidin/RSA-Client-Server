from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class RSAKeyGenerator:
    '''
    This class generates and saves RSA keys in PEM format.
    '''
    def __init__(self, private_key_file='RSAPrivateKey.pem', public_key_file='RSAPublicKey.pem', password=b'081290a0e436f30e02c420ce62821b43d865e74bddc04a48e345eb1f01c6e2d4'):
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file
        self.password = password

    def generate_keys(self):
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        # Generate public key
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_private_key(self, private_key):
        # Serialize private key
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.password)
        )
        return private_key_pem

    def serialize_public_key(self, public_key):
        # Serialize public key
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_pem

    def save_to_file(self, filename, data):
        # Save data to file
        with open(filename, 'wb') as f:
            f.write(data)

    def generate_and_save_keys(self):
        # Generate and save keys
        private_key, public_key = self.generate_keys()

        private_key_pem = self.serialize_private_key(private_key)
        self.save_to_file(self.private_key_file, private_key_pem)
        print(f'{self.private_key_file} successfully created')

        public_key_pem = self.serialize_public_key(public_key)
        self.save_to_file(self.public_key_file, public_key_pem)
        print(f'{self.public_key_file} successfully created')

if __name__ == "__main__":
    key_generator = RSAKeyGenerator()
    key_generator.generate_and_save_keys()
