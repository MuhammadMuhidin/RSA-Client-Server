from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

class CryptographyHandler:
    '''
    This class provides encryption, decryption, signing and verification
    of messages using RSA asymmetric cryptography.
    '''
    def __init__(self, private_key_file):
        self.private_key = self.load_private_key(private_key_file)

    def load_private_key(self, private_key_file):
        # Load private key from file in PEM format
        with open(private_key_file, 'rb') as f:
            private_key_pem = f.read()
        return serialization.load_pem_private_key(
            private_key_pem,
            password=b'081290a0e436f30e02c420ce62821b43d865e74bddc04a48e345eb1f01c6e2d4'
        )

    def decrypt_message(self, ciphertext):
        # Decrypt message using private key
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def sign_message(self, message_sign):
        # Sign message using private key
        signature = self.private_key.sign(
            message_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
