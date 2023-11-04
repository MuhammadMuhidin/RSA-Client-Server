from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import requests
import json

class APIClient:
    '''
    This class represents an API client,
    concept of api client is used to encrypt and send the messages to api validator.
    '''
    def __init__(self, public_key_file):
        self.public_key = self.load_public_key(public_key_file)

    def load_public_key(self, public_key_file):
        # Load public key from file in PEM format
        with open(public_key_file, 'rb') as f:
            public_key_pem = f.read()
        return serialization.load_pem_public_key(public_key_pem)

    def encrypt_message(self, plaintext):
        # Encrypt message using public key
        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext    

    def verify_signature(self, signature, message_sign):
        # Verify signature using public key
        try:
            self.public_key.verify(
                signature,
                message_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print ('Successfully validates data and signature trusted :)')
        except:
            print(f'Signature verification failed!')    

    def encrypt_and_verify(self, uri, plaintext, message_sign):
        # Assuming CryptographyHandler handles encryption and decryption
        ciphertext = self.encrypt_message(plaintext).hex()
        # Prepare the payload in a dictionary
        payload = {'payload': ciphertext}
        # Convert the payload dictionary to a JSON string
        json_payload = json.dumps(payload)
        # Set the Content-Type header to application/json
        headers = {'Content-Type': 'application/json'}
        # Make a POST request to the API
        response = requests.post(uri, data=json_payload, headers=headers)
        # Verify signature
        if response.status_code==200:
            sign_byte = bytes.fromhex(response.text)
            return self.verify_signature(sign_byte, message_sign)
        else:
            print(response.text)

def main():
    # Usage
    uri = 'http://muhammadmuhidin.pythonanywhere.com/validate'
    public_key_file = 'RSAPublicKey.pem'
    plaintext = b'D91C15E0578DFA3BF67299CDEBC5F194BCCC66EEA1B22078C1'
    message_sign = b'8c747032a1aa5af580f48ad2be75366bb517fe8b0990d10931eda23795f3cf26'

    # Create an instance of the APIClient
    api_client = APIClient(public_key_file)
    # Encrypt and veryify the signature
    api_client.encrypt_and_verify(uri, plaintext, message_sign)
if __name__== "__main__":
    main ()
