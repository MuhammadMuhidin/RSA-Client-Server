from flask import Flask, request, abort
from rsa import CryptographyHandler

app = Flask(__name__)
keygen = 'D91C15E0578DFA3BF67299CDEBC5F194BCCC66EEA1B22078C1'

@app.route('/', methods=['POST'])
def validator():
	data = request.get_json()
	plaintext = data['payload']
	encrypted_byte = bytes.fromhex(plaintext)
	rsa = CryptographyHandler('rsa/RSAPrivateKey.pem')
	decrypted = rsa.decrypt_message(encrypted_byte).decode()

	# Verify signature
	signature = rsa.sign_message(b'8c747032a1aa5af580f48ad2be75366bb517fe8b0990d10931eda23795f3cf26')
	# if Decrypting successful, sign signature. If not, abort.
	if keygen == decrypted:
		return signature.hex()
	else:
		abort(500, 'Decrypted data is invalid! :(')

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8000)
