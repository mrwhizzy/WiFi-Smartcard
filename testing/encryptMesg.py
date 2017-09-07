import base64
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


f = open("private.pem", 'r')
key = RSA.importKey(f.read(), passphrase = "12345678")
f.close()

while True:
	inp = raw_input("Input (max. 245 characters): ")
	if (len(inp) <= 245):
	    break   

cipher = PKCS1_v1_5.new(key)
ciphertext = cipher.encrypt(inp)

f = open('ciphertext', 'wb')
f.write(ciphertext)
f.close()