import base64
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


f = open("private.pem", 'r')
key = RSA.importKey(f.read(), passphrase = "12345678")
f.close()

message = "Foo, bar baz."

cipher = PKCS1_v1_5.new(key)
ciphertext = cipher.encrypt(message)

f = open('ciphertext', 'wb')
f.write(ciphertext)
f.close()