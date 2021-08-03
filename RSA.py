from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

plain_text = b'hello'

#generating key pair
pvt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_key = pvt_key.public_key()
print("\nPrivate key = ", pvt_key)
print("\nPublic key = ", pub_key)

#encrypting plain text
enc_text = pub_key.encrypt(plain_text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
print("\nEncrypted text = ", enc_text)

#decrypting the cipher text
dec_text = pvt_key.decrypt(enc_text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
print("\nDecrypted text = ", dec_text.decode())
