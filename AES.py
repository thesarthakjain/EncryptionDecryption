from Crypto.Cipher import AES

plain_text = "This is a super secret message ."

key = 'This is the key.'
mode = AES.MODE_CBC
IV = 'This is the IV .'

enc_obj = AES.new(key, mode, IV)
dec_obj = AES.new(key, mode, IV)

#encrypting the plain text
enc_text = enc_obj.encrypt(plain_text)
print("Encrypted text= ", enc_text)

#decrypting the plain text
dec_text = dec_obj.decrypt(enc_text)
print("Decrypted text= ", dec_text.decode())
