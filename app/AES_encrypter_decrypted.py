import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16
PEPPER = "b3a82ad64e8e26fcfe0c6a7d3b958b35fe525ab42074fbdb9d09b6c4d2865c7a" 

def create_aes_key(password, salt=None):
    if salt is None:
        salt = os.urandom(BLOCK_SIZE)
    password_with_pepper = password + PEPPER
    key = PBKDF2(password_with_pepper.encode(), salt=salt, dkLen=BLOCK_SIZE, count = 500000)
    return key, salt

def rsa_aes_encrypt(data, password):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    key, salt = create_aes_key(password)
    
    nonce = os.urandom(BLOCK_SIZE)

    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes.encrypt_and_digest(data)
    
    encrypted = nonce + salt + tag + ciphertext

    return base64.b64encode(encrypted).decode('utf-8')

def rsa_aes_decrypt(encrypted_data, password):
    encrypted_bytes = base64.b64decode(encrypted_data)
    
    nonce = encrypted_bytes[:BLOCK_SIZE]
    salt = encrypted_bytes[BLOCK_SIZE:BLOCK_SIZE*2]
    tag = encrypted_bytes[BLOCK_SIZE*2:BLOCK_SIZE*3]
    ciphertext = encrypted_bytes[BLOCK_SIZE*3:]
    
    key, _ = create_aes_key(password, salt)

    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    data = aes.decrypt_and_verify(ciphertext, tag)

    return data.decode('utf-8')
