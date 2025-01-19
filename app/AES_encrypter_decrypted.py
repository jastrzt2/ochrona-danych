import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16

def create_aes_key(password, salt=None):
    if salt is None:
        salt = os.urandom(BLOCK_SIZE)
    key = PBKDF2(password.encode(), salt=salt, dkLen=BLOCK_SIZE, count = 500000)
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
