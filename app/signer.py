from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def create_sign(content, private_key):
    if isinstance(content, str):
        content = content.encode('utf-8')

    hash_obj = SHA256.new(content)

    signature = pkcs1_15.new(private_key).sign(hash_obj)
    return signature

def verify_sign(content, signature, public_key):
    if isinstance(content, str):
        content = content.encode('utf-8')

    hash_obj = SHA256.new(content)

    public_key = RSA.import_key(public_key)
    
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False