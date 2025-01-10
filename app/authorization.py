from passlib.hash import sha256_crypt

def hash_password(password):
    return sha256_crypt.using(rounds=535000).hash(password)

def verify_password(password, hashed):
    return sha256_crypt.verify(password, hashed)

def hash_token(token):
    salt = "salt"
    return sha256_crypt.using(rounds=535000, salt=salt).hash(token)
