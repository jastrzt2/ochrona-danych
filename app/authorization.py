from passlib.hash import sha256_crypt
import os
import base64

token_salt = os.urandom(8).hex()
#token_salt jest inna za każdym uruchomieniem instacji aplikacji aplikacji, ale ustalona dla danej instacji aplikacji

def hash_password(password):
    return sha256_crypt.using(rounds=535000).hash(password)

def verify_password(password, hashed):
    return sha256_crypt.verify(password, hashed)

def hash_token(token):
    #mniej rund, bo czasowe tokeny cięzko zbrutforcować
    return sha256_crypt.using(rounds=1000, salt=token_salt).hash(token) 

