import argon2
import base64
import bcrypt
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, autoincrement=True, index=True)
    username = Column(String(128), primary_key=True)
    password = Column(String(255))
    email = Column(String(128), unique=True)

class Functions:
    send_email_user = ''
    send_email_pass = ''
    receive_email_user = ''
    argon2_time_cost = 3
    argon2_memory_cost = 64*1024
    argon2_parallelism = 1
    argon2_hash_len = 32
    argon2_salt_len = 16


    def __init__(self, **kwargs):
        if "send_email_user" in kwargs:
            self.send_email_user = kwargs['send_email_user']
        if "send_email_pass" in kwargs:
            self.send_email_pass = kwargs['send_email_pass']
        if "receive_email_user" in kwargs:
            self.receive_email_user = kwargs['receive_email_user']
        if "argon2_time_cost" in kwargs:
            self.argon2_time_cost = kwargs['argon2_time_cost']
        if "argon2_memory_cost" in kwargs:
            self.argon2_memory_cost = kwargs['argon2_memory_cost']
        if "argon2_parallelism" in kwargs:
            self.argon2_parallelism = kwargs['argon2_parallelism']
        if "argon2_hash_len" in kwargs:
            self.argon2_hash_len = kwargs['argon2_hash_len']
        if "argon2_salt_len" in kwargs:
            self.argon2_salt_len = kwargs['argon2_salt_len']

    hasher = argon2.PasswordHasher(
        time_cost=argon2_time_cost,  # number of iterations
        memory_cost=argon2_memory_cost,  # kb unit
        parallelism=argon2_parallelism,  # how many parallel threads to use
        hash_len=argon2_hash_len,  # the size of the derived key
        salt_len=argon2_salt_len  # the size of the random generated salt in bytes
    )

    ######### ENCODED/DECODED PASSWORD (NOT SECURED !!!) #########

    def base64_encoded(self, password_string):
        encoded = password_string.encode('utf-8')
        encrypted = base64.b64encode(encoded)
        encrypedPasswordstring = encrypted.decode('utf-8')
        return encrypedPasswordstring

    def base64_decoded(self, encrypedPasswordstring):
        decoded = base64.b64decode(encrypedPasswordstring.encode('utf-8'))
        decodedPasswordstring = decoded.decode('utf-8')
        return decodedPasswordstring

    ################################################################

    ######### ENCRYPTED PASSWORD #########
    def argon_encrypted(self, password_string):
        encrypedPasswordstring = self.hasher.hash(password_string)
        return encrypedPasswordstring

    def bcrypt_encrypted(self, password_string):
        encoded = password_string.encode('utf-8')
        encrypted = bcrypt.hashpw(encoded, bcrypt.gensalt())  # default salt value is 12
        encrypedPasswordstring = encrypted.decode('utf-8')
        return encrypedPasswordstring

    ######### CHECK PASSWORD #########

    def hashed_check(self,checkPasswordstring, encrypedPasswordstring, bcryptHash=False, argonHash=False):
        try:
            if bcryptHash is False and argonHash is False:
                raise Exception('Need to select one option (Bcrypt/Argon Hash)')
            if bcryptHash is True and argonHash is True:
                raise Exception('Select one option (Bcrypt/Argon Hash) only')
            if bcryptHash is True:
               check = bcrypt.checkpw(checkPasswordstring.encode('utf-8'),encrypedPasswordstring.encode('utf-8'))
               return check
            if argonHash is True:
               check = self.hasher.verify(encrypedPasswordstring, checkPasswordstring)
               return check
        except Exception as e:
            print(f"Exception occurred: {str(e)}")

    ################################################################