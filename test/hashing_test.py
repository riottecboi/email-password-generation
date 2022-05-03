from datamodel import Functions
import logging
import sys


logger = logging.getLogger('Password Hash')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

func = Functions(logger=logger)

######### ENCRYPTED PASSWORD #########
password = str(input('Enter password: '))

argon_encrypted = func.argon_encrypted(password)
logger.info('Argon Hashing: {}'.format(argon_encrypted))

bcrypt_encrypted = func.bcrypt_encrypted(password)
logger.info('Bcrypt Hashing: {}'.format(bcrypt_encrypted))

################################################################
######### CHECK PASSWORD #########
checkpassword = str(input('Enter password check: '))
Argoncheck = func.hashed_check(checkpassword, argon_encrypted, argonHash=True)
if Argoncheck is True:
    logger.info('Argon Hashing is correct')
else:
    logger.info('Wrong')

Bcryptcheck = func.hashed_check(checkpassword, bcrypt_encrypted, bcryptHash=True)

if Bcryptcheck is True:
    logger.info('Bcrypt Hashing is correct')
else:
    logger.info('Wrong')
################################################################