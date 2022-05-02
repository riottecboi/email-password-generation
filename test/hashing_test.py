from datamodel import Functions

func = Functions()
######### ENCRYPTED PASSWORD #########
password = str(input('Enter password: '))

argon_encrypted = func.argon_encrypted(password)
print('Argon Hashing: {}'.format(argon_encrypted))

bcrypt_encrypted = func.bcrypt_encrypted(password)
print('Bcrypt Hashing: {}'.format(bcrypt_encrypted))

################################################################
######### CHECK PASSWORD #########
checkpassword = str(input('Enter password check: '))
Argoncheck = func.hashed_check(checkpassword, argon_encrypted, argonHash=True)
if Argoncheck is True:
    print('Argon Hashing is correct')
else:
    print('Wrong')

Bcryptcheck = func.hashed_check(checkpassword, bcrypt_encrypted, bcryptHash=True)

if Bcryptcheck is True:
    print('Bcrypt Hashing is correct')
else:
    print('Wrong')
################################################################