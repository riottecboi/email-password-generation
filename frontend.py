from datamodel import Functions, Base
from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFProtect
from flask_env import MetaFlaskEnv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import logging
import sys
import os

class Configuration(metaclass=MetaFlaskEnv):
    MYSQL_STRING = "mysql+mysqlconnector://root:root@localhost/EPG"

SECRET_KEY = os.urandom(32)
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
try:
    app.config.from_pyfile('settings.cfg')
except FileNotFoundError:
    app.config.from_object(Configuration)

csrf = CSRFProtect(app)

logger = logging.getLogger('Email Password Generation')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

func = Functions(logger=logger)


@app.route('/', methods=['GET','POST'])
def index():
    select = 'default'
    if request.method == 'GET':
        return render_template('password_generation.html', select=select, gotValue=False)
    else:
        if request.form.get('opts') == 'alphanumeric':
            passwordString = func.generate_alphanumeric_random_password()
        elif request.form.get('opts') == 'hexa':
            passwordString = func.generate_hexasecret_random_password()
        elif request.form.get('opts') == 'uuid':
            passwordString = func.generate_uuid_random_passwords()
        else:
            return render_template('password_generation.html', select=select, gotValue=False)
        return render_template('password_generation.html', select=request.form.get('opts'), gotValue=True, password=passwordString)
@app.route('/hashed', methods=['GET', 'POST'])
def hashed():
    select = 'default'
    if request.method == 'GET':
        return render_template('encrypted_password.html', select=select, hash=False, type='hashed')
    else:
        if 'type' in request.args and 'encrypted' in request.args:
            hashedtype = request.args.get('type')
            encrypedPasswordstring = request.args.get('encrypted')
            passwordcheck = request.form.get('passwordcheck')
            try:
                if hashedtype == 'argon2':
                    check = func.hashed_check(checkPasswordstring=passwordcheck, encrypedPasswordstring=encrypedPasswordstring, argonHash=True)
                else:
                    check = func.hashed_check(checkPasswordstring=passwordcheck, encrypedPasswordstring=encrypedPasswordstring, bcryptHash=True)
            except Exception as e:
                logger.info(str(e))
                check = False
            if check is True:
                return render_template('redirect.html', message='Correct Password !!!', redirect="/hashed")
            else:
                return render_template('redirect.html', message='Incorrect Password !!!', redirect="/hashed")
                #return render_template('encrypted_password.html', hash=True, pwdEncrypted=encrypedPasswordstring, type='check', check=check)
        else:
            if request.form.get('opts') == 'argon2':
                passwordEncrypted = func.argon_encrypted(request.form.get('passwordstring'))
            else:
                passwordEncrypted = func.bcrypt_encrypted(request.form.get('passwordstring'))

        return render_template('encrypted_password.html', select=request.form.get('opts'), hash=True, pwdEncrypted=passwordEncrypted, hashedType=request.form.get('opts'), type='hashed')

# mysql_string = app.config['MYSQL_STRING']
# engine = create_engine(mysql_string, pool_pre_ping=True, echo=False)
# sessionFactory = sessionmaker(bind=engine)
# Base.metadata.create_all(engine)
if __name__ == '__main__':
    app.run()