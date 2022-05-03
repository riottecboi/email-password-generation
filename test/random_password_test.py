from datamodel import Functions
import logging
import sys

logger = logging.getLogger('Password Generation')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

func = Functions(logger=logger)

logger.info(f"Alphanumeric random password: {func.generate_alphanumeric_random_password()}\n")
logger.info(f"Hexa-secret random password: {func.generate_hexasecret_random_password()}\n")
logger.info(f"UUID random password: {func.generate_uuid_random_passwords()}\n")