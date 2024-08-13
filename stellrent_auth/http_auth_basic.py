from decouple import config
from flask_httpauth import HTTPBasicAuth
from . import log

basic_auth = HTTPBasicAuth()
__keys = eval(config('STLRNT_AUTH_BASIC_KEYS', cast=str))
log.info('BasicAuth database size: ' + str(len(__keys)))

@basic_auth.verify_password
def verify_password(username, password):
    log.debug('Requested username ' + username)
    for key in __keys:
        if key.get(username) is not None:
            log.debug('Username founded. Validating password')
            if password == key[username]:
                log.debug('Password match. Login granted!!!')
                return True
    return False
