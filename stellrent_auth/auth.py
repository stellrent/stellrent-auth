import os
import jwt
import requests
import logging
from functools import wraps
from requests_oauthlib import OAuth2Session
from flask import request

# https://oauthlib.readthedocs.io/en/latest/index.html
from oauthlib.oauth2 import BackendApplicationClient
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from stellrent_response.json_response import Unauthorized, Forbidden

client_token = None
idp_config_cache = None

class Oauth2:

    def __init__(self):
        self.STLRNT_AUTH_IDP_URL = os.environ['STLRNT_AUTH_IDP_URL']
        self.STLRNT_AUTH_API_CLIENT_ID = os.environ['STLRNT_AUTH_API_CLIENT_ID']
        self.STLRNT_AUTH_OID_CONFIG_URL = self.STLRNT_AUTH_IDP_URL + "/application/o/" + os.environ['STLRNT_AUTH_APPLICATION_SLUG'] + "/.well-known/openid-configuration"
        self.STLRNT_AUTH_API_CLIENT_USER = os.environ['STLRNT_AUTH_API_CLIENT_USER']
        self.STLRNT_AUTH_API_CLIENT_PASS = os.environ['STLRNT_AUTH_API_CLIENT_PASS']

    def cache_idp_config(self):
        global client_token
        global idp_config_cache

        logging.getLogger().debug("Creating IDP config cache")

        idp_config_cache = {}

        try:
            # Request IDP for OpenID configurations
            logging.getLogger().debug("OpenID Configuration URL: " + self.STLRNT_AUTH_OID_CONFIG_URL)
            oidc_config = requests.get(self.STLRNT_AUTH_OID_CONFIG_URL).json()
            logging.getLogger().debug(oidc_config)
            signing_algos = oidc_config["id_token_signing_alg_values_supported"]
            idp_config_cache['algos'] = signing_algos
            idp_config_cache['issuer'] = oidc_config["issuer"]
            idp_config_cache['token_endpoint'] = oidc_config["token_endpoint"]

            logging.getLogger().debug("Configuring JWK: " + self.STLRNT_AUTH_OID_CONFIG_URL)
            idp_config_cache['jwks_url'] = oidc_config['jwks_uri']
            idp_config_cache['jwks_client'] = jwt.PyJWKClient(oidc_config["jwks_uri"])
            logging.getLogger().debug(idp_config_cache)
            
            client_token = self.__fetch_token__()
        except Exception as err:
            logging.getLogger().error("Error getting Identity Provider settings")
            logging.getLogger().error(str(err))

    # https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#backend-application-flow     
    def __fetch_token__(self):

        client = BackendApplicationClient(client_id=self.STLRNT_AUTH_API_CLIENT_ID, scope='client-profile')
        oauth = OAuth2Session(client=client)
        api_access_token = oauth.fetch_token(
            token_url=idp_config_cache['token_endpoint'], 
            client_id = self.STLRNT_AUTH_API_CLIENT_ID,
            username = self.STLRNT_AUTH_API_CLIENT_USER,
            password = self.STLRNT_AUTH_API_CLIENT_PASS,
            scope = ["grant"]
        )
        
        if not 'public_key' in idp_config_cache:

            jwt_key = idp_config_cache['jwks_client'].get_signing_key_from_jwt(api_access_token['id_token'])
            idp_config_cache['public_key'] = jwt_key.key
        # token_is_valid = validate_access_token(token, app.get('AK_CLIENT_ID'))
        if self.validate_access_token(access_token=api_access_token):
            return api_access_token
        else:
            raise OAuth2Error(
                description="Invalid token API Access Token",
                status_code = 403
            )

    # https://pyjwt.readthedocs.io/en/latest/usage.html?highlight=secret%20key

    def validate_bearer_token(self, bearer_token):
        try:
            token_data = self.__decode_token__(token=bearer_token)
            return token_data
    
        except jwt.exceptions.PyJWTError as err:
            logging.getLogger().error(str(err))
            return False
        except Exception as ex:
            logging.getLogger().error(str(ex))
            return False

    # https://medium.com/@chaim_sanders/validating-okta-access-tokens-in-python-with-pyjwt-33b5a66f1341
    def validate_access_token(self, access_token):
        try:
            token_data = self.__decode_token__(token=access_token)
            if token_data:
                return True

        except jwt.exceptions.PyJWTError as err:
            logging.getLogger().error(str(err))
            return False
        except Exception as ex:
            logging.getLogger().error(str(ex))
            return False
        
    def user_grants_from_token(self, token):

        try:
            token_data = self.__decode_token__(token)
            if "grant" in token_data:
                print (token_data['grant'])
                return token_data['grant']
            else:
                print (token_data)
                return []

        except jwt.exceptions.PyJWTError as err:
            logging.getLogger().error(str(err))
            return []
        except Exception as ex:
            logging.getLogger().error(str(ex))
            return []
    
    def __decode_token__(self, token):

        if not jwt.algorithms.has_crypto:
            logging.getLogger().error("No crypto support for JWT, please install the cryptography dependency")
            raise OAuth2Error(
                    description="No crypto support for JWT",
                    status_code = 500
            )

        # Client Token
        if type(token) == str:
            token = str.replace(token, 'Bearer ', '')
            jwt_token_data = self.__decode_jwt_token(token=token)
            return jwt_token_data
        
        # Access Token
        access_token_data = self.__decode_jwt_token(token=token['access_token'])
        return access_token_data
    
    def __decode_jwt_token(self, token):
        token_data = jwt.decode(
            jwt=token,
            verify=True,
            issuer=idp_config_cache['issuer'],
            algorithms=idp_config_cache['algos'],
            audience=self.STLRNT_AUTH_API_CLIENT_ID,
            key=idp_config_cache['public_key'],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            }
        )
        return token_data

    # https://github.com/curityio/flask-of-oil
    def grant_required(self, require_grants=[]):
        def inner_decorator(function):
            @wraps(function)
            def wrapper(*args, **kwargs):
                if "Authorization" not in request.headers:
                    return Unauthorized("Access to this resource requires Authorization header parameter").make_response()
                valid_token = self.validate_bearer_token(request.headers['Authorization'])
                
                if valid_token:

                    if require_grants is not None and len(require_grants) > 0:
                        
                        user_grants = self.user_grants_from_token(request.headers['Authorization'])
                        set_require_grants = set(require_grants)
                        set_user_grants = set(user_grants)
                        user_has_grant = set_user_grants.intersection(set_require_grants)
                        if len(user_has_grant) > 0 :
                            return function(*args, **kwargs)
                        else:
                            logging.getLogger().debug("Endpoint Grant required: " + str(require_grants))
                            logging.getLogger().debug("User Grant: " + str(user_grants))
                            return Forbidden('You do not have permission to access this resource').make_response()

                    return function(*args, **kwargs)
                return Unauthorized("Invalid Token").make_response()
            wrapper.__name__ = function.__name__
            return wrapper
        return inner_decorator