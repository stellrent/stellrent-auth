from stellrent_auth.auth import Oauth2

def test_oauth2():
    auth = Oauth2()
    auth.cache_idp_config()
