from stellrent_auth.auth import Oauth2

def test_oauth2():
    auth = Oauth2()
    auth.cache_idp_config()

    @auth.grant_required(
        require_grants=[
            'fine-manager-partner', 
            "fine-manager-admin"
        ]
    )
    def test_route():
        return None
    
    def test_public_route():
        return None
    