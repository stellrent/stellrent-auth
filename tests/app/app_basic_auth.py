from flask import Flask
from stellrent_response.json_response import DataResponse, NoDataResponse, Forbidden
from stellrent_auth.http_auth_basic import basic_auth

def create_app():
    app = Flask("Flask Application configured for tests")
    
    @app.route("/public")
    def public_endpoint():
        response_body = {
            "status": "ok"
        }
        return DataResponse(data=response_body).make_response()

    @app.route("/private")
    @basic_auth.login_required
    def basic_auth_endpoint():
        response_body = {
            "status": "ok"
        }
        return DataResponse(data=response_body).make_response()
    
    return app