from tests.app.app_basic_auth import create_app
from decouple import config
import pytest

@pytest.fixture()
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
    })
    yield app

@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()

def test_public_route(client):
    response = client.get("/public")
    assert response.status_code == 200

def test_private_route_unauthorized(client):
    response = client.get("/private")
    assert response.status_code == 401
    response = client.get("/private", auth=('invalidU', 'invalidP'))
    assert response.status_code == 401

def test_private_route_success(client):
    keys = eval(config('STLRNT_AUTH_BASIC_KEYS'))
    for login in keys:
        print("Using BASIC AUTH Key: " + str(login))
        for user, password in login.items():
            print("Testing Login: " + user)
            response = client.get("/private", auth=(user, password))
            assert response.status_code == 200


