from app import db
from app import app
from app import User, Post
from werkzeug.security import generate_password_hash
import pytest

# @pytest.fixture
# def app():
#     app = create_app(config_name='testing')
#     with app.app_context():
#         db.create_all()
#         yield app
#         db.session.remove()
#         db.drop_all()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    client = app.test_client()

    with app.app_context():
        # db.create_all()
        # db.session.remove()
        # db.drop_all()
        yield client


def test_search_authenticated(client):
    # Create a test user and login
    user = create_test_user("testuser", "testpassword")
    with client:
        client.post("/login", data={"username": "testuser", "password": "testpassword"})

        # Test the search route with a valid query
        response = client.post("/search", data={"q": "test"}, follow_redirects=True)

        assert response.status_code == 200


def test_search_unauthenticated(client):
    response = client.get("/search", follow_redirects=True)

    assert response.status_code == 200
    assert b"Login" in response.data
    assert b"Please log in to access this page." in response.data


def test_search_no_results(client):
    # Create a test user and login
    user = create_test_user("testnewuser", "testpassword")
    with client:
        client.post(
            "/login", data={"username": "testnewuser", "password": "testpassword"}
        )

        # Test the search route with a query that should return no results
        response = client.post(
            "/search", data={"q": "nonexistent"}, follow_redirects=True
        )

        assert response.status_code == 200


def test_search_invalid_form(client):
    response = client.post("/search", data={"q": "invalidquery"}, follow_redirects=True)

    assert response.status_code == 200


def create_test_user(username, password):
    hashed_password = generate_password_hash(password)
    user = User(username=username, password_hash=hashed_password)
    db.session.add(user)
    db.session.commit()
    return user
