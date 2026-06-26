import pytest

from app import create_app
from app.extensions import db as _db
from app.models import User, Post


@pytest.fixture(scope="session")
def app():
    app = create_app("testing")
    return app


@pytest.fixture(scope="function")
def db(app):
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture(scope="function")
def client(app, db):
    return app.test_client()


@pytest.fixture
def authenticated_client(client, db):
    user = User(username="testuser")
    user.set_password("testpassword")
    db.session.add(user)
    db.session.commit()
    client.post(
        "/login",
        data={"username": "testuser", "password": "testpassword"},
        follow_redirects=True,
    )
    return client


@pytest.fixture
def second_user(db):
    user = User(username="otheruser")
    user.set_password("otherpassword")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def sample_post(authenticated_client, db):
    user = User.query.filter_by(username="testuser").first()
    post = Post(title="Sample Post", caption="Sample caption", user_id=user.id)
    db.session.add(post)
    db.session.commit()
    return post
