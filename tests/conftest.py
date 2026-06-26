import pytest

from app import create_app
from app.extensions import db as _db
from app.models import Post, User


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


@pytest.fixture
def teacher_client(app, db):
    user = User(username="teacheruser", role="teacher")
    user.set_password("teacherpass")
    db.session.add(user)
    db.session.commit()
    client = app.test_client()
    client.post(
        "/login",
        data={"username": "teacheruser", "password": "teacherpass"},
        follow_redirects=True,
    )
    return client


@pytest.fixture
def senior_student_client(app, db):
    user = User(username="senioruser", role="senior_student")
    user.set_password("seniorpass")
    db.session.add(user)
    db.session.commit()
    client = app.test_client()
    client.post(
        "/login",
        data={"username": "senioruser", "password": "seniorpass"},
        follow_redirects=True,
    )
    return client


@pytest.fixture
def admin_client(app, db):
    user = User(username="ADMIN_USER", role="teacher")
    user.set_password("adminpass")
    db.session.add(user)
    db.session.commit()
    client = app.test_client()
    client.post(
        "/login",
        data={"username": "ADMIN_USER", "password": "adminpass"},
        follow_redirects=True,
    )
    return client
