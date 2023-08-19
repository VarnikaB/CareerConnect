from app import  db
from app import User
from app import app
from flask_login import current_user
from werkzeug.security import generate_password_hash
import pytest




@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()

    with app.app_context():
        # db.create_all()
        # db.session.remove()
        # db.drop_all()
        yield client

def create_test_user(username, password):
    hashed_password = generate_password_hash(password)
    user = User(username=username, password_hash=hashed_password)
    db.session.add(user)
    db.session.commit()
    return user

def test_successful_login(client):
    user = create_test_user('testuser', 'testpassword')

    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    }, follow_redirects=True)

    assert response.status_code == 200

def test_unsuccessful_login(client):
    response = client.post('/login', data={
        'username': 'nonexistentuser',
        'password': 'invalidpassword'
    }, follow_redirects=True)

    assert response.status_code == 200

def test_redirect_after_unsuccessful_login(client):
    response = client.post('/login', data={
        'username': 'nonexistentuser',
        'password': 'invalidpassword',
        'next': '/protected_page'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Login' in response.data  # Assuming the login page is still shown
