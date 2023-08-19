from app import User, RegistrationForm, db
from app import app
from werkzeug.security import generate_password_hash
import pytest


@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()

    with app.app_context():
        yield client

def test_register_valid(client):
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'testpassword',
        'confirm_password': 'testpassword'
    }, follow_redirects=True)

    assert response.status_code == 200

def test_register_existing_user(client):
    existing_user = User(username='testuser', password_hash=generate_password_hash('testpassword'))
    db.session.add(existing_user)
    db.session.commit()

    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'testpassword',
        'confirm_password': 'testpassword'
    }, follow_redirects=True)

    assert response.status_code == 200

def test_register_empty_form(client):
    response = client.post('/register', data={}, follow_redirects=True)

    assert response.status_code == 200
    assert b'This field is required.' in response.data
