from app.models import User


def test_register_new_user(client, db):
    response = client.post(
        "/register",
        data={
            "username": "newuser",
            "password": "password123",
            "confirm_password": "password123",
            "role": "student",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    user = User.query.filter_by(username="newuser").first()
    assert user is not None


def test_register_existing_user(client, db):
    user = User(username="existing")
    user.set_password("password")
    db.session.add(user)
    db.session.commit()

    response = client.post(
        "/register",
        data={
            "username": "existing",
            "password": "password123",
            "confirm_password": "password123",
            "role": "student",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"already" in response.data.lower()


def test_login_valid_user(client, db):
    user = User(username="loginuser")
    user.set_password("mypassword")
    db.session.add(user)
    db.session.commit()

    response = client.post(
        "/login",
        data={"username": "loginuser", "password": "mypassword"},
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_login_invalid_password(client, db):
    user = User(username="badpass")
    user.set_password("correctpass")
    db.session.add(user)
    db.session.commit()

    response = client.post(
        "/login",
        data={"username": "badpass", "password": "wrongpass"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Invalid" in response.data


def test_logout(authenticated_client):
    response = authenticated_client.get("/logout", follow_redirects=True)
    assert response.status_code == 200
