from app.models import Comment, Like, Post, User


def test_profile_requires_login(client):
    response = client.get("/profile/testuser")
    assert response.status_code == 302


def test_view_own_profile(authenticated_client, db):
    response = authenticated_client.get("/profile/testuser")
    assert response.status_code == 200
    assert b"testuser" in response.data


def test_view_other_profile(authenticated_client, second_user):
    response = authenticated_client.get(f"/profile/{second_user.username}")
    assert response.status_code == 200
    assert b"otheruser" in response.data


def test_profile_nonexistent_user(authenticated_client, db):
    response = authenticated_client.get("/profile/nobody")
    assert response.status_code == 404


def test_update_account_get(authenticated_client, db):
    response = authenticated_client.get("/update_account")
    assert response.status_code == 200


def test_update_account_post(authenticated_client, db):
    response = authenticated_client.post(
        "/update_account",
        data={"username": "newname", "occupation": "Engineer"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    user = User.query.filter_by(username="newname").first()
    assert user is not None
    assert user.occupation == "Engineer"


def test_delete_account_correct_password(authenticated_client, db):
    response = authenticated_client.post(
        "/delete_account",
        data={"password": "testpassword", "confirm_password": "testpassword"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert User.query.filter_by(username="testuser").first() is None


def test_delete_account_wrong_password(authenticated_client, db):
    response = authenticated_client.post(
        "/delete_account",
        data={"password": "wrongpass", "confirm_password": "wrongpass"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert User.query.filter_by(username="testuser").first() is not None


def test_likes_of_user_page(authenticated_client, db):
    response = authenticated_client.get("/likes/user/testuser")
    assert response.status_code == 200


def test_comments_of_user_page(authenticated_client, db):
    response = authenticated_client.get("/comments/user/testuser")
    assert response.status_code == 200
