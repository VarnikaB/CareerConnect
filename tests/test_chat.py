from app.models import User, Chat


def test_chat_requires_login(client):
    response = client.get("/chat?username=someone")
    assert response.status_code == 302


def test_chat_page_renders(authenticated_client, second_user):
    response = authenticated_client.get(f"/chat?username={second_user.username}")
    assert response.status_code == 200


def test_send_chat_message(authenticated_client, second_user, db):
    response = authenticated_client.post(
        f"/chat?username={second_user.username}",
        data={"message": "Hello there!"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    chat = Chat.query.filter_by(receiver_id=second_user.id).first()
    assert chat is not None
    assert chat.chat_text == "Hello there!"


def test_chat_with_nonexistent_user(authenticated_client, db):
    response = authenticated_client.post(
        "/chat?username=ghost",
        data={"message": "Are you there?"},
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_all_chats_requires_login(client):
    response = client.get("/all_chats")
    assert response.status_code == 302


def test_all_chats_page(authenticated_client, db):
    response = authenticated_client.get("/all_chats")
    assert response.status_code == 200


def test_all_chats_shows_conversations(authenticated_client, second_user, db):
    authenticated_client.post(
        f"/chat?username={second_user.username}",
        data={"message": "Hey!"},
        follow_redirects=True,
    )

    response = authenticated_client.get("/all_chats")
    assert response.status_code == 200
    assert b"otheruser" in response.data
