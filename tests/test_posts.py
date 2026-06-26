from app.models import Post, User


def test_create_post(authenticated_client, db):
    response = authenticated_client.post(
        "/post/create_post",
        data={"title": "Test Post", "caption": "Test caption", "is_anonymous": False},
        follow_redirects=True,
    )
    assert response.status_code == 200
    post = Post.query.filter_by(title="Test Post").first()
    assert post is not None
    assert post.caption == "Test caption"


def test_feed_requires_login(client):
    response = client.get("/feed")
    assert response.status_code == 302


def test_feed_with_auth(authenticated_client):
    response = authenticated_client.get("/feed")
    assert response.status_code == 200


def test_post_repr(db):
    user = User(username="repruser")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()

    post = Post(title="Repr Test", caption="content", user_id=user.id)
    db.session.add(post)
    db.session.commit()

    assert "Repr Test" in repr(post)
