from app.models import Post, User


def test_search_requires_login(client):
    response = client.get("/search")
    assert response.status_code == 302


def test_search_no_results(authenticated_client, db):
    response = authenticated_client.get("/search?search_string=nonexistent")
    assert response.status_code == 200
    assert b"No posts found" in response.data


def test_search_with_results(authenticated_client, db):
    user = User.query.filter_by(username="testuser").first()
    post = Post(title="Flask Tutorial", caption="Learn Flask", user_id=user.id)
    db.session.add(post)
    db.session.commit()

    response = authenticated_client.get("/search?search_string=Flask")
    assert response.status_code == 200
    assert b"Flask Tutorial" in response.data
