from app.models import Comment, Post, User


def test_404_page(authenticated_client):
    response = authenticated_client.get("/nonexistent-page-xyz")
    assert response.status_code == 404


def test_403_page(authenticated_client, sample_post, second_user, db):
    comment = Comment(content="Forbidden", user_id=second_user.id, post_id=sample_post.id)
    db.session.add(comment)
    db.session.commit()

    response = authenticated_client.get(f"/post/{sample_post.id}/comment/{comment.id}/edit")
    assert response.status_code == 403
