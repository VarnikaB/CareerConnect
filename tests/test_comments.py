from app.models import Comment, Post, User


def test_comment_requires_login(client, db):
    response = client.get("/post/1/comment")
    assert response.status_code == 302


def test_view_comments_page(authenticated_client, sample_post):
    response = authenticated_client.get(f"/post/{sample_post.id}/comment")
    assert response.status_code == 200


def test_add_comment(authenticated_client, sample_post, db):
    response = authenticated_client.post(
        f"/post/{sample_post.id}/comment",
        data={"content": "Great post!"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    comment = Comment.query.filter_by(post_id=sample_post.id).first()
    assert comment is not None
    assert comment.content == "Great post!"


def test_add_comment_to_nonexistent_post(authenticated_client, db):
    response = authenticated_client.post(
        "/post/9999/comment",
        data={"content": "Hello"},
        follow_redirects=True,
    )
    assert response.status_code == 404


def test_edit_own_comment(authenticated_client, sample_post, db):
    user = User.query.filter_by(username="testuser").first()
    comment = Comment(content="Original", user_id=user.id, post_id=sample_post.id)
    db.session.add(comment)
    db.session.commit()

    response = authenticated_client.post(
        f"/post/{sample_post.id}/comment/{comment.id}/edit",
        data={"content": "Edited"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    db.session.refresh(comment)
    assert comment.content == "Edited"


def test_edit_comment_forbidden(authenticated_client, sample_post, second_user, db):
    comment = Comment(content="Not yours", user_id=second_user.id, post_id=sample_post.id)
    db.session.add(comment)
    db.session.commit()

    response = authenticated_client.get(f"/post/{sample_post.id}/comment/{comment.id}/edit")
    assert response.status_code == 403


def test_delete_own_comment(authenticated_client, sample_post, db):
    user = User.query.filter_by(username="testuser").first()
    comment = Comment(content="Delete me", user_id=user.id, post_id=sample_post.id)
    db.session.add(comment)
    db.session.commit()
    comment_id = comment.id

    response = authenticated_client.post(
        f"/post/{sample_post.id}/comment/{comment_id}/delete",
        data={},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert Comment.query.get(comment_id) is None


def test_delete_comment_forbidden(authenticated_client, sample_post, second_user, db):
    comment = Comment(content="Protected", user_id=second_user.id, post_id=sample_post.id)
    db.session.add(comment)
    db.session.commit()

    response = authenticated_client.get(f"/post/{sample_post.id}/comment/{comment.id}/delete")
    assert response.status_code == 403


def test_delete_comment_by_admin(app, second_user, db):
    post = Post(title="Admin Test Post", caption="content", user_id=second_user.id)
    db.session.add(post)
    db.session.commit()

    comment = Comment(content="Admin delete", user_id=second_user.id, post_id=post.id)
    db.session.add(comment)
    db.session.commit()

    admin = User(username="ADMIN_USER")
    admin.set_password("adminpass")
    db.session.add(admin)
    db.session.commit()

    admin_client = app.test_client()
    admin_client.post(
        "/login",
        data={"username": "ADMIN_USER", "password": "adminpass"},
        follow_redirects=True,
    )

    response = admin_client.post(
        f"/post/{post.id}/comment/{comment.id}/delete",
        data={},
        follow_redirects=True,
    )
    assert response.status_code == 200
