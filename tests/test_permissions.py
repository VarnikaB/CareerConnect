from app.models import User, Post, Comment


def test_student_cannot_add_question(authenticated_client):
    response = authenticated_client.get("/question/add_question")
    assert response.status_code == 403


def test_senior_student_can_add_question(senior_student_client):
    response = senior_student_client.get("/question/add_question")
    assert response.status_code == 200


def test_teacher_can_add_question(teacher_client):
    response = teacher_client.get("/question/add_question")
    assert response.status_code == 200


def test_admin_can_add_question(admin_client):
    response = admin_client.get("/question/add_question")
    assert response.status_code == 200


def test_student_cannot_access_change_role(authenticated_client, second_user):
    response = authenticated_client.get(f"/profile/{second_user.username}/change_role")
    assert response.status_code == 403


def test_teacher_can_promote_student_to_senior(teacher_client, db):
    student = User(username="promoteuser", role="student")
    student.set_password("pass")
    db.session.add(student)
    db.session.commit()

    response = teacher_client.post(
        "/profile/promoteuser/change_role",
        data={"role": "senior_student"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    db.session.refresh(student)
    assert student.role == "senior_student"


def test_teacher_cannot_set_teacher_role(teacher_client, db):
    student = User(username="noteacher", role="student")
    student.set_password("pass")
    db.session.add(student)
    db.session.commit()

    response = teacher_client.post(
        "/profile/noteacher/change_role",
        data={"role": "teacher"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    db.session.refresh(student)
    assert student.role == "student"


def test_admin_can_set_any_role(admin_client, db):
    student = User(username="anyrole", role="student")
    student.set_password("pass")
    db.session.add(student)
    db.session.commit()

    response = admin_client.post(
        "/profile/anyrole/change_role",
        data={"role": "teacher"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    db.session.refresh(student)
    assert student.role == "teacher"


def test_senior_student_can_delete_comment_on_own_post(senior_student_client, db):
    senior = User.query.filter_by(username="senioruser").first()
    post = Post(title="Senior Post", caption="content", user_id=senior.id)
    db.session.add(post)
    db.session.commit()

    other = User(username="commentor", role="student")
    other.set_password("pass")
    db.session.add(other)
    db.session.commit()

    comment = Comment(content="A comment", user_id=other.id, post_id=post.id)
    db.session.add(comment)
    db.session.commit()

    response = senior_student_client.post(
        f"/post/{post.id}/comment/{comment.id}/delete",
        data={},
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_student_cannot_delete_others_comment_on_own_post(authenticated_client, db):
    user = User.query.filter_by(username="testuser").first()
    post = Post(title="Student Post", caption="content", user_id=user.id)
    db.session.add(post)
    db.session.commit()

    other = User(username="othercommentor", role="student")
    other.set_password("pass")
    db.session.add(other)
    db.session.commit()

    comment = Comment(content="Not yours", user_id=other.id, post_id=post.id)
    db.session.add(comment)
    db.session.commit()

    response = authenticated_client.get(
        f"/post/{post.id}/comment/{comment.id}/delete"
    )
    assert response.status_code == 403


def test_register_with_role(client, db):
    response = client.post(
        "/register",
        data={
            "username": "newteacher",
            "password": "password123",
            "confirm_password": "password123",
            "role": "teacher",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    user = User.query.filter_by(username="newteacher").first()
    assert user is not None
    assert user.role == "teacher"


def test_register_defaults_to_student(client, db):
    response = client.post(
        "/register",
        data={
            "username": "defaultuser",
            "password": "password123",
            "confirm_password": "password123",
            "role": "student",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    user = User.query.filter_by(username="defaultuser").first()
    assert user.role == "student"
