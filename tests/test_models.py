from app.models import Chat, Comment, Like, Post, Question, User


def test_user_set_and_check_password(db):
    user = User(username="pwuser")
    user.set_password("secret123")
    db.session.add(user)
    db.session.commit()

    assert user.check_password("secret123") is True
    assert user.check_password("wrong") is False


def test_user_has_liked_post(db):
    user = User(username="liker")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()

    post = Post(title="Likeable", caption="content", user_id=user.id)
    db.session.add(post)
    db.session.commit()

    assert user.has_liked_post(post) is False
    user.like_post(post)
    db.session.commit()
    assert user.has_liked_post(post) is True


def test_user_like_post_idempotent(db):
    user = User(username="idempotent")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()

    post = Post(title="Once", caption="content", user_id=user.id)
    db.session.add(post)
    db.session.commit()

    user.like_post(post)
    user.like_post(post)
    db.session.commit()

    assert Like.query.filter_by(user_id=user.id, post_id=post.id).count() == 1


def test_user_unlike_post(db):
    user = User(username="unliker")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()

    post = Post(title="Unlikeable", caption="content", user_id=user.id)
    db.session.add(post)
    db.session.commit()

    user.like_post(post)
    db.session.commit()
    assert user.has_liked_post(post) is True

    user.unlike_post(post)
    db.session.commit()
    assert user.has_liked_post(post) is False


def test_user_unlike_post_noop(db):
    user = User(username="noop")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()

    post = Post(title="Never liked", caption="content", user_id=user.id)
    db.session.add(post)
    db.session.commit()

    user.unlike_post(post)
    db.session.commit()
    assert user.has_liked_post(post) is False


def test_user_send_chat(db):
    sender = User(username="sender")
    sender.set_password("pass")
    receiver = User(username="receiver")
    receiver.set_password("pass")
    db.session.add_all([sender, receiver])
    db.session.commit()

    sender.send_chat(receiver, "Hello!")
    chat = Chat.query.filter_by(sender_id=sender.id, receiver_id=receiver.id).first()
    assert chat is not None
    assert chat.chat_text == "Hello!"


def test_user_get_chats_with(db):
    user1 = User(username="chatter1")
    user1.set_password("pass")
    user2 = User(username="chatter2")
    user2.set_password("pass")
    db.session.add_all([user1, user2])
    db.session.commit()

    user1.send_chat(user2, "Hi")
    user2.send_chat(user1, "Hey")

    chats = user1.get_chats_with(user2).all()
    assert len(chats) == 2
    assert chats[0].chat_text == "Hi"
    assert chats[1].chat_text == "Hey"


def test_user_repr(db):
    user = User(username="repruser")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()
    assert "repruser" in repr(user)


def test_post_repr(db):
    user = User(username="postauthor")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()

    post = Post(title="My Post", caption="content", user_id=user.id)
    db.session.add(post)
    db.session.commit()
    assert "My Post" in repr(post)


def test_comment_repr(db):
    user = User(username="commenter")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()

    post = Post(title="Post", caption="c", user_id=user.id)
    db.session.add(post)
    db.session.commit()

    comment = Comment(content="Nice!", user_id=user.id, post_id=post.id)
    db.session.add(comment)
    db.session.commit()
    assert "Comment" in repr(comment)


def test_like_repr(db):
    user = User(username="likerep")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()

    post = Post(title="LP", caption="c", user_id=user.id)
    db.session.add(post)
    db.session.commit()

    like = Like(user_id=user.id, post_id=post.id)
    db.session.add(like)
    db.session.commit()
    assert "Like" in repr(like)


def test_question_repr(db):
    q = Question(
        question="What is Flask?",
        option1="A",
        option2="B",
        option3="C",
        option4="D",
        answer="A",
    )
    db.session.add(q)
    db.session.commit()
    assert "What is Flask?" in repr(q)
