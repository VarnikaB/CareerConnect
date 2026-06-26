from datetime import datetime
from zoneinfo import ZoneInfo

from flask_login import UserMixin
from sqlalchemy import or_, and_
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db, login_manager

IST = ZoneInfo("Asia/Kolkata")


def get_current_time():
    return datetime.now(IST)


class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    chat_text = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=get_current_time)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])

    def get_all_chats(self, current_user_send, user):
        return Chat.query.filter(
            or_(
                and_(Chat.sender == current_user_send, Chat.receiver == user),
                and_(Chat.sender == user, Chat.receiver == current_user_send),
            )
        ).order_by(Chat.timestamp)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_image = db.Column(db.String(128), default="def.jpg")
    occupation = db.Column(db.String(80), default="Student")

    posts = db.relationship("Post", back_populates="user", lazy="subquery")
    comments = db.relationship("Comment", backref="user", lazy="dynamic")
    likes = db.relationship("Like", backref="user", lazy="dynamic")

    chats_sent = db.relationship(
        "Chat",
        foreign_keys=[Chat.sender_id],
        lazy="dynamic",
        overlaps="sender",
    )
    chats_received = db.relationship(
        "Chat",
        foreign_keys=[Chat.receiver_id],
        lazy="dynamic",
        overlaps="receiver",
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_liked_post(self, post):
        return (
            Like.query.filter(Like.user_id == self.id, Like.post_id == post.id).count()
            > 0
        )

    def like_post(self, post):
        if not self.has_liked_post(post):
            each_like = Like(user_id=self.id, post_id=post.id)
            db.session.add(each_like)

    def unlike_post(self, post):
        if self.has_liked_post(post):
            Like.query.filter_by(user_id=self.id, post_id=post.id).delete()

    def send_chat(self, receiver, chat_text):
        new_chat = Chat(sender=self, receiver=receiver, chat_text=chat_text)
        db.session.add(new_chat)
        db.session.commit()

    def get_chats_with(self, other_user):
        return Chat.query.filter(
            or_(
                and_(Chat.sender == self, Chat.receiver == other_user),
                and_(Chat.sender == other_user, Chat.receiver == self),
            )
        ).order_by(Chat.timestamp)

    def __repr__(self):
        return f"User('{self.id}', '{self.username}', '{self.profile_image}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=get_current_time)
    last_updated = db.Column(
        db.DateTime, default=get_current_time, onupdate=get_current_time
    )
    is_anonymous = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20))
    caption = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(128))

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", back_populates="posts", lazy=True)

    likes = db.relationship("Like", backref="posts", lazy="dynamic")
    comments = db.relationship("Comment", backref="posts", lazy="dynamic")

    def __repr__(self):
        return f"Post('{self.id}', '{self.title}', '{self.timestamp}')"


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=get_current_time)
    option1 = db.Column(db.String(100))
    option2 = db.Column(db.String(100))
    option3 = db.Column(db.String(100))
    option4 = db.Column(db.String(100))
    answer = db.Column(db.String(100))

    def __repr__(self):
        return f"Question('{self.id}', '{self.question}', '{self.timestamp}')"


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(
        db.Integer, db.ForeignKey("post.id", ondelete="CASCADE"), nullable=False
    )
    timestamp = db.Column(db.DateTime, default=get_current_time)

    def __repr__(self):
        return f"Like('{self.id}')"


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=get_current_time)
    last_edited = db.Column(
        db.DateTime, default=get_current_time, onupdate=get_current_time
    )
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(
        db.Integer, db.ForeignKey("post.id", ondelete="CASCADE"), nullable=False
    )

    def __repr__(self):
        return f"Comment('{self.id}', '{self.timestamp}')"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
