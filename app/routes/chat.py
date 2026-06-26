from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import and_, or_

from app.extensions import db
from app.forms import ChatForm
from app.models import Chat, User

chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/chat", methods=["POST", "GET"])
@login_required
def chat():
    username = request.args.get("username")
    user = User.query.filter_by(username=username).first()
    chatform = ChatForm()
    current_user_send = User.query.filter_by(username=current_user.username).first()

    all_chats = Chat.query.filter(
        or_(
            and_(Chat.sender == current_user_send, Chat.receiver == user),
            and_(Chat.sender == user, Chat.receiver == current_user_send),
        )
    ).order_by(Chat.timestamp)

    if chatform.validate_on_submit():
        if user is None:
            flash("User does not exist", "danger")
            return redirect(url_for("main.feed"))

        message = chatform.message.data
        current_user_send.send_chat(user, message)

        from app.metrics import CHATS_SENT

        CHATS_SENT.inc()
        all_chats = Chat.query.filter(
            or_(
                and_(Chat.sender == current_user_send, Chat.receiver == user),
                and_(Chat.sender == user, Chat.receiver == current_user_send),
            )
        ).order_by(Chat.timestamp)

    return render_template(
        "chat.html",
        form=chatform,
        user=user,
        all_chats=all_chats,
        current_user=current_user_send,
    )


@chat_bp.route("/all_chats")
@login_required
def all_chats_with_people():
    user = User.query.filter_by(username=current_user.username).first()
    all_chats = Chat.query.filter((Chat.sender == user) | (Chat.receiver == user)).order_by(
        Chat.timestamp.desc()
    )

    people = []
    chat_text = []
    for chat_element in all_chats:
        if chat_element.sender.username != user.username:
            if chat_element.sender not in people:
                people.append(chat_element.sender)
                chat_text.append(chat_element.chat_text)
        else:
            if chat_element.receiver not in people:
                people.append(chat_element.receiver)
                chat_text.append(chat_element.chat_text)

    return render_template("all_chats.html", people=list(zip(people, chat_text)), form=ChatForm())
