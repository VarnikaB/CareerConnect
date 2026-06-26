from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user, logout_user

from app.extensions import db
from app.models import User, Post, Like, Comment
from app.forms import (
    UpdateAccountForm,
    DeleteAccountForm,
    ChatForm,
    LikeForm,
    UnlikeForm,
)
from app.utils import save_profile

users_bp = Blueprint("users", __name__)


@users_bp.route("/profile/<username>")
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get("page", 1, type=int)

    posts = (
        Post.query.filter_by(user_id=user.id)
        .order_by(Post.timestamp.desc())
        .paginate(page=page, per_page=5)
    )

    likes = Like.query.filter_by(user_id=user.id).count()
    comments = Comment.query.filter_by(user_id=user.id).count()
    published_posts_count = Post.query.filter_by(user_id=user.id).count()

    follow_form = ChatForm()
    like_form = LikeForm()
    unlike_form = UnlikeForm()

    return render_template(
        "profile.html",
        likes=likes,
        comments=comments,
        user=user,
        posts=posts,
        follow_form=follow_form,
        like_form=like_form,
        unlike_form=unlike_form,
        published_posts_count=published_posts_count,
    )


@users_bp.route("/update_account", methods=["GET", "POST"])
@login_required
def update_account():
    form = UpdateAccountForm()

    if form.validate_on_submit():
        if form.profile_image.data:
            picture_file = save_profile(form.profile_image.data)
            current_user.profile_image = picture_file

        current_user.username = form.username.data
        current_user.occupation = form.occupation.data
        db.session.commit()

        flash("Account updated!", "success")
        return redirect(url_for("users.profile", username=current_user.username))

    elif request.method == "GET":
        form.username.data = current_user.username

    return render_template(
        "update_account.html", title="Update Account", form=form
    )


@users_bp.route("/delete_account", methods=["GET", "POST"])
@login_required
def delete_account():
    form = DeleteAccountForm()

    if form.validate_on_submit():
        if current_user.check_password(form.password.data):
            db.session.query(Post).filter(Post.user_id == current_user.id).delete()
            db.session.delete(current_user)
            db.session.commit()
            logout_user()

            flash("Account deleted!", "success")
            return redirect(url_for("auth.login"))

        flash("Incorrect password!", "danger")
    return render_template("delete_account.html", form=form)


@users_bp.route("/likes/user/<username>", methods=["GET", "POST"])
@login_required
def likes_of_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    likes = Like.query.filter_by(user_id=user.id).all()
    posts = [like_element.posts for like_element in likes]
    return render_template("all_likes.html", title="All Likes", posts=posts)


@users_bp.route("/comments/user/<username>", methods=["GET", "POST"])
@login_required
def comments_of_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    comments = Comment.query.filter_by(user_id=user.id).all()
    posts = []
    for comment_element in comments:
        if comment_element.posts not in posts:
            posts.append(comment_element.posts)
    return render_template("all_comments.html", title="All Comments", posts=posts)
