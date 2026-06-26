import os
from datetime import datetime
from zoneinfo import ZoneInfo

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.forms import DeletePostForm, LikeForm, PostForm, UnlikeForm, UpdatePostForm
from app.models import Comment, Like, Post
from app.utils import save_post

IST = ZoneInfo("Asia/Kolkata")

posts_bp = Blueprint("posts", __name__)


@posts_bp.route("/post/create_post", methods=["GET", "POST"])
@login_required
def create_post():
    form = PostForm()

    if form.validate_on_submit():
        image_file = None
        if form.image.data:
            image_file = save_post(form.image.data)

        post = Post(
            title=form.title.data,
            caption=form.caption.data,
            image=image_file,
            user_id=current_user.id,
            is_anonymous=form.is_anonymous.data,
        )

        db.session.add(post)
        db.session.commit()

        from app.metrics import POSTS_CREATED

        POSTS_CREATED.inc()

        flash("Post created!", "success")
        return redirect(url_for("users.profile", username=current_user.username))

    return render_template("create_post.html", title="Create Post", form=form)


@posts_bp.route("/post/<int:post_id>/update", methods=["GET", "POST"])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user != current_user:
        abort(403)

    form = UpdatePostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.caption = form.caption.data
        post.is_anonymous = form.is_anonymous.data

        if form.image.data:
            if post.image:
                try:
                    os.remove(os.path.join(current_app.root_path, "static/posts", post.image))
                except OSError:
                    pass

            image_file = save_post(form.image.data)
            post.image = image_file

        post.last_updated = datetime.now(IST)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Couldn't update the post!", "danger")
            return redirect(url_for("posts.update_post", post_id=post.id))

        flash("Post updated!", "success")
        return redirect(url_for("users.profile", username=current_user.username))

    if request.method == "GET":
        form.title.data = post.title
        form.caption.data = post.caption
        form.is_anonymous.data = post.is_anonymous

    return render_template("update_post.html", form=form)


@posts_bp.route("/post/<int:post_id>/delete", methods=["GET", "POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user != current_user and not current_user.is_admin:
        abort(403)

    form = DeletePostForm()

    if form.validate_on_submit():
        db.session.query(Like).filter_by(post_id=post_id).delete()
        db.session.query(Comment).filter_by(post_id=post_id).delete()
        db.session.delete(post)
        db.session.commit()

        flash("Post deleted!", "success")
        return redirect(url_for("users.profile", username=current_user.username))

    return render_template("delete_post.html", post=post, form=form)


@posts_bp.route("/like/<int:post_id>", methods=["GET", "POST"])
@login_required
def like(post_id):
    post = Post.query.filter_by(id=post_id).first_or_404()
    current_user.like_post(post)
    db.session.commit()

    from app.metrics import LIKES_GIVEN

    LIKES_GIVEN.inc()

    flash(
        f'You liked "{post.title}" by {post.user.username}!',
        "success",
    )
    return redirect(url_for("main.feed"))


@posts_bp.route("/unlike/<int:post_id>", methods=["POST", "GET"])
@login_required
def unlike(post_id):
    post = Post.query.filter_by(id=post_id).first_or_404()
    current_user.unlike_post(post)
    db.session.commit()

    flash(
        f'You unliked "{post.title}" by {post.user.username}!',
        "info",
    )
    return redirect(url_for("main.feed"))
