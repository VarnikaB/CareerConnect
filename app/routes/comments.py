from flask import Blueprint, render_template, request, flash, redirect, url_for, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models import Post, Comment
from app.forms import CommentForm, EditCommentForm, DeleteCommentForm
from app.metrics import COMMENTS_CREATED

comments_bp = Blueprint("comments", __name__)


@comments_bp.route("/post/<int:post_id>/comment", methods=["GET", "POST"])
@login_required
def comment(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()

    form = CommentForm()

    if form.validate_on_submit():
        new_comment = Comment(
            content=form.content.data, user_id=current_user.id, post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()

        from app.metrics import COMMENTS_CREATED
        COMMENTS_CREATED.inc()

        flash("Comment added!", "success")
        return redirect(url_for("comments.comment", post_id=post_id))

    return render_template(
        "comment.html",
        form=form,
        post_id=post_id,
        comments=comments,
        post=post,
    )


@comments_bp.route(
    "/post/<int:post_id>/comment/<int:comment_id>/edit", methods=["GET", "POST"]
)
@login_required
def edit_comment(post_id, comment_id):
    particular_comment = Comment.query.get_or_404(comment_id)
    if particular_comment.user != current_user:
        abort(403)

    form = EditCommentForm()

    if form.validate_on_submit():
        particular_comment.content = form.content.data
        db.session.commit()

        flash("Comment edited!", "success")
        return redirect(
            url_for("comments.comment", post_id=particular_comment.post_id)
        )

    if request.method == "GET":
        form.content.data = particular_comment.content

    return render_template(
        "edit_comment.html",
        form=form,
        post_id=particular_comment.post_id,
        comment_id=particular_comment.id,
    )


@comments_bp.route(
    "/post/<int:post_id>/comment/<int:comment_id>/delete", methods=["GET", "POST"]
)
@login_required
def delete_comment(post_id, comment_id):
    particular_comment = Comment.query.get_or_404(comment_id)
    post = Post.query.get_or_404(post_id)
    if (
        particular_comment.user != current_user
        and not current_user.can_delete_others_comments(post)
    ):
        abort(403)

    form = DeleteCommentForm()

    if form.validate_on_submit():
        db.session.delete(particular_comment)
        db.session.commit()

        flash("Comment deleted!", "success")
        return redirect(url_for("comments.comment", post_id=post_id))

    return render_template(
        "delete_comment.html",
        form=form,
        post_id=particular_comment.post_id,
        comment_id=particular_comment.id,
        comment=particular_comment,
    )
