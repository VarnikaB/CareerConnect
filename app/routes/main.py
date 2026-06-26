from flask import Blueprint, render_template, request, current_app
from flask_login import login_required, current_user

from app.models import Post
from app.forms import LikeForm, UnlikeForm

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def welcome():
    return render_template("welcome.html")


@main_bp.route("/feed")
@login_required
def feed():
    page = request.args.get("page", 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(
        page=page, per_page=current_app.config["POSTS_PER_PAGE"]
    )
    like_form = LikeForm()
    unlike_form = UnlikeForm()
    return render_template(
        "feed.html",
        title="Feed",
        posts=posts,
        current_user=current_user,
        like_form=like_form,
        unlike_form=unlike_form,
    )
