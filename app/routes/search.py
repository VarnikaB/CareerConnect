from flask import Blueprint, render_template, request, flash
from flask_login import login_required
from sqlalchemy import or_

from app.models import User, Post
from app.forms import SearchForm

search_bp = Blueprint("search", __name__)


@search_bp.route("/search", methods=["GET", "POST"])
@login_required
def search():
    form = SearchForm()
    search_tag = request.args.get("search_string")

    if search_tag is not None:
        posts = Post.query.filter(
            or_(
                Post.caption.like(f"%{search_tag}%"),
                Post.title.like(f"%{search_tag}%"),
            )
        ).all()
        if not posts:
            flash("No posts found", "danger")
        else:
            flash("Search successful", "info")
        return render_template(
            "search.html",
            users=[],
            posts=posts,
            form=form,
            published_posts_count=0,
            query=search_tag,
            default_value="",
        )

    if form.validate_on_submit():
        query = form.q.data
        users = []
        posts = []
        published_posts_count = 0

        if query:
            users = User.query.filter(User.username.like(f"%{query}%")).all()
            posts = Post.query.filter(
                or_(
                    Post.caption.like(f"%{query}%"),
                    Post.title.like(f"%{query}%"),
                )
            ).all()
            published_posts_count = (
                Post.query.join(User)
                .filter(
                    User.username.in_([u.username for u in users]),
                    Post.status == "published",
                )
                .count()
            )

        if not users and not posts:
            flash("No results found", "danger")
        else:
            flash("Search successful", "info")

        return render_template(
            "search.html",
            users=users,
            posts=posts,
            form=form,
            published_posts_count=published_posts_count,
            query=query,
            default_value="",
        )

    return render_template("search.html", form=form, default_value="")
