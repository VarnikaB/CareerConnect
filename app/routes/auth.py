from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash

from app.extensions import db, limiter
from app.forms import LoginForm, RegistrationForm
from app.models import User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.feed"))

    form = RegistrationForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash("User already registered!", "danger")
            return redirect(url_for("auth.login"))

        if form.password.data != form.confirm_password.data:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("auth.register"))

        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            password_hash=hashed_password,
            role=form.role.data,
        )

        db.session.add(new_user)
        db.session.commit()

        from app.metrics import USER_REGISTRATIONS

        USER_REGISTRATIONS.inc()

        flash("Successfully Registered!", "info")
        return redirect(url_for("auth.login"))
    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.feed"))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            login_user(user)

            from app.metrics import USER_LOGINS

            USER_LOGINS.inc()

            flash("Successfully logged in!", "success")

            next_page = request.args.get("next")
            if next_page and not next_page.startswith("/"):
                next_page = None
            return redirect(next_page or url_for("main.feed"))
        flash("Invalid username or password!", "danger")
    return render_template("login.html", title="Login", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for("auth.login"))
