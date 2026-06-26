import os

from flask import Flask

from config import config
from app.extensions import db, migrate, login_manager, bootstrap


def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get("FLASK_CONFIG", "default")

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    login_manager.init_app(app)
    bootstrap.init_app(app)

    from app.metrics import init_metrics
    init_metrics(app)

    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.posts import posts_bp
    from app.routes.comments import comments_bp
    from app.routes.chat import chat_bp
    from app.routes.search import search_bp
    from app.routes.questions import questions_bp
    from app.routes.users import users_bp
    from app.routes.metrics import metrics_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(posts_bp)
    app.register_blueprint(comments_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(questions_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(metrics_bp)

    from app.errors import register_error_handlers

    register_error_handlers(app)

    @app.cli.command("seed-admin")
    def seed_admin():
        """Create the admin user if not present."""
        from app.models import User

        if not User.query.filter_by(username="ADMIN_USER").first():
            admin = User(username="ADMIN_USER")
            admin.set_password(os.environ.get("ADMIN_PASSWORD", "change-me"))
            admin.occupation = "Administrator"
            db.session.add(admin)
            db.session.commit()
            print("Admin user created.")
        else:
            print("Admin user already exists.")

    return app
