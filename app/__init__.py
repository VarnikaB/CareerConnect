import os
from typing import Optional

from flask import Flask

from app.extensions import db, limiter, login_manager, migrate, talisman
from config import config


def create_app(config_name: Optional[str] = None) -> Flask:
    if config_name is None:
        config_name = os.environ.get("FLASK_CONFIG", "default")

    from app.config_validator import validate_config

    validate_config(config_name)

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    login_manager.init_app(app)
    limiter.init_app(app)

    if not app.config.get("TESTING"):
        talisman.init_app(
            app,
            force_https=False,
            content_security_policy=app.config.get("CSP_POLICY"),
        )

    from app.logging_config import configure_logging

    configure_logging(app)

    from app.metrics import init_metrics

    init_metrics(app)

    from app.routes.auth import auth_bp
    from app.routes.chat import chat_bp
    from app.routes.comments import comments_bp
    from app.routes.health import health_bp
    from app.routes.main import main_bp
    from app.routes.metrics import metrics_bp
    from app.routes.posts import posts_bp
    from app.routes.questions import questions_bp
    from app.routes.search import search_bp
    from app.routes.users import users_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(posts_bp)
    app.register_blueprint(comments_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(questions_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(health_bp)

    from app.errors import register_error_handlers

    register_error_handlers(app)

    @app.cli.command("seed-admin")
    def seed_admin() -> None:
        """Create the admin user if not present."""
        from app.models import User

        if not User.query.filter_by(username="ADMIN_USER").first():
            admin = User(username="ADMIN_USER", role="teacher")
            admin.set_password(os.environ.get("ADMIN_PASSWORD", "change-me"))
            admin.occupation = "Administrator"
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Admin user created.")
        else:
            app.logger.info("Admin user already exists.")

    return app
