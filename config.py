import os

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    POSTS_PER_PAGE = int(os.environ.get("POSTS_PER_PAGE", 10))
    UPLOAD_FOLDER = "static/posts"
    ALLOWED_IMAGE_EXTENSIONS = ["JPG", "PNG"]
    MAX_CONTENT_LENGTH = 8 * 1024 * 1024


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL"
    ) or "sqlite:///" + os.path.join(basedir, "instance", "careerconnect.db")


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
