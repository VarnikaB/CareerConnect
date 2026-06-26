from flask import Blueprint, jsonify
from sqlalchemy import text

from app.extensions import db

health_bp = Blueprint("health", __name__)


@health_bp.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "unavailable"

    status = "healthy" if db_status == "connected" else "degraded"
    return jsonify({"status": status, "version": "1.0.0", "database": db_status}), (
        200 if status == "healthy" else 503
    )
