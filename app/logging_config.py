import logging
import sys
import uuid
from typing import Any

from flask import Flask, g, request


class RequestFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        record.request_id = getattr(g, "request_id", "-")
        return super().format(record)


def configure_logging(app: Flask) -> None:
    log_level = logging.DEBUG if app.debug else logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    if app.debug:
        fmt = "%(asctime)s [%(levelname)s] %(request_id)s %(name)s: %(message)s"
    else:
        fmt = '{"time":"%(asctime)s","level":"%(levelname)s","request_id":"%(request_id)s","logger":"%(name)s","message":"%(message)s"}'

    handler.setFormatter(RequestFormatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S"))

    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(log_level)

    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    @app.before_request
    def set_request_id() -> None:
        g.request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:8])

    @app.after_request
    def log_request(response: Any) -> Any:
        if request.path != "/health":
            app.logger.info("%s %s %s", request.method, request.path, response.status_code)
        return response
