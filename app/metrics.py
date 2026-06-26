import time

from flask import g, request
from prometheus_client import Counter, Histogram, Info

REQUEST_COUNT = Counter(
    "flask_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)

REQUEST_LATENCY = Histogram(
    "flask_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

USER_REGISTRATIONS = Counter(
    "careerconnect_user_registrations_total",
    "Total user registrations",
)

USER_LOGINS = Counter(
    "careerconnect_user_logins_total",
    "Total successful user logins",
)

POSTS_CREATED = Counter(
    "careerconnect_posts_created_total",
    "Total posts created",
)

COMMENTS_CREATED = Counter(
    "careerconnect_comments_created_total",
    "Total comments created",
)

LIKES_GIVEN = Counter(
    "careerconnect_likes_total",
    "Total likes given",
)

CHATS_SENT = Counter(
    "careerconnect_chats_sent_total",
    "Total chat messages sent",
)

APP_INFO = Info("careerconnect", "Application information")


def init_metrics(app):
    if app.config.get("TESTING"):
        return

    APP_INFO.info({"version": "1.0.0", "app_name": "CareerConnect"})

    @app.before_request
    def start_timer():
        g.start_time = time.time()

    @app.after_request
    def record_metrics(response):
        if hasattr(g, "start_time"):
            latency = time.time() - g.start_time
            endpoint = request.endpoint or "unknown"
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=endpoint,
            ).observe(latency)
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=endpoint,
                status_code=response.status_code,
            ).inc()
        return response
