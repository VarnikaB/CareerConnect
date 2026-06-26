import os
import sys


def validate_config(config_name: str) -> None:
    if config_name == "production":
        required = ["SECRET_KEY", "DATABASE_URL"]
        missing = [var for var in required if not os.environ.get(var)]
        if missing:
            print(f"FATAL: Missing required env vars for production: {', '.join(missing)}")
            sys.exit(1)

        if os.environ.get("SECRET_KEY") in (None, "", "change-me-in-production"):
            print("FATAL: SECRET_KEY must be set to a secure value in production")
            sys.exit(1)
