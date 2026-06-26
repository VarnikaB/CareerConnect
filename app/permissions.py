from functools import wraps
from typing import Any, Callable

from flask import abort
from flask_login import current_user


def role_required(*allowed_roles: str) -> Callable:
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            if current_user.is_admin:
                return f(*args, **kwargs)
            if current_user.role not in allowed_roles:
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def teacher_required(f: Callable) -> Callable:
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if not current_user.is_teacher:
            abort(403)
        return f(*args, **kwargs)

    return decorated_function
