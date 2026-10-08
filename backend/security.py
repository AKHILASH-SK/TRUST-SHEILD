"""
TrustShield - API security helpers.

Provides signed bearer tokens, auth decorators, an admin-key guard, a small
in-process rate limiter, login lockout, and a safe error responder.

State lives in this process (gunicorn runs a single worker). If the API is ever
scaled to several workers, move the rate-limit and lockout state to Redis.
"""

import hmac
import logging
import os
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from functools import wraps
from typing import Callable, Deque, Dict, Optional, Tuple

from flask import g, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

logger = logging.getLogger("trustshield.security")

IS_PRODUCTION = bool(
    os.getenv("RENDER")
    or os.getenv("FLY_APP_NAME")
    or os.getenv("RAILWAY_ENVIRONMENT")
    or os.getenv("TRUSTSHIELD_ENV", "").lower() == "production"
)

TOKEN_MAX_AGE_SECONDS = int(os.getenv("TOKEN_MAX_AGE_SECONDS", str(30 * 24 * 3600)))


def _load_secret(name: str) -> str:
    """Return a secret from the environment; in production it is mandatory."""
    value = os.getenv(name, "").strip()
    if value:
        return value
    if IS_PRODUCTION:
        raise RuntimeError(f"Environment variable {name} must be set in production")
    generated = secrets.token_urlsafe(48)
    logger.warning("%s is not set; using a temporary key for this process only", name)
    return generated


SECRET_KEY = _load_secret("SECRET_KEY")
_token_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="trustshield-auth-v1")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

def issue_token(user_id: int) -> str:
    return _token_serializer.dumps({"uid": int(user_id)})


def verify_token(token: str) -> Optional[int]:
    try:
        payload = _token_serializer.loads(token, max_age=TOKEN_MAX_AGE_SECONDS)
        return int(payload["uid"])
    except (BadSignature, SignatureExpired, KeyError, ValueError, TypeError):
        return None


def _bearer_token() -> Optional[str]:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


def current_user_id() -> Optional[int]:
    """User id from the request's bearer token, or None."""
    token = _bearer_token()
    return verify_token(token) if token else None


def require_auth(view: Callable) -> Callable:
    """The request must carry a valid bearer token; sets g.user_id."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user_id = current_user_id()
        if user_id is None:
            return jsonify({"error": "Authentication required"}), 401
        g.user_id = user_id
        return view(*args, **kwargs)
    return wrapper


def optional_auth(view: Callable) -> Callable:
    """Sets g.user_id when a valid token is present, otherwise None."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        g.user_id = current_user_id()
        return view(*args, **kwargs)
    return wrapper


def require_admin(view: Callable) -> Callable:
    """Requires the X-Admin-Key header to match ADMIN_API_KEY. Disabled if unset."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not ADMIN_API_KEY:
            return jsonify({"error": "Admin endpoints are disabled"}), 403
        supplied = request.headers.get("X-Admin-Key", "")
        if not hmac.compare_digest(supplied.encode(), ADMIN_API_KEY.encode()):
            return jsonify({"error": "Forbidden"}), 403
        return view(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Rate limiting (sliding window, in-process)
# ---------------------------------------------------------------------------

_rate_lock = threading.Lock()
_rate_hits: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
_RATE_MAX_KEYS = 20000


def client_ip() -> str:
    return request.remote_addr or "unknown"


def _allow(bucket: str, key: str, limit: int, window_seconds: int) -> bool:
    now = time.monotonic()
    with _rate_lock:
        if len(_rate_hits) > _RATE_MAX_KEYS:
            for stale in [k for k, v in _rate_hits.items() if not v or now - v[-1] > window_seconds]:
                _rate_hits.pop(stale, None)
        hits = _rate_hits[(bucket, key)]
        while hits and now - hits[0] > window_seconds:
            hits.popleft()
        if len(hits) >= limit:
            return False
        hits.append(now)
        return True


def rate_limit(bucket: str, limit: int, window_seconds: int = 60, per_user: bool = False) -> Callable:
    """Limit calls per client IP (or per authenticated user)."""
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapper(*args, **kwargs):
            key = client_ip()
            if per_user and getattr(g, "user_id", None) is not None:
                key = f"user:{g.user_id}"
            if not _allow(bucket, key, limit, window_seconds):
                response = jsonify({"error": "Too many requests. Please slow down."})
                response.status_code = 429
                response.headers["Retry-After"] = str(window_seconds)
                return response
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Login lockout
# ---------------------------------------------------------------------------

_LOCK_MAX_FAILURES = 5
_LOCK_WINDOW_SECONDS = 15 * 60
_failures_lock = threading.Lock()
_failures: Dict[str, Deque[float]] = defaultdict(deque)


def _lock_key(identity: str) -> str:
    return f"{identity}|{client_ip()}"


def is_locked_out(identity: str) -> bool:
    now = time.monotonic()
    with _failures_lock:
        entries = _failures[_lock_key(identity)]
        while entries and now - entries[0] > _LOCK_WINDOW_SECONDS:
            entries.popleft()
        return len(entries) >= _LOCK_MAX_FAILURES


def record_login_failure(identity: str) -> None:
    with _failures_lock:
        _failures[_lock_key(identity)].append(time.monotonic())


def clear_login_failures(identity: str) -> None:
    with _failures_lock:
        _failures.pop(_lock_key(identity), None)


# ---------------------------------------------------------------------------
# Errors and validation
# ---------------------------------------------------------------------------

def server_error(exc: Exception, public_message: str = "Internal server error"):
    """
    Log the real exception with a reference id and return a generic message.
    Client errors raised by Flask/Werkzeug (bad JSON 400, upload too large 413, ...) keep their own status.
    """
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException) and exc.code and exc.code < 500:
        return jsonify({"error": _CLIENT_ERROR_TEXT.get(exc.code, exc.name)}), exc.code
    reference = uuid.uuid4().hex[:12]
    logger.exception("Unhandled error [%s]: %s", reference, exc)
    return jsonify({"error": public_message, "reference": reference}), 500


_CLIENT_ERROR_TEXT = {
    400: "Malformed request",
    404: "Not found",
    405: "Method not allowed",
    413: "Upload too large",
    415: "Unsupported content type",
}


def sanitize_header_value(value: str, max_length: int = 300) -> str:
    """Remove CR/LF (header injection) and cap length."""
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())[:max_length]


def is_valid_pin(pin) -> bool:
    return isinstance(pin, str) and pin.isdigit() and 4 <= len(pin) <= 8


def is_valid_phone(phone) -> bool:
    if not isinstance(phone, str):
        return False
    digits = phone.replace("+", "").replace(" ", "").replace("-", "")
    return digits.isdigit() and 7 <= len(digits) <= 15


def is_valid_email(email) -> bool:
    return isinstance(email, str) and 3 <= len(email) <= 254 and "@" in email and "\n" not in email
