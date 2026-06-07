"""
ModTester — Simple single-user auth.

Demo credentials (configurable via env vars):
    MODTESTER_USER=admin
    MODTESTER_PASS=modtester2026

Produces a signed JWT stored as an httpOnly cookie.
"""
import os
import hmac
import hashlib
import json
import base64
import time

from starlette.requests import Request
from starlette.responses import JSONResponse
from audit import log_auth_event

SECRET = os.environ.get("AUTH_SECRET")
if not SECRET:
    raise RuntimeError("AUTH_SECRET environment variable must be set")
DEMO_USER = os.environ.get("MODTESTER_USER", "admin")
DEMO_PASS = os.environ.get("MODTESTER_PASS")
if not DEMO_PASS:
    raise RuntimeError("MODTESTER_PASS environment variable must be set")
TOKEN_TTL = 86400 * 7  # 7 days


def _check_password_complexity(password: str) -> str | None:
    """Returns error message if password doesn't meet complexity, None if OK."""
    if len(password) < 12:
        return "Password must be at least 12 characters"
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number"
    if not any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/~`" for c in password):
        return "Password must contain at least one special character"
    return None


def _sign(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header}.{body}.{sig_b64}"


def _verify(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        expected = hmac.new(SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected).decode().rstrip("=")
        if not hmac.compare_digest(sig, expected_b64):
            return None
        # Pad body for base64
        padded = body + "=" * (4 - len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


async def api_login(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid body"}, status_code=400)

    username = body.get("username", "")
    password = body.get("password", "")

    if not hmac.compare_digest(username, DEMO_USER) or not hmac.compare_digest(password, DEMO_PASS):
        log_auth_event("login_failure", username, request.client.host if request.client else "")
        return JSONResponse({"error": "invalid credentials"}, status_code=401)

    log_auth_event("login_success", username, request.client.host if request.client else "")
    token = _sign({"sub": username, "exp": time.time() + TOKEN_TTL})
    response = JSONResponse({"user": username, "token": token})
    response.set_cookie(
        "modtester_token",
        token,
        httponly=True,
        samesite="lax",
        max_age=TOKEN_TTL,
        path="/",
    )
    return response


async def api_logout(request: Request):
    response = JSONResponse({"ok": True})
    response.delete_cookie("modtester_token", path="/")
    return response


async def api_me(request: Request):
    token = request.cookies.get("modtester_token") or ""
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    payload = _verify(token)
    if not payload:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"user": payload["sub"]})


def require_auth(request: Request) -> dict | None:
    """Middleware helper — returns payload if valid, None if not."""
    token = request.cookies.get("modtester_token") or ""
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    return _verify(token)
