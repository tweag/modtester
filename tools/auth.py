"""
Authentication Handler
Handles web app login, token extraction, and session management.

The user provides credentials in natural language:
  "Here are creds for vulnbank: admin / p@ssw0rd123"
  "Use this JWT for api.target.com: eyJhbG..."
  "SSH into 10.0.0.5 as root with password toor"

The AI calls these tools to:
  - Log into web apps and extract session tokens
  - Store tokens for automatic reuse in subsequent requests
  - Retrieve stored auth headers for any target
  - Test if credentials are still valid
"""
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
import http.cookiejar
from typing import Optional

# Reuse target_state for credential storage
from .target_state import (
    _load_state, _save_state, target_add, target_add_credential,
)


def auth_login(
    host: str,
    login_url: str,
    username: str = "",
    password: str = "",
    username_field: str = "username",
    password_field: str = "password",
    extra_fields: str = "",
    token_path: str = "",
    method: str = "POST",
    content_type: str = "json",
) -> str:
    """
    Log into a web application and extract the session token.

    Makes a login request, extracts the token from the response
    (JSON body or Set-Cookie header), and stores it in target_state
    for automatic reuse in subsequent requests.

    Args:
        host: Target host (e.g., "vulnbank.org")
        login_url: Full login URL (e.g., "https://vulnbank.org/login")
        username: Username or email
        password: Password
        username_field: Login form field name for username (default: "username")
        password_field: Login form field name for password (default: "password")
        extra_fields: Additional form fields as JSON object (e.g., '{"remember": true}')
        token_path: Dot-path to token in JSON response (e.g., "data.token", "access_token", "jwt").
                    If empty, tries common paths automatically. Also checks Set-Cookie headers.
        method: HTTP method (default: POST)
        content_type: Request body format — "json" or "form" (default: json)

    Returns:
        Login result with extracted token, stored for reuse
    """
    # Build request body
    body = {username_field: username, password_field: password}

    if extra_fields:
        try:
            extras = json.loads(extra_fields)
            body.update(extras)
        except (json.JSONDecodeError, TypeError):
            pass

    # Encode body
    if content_type == "form":
        data = urllib.parse.urlencode(body).encode("utf-8")
        ct_header = "application/x-www-form-urlencoded"
    else:
        data = json.dumps(body).encode("utf-8")
        ct_header = "application/json"

    # Make request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cookie_jar),
    )

    req = urllib.request.Request(
        login_url,
        data=data,
        method=method.upper(),
        headers={
            "Content-Type": ct_header,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "application/json, text/html, */*",
        },
    )

    try:
        response = opener.open(req, timeout=30)
        status = response.getcode()
        resp_headers = dict(response.headers)
        resp_body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers) if e.headers else {}
        resp_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
    except Exception as e:
        return f"Login failed: {e}"

    results = [f"Login response: HTTP {status}"]
    token_found = None
    token_type = None

    # 1. Try extracting token from JSON response body
    try:
        resp_json = json.loads(resp_body)

        # If token_path specified, use it
        if token_path:
            obj = resp_json
            for key in token_path.split("."):
                if isinstance(obj, dict):
                    obj = obj.get(key)
                else:
                    obj = None
                    break
            if obj and isinstance(obj, str):
                token_found = obj
                token_type = "bearer"
                results.append(f"Token extracted from response.{token_path}")
        else:
            # Auto-detect common token paths
            common_paths = [
                "token", "access_token", "jwt", "auth_token", "session_token",
                "data.token", "data.access_token", "data.jwt",
                "result.token", "response.token",
                "data.jwt_token", "data.session_token",
            ]
            for path in common_paths:
                obj = resp_json
                for key in path.split("."):
                    if isinstance(obj, dict):
                        obj = obj.get(key)
                    else:
                        obj = None
                        break
                if obj and isinstance(obj, str) and len(obj) > 10:
                    token_found = obj
                    token_type = "bearer"
                    results.append(f"Token auto-detected at response.{path}")
                    break

    except (json.JSONDecodeError, TypeError):
        pass

    # 2. Check Set-Cookie headers
    cookies = list(cookie_jar)
    session_cookies = [c for c in cookies if any(
        s in c.name.lower() for s in ["session", "token", "jwt", "auth", "sid", "csrf"]
    )]

    if session_cookies and not token_found:
        # Use the first session-like cookie
        cookie = session_cookies[0]
        token_found = f"{cookie.name}={cookie.value}"
        token_type = "cookie"
        results.append(f"Session cookie found: {cookie.name}")
    elif session_cookies:
        # Also record cookies even if we have a bearer token
        for c in session_cookies:
            results.append(f"Cookie: {c.name}={c.value[:20]}...")

    # 3. Check for tokens in response headers
    for header_name in ["Authorization", "X-Auth-Token", "X-Session-Token"]:
        val = resp_headers.get(header_name, "")
        if val and not token_found:
            token_found = val
            token_type = "header"
            results.append(f"Token from header: {header_name}")

    # Store results
    host_key = host.strip().lower()

    if token_found:
        # Store credential with token
        target_add_credential(
            host=host_key,
            credential_type=f"auth_{token_type}",
            username=username,
            password=password,
            token=token_found,
            source=f"auth_login via {login_url}",
            notes=f"type={token_type}",
        )

        # Store the active auth header for this host
        state = _load_state()
        if host_key not in state:
            target_add(host_key)
            state = _load_state()

        # Build the auth header
        if token_type == "bearer":
            auth_header = f"Bearer {token_found}"
        elif token_type == "cookie":
            auth_header = token_found  # Already in name=value format
        else:
            auth_header = token_found

        state[host_key]["active_auth"] = {
            "type": token_type,
            "header": auth_header,
            "token": token_found,
            "username": username,
            "login_url": login_url,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }
        _save_state(state)

        masked_token = token_found[:20] + "..." if len(token_found) > 20 else token_found
        results.append(f"\nAuthentication SUCCESSFUL")
        results.append(f"Token ({token_type}): {masked_token}")
        results.append(f"Stored for host: {host_key}")
        results.append(f"\nUse auth_headers(host=\"{host_key}\") to get headers for subsequent requests.")
    else:
        results.append(f"\nNo token found in response.")
        results.append(f"Response body (first 500 chars): {resp_body[:500]}")
        results.append(f"\nTry specifying token_path if the token is in a non-standard location.")

    return "\n".join(results)


def auth_set_token(
    host: str,
    token: str,
    token_type: str = "bearer",
    username: str = "",
    notes: str = "",
) -> str:
    """
    Manually set an auth token for a host. Use when the user provides a
    token directly instead of logging in.

    Examples:
        "Use this JWT for vulnbank.org: eyJhbG..."
        "Here's the API key for api.target.com: sk-abc123..."

    Args:
        host: Target host
        token: The token or API key
        token_type: Type — "bearer", "cookie", "api_key", "basic" (default: bearer)
        username: Associated username (optional)
        notes: Context (optional)

    Returns:
        Confirmation
    """
    host_key = host.strip().lower()
    state = _load_state()

    if host_key not in state:
        target_add(host_key)
        state = _load_state()

    # Build auth header based on type
    if token_type == "bearer":
        auth_header = f"Bearer {token}"
    elif token_type == "basic":
        import base64
        auth_header = f"Basic {base64.b64encode(token.encode()).decode()}"
    elif token_type == "api_key":
        auth_header = token  # Raw API key — AI adds the right header name
    elif token_type == "cookie":
        auth_header = token
    else:
        auth_header = token

    state[host_key]["active_auth"] = {
        "type": token_type,
        "header": auth_header,
        "token": token,
        "username": username,
        "login_url": "",
        "timestamp": __import__("datetime").datetime.now().isoformat(),
    }
    _save_state(state)

    # Also store as credential
    target_add_credential(
        host=host_key,
        credential_type=token_type,
        username=username,
        token=token,
        source="user-provided",
        notes=notes,
    )

    masked = token[:20] + "..." if len(token) > 20 else token
    return (
        f"Auth set for {host_key}: {token_type} token stored\n"
        f"Token: {masked}\n"
        f"Use auth_headers(host=\"{host_key}\") to get headers for requests."
    )


def auth_headers(host: str) -> str:
    """
    Get the stored auth headers for a host. Use the output as headers
    in http_fetch calls to make authenticated requests.

    Args:
        host: Target host

    Returns:
        JSON headers string ready to pass to http_fetch headers parameter,
        or a message if no auth is stored.
    """
    state = _load_state()
    host_key = host.strip().lower()

    if host_key not in state:
        return f"No data for {host_key}. Log in first with auth_login or set a token with auth_set_token."

    auth = state[host_key].get("active_auth")
    if not auth:
        # Check if there are any credentials with tokens
        creds = state[host_key].get("credentials", [])
        token_creds = [c for c in creds if c.get("token")]
        if token_creds:
            latest = token_creds[-1]
            token = latest["token"]
            ctype = latest.get("type", "bearer")
            if "bearer" in ctype or "jwt" in ctype.lower():
                return json.dumps({"Authorization": f"Bearer {token}"})
            elif "cookie" in ctype:
                return json.dumps({"Cookie": token})
            else:
                return json.dumps({"Authorization": f"Bearer {token}"})

        return f"No auth stored for {host_key}. Use auth_login or auth_set_token first."

    token_type = auth.get("type", "bearer")
    header_value = auth.get("header", "")

    if token_type == "cookie":
        headers = {"Cookie": header_value}
    elif token_type == "api_key":
        headers = {"X-API-Key": header_value}
    else:
        headers = {"Authorization": header_value}

    return json.dumps(headers)


def auth_test(host: str, test_url: str = "") -> str:
    """
    Test if stored credentials for a host are still valid.
    Makes a request to a protected endpoint and checks the response.

    Args:
        host: Target host
        test_url: URL to test (default: tries common auth-check endpoints)

    Returns:
        Whether auth is valid, expired, or missing
    """
    state = _load_state()
    host_key = host.strip().lower()

    if host_key not in state or not state[host_key].get("active_auth"):
        return f"No auth stored for {host_key}"

    auth = state[host_key]["active_auth"]
    token_type = auth.get("type", "bearer")
    header_value = auth.get("header", "")

    # Build test URL
    if not test_url:
        # Try common protected endpoints
        proto = "https"
        test_urls = [
            f"{proto}://{host_key}/dashboard",
            f"{proto}://{host_key}/api/me",
            f"{proto}://{host_key}/api/profile",
            f"{proto}://{host_key}/api/user",
        ]
    else:
        test_urls = [test_url]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in test_urls:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
            if token_type == "cookie":
                headers["Cookie"] = header_value
            else:
                headers["Authorization"] = header_value

            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            status = resp.getcode()

            if status in (200, 201, 204):
                return f"Auth VALID for {host_key} — {url} returned {status}"

        except urllib.error.HTTPError as e:
            if e.code == 401:
                return f"Auth EXPIRED/INVALID for {host_key} — {url} returned 401. Re-login needed."
            elif e.code == 403:
                return f"Auth valid but FORBIDDEN on {url} (403). Token works but lacks permissions."
        except Exception:
            continue

    return f"Could not verify auth for {host_key}. Tested: {', '.join(test_urls)}"


def auth_clear(host: str = "") -> str:
    """
    Clear stored auth for a host (or all hosts if empty).

    Args:
        host: Target host (empty = clear all)

    Returns:
        Confirmation
    """
    state = _load_state()

    if host:
        host_key = host.strip().lower()
        if host_key in state and "active_auth" in state[host_key]:
            del state[host_key]["active_auth"]
            _save_state(state)
            return f"Auth cleared for {host_key}"
        return f"No auth stored for {host_key}"
    else:
        for key in state:
            if "active_auth" in state[key]:
                del state[key]["active_auth"]
        _save_state(state)
        return "Auth cleared for all hosts"
