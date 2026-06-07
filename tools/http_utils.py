"""
HTTP Utility Tools
- http_fetch: Fetch any URL with full control over method, headers, body
- http_methods: Test which HTTP methods a URL accepts
- cookie_check: Analyze Set-Cookie headers for security flags

These are the "hands" the AI was missing. When katana discovers /internal/config.json
or feroxbuster finds /console, the AI needs a way to actually fetch and read it.
Previously it had no tool for this — it could discover paths but not examine them.
"""
import json
import ssl
import urllib.request
import urllib.error
import urllib.parse
from typing import Optional, Dict


# Shared: permissive SSL context for targets with self-signed certs
def _make_ssl_context() -> ssl.SSLContext:
    """Create an SSL context that accepts any certificate.
    Security scanning targets often have self-signed or expired certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _truncate(text: str, max_len: int = 50000) -> str:
    """Truncate text with a note if it was cut."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n\n[... truncated at {max_len} chars, full response was {len(text)} chars]"


# =============================================================================
# http_fetch
# =============================================================================

def http_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    follow_redirects: bool = True,
    timeout: int = 15,
    max_body: int = 50000,
) -> str:
    """
    Fetch a URL and return status, headers, and body.

    This is the general-purpose HTTP tool for probing endpoints discovered
    by other tools. Use it to: read config files, check debug consoles,
    fetch API schemas, download robots.txt, test for information disclosure,
    send custom requests to API endpoints.

    Args:
        url: Full URL to fetch (e.g., "https://target.com/robots.txt")
        method: HTTP method — GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
        headers: Dict of custom HTTP headers (e.g., {"Authorization": "Bearer xxx"})
        body: Request body for POST/PUT/PATCH requests (string or JSON string)
        follow_redirects: Follow 301/302 redirects. Default True.
        timeout: Request timeout in seconds. Default 15.
        max_body: Maximum response body bytes to return. Default 50000.

    Returns:
        Status code, response headers, and body content
    """
    method = method.upper()
    valid_methods = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
    if method not in valid_methods:
        return f"Error: Invalid method '{method}'. Use one of: {', '.join(valid_methods)}"

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ctx = _make_ssl_context()

    # Build request
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)

    # Encode body
    body_bytes = None
    if body is not None:
        body_bytes = body.encode("utf-8")
        if "Content-Type" not in req_headers:
            # Auto-detect JSON
            stripped = body.strip()
            if stripped.startswith(("{", "[")):
                req_headers["Content-Type"] = "application/json"
            elif "=" in stripped and "&" in stripped:
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                req_headers["Content-Type"] = "text/plain"

    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)

    result_lines = [f"[{method}] {url}", ""]

    try:
        # Build opener with or without redirect handling
        if follow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
        else:
            # Custom handler that stops on redirects
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(
                NoRedirectHandler,
                urllib.request.HTTPSHandler(context=ctx),
            )

        response = opener.open(req, timeout=timeout)
        status = response.status
        resp_headers = dict(response.headers)

        # Read body (capped)
        try:
            raw_body = response.read(max_body + 1)
            body_text = raw_body.decode("utf-8", errors="replace")
        except Exception:
            body_text = "(could not read response body)"

        result_lines.append(f"Status: {status}")
        result_lines.append("")

        # Response headers
        result_lines.append("Response Headers:")
        for key, value in sorted(resp_headers.items()):
            result_lines.append(f"  {key}: {value}")
        result_lines.append("")

        # Body
        result_lines.append("Body:")
        result_lines.append(_truncate(body_text, max_body))

        return "\n".join(result_lines)

    except urllib.error.HTTPError as e:
        # HTTP errors still have useful response data
        status = e.code
        resp_headers = dict(e.headers) if e.headers else {}

        try:
            error_body = e.read(max_body).decode("utf-8", errors="replace")
        except Exception:
            error_body = ""

        result_lines.append(f"Status: {status} ({e.reason})")
        result_lines.append("")

        if resp_headers:
            result_lines.append("Response Headers:")
            for key, value in sorted(resp_headers.items()):
                result_lines.append(f"  {key}: {value}")
            result_lines.append("")

        if error_body:
            result_lines.append("Body:")
            result_lines.append(_truncate(error_body, max_body))

        return "\n".join(result_lines)

    except urllib.error.URLError as e:
        reason = str(e.reason)
        if "getaddrinfo failed" in reason or "Name or service not known" in reason:
            return f"[{method}] {url}\n\nError: Domain does not resolve (DNS failure)"
        elif "Connection refused" in reason:
            return f"[{method}] {url}\n\nError: Connection refused — port may be closed"
        elif "timed out" in reason.lower():
            return f"[{method}] {url}\n\nError: Connection timed out after {timeout}s"
        else:
            return f"[{method}] {url}\n\nError: {reason}"

    except Exception as e:
        return f"[{method}] {url}\n\nError: {e}"


# =============================================================================
# http_methods
# =============================================================================

def http_methods(
    url: str,
    timeout: int = 10,
) -> str:
    """
    Test which HTTP methods a URL accepts.

    Sends an OPTIONS request first, then tests each method individually.
    Finds: writable endpoints (PUT/DELETE allowed), CORS config (OPTIONS response),
    method override possibilities, and unexpected method handling.

    PUT enabled on a web root is a potential webshell upload vector.
    DELETE enabled is a potential data destruction vector.

    Args:
        url: URL to test (e.g., "https://target.com/upload")
        timeout: Per-request timeout in seconds

    Returns:
        Allowed methods and response details for each
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ctx = _make_ssl_context()
    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    result_lines = [f"HTTP Method Testing: {url}", "=" * 60, ""]

    # Phase 1: OPTIONS request
    try:
        req = urllib.request.Request(url, headers=base_headers, method="OPTIONS")
        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)

        allow_header = response.headers.get("Allow", "")
        cors_origin = response.headers.get("Access-Control-Allow-Origin", "")
        cors_methods = response.headers.get("Access-Control-Allow-Methods", "")

        result_lines.append("[OPTIONS] Response:")
        result_lines.append(f"  Status: {response.status}")
        if allow_header:
            result_lines.append(f"  Allow: {allow_header}")
        if cors_origin:
            result_lines.append(f"  CORS Origin: {cors_origin}")
        if cors_methods:
            result_lines.append(f"  CORS Methods: {cors_methods}")
        if not allow_header and not cors_methods:
            result_lines.append("  (No Allow or CORS headers returned)")
        result_lines.append("")

    except urllib.error.HTTPError as e:
        result_lines.append(f"[OPTIONS] Status: {e.code} ({e.reason})")
        allow_header = e.headers.get("Allow", "") if e.headers else ""
        if allow_header:
            result_lines.append(f"  Allow: {allow_header}")
        result_lines.append("")
    except Exception as e:
        result_lines.append(f"[OPTIONS] Error: {e}")
        result_lines.append("")

    # Phase 2: Test individual methods
    test_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]

    for method in test_methods:
        try:
            # For methods that typically need a body, send a minimal one
            body = None
            if method in ("POST", "PUT", "PATCH"):
                body = b"test=1"

            req = urllib.request.Request(url, data=body, headers=base_headers, method=method)
            if body:
                req.add_header("Content-Type", "application/x-www-form-urlencoded")

            response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            status = response.status
            server = response.headers.get("Server", "")

            if method in ("PUT", "DELETE"):
                result_lines.append(f"[{method}] Status: {status} *** ALLOWED — potential security issue ***")
            else:
                result_lines.append(f"[{method}] Status: {status}")

            if server:
                result_lines.append(f"  Server: {server}")

        except urllib.error.HTTPError as e:
            status = e.code
            if status == 405:
                result_lines.append(f"[{method}] Status: 405 Method Not Allowed")
            elif status == 403:
                result_lines.append(f"[{method}] Status: 403 Forbidden (exists but blocked)")
            elif status == 401:
                result_lines.append(f"[{method}] Status: 401 Unauthorized (requires auth)")
            else:
                result_lines.append(f"[{method}] Status: {status} ({e.reason})")

        except Exception as e:
            result_lines.append(f"[{method}] Error: {e}")

    # Summary
    result_lines.append("")
    result_lines.append("Summary:")

    # Parse findings
    full_text = "\n".join(result_lines)
    if "ALLOWED" in full_text:
        result_lines.append("  *** WARNING: Potentially dangerous methods are enabled ***")
        result_lines.append("  PUT allowed = possible file upload / overwrite")
        result_lines.append("  DELETE allowed = possible data destruction")
    else:
        result_lines.append("  No dangerous methods detected.")

    return "\n".join(result_lines)


# =============================================================================
# cookie_check
# =============================================================================

def cookie_check(
    url: str,
    timeout: int = 15,
) -> str:
    """
    Fetch a URL and analyze all Set-Cookie headers for security flags.

    Checks each cookie for:
    - Secure flag (missing = cookie sent over unencrypted HTTP)
    - HttpOnly flag (missing = cookie accessible to JavaScript / XSS can steal it)
    - SameSite attribute (missing = CSRF risk)
    - Expires/Max-Age (session vs persistent)
    - Path scope

    Session cookies without Secure + HttpOnly + SameSite are always a finding.

    Args:
        url: URL that sets cookies (e.g., login page, home page)
        timeout: Request timeout in seconds

    Returns:
        Analysis of each cookie's security properties
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ctx = _make_ssl_context()

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )

    try:
        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status = response.status
        all_headers = response.headers
    except urllib.error.HTTPError as e:
        # HTTP errors can still set cookies (e.g., 302 redirect to login)
        status = e.code
        all_headers = e.headers if e.headers else {}
    except urllib.error.URLError as e:
        return f"Error connecting to {url}: {e.reason}"
    except Exception as e:
        return f"Error: {e}"

    # Extract all Set-Cookie headers
    # HTTPMessage.get_all returns a list; headers.items() gets all including dupes
    raw_cookies = []
    if hasattr(all_headers, "get_all"):
        raw_cookies = all_headers.get_all("Set-Cookie") or []
    else:
        # Fallback: parse from raw headers
        for key, value in all_headers.items():
            if key.lower() == "set-cookie":
                raw_cookies.append(value)

    if not raw_cookies:
        return (
            f"Cookie Analysis for {url}\n"
            f"Status: {status}\n\n"
            f"No Set-Cookie headers found in response.\n"
            f"The server may not set cookies on this page, "
            f"or cookies may only be set after authentication."
        )

    result_lines = [
        f"Cookie Analysis for {url}",
        f"Status: {status}",
        f"Cookies found: {len(raw_cookies)}",
        "=" * 60,
        "",
    ]

    issues_count = 0
    total_cookies = 0

    for cookie_str in raw_cookies:
        total_cookies += 1

        # Parse the cookie string
        # Format: name=value; attr1; attr2=val2; ...
        parts = [p.strip() for p in cookie_str.split(";")]
        if not parts:
            continue

        # First part is name=value
        name_value = parts[0]
        if "=" in name_value:
            cookie_name = name_value.split("=", 1)[0].strip()
            cookie_value = name_value.split("=", 1)[1].strip()
        else:
            cookie_name = name_value.strip()
            cookie_value = ""

        # Parse attributes (case-insensitive)
        attrs = {}
        for part in parts[1:]:
            part_stripped = part.strip()
            if not part_stripped:
                continue
            if "=" in part_stripped:
                attr_name, attr_value = part_stripped.split("=", 1)
                attrs[attr_name.strip().lower()] = attr_value.strip()
            else:
                attrs[part_stripped.lower()] = True

        # Check security flags
        has_secure = "secure" in attrs
        has_httponly = "httponly" in attrs
        has_samesite = "samesite" in attrs
        samesite_value = attrs.get("samesite", "").lower() if isinstance(attrs.get("samesite"), str) else ""
        has_expires = "expires" in attrs or "max-age" in attrs
        path = attrs.get("path", "/")
        domain = attrs.get("domain", "")

        # Determine if this looks like a session cookie
        session_indicators = ["session", "sess", "sid", "token", "auth", "jwt", "csrf"]
        is_session_like = any(ind in cookie_name.lower() for ind in session_indicators)

        # Build per-cookie report
        result_lines.append(f"Cookie: {cookie_name}")
        result_lines.append(f"  Value: {cookie_value[:80]}{'...' if len(cookie_value) > 80 else ''}")
        if domain:
            result_lines.append(f"  Domain: {domain}")
        result_lines.append(f"  Path: {path}")
        result_lines.append(f"  Persistent: {'Yes' if has_expires else 'No (session cookie)'}")

        cookie_issues = []

        if not has_secure:
            cookie_issues.append("[FAIL] Secure flag MISSING — cookie sent over HTTP (interceptable)")
            issues_count += 1
        else:
            result_lines.append("  [PASS] Secure flag set")

        if not has_httponly:
            cookie_issues.append("[FAIL] HttpOnly flag MISSING — accessible to JavaScript (XSS can steal it)")
            issues_count += 1
        else:
            result_lines.append("  [PASS] HttpOnly flag set")

        if not has_samesite:
            cookie_issues.append("[FAIL] SameSite attribute MISSING — CSRF risk")
            issues_count += 1
        elif samesite_value == "none":
            cookie_issues.append("[WARN] SameSite=None — cookie sent on all cross-site requests")
            issues_count += 1
        else:
            result_lines.append(f"  [PASS] SameSite={samesite_value or 'set'}")

        if cookie_issues:
            for issue in cookie_issues:
                result_lines.append(f"  {issue}")

        if is_session_like and cookie_issues:
            result_lines.append(f"  *** This appears to be a session cookie — missing flags are HIGH severity ***")

        result_lines.append("")

    # Summary
    result_lines.append("=" * 60)
    result_lines.append("Summary:")
    result_lines.append(f"  Cookies analyzed: {total_cookies}")
    result_lines.append(f"  Security issues: {issues_count}")

    if issues_count == 0:
        result_lines.append("  All cookies have proper security flags.")
    else:
        result_lines.append("")
        result_lines.append("Recommendations:")
        # Check which flags were missing across all cookies
        all_text = "\n".join(result_lines)
        if "Secure flag MISSING" in all_text:
            result_lines.append("  - Add 'Secure' flag to all cookies (ensures HTTPS-only transmission)")
        if "HttpOnly flag MISSING" in all_text:
            result_lines.append("  - Add 'HttpOnly' flag to session cookies (prevents JavaScript access)")
        if "SameSite attribute MISSING" in all_text or "SameSite=None" in all_text:
            result_lines.append("  - Set 'SameSite=Lax' or 'SameSite=Strict' on cookies (prevents CSRF)")

    return "\n".join(result_lines)
