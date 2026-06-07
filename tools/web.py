"""Web tools — HTTP probing, headers, fuzzing, crawling."""
import subprocess
import shlex
import httpx
from typing import List, Optional


def http_probe(targets: list) -> str:
    """Probe URLs for availability and technology detection."""
    if not targets:
        return "No targets provided"
    targets_str = "\n".join(targets[:50])
    cmd = f"echo '{targets_str}' | httpx -silent -status-code -title -tech-detect -content-length"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return result.stdout.strip() or "No live hosts detected"
    except Exception as e:
        return f"Error: {e}"


def http_headers_check(url: str) -> str:
    """Analyze HTTP security headers."""
    try:
        r = httpx.get(url, timeout=15.0, follow_redirects=True, verify=False)
        headers = dict(r.headers)

        security_headers = [
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options",
            "x-xss-protection", "referrer-policy",
            "permissions-policy", "cross-origin-opener-policy",
        ]

        lines = [f"URL: {url}", f"Status: {r.status_code}", ""]
        lines.append("Security Headers:")
        for h in security_headers:
            val = headers.get(h, "MISSING")
            status = "✓" if val != "MISSING" else "✗"
            lines.append(f"  {status} {h}: {val}")

        lines.append("\nAll Headers:")
        for k, v in headers.items():
            lines.append(f"  {k}: {v}")

        return "\n".join(lines)
    except Exception as e:
        return f"Error fetching {url}: {e}"


def http_fetch(url: str, method: str = "GET", headers: dict = None, body: str = None) -> str:
    """Fetch a URL and return response."""
    try:
        kwargs = {"timeout": 30.0, "follow_redirects": True, "verify": False}
        if headers:
            kwargs["headers"] = headers
        if body and method in ("POST", "PUT"):
            kwargs["content"] = body

        r = httpx.request(method, url, **kwargs)
        resp_headers = "\n".join(f"  {k}: {v}" for k, v in r.headers.items())
        body_text = r.text[:10000]

        return f"HTTP {r.status_code} {method} {url}\n\nHeaders:\n{resp_headers}\n\nBody:\n{body_text}"
    except Exception as e:
        return f"Error: {e}"


def http_methods(url: str) -> str:
    """Test which HTTP methods are allowed."""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    results = []
    for m in methods:
        try:
            r = httpx.request(m, url, timeout=10.0, follow_redirects=False, verify=False)
            results.append(f"  {m}: {r.status_code}")
        except Exception:
            results.append(f"  {m}: ERROR")
    return f"HTTP Methods for {url}:\n" + "\n".join(results)


def cookie_check(url: str) -> str:
    """Analyze cookie security attributes."""
    try:
        r = httpx.get(url, timeout=15.0, follow_redirects=True, verify=False)
        cookies = r.headers.get_list("set-cookie")
        if not cookies:
            return f"No cookies set by {url}"

        lines = [f"Cookies from {url}:", ""]
        for c in cookies:
            lines.append(f"  Raw: {c}")
            c_lower = c.lower()
            flags = []
            if "secure" in c_lower:
                flags.append("✓ Secure")
            else:
                flags.append("✗ Secure MISSING")
            if "httponly" in c_lower:
                flags.append("✓ HttpOnly")
            else:
                flags.append("✗ HttpOnly MISSING")
            if "samesite" in c_lower:
                flags.append("✓ SameSite")
            else:
                flags.append("✗ SameSite MISSING")
            lines.append(f"  Flags: {', '.join(flags)}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


def ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
              extensions: str = "") -> str:
    """Web fuzzing with ffuf."""
    cmd = f"ffuf -u {shlex.quote(url)} -w {shlex.quote(wordlist)} -mc all -fc 404 -t 50 -timeout 10"
    if extensions:
        cmd += f" -e {shlex.quote(extensions)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        return (result.stdout + result.stderr).strip()[:10000] or "No results"
    except subprocess.TimeoutExpired:
        return "Fuzzing timed out"
    except Exception as e:
        return f"Error: {e}"


def katana_crawl(targets: str, depth: int = 3) -> str:
    """Deep web crawler."""
    cmd = f"katana -u {shlex.quote(targets)} -d {depth} -silent -jc -kf"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        return result.stdout.strip()[:10000] or "No endpoints discovered"
    except subprocess.TimeoutExpired:
        return "Crawl timed out"
    except Exception as e:
        return f"Error: {e}"


def waybackurls_fetch(domain: str) -> str:
    """Fetch historical URLs from Wayback Machine."""
    cmd = f"echo {shlex.quote(domain)} | waybackurls"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        urls = result.stdout.strip().split("\n")
        urls = [u for u in urls if u.strip()]
        if not urls:
            return f"No historical URLs for {domain}"
        return f"Found {len(urls)} historical URLs for {domain}:\n" + "\n".join(urls[:200])
    except Exception as e:
        return f"Error: {e}"
