"""Injection & protocol tools — commix, sslscan."""
import subprocess
import shlex


def commix_scan(url: str, data: str = "", param: str = "") -> str:
    """Command injection detection and exploitation."""
    cmd = f"commix -u {shlex.quote(url)} --batch --level=3"
    if data:
        cmd += f" --data={shlex.quote(data)}"
    if param:
        cmd += f" -p {shlex.quote(param)}"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return (result.stdout + result.stderr).strip()[:10000] or "No command injection found"
    except subprocess.TimeoutExpired:
        return "Command injection testing timed out"
    except Exception as e:
        return f"Error: {e}"


def sslscan_check(target: str) -> str:
    """Check SSL/TLS cipher suites and certificate."""
    cmd = f"sslscan --no-colour {shlex.quote(target)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return (result.stdout + result.stderr).strip()[:5000] or "No SSL data"
    except Exception as e:
        return f"Error: {e}"
