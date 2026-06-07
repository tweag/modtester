"""Enumeration tools — nikto, testssl, enum4linux, netcat, smbclient."""
import subprocess
import shlex
from urllib.parse import urlparse


def nikto_scan(target: str) -> str:
    """Web server vulnerability scanner."""
    cmd = f"nikto -h {shlex.quote(target)} -Tuning 1234567890 -timeout 10 -maxtime 120"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
        return (result.stdout + result.stderr).strip()[:10000] or "No findings"
    except subprocess.TimeoutExpired:
        return "Nikto scan timed out"
    except Exception as e:
        return f"Error: {e}"


def testssl_scan(target: str, port: str = "443") -> str:
    """TLS/SSL configuration analysis."""
    cmd = f"testssl.sh --color 0 --quiet {shlex.quote(target)}:{shlex.quote(port)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return (result.stdout + result.stderr).strip()[:10000] or "No results"
    except subprocess.TimeoutExpired:
        return "TLS scan timed out"
    except Exception as e:
        return f"Error: {e}"


def enum4linux_scan(target: str) -> str:
    """SMB/NetBIOS enumeration."""
    host = target.split("/")[0].split(":")[0]
    cmd = f"enum4linux-ng -A {shlex.quote(host)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return (result.stdout + result.stderr).strip()[:10000] or "No SMB data"
    except subprocess.TimeoutExpired:
        return "SMB enumeration timed out"
    except Exception as e:
        return f"Error: {e}"


def netcat_connect(host: str, port: int, data: str = "", timeout: int = 10) -> str:
    """Banner grab via netcat."""
    timeout = min(timeout, 30)
    if data:
        cmd = f"echo -n {shlex.quote(data)} | nc -w {timeout} {shlex.quote(host)} {port}"
    else:
        cmd = f"nc -w {timeout} {shlex.quote(host)} {port}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout + 5)
        return (result.stdout + result.stderr).strip() or f"Connected to {host}:{port} — no banner"
    except subprocess.TimeoutExpired:
        return f"Connection to {host}:{port} timed out"
    except Exception as e:
        return f"Error: {e}"


def smbclient_list(target: str) -> str:
    """List SMB shares."""
    host = target.split("/")[0].split(":")[0]
    cmd = f"smbclient -L //{shlex.quote(host)} -N"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return (result.stdout + result.stderr).strip() or "No shares found"
    except Exception as e:
        return f"Error: {e}"
