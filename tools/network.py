"""Network scanning tools — nmap, masscan."""
import subprocess
import shlex
from urllib.parse import urlparse


def _extract_host(target: str) -> str:
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        return parsed.netloc.split(":")[0]
    return target.split("/")[0].split(":")[0]


def nmap_scan(target: str, scan_type: str = "quick", ports: str = "") -> str:
    """Port scan with nmap."""
    host = _extract_host(target)

    scan_flags = {
        "quick": "-sV --top-ports 1000",
        "full": "-sV -p-",
        "stealth": "-sS -sV --top-ports 1000",
        "udp": "-sU --top-ports 100",
        "comprehensive": "-sV -sC -O -p- --min-rate 1000",
    }

    flags = scan_flags.get(scan_type, scan_flags["quick"])
    cmd = f"nmap {flags} {shlex.quote(host)}"
    if ports:
        cmd = f"nmap {flags} -p {shlex.quote(ports)} {shlex.quote(host)}"

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=300
        )
        output = result.stdout + result.stderr
        return output.strip() if output.strip() else "No results"
    except subprocess.TimeoutExpired:
        return "Scan timed out (300s limit)"
    except Exception as e:
        return f"Error: {e}"


def masscan_scan(target: str, ports: str = "1-65535", rate: int = 1000) -> str:
    """Ultra-fast port scanner."""
    host = _extract_host(target)
    rate = min(rate, 10000)  # Safety cap

    cmd = f"masscan {shlex.quote(host)} -p {shlex.quote(ports)} --rate {rate}"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=300
        )
        return (result.stdout + result.stderr).strip() or "No results"
    except subprocess.TimeoutExpired:
        return "Scan timed out"
    except Exception as e:
        return f"Error: {e}"
