"""DNS tools — dns_lookup, whois_lookup, crtsh_lookup."""
import subprocess
import shlex
import json
import httpx


def dns_lookup(domain: str, record_type: str = "A") -> str:
    """DNS record lookup."""
    cmd = f"dig +short {shlex.quote(domain)} {shlex.quote(record_type)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout.strip()
        if not output:
            return f"No {record_type} records found for {domain}"
        return f"{record_type} records for {domain}:\n{output}"
    except Exception as e:
        return f"Error: {e}"


def whois_lookup(domain: str) -> str:
    """WHOIS domain registration information."""
    cmd = f"whois {shlex.quote(domain)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()[:5000] or "No WHOIS data"
    except Exception as e:
        return f"Error: {e}"


def crtsh_lookup(domain: str) -> str:
    """Certificate transparency subdomain discovery."""
    try:
        r = httpx.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30.0,
            follow_redirects=True,
        )
        if r.status_code != 200:
            return f"crt.sh returned {r.status_code}"
        entries = r.json()
        names = sorted(set(
            e.get("name_value", "").strip()
            for e in entries
            if e.get("name_value")
        ))
        if not names:
            return f"No certificates found for {domain}"
        return f"Certificate transparency — {len(names)} unique names for {domain}:\n" + "\n".join(names[:100])
    except Exception as e:
        return f"Error: {e}"
