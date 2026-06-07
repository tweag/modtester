"""Recon tools — subfinder, arjun."""
import subprocess
import shlex


def subfinder_enum(domain: str) -> str:
    """Passive subdomain enumeration."""
    cmd = f"subfinder -d {shlex.quote(domain)} -silent"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
        subs = [s for s in result.stdout.strip().split("\n") if s.strip()]
        if not subs:
            return f"No subdomains found for {domain}"
        return f"Found {len(subs)} subdomains for {domain}:\n" + "\n".join(sorted(subs))
    except subprocess.TimeoutExpired:
        return "Subdomain enumeration timed out"
    except Exception as e:
        return f"Error: {e}"


def arjun_scan(url: str) -> str:
    """Discover hidden HTTP parameters."""
    cmd = f"arjun -u {shlex.quote(url)} --stable"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return (result.stdout + result.stderr).strip()[:5000] or "No hidden parameters found"
    except subprocess.TimeoutExpired:
        return "Parameter discovery timed out"
    except Exception as e:
        return f"Error: {e}"
