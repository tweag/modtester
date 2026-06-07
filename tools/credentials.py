"""
Credential Testing Tools
- credential_test: Brute-force / credential testing via hydra
- default_creds_check: Test common default credentials
"""
import subprocess
from typing import Optional


def credential_test(
    target: str,
    service: str = "ssh",
    username: Optional[str] = None,
    username_list: Optional[str] = None,
    password: Optional[str] = None,
    password_list: str = "/usr/share/wordlists/passwords/top-1000.txt",
    port: Optional[int] = None,
    threads: int = 4,
    timeout: int = 30,
    additional_args: Optional[str] = None
) -> str:
    """
    Test credentials against a network service using hydra.

    Args:
        target: Target IP or hostname
        service: Service to test - ssh, ftp, http-get, http-post-form, smb,
                 mysql, rdp, telnet, vnc, pop3, imap, smtp, snmp, mssql, postgres
        username: Single username to test
        username_list: Path to file with usernames (one per line)
        password: Single password to test
        password_list: Path to file with passwords (one per line)
        port: Service port (uses default if not specified)
        threads: Concurrent connections (default 4, max 16)
        timeout: Connection timeout per attempt in seconds
        additional_args: Extra hydra arguments as string (e.g., "/admin:^USER^:^PASS^:F=failed" for http-post-form)

    Returns:
        Discovered valid credentials or "no valid credentials found"
    """
    threads = min(threads, 16)

    try:
        cmd = ["hydra"]

        # Username
        if username:
            cmd.extend(["-l", username])
        elif username_list:
            cmd.extend(["-L", username_list])
        else:
            cmd.extend(["-l", "admin"])

        # Password
        if password:
            cmd.extend(["-p", password])
        else:
            cmd.extend(["-P", password_list])

        # Options
        cmd.extend(["-t", str(threads)])
        cmd.extend(["-w", str(timeout)])
        cmd.extend(["-f"])  # Stop on first valid pair
        cmd.extend(["-o", "/tmp/hydra_results.txt"])

        # Port
        if port:
            cmd.extend(["-s", str(port)])

        # Additional args for complex services like http-post-form
        if additional_args:
            cmd.extend([target, service, additional_args])
        else:
            cmd.extend([target, service])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        output = result.stdout if result.stdout else ""
        if result.stderr:
            # Filter out hydra banner noise
            stderr_lines = [
                line for line in result.stderr.split("\n")
                if line.strip() and "Hydra" not in line and "http://www.thc.org" not in line
            ]
            if stderr_lines:
                output += "\n" + "\n".join(stderr_lines)

        # Check for valid credentials in output
        if "login:" in output.lower() and "password:" in output.lower():
            return f"VALID CREDENTIALS FOUND:\n{output}"

        return output.strip() if output.strip() else "No valid credentials found."

    except subprocess.TimeoutExpired:
        return "Error: Credential test timed out (10 minute limit). Try fewer passwords or threads."
    except FileNotFoundError:
        return "Error: hydra not found."
    except Exception as e:
        return f"Error: {e}"


def default_creds_check(
    target: str,
    service: str = "ssh",
    port: Optional[int] = None
) -> str:
    """
    Test common default credentials against a service.
    Uses a small built-in list for speed.

    Args:
        target: Target IP or hostname
        service: Service type (ssh, ftp, mysql, telnet, vnc, snmp)
        port: Service port (uses default if not specified)

    Returns:
        Any valid default credentials found
    """
    # Common default credential pairs
    default_pairs = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("root", "toor"),
        ("root", "password"),
        ("user", "user"),
        ("test", "test"),
        ("guest", "guest"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
        ("postgres", "postgres"),
        ("mysql", "mysql"),
        ("ftp", "ftp"),
        ("anonymous", ""),
    ]

    results = [f"Default credential check for {service}://{target}\n"]
    found = []

    for username, password in default_pairs:
        try:
            cmd = ["hydra", "-l", username, "-p", password, "-t", "1", "-w", "10", "-f"]
            if port:
                cmd.extend(["-s", str(port)])
            cmd.extend([target, service])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr

            if "login:" in output.lower() and "password:" in output.lower():
                found.append(f"  {username}:{password}")
                results.append(f"[FOUND] {username}:{password}")

        except (subprocess.TimeoutExpired, Exception):
            continue

    if found:
        results.insert(1, f"VALID DEFAULT CREDENTIALS ({len(found)}):")
        results.append(f"\nTotal: {len(found)} valid credential pair(s)")
    else:
        results.append("No default credentials found.")

    return "\n".join(results)
