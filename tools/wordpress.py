"""
WordPress Security Tools
WPScan for WordPress vulnerability scanning.
"""
import subprocess
import re
import os


def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from output."""
    return re.sub(r'\x1B\[[0-9;]*[mGK]', '', text)


def wpscan_scan(url: str, enumerate: list = None, detection_mode: str = "mixed",
                api_token: str = None, random_user_agent: bool = True,
                force: bool = False, disable_tls_checks: bool = False) -> str:
    """
    Scan WordPress sites for vulnerabilities using WPScan.
    
    Args:
        url: Target WordPress URL
        enumerate: What to enumerate: vp (vulnerable plugins), ap (all plugins), 
                   p (popular plugins), vt (vulnerable themes), at (all themes),
                   t (popular themes), tt (timthumbs), cb (config backups), 
                   dbe (db exports), u (users), m (media)
        detection_mode: mixed, passive, or aggressive
        api_token: WPScan API token (falls back to WPSCAN_API_TOKEN env var)
        random_user_agent: Use random user agents
        force: Force scan even if WordPress not detected
        disable_tls_checks: Disable TLS certificate verification
    
    Returns:
        WPScan results
    
    Note: Set WPSCAN_API_TOKEN environment variable for vulnerability database access.
    """
    # Use env var if api_token not provided
    token = api_token or os.environ.get("WPSCAN_API_TOKEN")
    
    cmd = ["wpscan", "--url", url, "--no-banner"]
    
    if enumerate:
        cmd.extend(["-e", ",".join(enumerate)])
    else:
        cmd.extend(["-e", "vp,vt,tt,cb,dbe,u"])  # Default enumeration
    
    if detection_mode:
        cmd.extend(["--detection-mode", detection_mode])
    
    if token:
        cmd.extend(["--api-token", token])
    
    if random_user_agent:
        cmd.append("--random-user-agent")
    
    if force:
        cmd.append("--force")
    
    if disable_tls_checks:
        cmd.append("--disable-tls-checks")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # WordPress scans can take a while
        )
        output = result.stdout + result.stderr
        return strip_ansi(output)
    except subprocess.TimeoutExpired:
        return "Error: WPScan timed out after 600 seconds"
    except FileNotFoundError:
        return "Error: wpscan not found. Install with: gem install wpscan"
    except Exception as e:
        return f"Error running wpscan: {e}"
