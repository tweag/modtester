"""
Brute-Force and Password Tools
- feroxbuster: Fast directory brute-forcing
- gobuster: Directory brute-forcing (dir mode)
"""
import subprocess
from typing import Optional, List


def feroxbuster_scan(url: str, wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
                     threads: int = 50, depth: int = 2, extensions: Optional[str] = None,
                     status_codes: str = "200,204,301,302,307,401,403,405") -> str:
    """
    Fast directory and file brute-forcing using feroxbuster.
    
    Args:
        url: Target URL (e.g., "https://example.com")
        wordlist: Path to wordlist file
        threads: Number of concurrent threads (default 50)
        depth: Recursion depth (default 2)
        extensions: File extensions to search (e.g., "php,html,js")
        status_codes: HTTP status codes to include in results
    
    Returns:
        Discovered directories and files
    """
    try:
        cmd = [
            "feroxbuster",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-d", str(depth),
            "-s", status_codes,
            "--no-state",
            "-q"  # Quiet mode for cleaner output
        ]
        
        if extensions:
            cmd.extend(["-x", extensions])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        output = result.stdout if result.stdout else ""
        if result.stderr and "error" in result.stderr.lower():
            output += f"\nWarnings: {result.stderr}"
        return output if output.strip() else "No results found"
    except subprocess.TimeoutExpired:
        return "Error: Scan timed out (10 minute limit)"
    except FileNotFoundError:
        return "Error: feroxbuster not found. Install with: cargo install feroxbuster"
    except Exception as e:
        return f"Error: {e}"


def gobuster_dir(url: str, wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
                 threads: int = 50, extensions: Optional[str] = None,
                 status_codes: str = "200,204,301,302,307,401,403") -> str:
    """
    Directory brute-forcing using gobuster.
    
    Args:
        url: Target URL
        wordlist: Path to wordlist
        threads: Number of threads
        extensions: File extensions (e.g., "php,html,txt")
        status_codes: Status codes to show
    
    Returns:
        Discovered paths
    """
    try:
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-s", status_codes,
            "-q",  # Quiet
            "--no-progress"
        ]
        
        if extensions:
            cmd.extend(["-x", extensions])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        output = result.stdout if result.stdout else ""
        if result.stderr and "error" in result.stderr.lower():
            output += f"\nWarnings: {result.stderr}"
        return output if output.strip() else "No results found"
    except subprocess.TimeoutExpired:
        return "Error: Scan timed out (10 minute limit)"
    except FileNotFoundError:
        return "Error: gobuster not found. Install with: apt install gobuster"
    except Exception as e:
        return f"Error: {e}"
