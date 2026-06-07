"""
Target State Tracker
Maintains per-host intelligence across multi-target assessments.

The AI uses these tools to:
  - Register targets as it discovers them
  - Record open ports, services, technologies, credentials, vulns per host
  - Query what it knows about a host before scanning
  - Track assessment progress across multiple hosts
  - Avoid redundant scans ("already ran nmap on this host")

State persists in-memory and on disk at /tmp/targets/state.json.
"""
import os
import json
from typing import Optional
from datetime import datetime


STATE_DIR = "/tmp/targets"
STATE_FILE = os.path.join(STATE_DIR, "state.json")

# Per-assessment context (set by chat_api before tool execution)
_current_assessment_id: Optional[str] = None


def set_assessment_context(assessment_id: Optional[str]):
    """Set the current assessment context for DynamoDB persistence."""
    global _current_assessment_id
    _current_assessment_id = assessment_id


def _load_state() -> dict:
    """Load target state for the CURRENT assessment.

    With an assessment context set we isolate STRICTLY to that assessment's
    DynamoDB record and never read the shared local file — otherwise host/vuln
    intelligence from a previous assessment would leak into a new one. The shared
    local file is only used in standalone/CLI mode (no assessment context).
    """
    global _current_assessment_id
    if _current_assessment_id:
        try:
            import db as _db
            return _db.target_state_get(_current_assessment_id) or {}
        except Exception:
            return {}
    # No assessment context (standalone/CLI) — use the shared local file.
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def _save_state(state: dict):
    """Save target state for the CURRENT assessment.

    With an assessment context set we persist ONLY to that assessment's DynamoDB
    record (no shared local file) so host/vuln state can never bleed across
    assessments. Without a context (standalone/CLI) we use the shared local file.
    """
    global _current_assessment_id
    if _current_assessment_id:
        try:
            import db as _db
            _db.target_state_save(_current_assessment_id, state)
        except Exception:
            pass
        return
    # No assessment context (standalone/CLI) — use the shared local file.
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def target_add(
    host: str,
    hostname: str = "",
    ip: str = "",
    os_info: str = "",
    waf: str = "",
    technology: str = "",
    notes: str = "",
) -> str:
    """
    Register a target host. Call this when you discover a new host during recon.

    Args:
        host: Primary identifier — domain or IP (e.g., "vulnbank.org" or "10.0.0.5")
        hostname: Resolved hostname (if host is an IP)
        ip: Resolved IP (if host is a domain)
        os_info: Detected OS or server info
        waf: Detected WAF (e.g., "Cloudflare", "AWS WAF", "none detected")
        technology: Tech stack (e.g., "Python/Flask, Werkzeug, PostgreSQL")
        notes: Any other recon notes

    Returns:
        Confirmation with target summary
    """
    state = _load_state()

    key = host.strip().lower()
    now = datetime.now().isoformat()

    if key in state:
        # Update existing target
        target = state[key]
        if hostname:
            target["hostname"] = hostname
        if ip:
            target["ip"] = ip
        if os_info:
            target["os"] = os_info
        if waf:
            target["waf"] = waf
        if technology:
            # Append new tech, avoid duplicates
            existing = set(t.strip() for t in target.get("technology", "").split(",") if t.strip())
            new_tech = set(t.strip() for t in technology.split(",") if t.strip())
            target["technology"] = ", ".join(sorted(existing | new_tech))
        if notes:
            target["notes"] = notes
        target["updated"] = now
        action = "Updated"
    else:
        state[key] = {
            "host": host,
            "hostname": hostname,
            "ip": ip,
            "os": os_info,
            "waf": waf,
            "technology": technology,
            "notes": notes,
            "ports": [],
            "services": [],
            "credentials": [],
            "vulnerabilities": [],
            "scans_completed": [],
            "created": now,
            "updated": now,
        }
        action = "Added"

    _save_state(state)
    return f"{action} target: {key} | Tech: {technology or 'unknown'} | WAF: {waf or 'unknown'}"


def target_add_port(
    host: str,
    port: int,
    protocol: str = "tcp",
    service: str = "",
    version: str = "",
    state_info: str = "open",
) -> str:
    """
    Record an open port and service on a target. Call after nmap/masscan results.

    Args:
        host: Target host
        port: Port number
        protocol: tcp or udp
        service: Service name (e.g., "http", "ssh", "mysql")
        version: Version string (e.g., "Apache/2.4.49", "OpenSSH 8.9")
        state_info: Port state (open, filtered, closed)

    Returns:
        Confirmation
    """
    state = _load_state()
    key = host.strip().lower()

    if key not in state:
        # Auto-register target
        target_add(host)
        state = _load_state()

    target = state[key]

    # Avoid duplicate ports
    existing_ports = {(p["port"], p["protocol"]) for p in target.get("ports", [])}
    if (port, protocol) not in existing_ports:
        target["ports"].append({
            "port": port,
            "protocol": protocol,
            "service": service,
            "version": version,
            "state": state_info,
        })

    # Track unique services
    if service and service not in target.get("services", []):
        target["services"].append(service)

    target["updated"] = datetime.now().isoformat()
    _save_state(state)

    return f"{key}:{port}/{protocol} — {service} {version} ({state_info})"


def target_add_credential(
    host: str,
    credential_type: str,
    username: str = "",
    password: str = "",
    token: str = "",
    source: str = "",
    notes: str = "",
) -> str:
    """
    Record discovered credentials for a target. Call whenever you find creds.

    Args:
        host: Target host
        credential_type: Type — "password", "jwt_secret", "api_key", "ssh_key", "token", "db_creds", "aws_key"
        username: Username or key ID
        password: Password or secret value
        token: Full token string (for JWT, API keys)
        source: Where you found it (e.g., "SSRF to /internal/secret", "default creds check")
        notes: Additional context

    Returns:
        Confirmation (credentials are masked in output for safety)
    """
    state = _load_state()
    key = host.strip().lower()

    if key not in state:
        target_add(host)
        state = _load_state()

    target = state[key]
    cred = {
        "type": credential_type,
        "username": username,
        "password": password,
        "token": token[:50] + "..." if len(token) > 50 else token,
        "source": source,
        "notes": notes,
        "timestamp": datetime.now().isoformat(),
    }

    target.setdefault("credentials", []).append(cred)
    target["updated"] = datetime.now().isoformat()
    _save_state(state)

    # Mask password in confirmation
    masked = password[:2] + "***" if len(password) > 2 else "***"
    return f"Credential recorded: {credential_type} on {key} — {username}:{masked} (source: {source})"


def target_add_vuln(
    host: str,
    title: str,
    severity: str = "HIGH",
    endpoint: str = "",
    vuln_type: str = "",
    verified: bool = False,
    notes: str = "",
) -> str:
    """
    Record a vulnerability on a target. Call as you discover vulns.
    This is a lightweight tracker — use report_add_finding for the full report entry.

    Args:
        host: Target host
        title: Vulnerability title
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        endpoint: Affected endpoint (e.g., "/api/login", "/upload_profile_picture_url")
        vuln_type: Category (e.g., "SQLi", "SSRF", "BOLA", "XSS")
        verified: Whether this has been confirmed through exploitation
        notes: Additional context

    Returns:
        Confirmation
    """
    state = _load_state()
    key = host.strip().lower()

    if key not in state:
        target_add(host)
        state = _load_state()

    target = state[key]
    vuln = {
        "title": title,
        "severity": severity.upper(),
        "endpoint": endpoint,
        "type": vuln_type,
        "verified": verified,
        "notes": notes,
        "timestamp": datetime.now().isoformat(),
    }

    target.setdefault("vulnerabilities", []).append(vuln)
    target["updated"] = datetime.now().isoformat()
    _save_state(state)

    status = "CONFIRMED" if verified else "UNCONFIRMED"
    return f"[{severity}] {title} on {key}{endpoint} ({status})"


def target_log_scan(host: str, tool_name: str, notes: str = "") -> str:
    """
    Log that a scan was completed on a target. Prevents redundant scans.

    Args:
        host: Target host
        tool_name: Tool that was run (e.g., "nmap_scan", "nuclei_scan")
        notes: Scan notes or summary

    Returns:
        Confirmation
    """
    state = _load_state()
    key = host.strip().lower()

    if key not in state:
        target_add(host)
        state = _load_state()

    target = state[key]
    scan_entry = {
        "tool": tool_name,
        "notes": notes,
        "timestamp": datetime.now().isoformat(),
    }

    target.setdefault("scans_completed", []).append(scan_entry)
    target["updated"] = datetime.now().isoformat()
    _save_state(state)

    return f"Logged: {tool_name} on {key}"


def target_get(host: str) -> str:
    """
    Get everything known about a target. Call before scanning to check
    what you already know and avoid redundant work.

    Args:
        host: Target host to look up

    Returns:
        Full target intelligence summary
    """
    state = _load_state()
    key = host.strip().lower()

    if key not in state:
        return f"No data for {key}. Run recon first."

    t = state[key]

    lines = [f"TARGET: {t['host']}"]

    if t.get("ip"):
        lines.append(f"  IP: {t['ip']}")
    if t.get("hostname"):
        lines.append(f"  Hostname: {t['hostname']}")
    if t.get("os"):
        lines.append(f"  OS: {t['os']}")
    if t.get("waf"):
        lines.append(f"  WAF: {t['waf']}")
    if t.get("technology"):
        lines.append(f"  Tech: {t['technology']}")

    # Ports
    ports = t.get("ports", [])
    if ports:
        lines.append(f"\n  PORTS ({len(ports)}):")
        for p in ports:
            lines.append(f"    {p['port']}/{p['protocol']} — {p.get('service', '?')} {p.get('version', '')}")

    # Credentials
    creds = t.get("credentials", [])
    if creds:
        lines.append(f"\n  CREDENTIALS ({len(creds)}):")
        for c in creds:
            masked_pw = c.get("password", "")[:2] + "***" if c.get("password") else ""
            lines.append(f"    [{c['type']}] {c.get('username', '')}:{masked_pw} (via {c.get('source', '?')})")

    # Vulnerabilities
    vulns = t.get("vulnerabilities", [])
    if vulns:
        lines.append(f"\n  VULNERABILITIES ({len(vulns)}):")
        for v in vulns:
            status = "✓" if v.get("verified") else "?"
            lines.append(f"    [{status}] {v['severity']:8s} {v['title']} @ {v.get('endpoint', '?')}")

    # Scans completed
    scans = t.get("scans_completed", [])
    if scans:
        tool_names = list(set(s["tool"] for s in scans))
        lines.append(f"\n  SCANS COMPLETED: {', '.join(tool_names)}")

    if t.get("notes"):
        lines.append(f"\n  NOTES: {t['notes']}")

    return "\n".join(lines)


def target_list() -> str:
    """
    List all tracked targets with a summary of what's known.

    Returns:
        Summary table of all targets
    """
    state = _load_state()

    if not state:
        return "No targets tracked. Use target_add when you discover hosts."

    lines = [f"TARGETS ({len(state)}):", ""]

    for key, t in state.items():
        port_count = len(t.get("ports", []))
        cred_count = len(t.get("credentials", []))
        vuln_count = len(t.get("vulnerabilities", []))
        scan_count = len(t.get("scans_completed", []))
        confirmed = sum(1 for v in t.get("vulnerabilities", []) if v.get("verified"))

        waf = t.get("waf", "")
        waf_str = f" [{waf}]" if waf else ""

        lines.append(
            f"  {t['host']}{waf_str}: "
            f"{port_count} ports, {cred_count} creds, "
            f"{vuln_count} vulns ({confirmed} confirmed), "
            f"{scan_count} scans"
        )

    return "\n".join(lines)


def target_clear() -> str:
    """
    Clear all target tracking data. Use before starting a new assessment.

    Returns:
        Confirmation
    """
    _save_state({})
    return "All target data cleared."
