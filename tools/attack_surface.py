"""
Attack Surface Map Generator
Produces a standardized visual tree of the target's attack surface.

Pulls from target_state data (hosts, ports, vulns) and any additional
endpoints/notes provided by the AI. Renders a consistent tree layout
every time — no AI improvisation, same structure, same format.

Called after recon phase, before exploitation begins.
"""
import os
import json


STATE_DIR = "/tmp/targets"
STATE_FILE = os.path.join(STATE_DIR, "state.json")


def _load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def _categorize_endpoint(endpoint: str, vuln_type: str = "", notes: str = "") -> str:
    ep = endpoint.lower()
    if any(p in ep for p in ["/admin", "/dashboard", "/panel", "/manage", "/console",
                              "/sup3r", "/super", "/backend", "/cms", "/wp-admin"]):
        return "admin"
    if any(p in ep for p in ["/login", "/signin", "/auth", "/register", "/signup",
                              "/forgot", "/reset", "/password", "/logout", "/oauth",
                              "/token", "/session", "/2fa", "/mfa"]):
        return "auth"
    if any(p in ep for p in ["/api/", "/api.", "/graphql", "/rest/", "/v1/", "/v2/",
                              "/v3/", "/swagger", "/openapi", "/docs", "/schema",
                              "/webhook"]):
        return "api"
    if any(p in ep for p in ["/internal", "/meta-data", "/169.254", "/127.0.0.1",
                              "localhost", "/config.json", "/secret", "/.env"]):
        return "internal"
    if any(p in ep for p in ["/upload", "/download", "/file", "/media", "/static",
                              "/assets", "/images"]):
        return "resources"
    return "public"


def _shorten_vuln(vuln_type: str) -> str:
    if not vuln_type:
        return ""
    short = {
        "sql injection": "SQLi", "sqli": "SQLi",
        "cross-site scripting": "XSS", "xss": "XSS",
        "server-side request forgery": "SSRF", "ssrf": "SSRF",
        "broken object level authorization": "BOLA", "bola": "BOLA", "idor": "IDOR",
        "broken object property level authorization": "BOPLA", "bopla": "BOPLA",
        "remote code execution": "RCE", "rce": "RCE",
        "local file inclusion": "LFI", "lfi": "LFI",
        "cross-site request forgery": "CSRF", "csrf": "CSRF",
        "information disclosure": "InfoDisc",
        "prompt injection": "PromptInj",
        "race condition": "RaceCond",
        "mass assignment": "MassAssign",
        "broken auth": "BrokenAuth",
        "access control": "AccessCtrl",
        "no auth": "NoAuth",
    }
    vt = vuln_type.lower()
    for long_form, short_form in short.items():
        if long_form in vt:
            return short_form
    return vuln_type[:15]


def attack_surface_map(
    host: str = "",
    endpoints: str = "",
    title: str = "",
) -> str:
    """
    Generate a visual attack surface map from target_state data.

    Call this after recon to produce a standardized tree of the target's
    attack surface. The map shows host info, categorized endpoints, and
    vulnerability labels.

    Args:
        host: Target host to map (maps all hosts if empty)
        endpoints: Additional endpoints as JSON array of objects, each with
                   "path", "status" (HTTP code), "vuln_type", "severity", "notes".
                   Example: [{"path":"/login","status":200,"vuln_type":"SQLi","severity":"CRITICAL","notes":"POST param"}]
                   Use this to add endpoints not yet in target_state.
        title: Optional title override (default: "Attack Surface Map")

    Returns:
        Formatted attack surface tree
    """
    state = _load_state()
    map_title = title or "Attack Surface Map"

    # Parse additional endpoints
    extra_endpoints = []
    if endpoints:
        try:
            extra_endpoints = json.loads(endpoints) if isinstance(endpoints, str) else endpoints
        except (json.JSONDecodeError, TypeError):
            extra_endpoints = []

    # Select hosts
    hosts_to_map = {}
    if host:
        key = host.strip().lower()
        if key in state:
            hosts_to_map[key] = state[key]
        else:
            hosts_to_map[key] = {
                "host": host, "ip": "", "waf": "", "technology": "",
                "ports": [], "vulnerabilities": [], "credentials": [],
                "services": [], "scans_completed": [],
            }
    else:
        hosts_to_map = state if state else {}

    if not hosts_to_map and not extra_endpoints:
        return (
            "No target data available. Register targets first:\n"
            "  target_add host=<domain> waf=<waf> technology=<tech>\n"
            "  target_add_vuln host=<domain> title=<vuln> endpoint=<path>\n"
            "Then call attack_surface_map again."
        )

    lines = [f"### {map_title}", "```"]

    for key, target in hosts_to_map.items():
        hostname = target.get("host", key)
        waf = target.get("waf", "")
        tech = target.get("technology", "")

        # Host header
        meta_parts = []
        if waf:
            meta_parts.append(waf)
        if tech:
            tech_items = [t.strip() for t in tech.split(",")][:3]
            meta_parts.append(", ".join(tech_items))
        host_label = hostname
        if meta_parts:
            host_label += f" ({', '.join(meta_parts)})"

        lines.append(f"                {host_label}")
        lines.append(f"                       │")

        # Collect endpoints
        all_endpoints = {}

        for v in target.get("vulnerabilities", []):
            ep = v.get("endpoint", "")
            if ep:
                all_endpoints[ep] = {
                    "path": ep,
                    "vuln_type": v.get("type", v.get("title", "")),
                    "severity": v.get("severity", ""),
                    "notes": v.get("notes", ""),
                    "verified": v.get("verified", False),
                    "status": "",
                }

        for ep in extra_endpoints:
            path = ep.get("path", "")
            if path:
                if path in all_endpoints:
                    existing = all_endpoints[path]
                    if ep.get("vuln_type") and not existing.get("vuln_type"):
                        existing["vuln_type"] = ep["vuln_type"]
                    if ep.get("status"):
                        existing["status"] = str(ep["status"])
                    if ep.get("notes"):
                        existing["notes"] = ep["notes"]
                else:
                    all_endpoints[path] = {
                        "path": path,
                        "vuln_type": ep.get("vuln_type", ""),
                        "severity": ep.get("severity", ""),
                        "notes": ep.get("notes", ""),
                        "verified": False,
                        "status": str(ep.get("status", "")),
                    }

        # Categorize
        cat_order = ["public", "auth", "api", "admin", "internal", "resources"]
        categories = {k: [] for k in cat_order}
        for path, info in sorted(all_endpoints.items()):
            cat = _categorize_endpoint(path, info.get("vuln_type", ""), info.get("notes", ""))
            categories[cat].append(info)
        active_cats = [(k, categories[k]) for k in cat_order if categories[k]]

        cat_display = {
            "public": "Public Pages",
            "auth": "Auth Endpoints",
            "api": "API Endpoints",
            "admin": "Admin Panel",
            "internal": "Internal (SSRF targets)",
            "resources": "Resources",
        }

        # Top-level branch connector
        if len(active_cats) >= 3:
            lines.append(f"          ┌─────────────┼─────────────┐")
            lines.append(f"          │             │             │")
        elif len(active_cats) == 2:
            lines.append(f"          ┌─────────────┴─────────────┐")
            lines.append(f"          │                           │")

        # Render each category vertically
        for ci, (cat_key, ep_list) in enumerate(active_cats):
            cat_name = cat_display.get(cat_key, cat_key)
            lines.append(f"  {cat_name}")

            sorted_eps = sorted(ep_list, key=lambda x: x.get("path", ""))
            for ei, ep in enumerate(sorted_eps):
                is_last = (ei == len(sorted_eps) - 1)
                connector = "└──" if is_last else "├──"

                path = ep.get("path", "?")
                vuln = _shorten_vuln(ep.get("vuln_type", ""))
                status = ep.get("status", "")
                notes = ep.get("notes", "")

                label = path
                parts = []
                if status:
                    parts.append(status)
                if vuln:
                    parts.append(f"({vuln})")
                elif notes:
                    short_note = notes[:20]
                    parts.append(f"({short_note})")
                if parts:
                    label += " " + " ".join(parts)

                lines.append(f"    {connector} {label}")

            # Spacing between categories
            if ci < len(active_cats) - 1:
                lines.append("")

        lines.append("")

        # Credentials
        creds = target.get("credentials", [])
        if creds:
            cred_strs = []
            for c in creds:
                ctype = c.get("type", "?")
                user = c.get("username", "")
                source = c.get("source", "")
                if user:
                    cred_strs.append(f"{ctype}: {user}:*** (via {source})" if source else f"{ctype}: {user}:***")
                else:
                    cred_strs.append(f"{ctype} (via {source})" if source else ctype)
            lines.append("  Credentials Obtained:")
            for cs in cred_strs:
                lines.append(f"    • {cs}")
            lines.append("")

        # Ports
        ports = target.get("ports", [])
        if ports:
            port_strs = []
            for p in sorted(ports, key=lambda x: x.get("port", 0)):
                svc = p.get("service", "?")
                ver = p.get("version", "")
                ps = f"{p['port']}/{p.get('protocol','tcp')} {svc}"
                if ver:
                    ps += f" ({ver})"
                port_strs.append(ps)
            lines.append(f"  Open Ports: {' | '.join(port_strs)}")
            lines.append("")

        # Priority attack chains — CRITICAL and HIGH
        vulns = target.get("vulnerabilities", [])
        sev_order = {"CRITICAL": 0, "HIGH": 1}
        priority_vulns = sorted(
            [v for v in vulns if v.get("severity") in sev_order],
            key=lambda v: sev_order.get(v.get("severity", ""), 99)
        )

        if priority_vulns:
            lines.append("  Highest-priority attack chains:")
            for i, v in enumerate(priority_vulns[:7], 1):
                ep = v.get("endpoint", "?")
                vtype = v.get("type", v.get("title", "?"))
                short = _shorten_vuln(vtype)
                sev = v.get("severity", "?")
                verified = "✓" if v.get("verified") else "?"
                lines.append(f"    {i}. [{verified}] {sev} — {short} on {ep}")

        lines.append("")

    lines.append("```")

    total_hosts = len(hosts_to_map)
    total_eps = sum(len(t.get("vulnerabilities", [])) for t in hosts_to_map.values()) + len(extra_endpoints)
    lines.append(f"\n{total_hosts} host(s) | {total_eps} endpoint(s) mapped")

    return "\n".join(lines)
