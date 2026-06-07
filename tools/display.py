"""
Tool Action Messages — argument-aware status messages for CLI and GUI.

Each tool maps to a callable(args) → human-readable status string.
These replace raw tool names in the UI so the experience feels like
an intelligent agent, not a function dispatcher.

Usage:
    from tools.display import get_action_message
    msg = get_action_message("nmap_scan", {"target": "10.10.10.5"})
    # → "Scanning ports on 10.10.10.5..."
"""


def _safe(args: dict, key: str, default: str = "") -> str:
    """Safely get a string value from args."""
    v = args.get(key, default)
    if isinstance(v, list):
        return ", ".join(str(i) for i in v[:3]) + ("..." if len(v) > 3 else "")
    return str(v) if v else default


# ---------------------------------------------------------------------------
# Action message templates — every registered tool gets one
# ---------------------------------------------------------------------------

TOOL_ACTION_MESSAGES = {
    # --- Reconnaissance ---
    "dns_lookup": lambda a: f"Resolving {_safe(a, 'record_type', 'A')} records for {_safe(a, 'domain', 'target')}...",
    "whois_lookup": lambda a: f"Querying WHOIS registration for {_safe(a, 'domain', 'target')}...",
    "crtsh_lookup": lambda a: f"Searching certificate transparency logs for {_safe(a, 'domain', 'target')}...",
    "subfinder_enum": lambda a: f"Enumerating subdomains for {_safe(a, 'domain', 'target')}...",
    "arjun_scan": lambda a: f"Discovering hidden parameters on {_safe(a, 'url', 'target')}...",
    "http_probe": lambda a: f"Probing {len(a.get('targets', []))} URLs for live hosts...",

    # --- Network ---
    "nmap_scan": lambda a: f"Scanning ports on {_safe(a, 'target', 'host')}...",
    "masscan_scan": lambda a: f"Fast scanning ports on {_safe(a, 'target', 'host')}...",
    "netcat_connect": lambda a: f"Connecting to {_safe(a, 'host')}:{_safe(a, 'port')}...",
    "netcat_listen": lambda a: f"Listening on port {_safe(a, 'port')}...",

    # --- Enumeration ---
    "nikto_scan": lambda a: f"Scanning web server at {_safe(a, 'target')}...",
    "testssl_scan": lambda a: f"Testing TLS/SSL configuration on {_safe(a, 'target')}:{_safe(a, 'port', '443')}...",
    "enum4linux_scan": lambda a: f"Enumerating SMB services on {_safe(a, 'target')}...",
    "smbclient_list": lambda a: f"Listing SMB shares on {_safe(a, 'target')}...",
    "sslscan_check": lambda a: f"Checking SSL/TLS ciphers on {_safe(a, 'target')}...",

    # --- Web Discovery ---
    "ffuf_fuzz": lambda a: f"Fuzzing {_safe(a, 'url', 'target')} for hidden paths...",
    "katana_crawl": lambda a: f"Crawling {_safe(a, 'targets', 'target')} (depth {_safe(a, 'depth', '3')})...",
    "waybackurls_fetch": lambda a: f"Fetching historical URLs for {_safe(a, 'domain', 'target')}...",
    "http_headers_check": lambda a: f"Analyzing security headers for {_safe(a, 'url', 'target')}...",
    "http_fetch": lambda a: f"Fetching {_safe(a, 'url', 'target')}...",
    "http_methods": lambda a: f"Testing HTTP methods on {_safe(a, 'url', 'target')}...",
    "cookie_check": lambda a: f"Analyzing cookie security for {_safe(a, 'url', 'target')}...",
    "feroxbuster_scan": lambda a: f"Discovering directories on {_safe(a, 'url', 'target')}...",
    "gobuster_dir": lambda a: f"Brute-forcing directories on {_safe(a, 'url', 'target')}...",

    # --- Vulnerability Assessment ---
    "nuclei_scan": lambda a: f"Running vulnerability templates against {_safe(a, 'target')}...",
    "sqlmap_scan": lambda a: f"Testing SQL injection on {_safe(a, 'url', 'target')}...",
    "sqli_payloads": lambda a: f"Generating {_safe(a, 'test_type', 'auth_bypass')} payloads for {_safe(a, 'target_dbms', 'generic')}...",
    "commix_scan": lambda a: f"Testing command injection on {_safe(a, 'url', 'target')}...",

    # --- API Security ---
    "jwt_test": lambda a: f"Analyzing JWT token security...",
    "graphql_test": lambda a: f"Testing GraphQL endpoint at {_safe(a, 'url', 'target')}...",

    # --- Exploitation ---
    "msfconsole_run": lambda a: (
        f"Executing exploit: {_safe(a, 'module')}..."
        if a.get("module")
        else f"Running exploit framework: {_safe(a, 'execute_cmd', 'command')}..."
    ),
    "msfvenom_generate": lambda a: f"Generating {_safe(a, 'payload', 'payload')} → {_safe(a, 'lhost')}:{_safe(a, 'lport')}...",
    "searchsploit_search": lambda a: f"Searching exploit database for {_safe(a, 'query', _safe(a, 'term', 'target'))}...",
    "searchsploit_examine": lambda a: f"Examining exploit {_safe(a, 'path', _safe(a, 'edb_id', ''))}...",
    "searchsploit_mirror": lambda a: f"Downloading exploit {_safe(a, 'edb_id', '')}...",

    # --- Metasploit RPC ---
    "msf_list_exploits": lambda a: f"Searching exploit modules matching '{_safe(a, 'search', '*')}'...",
    "msf_list_payloads": lambda a: f"Searching payload modules matching '{_safe(a, 'search', '*')}'...",
    "msf_run_exploit": lambda a: f"Executing exploit against {_safe(a, 'options', {}).get('RHOSTS', 'target')}...",
    "msf_run_auxiliary": lambda a: f"Running auxiliary scan: {_safe(a, 'module')}...",
    "msf_run_post": lambda a: f"Running post-exploitation: {_safe(a, 'module')}...",
    "msf_list_sessions": lambda a: "Listing active sessions...",
    "msf_session_command": lambda a: f"Sending command to session {_safe(a, 'session_id')}...",
    "msf_terminate_session": lambda a: f"Terminating session {_safe(a, 'session_id')}...",
    "msf_start_listener": lambda a: f"Starting listener on {_safe(a, 'lhost', '0.0.0.0')}:{_safe(a, 'lport', '4444')}...",
    "msf_list_jobs": lambda a: "Listing active jobs...",
    "msf_stop_job": lambda a: f"Stopping job {_safe(a, 'job_id')}...",
    "msf_generate_payload": lambda a: f"Generating {_safe(a, 'payload')} payload...",
    "msf_search_modules": lambda a: f"Searching exploit database for '{_safe(a, 'query')}'...",
    "msf_module_info": lambda a: f"Getting info for module {_safe(a, 'module')}...",

    # --- Verification ---
    "verify_sqli": lambda a: f"Verifying SQL injection on {_safe(a, 'url', 'target')}...",
    "verify_rce": lambda a: f"Testing remote code execution on {_safe(a, 'url', 'target')}...",
    "verify_lfi": lambda a: f"Attempting file inclusion on {_safe(a, 'url', 'target')}...",
    "verify_default_creds": lambda a: f"Trying default credentials on {_safe(a, 'service', 'service')} at {_safe(a, 'target')}...",
    "verify_cve": lambda a: f"Exploiting {_safe(a, 'cve_id', 'CVE')} against {_safe(a, 'target')}...",

    # --- Post-Exploitation ---
    "postexploit_system_info": lambda a: f"Gathering system information from {_safe(a, 'target')}...",
    "postexploit_privesc_check": lambda a: f"Checking privilege escalation vectors on {_safe(a, 'target')}...",
    "postexploit_read_file": lambda a: f"Reading {_safe(a, 'filepath', '/etc/passwd')} from {_safe(a, 'target')}...",
    "postexploit_credential_dump": lambda a: f"Extracting stored credentials from {_safe(a, 'target')}...",
    "postexploit_internal_scan": lambda a: f"Scanning internal network {_safe(a, 'scan_range', '')} from {_safe(a, 'target')}...",

    # --- Reporting ---
    "report_add_finding": lambda a: f"Recording finding: {_safe(a, 'title', 'vulnerability')}...",
    "report_generate": lambda a: f"Generating {_safe(a, 'format', 'markdown')} penetration test report...",
    "report_list_findings": lambda a: "Reviewing collected findings...",
    "report_clear_findings": lambda a: "Clearing all findings...",
    "report_import_evidence": lambda a: "Importing evidence from captures...",
    "assessment_set_status": lambda a: f"Updating assessment status to {_safe(a, 'status', 'active')}...",

    # --- Sessions ---
    "session_create": lambda a: f"Opening {_safe(a, 'session_type', 'bash')} session to {_safe(a, 'target', 'host')}...",
    "session_exec": lambda a: f"Executing command in session {_safe(a, 'session_id')}...",
    "session_read": lambda a: f"Reading output from session {_safe(a, 'session_id')}...",
    "session_close": lambda a: f"Closing session {_safe(a, 'session_id')}...",
    "session_list": lambda a: "Listing active sessions...",
    "session_history": lambda a: f"Getting history for session {_safe(a, 'session_id')}...",

    # --- Target State ---
    "target_add": lambda a: f"Registering target {_safe(a, 'host', 'host')}...",
    "target_add_port": lambda a: f"Recording port {_safe(a, 'port')} on {_safe(a, 'host')}...",
    "target_add_credential": lambda a: f"Recording credential for {_safe(a, 'service', 'service')} on {_safe(a, 'host')}...",
    "target_add_vuln": lambda a: f"Recording vulnerability on {_safe(a, 'host', 'target')}...",
    "target_log_scan": lambda a: f"Logging scan of {_safe(a, 'host', 'target')}...",
    "target_get": lambda a: f"Querying target data for {_safe(a, 'host', 'target')}...",
    "target_list": lambda a: "Listing all discovered targets...",
    "target_clear": lambda a: "Clearing target state...",

    # --- Evidence ---
    "evidence_capture": lambda a: f"Capturing evidence: {_safe(a, 'title', 'finding')}...",
    "evidence_list": lambda a: "Listing captured evidence...",
    "evidence_get": lambda a: f"Retrieving evidence #{_safe(a, 'evidence_id', '')}...",
    "evidence_clear": lambda a: "Clearing evidence...",

    # --- Authentication ---
    "auth_login": lambda a: f"Authenticating to {_safe(a, 'url', 'target')}...",
    "auth_set_token": lambda a: "Setting authentication token...",
    "auth_headers": lambda a: "Getting authentication headers...",
    "auth_test": lambda a: f"Testing authentication against {_safe(a, 'url', 'target')}...",
    "auth_clear": lambda a: "Clearing authentication state...",

    # --- Attack Surface ---
    "attack_surface_map": lambda a: f"Mapping attack surface for {_safe(a, 'target', 'target')}...",

    # --- OSINT ---
    "theharvester_search": lambda a: f"Gathering OSINT for {_safe(a, 'domain', 'target')}...",
    "shodan_search": lambda a: f"Searching internet-connected devices for {_safe(a, 'query', _safe(a, 'target', 'target'))}...",
    "email_harvest": lambda a: f"Discovering email addresses for {_safe(a, 'domain', 'target')}...",

    # --- WordPress ---
    "wpscan_scan": lambda a: f"Scanning WordPress installation at {_safe(a, 'url', _safe(a, 'target', 'site'))}...",

    # --- Credentials ---
    "credential_test": lambda a: f"Testing credentials on {_safe(a, 'service', 'service')} at {_safe(a, 'target')}...",
    "default_creds_check": lambda a: f"Checking default credentials on {_safe(a, 'target')}...",

    # --- ZAP (CLI) ---
    "zap_baseline_scan": lambda a: f"Running passive security scan on {_safe(a, 'target')}...",
    "zap_full_scan": lambda a: f"Running active security scan on {_safe(a, 'target')}...",
    "zap_api_scan": lambda a: f"Scanning API endpoints at {_safe(a, 'target')}...",
    "zap_cli_scan": lambda a: f"Security scanning {_safe(a, 'target')}...",
    "zap_ajax_spider": lambda a: f"JavaScript-aware crawling of {_safe(a, 'target')}...",
    "zap_quick_scan": lambda a: f"Quick security scan of {_safe(a, 'target')}...",
    "zap_authenticated_scan": lambda a: f"Authenticated scan of {_safe(a, 'target')}...",

    # --- ZAP API ---
    "zap_create_context": lambda a: f"Creating scan context '{_safe(a, 'name', 'default')}'...",
    "zap_list_contexts": lambda a: "Listing scan contexts...",
    "zap_spider": lambda a: f"Crawling {_safe(a, 'target')} for pages...",
    "zap_spider_status": lambda a: f"Checking crawl progress (scan {_safe(a, 'scan_id', '')})...",
    "zap_stop_spider": lambda a: "Stopping crawl...",
    "zap_ajax_spider_status": lambda a: "Checking JavaScript crawl status...",
    "zap_stop_ajax_spider": lambda a: "Stopping JavaScript crawl...",
    "zap_active_scan": lambda a: f"Actively scanning {_safe(a, 'target')} for vulnerabilities...",
    "zap_scan_status": lambda a: f"Checking scan progress (scan {_safe(a, 'scan_id', '')})...",
    "zap_stop_scan": lambda a: "Stopping active scan...",
    "zap_passive_scan_status": lambda a: "Checking passive scan queue...",
    "zap_get_alerts": lambda a: f"Retrieving vulnerability alerts for {_safe(a, 'target', 'all targets')}...",
    "zap_alert_detail": lambda a: f"Getting details for alert #{_safe(a, 'alert_id', '')}...",
    "zap_get_sites": lambda a: "Listing discovered sites...",
    "zap_get_urls": lambda a: f"Listing discovered URLs for {_safe(a, 'target', 'all')}...",
    "zap_get_history": lambda a: "Reading HTTP request history...",
    "zap_generate_report": lambda a: f"Generating security scan report ({_safe(a, 'template', 'HTML')})...",
    "zap_list_scan_policies": lambda a: "Listing scan policies...",
    "zap_new_session": lambda a: "Starting fresh scan session...",
    "zap_access_url": lambda a: f"Accessing {_safe(a, 'url', 'URL')} to seed scanner...",

    # --- Burp Suite ---
    "burp_check_connection": lambda a: "Checking scanner connection...",
    "burp_start_scan": lambda a: f"Starting vulnerability scan against {_safe(a, 'target_urls', 'targets')}...",
    "burp_scan_status": lambda a: f"Checking scan progress (task {_safe(a, 'task_id', '')})...",
    "burp_scan_issues": lambda a: f"Retrieving vulnerability findings from scan {_safe(a, 'task_id', '')}...",
    "burp_cancel_scan": lambda a: f"Cancelling scan {_safe(a, 'task_id', '')}...",
    "burp_issue_definitions": lambda a: f"Browsing vulnerability knowledge base{' for ' + _safe(a, 'search') if a.get('search') else ''}...",
    "burp_scan_configs": lambda a: "Listing available scan configurations...",

    # --- Cloud ---
    "scoutsuite_aws": lambda a: f"Auditing AWS configuration ({_safe(a, 'profile', 'default')})...",
    "scoutsuite_azure": lambda a: "Auditing Azure configuration...",
    "scoutsuite_gcp": lambda a: "Auditing GCP configuration...",
    "prowler_aws": lambda a: f"Running AWS compliance check ({_safe(a, 'compliance', 'CIS')})...",
    "prowler_azure": lambda a: "Running Azure compliance check...",
    "prowler_gcp": lambda a: "Running GCP compliance check...",
    "cloud_credential_test": lambda a: f"Validating cloud credentials ({_safe(a, 'provider', 'AWS')})...",

    # --- Mobile ---
    "mobsf_upload": lambda a: f"Uploading mobile app for analysis...",
    "mobsf_scan": lambda a: f"Scanning mobile application...",
    "mobsf_report": lambda a: "Generating mobile security report...",
    "mobsf_extract_urls": lambda a: "Extracting URLs from mobile app...",
    "mobsf_scorecard": lambda a: "Generating security scorecard...",
    "mobsf_scan_logs": lambda a: "Retrieving scan logs...",
    "mobsf_recent_scans": lambda a: "Listing recent mobile scans...",
    "mobsf_delete_scan": lambda a: "Removing scan data...",

    # --- Client-side ---
    "export_runbook": lambda a: "Exporting attack runbook...",
}


def get_action_message(tool_name: str, arguments: dict) -> str:
    """
    Get a specific, argument-aware status message for a tool execution.

    Returns a human-readable string like:
        "Scanning ports on 10.10.10.5..."
        "Testing SQL injection on https://acme.com/login..."
        "Extracting stored credentials from 10.10.10.5..."

    Falls back to a generic message if the tool isn't mapped.
    """
    template = TOOL_ACTION_MESSAGES.get(tool_name)
    if template:
        try:
            return template(arguments or {})
        except Exception:
            pass
    # Fallback: use the target if available, otherwise generic
    target = (
        arguments.get("target")
        or arguments.get("url")
        or arguments.get("host")
        or arguments.get("domain")
        or ""
    ) if arguments else ""
    if target:
        return f"Processing {target}..."
    return "Processing..."
