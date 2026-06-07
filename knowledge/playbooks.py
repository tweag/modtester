"""
Attack Playbooks — 10 representative patterns.

When the AI discovers something, the playbook tells it what to do next.
"""

PLAYBOOKS = [
    {
        "id": "werkzeug_debugger",
        "name": "Werkzeug Debugger Console",
        "triggers": ["werkzeug", "debugger", "/console"],
        "severity": "CRITICAL",
        "steps": [
            {"action": "Fetch /console endpoint", "tool": "http_fetch"},
            {"action": "If no PIN → execute id command", "tool": "verify_rce"},
            {"action": "If PIN → gather MAC, machine-id for calculation", "tool": "http_fetch"},
        ],
    },
    {
        "id": "exposed_git",
        "name": "Exposed .git Directory",
        "triggers": [".git", "git repository", "/.git/HEAD"],
        "severity": "HIGH",
        "steps": [
            {"action": "Fetch /.git/HEAD to confirm", "tool": "http_fetch"},
            {"action": "Fetch /.git/config for repo info", "tool": "http_fetch"},
            {"action": "Attempt to dump objects", "tool": "http_fetch"},
        ],
    },
    {
        "id": "default_credentials",
        "name": "Default Credentials on Admin Panel",
        "triggers": ["login", "admin panel", "wp-login", "jenkins", "tomcat manager"],
        "severity": "CRITICAL",
        "steps": [
            {"action": "Test default credentials", "tool": "verify_default_creds"},
            {"action": "If successful → enumerate access", "tool": "http_fetch"},
            {"action": "Check for command execution", "tool": "verify_rce"},
        ],
    },
    {
        "id": "sql_injection",
        "name": "SQL Injection in Parameters",
        "triggers": ["sql", "error in your SQL syntax", "mysql", "postgres", "oracle"],
        "severity": "CRITICAL",
        "steps": [
            {"action": "Confirm with targeted sqlmap scan", "tool": "sqlmap_scan"},
            {"action": "Extract database names", "tool": "verify_sqli"},
            {"action": "Dump sensitive tables", "tool": "sqlmap_scan"},
        ],
    },
    {
        "id": "open_redirect",
        "name": "Open Redirect to Phishing",
        "triggers": ["redirect", "url=", "next=", "return=", "dest="],
        "severity": "MEDIUM",
        "steps": [
            {"action": "Test redirect with external URL", "tool": "http_fetch"},
            {"action": "Check for SSRF via redirect", "tool": "http_fetch"},
        ],
    },
    {
        "id": "jwt_weak",
        "name": "Weak JWT Implementation",
        "triggers": ["jwt", "json web token", "eyJ", "bearer"],
        "severity": "HIGH",
        "steps": [
            {"action": "Decode token, check algorithm", "tool": "http_fetch"},
            {"action": "Test alg:none bypass", "tool": "http_fetch"},
            {"action": "Brute-force weak secret", "tool": "http_fetch"},
        ],
    },
    {
        "id": "lfi_path_traversal",
        "name": "Local File Inclusion",
        "triggers": ["file=", "path=", "include=", "template=", "page="],
        "severity": "HIGH",
        "steps": [
            {"action": "Test path traversal payloads", "tool": "verify_lfi"},
            {"action": "Read /etc/passwd", "tool": "verify_lfi"},
            {"action": "Attempt log poisoning for RCE", "tool": "http_fetch"},
        ],
    },
    {
        "id": "wordpress_vuln",
        "name": "WordPress Vulnerabilities",
        "triggers": ["wordpress", "wp-content", "wp-includes", "wp-json"],
        "severity": "HIGH",
        "steps": [
            {"action": "Enumerate plugins and themes", "tool": "nuclei_scan"},
            {"action": "Test xmlrpc for brute-force", "tool": "http_fetch"},
            {"action": "Check for user enumeration", "tool": "http_fetch"},
        ],
    },
    {
        "id": "exposed_api_docs",
        "name": "Exposed API Documentation",
        "triggers": ["swagger", "openapi", "/api-docs", "/swagger-ui", "graphql"],
        "severity": "MEDIUM",
        "steps": [
            {"action": "Fetch API documentation", "tool": "http_fetch"},
            {"action": "Test unauthenticated access to endpoints", "tool": "http_fetch"},
            {"action": "Test for BOLA/IDOR vulnerabilities", "tool": "http_fetch"},
        ],
    },
    {
        "id": "spring_actuator",
        "name": "Spring Boot Actuator Exposure",
        "triggers": ["spring", "actuator", "/env", "/heapdump", "/mappings"],
        "severity": "HIGH",
        "steps": [
            {"action": "Enumerate actuator endpoints", "tool": "http_fetch"},
            {"action": "Check /env for secrets", "tool": "http_fetch"},
            {"action": "Download /heapdump for credential extraction", "tool": "http_fetch"},
        ],
    },
]


def match_playbooks(text: str) -> list:
    """Find playbooks whose triggers match the given text."""
    text_lower = text.lower()
    matches = []
    for pb in PLAYBOOKS:
        for trigger in pb["triggers"]:
            if trigger.lower() in text_lower:
                matches.append(pb)
                break
    return matches
