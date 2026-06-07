"""
Security Tools Module — ModTester
Single source of truth for all available tools.
Focused on Web, Mobile API, and Public IP penetration testing.
"""

# Network
from .network import nmap_scan, masscan_scan

# DNS
from .dns import dns_lookup, whois_lookup, crtsh_lookup

# Web Discovery
from .web import http_probe, http_headers_check, ffuf_fuzz, katana_crawl, waybackurls_fetch

# HTTP Utilities
from .http_utils import http_fetch, http_methods, cookie_check

# API Security
from .api_security import jwt_test, graphql_test

# Recon
from .recon import subfinder_enum, arjun_scan

# Enumeration
from .enumeration import nikto_scan, testssl_scan, netcat_connect

# Vulnerability
from .vuln import nuclei_scan, sqlmap_scan, sqli_payloads

# Injection
from .injection import commix_scan, sslscan_check

# Content Discovery
from .bruteforce import feroxbuster_scan

# WordPress
from .wordpress import wpscan_scan

# Credentials
from .credentials import credential_test, default_creds_check

# Exploitation
from .exploit import searchsploit_search, searchsploit_examine

# Verification
from .verify import verify_sqli, verify_rce, verify_lfi, verify_default_creds, verify_cve

# Reporting
from .reporting import report_add_finding, report_list_findings, report_clear_findings, report_import_evidence, report_generate

# Target State Tracking
from .target_state import target_add, target_add_port, target_add_credential, target_add_vuln, target_log_scan, target_get, target_list, target_clear

# Evidence Capture
from .auto_evidence import evidence_capture, evidence_list, evidence_get, evidence_clear

# Attack Surface Mapping
from .attack_surface import attack_surface_map

# Authentication Handler
from .auth import auth_login, auth_set_token, auth_headers, auth_test, auth_clear

# Interactive Sessions
from .sessions import session_create, session_exec, session_read, session_close, session_list, session_history

# =============================================================================
# TOOL REGISTRY — drives server endpoints, client tool list, documentation
# =============================================================================

TOOL_REGISTRY = {
    # --- Network ---
    "nmap_scan": {
        "fn": nmap_scan, "category": "network",
        "description": "Port scan with service detection and OS fingerprinting.",
        "schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "scan_type": {"type": "string", "enum": ["quick", "full", "stealth", "udp", "comprehensive"]},
                "ports": {"type": "string", "description": "Ports (e.g., '22,80,443' or '1-1000')"},
            },
            "required": ["target"],
        },
    },
    "masscan_scan": {
        "fn": masscan_scan, "category": "network",
        "description": "Ultra-fast port scanner for large IP ranges.",
        "schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or CIDR range"},
                "ports": {"type": "string", "description": "Port range"},
                "rate": {"type": "integer", "description": "Packets per second (max 10000)"},
            },
            "required": ["target"],
        },
    },
    "netcat_connect": {
        "fn": netcat_connect, "category": "network",
        "description": "Banner grab and port interaction via netcat.",
        "schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "data": {"type": "string"},
            },
            "required": ["host", "port"],
        },
    },

    # --- DNS ---
    "dns_lookup": {
        "fn": dns_lookup, "category": "dns",
        "description": "DNS record lookup (A, AAAA, MX, TXT, NS, CNAME, SOA).",
        "schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "record_type": {"type": "string", "enum": ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "ANY"]},
            },
            "required": ["domain"],
        },
    },
    "whois_lookup": {
        "fn": whois_lookup, "category": "dns",
        "description": "WHOIS domain registration information.",
        "schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    "crtsh_lookup": {
        "fn": crtsh_lookup, "category": "dns",
        "description": "Subdomain discovery via certificate transparency logs.",
        "schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },

    # --- Web ---
    "http_probe": {
        "fn": http_probe, "category": "web",
        "description": "Probe URLs for availability and technology detection.",
        "schema": {
            "type": "object",
            "properties": {"targets": {"type": "array", "items": {"type": "string"}}},
            "required": ["targets"],
        },
    },
    "http_headers_check": {
        "fn": http_headers_check, "category": "web",
        "description": "Analyze HTTP security headers (HSTS, CSP, X-Frame-Options).",
        "schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    "http_fetch": {
        "fn": http_fetch, "category": "web",
        "description": "Fetch a URL and return headers + body. Use for config files, API schemas.",
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                "headers": {"type": "object"},
                "body": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    "http_methods": {
        "fn": http_methods, "category": "web",
        "description": "Test which HTTP methods are allowed on a URL.",
        "schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    "cookie_check": {
        "fn": cookie_check, "category": "web",
        "description": "Analyze cookie security attributes (Secure, HttpOnly, SameSite).",
        "schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    "ffuf_fuzz": {
        "fn": ffuf_fuzz, "category": "web",
        "description": "Web fuzzer for hidden directories, files, and parameters.",
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL with FUZZ keyword"},
                "wordlist": {"type": "string"},
                "extensions": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    "katana_crawl": {
        "fn": katana_crawl, "category": "web",
        "description": "Deep web crawler discovering endpoints, forms, and JavaScript files.",
        "schema": {
            "type": "object",
            "properties": {
                "targets": {"type": "string", "description": "URL to crawl"},
                "depth": {"type": "integer"},
            },
            "required": ["targets"],
        },
    },
    "waybackurls_fetch": {
        "fn": waybackurls_fetch, "category": "web",
        "description": "Fetch historical URLs from the Wayback Machine.",
        "schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    "feroxbuster_scan": {
        "fn": feroxbuster_scan, "category": "web",
        "description": "Recursive content discovery with feroxbuster.",
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "wordlist": {"type": "string"},
                "extensions": {"type": "string"},
                "depth": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    "nikto_scan": {
        "fn": nikto_scan, "category": "web",
        "description": "Web server vulnerability scanner (misconfigs, dangerous files).",
        "schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },

    # --- API Security ---
    "jwt_test": {
        "fn": jwt_test, "category": "api",
        "description": "JWT token analysis: decode, test alg:none, brute-force weak secrets.",
        "schema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "JWT token to analyze"},
                "action": {"type": "string", "enum": ["decode", "test_none", "brute_secret", "forge"]},
            },
            "required": ["token"],
        },
    },
    "graphql_test": {
        "fn": graphql_test, "category": "api",
        "description": "GraphQL security testing: introspection, schema extraction, injection.",
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "GraphQL endpoint URL"},
                "action": {"type": "string", "enum": ["introspection", "schema", "test"]},
            },
            "required": ["url"],
        },
    },

    # --- Recon ---
    "subfinder_enum": {
        "fn": subfinder_enum, "category": "recon",
        "description": "Passive subdomain enumeration using multiple sources.",
        "schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    "arjun_scan": {
        "fn": arjun_scan, "category": "recon",
        "description": "Discover hidden HTTP parameters on endpoints.",
        "schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },

    # --- SSL/TLS ---
    "testssl_scan": {
        "fn": testssl_scan, "category": "ssl",
        "description": "Comprehensive TLS/SSL analysis (protocols, ciphers, vulnerabilities).",
        "schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "port": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    "sslscan_check": {
        "fn": sslscan_check, "category": "ssl",
        "description": "Check SSL/TLS cipher suites and certificate details.",
        "schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },

    # --- Vulnerability ---
    "nuclei_scan": {
        "fn": nuclei_scan, "category": "vulnerability",
        "description": "Template-based vulnerability scanner (CVEs, misconfigs, exposures).",
        "schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "templates": {"type": "string", "description": "Template path or tag"},
                "tags": {"type": "string", "description": "Comma-separated tags (cve,xss,sqli,rce)"},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
            },
            "required": ["target"],
        },
    },
    "sqlmap_scan": {
        "fn": sqlmap_scan, "category": "vulnerability",
        "description": "Automated SQL injection detection and exploitation.",
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "data": {"type": "string", "description": "POST data"},
                "param": {"type": "string", "description": "Parameter to test"},
                "level": {"type": "integer"},
                "risk": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    "sqli_payloads": {
        "fn": sqli_payloads, "category": "vulnerability",
        "description": "Generate SQL injection test payloads for manual testing.",
        "schema": {
            "type": "object",
            "properties": {
                "test_type": {"type": "string", "enum": ["auth_bypass", "union", "blind", "time_based", "error_based"]},
                "target_dbms": {"type": "string", "enum": ["mysql", "postgres", "mssql", "oracle", "generic"]},
            },
            "required": [],
        },
    },
    "commix_scan": {
        "fn": commix_scan, "category": "vulnerability",
        "description": "Automated command injection detection and exploitation.",
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "data": {"type": "string"},
                "param": {"type": "string"},
            },
            "required": ["url"],
        },
    },

    # --- WordPress ---
    "wpscan_scan": {
        "fn": wpscan_scan, "category": "wordpress",
        "description": "WordPress vulnerability scanner (plugins, themes, users).",
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "enumerate": {"type": "string", "description": "What to enumerate (vp,vt,u,dbe)"},
            },
            "required": ["url"],
        },
    },

    # --- Credentials ---
    "credential_test": {
        "fn": credential_test, "category": "credentials",
        "description": "Test credentials against a service (SSH, FTP, HTTP, etc.).",
        "schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "service": {"type": "string", "enum": ["ssh", "ftp", "http", "mysql", "postgres", "rdp", "smb"]},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "userlist": {"type": "string"},
                "passlist": {"type": "string"},
                "threads": {"type": "integer"},
            },
            "required": ["target", "service"],
        },
    },
    "default_creds_check": {
        "fn": default_creds_check, "category": "credentials",
        "description": "Quick check of common default credentials on a service.",
        "schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "service": {"type": "string"},
                "port": {"type": "integer"},
            },
            "required": ["target", "service"],
        },
    },

    # --- Exploitation ---
    "searchsploit_search": {
        "fn": searchsploit_search, "category": "exploitation",
        "description": "Search Exploit-DB for known exploits by keyword.",
        "schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    "searchsploit_examine": {
        "fn": searchsploit_examine, "category": "exploitation",
        "description": "Read the source code of an exploit from Exploit-DB.",
        "schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },

    # --- Verification ---
    "verify_sqli": {
        "fn": verify_sqli, "category": "verification",
        "description": "Verify SQL injection by extracting database information.",
        "schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "param": {"type": "string"}},
            "required": ["url"],
        },
    },
    "verify_rce": {
        "fn": verify_rce, "category": "verification",
        "description": "Verify remote code execution by running system commands.",
        "schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "param": {"type": "string"}, "method": {"type": "string"}},
            "required": ["url"],
        },
    },
    "verify_lfi": {
        "fn": verify_lfi, "category": "verification",
        "description": "Verify local file inclusion by reading sensitive files.",
        "schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "param": {"type": "string"}},
            "required": ["url"],
        },
    },
    "verify_default_creds": {
        "fn": verify_default_creds, "category": "verification",
        "description": "Test common default credentials on services.",
        "schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "service": {"type": "string"}},
            "required": ["target", "service"],
        },
    },
    "verify_cve": {
        "fn": verify_cve, "category": "verification",
        "description": "Attempt to exploit a specific CVE against the target.",
        "schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "cve_id": {"type": "string"}},
            "required": ["target", "cve_id"],
        },
    },

    # --- Target State Tracking ---
    "target_add": {
        "fn": target_add, "category": "tracking",
        "description": "Register a target with technology, WAF, and OS info.",
        "schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "technology": {"type": "string"},
                "waf": {"type": "string"},
                "os": {"type": "string"},
            },
            "required": ["host"],
        },
    },
    "target_add_port": {
        "fn": target_add_port, "category": "tracking",
        "description": "Record a discovered open port on a target.",
        "schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "service": {"type": "string"},
                "version": {"type": "string"},
            },
            "required": ["host", "port"],
        },
    },
    "target_add_credential": {
        "fn": target_add_credential, "category": "tracking",
        "description": "Record discovered credentials for a target.",
        "schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "service": {"type": "string"},
            },
            "required": ["host", "username"],
        },
    },
    "target_add_vuln": {
        "fn": target_add_vuln, "category": "tracking",
        "description": "Record a discovered vulnerability on a target.",
        "schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "title": {"type": "string"},
                "severity": {"type": "string"},
                "description": {"type": "string"},
            },
            "required": ["host", "title", "severity"],
        },
    },
    "target_log_scan": {
        "fn": target_log_scan, "category": "tracking",
        "description": "Log that a scan was run on a target (prevents duplicates).",
        "schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "tool_name": {"type": "string"},
                "notes": {"type": "string"},
            },
            "required": ["host", "tool_name"],
        },
    },
    "target_get": {
        "fn": target_get, "category": "tracking",
        "description": "Get all known information about a target.",
        "schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": ["host"],
        },
    },
    "target_list": {
        "fn": target_list, "category": "tracking",
        "description": "List all registered targets and their status.",
        "schema": {"type": "object", "properties": {}, "required": []},
    },
    "target_clear": {
        "fn": target_clear, "category": "tracking",
        "description": "Clear all target state data.",
        "schema": {"type": "object", "properties": {}, "required": []},
    },

    # --- Evidence ---
    "evidence_capture": {
        "fn": evidence_capture, "category": "evidence",
        "description": "Capture and store evidence (screenshots, request/response, output).",
        "schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "content": {"type": "string"},
                "evidence_type": {"type": "string", "enum": ["screenshot", "request", "response", "output", "file"]},
                "severity": {"type": "string"},
            },
            "required": ["title", "content"],
        },
    },
    "evidence_list": {
        "fn": evidence_list, "category": "evidence",
        "description": "List all captured evidence.",
        "schema": {"type": "object", "properties": {}, "required": []},
    },
    "evidence_get": {
        "fn": evidence_get, "category": "evidence",
        "description": "Retrieve specific evidence by title.",
        "schema": {
            "type": "object",
            "properties": {"title_search": {"type": "string"}},
            "required": ["title_search"],
        },
    },
    "evidence_clear": {
        "fn": evidence_clear, "category": "evidence",
        "description": "Clear all captured evidence.",
        "schema": {"type": "object", "properties": {}, "required": []},
    },

    # --- Attack Surface ---
    "attack_surface_map": {
        "fn": attack_surface_map, "category": "recon",
        "description": "Generate a visual attack surface map from discovered data.",
        "schema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": [],
        },
    },

    # --- Authentication ---
    "auth_login": {
        "fn": auth_login, "category": "auth",
        "description": "Log into a target with credentials and store the session.",
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
            },
            "required": ["url", "username", "password"],
        },
    },
    "auth_set_token": {
        "fn": auth_set_token, "category": "auth",
        "description": "Set a bearer/JWT token for authenticated requests.",
        "schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "token": {"type": "string"},
                "token_type": {"type": "string"},
            },
            "required": ["host", "token"],
        },
    },
    "auth_headers": {
        "fn": auth_headers, "category": "auth",
        "description": "Get stored auth headers for a target host.",
        "schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": ["host"],
        },
    },
    "auth_test": {
        "fn": auth_test, "category": "auth",
        "description": "Test if stored authentication is still valid.",
        "schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}, "test_url": {"type": "string"}},
            "required": ["host"],
        },
    },
    "auth_clear": {
        "fn": auth_clear, "category": "auth",
        "description": "Clear stored authentication for a host.",
        "schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": [],
        },
    },

    # --- Sessions ---
    "session_create": {
        "fn": session_create, "category": "sessions",
        "description": "Create an interactive session (SSH, shell, MySQL, etc.).",
        "schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Command to start session (e.g., ssh user@host)"},
                "session_type": {"type": "string", "enum": ["ssh", "shell", "mysql", "msfconsole"]},
            },
            "required": ["command"],
        },
    },
    "session_exec": {
        "fn": session_exec, "category": "sessions",
        "description": "Execute a command in an active session.",
        "schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "command": {"type": "string"},
            },
            "required": ["session_id", "command"],
        },
    },
    "session_read": {
        "fn": session_read, "category": "sessions",
        "description": "Read output from an active session.",
        "schema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    "session_close": {
        "fn": session_close, "category": "sessions",
        "description": "Close an active session.",
        "schema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    "session_list": {
        "fn": session_list, "category": "sessions",
        "description": "List all active sessions.",
        "schema": {"type": "object", "properties": {}, "required": []},
    },
    "session_history": {
        "fn": session_history, "category": "sessions",
        "description": "Get command history for a session.",
        "schema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },

    # --- Reporting ---
    "report_add_finding": {
        "fn": report_add_finding, "category": "reporting",
        "description": "Record a security finding with severity and evidence.",
        "schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "description": {"type": "string"},
                "evidence": {"type": "string"},
                "remediation": {"type": "string"},
            },
            "required": ["title", "severity", "description"],
        },
    },
    "report_list_findings": {
        "fn": report_list_findings, "category": "reporting",
        "description": "List all recorded findings.",
        "schema": {"type": "object", "properties": {}, "required": []},
    },
    "report_clear_findings": {
        "fn": report_clear_findings, "category": "reporting",
        "description": "Clear all recorded findings.",
        "schema": {"type": "object", "properties": {}, "required": []},
    },
    "report_import_evidence": {
        "fn": report_import_evidence, "category": "reporting",
        "description": "Import captured evidence into the report.",
        "schema": {"type": "object", "properties": {}, "required": []},
    },
    "report_generate": {
        "fn": report_generate, "category": "reporting",
        "description": "Generate a professional penetration test report.",
        "schema": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["markdown", "json", "html"]},
                "target": {"type": "string"},
                "engagement_name": {"type": "string"},
            },
            "required": [],
        },
    },
    "assessment_set_status": {
        "fn": None, "category": "reporting",
        "description": "Set the assessment status. Use when the user asks to mark as completed, return to active, or pause.",
        "schema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["active", "completed", "paused"],
                           "description": "The new status for the assessment"},
            },
            "required": ["status"],
        },
    },
}

# Derived lookups
TOOL_FUNCTIONS = {name: info["fn"] for name, info in TOOL_REGISTRY.items()}
TOOL_CATEGORIES = {}
for name, info in TOOL_REGISTRY.items():
    cat = info["category"]
    TOOL_CATEGORIES.setdefault(cat, []).append(name)
