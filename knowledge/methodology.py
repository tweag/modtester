"""
Testing Methodology — PTES, OWASP Testing Guide, NIST 800-115

Defines the engagement structure an AI pentester follows.
"""

METHODOLOGY = {
    "framework": "PTES + OWASP Testing Guide v4",
    "phases": [
        {
            "id": 1,
            "name": "Pre-Engagement",
            "description": "Define scope, rules of engagement, authorization verification.",
            "exit_criteria": ["Written authorization confirmed", "Scope documented", "Communication plan established"],
        },
        {
            "id": 2,
            "name": "Intelligence Gathering",
            "description": "Passive and active reconnaissance to map the target.",
            "tools": ["dns_lookup", "whois_lookup", "crtsh_lookup", "subfinder_enum", "http_probe"],
            "exit_criteria": ["Subdomains enumerated", "Technologies identified", "Attack surface mapped"],
        },
        {
            "id": 3,
            "name": "Threat Modeling",
            "description": "Identify likely attack vectors based on discovered architecture.",
            "tools": ["attack_surface_map"],
            "exit_criteria": ["Threat model generated", "Priority targets identified"],
        },
        {
            "id": 4,
            "name": "Vulnerability Analysis",
            "description": "Systematic scanning and manual testing for weaknesses.",
            "tools": ["nuclei_scan", "nikto_scan", "testssl_scan", "sqlmap_scan", "http_headers_check"],
            "exit_criteria": ["All ports/services scanned", "Web vulns tested", "SSL/TLS assessed"],
        },
        {
            "id": 5,
            "name": "Exploitation",
            "description": "Attempt to exploit confirmed vulnerabilities.",
            "tools": ["verify_sqli", "verify_rce", "verify_lfi", "msfconsole_run", "verify_cve"],
            "exit_criteria": ["Vulnerabilities verified with PoC", "Access gained or documented"],
        },
        {
            "id": 6,
            "name": "Post-Exploitation",
            "description": "Assess impact — privilege escalation, lateral movement, data access.",
            "tools": ["postexploit_system_info", "postexploit_privesc_check",
                      "postexploit_credential_dump", "postexploit_internal_scan"],
            "exit_criteria": ["Maximum impact demonstrated", "Credential reuse tested"],
        },
        {
            "id": 7,
            "name": "Reporting",
            "description": "Document all findings with evidence and remediation guidance.",
            "tools": ["report_add_finding", "report_generate"],
            "exit_criteria": ["All findings documented", "Report generated with evidence"],
        },
    ],
    "severity_classification": {
        "source": "NIST SP 800-115 / CVSS v3.1",
        "levels": {
            "CRITICAL": {"cvss_range": "9.0-10.0", "description": "Full system compromise, RCE, auth bypass"},
            "HIGH": {"cvss_range": "7.0-8.9", "description": "Significant data exposure, privilege escalation"},
            "MEDIUM": {"cvss_range": "4.0-6.9", "description": "Limited impact, requires interaction"},
            "LOW": {"cvss_range": "0.1-3.9", "description": "Informational, hardening recommendations"},
            "INFO": {"cvss_range": "0.0", "description": "Best practice, no direct security impact"},
        },
    },
}
