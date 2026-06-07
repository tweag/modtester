"""
OWASP ASVS 4.0 — Top 50 Most Impactful Verification Requirements

Representative sample demonstrating standards-based assessment capability.
Full version has 286 requirements across 14 categories.
"""

ASVS_TOP_50 = [
    # V2 — Authentication
    {"id": "2.1.1", "category": "Authentication", "requirement": "Verify passwords are at least 8 characters", "level": 1, "cwe": 521, "tools": ["http_fetch"]},
    {"id": "2.1.7", "category": "Authentication", "requirement": "Verify passwords are checked against breached password lists", "level": 1, "cwe": 521, "tools": ["http_fetch"]},
    {"id": "2.2.1", "category": "Authentication", "requirement": "Verify anti-automation controls for credential stuffing", "level": 1, "cwe": 307, "tools": ["http_fetch", "verify_default_creds"]},
    {"id": "2.5.2", "category": "Authentication", "requirement": "Verify password hints or knowledge-based auth not present", "level": 1, "cwe": 640, "tools": ["http_fetch"]},
    {"id": "2.7.1", "category": "Authentication", "requirement": "Verify OTP/TOTP tokens expire after use", "level": 1, "cwe": 287, "tools": ["http_fetch"]},
    {"id": "2.8.1", "category": "Authentication", "requirement": "Verify time-based OTP has defined lifetime", "level": 2, "cwe": 613, "tools": ["http_fetch"]},

    # V3 — Session Management
    {"id": "3.2.1", "category": "Session Management", "requirement": "Verify new session token on authentication", "level": 1, "cwe": 384, "tools": ["cookie_check", "http_fetch"]},
    {"id": "3.4.1", "category": "Session Management", "requirement": "Verify cookie-based tokens have Secure attribute", "level": 1, "cwe": 614, "tools": ["cookie_check"]},
    {"id": "3.4.2", "category": "Session Management", "requirement": "Verify cookie-based tokens have HttpOnly attribute", "level": 1, "cwe": 1004, "tools": ["cookie_check"]},
    {"id": "3.4.3", "category": "Session Management", "requirement": "Verify cookie-based tokens have SameSite attribute", "level": 1, "cwe": 16, "tools": ["cookie_check"]},
    {"id": "3.7.1", "category": "Session Management", "requirement": "Verify logout invalidates session server-side", "level": 1, "cwe": 613, "tools": ["http_fetch"]},

    # V4 — Access Control
    {"id": "4.1.1", "category": "Access Control", "requirement": "Verify access controls enforced server-side", "level": 1, "cwe": 602, "tools": ["http_fetch", "http_methods"]},
    {"id": "4.1.2", "category": "Access Control", "requirement": "Verify access controls cannot be bypassed by parameter tampering", "level": 1, "cwe": 639, "tools": ["http_fetch", "arjun_scan"]},
    {"id": "4.2.1", "category": "Access Control", "requirement": "Verify sensitive data/APIs protected against IDOR", "level": 1, "cwe": 639, "tools": ["http_fetch"]},
    {"id": "4.3.1", "category": "Access Control", "requirement": "Verify admin interfaces use MFA or additional controls", "level": 1, "cwe": 419, "tools": ["http_fetch"]},

    # V5 — Input Validation
    {"id": "5.1.1", "category": "Input Validation", "requirement": "Verify HTTP parameter pollution defenses", "level": 1, "cwe": 235, "tools": ["arjun_scan", "http_fetch"]},
    {"id": "5.2.1", "category": "Input Validation", "requirement": "Verify anti-XSS on HTML form fields", "level": 1, "cwe": 79, "tools": ["nuclei_scan"]},
    {"id": "5.3.1", "category": "Input Validation", "requirement": "Verify output encoding prevents XSS", "level": 1, "cwe": 79, "tools": ["nuclei_scan", "http_fetch"]},
    {"id": "5.3.4", "category": "Input Validation", "requirement": "Verify data selection/queries use parameterized queries", "level": 1, "cwe": 89, "tools": ["sqlmap_scan", "verify_sqli"]},
    {"id": "5.3.7", "category": "Input Validation", "requirement": "Verify application protects against OS command injection", "level": 1, "cwe": 78, "tools": ["commix_scan", "verify_rce"]},
    {"id": "5.3.8", "category": "Input Validation", "requirement": "Verify application protects against LFI/RFI", "level": 1, "cwe": 829, "tools": ["verify_lfi", "nuclei_scan"]},
    {"id": "5.5.2", "category": "Input Validation", "requirement": "Verify XML parsing is configured to prevent XXE", "level": 1, "cwe": 611, "tools": ["nuclei_scan", "http_fetch"]},

    # V6 — Cryptography
    {"id": "6.2.1", "category": "Cryptography", "requirement": "Verify all cryptographic modules fail securely", "level": 1, "cwe": 310, "tools": ["testssl_scan"]},
    {"id": "6.2.5", "category": "Cryptography", "requirement": "Verify insecure algorithms (MD5, SHA1) not used for security", "level": 2, "cwe": 327, "tools": ["testssl_scan", "sslscan_check"]},

    # V7 — Error Handling
    {"id": "7.1.1", "category": "Error Handling", "requirement": "Verify app does not log credentials or sensitive data", "level": 1, "cwe": 532, "tools": ["http_fetch"]},
    {"id": "7.4.1", "category": "Error Handling", "requirement": "Verify generic error messages shown to users", "level": 1, "cwe": 210, "tools": ["http_fetch", "nuclei_scan"]},

    # V8 — Data Protection
    {"id": "8.1.1", "category": "Data Protection", "requirement": "Verify sensitive data identified and classified", "level": 1, "cwe": 200, "tools": ["http_fetch"]},
    {"id": "8.3.1", "category": "Data Protection", "requirement": "Verify sensitive data in HTTP body/headers sent with cache-control", "level": 1, "cwe": 524, "tools": ["http_headers_check"]},
    {"id": "8.3.4", "category": "Data Protection", "requirement": "Verify sensitive data not included in URL parameters", "level": 1, "cwe": 319, "tools": ["http_fetch", "katana_crawl"]},

    # V9 — Communications
    {"id": "9.1.1", "category": "Communications", "requirement": "Verify TLS for all client connections", "level": 1, "cwe": 319, "tools": ["testssl_scan", "sslscan_check"]},
    {"id": "9.1.2", "category": "Communications", "requirement": "Verify TLS 1.2+ with strong cipher suites", "level": 1, "cwe": 326, "tools": ["testssl_scan", "sslscan_check"]},
    {"id": "9.1.3", "category": "Communications", "requirement": "Verify only latest recommended TLS versions enabled", "level": 1, "cwe": 326, "tools": ["testssl_scan"]},

    # V10 — Malicious Code
    {"id": "10.3.2", "category": "Malicious Code", "requirement": "Verify application source code does not contain backdoors", "level": 3, "cwe": 507, "tools": ["nuclei_scan"]},

    # V11 — Business Logic
    {"id": "11.1.1", "category": "Business Logic", "requirement": "Verify app processes only business logic flows in sequential order", "level": 1, "cwe": 841, "tools": ["http_fetch"]},

    # V12 — Files and Resources
    {"id": "12.1.1", "category": "Files and Resources", "requirement": "Verify uploaded files stored outside webroot", "level": 1, "cwe": 552, "tools": ["http_fetch", "ffuf_fuzz"]},
    {"id": "12.3.1", "category": "Files and Resources", "requirement": "Verify user-submitted filenames sanitized", "level": 1, "cwe": 22, "tools": ["verify_lfi", "http_fetch"]},

    # V13 — API and Web Service
    {"id": "13.1.1", "category": "API Security", "requirement": "Verify all API responses contain proper Content-Type", "level": 1, "cwe": 16, "tools": ["http_fetch", "http_headers_check"]},
    {"id": "13.2.1", "category": "API Security", "requirement": "Verify RESTful APIs validate Content-Type header", "level": 1, "cwe": 436, "tools": ["http_fetch"]},
    {"id": "13.2.5", "category": "API Security", "requirement": "Verify REST APIs check incoming Content-Type is expected", "level": 2, "cwe": 436, "tools": ["http_fetch"]},
    {"id": "13.4.1", "category": "API Security", "requirement": "Verify GraphQL has query depth/complexity limits", "level": 2, "cwe": 770, "tools": ["http_fetch"]},

    # V14 — Configuration
    {"id": "14.1.1", "category": "Configuration", "requirement": "Verify build/deploy processes address security", "level": 2, "cwe": 2, "tools": ["nuclei_scan"]},
    {"id": "14.2.1", "category": "Configuration", "requirement": "Verify all components are up to date", "level": 1, "cwe": 1104, "tools": ["nuclei_scan"]},
    {"id": "14.3.2", "category": "Configuration", "requirement": "Verify debug modes disabled in production", "level": 1, "cwe": 497, "tools": ["nuclei_scan", "http_fetch"]},
    {"id": "14.4.1", "category": "Configuration", "requirement": "Verify every HTTP response contains Content-Type with charset", "level": 1, "cwe": 173, "tools": ["http_headers_check"]},
    {"id": "14.4.3", "category": "Configuration", "requirement": "Verify Content-Security-Policy header prevents XSS", "level": 1, "cwe": 1021, "tools": ["http_headers_check"]},
    {"id": "14.4.4", "category": "Configuration", "requirement": "Verify X-Content-Type-Options: nosniff is set", "level": 1, "cwe": 16, "tools": ["http_headers_check"]},
    {"id": "14.4.5", "category": "Configuration", "requirement": "Verify Strict-Transport-Security header on all responses", "level": 1, "cwe": 523, "tools": ["http_headers_check"]},
    {"id": "14.4.6", "category": "Configuration", "requirement": "Verify Referrer-Policy header is included", "level": 1, "cwe": 116, "tools": ["http_headers_check"]},
    {"id": "14.5.1", "category": "Configuration", "requirement": "Verify application server accepts only defined HTTP methods", "level": 1, "cwe": 749, "tools": ["http_methods"]},
    {"id": "14.5.3", "category": "Configuration", "requirement": "Verify CORS Access-Control-Allow-Origin uses strict allowlist", "level": 1, "cwe": 346, "tools": ["http_headers_check", "nuclei_scan"]},
]


def get_asvs_by_category(category: str) -> list:
    """Get ASVS requirements for a specific category."""
    return [r for r in ASVS_TOP_50 if r["category"].lower() == category.lower()]


def get_asvs_summary() -> dict:
    """Get summary statistics."""
    categories = {}
    for r in ASVS_TOP_50:
        cat = r["category"]
        categories[cat] = categories.get(cat, 0) + 1
    return {
        "total": len(ASVS_TOP_50),
        "categories": categories,
        "note": "Sample of 50 most impactful requirements. Full ASVS has 286.",
    }
