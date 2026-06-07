"""
OWASP ASVS 4.0 — Chapter 14: Configuration

Verification requirements for configuration.
25 test cases with CWE mappings and Modus MCP tool recommendations.

Usage:
    from knowledge.asvs.configuration import TESTS, get_tests_by_level
"""


CATEGORY = "Configuration"
CHAPTER = 14


TESTS = [
    {
        "id": '14.1.1',
        "area": 'Build and Deploy',
        "level": 2,
        "cwe": None,
        "nist": None,
        "requirement": 'Verify that the application build and deployment processes are performed in a secure and repeatable way, such as CI / CD automation, automated configuration management, and automated deployment scripts.',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '14.1.2',
        "area": 'Build and Deploy',
        "level": 2,
        "cwe": 120,
        "nist": None,
        "requirement": 'Verify that compiler flags are configured to enable all available buffer overflow protections and warnings, including stack randomization, data execution prevention, and to break the build if an unsafe pointer, memory, format string, integer, or string operations are found.',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '14.1.3',
        "area": 'Build and Deploy',
        "level": 2,
        "cwe": 16,
        "nist": None,
        "requirement": 'Verify that server configuration is hardened as per the recommendations of the application server and frameworks in use.',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '14.1.4',
        "area": 'Build and Deploy',
        "level": 2,
        "cwe": None,
        "nist": None,
        "requirement": 'Verify that the application, configuration, and all dependencies can be re-deployed using automated deployment scripts, built from a documented and tested runbook in a reasonable time, or restored from backups in a timely fashion.',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '14.1.5',
        "area": 'Build and Deploy',
        "level": 3,
        "cwe": None,
        "nist": None,
        "requirement": 'Verify that authorized administrators can verify the integrity of all security-relevant configurations to detect tampering.',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '14.2.1',
        "area": 'Dependency',
        "level": 1,
        "cwe": 1026,
        "nist": None,
        "requirement": 'Verify that all components are up to date, preferably using a dependency checker during build or compile time. ([C2](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['nuclei_scan'],
    },
    {
        "id": '14.2.2',
        "area": 'Dependency',
        "level": 1,
        "cwe": 1002,
        "nist": None,
        "requirement": 'Verify that all unneeded features, documentation, sample applications and configurations are removed.',
        "tools": ['nuclei_scan'],
    },
    {
        "id": '14.2.3',
        "area": 'Dependency',
        "level": 1,
        "cwe": 829,
        "nist": None,
        "requirement": 'Verify that if application assets, such as JavaScript libraries, CSS stylesheets or web fonts, are hosted externally on a content delivery network (CDN) or external provider, Subresource Integrity (SRI) is used to validate the integrity of the asset.',
        "tools": ['nuclei_scan'],
    },
    {
        "id": '14.2.4',
        "area": 'Dependency',
        "level": 2,
        "cwe": 829,
        "nist": None,
        "requirement": 'Verify that third party components come from pre-defined, trusted and continually maintained repositories. ([C2](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['nuclei_scan'],
    },
    {
        "id": '14.2.5',
        "area": 'Dependency',
        "level": 2,
        "cwe": None,
        "nist": None,
        "requirement": 'Verify that a Software Bill of Materials (SBOM) is maintained of all third party libraries in use. ([C2](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['nuclei_scan'],
    },
    {
        "id": '14.2.6',
        "area": 'Dependency',
        "level": 2,
        "cwe": 265,
        "nist": None,
        "requirement": 'Verify that the attack surface is reduced by sandboxing or encapsulating third party libraries to expose only the required behaviour into the application. ([C2](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['nuclei_scan'],
    },
    {
        "id": '14.3.1',
        "area": 'Unintended Security Disclosure',
        "level": 1,
        "cwe": 209,
        "nist": None,
        "requirement": '[DELETED, DUPLICATE OF 7.4.1]',
        "tools": ['http_fetch', 'feroxbuster_scan', 'nikto_scan', 'nuclei_scan', 'http_headers_check'],
    },
    {
        "id": '14.3.2',
        "area": 'Unintended Security Disclosure',
        "level": 1,
        "cwe": 497,
        "nist": None,
        "requirement": 'Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles, and unintended security disclosures.',
        "tools": ['http_fetch', 'feroxbuster_scan', 'nikto_scan', 'nuclei_scan', 'http_headers_check'],
    },
    {
        "id": '14.3.3',
        "area": 'Unintended Security Disclosure',
        "level": 1,
        "cwe": 200,
        "nist": None,
        "requirement": 'Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components.',
        "tools": ['http_fetch', 'feroxbuster_scan', 'nikto_scan', 'nuclei_scan', 'http_headers_check'],
    },
    {
        "id": '14.4.1',
        "area": 'HTTP Security Headers',
        "level": 1,
        "cwe": 173,
        "nist": None,
        "requirement": 'Verify that every HTTP response contains a Content-Type header. Also specify a safe character set (e.g., UTF-8, ISO-8859-1) if the content types are text/*, /+xml and application/xml. Content must match with the provided Content-Type header.',
        "tools": ['http_headers_check', 'cookie_check'],
    },
    {
        "id": '14.4.2',
        "area": 'HTTP Security Headers',
        "level": 1,
        "cwe": 116,
        "nist": None,
        "requirement": 'Verify that all API responses contain Content-Disposition: attachment; filename="api.json" header (or other appropriate filename for the content type).',
        "tools": ['http_headers_check', 'cookie_check'],
    },
    {
        "id": '14.4.3',
        "area": 'HTTP Security Headers',
        "level": 1,
        "cwe": 1021,
        "nist": None,
        "requirement": 'Verify that a Content Security Policy (CSP) response header is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript injection vulnerabilities.',
        "tools": ['http_headers_check', 'cookie_check'],
    },
    {
        "id": '14.4.4',
        "area": 'HTTP Security Headers',
        "level": 1,
        "cwe": 116,
        "nist": None,
        "requirement": 'Verify that all responses contain a X-Content-Type-Options: nosniff header.',
        "tools": ['http_headers_check', 'cookie_check'],
    },
    {
        "id": '14.4.5',
        "area": 'HTTP Security Headers',
        "level": 1,
        "cwe": 523,
        "nist": None,
        "requirement": 'Verify that a Strict-Transport-Security header is included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800; includeSubdomains.',
        "tools": ['http_headers_check', 'cookie_check'],
    },
    {
        "id": '14.4.6',
        "area": 'HTTP Security Headers',
        "level": 1,
        "cwe": 116,
        "nist": None,
        "requirement": 'Verify that a suitable Referrer-Policy header is included to avoid exposing sensitive information in the URL through the Referer header to untrusted parties.',
        "tools": ['http_headers_check', 'cookie_check'],
    },
    {
        "id": '14.4.7',
        "area": 'HTTP Security Headers',
        "level": 1,
        "cwe": 1021,
        "nist": None,
        "requirement": 'Verify that the content of a web application cannot be embedded in a third-party site by default and that embedding of the exact resources is only allowed where necessary by using suitable Content-Security-Policy: frame-ancestors and X-Frame-Options response headers.',
        "tools": ['http_headers_check', 'cookie_check'],
    },
    {
        "id": '14.5.1',
        "area": 'HTTP Request Header Validation',
        "level": 1,
        "cwe": 749,
        "nist": None,
        "requirement": 'Verify that the application server only accepts the HTTP methods in use by the application/API, including pre-flight OPTIONS, and logs/alerts on any requests that are not valid for the application context.',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '14.5.2',
        "area": 'HTTP Request Header Validation',
        "level": 1,
        "cwe": 346,
        "nist": None,
        "requirement": 'Verify that the supplied Origin header is not used for authentication or access control decisions, as the Origin header can easily be changed by an attacker.',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '14.5.3',
        "area": 'HTTP Request Header Validation',
        "level": 1,
        "cwe": 346,
        "nist": None,
        "requirement": 'Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header uses a strict allow list of trusted domains and subdomains to match against and does not support the "null" origin.',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '14.5.4',
        "area": 'HTTP Request Header Validation',
        "level": 2,
        "cwe": 306,
        "nist": None,
        "requirement": 'Verify that HTTP headers added by a trusted proxy or SSO devices, such as a bearer token, are authenticated by the application.',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
]


def get_tests_by_level(level: int = 1) -> list:
    """Return tests applicable at the given ASVS level (1, 2, or 3)."""
    return [t for t in TESTS if t["level"] <= level and t["level"] > 0]


def get_tests_by_area(area: str) -> list:
    """Return tests for a specific area within this category."""
    return [t for t in TESTS if area.lower() in t["area"].lower()]


def get_automated_tests() -> list:
    """Return tests that have tool mappings (can be partially automated)."""
    return [t for t in TESTS if t["tools"]]
