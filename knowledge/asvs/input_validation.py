"""
OWASP ASVS 4.0 — Chapter 5: Input Validation

Verification requirements for input validation.
30 test cases with CWE mappings and Modus MCP tool recommendations.

Usage:
    from knowledge.asvs.input_validation import TESTS, get_tests_by_level
"""


CATEGORY = "Input Validation"
CHAPTER = 5


TESTS = [
    {
        "id": '5.1.1',
        "area": 'Input Validation',
        "level": 1,
        "cwe": 235,
        "nist": None,
        "requirement": 'Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (GET, POST, cookies, headers, or environment variables).',
        "tools": ['sqlmap_scan', 'commix_scan', 'nuclei_scan', 'arjun_scan', 'http_fetch'],
    },
    {
        "id": '5.1.2',
        "area": 'Input Validation',
        "level": 1,
        "cwe": 915,
        "nist": None,
        "requirement": 'Verify that frameworks protect against mass parameter assignment attacks, or that the application has countermeasures to protect against unsafe parameter assignment, such as marking fields private or similar. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['sqlmap_scan', 'commix_scan', 'nuclei_scan', 'arjun_scan', 'http_fetch'],
    },
    {
        "id": '5.1.3',
        "area": 'Input Validation',
        "level": 1,
        "cwe": 20,
        "nist": None,
        "requirement": 'Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (allow lists). ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['sqlmap_scan', 'commix_scan', 'nuclei_scan', 'arjun_scan', 'http_fetch'],
    },
    {
        "id": '5.1.4',
        "area": 'Input Validation',
        "level": 1,
        "cwe": 20,
        "nist": None,
        "requirement": 'Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length and pattern (e.g. credit card numbers, e-mail addresses, telephone numbers, or validating that two related fields are reasonable, such as checking that suburb and zip/postcode match). ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['sqlmap_scan', 'commix_scan', 'nuclei_scan', 'arjun_scan', 'http_fetch'],
    },
    {
        "id": '5.1.5',
        "area": 'Input Validation',
        "level": 1,
        "cwe": 601,
        "nist": None,
        "requirement": 'Verify that URL redirects and forwards only allow destinations which appear on an allow list, or show a warning when redirecting to potentially untrusted content.',
        "tools": ['sqlmap_scan', 'commix_scan', 'nuclei_scan', 'arjun_scan', 'http_fetch'],
    },
    {
        "id": '5.2.1',
        "area": 'Sanitization and Sandboxing',
        "level": 1,
        "cwe": 116,
        "nist": None,
        "requirement": 'Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized with an HTML sanitizer library or framework feature. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['nuclei_scan', 'sqlmap_scan', 'commix_scan'],
    },
    {
        "id": '5.2.2',
        "area": 'Sanitization and Sandboxing',
        "level": 1,
        "cwe": 138,
        "nist": None,
        "requirement": 'Verify that unstructured data is sanitized to enforce safety measures such as allowed characters and length.',
        "tools": ['nuclei_scan', 'sqlmap_scan', 'commix_scan'],
    },
    {
        "id": '5.2.3',
        "area": 'Sanitization and Sandboxing',
        "level": 1,
        "cwe": 147,
        "nist": None,
        "requirement": 'Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection.',
        "tools": ['nuclei_scan', 'sqlmap_scan', 'commix_scan'],
    },
    {
        "id": '5.2.4',
        "area": 'Sanitization and Sandboxing',
        "level": 1,
        "cwe": 95,
        "nist": None,
        "requirement": 'Verify that the application avoids the use of eval() or other dynamic code execution features. Where there is no alternative, any user input being included must be sanitized or sandboxed before being executed.',
        "tools": ['nuclei_scan', 'sqlmap_scan', 'commix_scan'],
    },
    {
        "id": '5.2.5',
        "area": 'Sanitization and Sandboxing',
        "level": 1,
        "cwe": 94,
        "nist": None,
        "requirement": 'Verify that the application protects against template injection attacks by ensuring that any user input being included is sanitized or sandboxed.',
        "tools": ['nuclei_scan', 'sqlmap_scan', 'commix_scan'],
    },
    {
        "id": '5.2.6',
        "area": 'Sanitization and Sandboxing',
        "level": 1,
        "cwe": 918,
        "nist": None,
        "requirement": 'Verify that the application protects against SSRF attacks, by validating or sanitizing untrusted data or HTTP file metadata, such as filenames and URL input fields, and uses allow lists of protocols, domains, paths and ports.',
        "tools": ['nuclei_scan', 'sqlmap_scan', 'commix_scan'],
    },
    {
        "id": '5.2.7',
        "area": 'Sanitization and Sandboxing',
        "level": 1,
        "cwe": 159,
        "nist": None,
        "requirement": 'Verify that the application sanitizes, disables, or sandboxes user-supplied Scalable Vector Graphics (SVG) scriptable content, especially as they relate to XSS resulting from inline scripts, and foreignObject.',
        "tools": ['nuclei_scan', 'sqlmap_scan', 'commix_scan'],
    },
    {
        "id": '5.2.8',
        "area": 'Sanitization and Sandboxing',
        "level": 1,
        "cwe": 94,
        "nist": None,
        "requirement": 'Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar.',
        "tools": ['nuclei_scan', 'sqlmap_scan', 'commix_scan'],
    },
    {
        "id": '5.3.1',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 116,
        "nist": None,
        "requirement": "Verify that output encoding is relevant for the interpreter and context required. For example, use encoders specifically for HTML values, HTML attributes, JavaScript, URL parameters, HTTP headers, SMTP, and others as the context requires, especially from untrusted inputs (e.g. names with Unicode or apostrophes, such as ねこ or O'Hara). ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))",
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.3.2',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 176,
        "nist": None,
        "requirement": "Verify that output encoding preserves the user's chosen character set and locale, such that any Unicode character point is valid and safely handled. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))",
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.3.3',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 79,
        "nist": None,
        "requirement": 'Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected, stored, and DOM based XSS. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.3.4',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 89,
        "nist": None,
        "requirement": 'Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks. ([C3](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.3.5',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 89,
        "nist": None,
        "requirement": 'Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection. ([C3, C4](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.3.6',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 830,
        "nist": None,
        "requirement": 'Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.3.7',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 943,
        "nist": None,
        "requirement": 'Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.3.8',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 78,
        "nist": None,
        "requirement": 'Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.3.9',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 829,
        "nist": None,
        "requirement": 'Verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks.',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.3.10',
        "area": 'Output encoding and Injection Prevention',
        "level": 1,
        "cwe": 643,
        "nist": None,
        "requirement": 'Verify that the application protects against XPath injection or XML injection attacks. ([C4](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.4.1',
        "area": 'Memory, String and Unmanaged Code',
        "level": 2,
        "cwe": 120,
        "nist": None,
        "requirement": 'Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows.',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.4.2',
        "area": 'Memory, String and Unmanaged Code',
        "level": 2,
        "cwe": 134,
        "nist": None,
        "requirement": 'Verify that format strings do not take potentially hostile input, and are constant.',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.4.3',
        "area": 'Memory, String and Unmanaged Code',
        "level": 2,
        "cwe": 190,
        "nist": None,
        "requirement": 'Verify that sign, range, and input validation techniques are used to prevent integer overflows.',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '5.5.1',
        "area": 'Deserialization Prevention',
        "level": 1,
        "cwe": 502,
        "nist": None,
        "requirement": 'Verify that serialized objects use integrity checks or are encrypted to prevent hostile object creation or data tampering. ([C5](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '5.5.2',
        "area": 'Deserialization Prevention',
        "level": 1,
        "cwe": 611,
        "nist": None,
        "requirement": 'Verify that the application correctly restricts XML parsers to only use the most restrictive configuration possible and to ensure that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks.',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '5.5.3',
        "area": 'Deserialization Prevention',
        "level": 1,
        "cwe": 502,
        "nist": None,
        "requirement": 'Verify that deserialization of untrusted data is avoided or is protected in both custom code and third-party libraries (such as JSON, XML and YAML parsers).',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '5.5.4',
        "area": 'Deserialization Prevention',
        "level": 1,
        "cwe": 95,
        "nist": None,
        "requirement": 'Verify that when parsing JSON in browsers or JavaScript-based backends, JSON.parse is used to parse the JSON document. Do not use eval() to parse JSON.',
        "tools": ['nuclei_scan', 'http_fetch'],
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
