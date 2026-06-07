"""
OWASP ASVS 4.0 — Chapter 13: API and Web Service

Verification requirements for api and web service.
15 test cases with CWE mappings and Modus MCP tool recommendations.

Usage:
    from knowledge.asvs.api_and_web_service import TESTS, get_tests_by_level
"""


CATEGORY = "API and Web Service"
CHAPTER = 13


TESTS = [
    {
        "id": '13.1.1',
        "area": 'Generic Web Service Security',
        "level": 1,
        "cwe": 116,
        "nist": None,
        "requirement": 'Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing behavior that could be used in SSRF and RFI attacks.',
        "tools": ['http_fetch', 'nuclei_scan', 'http_methods'],
    },
    {
        "id": '13.1.2',
        "area": 'Generic Web Service Security',
        "level": 1,
        "cwe": 419,
        "nist": None,
        "requirement": '[DELETED, DUPLICATE OF 4.3.1]',
        "tools": ['http_fetch', 'nuclei_scan', 'http_methods'],
    },
    {
        "id": '13.1.3',
        "area": 'Generic Web Service Security',
        "level": 1,
        "cwe": 598,
        "nist": None,
        "requirement": 'Verify API URLs do not expose sensitive information, such as the API key, session tokens etc.',
        "tools": ['http_fetch', 'nuclei_scan', 'http_methods'],
    },
    {
        "id": '13.1.4',
        "area": 'Generic Web Service Security',
        "level": 2,
        "cwe": 285,
        "nist": None,
        "requirement": 'Verify that authorization decisions are made at both the URI, enforced by programmatic or declarative security at the controller or router, and at the resource level, enforced by model-based permissions.',
        "tools": ['http_fetch', 'nuclei_scan', 'http_methods'],
    },
    {
        "id": '13.1.5',
        "area": 'Generic Web Service Security',
        "level": 2,
        "cwe": 434,
        "nist": None,
        "requirement": 'Verify that requests containing unexpected or missing content types are rejected with appropriate headers (HTTP response status 406 Unacceptable or 415 Unsupported Media Type).',
        "tools": ['http_fetch', 'nuclei_scan', 'http_methods'],
    },
    {
        "id": '13.2.1',
        "area": 'RESTful Web Service',
        "level": 1,
        "cwe": 650,
        "nist": None,
        "requirement": 'Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users using DELETE or PUT on protected API or resources.',
        "tools": ['http_fetch', 'http_methods', 'arjun_scan', 'jwt_test'],
    },
    {
        "id": '13.2.2',
        "area": 'RESTful Web Service',
        "level": 1,
        "cwe": 20,
        "nist": None,
        "requirement": 'Verify that JSON schema validation is in place and verified before accepting input.',
        "tools": ['http_fetch', 'http_methods', 'arjun_scan', 'jwt_test'],
    },
    {
        "id": '13.2.3',
        "area": 'RESTful Web Service',
        "level": 1,
        "cwe": 352,
        "nist": None,
        "requirement": 'Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: double submit cookie pattern, CSRF nonces, or Origin request header checks.',
        "tools": ['http_fetch', 'http_methods', 'arjun_scan', 'jwt_test'],
    },
    {
        "id": '13.2.4',
        "area": 'RESTful Web Service',
        "level": 2,
        "cwe": 770,
        "nist": None,
        "requirement": '[DELETED, DUPLICATE OF 11.1.4]',
        "tools": ['http_fetch', 'http_methods', 'arjun_scan', 'jwt_test'],
    },
    {
        "id": '13.2.5',
        "area": 'RESTful Web Service',
        "level": 2,
        "cwe": 436,
        "nist": None,
        "requirement": 'Verify that REST services explicitly check the incoming Content-Type to be the expected one, such as application/xml or application/json.',
        "tools": ['http_fetch', 'http_methods', 'arjun_scan', 'jwt_test'],
    },
    {
        "id": '13.2.6',
        "area": 'RESTful Web Service',
        "level": 2,
        "cwe": 345,
        "nist": None,
        "requirement": 'Verify that the message headers and payload are trustworthy and not modified in transit. Requiring strong encryption for transport (TLS only) may be sufficient in many cases as it provides both confidentiality and integrity protection. Per-message digital signatures can provide additional assurance on top of the transport protections for high-security applications but bring with them additional complexity and risks to weigh against the benefits.',
        "tools": ['http_fetch', 'http_methods', 'arjun_scan', 'jwt_test'],
    },
    {
        "id": '13.3.1',
        "area": 'SOAP Web Service',
        "level": 1,
        "cwe": 20,
        "nist": None,
        "requirement": 'Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes place.',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '13.3.2',
        "area": 'SOAP Web Service',
        "level": 2,
        "cwe": 345,
        "nist": None,
        "requirement": 'Verify that the message payload is signed using WS-Security to ensure reliable transport between client and service.',
        "tools": ['nuclei_scan', 'http_fetch'],
    },
    {
        "id": '13.4.1',
        "area": 'GraphQL',
        "level": 2,
        "cwe": 770,
        "nist": None,
        "requirement": 'Verify that a query allow list or a combination of depth limiting and amount limiting is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. For more advanced scenarios, query cost analysis should be used.',
        "tools": ['graphql_test', 'http_fetch'],
    },
    {
        "id": '13.4.2',
        "area": 'GraphQL',
        "level": 2,
        "cwe": 285,
        "nist": None,
        "requirement": 'Verify that GraphQL or other data layer authorization logic should be implemented at the business logic layer instead of the GraphQL layer.',
        "tools": ['graphql_test', 'http_fetch'],
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
