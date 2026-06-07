"""
OWASP ASVS 4.0 — Chapter 3: Session Management

Verification requirements for session management.
20 test cases with CWE mappings and Modus MCP tool recommendations.

Usage:
    from knowledge.asvs.session_management import TESTS, get_tests_by_level
"""


CATEGORY = "Session Management"
CHAPTER = 3


TESTS = [
    {
        "id": '3.1.1',
        "area": 'Fundamental Session Management Security',
        "level": 1,
        "cwe": 598,
        "nist": None,
        "requirement": 'Verify the application never reveals session tokens in URL parameters or error messages.',
        "tools": ['cookie_check', 'http_fetch', 'nuclei_scan'],
    },
    {
        "id": '3.2.1',
        "area": 'Session Binding',
        "level": 1,
        "cwe": 384,
        "nist": '7.1',
        "requirement": 'Verify the application generates a new session token on user authentication. ([C6](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=Formal_Numbering))',
        "tools": ['cookie_check', 'http_fetch'],
    },
    {
        "id": '3.2.2',
        "area": 'Session Binding',
        "level": 1,
        "cwe": 331,
        "nist": '7.1',
        "requirement": 'Verify that session tokens possess at least 64 bits of entropy. ([C6](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=Formal_Numbering))',
        "tools": ['cookie_check', 'http_fetch'],
    },
    {
        "id": '3.2.3',
        "area": 'Session Binding',
        "level": 1,
        "cwe": 539,
        "nist": '7.1',
        "requirement": 'Verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies (see section 3.4) or HTML 5 session storage.',
        "tools": ['cookie_check', 'http_fetch'],
    },
    {
        "id": '3.2.4',
        "area": 'Session Binding',
        "level": 2,
        "cwe": 331,
        "nist": '7.1',
        "requirement": 'Verify that session tokens are generated using approved cryptographic algorithms. ([C6](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=Formal_Numbering))',
        "tools": ['cookie_check', 'http_fetch'],
    },
    {
        "id": '3.3.1',
        "area": 'Session Termination',
        "level": 1,
        "cwe": 613,
        "nist": '7.1',
        "requirement": 'Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including across relying parties. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['http_fetch', 'cookie_check'],
    },
    {
        "id": '3.3.2',
        "area": 'Session Termination',
        "level": 1,
        "cwe": 613,
        "nist": '7.2',
        "requirement": 'If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))\n* L1: 30 days\n* L2: 12 hours or 30 minutes of inactivity, 2FA optional\n* L3: 12 hours or 15 minutes of inactivity, with 2FA',
        "tools": ['http_fetch', 'cookie_check'],
    },
    {
        "id": '3.3.3',
        "area": 'Session Termination',
        "level": 2,
        "cwe": 613,
        "nist": None,
        "requirement": 'Verify that the application gives the option to terminate all other active sessions after a successful password change (including change via password reset/recovery), and that this is effective across the application, federated login (if present), and any relying parties.',
        "tools": ['http_fetch', 'cookie_check'],
    },
    {
        "id": '3.3.4',
        "area": 'Session Termination',
        "level": 2,
        "cwe": 613,
        "nist": '7.1',
        "requirement": 'Verify that users are able to view and (having re-entered login credentials) log out of any or all currently active sessions and devices.',
        "tools": ['http_fetch', 'cookie_check'],
    },
    {
        "id": '3.4.1',
        "area": 'Cookie-based Session Management',
        "level": 1,
        "cwe": 614,
        "nist": '7.1.1',
        "requirement": "Verify that cookie-based session tokens have the 'Secure' attribute set. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))",
        "tools": ['cookie_check', 'http_fetch'],
    },
    {
        "id": '3.4.2',
        "area": 'Cookie-based Session Management',
        "level": 1,
        "cwe": 1004,
        "nist": '7.1.1',
        "requirement": "Verify that cookie-based session tokens have the 'HttpOnly' attribute set. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))",
        "tools": ['cookie_check', 'http_fetch'],
    },
    {
        "id": '3.4.3',
        "area": 'Cookie-based Session Management',
        "level": 1,
        "cwe": 16,
        "nist": '7.1.1',
        "requirement": "Verify that cookie-based session tokens utilize the 'SameSite' attribute to limit exposure to cross-site request forgery attacks. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))",
        "tools": ['cookie_check', 'http_fetch'],
    },
    {
        "id": '3.4.4',
        "area": 'Cookie-based Session Management',
        "level": 1,
        "cwe": 16,
        "nist": '7.1.1',
        "requirement": 'Verify that cookie-based session tokens use the "__Host-" prefix so cookies are only sent to the host that initially set the cookie.',
        "tools": ['cookie_check', 'http_fetch'],
    },
    {
        "id": '3.4.5',
        "area": 'Cookie-based Session Management',
        "level": 1,
        "cwe": 16,
        "nist": '7.1.1',
        "requirement": 'Verify that if the application is published under a domain name with other applications that set or use session cookies that might disclose the session cookies, set the path attribute in cookie-based session tokens using the most precise path possible. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering))',
        "tools": ['cookie_check', 'http_fetch'],
    },
    {
        "id": '3.5.1',
        "area": 'Token-based Session Management',
        "level": 2,
        "cwe": 290,
        "nist": '7.1.2',
        "requirement": 'Verify the application allows users to revoke OAuth tokens that form trust relationships with linked applications.',
        "tools": ['jwt_test', 'http_fetch'],
    },
    {
        "id": '3.5.2',
        "area": 'Token-based Session Management',
        "level": 2,
        "cwe": 798,
        "nist": None,
        "requirement": 'Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations.',
        "tools": ['jwt_test', 'http_fetch'],
    },
    {
        "id": '3.5.3',
        "area": 'Token-based Session Management',
        "level": 2,
        "cwe": 345,
        "nist": None,
        "requirement": 'Verify that stateless session tokens use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks.',
        "tools": ['jwt_test', 'http_fetch'],
    },
    {
        "id": '3.6.1',
        "area": 'Federated Re-authentication',
        "level": 3,
        "cwe": 613,
        "nist": '7.2.1',
        "requirement": "Verify that  Relying Parties (RPs) specify the maximum authentication time to Credential Service Providers (CSPs) and that CSPs re-authenticate the subscriber if they haven't used a session within that period.",
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '3.6.2',
        "area": 'Federated Re-authentication',
        "level": 3,
        "cwe": 613,
        "nist": '7.2.1',
        "requirement": 'Verify that Credential Service Providers (CSPs) inform Relying Parties (RPs) of the last authentication event, to allow RPs to determine if they need to re-authenticate the user.',
        "tools": ['http_fetch', 'nuclei_scan'],
    },
    {
        "id": '3.7.1',
        "area": 'Defenses Against Session Management Exploits',
        "level": 1,
        "cwe": 778,
        "nist": None,
        "requirement": 'Verify the application ensures a valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications.',
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
