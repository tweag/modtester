"""
OWASP MASVS/MASTG — MASVS-AUTH: Authentication and Authorization

The app uses secure authentication and authorization protocols and follows relevant best practices.

5 test cases with platform-specific guidance and tool mappings.
Based on OWASP MASTG v1.7.0 and MASVS v2.0.0.

Usage:
    from knowledge.masvs.auth import TESTS, get_tests_by_platform
"""


MASVS_ID = "MASVS-AUTH"
CATEGORY = "Authentication and Authorization"
DESCRIPTION = "The app uses secure authentication and authorization protocols and follows relevant best practices."


TESTS = [
    {
        "id": "MASTG-TEST-0021",
        "masvs_id": "MASVS-AUTH-1",
        "title": "Testing Confirm Credentials (Android)",
        "platform": "android",
        "description": "Verify that the app properly implements biometric authentication using BiometricPrompt API with crypto-based confirmation, not just event-based.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": [],
        "mastg_guidance": "Check BiometricPrompt implementation. Verify CryptoObject is used (crypto-based auth). Test fallback mechanisms.",
    },
    {
        "id": "MASTG-TEST-0022",
        "masvs_id": "MASVS-AUTH-1",
        "title": "Testing Local Authentication (iOS)",
        "platform": "ios",
        "description": "Verify that local authentication (Touch ID/Face ID) is implemented securely using Keychain access control with biometric binding.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": [],
        "mastg_guidance": "Check LAContext usage. Verify Keychain items use kSecAccessControlBiometryCurrentSet. Test if biometric bypass is possible via Frida.",
    },
    {
        "id": "MASTG-TEST-0023",
        "masvs_id": "MASVS-AUTH-2",
        "title": "Testing OAuth/SSO Authentication",
        "platform": "android",
        "description": "Verify that OAuth 2.0 / OpenID Connect implementations use PKCE, validate tokens properly, and do not expose tokens in logs or URLs.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": ["jwt_test", "http_fetch", "nuclei_scan"],
        "mastg_guidance": "Intercept OAuth flow. Check for PKCE (code_challenge). Verify token storage. Test token refresh and revocation.",
    },
    {
        "id": "MASTG-TEST-0024",
        "masvs_id": "MASVS-AUTH-2",
        "title": "Verifying Session Management",
        "platform": "android",
        "description": "Verify that session tokens are generated securely, transmitted over TLS, have appropriate expiry, and are invalidated on logout.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": ["jwt_test", "cookie_check", "http_fetch"],
        "mastg_guidance": "Check token entropy and expiry. Test session invalidation on logout. Verify tokens are not cached insecurely. Test concurrent session handling.",
    },
    {
        "id": "MASTG-TEST-0025",
        "masvs_id": "MASVS-AUTH-3",
        "title": "Testing Step-up Authentication",
        "platform": "android",
        "description": "Verify that sensitive operations (payments, password changes, data export) require additional authentication beyond the initial session.",
        "l1": False,
        "l2": True,
        "r": False,
        "tools": ["http_fetch"],
        "mastg_guidance": "Identify sensitive endpoints. Test if they can be accessed with only session token. Verify re-authentication is required.",
    },
]


def get_tests_by_platform(platform: str = "android") -> list:
    """Return tests for a specific platform (android/ios)."""
    return [t for t in TESTS if t["platform"] == platform.lower()]


def get_tests_by_level(level: str = "l1") -> list:
    """Return tests for a specific MASVS level (l1, l2, r)."""
    return [t for t in TESTS if t.get(level.lower(), False)]


def get_automated_tests() -> list:
    """Return tests that have tool mappings."""
    return [t for t in TESTS if t["tools"]]
