"""
OWASP MASVS/MASTG — MASVS-NETWORK: Network Communication

The app secures all network communication following current best practices.

9 test cases with platform-specific guidance and tool mappings.
Based on OWASP MASTG v1.7.0 and MASVS v2.0.0.

Usage:
    from knowledge.masvs.network import TESTS, get_tests_by_platform
"""


MASVS_ID = "MASVS-NETWORK"
CATEGORY = "Network Communication"
DESCRIPTION = "The app secures all network communication following current best practices."


TESTS = [
    {
        "id": "MASTG-TEST-0026",
        "masvs_id": "MASVS-NETWORK-1",
        "title": "Testing Data Encryption on the Network",
        "platform": "android",
        "description": "Verify that all network communication uses TLS 1.2+ and does not fall back to cleartext HTTP. Check Network Security Configuration.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": ["testssl_scan", "sslscan_check", "nmap_scan", "http_headers_check"],
        "mastg_guidance": "Check res/xml/network_security_config.xml. Verify cleartextTrafficPermitted=false. Intercept traffic with proxy to find cleartext connections.",
    },
    {
        "id": "MASTG-TEST-0027",
        "masvs_id": "MASVS-NETWORK-1",
        "title": "Testing Data Encryption on the Network (iOS)",
        "platform": "ios",
        "description": "Verify that App Transport Security (ATS) is properly configured and not globally disabled. All connections should use TLS 1.2+.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": ["testssl_scan", "sslscan_check", "nmap_scan"],
        "mastg_guidance": "Check Info.plist for NSAppTransportSecurity exceptions. Verify NSAllowsArbitraryLoads is not set to true. Test with proxy.",
    },
    {
        "id": "MASTG-TEST-0028",
        "masvs_id": "MASVS-NETWORK-1",
        "title": "Testing the TLS Settings",
        "platform": "android",
        "description": "Verify that the server supports only strong TLS versions (1.2, 1.3) and cipher suites. No SSLv3, TLS 1.0/1.1, or weak ciphers.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": ["testssl_scan", "sslscan_check"],
        "mastg_guidance": "Run testssl.sh against all API endpoints. Check for BEAST, POODLE, FREAK, Logjam vulnerabilities. Verify certificate chain.",
    },
    {
        "id": "MASTG-TEST-0029",
        "masvs_id": "MASVS-NETWORK-1",
        "title": "Testing Endpoint Identity Verification",
        "platform": "android",
        "description": "Verify that the app validates the server certificate chain, hostname, and does not override TrustManager or HostnameVerifier to accept all certificates.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": ["nuclei_scan", "testssl_scan"],
        "mastg_guidance": "Search for custom TrustManager implementations. Check for ALLOW_ALL_HOSTNAME_VERIFIER. Verify no certificate pinning bypass in production.",
    },
    {
        "id": "MASTG-TEST-0030",
        "masvs_id": "MASVS-NETWORK-2",
        "title": "Testing Custom Certificate Stores and SSL Pinning",
        "platform": "android",
        "description": "Verify that the app implements certificate pinning for critical connections and handles pin failures securely.",
        "l1": False,
        "l2": True,
        "r": False,
        "tools": ["testssl_scan"],
        "mastg_guidance": "Check for OkHttp CertificatePinner, Network Security Config pins, or TrustKit. Test if app rejects connections with proxy CA cert.",
    },
    {
        "id": "MASTG-TEST-0031",
        "masvs_id": "MASVS-NETWORK-2",
        "title": "Testing Custom Certificate Stores and SSL Pinning (iOS)",
        "platform": "ios",
        "description": "Verify that certificate pinning is implemented using TrustKit, ATS pinning, or custom URLSession delegate, and cannot be trivially bypassed.",
        "l1": False,
        "l2": True,
        "r": False,
        "tools": ["testssl_scan"],
        "mastg_guidance": "Check for TrustKit configuration, custom URLSessionDelegate, or ATS pinning. Test with proxy using SSL Kill Switch or objection.",
    },
    {
        "id": "MASTG-TEST-0032",
        "masvs_id": "MASVS-NETWORK-1",
        "title": "Testing for Cleartext Traffic",
        "platform": "android",
        "description": "Verify no sensitive data is transmitted over cleartext HTTP connections, including WebView content and third-party SDK traffic.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": ["nmap_scan", "http_fetch"],
        "mastg_guidance": "Capture all network traffic with proxy. Filter for HTTP (non-HTTPS) connections. Check WebView loadUrl calls for http:// URLs.",
    },
    {
        "id": "MASTG-TEST-0033",
        "masvs_id": "MASVS-NETWORK-1",
        "title": "Testing for Cleartext Traffic (iOS)",
        "platform": "ios",
        "description": "Verify no cleartext HTTP traffic is used. Check ATS configuration for exceptions that allow insecure connections.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": ["nmap_scan", "http_fetch"],
        "mastg_guidance": "Check Info.plist NSAppTransportSecurity for domain exceptions. Intercept traffic and identify any HTTP connections.",
    },
    {
        "id": "MASTG-TEST-0034",
        "masvs_id": "MASVS-NETWORK-1",
        "title": "Testing for Unencrypted Sensitive Data in Network Traffic",
        "platform": "android",
        "description": "Verify that sensitive data (credentials, tokens, PII) in network requests is encrypted and not visible in URL parameters.",
        "l1": True,
        "l2": True,
        "r": False,
        "tools": ["http_fetch", "nuclei_scan"],
        "mastg_guidance": "Intercept HTTPS traffic with proxy (Burp/mitmproxy). Check for credentials in URLs, unencrypted fields in request bodies.",
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
