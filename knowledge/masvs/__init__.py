"""
OWASP Mobile Application Security (MAS) Knowledge Base (trimmed for ModTester)
2 categories: Network + Auth (server-side/API testing).
"""

from .auth import TESTS as AUTH_TESTS
from .network import TESTS as NETWORK_TESTS


ALL_CATEGORIES = {
    "MASVS-AUTH": AUTH_TESTS,
    "MASVS-NETWORK": NETWORK_TESTS,
}

CATEGORY_NAMES = {
    "MASVS-AUTH": "Authentication and Authorization",
    "MASVS-NETWORK": "Network Communication",
}


def get_all_tests() -> list:
    all_tests = []
    for category, tests in ALL_CATEGORIES.items():
        for test in tests:
            t = dict(test)
            t["category"] = category
            all_tests.append(t)
    return all_tests


def get_tests_for_category(category: str) -> list:
    cat_upper = category.upper()
    for cat_name, tests in ALL_CATEGORIES.items():
        if cat_upper in cat_name:
            return tests
    return []


def get_tests_by_platform(platform: str) -> list:
    return [t for t in get_all_tests() if t.get("platform", "").lower() == platform.lower()]


def get_coverage_summary(tools_used: list = None) -> dict:
    all_tests = get_all_tests()
    automated = [t for t in all_tests if t.get("tools")]
    platforms = {"android": 0, "ios": 0}
    for t in all_tests:
        p = t.get("platform", "").lower()
        if p in platforms:
            platforms[p] += 1
    summary = {
        "total_tests": len(all_tests),
        "automated_tests": len(automated),
        "manual_tests": len(all_tests) - len(automated),
        "platforms": platforms,
        "categories": {},
    }
    for cat_name, tests in ALL_CATEGORIES.items():
        cat_auto = [t for t in tests if t.get("tools")]
        summary["categories"][cat_name] = {
            "total": len(tests),
            "automated": len(cat_auto),
        }
    return summary
