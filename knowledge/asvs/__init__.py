"""
OWASP ASVS 4.0 Knowledge Base (trimmed for ModTester demo)
5 categories focused on web + mobile API + public IP testing.
"""

from .authentication import TESTS as AUTHENTICATION_TESTS
from .session_management import TESTS as SESSION_MANAGEMENT_TESTS
from .input_validation import TESTS as INPUT_VALIDATION_TESTS
from .api_and_web_service import TESTS as API_AND_WEB_SERVICE_TESTS
from .configuration import TESTS as CONFIGURATION_TESTS


ALL_CATEGORIES = {
    "Authentication": AUTHENTICATION_TESTS,
    "Session Management": SESSION_MANAGEMENT_TESTS,
    "Input Validation": INPUT_VALIDATION_TESTS,
    "API and Web Service": API_AND_WEB_SERVICE_TESTS,
    "Configuration": CONFIGURATION_TESTS,
}


def get_all_tests() -> list:
    """Return all 286 ASVS test cases."""
    all_tests = []
    for category, tests in ALL_CATEGORIES.items():
        for test in tests:
            t = dict(test)
            t["category"] = category
            all_tests.append(t)
    return all_tests


def get_tests_for_category(category: str) -> list:
    """Return tests for a specific category (case-insensitive partial match)."""
    cat_lower = category.lower()
    for cat_name, tests in ALL_CATEGORIES.items():
        if cat_lower in cat_name.lower():
            return tests
    return []


def get_tests_by_level(level: int = 1) -> list:
    """Return all tests applicable at the given ASVS level (1, 2, or 3)."""
    return [t for t in get_all_tests() if t["level"] <= level and t["level"] > 0]


def get_tests_by_cwe(cwe_id: int) -> list:
    """Return all tests mapped to a specific CWE."""
    return [t for t in get_all_tests() if t.get("cwe") == cwe_id]


def search_tests(query: str) -> list:
    """Search test requirements by keyword."""
    q = query.lower()
    return [t for t in get_all_tests() if q in t.get("requirement", "").lower()
            or q in t.get("area", "").lower()]


def get_coverage_summary(tools_used: list = None) -> dict:
    """
    Get a summary of ASVS coverage, optionally showing what's been
    covered by the tools already used in an assessment.

    Returns dict with total counts, per-category counts, and coverage %.
    """
    all_tests = get_all_tests()
    automated = [t for t in all_tests if t.get("tools")]
    manual = [t for t in all_tests if not t.get("tools")]

    summary = {
        "total_tests": len(all_tests),
        "automated_tests": len(automated),
        "manual_tests": len(manual),
        "categories": {},
    }

    for cat_name, tests in ALL_CATEGORIES.items():
        cat_auto = [t for t in tests if t.get("tools")]
        summary["categories"][cat_name] = {
            "total": len(tests),
            "automated": len(cat_auto),
            "manual": len(tests) - len(cat_auto),
        }

    if tools_used:
        tools_set = set(tools_used)
        covered = [t for t in all_tests if tools_set.intersection(set(t.get("tools", [])))]
        summary["covered_by_tools"] = len(covered)
        summary["coverage_pct"] = round(len(covered) / len(all_tests) * 100, 1) if all_tests else 0
        summary["uncovered"] = [
            {"id": t["id"], "category": t.get("category", ""), "requirement": t["requirement"][:80]}
            for t in all_tests if not tools_set.intersection(set(t.get("tools", [])))
        ]

    return summary


def get_checklist_text(level: int = 1) -> str:
    """
    Get a compact checklist for inclusion in the AI system prompt.
    Groups by category, shows test count and tool coverage.
    """
    lines = [f"OWASP ASVS Level {level} Checklist:"]
    total = 0
    for cat_name, tests in ALL_CATEGORIES.items():
        level_tests = [t for t in tests if t["level"] <= level and t["level"] > 0]
        auto = [t for t in level_tests if t.get("tools")]
        if level_tests:
            lines.append(f"  {cat_name}: {len(level_tests)} tests ({len(auto)} automated)")
            total += len(level_tests)
    lines.append(f"\n  Total: {total} tests at Level {level}")
    return "\n".join(lines)
