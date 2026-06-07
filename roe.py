"""
Rules of Engagement (ROE) module.

Defines engagement boundaries, scope constraints, and authorization checks
for penetration testing activities.
"""

import json
import os
from pathlib import Path

ROE_PROFILES_DIR = Path(__file__).parent / "roe_profiles"


def load_roe_profile(name: str) -> dict:
    """Load a ROE profile by name."""
    path = ROE_PROFILES_DIR / f"{name}.json"
    if not path.exists():
        return {"error": f"ROE profile '{name}' not found"}
    with open(path, "r") as f:
        return json.load(f)


def list_roe_profiles() -> list[str]:
    """List available ROE profiles."""
    if not ROE_PROFILES_DIR.exists():
        return []
    return [p.stem for p in ROE_PROFILES_DIR.glob("*.json")]


def check_scope(target: str, roe: dict) -> bool:
    """Check if a target is within the engagement scope."""
    scope = roe.get("scope", {})
    in_scope = scope.get("in_scope", [])
    out_of_scope = scope.get("out_of_scope", [])

    # Check exclusions first
    for excluded in out_of_scope:
        if excluded in target or target in excluded:
            return False

    # Check inclusions
    if not in_scope:
        return True  # No scope defined = everything allowed
    for included in in_scope:
        if included in target or target in included:
            return True

    return False


def get_default_roe() -> dict:
    """Return default ROE for demo/testing."""
    return {
        "engagement": "ModTester Demo",
        "scope": {
            "in_scope": ["*"],
            "out_of_scope": []
        },
        "rules": {
            "dos_allowed": False,
            "social_engineering": False,
            "physical_access": False,
            "data_exfiltration": False,
            "max_threads": 10,
        },
        "timeframe": {
            "start": "2026-01-01",
            "end": "2026-12-31"
        }
    }
