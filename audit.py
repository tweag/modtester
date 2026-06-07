"""
ModTester — Audit Logger.

Structured audit events for every tool execution and AI interaction.
Locally logs to stdout (JSON). In production, CloudWatch captures these
for compliance, incident response, and governance.

Every log entry includes: who, what, when, target, result status.
Tool names are logged internally for audit but NEVER exposed to users.
"""
import json
import time
import os
import sys
from datetime import datetime, timezone


AUDIT_ENABLED = os.environ.get("AUDIT_ENABLED", "true").lower() in ("1", "true", "yes")


def _emit(event: dict):
    """Write structured JSON audit event to stdout (captured by CloudWatch)."""
    if not AUDIT_ENABLED:
        return
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    event["service"] = "modtester"
    # Write as single-line JSON for CloudWatch Logs Insights
    sys.stdout.write(json.dumps(event, default=str) + "\n")
    sys.stdout.flush()


def log_tool_execution(
    assessment_id: str,
    tool_name: str,
    tool_input: dict,
    duration_ms: float,
    success: bool,
    result_size: int,
    user: str = "demo",
):
    """Log a tool execution event."""
    _emit({
        "event_type": "tool_execution",
        "assessment_id": assessment_id,
        "tool": tool_name,
        "target": tool_input.get("target") or tool_input.get("url") or tool_input.get("host") or tool_input.get("domain") or "",
        "duration_ms": round(duration_ms),
        "success": success,
        "result_bytes": result_size,
        "user": user,
    })


def log_ai_request(
    assessment_id: str,
    model: str,
    user_message_preview: str,
    tools_called: list[str],
    total_duration_ms: float,
    user: str = "demo",
):
    """Log an AI conversation turn."""
    _emit({
        "event_type": "ai_request",
        "assessment_id": assessment_id,
        "model": model,
        "message_preview": user_message_preview[:100],
        "tools_called_count": len(tools_called),
        "total_duration_ms": round(total_duration_ms),
        "user": user,
    })


def log_auth_event(
    event: str,  # "login_success", "login_failure", "logout"
    username: str,
    ip: str = "",
):
    """Log an authentication event."""
    _emit({
        "event_type": "auth",
        "action": event,
        "username": username,
        "source_ip": ip,
    })


def log_assessment_event(
    assessment_id: str,
    action: str,  # "created", "completed", "deleted"
    user: str = "demo",
    details: dict | None = None,
):
    """Log assessment lifecycle events."""
    _emit({
        "event_type": "assessment",
        "assessment_id": assessment_id,
        "action": action,
        "user": user,
        "details": details or {},
    })
