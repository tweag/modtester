"""
Auto Evidence Capture
Automatically captures significant tool output as timestamped evidence files.

The AI calls evidence_capture after any tool produces interesting results —
credentials, config files, sensitive data, confirmed vulnerabilities, etc.
This ensures nothing is lost and all evidence is available for reporting.

Evidence saves to the local project evidence/ directory by default.
Set EVIDENCE_DIR env var to change the location.
Set EVIDENCE_S3_BUCKET env var to enable S3 cloud storage.

Separate from verify_* tools (which do controlled re-exploitation).
This captures the FIRST discovery, not the verification.
"""
import os
import json
import hashlib
from typing import Optional
from datetime import datetime

from config import EVIDENCE_DIR, EVIDENCE_S3_BUCKET, EVIDENCE_S3_PREFIX


AUTO_DIR = os.path.join(EVIDENCE_DIR, "auto")


def evidence_capture(
    title: str,
    content: str,
    source_tool: str = "",
    target: str = "",
    severity: str = "HIGH",
    evidence_type: str = "tool_output",
    finding_id: str = "",
) -> str:
    """
    Capture evidence from a tool result. Call this whenever a tool returns
    something significant — credentials, sensitive data, config files,
    confirmed vulnerabilities, interesting error messages.

    The evidence is saved as a file and can be referenced in the final report.

    Args:
        title: Short description (e.g., "JWT Secret Exposed", "Admin Panel 2985 Users")
        content: The actual evidence — raw tool output, extracted data, HTTP response
        source_tool: Which tool produced this (e.g., "http_fetch", "nmap_scan")
        target: Target URL/IP/endpoint
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        evidence_type: Category — "tool_output", "credentials", "config_file",
                       "sensitive_data", "http_response", "error_message", "screenshot"
        finding_id: Optional link to a report finding (e.g., "VULN-001")

    Returns:
        Confirmation with evidence file path
    """
    os.makedirs(AUTO_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_title = title[:50].replace(" ", "_").replace("/", "-").replace("\\", "-")
    safe_title = "".join(c for c in safe_title if c.isalnum() or c in "_-")

    filename = f"{timestamp}_{severity}_{safe_title}"

    # Save the raw content
    content_file = os.path.join(AUTO_DIR, f"{filename}.txt")
    with open(content_file, "w", encoding="utf-8") as f:
        f.write(content[:50000])  # Cap at 50KB

    # Save structured metadata
    meta = {
        "title": title,
        "source_tool": source_tool,
        "target": target,
        "severity": severity.upper(),
        "evidence_type": evidence_type,
        "finding_id": finding_id,
        "timestamp": datetime.now().isoformat(),
        "content_file": content_file,
        "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
        "content_size": len(content),
    }

    meta_file = os.path.join(AUTO_DIR, f"{filename}.json")
    with open(meta_file, "w") as f:
        json.dump(meta, f, indent=2)

    # Upload to S3 if configured
    s3_note = ""
    if EVIDENCE_S3_BUCKET:
        try:
            import boto3
            s3 = boto3.client("s3")
            s3_key_content = f"{EVIDENCE_S3_PREFIX}{filename}.txt"
            s3_key_meta = f"{EVIDENCE_S3_PREFIX}{filename}.json"
            s3.upload_file(content_file, EVIDENCE_S3_BUCKET, s3_key_content)
            s3.upload_file(meta_file, EVIDENCE_S3_BUCKET, s3_key_meta)
            s3_note = f"\n  S3: s3://{EVIDENCE_S3_BUCKET}/{s3_key_content}"
        except Exception as e:
            s3_note = f"\n  S3 upload failed: {e}"

    return (
        f"Evidence captured: [{severity}] {title}\n"
        f"  File: {content_file}\n"
        f"  Size: {len(content)} chars | Source: {source_tool} | Target: {target}"
        f"{s3_note}"
    )


def evidence_list(severity_filter: str = "", evidence_type_filter: str = "") -> str:
    """
    List all captured evidence files.

    Args:
        severity_filter: Optional — show only this severity (e.g., "CRITICAL")
        evidence_type_filter: Optional — show only this type (e.g., "credentials")

    Returns:
        Summary of all evidence files
    """
    if not os.path.exists(AUTO_DIR):
        return "No evidence captured yet. Use evidence_capture after significant findings."

    meta_files = sorted(
        [f for f in os.listdir(AUTO_DIR) if f.endswith(".json")],
        reverse=True,
    )

    if not meta_files:
        return "No evidence captured yet."

    entries = []
    for mf in meta_files:
        try:
            with open(os.path.join(AUTO_DIR, mf), "r") as f:
                meta = json.load(f)

            sev = meta.get("severity", "")
            etype = meta.get("evidence_type", "")

            if severity_filter and sev != severity_filter.upper():
                continue
            if evidence_type_filter and etype != evidence_type_filter:
                continue

            entries.append(meta)
        except (json.JSONDecodeError, IOError):
            continue

    if not entries:
        return f"No evidence matching filters. Total files: {len(meta_files)}"

    # Count by severity
    counts = {}
    for e in entries:
        s = e.get("severity", "?")
        counts[s] = counts.get(s, 0) + 1

    lines = [
        f"Evidence Files ({len(entries)} total):",
        f"  CRITICAL: {counts.get('CRITICAL', 0)}  HIGH: {counts.get('HIGH', 0)}  "
        f"MEDIUM: {counts.get('MEDIUM', 0)}  LOW: {counts.get('LOW', 0)}",
        "",
    ]

    for e in entries:
        size_kb = e.get("content_size", 0) / 1024
        lines.append(
            f"  [{e.get('severity', '?'):8s}] {e.get('title', '?')[:55]}"
            f"  ({e.get('source_tool', '?')}, {size_kb:.1f}KB)"
        )

    return "\n".join(lines)


def evidence_get(title_search: str) -> str:
    """
    Retrieve the content of a specific evidence file by searching its title.

    Args:
        title_search: Search term to match against evidence titles

    Returns:
        Evidence content (first match)
    """
    if not os.path.exists(AUTO_DIR):
        return "No evidence captured yet."

    search = title_search.lower()
    meta_files = sorted(
        [f for f in os.listdir(AUTO_DIR) if f.endswith(".json")],
        reverse=True,
    )

    for mf in meta_files:
        try:
            with open(os.path.join(AUTO_DIR, mf), "r") as f:
                meta = json.load(f)

            if search in meta.get("title", "").lower():
                content_file = meta.get("content_file", "")
                if os.path.exists(content_file):
                    with open(content_file, "r", encoding="utf-8") as cf:
                        content = cf.read()

                    return (
                        f"Evidence: {meta.get('title', '?')}\n"
                        f"Severity: {meta.get('severity', '?')} | "
                        f"Tool: {meta.get('source_tool', '?')} | "
                        f"Target: {meta.get('target', '?')}\n"
                        f"Captured: {meta.get('timestamp', '?')}\n"
                        f"{'=' * 60}\n"
                        f"{content[:10000]}"
                    )
        except (json.JSONDecodeError, IOError):
            continue

    return f"No evidence matching '{title_search}'"


def evidence_clear() -> str:
    """
    Clear all auto-captured evidence. Use before starting a new assessment.

    Returns:
        Confirmation
    """
    import shutil
    if os.path.exists(AUTO_DIR):
        shutil.rmtree(AUTO_DIR)
        os.makedirs(AUTO_DIR, exist_ok=True)
    return "All auto-captured evidence cleared."
