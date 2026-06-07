"""
VAPT Report Generator
Produces professional penetration testing reports from collected findings and evidence.

Capabilities:
  - Collect findings from evidence directory
  - Structure into executive summary, methodology, findings, remediation
  - Generate Markdown report
  - Generate HTML report (styled, client-ready)
  - Finding severity classification and CVSS-aligned scoring
  - Attack chain narratives
  - Evidence appendix with reproduction steps

IMPORTANT: report_generate returns the full report content in the response
so the user sees it locally (in terminal or GUI). The file is also saved
on the server at /tmp/reports/ as a backup.
"""
import os
import json
import glob
from typing import Optional, List, Dict
from datetime import datetime

from config import EVIDENCE_DIR, REPORTS_DIR


# =============================================================================
# FINDING MANAGEMENT
# =============================================================================

# In-memory finding store (persisted to disk + DynamoDB)
_findings_file = os.path.join(REPORTS_DIR, "findings.json")


def _load_findings() -> List[dict]:
    """Load findings for the CURRENT assessment.

    When an assessment context is set we isolate STRICTLY to that assessment's
    DynamoDB record and never read the shared local file — otherwise findings
    from a previous assessment would leak into a new one. The shared local file
    is only used in standalone/CLI mode (no assessment context).
    """
    from tools.target_state import _current_assessment_id
    if _current_assessment_id:
        try:
            import db as _db
            return _db.findings_get(_current_assessment_id) or []
        except Exception:
            return []
    # No assessment context (standalone/CLI) — use the shared local file.
    if os.path.exists(_findings_file):
        try:
            with open(_findings_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def _save_findings(findings: List[dict]):
    """Save findings for the CURRENT assessment.

    With an assessment context set we persist ONLY to that assessment's DynamoDB
    record (no shared local file) so findings can never bleed across assessments.
    Without a context (standalone/CLI) we fall back to the shared local file.
    """
    from tools.target_state import _current_assessment_id
    if _current_assessment_id:
        try:
            import db as _db
            _db.findings_save(_current_assessment_id, findings)
        except Exception:
            pass
        return
    # No assessment context (standalone/CLI) — use the shared local file.
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(_findings_file, "w") as f:
        json.dump(findings, f, indent=2)


def report_add_finding(
    title: str,
    severity: str = "HIGH",
    status: str = "CONFIRMED",
    target: str = "",
    description: str = "",
    evidence: str = "",
    reproduction: str = "",
    remediation: str = "",
    category: str = "General",
    finding_id: Optional[str] = None,
    cvss_score: Optional[float] = None,
    attack_chain: Optional[str] = None,
) -> str:
    """
    Add a finding to the report.

    Args:
        title: Finding title (e.g., "SQL Injection in login parameter")
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        status: CONFIRMED or UNCONFIRMED
        target: Affected target URL/IP
        description: What the vulnerability is and why it matters
        evidence: Proof — extracted data, command output, etc.
        reproduction: Steps to reproduce the finding
        remediation: How to fix it
        category: Finding category (e.g., Injection, Authentication, Cryptography)
        finding_id: Unique ID (auto-generated if not provided)
        cvss_score: CVSS score 0.0-10.0
        attack_chain: Description of how this was found (tool chain)

    Returns:
        Confirmation with finding ID
    """
    findings = _load_findings()

    finding_id = finding_id or f"F-{len(findings) + 1:03d}"

    severity = severity.upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity = "HIGH"

    finding = {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "status": status.upper(),
        "target": target,
        "description": description,
        "evidence": evidence[:10000],
        "reproduction": reproduction,
        "remediation": remediation,
        "category": category,
        "cvss_score": cvss_score,
        "attack_chain": attack_chain,
        "timestamp": datetime.now().isoformat(),
    }

    findings.append(finding)
    _save_findings(findings)

    return f"Finding added: [{finding_id}] {severity} — {title} ({status})"


def report_list_findings() -> str:
    """
    List all findings in the current report.

    Returns:
        Summary table of all findings
    """
    findings = _load_findings()

    if not findings:
        return "No findings recorded. Use report_add_finding to add vulnerabilities."

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "HIGH")] = counts.get(f.get("severity", "HIGH"), 0) + 1

    lines = [
        f"Findings Summary ({len(findings)} total):",
        f"  CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  "
        f"MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}  INFO: {counts['INFO']}",
        "",
    ]

    for f in findings:
        status_icon = "✓" if f.get("status") == "CONFIRMED" else "?"
        lines.append(
            f"  [{status_icon}] {f['id']} | {f['severity']:8s} | {f['title'][:60]}"
        )

    return "\n".join(lines)


def report_clear_findings() -> str:
    """
    Clear all findings. Use before starting a new assessment.

    Returns:
        Confirmation
    """
    _save_findings([])
    return "All findings cleared."


def report_import_evidence() -> str:
    """
    Import findings from the evidence directory.
    Scans /tmp/evidence/*/result.json for structured verification results
    and adds them as findings.

    Returns:
        Number of findings imported
    """
    findings = _load_findings()
    imported = 0

    evidence_files = glob.glob(os.path.join(EVIDENCE_DIR, "*/result.json"))

    for filepath in evidence_files:
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            fid = data.get("finding_id", "")

            # Skip if already imported
            if any(f["id"] == fid for f in findings):
                continue

            finding = {
                "id": fid,
                "title": data.get("vulnerability_type", "Unknown"),
                "severity": data.get("severity", "HIGH"),
                "status": data.get("status", "UNCONFIRMED"),
                "target": data.get("target", ""),
                "description": data.get("vulnerability_type", ""),
                "evidence": data.get("evidence", ""),
                "reproduction": data.get("reproduction_steps", ""),
                "remediation": "",
                "category": _categorize(data.get("vulnerability_type", "")),
                "cvss_score": None,
                "attack_chain": None,
                "evidence_file": data.get("evidence_file", ""),
                "timestamp": data.get("timestamp", datetime.now().isoformat()),
            }

            findings.append(finding)
            imported += 1

        except (json.JSONDecodeError, IOError, KeyError):
            continue

    _save_findings(findings)
    return f"Imported {imported} finding(s) from evidence directory. Total findings: {len(findings)}."


def _categorize(vuln_type: str) -> str:
    """Auto-categorize a finding based on vulnerability type."""
    vt = vuln_type.lower()
    if "sql" in vt:
        return "Injection"
    if "rce" in vt or "command" in vt:
        return "Injection"
    if "lfi" in vt or "file inclusion" in vt:
        return "Injection"
    if "xss" in vt or "cross-site" in vt:
        return "Injection"
    if "cred" in vt or "password" in vt or "default" in vt:
        return "Authentication"
    if "ssl" in vt or "tls" in vt or "crypto" in vt:
        return "Cryptography"
    if "cve" in vt:
        return "Known Vulnerability"
    if "header" in vt:
        return "Misconfiguration"
    return "General"


# =============================================================================
# REPORT GENERATION
# =============================================================================

def report_generate(
    assessment_name: str = "Security Assessment",
    client_name: str = "",
    tester_name: str = "",
    scope: str = "",
    format: str = "markdown",
    executive_summary: str = "",
    methodology_notes: str = "",
    target: str = "",
    engagement_name: str = "",
) -> str:
    """
    Generate a professional VAPT report from collected findings.

    The full report content is returned in the response so the user
    sees it locally. The file is also saved on the server as backup.

    Args:
        assessment_name: Name of the assessment engagement
        client_name: Client/organization name
        tester_name: Penetration tester name
        scope: Assessment scope description
        format: Report format — "markdown" or "html"
        executive_summary: AI-written executive summary (provide this from analysis)
        methodology_notes: Additional methodology notes
        target: Alias for scope (the tool schema exposes this name)
        engagement_name: Alias for assessment_name (the tool schema exposes this name)

    Returns:
        Full report content (Markdown or HTML) preceded by a summary line
    """
    # The tool schema advertises `target` and `engagement_name`; map them onto
    # the canonical parameters so the model's calls never raise TypeError.
    if engagement_name and assessment_name == "Security Assessment":
        assessment_name = engagement_name
    if target and not scope:
        scope = target
    # Normalize unsupported formats (schema lists "json") to markdown.
    if format not in ("markdown", "html"):
        format = "markdown"
    findings = _load_findings()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    date_str = datetime.now().strftime("%B %d, %Y")

    if format == "html":
        return _generate_html_report(
            findings, assessment_name, client_name, tester_name,
            scope, executive_summary, methodology_notes, timestamp, date_str,
        )
    else:
        return _generate_markdown_report(
            findings, assessment_name, client_name, tester_name,
            scope, executive_summary, methodology_notes, timestamp, date_str,
        )


def _severity_order(severity: str) -> int:
    """Sort order for severities."""
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity, 5)


def _generate_markdown_report(
    findings, assessment_name, client_name, tester_name,
    scope, executive_summary, methodology_notes, timestamp, date_str,
) -> str:
    """Generate Markdown report."""

    sorted_findings = sorted(findings, key=lambda f: _severity_order(f.get("severity", "HIGH")))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in sorted_findings:
        sev = f.get("severity", "HIGH")
        counts[sev] = counts.get(sev, 0) + 1

    confirmed = sum(1 for f in sorted_findings if f.get("status") == "CONFIRMED")
    unconfirmed = len(sorted_findings) - confirmed

    report = f"""# {assessment_name}
## Penetration Testing Report

| Field | Detail |
|-------|--------|
| **Client** | {client_name or 'N/A'} |
| **Tester** | {tester_name or 'N/A'} |
| **Date** | {date_str} |
| **Scope** | {scope or 'See methodology section'} |
| **Classification** | CONFIDENTIAL |

---

## 1. Executive Summary

{executive_summary or _auto_executive_summary(sorted_findings, counts)}

### Finding Overview

| Severity | Count |
|----------|-------|
| CRITICAL | {counts['CRITICAL']} |
| HIGH | {counts['HIGH']} |
| MEDIUM | {counts['MEDIUM']} |
| LOW | {counts['LOW']} |
| INFO | {counts['INFO']} |
| **Total** | **{len(sorted_findings)}** |

Confirmed: {confirmed} | Unconfirmed: {unconfirmed}

---

## 2. Methodology

This assessment followed a structured black-box penetration testing methodology:

1. **Reconnaissance** — OSINT, DNS enumeration, subdomain discovery
2. **Scanning** — Port scanning, service detection, technology fingerprinting
3. **Vulnerability Discovery** — Automated and manual vulnerability scanning
4. **Verification** — Each finding verified through controlled exploitation with evidence capture
5. **Exploitation** — Confirmed vulnerabilities exploited to demonstrate impact
6. **Post-Exploitation** — System enumeration, privilege escalation, credential extraction
7. **Reporting** — Findings documented with evidence and remediation guidance

{methodology_notes}

---

## 3. Findings

"""

    for i, finding in enumerate(sorted_findings, 1):
        sev = finding.get("severity", "HIGH")
        status = finding.get("status", "UNCONFIRMED")
        status_badge = "CONFIRMED" if status == "CONFIRMED" else "UNCONFIRMED"

        report += f"""### 3.{i}. {finding.get('title', 'Untitled')}

| Field | Value |
|-------|-------|
| **ID** | {finding.get('id', f'F-{i:03d}')} |
| **Severity** | {sev} |
| **Status** | {status_badge} |
| **Target** | `{finding.get('target', 'N/A')}` |
| **Category** | {finding.get('category', 'General')} |
{f"| **CVSS** | {finding['cvss_score']} |" if finding.get('cvss_score') else ""}

**Description:**

{finding.get('description', 'No description provided.')}

"""

        if finding.get("attack_chain"):
            report += f"""**Attack Chain:**

{finding['attack_chain']}

"""

        if finding.get("evidence"):
            report += f"""**Evidence:**

```
{finding['evidence'][:3000]}
```

"""

        if finding.get("reproduction"):
            report += f"""**Reproduction Steps:**

```
{finding['reproduction']}
```

"""

        if finding.get("remediation"):
            report += f"""**Remediation:**

{finding['remediation']}

"""

        report += "---\n\n"

    report += f"""## 4. Remediation Summary

### Immediate Actions (Critical & High)

"""
    for f in sorted_findings:
        if f.get("severity") in ("CRITICAL", "HIGH"):
            report += f"- **{f.get('id')}** — {f.get('title')}: {f.get('remediation', 'See finding details.')}\n"

    report += f"""

### Short-Term Actions (Medium)

"""
    for f in sorted_findings:
        if f.get("severity") == "MEDIUM":
            report += f"- **{f.get('id')}** — {f.get('title')}: {f.get('remediation', 'See finding details.')}\n"

    report += f"""

### Long-Term Actions (Low & Informational)

"""
    for f in sorted_findings:
        if f.get("severity") in ("LOW", "INFO"):
            report += f"- **{f.get('id')}** — {f.get('title')}: {f.get('remediation', 'See finding details.')}\n"

    report += f"""

---

## 5. Appendix

### A. Tools Used

The following tools were used during this assessment:

- nmap, masscan — Network scanning
- nuclei, nikto — Vulnerability scanning
- sqlmap — SQL injection testing
- commix — Command injection testing
- hydra — Credential testing
- Metasploit Framework — Exploitation
- LinPEAS — Privilege escalation enumeration
- http_fetch, http_methods, cookie_check — HTTP analysis
- jwt_test, graphql_test — API security testing
- Custom scripts — Verification and evidence collection

### B. Evidence Files

Evidence files are stored in: `{EVIDENCE_DIR}/`

"""
    evidence_dirs = glob.glob(os.path.join(EVIDENCE_DIR, "*/"))
    for d in sorted(evidence_dirs):
        dirname = os.path.basename(d.rstrip("/"))
        files = os.listdir(d)
        report += f"- `{dirname}/`: {', '.join(files)}\n"

    report += f"""

---

*Report generated: {date_str}*
*Classification: CONFIDENTIAL*
"""

    # Return full report content with metadata header
    # Client saves this to a local file — no server-side storage
    confirmed_count = confirmed
    total_count = len(sorted_findings)
    summary = (
        f"Findings: {total_count} ({confirmed_count} confirmed) | Format: Markdown\n"
        f"\n{'=' * 60}\n\n"
    )
    return summary + report


def _generate_html_report(
    findings, assessment_name, client_name, tester_name,
    scope, executive_summary, methodology_notes, timestamp, date_str,
) -> str:
    """Generate styled HTML report."""

    sorted_findings = sorted(findings, key=lambda f: _severity_order(f.get("severity", "HIGH")))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in sorted_findings:
        sev = f.get("severity", "HIGH")
        counts[sev] = counts.get(sev, 0) + 1

    confirmed = sum(1 for f in sorted_findings if f.get("status") == "CONFIRMED")

    severity_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#2563eb",
        "INFO": "#6b7280",
    }

    exec_summary = executive_summary or _auto_executive_summary(sorted_findings, counts)

    # Build findings HTML
    findings_html = ""
    for i, finding in enumerate(sorted_findings, 1):
        sev = finding.get("severity", "HIGH")
        color = severity_colors.get(sev, "#6b7280")
        status = finding.get("status", "UNCONFIRMED")

        evidence_html = ""
        if finding.get("evidence"):
            esc_evidence = finding["evidence"][:3000].replace("<", "&lt;").replace(">", "&gt;")
            evidence_html = f'<div class="evidence"><h4>Evidence</h4><pre>{esc_evidence}</pre></div>'

        repro_html = ""
        if finding.get("reproduction"):
            esc_repro = finding["reproduction"].replace("<", "&lt;").replace(">", "&gt;")
            repro_html = f'<div class="reproduction"><h4>Reproduction</h4><pre>{esc_repro}</pre></div>'

        remediation_html = ""
        if finding.get("remediation"):
            remediation_html = f'<div class="remediation"><h4>Remediation</h4><p>{finding["remediation"]}</p></div>'

        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity-badge" style="background:{color}">{sev}</span>
                <span class="status-badge {'confirmed' if status == 'CONFIRMED' else 'unconfirmed'}">{status}</span>
                <h3>{finding.get('id', f'F-{i:03d}')} — {finding.get('title', 'Untitled')}</h3>
            </div>
            <table class="finding-meta">
                <tr><td><strong>Target:</strong></td><td><code>{finding.get('target', 'N/A')}</code></td></tr>
                <tr><td><strong>Category:</strong></td><td>{finding.get('category', 'General')}</td></tr>
            </table>
            <p>{finding.get('description', '')}</p>
            {evidence_html}
            {repro_html}
            {remediation_html}
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{assessment_name} — VAPT Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #111; color: #e5e5e5; line-height: 1.6; }}
        .container {{ max-width: 900px; margin: 0 auto; padding: 40px 30px; }}
        h1 {{ font-size: 1.8em; margin-bottom: 5px; color: #fff; }}
        h2 {{ font-size: 1.4em; margin: 30px 0 15px; color: #fff; border-bottom: 1px solid #333; padding-bottom: 8px; }}
        h3 {{ font-size: 1.1em; color: #fff; display: inline; }}
        h4 {{ font-size: 0.95em; color: #ccc; margin: 12px 0 6px; }}
        p {{ margin: 8px 0; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ text-align: left; padding: 8px 12px; border: 1px solid #333; }}
        th {{ background: #1a1a1a; color: #fff; }}
        td {{ background: #0d0d0d; }}
        code {{ background: #1a1a1a; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
        pre {{ background: #0a0a0a; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; border: 1px solid #222; white-space: pre-wrap; word-wrap: break-word; }}
        .header {{ text-align: center; padding: 30px 0; border-bottom: 2px solid #333; margin-bottom: 30px; }}
        .header .subtitle {{ color: #888; font-size: 1.1em; }}
        .meta-table td {{ font-size: 0.95em; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 15px 0; }}
        .summary-card {{ text-align: center; padding: 15px; border-radius: 8px; }}
        .summary-card .count {{ font-size: 2em; font-weight: bold; }}
        .summary-card .label {{ font-size: 0.8em; color: #aaa; }}
        .finding {{ background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; margin: 15px 0; }}
        .finding-header {{ margin-bottom: 12px; }}
        .severity-badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; color: #fff; font-size: 0.8em; font-weight: bold; margin-right: 8px; }}
        .status-badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; margin-right: 10px; }}
        .status-badge.confirmed {{ background: #166534; color: #4ade80; }}
        .status-badge.unconfirmed {{ background: #713f12; color: #fbbf24; }}
        .finding-meta td {{ background: transparent; border: none; padding: 3px 10px; }}
        .evidence, .reproduction, .remediation {{ margin-top: 10px; }}
        .remediation p {{ background: #0d2818; padding: 10px; border-radius: 4px; border-left: 3px solid #22c55e; }}
        .footer {{ text-align: center; padding: 20px 0; margin-top: 40px; border-top: 1px solid #333; color: #666; font-size: 0.85em; }}
        @media print {{ body {{ background: #fff; color: #111; }} .finding {{ border-color: #ccc; background: #f9f9f9; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{assessment_name}</h1>
            <p class="subtitle">Penetration Testing Report</p>
        </div>

        <table class="meta-table">
            <tr><td><strong>Client:</strong></td><td>{client_name or 'N/A'}</td></tr>
            <tr><td><strong>Tester:</strong></td><td>{tester_name or 'N/A'}</td></tr>
            <tr><td><strong>Date:</strong></td><td>{date_str}</td></tr>
            <tr><td><strong>Scope:</strong></td><td>{scope or 'See methodology'}</td></tr>
            <tr><td><strong>Classification:</strong></td><td>CONFIDENTIAL</td></tr>
        </table>

        <h2>1. Executive Summary</h2>
        <p>{exec_summary}</p>

        <div class="summary-grid">
            <div class="summary-card" style="background:#450a0a"><div class="count">{counts['CRITICAL']}</div><div class="label">Critical</div></div>
            <div class="summary-card" style="background:#431407"><div class="count">{counts['HIGH']}</div><div class="label">High</div></div>
            <div class="summary-card" style="background:#422006"><div class="count">{counts['MEDIUM']}</div><div class="label">Medium</div></div>
            <div class="summary-card" style="background:#172554"><div class="count">{counts['LOW']}</div><div class="label">Low</div></div>
            <div class="summary-card" style="background:#1f1f1f"><div class="count">{counts['INFO']}</div><div class="label">Info</div></div>
        </div>
        <p>Confirmed: {confirmed} | Unconfirmed: {len(sorted_findings) - confirmed}</p>

        <h2>2. Methodology</h2>
        <p>This assessment followed a structured black-box penetration testing approach covering reconnaissance, scanning, vulnerability discovery, verification through controlled exploitation, post-exploitation enumeration, and evidence-based reporting.</p>
        {f'<p>{methodology_notes}</p>' if methodology_notes else ''}

        <h2>3. Findings</h2>
        {findings_html if findings_html else '<p>No findings recorded.</p>'}

        <h2>4. Remediation Priority</h2>
        <table>
            <tr><th>Priority</th><th>Finding</th><th>Severity</th></tr>
            {''.join(f'<tr><td>{i}</td><td>{f.get("id","")} — {f.get("title","")}</td><td>{f.get("severity","")}</td></tr>' for i, f in enumerate(sorted_findings, 1))}
        </table>

        <div class="footer">
            <p>Report generated: {date_str} | Classification: CONFIDENTIAL</p>
        </div>
    </div>
</body>
</html>"""

    # Return full report content with metadata header
    # Client saves this to a local file — no server-side storage
    summary = (
        f"Findings: {len(sorted_findings)} ({confirmed} confirmed) | Format: HTML\n"
        f"\n{'=' * 60}\n\n"
    )
    return summary + html


def _auto_executive_summary(findings: list, counts: dict) -> str:
    """Generate automatic executive summary when AI doesn't provide one."""
    total = len(findings)
    if total == 0:
        return "No vulnerabilities were identified during this assessment."

    confirmed = sum(1 for f in findings if f.get("status") == "CONFIRMED")
    critical_high = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)

    risk_level = "CRITICAL" if counts.get("CRITICAL", 0) > 0 else \
                 "HIGH" if counts.get("HIGH", 0) > 0 else \
                 "MEDIUM" if counts.get("MEDIUM", 0) > 0 else "LOW"

    summary = (
        f"This penetration test identified {total} finding(s), "
        f"of which {confirmed} were confirmed through controlled exploitation. "
    )

    if critical_high > 0:
        summary += (
            f"The overall risk posture is {risk_level}, with {critical_high} "
            f"critical or high severity issue(s) requiring immediate attention. "
        )

    # Mention top findings
    top = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")][:3]
    if top:
        summary += "Key findings include: "
        summary += "; ".join(f.get("title", "Unknown") for f in top)
        summary += ". "

    summary += "Detailed remediation guidance is provided for each finding."

    return summary
