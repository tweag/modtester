"""
ModTester - DynamoDB persistence layer.

Tables:
    assessments  - Active and completed security assessments
    chat_history - Per-assessment chat messages
    reports      - Generated pentest reports

Local dev uses DynamoDB Local (docker-compose).
Production uses real DynamoDB via IAM/Bedrock credentials.
"""
import os
import uuid
import time
import json
from decimal import Decimal
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

DYNAMODB_ENDPOINT = os.environ.get("DYNAMODB_ENDPOINT", "http://localhost:4002")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

_USE_LOCAL = bool(DYNAMODB_ENDPOINT)

_client_kwargs = {"region_name": AWS_REGION}
if _USE_LOCAL:
    _client_kwargs["endpoint_url"] = DYNAMODB_ENDPOINT
    # DynamoDB Local ignores credentials but boto3 requires them
    _client_kwargs["aws_access_key_id"] = "local"
    _client_kwargs["aws_secret_access_key"] = "local"

from botocore.config import Config as BotoConfig
_client_kwargs["config"] = BotoConfig(
    connect_timeout=15, read_timeout=30, retries={"max_attempts": 5}
)

_resource = None

def _get_resource():
    global _resource
    if _resource is None:
        _resource = boto3.resource("dynamodb", **_client_kwargs)
    return _resource

TABLE_PREFIX = os.environ.get("DYNAMODB_TABLE_PREFIX", "modtester_")

# ---------------------------------------------------------------------------
# Table references (lazy-created)
# ---------------------------------------------------------------------------

_tables = {}


def _table(name: str):
    full = f"{TABLE_PREFIX}{name}"
    if full not in _tables:
        _tables[full] = _get_resource().Table(full)
    return _tables[full]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# JSON <-> Decimal helpers  (DynamoDB stores numbers as Decimal)
# ---------------------------------------------------------------------------

def _to_dynamo(obj):
    """Convert floats -> Decimal for DynamoDB."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _to_dynamo(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_dynamo(v) for v in obj]
    return obj


def _from_dynamo(obj):
    """Convert Decimal -> float/int for JSON."""
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    if isinstance(obj, dict):
        return {k: _from_dynamo(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_from_dynamo(v) for v in obj]
    return obj


# ===========================================================================
# TABLE CREATION  (for local dev & initial deploy)
# ===========================================================================

TABLE_SCHEMAS = {
    "assessments": {
        "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
        "AttributeDefinitions": [
            {"AttributeName": "id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "status-index",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    },
    "chat_history": {
        "KeySchema": [
            {"AttributeName": "assessment_id", "KeyType": "HASH"},
            {"AttributeName": "timestamp", "KeyType": "RANGE"},
        ],
        "AttributeDefinitions": [
            {"AttributeName": "assessment_id", "AttributeType": "S"},
            {"AttributeName": "timestamp", "AttributeType": "S"},
        ],
    },
    "target_state": {
        "KeySchema": [{"AttributeName": "assessment_id", "KeyType": "HASH"}],
        "AttributeDefinitions": [
            {"AttributeName": "assessment_id", "AttributeType": "S"},
        ],
    },
    "reports": {
        "KeySchema": [
            {"AttributeName": "assessment_id", "KeyType": "HASH"},
            {"AttributeName": "created_at", "KeyType": "RANGE"},
        ],
        "AttributeDefinitions": [
            {"AttributeName": "assessment_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
    },
}


def create_tables():
    """Create all tables if they don't exist. Safe to call multiple times."""
    resource = _get_resource()
    client = resource.meta.client
    existing = client.list_tables()["TableNames"]
    for name, schema in TABLE_SCHEMAS.items():
        full = f"{TABLE_PREFIX}{name}"
        if full in existing:
            continue
        params = {
            "TableName": full,
            "KeySchema": schema["KeySchema"],
            "AttributeDefinitions": schema["AttributeDefinitions"],
            "BillingMode": "PAY_PER_REQUEST",
        }
        if "GlobalSecondaryIndexes" in schema:
            gsis = []
            for gsi in schema["GlobalSecondaryIndexes"]:
                # PAY_PER_REQUEST doesn't need ProvisionedThroughput
                gsis.append({
                    "IndexName": gsi["IndexName"],
                    "KeySchema": gsi["KeySchema"],
                    "Projection": gsi["Projection"],
                })
            params["GlobalSecondaryIndexes"] = gsis
        client.create_table(**params)
        client.get_waiter("table_exists").wait(TableName=full)
    return [f"{TABLE_PREFIX}{n}" for n in TABLE_SCHEMAS]


# ===========================================================================
# ASSESSMENTS
# ===========================================================================

def assessment_create(
    name: str,
    target: str,
    scope_type: str = "web",
    scope: dict | None = None,
    roe: dict | None = None,
) -> dict:
    """Create a new assessment. Returns the full item."""
    item = {
        "id": _new_id(),
        "name": name,
        "target": target,
        "scope_type": scope_type,  # web | mobile_api | public_ip
        "scope": scope or {},
        "roe": roe or {},
        "status": "active",
        "findings_count": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    _table("assessments").put_item(Item=_to_dynamo(item))
    return item


def assessment_get(assessment_id: str) -> dict | None:
    resp = _table("assessments").get_item(Key={"id": assessment_id})
    item = resp.get("Item")
    return _from_dynamo(item) if item else None


def assessment_list(status: str | None = None) -> list[dict]:
    tbl = _table("assessments")
    if status:
        resp = tbl.query(
            IndexName="status-index",
            KeyConditionExpression=Key("status").eq(status),
        )
    else:
        resp = tbl.scan()
    return [_from_dynamo(i) for i in resp.get("Items", [])]


def assessment_update(assessment_id: str, **fields) -> dict | None:
    fields["updated_at"] = _now_iso()
    expr_parts, names, values = [], {}, {}
    for i, (k, v) in enumerate(fields.items()):
        alias = f"#f{i}"
        val = f":v{i}"
        expr_parts.append(f"{alias} = {val}")
        names[alias] = k
        values[val] = _to_dynamo(v)
    resp = _table("assessments").update_item(
        Key={"id": assessment_id},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )
    return _from_dynamo(resp.get("Attributes"))


def assessment_delete(assessment_id: str):
    _table("assessments").delete_item(Key={"id": assessment_id})
    # Also purge chat + reports
    _purge_sort_key_table("chat_history", "assessment_id", assessment_id, "timestamp")
    _purge_sort_key_table("reports", "assessment_id", assessment_id, "created_at")


def _purge_sort_key_table(table_name: str, pk: str, pk_val: str, sk: str):
    tbl = _table(table_name)
    resp = tbl.query(KeyConditionExpression=Key(pk).eq(pk_val))
    with tbl.batch_writer() as batch:
        for item in resp.get("Items", []):
            batch.delete_item(Key={pk: pk_val, sk: item[sk]})


# ===========================================================================
# CHAT HISTORY
# ===========================================================================

def chat_add(assessment_id: str, role: str, content: str, metadata: dict | None = None) -> dict:
    item = {
        "assessment_id": assessment_id,
        "timestamp": _now_iso(),
        "message_id": _new_id(),
        "role": role,  # user | assistant | system | tool
        "content": content,
        "metadata": metadata or {},
    }
    _table("chat_history").put_item(Item=_to_dynamo(item))
    return item


def chat_list(assessment_id: str, limit: int = 100) -> list[dict]:
    resp = _table("chat_history").query(
        KeyConditionExpression=Key("assessment_id").eq(assessment_id),
        ScanIndexForward=True,
        Limit=limit,
    )
    return [_from_dynamo(i) for i in resp.get("Items", [])]


def chat_clear(assessment_id: str):
    _purge_sort_key_table("chat_history", "assessment_id", assessment_id, "timestamp")


# ===========================================================================
# REPORTS
# ===========================================================================

def report_save(assessment_id: str, report_type: str, content: str, findings: list | None = None) -> dict:
    # Delete previous reports for this assessment (keep only latest)
    try:
        existing = report_list(assessment_id)
        if existing:
            tbl = _table("reports")
            with tbl.batch_writer() as batch:
                for old_report in existing:
                    batch.delete_item(Key={
                        "assessment_id": old_report["assessment_id"],
                        "created_at": old_report["created_at"],
                    })
    except Exception:
        pass  # Non-critical — proceed with save

    item = {
        "assessment_id": assessment_id,
        "created_at": _now_iso(),
        "report_id": _new_id(),
        "report_type": report_type,  # executive | technical | full
        "content": content,
        "findings": findings or [],
    }
    _table("reports").put_item(Item=_to_dynamo(item))
    return item


def report_list(assessment_id: str) -> list[dict]:
    resp = _table("reports").query(
        KeyConditionExpression=Key("assessment_id").eq(assessment_id),
        ScanIndexForward=False,
    )
    return [_from_dynamo(i) for i in resp.get("Items", [])]


def report_get_latest(assessment_id: str) -> dict | None:
    resp = _table("reports").query(
        KeyConditionExpression=Key("assessment_id").eq(assessment_id),
        ScanIndexForward=False,
        Limit=1,
    )
    items = resp.get("Items", [])
    return _from_dynamo(items[0]) if items else None


# ===========================================================================
# TARGET STATE & FINDINGS PERSISTENCE (per-assessment)
# ===========================================================================

def target_state_get(assessment_id: str) -> dict:
    """Get target state for an assessment."""
    try:
        resp = _table("target_state").get_item(Key={"assessment_id": assessment_id})
        item = resp.get("Item")
        if item:
            return _from_dynamo(item.get("state", {}))
    except Exception:
        pass
    return {}


def target_state_save(assessment_id: str, state: dict):
    """Save target state for an assessment."""
    try:
        _table("target_state").put_item(Item=_to_dynamo({
            "assessment_id": assessment_id,
            "state": state,
            "updated_at": _now_iso(),
        }))
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to persist target_state: {e}")


def findings_get(assessment_id: str) -> list:
    """Get findings for an assessment."""
    try:
        resp = _table("target_state").get_item(Key={"assessment_id": assessment_id})
        item = resp.get("Item")
        if item:
            return _from_dynamo(item.get("findings", []))
    except Exception:
        pass
    return []


def findings_save(assessment_id: str, findings: list):
    """Save findings for an assessment."""
    try:
        _table("target_state").update_item(
            Key={"assessment_id": assessment_id},
            UpdateExpression="SET findings = :f, updated_at = :t",
            ExpressionAttributeValues=_to_dynamo({
                ":f": findings,
                ":t": _now_iso(),
            }),
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to persist findings: {e}")


# ===========================================================================
# SEED DATA  (for demo / dev)
# ===========================================================================

SEED_ASSESSMENTS = [
    {
        "name": "OWASP Juice Shop - Full Pentest",
        "target": "https://juice-shop.example.com",
        "scope_type": "web",
        "scope": {"urls": ["https://juice-shop.example.com"], "methods": ["GET", "POST", "PUT", "DELETE"]},
    },
    {
        "name": "Corporate API - Auth & Access Control",
        "target": "https://api.corpsite.example.com",
        "scope_type": "web",
        "scope": {"urls": ["https://api.corpsite.example.com/v1/*"], "methods": ["GET", "POST"]},
    },
    {
        "name": "Mobile Banking API - MASVS Audit",
        "target": "https://mobile-api.bank.example.com",
        "scope_type": "mobile_api",
        "scope": {"urls": ["https://mobile-api.bank.example.com/*"]},
    },
    {
        "name": "E-Commerce Platform - PCI Scope",
        "target": "https://shop.example.com",
        "scope_type": "web",
        "scope": {"urls": ["https://shop.example.com", "https://checkout.example.com"]},
    },
    {
        "name": "Public Infrastructure - External Scan",
        "target": "203.0.113.0/24",
        "scope_type": "public_ip",
        "scope": {"cidrs": ["203.0.113.0/24"], "exclude_ips": ["203.0.113.1"]},
    },
    {
        "name": "Healthcare Portal - HIPAA Assessment",
        "target": "https://patient.healthco.example.com",
        "scope_type": "web",
        "scope": {"urls": ["https://patient.healthco.example.com/*", "https://api.healthco.example.com/*"]},
    },
    {
        "name": "SaaS Platform - Multi-Tenant Isolation",
        "target": "https://app.saasco.example.com",
        "scope_type": "web",
        "scope": {"urls": ["https://app.saasco.example.com", "https://admin.saasco.example.com"]},
    },
    {
        "name": "FinTech GraphQL API - Security Review",
        "target": "https://gql.fintech.example.com",
        "scope_type": "web",
        "scope": {"urls": ["https://gql.fintech.example.com/graphql"]},
    },
    {
        "name": "IoT Gateway - Firmware & Network",
        "target": "198.51.100.0/24",
        "scope_type": "public_ip",
        "scope": {"cidrs": ["198.51.100.0/24"], "ports": ["80", "443", "8883", "1883"]},
    },
    {
        "name": "WordPress Enterprise - Plugin Audit",
        "target": "https://blog.enterprise.example.com",
        "scope_type": "web",
        "scope": {"urls": ["https://blog.enterprise.example.com"]},
    },
]


def seed_data():
    """Insert sample assessments + chat messages for demo. Idempotent-ish."""
    existing = assessment_list()
    if existing:
        return existing  # already seeded

    created = []
    for seed in SEED_ASSESSMENTS:
        a = assessment_create(**seed)
        created.append(a)

    # -- Juice Shop (completed with full chat history + report) --
    js = created[0]
    chat_add(js["id"], "system", f"Assessment '{js['name']}' started. Target: {js['target']}")
    chat_add(js["id"], "user", "Run a full reconnaissance and vulnerability scan on this target")
    chat_add(js["id"], "assistant",
        "I'll begin a comprehensive security assessment of the Juice Shop application. "
        "Starting with reconnaissance to map the attack surface.\n\n"
        "**Phase 1 - Reconnaissance**\n"
        "*  Subdomain enumeration: 3 subdomains found\n"
        "*  Port scan: 80 (HTTP), 443 (HTTPS), 3000 (Node.js)\n"
        "*  Technology stack: Express.js, Angular, SQLite\n"
        "*  47 endpoints discovered via crawling")
    chat_add(js["id"], "assistant",
        "**Phase 2 - Vulnerability Assessment**\n"
        "Running automated scans and manual testing against discovered endpoints...\n\n"
        " **CRITICAL** - SQL Injection in `/rest/products/search?q=` (CVSS 9.8)\n"
        "Payload: `')) UNION SELECT * FROM Users--` returns full user table.\n\n"
        " **HIGH** - Broken Access Control on `/api/Users` (CVSS 8.2)\n"
        "Admin panel accessible without authentication at `/#/administration`.\n\n"
        " **HIGH** - Reflected XSS in search field (CVSS 7.5)\n"
        "Input `<iframe src=\"javascript:alert('xss')\">` executes in browser.\n\n"
        " **HIGH** - IDOR on `/api/BasketItems/{id}` (CVSS 7.1)\n"
        "Can modify other users' basket items by changing the ID parameter.")
    chat_add(js["id"], "assistant",
        "**Phase 3 - Additional Findings**\n\n"
        " **MEDIUM** - Sensitive data in JWT (CVSS 6.5) - email and role in payload\n"
        " **MEDIUM** - Missing rate limiting on login endpoint (CVSS 5.3)\n"
        " **MEDIUM** - Verbose error messages exposing stack traces (CVSS 5.0)\n"
        " **MEDIUM** - CORS misconfiguration allowing wildcard origins (CVSS 4.8)\n"
        " **MEDIUM** - Missing security headers: X-Frame-Options, CSP (CVSS 4.3)\n"
        " **LOW** - Server version disclosed in response headers (CVSS 3.1)\n"
        " **LOW** - Cookie without Secure flag (CVSS 2.6)\n"
        "[i] **INFO** - robots.txt exposes admin paths\n\n"
        "**Assessment complete.** 12 findings identified: 1 Critical, 3 High, 5 Medium, 2 Low, 1 Info.")
    chat_add(js["id"], "user", "Generate an executive report")
    chat_add(js["id"], "assistant",
        "Report generated successfully. You can view it in the **Report** tab above. "
        "The report includes an executive summary, detailed findings with remediation guidance, "
        "and a risk matrix.")

    assessment_update(js["id"], status="completed", findings_count=12, critical=1, high=3, medium=5, low=2, info=1)
    report_save(
        js["id"],
        "executive",
        "# Executive Summary - OWASP Juice Shop\n\n"
        "## Overview\n"
        "A comprehensive penetration test was conducted against the OWASP Juice Shop application "
        "at https://juice-shop.example.com. The assessment identified **12 vulnerabilities** across "
        "multiple severity levels.\n\n"
        "## Risk Rating: HIGH\n\n"
        "| Severity | Count |\n"
        "|----------|-------|\n"
        "|  Critical | 1 |\n"
        "|  High | 3 |\n"
        "|  Medium | 5 |\n"
        "|  Low | 2 |\n"
        "| [i] Info | 1 |\n\n"
        "## Critical & High Findings\n\n"
        "### 1. SQL Injection in Product Search (CRITICAL - CVSS 9.8)\n"
        "The `/rest/products/search` endpoint is vulnerable to SQL injection via the `q` parameter. "
        "An attacker can extract the entire database including user credentials.\n"
        "**Remediation:** Use parameterized queries or an ORM. Input validation alone is insufficient.\n\n"
        "### 2. Broken Access Control - Admin Panel (HIGH - CVSS 8.2)\n"
        "The admin panel at `/#/administration` is accessible without proper authorization checks. "
        "Any authenticated user can access admin functionality.\n"
        "**Remediation:** Implement server-side role-based access control on all admin endpoints.\n\n"
        "### 3. Reflected XSS in Search (HIGH - CVSS 7.5)\n"
        "User input in the search field is rendered without sanitization, allowing script injection.\n"
        "**Remediation:** Implement output encoding and Content Security Policy headers.\n\n"
        "### 4. Insecure Direct Object Reference (HIGH - CVSS 7.1)\n"
        "Basket item IDs are sequential and predictable. Users can modify other users' baskets.\n"
        "**Remediation:** Validate resource ownership on every request. Use UUIDs instead of sequential IDs.\n\n"
        "## Recommendations\n"
        "1. **Immediate:** Patch the SQL injection vulnerability - this is actively exploitable\n"
        "2. **Short-term:** Fix access control and XSS issues within 30 days\n"
        "3. **Medium-term:** Implement security headers, rate limiting, and secure cookie flags\n"
        "4. **Ongoing:** Integrate SAST/DAST into CI/CD pipeline\n",
        findings=[
            {"severity": "critical", "title": "SQL Injection in Product Search", "cvss": 9.8, "cwe": "CWE-89", "owasp": "A03:2021 Injection", "location": "/rest/products/search?q=", "description": "UNION-based SQL injection allows full database extraction including user credentials.", "remediation": "Use parameterized queries or an ORM."},
            {"severity": "high", "title": "Broken Access Control - Admin Panel", "cvss": 8.2, "cwe": "CWE-284", "owasp": "A01:2021 Broken Access Control", "location": "/#/administration", "description": "Admin panel accessible without authorization. Any authenticated user can access admin functionality.", "remediation": "Implement server-side RBAC on all admin endpoints."},
            {"severity": "high", "title": "Reflected XSS in Search Field", "cvss": 7.5, "cwe": "CWE-79", "owasp": "A03:2021 Injection", "location": "/search?q=", "description": "User input rendered without sanitization, allowing script injection via iframe tags.", "remediation": "Implement output encoding and Content Security Policy headers."},
            {"severity": "high", "title": "Insecure Direct Object Reference", "cvss": 7.1, "cwe": "CWE-639", "owasp": "A01:2021 Broken Access Control", "location": "/api/BasketItems/{id}", "description": "Sequential IDs allow users to modify other users' basket items.", "remediation": "Validate resource ownership. Use UUIDs instead of sequential IDs."},
            {"severity": "medium", "title": "Sensitive Data in JWT", "cvss": 6.5, "cwe": "CWE-200", "owasp": "A02:2021 Cryptographic Failures", "location": "Authorization header", "description": "JWT payload contains email and role in cleartext.", "remediation": "Minimize JWT claims. Use JWE for sensitive data."},
            {"severity": "medium", "title": "Missing Rate Limiting", "cvss": 5.3, "cwe": "CWE-307", "owasp": "A07:2021 Identification Failures", "location": "/rest/user/login", "description": "No rate limiting on login allows unlimited brute-force attempts.", "remediation": "Implement rate limiting and account lockout."},
            {"severity": "medium", "title": "Verbose Error Messages", "cvss": 5.0, "cwe": "CWE-209", "owasp": "A05:2021 Security Misconfiguration", "location": "Global error handler", "description": "Stack traces and internal paths exposed in 500 error responses.", "remediation": "Return generic error messages in production."},
            {"severity": "medium", "title": "CORS Misconfiguration", "cvss": 4.8, "cwe": "CWE-942", "owasp": "A05:2021 Security Misconfiguration", "location": "Access-Control-Allow-Origin", "description": "Wildcard CORS policy allows any origin to make credentialed requests.", "remediation": "Restrict to trusted domains only."},
            {"severity": "medium", "title": "Missing Security Headers", "cvss": 4.3, "cwe": "CWE-693", "owasp": "A05:2021 Security Misconfiguration", "location": "HTTP response headers", "description": "Missing X-Content-Type-Options, X-Frame-Options, and CSP headers.", "remediation": "Add all recommended security headers."},
            {"severity": "low", "title": "Server Version Disclosure", "cvss": 3.1, "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration", "location": "Server header", "description": "Server header reveals Express.js version.", "remediation": "Remove or obfuscate the Server header."},
            {"severity": "low", "title": "Cookie Without Secure Flag", "cvss": 2.6, "cwe": "CWE-614", "owasp": "A02:2021 Cryptographic Failures", "location": "Set-Cookie header", "description": "Session cookie transmittable over HTTP.", "remediation": "Set Secure flag on all cookies."},
            {"severity": "info", "title": "robots.txt Exposes Admin Paths", "cvss": 0.0, "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "location": "/robots.txt", "description": "Disallow entries reveal admin and FTP paths.", "remediation": "Review robots.txt. Do not rely on it for access control."},
        ],
    )

    # -- Corporate API (active, some findings) --
    ca = created[1]
    chat_add(ca["id"], "system", f"Assessment '{ca['name']}' started. Target: {ca['target']}")
    chat_add(ca["id"], "user", "Test authentication and access control on https://api.corpsite.example.com/v1/")
    chat_add(ca["id"], "assistant",
        "Running authentication and access control tests against `https://api.corpsite.example.com/v1/`.\n\n"
        "**Enumerated endpoints:**\n"
        "```\n"
        "POST /v1/auth/token\n"
        "GET  /v1/users/me\n"
        "GET  /v1/admin/users\n"
        "PUT  /v1/users/{id}/role\n"
        "```\n\n"
        "**Findings:**\n"
        " **HIGH** - API keys transmitted in query parameters on `GET /v1/users?api_key=...` (CVSS 7.5)\n"
        " **MEDIUM** - No rate limiting on `POST /v1/auth/token` - 500 requests/min accepted (CVSS 5.3)\n"
        " **MEDIUM** - CORS `Access-Control-Allow-Origin: *` on `api.corpsite.example.com` (CVSS 4.8)\n"
        " **LOW** - Server header exposes `X-API-Version: 2.3.1` (CVSS 2.1)\n\n"
        "Testing BOLA on `/v1/admin/users` next...")
    assessment_update(ca["id"], status="active", findings_count=4, critical=0, high=1, medium=2, low=1, info=0)

    # -- Mobile Banking (active, critical finding) --
    mb = created[2]
    chat_add(mb["id"], "system", f"Assessment '{mb['name']}' started. Target: {mb['target']}")
    chat_add(mb["id"], "user", "Run MASVS audit against https://mobile-api.bank.example.com - check certificate pinning, local storage, and auth flows")
    chat_add(mb["id"], "assistant",
        "MASVS audit against `https://mobile-api.bank.example.com`.\n\n"
        "**API surface discovered:**\n"
        "```\n"
        "POST /api/v2/auth/login\n"
        "POST /api/v2/auth/biometric\n"
        "GET  /api/v2/accounts/{id}/balance\n"
        "POST /api/v2/transfers\n"
        "```\n\n"
        "**Findings:**\n"
        " **CRITICAL** - No certificate pinning - MITM interception of `mobile-api.bank.example.com` trivial with proxy (CVSS 9.1)\n"
        " **HIGH** - Auth tokens stored in plaintext SharedPreferences at `/data/data/com.bank.app/shared_prefs/auth.xml` (CVSS 7.8)\n"
        " **HIGH** - Root detection uses `su` binary check only - trivially bypassed with Magisk (CVSS 7.0)\n"
        " **MEDIUM** - Biometric auth falls back to 4-digit PIN on `POST /api/v2/auth/biometric` failure (CVSS 5.9)\n"
        " **MEDIUM** - Debug logging writes full request/response bodies to logcat in production (CVSS 4.0)\n\n"
        "Analyzing TLS configuration on `mobile-api.bank.example.com:443`...")
    assessment_update(mb["id"], status="active", findings_count=5, critical=1, high=2, medium=2, low=0, info=0)

    # -- E-Commerce (completed, PCI findings) --
    ec = created[3]
    chat_add(ec["id"], "system", f"Assessment '{ec['name']}' started. Target: {ec['target']}")
    chat_add(ec["id"], "user", "Run PCI-DSS focused scan on https://shop.example.com and https://checkout.example.com")
    chat_add(ec["id"], "assistant",
        "PCI-DSS compliance assessment of `https://shop.example.com` and `https://checkout.example.com` completed.\n\n"
        "**Scanned endpoints:**\n"
        "```\n"
        "https://shop.example.com/cart\n"
        "https://checkout.example.com/payment\n"
        "https://checkout.example.com/api/charge\n"
        "```\n\n"
        "**Findings:**\n"
        " **HIGH** - TLS 1.0/1.1 enabled on `checkout.example.com:443` (CVSS 7.4)\n"
        " **MEDIUM** - Card number visible in DOM at `checkout.example.com/payment` via JS `document.getElementById('cc-num').value` (CVSS 6.5)\n"
        " **MEDIUM** - Session idle timeout is 30 min on `shop.example.com` (PCI requires <=15 min) (CVSS 4.0)\n"
        " **LOW** - No `Content-Security-Policy` header on `checkout.example.com` (CVSS 3.0)\n"
        "[i] **INFO** - PCI SAQ-A eligible once TLS issue resolved\n\n"
        "All tests complete. Report generated.")
    assessment_update(ec["id"], status="completed", findings_count=5, critical=0, high=1, medium=2, low=1, info=1)
    report_save(ec["id"], "executive",
        "# PCI-DSS Compliance Assessment - E-Commerce Platform\n\n"
        "## Status: CONDITIONAL PASS\n\n"
        "The checkout flow at https://checkout.example.com was assessed against PCI-DSS v4.0.\n\n"
        "| Requirement | Status |\n|---|---|\n"
        "| Req 2: Secure configurations | Partial |\n"
        "| Req 4: Encrypt transmission | Fail - TLS 1.0 on checkout.example.com:443 |\n"
        "| Req 6: Secure development | Pass |\n"
        "| Req 8: Authentication | Pass |\n\n"
        "**Priority:** Disable TLS 1.0/1.1 on checkout.example.com immediately.\n",
        findings=[
            {"severity": "high", "title": "TLS 1.0 Enabled on Checkout", "cvss": 7.4, "cwe": "CWE-326", "owasp": "A02:2021 Cryptographic Failures", "location": "checkout.example.com:443", "description": "TLS 1.0 enabled on payment checkout endpoint, violating PCI-DSS Req 4.", "remediation": "Disable TLS 1.0/1.1. Enforce TLS 1.2+ with strong cipher suites."},
            {"severity": "medium", "title": "Default Admin Credentials on CMS", "cvss": 6.5, "cwe": "CWE-798", "owasp": "A07:2021 Identification Failures", "location": "shop.example.com/admin", "description": "CMS admin panel uses default credentials.", "remediation": "Change default credentials. Enforce strong password policy."},
            {"severity": "medium", "title": "Missing HTTP Strict Transport Security", "cvss": 5.4, "cwe": "CWE-319", "owasp": "A05:2021 Security Misconfiguration", "location": "shop.example.com", "description": "HSTS header not set. Users may connect over HTTP initially.", "remediation": "Add Strict-Transport-Security header with includeSubDomains."},
            {"severity": "low", "title": "Directory Listing Enabled", "cvss": 3.5, "cwe": "CWE-548", "owasp": "A05:2021 Security Misconfiguration", "location": "shop.example.com/assets/", "description": "Directory listing enabled on static assets folder.", "remediation": "Disable directory listing in web server configuration."},
            {"severity": "info", "title": "X-Powered-By Header Present", "cvss": 0.0, "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration", "location": "HTTP response headers", "description": "X-Powered-By header reveals technology stack.", "remediation": "Remove X-Powered-By header."},
        ],
    )

    # -- Public Infrastructure (active, network findings) --
    pi = created[4]
    chat_add(pi["id"], "system", f"Assessment '{pi['name']}' started. Target: {pi['target']}")
    chat_add(pi["id"], "user", "Run external port scan and service enumeration on 203.0.113.0/24 (exclude 203.0.113.1)")
    chat_add(pi["id"], "assistant",
        "Nmap scan of `203.0.113.0/24` complete (254 hosts, excluding `203.0.113.1`).\n\n"
        "**Host Discovery:** 12 live hosts, 47 open ports.\n\n"
        "**Key hosts:**\n"
        "```\n"
        "203.0.113.2   - ns1.example.com    (53/tcp, 53/udp)\n"
        "203.0.113.10  - snmp.example.com   (161/udp)\n"
        "203.0.113.15  - ssh-gw.example.com (22/tcp)\n"
        "203.0.113.23  - web3.example.com   (80/tcp, 443/tcp) - Apache 2.4.49\n"
        "203.0.113.45  - rdp.example.com    (3389/tcp)\n"
        "```\n\n"
        "**Findings:**\n"
        " **HIGH** - `203.0.113.15:22` SSH accepts password auth, no fail2ban (CVSS 7.5)\n"
        " **HIGH** - `203.0.113.23:80` Apache 2.4.49 vulnerable to path traversal CVE-2021-41773 (CVSS 7.5)\n"
        " **MEDIUM** - `203.0.113.10:161` SNMP v1/v2c with community string `public` (CVSS 5.3)\n"
        " **MEDIUM** - `203.0.113.45:3389` RDP exposed without Network Level Auth (CVSS 5.0)\n"
        " **LOW** - `203.0.113.2:53` allows zone transfer (AXFR) (CVSS 3.5)\n\n"
        "Recommend prioritizing `203.0.113.23` - the Apache path traversal is actively exploited in the wild.")
    assessment_update(pi["id"], status="active", findings_count=5, critical=0, high=2, medium=2, low=1, info=0)

    # -- Healthcare Portal (active, HIPAA focus) --
    hp = created[5]
    chat_add(hp["id"], "system", f"Assessment '{hp['name']}' started. Target: {hp['target']}")
    chat_add(hp["id"], "user", "Test https://patient.healthco.example.com and https://api.healthco.example.com for PHI exposure and HIPAA violations")
    chat_add(hp["id"], "assistant",
        "HIPAA security assessment of `patient.healthco.example.com` and `api.healthco.example.com`.\n\n"
        "**Endpoints tested:**\n"
        "```\n"
        "GET  https://api.healthco.example.com/api/patients/1001\n"
        "GET  https://api.healthco.example.com/api/patients/1002\n"
        "GET  https://patient.healthco.example.com/records?id=1001\n"
        "POST https://api.healthco.example.com/api/prescriptions\n"
        "```\n\n"
        "**Findings:**\n"
        " **CRITICAL** - IDOR on `GET /api/patients/{id}` - incrementing ID returns other patients' PHI including SSN, DOB, diagnoses (CVSS 9.6)\n"
        " **HIGH** - Stack trace on `api.healthco.example.com` leaks PHI in 500 error: `Patient SSN=XXX-XX-1234` (CVSS 7.5)\n"
        " **MEDIUM** - No audit trail for PHI access on `/api/patients/*` endpoints (CVSS 6.0)\n\n"
        "Testing encryption at rest on the database backing `api.healthco.example.com`...")
    assessment_update(hp["id"], status="active", findings_count=3, critical=1, high=1, medium=1, low=0, info=0)

    # -- SaaS Platform (completed, tenant isolation) --
    sp = created[6]
    chat_add(sp["id"], "system", f"Assessment '{sp['name']}' started. Target: {sp['target']}")
    chat_add(sp["id"], "user", "Test tenant isolation on https://app.saasco.example.com - can tenant A access tenant B's data?")
    chat_add(sp["id"], "assistant",
        "Tenant isolation testing on `app.saasco.example.com` and `admin.saasco.example.com` completed.\n\n"
        "**Test methodology:**\n"
        "1. Authenticated as Tenant A (`acme-corp`) on `app.saasco.example.com`\n"
        "2. Intercepted requests and modified `X-Tenant-ID` header to Tenant B (`globex-inc`)\n"
        "3. Tested S3 bucket at `s3://saasco-uploads/` for cross-tenant access\n\n"
        "**Findings:**\n"
        " **CRITICAL** - `X-Tenant-ID: globex-inc` header on `GET /api/data` returns Tenant B data while authenticated as Tenant A (CVSS 9.8)\n"
        " **HIGH** - `s3://saasco-uploads/globex-inc/*` listable with Tenant A credentials (CVSS 8.0)\n"
        " **MEDIUM** - `GET /admin/users?search=@` on `admin.saasco.example.com` returns users across all tenants (CVSS 5.5)\n"
        " **LOW** - JWT payload on `app.saasco.example.com` includes `tenant_name` in cleartext (CVSS 2.5)\n\n"
        "**Critical:** The `X-Tenant-ID` bypass exposes all tenant data to any authenticated user.")
    assessment_update(sp["id"], status="completed", findings_count=4, critical=1, high=1, medium=1, low=1, info=0)
    report_save(sp["id"], "executive",
        "# Tenant Isolation Assessment - SaaS Platform\n\n"
        "## Risk Rating: CRITICAL\n\n"
        "Target: `app.saasco.example.com` / `admin.saasco.example.com`\n\n"
        "A critical tenant boundary bypass was discovered. Authenticated users can manipulate the "
        "`X-Tenant-ID` header on `app.saasco.example.com/api/data` to access any tenant's data.\n\n"
        "## Impact\n"
        "Complete compromise of multi-tenancy. All customer data at risk.\n\n"
        "## Remediation\n"
        "1. **Immediate:** Remove trust of client-supplied `X-Tenant-ID` header\n"
        "2. **Short-term:** Derive tenant from JWT `sub` claim on `app.saasco.example.com`\n"
        "3. **Verify:** Add integration tests for cross-tenant access on `/api/data`\n",
        findings=[
            {"severity": "critical", "title": "Cross-Tenant Data Access via Header Manipulation", "cvss": 9.8, "cwe": "CWE-284", "owasp": "A01:2021 Broken Access Control", "location": "GET /api/data (X-Tenant-ID header)", "description": "Modifying X-Tenant-ID header returns other tenants' data. Complete tenant isolation bypass.", "remediation": "Derive tenant context from JWT claims server-side. Never trust client-supplied tenant identifiers."},
            {"severity": "high", "title": "S3 Bucket Cross-Tenant Listing", "cvss": 8.0, "cwe": "CWE-284", "owasp": "A01:2021 Broken Access Control", "location": "s3://saasco-uploads/{tenant}/*", "description": "S3 bucket prefix for other tenants is listable with any authenticated tenant's credentials.", "remediation": "Implement per-tenant IAM policies scoped to S3 prefixes."},
            {"severity": "medium", "title": "Admin User Search Leaks Cross-Tenant Users", "cvss": 5.5, "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "location": "GET /admin/users?search=@", "description": "Admin user search endpoint returns users across all tenants.", "remediation": "Add tenant_id filter to all admin queries."},
            {"severity": "low", "title": "Tenant Name in JWT Payload", "cvss": 2.5, "cwe": "CWE-200", "owasp": "A02:2021 Cryptographic Failures", "location": "JWT payload", "description": "JWT payload exposes tenant_name in cleartext.", "remediation": "Use opaque tenant IDs. Remove unnecessary claims from JWT."},
        ],
    )

    # -- FinTech GraphQL (active) --
    ft = created[7]
    chat_add(ft["id"], "system", f"Assessment '{ft['name']}' started. Target: {ft['target']}")
    chat_add(ft["id"], "user", "Test https://gql.fintech.example.com/graphql for introspection, injection, and auth bypass")
    chat_add(ft["id"], "assistant",
        "GraphQL security assessment on `https://gql.fintech.example.com/graphql`.\n\n"
        "**Introspection query result:**\n"
        "```graphql\n"
        "# Full schema exposed - 47 types, 12 mutations\n"
        "type User { id: ID!, email: String!, balance: Float!, ssn: String }\n"
        "type Transaction { id: ID!, amount: Float!, from: User!, to: User! }\n"
        "mutation transferFunds(from: ID!, to: ID!, amount: Float!): Transaction\n"
        "```\n\n"
        "**Findings:**\n"
        " **HIGH** - Introspection enabled at `gql.fintech.example.com/graphql?query={__schema{types{name}}}` - full schema with `ssn` field exposed (CVSS 7.5)\n"
        " **HIGH** - No query depth limit - nested query `{ users { transactions { from { transactions ... } } } }` consumed 8GB RAM (CVSS 7.0)\n"
        " **MEDIUM** - Batch queries via array `[{query:...},{query:...}]` allow credential brute-force (CVSS 5.3)\n"
        " **MEDIUM** - `mutation transferFunds` accessible to non-admin roles (CVSS 6.0)\n\n"
        "Testing authorization on `transferFunds` mutation with different user roles...")
    assessment_update(ft["id"], status="active", findings_count=4, critical=0, high=2, medium=2, low=0, info=0)

    # -- IoT Gateway (active) --
    iot = created[8]
    chat_add(iot["id"], "system", f"Assessment '{iot['name']}' started. Target: {iot['target']}")
    chat_add(iot["id"], "user", "Scan 198.51.100.0/24 - check ports 80, 443, 1883, 8883 for MQTT brokers and web admin panels")
    chat_add(iot["id"], "assistant",
        "Network scan of `198.51.100.0/24` (ports 80, 443, 1883, 8883) complete.\n\n"
        "**Host discovery:**\n"
        "```\n"
        "198.51.100.1   - Gateway admin   (80/tcp, 1883/tcp)\n"
        "198.51.100.5   - Sensor hub      (8080/tcp)\n"
        "198.51.100.12  - Camera DVR      (443/tcp, 554/tcp)\n"
        "198.51.100.20  - Thermostat      (80/tcp)\n"
        "198.51.100.30  - Smart lock      (443/tcp)\n"
        "```\n\n"
        "**Findings:**\n"
        " **CRITICAL** - MQTT broker at `198.51.100.1:1883` accepts anonymous connections - subscribed to `#` and received all sensor telemetry (CVSS 9.1)\n"
        " **HIGH** - `198.51.100.1:80` admin panel accepts `admin/admin` credentials (CVSS 8.0)\n"
        " **MEDIUM** - `198.51.100.5:8080` firmware update via HTTP (no HTTPS, no signature verification) (CVSS 6.5)\n"
        " **LOW** - Device serial numbers published to MQTT topic `devices/+/info` on `198.51.100.1:1883` (CVSS 3.0)\n\n"
        "Priority: Lock down `198.51.100.1:1883` - any device on the network can read all sensor data and send commands.")
    assessment_update(iot["id"], status="active", findings_count=4, critical=1, high=1, medium=1, low=1, info=0)

    # -- WordPress (paused) --
    wp = created[9]
    chat_add(wp["id"], "system", f"Assessment '{wp['name']}' started. Target: {wp['target']}")
    chat_add(wp["id"], "user", "Scan https://blog.enterprise.example.com for vulnerable plugins and WordPress misconfigurations")
    chat_add(wp["id"], "assistant",
        "WordPress scan of `https://blog.enterprise.example.com` initiated but **paused** - "
        "WAF (Cloudflare) detected and blocking automated requests after 15 seconds.\n\n"
        "**Partial results before block:**\n"
        "```\n"
        "WordPress 6.2 detected at blog.enterprise.example.com\n"
        "xmlrpc.php: accessible at https://blog.enterprise.example.com/xmlrpc.php\n"
        "wp-login.php: accessible at https://blog.enterprise.example.com/wp-login.php\n"
        "Plugins found: 14 (version checks incomplete due to WAF)\n"
        "```\n\n"
        "**Findings:**\n"
        " **MEDIUM** - WordPress 6.2 at `blog.enterprise.example.com` is outdated (latest: 6.5) (CVSS 5.0)\n"
        " **MEDIUM** - `blog.enterprise.example.com/xmlrpc.php` enabled - brute-force via `system.multicall` possible (CVSS 5.3)\n"
        "[i] **INFO** - 14 plugins detected, full enumeration blocked by WAF\n\n"
        "Recommend requesting Cloudflare WAF whitelist for source IP to continue scan.")
    assessment_update(wp["id"], status="paused", findings_count=3, critical=0, high=0, medium=2, low=0, info=1)

    return created


# ===========================================================================
# INIT HELPER
# ===========================================================================

def init_db(seed: bool = True):
    """Create tables and optionally seed. Called at server startup."""
    import time as _time
    max_retries = 10
    for attempt in range(1, max_retries + 1):
        try:
            create_tables()
            break
        except Exception as e:
            if attempt == max_retries:
                raise
            print(f"[!] DynamoDB not ready (attempt {attempt}/{max_retries}): {e}")
            _time.sleep(5)
    if seed:
        return seed_data()
    return []
