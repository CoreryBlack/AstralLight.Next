#!/usr/bin/env python3
"""Signed Gateway v3 worker-id readiness probe (DIST_TEST_MODE=rust only).

Single-shot readiness probe for the Rust TrustGraph test-control plane:
``GET /main/api/v1/internal/test-control/worker-id`` (frozen path, see
``AstralLight-Rust/astral-trustgraph/src/api/test_control.rs``).

The Rust endpoint sits behind the full middleware chain; this probe sends a
complete, honestly signed request and adds no bypass of any kind:

1. ``gateway_signature_middleware`` -- headers ``X-Gateway-Auth: verified``,
   ``X-Gateway-Ts`` (ms) and ``X-Gateway-Signature`` (HMAC-SHA256 hex) over the
   canonical 15-line Gateway v3 payload, byte-for-byte aligned with
   ``astral_common::middleware::gateway_signature::compute_hmac_signature_v3``
   (prefix ``astral-gateway-v3`` + 14 fields, empty values stay empty lines).
2. ``permission_check_middleware`` -- the probe identity must already hold a
   published ``monitor:read`` authorization in the shared store. This harness
   never creates permissions; provisioning is the operator's responsibility.
3. ``X-Test-Control-Token`` -- constant-time token check inside the handler.

Fail-closed contract: every required environment variable must be present and
valid; any missing/invalid input exits non-zero with a ``REASON:<TOKEN>`` line
on stderr and no request is sent. The direct probe (not ``--self-test``)
additionally requires ``DIST_TEST_PROBE_ACTION=read`` (exact value), accepts
only the exact frozen path ``/main/api/v1/internal/test-control/worker-id``
(the caller supplies the full URL; the probe never appends to or signs a
different path), and rejects Gateway secrets shorter than 32 characters or
containing obvious placeholder markers. Secrets are read from the environment
only (never argv, never logs, never printed); stdout on success is one
non-sensitive JSON line (``nodeId`` / ``workerId`` / ``configFingerprint``).

Offline validation (no network): ``python3 probe_worker_id.py --self-test``
recomputes the golden vector locked by the Rust unit test
``gateway_signature::tests::v3_golden_vector_is_stable``.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Canonical Gateway v3 payload prefix (Rust compute_hmac_signature_v3).
SIGNATURE_PREFIX = "astral-gateway-v3"

# Signature-bound identity fields. Names mirror the header contract; values
# are trimmed exactly like the Rust verifier trims them.
ENV_SIGNATURE_TEXT = (
    "DIST_TEST_PROBE_TOKEN_ID",
    "DIST_TEST_PROBE_TOKEN_USE",
    "DIST_TEST_PROBE_CLAIMS_VERSION",
    "DIST_TEST_PROBE_ACTION_CODES",
    "DIST_TEST_PROBE_USER_ROLES",
)
ENV_SIGNATURE_IDS = (
    "DIST_TEST_PROBE_USER_ID",
    "DIST_TEST_PROBE_IDENTITY_CARD_ID",
    "DIST_TEST_PROBE_USER_CARD_ID",
    "DIST_TEST_PROBE_USER_CARD_DOMAIN_ID",
    "DIST_TEST_PROBE_USER_CARD_TENANT_ID",
)
ENV_PRINCIPAL_KIND = "DIST_TEST_PROBE_PRINCIPAL_KIND"
ENV_TEST_CONTROL_TOKEN = "TEST_CONTROL_TOKEN"
ENV_GATEWAY_HMAC_SECRET = "GATEWAY_HMAC_SECRET"
# Operator action gate for the direct probe path (not the offline self-test).
ENV_PROBE_ACTION = "DIST_TEST_PROBE_ACTION"

# Rust PrincipalKind::parse accepts exactly these values.
PRINCIPAL_KINDS = ("PLATFORM_USER", "APP_USER")

# parse_positive_id alignment: i64, strictly positive, bounded input length.
POSITIVE_INT_RE = re.compile(r"^[1-9][0-9]{0,17}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
# Whitespace or control characters inside signature-bound text values are
# never valid: surrounding whitespace is trimmed like the Rust verifier trims
# (require_env), so anything this pattern matches is internal and fails closed.
TEXT_INTERNAL_BAD_RE = re.compile(r"[\s\x00-\x1f\x7f-\x9f]")
MAX_URL_LENGTH = 2048
MAX_RESPONSE_BYTES = 65536
# Bounded outbound timeout: overridable via --timeout (clamped 1..30 seconds).
DEFAULT_TIMEOUT_SECONDS = 5.0
# Frozen Rust test-control endpoint: the caller supplies the full URL, but the
# probe signs and sends exactly this path or fails closed.
WORKER_ID_URL_PATH = "/main/api/v1/internal/test-control/worker-id"
# Case-insensitive placeholder markers rejected in GATEWAY_HMAC_SECRET; the
# value itself is never printed, a rejected secret only yields INVALID_ENV.
SECRET_PLACEHOLDER_MARKERS = (
    "change-me",
    "changeme",
    "replace",
    "example",
    "todo",
    "tbd",
    "xxxx",
    "password",
    "test",
)


class ProbeError(Exception):
    """Probe failure carrying a sanitized reason token (never secret values)."""


def require_env(name: str) -> str:
    """Read a required environment variable, trimmed and control-char free."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        raise ProbeError("MISSING_ENV:%s" % name)
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise ProbeError("INVALID_ENV:%s" % name)
    value = raw.strip()
    if value == "":
        raise ProbeError("INVALID_ENV:%s" % name)
    return value


def require_signature_text_env(name: str) -> str:
    """Read a signature-bound text field, rejecting internal bad characters.

    Surrounding whitespace is trimmed exactly like the Rust verifier trims
    header values (require_env); any whitespace or control character that
    remains after that trim is internal and fails closed.
    """
    value = require_env(name)
    if TEXT_INTERNAL_BAD_RE.search(value):
        raise ProbeError("INVALID_ENV:%s" % name)
    return value


def require_positive_int_env(name: str) -> str:
    value = require_env(name)
    if not POSITIVE_INT_RE.match(value):
        raise ProbeError("INVALID_ENV:%s" % name)
    return value


def require_principal_kind_env() -> str:
    value = require_env(ENV_PRINCIPAL_KIND)
    if value not in PRINCIPAL_KINDS:
        raise ProbeError("INVALID_ENV:%s" % ENV_PRINCIPAL_KIND)
    return value


def require_secret_env(name: str, min_length: int) -> str:
    value = require_env(name)
    if len(value) < min_length:
        raise ProbeError("INVALID_ENV:%s" % name)
    return value


def require_probe_action_env() -> str:
    """Gate the direct probe behind an explicit operator action selection."""
    value = require_env(ENV_PROBE_ACTION)
    if value != "read":
        raise ProbeError("INVALID_ENV:%s" % ENV_PROBE_ACTION)
    return value


def require_gateway_secret_env() -> str:
    """Read the Gateway HMAC secret; reject short or placeholder-like values.

    The value itself is never included in error output or logs.
    """
    value = require_secret_env(ENV_GATEWAY_HMAC_SECRET, min_length=32)
    lowered = value.lower()
    if any(marker in lowered for marker in SECRET_PLACEHOLDER_MARKERS):
        raise ProbeError("INVALID_ENV:%s" % ENV_GATEWAY_HMAC_SECRET)
    return value


def parse_endpoint_url(url: str) -> str:
    """Validate the endpoint URL and return the path used in the signature.

    The path must be exactly ``WORKER_ID_URL_PATH``: the caller supplies the
    full URL and the probe never appends to or signs a different path.
    """
    if len(url) > MAX_URL_LENGTH or any(ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        raise ProbeError("INVALID_URL")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ProbeError("INVALID_URL")
    # Credentials in the URL, query strings or fragments would break the
    # signature path contract and risk leaking secrets -> fail closed.
    if parts.username is not None or parts.password is not None:
        raise ProbeError("INVALID_URL")
    if parts.query or parts.fragment:
        raise ProbeError("INVALID_URL")
    path = parts.path or "/"
    if not path.startswith("/"):
        raise ProbeError("INVALID_URL")
    if path != WORKER_ID_URL_PATH:
        raise ProbeError("URL_PATH_MISMATCH")
    return path


def compute_signature_v3(secret: str, fields: list) -> str:
    """HMAC-SHA256 hex over the canonical 15-line Gateway v3 payload.

    Mirrors ``compute_hmac_signature_v3``: ``SIGNATURE_PREFIX`` plus the 14
    given fields, joined with newlines (15 lines total). Empty values remain
    empty lines so producer and verifier see identical field order.
    """
    payload = "\n".join([SIGNATURE_PREFIX, *fields])
    digest = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def build_headers(secret: str, signature_path: str, request_id: str) -> dict:
    """Assemble the exact header set the Rust middleware chain evaluates."""
    text_values = {name: require_signature_text_env(name) for name in ENV_SIGNATURE_TEXT}
    identity = {name: require_positive_int_env(name) for name in ENV_SIGNATURE_IDS}
    principal_kind = require_principal_kind_env()
    test_control_token = require_secret_env(ENV_TEST_CONTROL_TOKEN, min_length=1)

    timestamp = str(int(time.time() * 1000))
    signature = compute_signature_v3(
        secret,
        [
            "GET",
            signature_path,
            identity["DIST_TEST_PROBE_USER_ID"],
            principal_kind,
            text_values["DIST_TEST_PROBE_TOKEN_ID"],
            identity["DIST_TEST_PROBE_IDENTITY_CARD_ID"],
            identity["DIST_TEST_PROBE_USER_CARD_ID"],
            identity["DIST_TEST_PROBE_USER_CARD_DOMAIN_ID"],
            identity["DIST_TEST_PROBE_USER_CARD_TENANT_ID"],
            text_values["DIST_TEST_PROBE_TOKEN_USE"],
            text_values["DIST_TEST_PROBE_CLAIMS_VERSION"],
            text_values["DIST_TEST_PROBE_ACTION_CODES"],
            text_values["DIST_TEST_PROBE_USER_ROLES"],
            timestamp,
        ],
    )

    return {
        "X-Gateway-Auth": "verified",
        "X-Gateway-Ts": timestamp,
        "X-Gateway-Signature": signature,
        "x-user-id": identity["DIST_TEST_PROBE_USER_ID"],
        "x-principal-kind": principal_kind,
        "x-token-id": text_values["DIST_TEST_PROBE_TOKEN_ID"],
        "x-identity-card-id": identity["DIST_TEST_PROBE_IDENTITY_CARD_ID"],
        "x-user-card-id": identity["DIST_TEST_PROBE_USER_CARD_ID"],
        "x-user-card-domain-id": identity["DIST_TEST_PROBE_USER_CARD_DOMAIN_ID"],
        "x-user-card-tenant-id": identity["DIST_TEST_PROBE_USER_CARD_TENANT_ID"],
        "x-token-use": text_values["DIST_TEST_PROBE_TOKEN_USE"],
        "x-claims-version": text_values["DIST_TEST_PROBE_CLAIMS_VERSION"],
        "x-action-codes": text_values["DIST_TEST_PROBE_ACTION_CODES"],
        "x-user-roles": text_values["DIST_TEST_PROBE_USER_ROLES"],
        "X-Test-Control-Token": test_control_token,
        "x-request-id": request_id,
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Fail closed on redirects instead of re-sending signed headers."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def probe_once(url: str, expected_node_id: str, request_id: str, timeout_seconds: float) -> dict:
    """Send one signed GET and validate the worker-id response shape.

    Direct-path gates run before anything is built or sent: the operator
    action selection must be exactly ``read`` (require_probe_action_env) and
    the Gateway HMAC secret must pass full secret validation, including the
    length floor and placeholder markers (require_gateway_secret_env).
    """
    require_probe_action_env()
    signature_path = parse_endpoint_url(url)
    secret = require_gateway_secret_env()
    headers = build_headers(secret, signature_path, request_id)

    request = urllib.request.Request(url, method="GET", headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            status = response.getcode()
            body = response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as error:
        # Error bodies carry only fixed contract fields (code/message/traceId/
        # errorType/decision/reasonCode); surface status plus a reason code.
        detail = ""
        try:
            payload = json.loads(error.read(MAX_RESPONSE_BYTES).decode("utf-8"))
            if isinstance(payload, dict):
                detail = str(payload.get("reasonCode") or payload.get("errorType") or "")
        except Exception:  # noqa: BLE001 - reason extraction is best effort
            detail = ""
        detail = re.sub(r"[^A-Za-z0-9_.-]", "_", detail)[:64]
        raise ProbeError("HTTP_ERROR:%s%s" % (error.code, ":%s" % detail if detail else "")) from error
    except (urllib.error.URLError, OSError) as error:
        raise ProbeError("NETWORK_ERROR") from error

    if status != 200:
        raise ProbeError("HTTP_ERROR:%s" % status)
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError("RESPONSE_NOT_JSON") from error
    if not isinstance(value, dict):
        raise ProbeError("RESPONSE_NOT_JSON")

    node_id = value.get("nodeId")
    if not isinstance(node_id, str) or node_id != expected_node_id:
        raise ProbeError("NODE_ID_MISMATCH")
    for field in ("workerId", "configFingerprint"):
        field_value = value.get(field)
        if not isinstance(field_value, str) or not field_value or field_value == "null":
            raise ProbeError("MISSING_FIELD:%s" % field)
    # Rust-only contract fields, validated when present.
    for field in ("jvmStartTime", "processIdentityHash"):
        field_value = value.get(field)
        if field_value is not None and (
            not isinstance(field_value, str) or not field_value or field_value == "null"
        ):
            raise ProbeError("MISSING_FIELD:%s" % field)

    # Output is limited to the three non-sensitive contract fields shared with
    # the Java probe contract; never echoes headers, tokens or the URL.
    return {
        "nodeId": node_id,
        "workerId": value["workerId"],
        "configFingerprint": value["configFingerprint"],
    }


def run_self_test() -> int:
    """Recompute the Rust v3 golden vector; exit 0 on exact match."""
    secret = "test-secret-at-least-32-chars-long!!"
    fields = [
        "GET",
        "/v1/app/learn/progress/12",
        "42",
        "PLATFORM_USER",
        "jti-abc",
        "identity-card",
        "user-card",
        "user-domain",
        "user-tenant",
        "ACCESS",
        "2",
        "read",
        "USER",
        "1700000000000",
    ]
    expected = "dab71988d282189ecdfe643fb112034d9d0b5c1df3e1906781f73f729bd65b46"
    payload = "\n".join([SIGNATURE_PREFIX, *fields])
    if payload.count("\n") != 14:
        print("SELF-TEST:FAIL:PAYLOAD_LINE_COUNT", file=sys.stderr)
        return 1
    actual = compute_signature_v3(secret, fields)
    if not hmac.compare_digest(actual, expected):
        print("SELF-TEST:FAIL:SIGNATURE_MISMATCH", file=sys.stderr)
        return 1
    print("SELF-TEST:PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Signed Gateway v3 worker-id readiness probe (Rust mode)."
    )
    parser.add_argument("--url", help="full worker-id endpoint URL")
    parser.add_argument("--node-id", help="expected nodeId of the probed node")
    parser.add_argument("--request-id", help="run-scoped request id (X-Request-Id)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="bounded per-attempt timeout in seconds (1..30, default 5)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="offline golden-vector check of the v3 signature; no network",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    try:
        if not args.url or not args.node_id:
            raise ProbeError("MISSING_ARGS")
        if not REQUEST_ID_RE.match(args.request_id or ""):
            raise ProbeError("INVALID_REQUEST_ID")
        timeout_seconds = min(max(args.timeout, 1.0), 30.0)
        result = probe_once(args.url, args.node_id, args.request_id, timeout_seconds)
    except ProbeError as error:
        print("REASON:%s" % error.args[0], file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
