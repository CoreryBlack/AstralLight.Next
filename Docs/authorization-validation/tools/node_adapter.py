#!/usr/bin/env python3
"""Import-safe, standard-library-only node adapter for authorization validation.

Scope and safety boundary (Exec-L1):

- Importing this module performs ZERO file, environment, network, or
  subprocess I/O. All state is created explicitly: :func:`load_config`
  validates a flat run_config mapping when the caller invokes it, and :class:`NodeAdapter` methods are the only entry
  points that can touch the outside world.
- Every external command goes through an injected :class:`CommandRunner`; the
  production :class:`SubprocessRunner` calls ``subprocess.run`` with an argv
  list and never ``shell=True``, and only when an explicit adapter method is
  called. All HTTP goes through an injected :class:`HttpTransport`; the
  production :class:`UrllibHttpTransport` uses ``urllib.request`` only (no
  third-party dependency).
- Secrets (MySQL root password, Redis password, HMAC key) are loaded lazily,
  passed only via stdin, never placed in argv or the process environment,
  never echoed into results, and never retained on the adapter between calls.
  Public metadata exposes only provenance digests and node labels -- never
  URLs, hosts, SSH targets, base_dir, database/container names, secret paths,
  or passwords. Error details are scrubbed for host-like tokens.
- SQL is guarded to a single SELECT statement; Redis verbs are restricted to
  ``GET``/``LLEN``/``PING``. Signed HTTP is restricted to
  ``GET``/``POST``/``PUT``/``DELETE`` under ``/main/api/v1/*``. Mutation methods
  are inert until an explicit caller invokes them and are intended only for the
  separately gated live campaign; import, construction, and offline preflight
  remain side-effect free. The log-slice method only reads log lines matching
  caller-supplied safe request/operation identifiers and never starts or stops
  anything.

Gateway v3 signed-header contract (mirrors the distributed validation harness,
``rust-s15/s15_coordinator.py`` ``sign_headers``): the HMAC-SHA256 input is
exactly 15 fields joined with ``\\n``:

1. ``astral-gateway-v3``
2. METHOD
3. path without query
4. user id
5. ``PLATFORM_USER``
6. token id (empty)
7. identity card id
8. user card id
9. domain id
10. tenant id
11-14. four reserved empty fields
15. timestamp in milliseconds

The header set carries ``x-request-id`` and ``x-gateway-auth: verified`` plus
the identity fields and signature, exactly like the frozen harness.

MySQL access design note: the container-side ``mysql`` client reads the root
password only from the ``MYSQL_PWD`` environment inside the container. A
temporary ``[client]`` options file would require a shell-managed file
lifecycle inside the container, so the adapter uses the blessed explicit
stdin wrapper instead: ``docker exec -i <container> sh -c <FIXED literal
script> sh <database> <query>`` where the fixed script is
``MYSQL_PWD="$(cat)" exec mysql -uroot -N -e "$2" "$1"``. The query and
database travel as positional argv (never interpolated into the script
text), the password travels through stdin, and argv contains no secret.
Redis uses the same fixed stdin-auth pattern with ``REDISCLI_AUTH="$(cat)"``.

When constructed with a default actor, the adapter also satisfies the
``e3_e4.ReadOnlyProbe`` duck type (``sql`` / ``redis`` / ``signed_get``), so
the campaign harness can inject it as the E3/E4 probe.

Python 3.8+ standard library only. Offline unit tests live in
``test_node_adapter.py`` next to this file and use injected fake runners,
fake transports, and temporary files only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import time
import types
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    runtime_checkable,
)

import experiment_common
from experiment_common import SAFE_ID, validate_run_config_shape

__all__ = [
    "GATEWAY_AUTH_VERIFIED",
    "GATEWAY_PATH_PREFIX",
    "GATEWAY_V3_PREFIX",
    "LOG_FILE_BY_NODE",
    "NODE_ALIASES",
    "PRINCIPAL_KIND_PLATFORM_USER",
    "READONLY_REDIS_VERBS",
    "REQUEST_ID_RE",
    "SIGNED_HTTP_METHODS",
    "Actor",
    "AdapterError",
    "CommandResult",
    "CommandRunner",
    "ConfigError",
    "HttpTransport",
    "NodeAdapter",
    "NodeAdapterConfig",
    "RoleActorProbe",
    "SubprocessRunner",
    "UrllibHttpTransport",
    "build_gateway_v3_payload",
    "load_config",
]

# ---------------------------------------------------------------------------
# Contract constants (pure data; no I/O at import time).
# ---------------------------------------------------------------------------

GATEWAY_V3_PREFIX = "astral-gateway-v3"
PRINCIPAL_KIND_PLATFORM_USER = "PLATFORM_USER"
GATEWAY_AUTH_VERIFIED = "verified"
#: Signed requests are restricted to the protected endpoint family.
GATEWAY_PATH_PREFIX = "/main/api/v1/"

#: Canonical node aliases. Host targets are never derived from these labels
#: inside returned metadata; the mapping to real targets stays private.
NODE_ALIASES = ("node-a", "node-b", "node-c")
#: Per-node server log file name inside base_dir (frozen harness layout).
LOG_FILE_BY_NODE = {
    "node-a": "server_a.log",
    "node-b": "server_b.log",
    "node-c": "server_c.log",
}
#: Redis commands this adapter may ever send.
READONLY_REDIS_VERBS = frozenset({"GET", "LLEN", "PING"})
#: Signed HTTP verbs available to the separately gated live campaign.
SIGNED_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE"})
#: Server-side durable operation-id contract used by mutation/audit code.
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$")

_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_DB_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_BASE_DIR_RE = re.compile(r"^~?[A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+)*$")
_METHOD_RE = re.compile(r"^[A-Za-z]{1,32}$")
_REDIS_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+*-]{0,511}$")
_AGGREGATE_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_MAX_SIGNED_I64 = (1 << 63) - 1
_HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")

# Host-like token scrubbing for error details (same policy as e3_e4.py).
_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOSTNAME_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+"
    r"(?:com|net|org|edu|gov|io|dev|app|local|internal|lan|example|test|invalid)\b",
    re.IGNORECASE,
)
_SCRUB_REPLACEMENT = "[redacted-host]"

#: Fixed container-side MySQL wrapper. $1 = database, $2 = query (positional
#: argv after ``sh -c``); the password arrives on stdin via ``$(cat)``.
_MYSQL_STDIN_SCRIPT = 'MYSQL_PWD="$(cat)" exec mysql -uroot -N -e "$2" "$1"'
#: Fixed container-side Redis wrapper: every argument after ``sh`` is passed
#: to redis-cli verbatim; the password arrives on stdin via ``$(cat)``.
_REDIS_STDIN_SCRIPT = 'REDISCLI_AUTH="$(cat)" exec redis-cli "$@"'

#: Fixed log-slice script executed remotely (or locally for node-b) via
#: ``python3 -`` with the script delivered on stdin. argv carries only the
#: base directory, log file name, and a base64-encoded JSON identifier list;
#: the script re-validates every identifier against the safe alphabet.
_LOG_GREP_SCRIPT = """import base64, binascii, json, re, sys

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def main(argv):
    if len(argv) != 4:
        raise SystemExit(2)
    base, name, payload = argv[1], argv[2], argv[3]
    # The argv payload is base64(json(identifiers)) -- encoded by read_log_lines
    # so the identifier list never rides as raw shell-visible JSON.
    try:
        identifiers = json.loads(base64.b64decode(payload, validate=True))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        raise SystemExit(2)
    if not isinstance(identifiers, list) or not identifiers:
        raise SystemExit(2)
    for item in identifiers:
        if not isinstance(item, str) or not _SAFE_ID.fullmatch(item):
            raise SystemExit(2)
    path = base.rstrip("/") + "/" + name
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if any(item in line for item in identifiers):
                sys.stdout.write(line)


main(sys.argv)
"""


def _scrub_text(value: str) -> str:
    """Redact host-like tokens (URLs, IP literals, hostnames) from text."""
    scrubbed = _URL_RE.sub(_SCRUB_REPLACEMENT, value)
    scrubbed = _IPV4_RE.sub(_SCRUB_REPLACEMENT, scrubbed)
    return _HOSTNAME_RE.sub(_SCRUB_REPLACEMENT, scrubbed)


# ---------------------------------------------------------------------------
# Errors. Messages carry only constant labels plus scrubbed excerpts; they
# never include argv, secrets, or unscrubbed host targets.
# ---------------------------------------------------------------------------


class AdapterError(RuntimeError):
    """An adapter operation failed; details are scrubbed and bounded."""

    def __init__(self, kind: str, detail: str = "", exit_code: Optional[int] = None) -> None:
        self.kind = str(kind)
        self.exit_code = exit_code
        self.detail = _scrub_text(str(detail))[:300] if detail else ""
        message = self.kind if not self.detail else "%s: %s" % (self.kind, self.detail)
        super().__init__(message)


class ConfigError(ValueError):
    """run_config mapping rejected; problems are constant field labels."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = sorted(set(str(problem) for problem in problems))
        super().__init__("invalid run_config: %s" % ", ".join(self.problems))


# ---------------------------------------------------------------------------
# Injected transport protocols and production implementations.
# ---------------------------------------------------------------------------


class CommandResult(NamedTuple):
    """Structured result of one injected command execution."""

    argv: Tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str


@runtime_checkable
class CommandRunner(Protocol):
    """Runner injected into :class:`NodeAdapter` (fake in tests)."""

    def run(
        self, argv: Sequence[str], *, stdin_text: str = "", timeout_s: float = 60.0
    ) -> CommandResult: ...


@runtime_checkable
class HttpTransport(Protocol):
    """HTTP transport injected into :class:`NodeAdapter` (fake in tests)."""

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: Optional[bytes],
        timeout_s: float,
    ) -> Tuple[int, str]: ...


class SubprocessRunner:
    """Production :class:`CommandRunner`.

    ``subprocess`` is touched only inside :meth:`run`, i.e. only when an
    explicit adapter method is called. The command list form is used and
    ``shell=True`` is never set (it is subprocess.run's default to not use a
    shell, and this class never overrides that default).
    """

    def run(
        self, argv: Sequence[str], *, stdin_text: str = "", timeout_s: float = 60.0
    ) -> CommandResult:
        argv_tuple = tuple(str(part) for part in argv)
        try:
            completed = subprocess.run(
                list(argv_tuple),
                input=stdin_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired as error:
            raise AdapterError("runner_timeout", "timeout after %ss" % (timeout_s,)) from error
        except OSError as error:
            raise AdapterError("runner_spawn_failed", type(error).__name__) from error
        return CommandResult(
            argv=argv_tuple,
            exit_code=int(completed.returncode),
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )


class UrllibHttpTransport:
    """Production :class:`HttpTransport` on top of ``urllib.request``.

    Non-2xx responses are returned as ``(status, body)`` rather than raised, so
    callers see the server decision. Transport-level failures (DNS, refused,
    timeout) propagate as ``urllib.error.URLError``/``OSError``.
    """

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: Optional[bytes],
        timeout_s: float,
    ) -> Tuple[int, str]:
        request = urllib.request.Request(
            url,
            data=body,
            headers=dict(headers),
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_s) as response:
                return int(response.status), response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            return int(error.code), error.read().decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Actor: signed-request identity (dual-card + domain + tenant).
# ---------------------------------------------------------------------------


def _check_payload_field(name: str, value: Any) -> None:
    """Signed-payload integrity: bounded, non-empty, newline-free fields."""
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("actor field %s must be a non-empty string of at most 256 chars" % name)
    if any(char in value for char in "\n\r\t") or value != value.strip():
        raise ValueError("actor field %s must not contain whitespace or padding" % name)


@dataclass(frozen=True)
class Actor:
    """Identity used to build Gateway v3 signatures."""

    user_id: str
    identity_card: str
    user_card: str
    domain: str
    tenant: str

    def __post_init__(self) -> None:
        for name in ("user_id", "identity_card", "user_card", "domain", "tenant"):
            _check_payload_field(name, getattr(self, name))

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "Actor":
        """Build from a flat mapping (``icard``/``card`` aliases accepted)."""
        if not isinstance(raw, Mapping):
            raise TypeError("actor must be a mapping")

        def pick(*names: str) -> Any:
            for name in names:
                value = raw.get(name)
                if value is not None:
                    return value
            return None

        fields = {
            "user_id": pick("user_id"),
            "identity_card": pick("identity_card", "icard"),
            "user_card": pick("user_card", "card"),
            "domain": pick("domain"),
            "tenant": pick("tenant"),
        }
        missing = sorted(name for name, value in fields.items() if value is None)
        if missing:
            raise ValueError("actor missing fields: %s" % ", ".join(missing))
        coerced = {
            name: value if isinstance(value, str) else str(value)
            for name, value in fields.items()
        }
        return cls(**coerced)


def build_gateway_v3_payload(actor: Actor, method: str, path: str, timestamp_ms: Any) -> str:
    """Build the exact 15-field Gateway v3 signing payload (see module docstring)."""
    return "\n".join(
        [
            GATEWAY_V3_PREFIX,
            method.strip(),
            path.split("?", 1)[0],
            actor.user_id,
            PRINCIPAL_KIND_PLATFORM_USER,
            "",
            actor.identity_card,
            actor.user_card,
            actor.domain,
            actor.tenant,
            "",
            "",
            "",
            "",
            str(timestamp_ms),
        ]
    )


# ---------------------------------------------------------------------------
# Typed/validated configuration (explicit loader; compatible with the flat
# run_config mapping).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NodeAdapterConfig:
    """Validated run configuration.

    Provenance fields are public. Topology and secret fields are marked
    ``repr=False`` so neither ``repr()`` nor ``str()`` ever exposes URLs,
    hosts, SSH targets, base_dir, database/container names, the HMAC secret
    path, or passwords. Mappings are wrapped in read-only proxy views.
    """

    # Provenance (public metadata).
    run_id: str
    binary_sha256: str
    source_snapshot_sha256: str
    source_git_rev: str
    source_dirty_patch_sha256: str
    bootstrap_bin_sha256: str
    source_dirty: Optional[bool]
    # Topology (private).
    nodes: Mapping[str, str] = field(repr=False)
    ssh: Mapping[str, str] = field(repr=False)
    base_dir: str = field(repr=False)
    db: str = field(repr=False)
    mysql_container: str = field(repr=False)
    redis_container: str = field(repr=False)
    hmac_secret_file: str = field(repr=False)
    ports: Mapping[str, int] = field(repr=False)
    git_rev: Optional[str] = field(repr=False)
    redis_port: Optional[int] = field(repr=False)
    # Secrets (private; optional at load, required at use).
    mysql_root: Optional[str] = field(repr=False)
    redis_password: Optional[str] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "nodes", types.MappingProxyType(dict(self.nodes)))
        object.__setattr__(self, "ssh", types.MappingProxyType(dict(self.ssh)))
        object.__setattr__(self, "ports", types.MappingProxyType(dict(self.ports)))

    def public_metadata(self) -> Dict[str, Any]:
        """Provenance-only view; matches ``experiment_common.public_provenance``.

        Never contains URLs, hosts, SSH targets, base_dir, database/container
        names, secret paths, passwords, or ports.
        """
        return {
            "runId": self.run_id,
            "binarySha256": self.binary_sha256,
            "sourceSnapshotSha256": self.source_snapshot_sha256,
            "sourceGitRev": self.source_git_rev,
            "sourceDirty": self.source_dirty,
            "sourceDirtyPatchSha256": self.source_dirty_patch_sha256,
            "bootstrapBinSha256": self.bootstrap_bin_sha256,
            "nodeLabels": list(NODE_ALIASES),
        }


def load_config(raw: Mapping[str, Any]) -> NodeAdapterConfig:
    """Validate a flat run_config mapping into a typed config.

    Reuses ``experiment_common.validate_run_config_shape`` for the mandatory
    provenance fields and node-a/b/c shape, then adds adapter-specific checks
    (safe database/container identifiers, node URL scheme, SSH targets for
    node-a/node-c, base_dir path alphabet, secret types). Raises
    :class:`ConfigError` with sorted constant problem labels; raw values are
    never echoed into error messages.
    """
    if not isinstance(raw, Mapping):
        raise ConfigError(["config_not_a_mapping"])
    problems: List[str] = list(validate_run_config_shape(raw))

    nodes = raw.get("nodes")
    if isinstance(nodes, Mapping):
        for alias in NODE_ALIASES:
            value = nodes.get(alias)
            if (
                not isinstance(value, str)
                or not value.startswith(("http://", "https://"))
                or value.endswith("/")
                or "?" in value
                or any(char.isspace() for char in value)
            ):
                problems.append("invalid:nodes")
                break
    ssh = raw.get("ssh")
    if isinstance(ssh, Mapping):
        for alias in ("node-a", "node-c"):
            value = ssh.get(alias)
            if not isinstance(value, str) or not value or any(char.isspace() for char in value):
                problems.append("invalid:ssh")
                break
    else:
        problems.append("invalid:ssh")

    base_dir = raw.get("base_dir")
    if (
        not isinstance(base_dir, str)
        or not base_dir
        or not _BASE_DIR_RE.fullmatch(base_dir)
        or ".." in base_dir.split("/")
    ):
        problems.append("invalid:base_dir")

    db = raw.get("db")
    if not isinstance(db, str) or not _DB_NAME_RE.fullmatch(db):
        problems.append("invalid:db")

    for name in ("mysql_container", "redis_container"):
        value = raw.get(name)
        if not isinstance(value, str) or not _CONTAINER_RE.fullmatch(value):
            problems.append("invalid:%s" % name)

    hmac_secret_file = raw.get("hmac_secret_file")
    if (
        not isinstance(hmac_secret_file, str)
        or not hmac_secret_file
        or any(char.isspace() for char in hmac_secret_file)
    ):
        problems.append("invalid:hmac_secret_file")

    ports = raw.get("ports")
    if ports is not None:
        ports_ok = isinstance(ports, Mapping) and set(ports) == set(NODE_ALIASES)
        if ports_ok:
            for alias in NODE_ALIASES:
                value = ports.get(alias)
                if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
                    ports_ok = False
                    break
        if not ports_ok:
            problems.append("invalid:ports")

    mysql_root = raw.get("mysql_root")
    if mysql_root is not None and (not isinstance(mysql_root, str) or not mysql_root):
        problems.append("invalid:mysql_root")

    redis_password = raw.get("redis_password")
    if redis_password is not None and (not isinstance(redis_password, str) or not redis_password):
        problems.append("invalid:redis_password")

    git_rev = raw.get("git_rev")
    if git_rev is not None and (not isinstance(git_rev, str) or not _HEX40_RE.fullmatch(git_rev)):
        problems.append("invalid:git_rev")

    redis_port = raw.get("redis_port")
    if redis_port is not None and (
        isinstance(redis_port, bool)
        or not isinstance(redis_port, int)
        or not 0 < redis_port < 65536
    ):
        problems.append("invalid:redis_port")

    problems = sorted(set(problems))
    if problems:
        raise ConfigError(problems)

    source_dirty = raw.get("source_dirty")
    return NodeAdapterConfig(
        run_id=str(raw["run_id"]),
        binary_sha256=str(raw["binary_sha256"]),
        source_snapshot_sha256=str(raw["source_snapshot_sha256"]),
        source_git_rev=str(raw["source_git_rev"]),
        source_dirty_patch_sha256=str(raw["source_dirty_patch_sha256"]),
        bootstrap_bin_sha256=str(raw["bootstrap_bin_sha256"]),
        source_dirty=source_dirty if isinstance(source_dirty, bool) else None,
        nodes=dict(nodes),
        ssh=dict(ssh),
        base_dir=base_dir,
        db=db,
        mysql_container=str(raw["mysql_container"]),
        redis_container=str(raw["redis_container"]),
        hmac_secret_file=hmac_secret_file,
        ports=dict(ports) if isinstance(ports, Mapping) else {},
        git_rev=git_rev,
        redis_port=redis_port,
        mysql_root=mysql_root,
        redis_password=redis_password,
    )


# ---------------------------------------------------------------------------
# Read-only guards and parsers.
# ---------------------------------------------------------------------------

_LINE_COMMENT_RE = re.compile(r"--[^\n]*|#[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _require_select_only(query: str) -> str:
    """Validate that ``query`` is a single SELECT statement; return it intact.

    Conservative by design (mirrors e3_e4.py): any statement separator beyond
    one trailing semicolon is rejected even inside string literals.
    """
    if not isinstance(query, str) or not query.strip():
        raise ValueError("SQL statement must be a non-empty string")
    stripped = _BLOCK_COMMENT_RE.sub(" ", _LINE_COMMENT_RE.sub(" ", query)).strip()
    if not stripped.upper().startswith("SELECT"):
        raise ValueError(
            "only single SELECT statements are permitted (read-only reconciliation contract)"
        )
    body = stripped[:-1] if stripped.endswith(";") else stripped
    if ";" in body:
        raise ValueError("multiple SQL statements are not permitted")
    upper_body = body.upper()
    if re.search(r"\bINTO\s+(?:OUTFILE|DUMPFILE)\b", upper_body):
        raise ValueError("SELECT INTO OUTFILE/DUMPFILE is not permitted")
    if re.search(r"\bFOR\s+(?:UPDATE|SHARE)\b|\bLOCK\s+IN\s+SHARE\s+MODE\b", upper_body):
        raise ValueError("locking SELECT statements are not permitted")
    if re.search(r"\b(?:GET_LOCK|RELEASE_LOCK)\s*\(", upper_body):
        raise ValueError("named-lock functions are not permitted")
    return query


def _parse_tsv(stdout: str) -> List[List[str]]:
    """Parse ``mysql -N`` TSV output, preserving empty cells.

    Rows are split on ``\\n`` after CRLF normalization and only truly empty
    lines are dropped, matching the frozen harness parser. Known limitation
    (same as the harness): a one-column row whose single cell is empty is
    indistinguishable from a blank line and is dropped.
    """
    normalized = stdout.replace("\r\n", "\n")
    return [line.split("\t") for line in normalized.split("\n") if line != ""]


def _aggregate_type(value: str) -> str:
    if not isinstance(value, str) or not _AGGREGATE_TYPE_RE.fullmatch(value):
        raise ValueError("aggregate_type must be an uppercase identifier (e.g. RULE_SET, CARD)")
    return value


def _aggregate_id(value: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > _MAX_SIGNED_I64
    ):
        raise ValueError("aggregate_id must be a positive signed 64-bit integer")
    return value


def _tenant_id(value: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > _MAX_SIGNED_I64
    ):
        raise ValueError("tenant_id must be a positive signed 64-bit integer")
    return value


def _operation_id(value: str) -> str:
    if not isinstance(value, str) or len(value) > 64 or not SAFE_ID.fullmatch(value):
        raise ValueError("operation_id must be a safe identifier of at most 64 characters")
    return value


# ---------------------------------------------------------------------------
# The adapter.
# ---------------------------------------------------------------------------


class NodeAdapter:
    """Read-only node adapter over injected command/HTTP transports.

    Construction performs no I/O and requires no external services. The
    constructor never touches ``subprocess``; that happens only when an
    explicit method is invoked and only through the injected runner.
    """

    def __init__(
        self,
        config: NodeAdapterConfig,
        *,
        actor: Optional[Actor] = None,
        runner: Optional[CommandRunner] = None,
        transport: Optional[HttpTransport] = None,
        clock: Optional[Callable[[], float]] = None,
        request_id_factory: Optional[Callable[[], str]] = None,
    ) -> None:
        if not isinstance(config, NodeAdapterConfig):
            raise TypeError("config must be a NodeAdapterConfig from load_config()")
        if actor is not None and not isinstance(actor, Actor):
            raise TypeError("actor must be an Actor (use Actor.from_mapping)")
        self._config = config
        self._actor = actor
        self._runner: CommandRunner = runner if runner is not None else SubprocessRunner()
        self._transport: HttpTransport = transport if transport is not None else UrllibHttpTransport()
        self._clock: Callable[[], float] = clock if clock is not None else time.time
        self._request_id_factory: Callable[[], str] = (
            request_id_factory if request_id_factory is not None else (lambda: str(uuid.uuid4()))
        )

    def __repr__(self) -> str:
        # Only public provenance metadata; never topology or secrets.
        return "NodeAdapter(config=%r)" % (self._config.public_metadata(),)

    # -- Gateway v3 signed headers -----------------------------------------

    def _load_hmac_secret(self) -> str:
        """Load the HMAC key lazily; used for signing only, never retained."""
        path = self._config.hmac_secret_file
        try:
            with open(os.path.expanduser(path), "r", encoding="utf-8") as handle:
                secret = handle.read().strip()
        except OSError as error:
            raise AdapterError("hmac_secret_unreadable", type(error).__name__) from error
        if not secret:
            raise AdapterError("hmac_secret_empty")
        return secret

    def sign_headers(
        self,
        actor: Actor,
        method: str,
        path: str,
        *,
        request_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """Canonical Gateway v3 signed header set (15-field HMAC-SHA256 payload).

        ``request_id`` may be pinned by the caller for stable correlation; the
        timestamp comes from the injected clock. The HMAC key is loaded from
        the configured secret file at call time, validated non-empty, used,
        and discarded (never stored on the adapter).
        """
        if not isinstance(actor, Actor):
            raise TypeError("actor must be an Actor")
        if not isinstance(method, str) or not _METHOD_RE.fullmatch(method.strip()):
            raise ValueError("method must be an alphabetic HTTP verb")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or any(char in path for char in " \t\r\n")
        ):
            raise ValueError("path must be an absolute path without whitespace")
        if request_id is None:
            request_id = self._request_id_factory()
        if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
            raise ValueError(
                "request_id must match the server operation-id alphabet and fit 64 bytes"
            )

        method_value = method.strip()
        timestamp_ms = str(int(self._clock() * 1000))
        payload = build_gateway_v3_payload(actor, method_value, path, timestamp_ms)
        secret = self._load_hmac_secret()
        signature = hmac.new(
            secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        del secret  # do not retain the key beyond this call
        return {
            "x-request-id": request_id,
            "x-user-id": actor.user_id,
            "x-principal-kind": PRINCIPAL_KIND_PLATFORM_USER,
            "x-identity-card-id": actor.identity_card,
            "x-user-card-id": actor.user_card,
            "x-user-card-domain-id": actor.domain,
            "x-user-card-tenant-id": actor.tenant,
            "x-gateway-ts": timestamp_ms,
            "x-gateway-signature": signature,
            "x-gateway-auth": GATEWAY_AUTH_VERIFIED,
            "Content-Type": "application/json",
        }

    # -- MySQL (SELECT-only) -------------------------------------------------

    def sql(self, query: str, *, timeout_s: float = 60.0) -> List[List[str]]:
        """Run one guarded SELECT through docker exec; parse TSV preserving empties.

        The password travels via stdin only (never argv, never the process
        environment, never the result). The fixed container-side script and
        positional argv design are documented in the module docstring.
        """
        query = _require_select_only(query)
        if self._config.mysql_root is None:
            raise AdapterError("mysql_root_missing")
        if not _CONTAINER_RE.fullmatch(self._config.mysql_container) or not _DB_NAME_RE.fullmatch(
            self._config.db
        ):
            raise AdapterError("invalid_sql_target")
        argv = [
            "docker",
            "exec",
            "-i",
            self._config.mysql_container,
            "sh",
            "-c",
            _MYSQL_STDIN_SCRIPT,
            "sh",
            self._config.db,
            query,
        ]
        result = self._runner.run(argv, stdin_text=self._config.mysql_root, timeout_s=float(timeout_s))
        if result.exit_code != 0:
            raise AdapterError("sql_failed", result.stderr[-300:], exit_code=result.exit_code)
        return _parse_tsv(result.stdout)

    # -- Redis (GET/LLEN/PING only) ------------------------------------------

    def redis(self, verb: str, *args: str, timeout_s: float = 30.0) -> str:
        """One read-only Redis command through the fixed stdin-auth pattern.

        The password travels via stdin only and never appears in argv or the
        result. Verbs outside ``GET``/``LLEN``/``PING`` are rejected before
        any command is built.
        """
        verb_value = str(verb).upper()
        if verb_value not in READONLY_REDIS_VERBS:
            raise ValueError(
                "redis verb %r is outside the read-only allowlist %s"
                % (str(verb)[:40], sorted(READONLY_REDIS_VERBS))
            )
        if verb_value == "PING":
            if args:
                raise ValueError("PING takes no arguments")
        else:
            if len(args) != 1:
                raise ValueError("%s requires exactly one key" % verb_value)
            key = args[0]
            if not isinstance(key, str) or not _REDIS_KEY_RE.fullmatch(key):
                raise ValueError("redis key must match the safe key alphabet")
        if self._config.redis_password is None:
            raise AdapterError("redis_password_missing")
        if not _CONTAINER_RE.fullmatch(self._config.redis_container):
            raise AdapterError("invalid_redis_target")
        argv = [
            "docker",
            "exec",
            "-i",
            self._config.redis_container,
            "sh",
            "-c",
            _REDIS_STDIN_SCRIPT,
            "sh",
            verb_value,
        ] + list(args)
        result = self._runner.run(argv, stdin_text=self._config.redis_password, timeout_s=float(timeout_s))
        if result.exit_code != 0:
            raise AdapterError("redis_failed", result.stderr[-300:], exit_code=result.exit_code)
        return result.stdout.strip()

    # -- Signed protected HTTP -----------------------------------------------

    def signed_request(
        self,
        node: str,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        actor: Optional[Actor] = None,
        *,
        request_id: Optional[str] = None,
        timeout_s: float = 30.0,
    ) -> Tuple[int, Dict[str, Any], str]:
        """Signed request against ``/main/api/v1/*`` on a node alias.

        Returns ``(http_status, parsed_json_object, request_id)``. Only the
        explicitly allowlisted verbs are accepted. Request bodies, when
        present, must be JSON objects and are serialized deterministically.
        This method performs the live side effect for POST/PUT/DELETE only when
        an explicit caller invokes it; construction and preflight remain inert.
        """
        if node not in NODE_ALIASES:
            raise ValueError("node must be one of %s" % (", ".join(NODE_ALIASES),))
        if not isinstance(method, str):
            raise TypeError("method must be a string")
        method_value = method.strip().upper()
        if method_value not in SIGNED_HTTP_METHODS:
            raise ValueError("method is outside the signed HTTP allowlist")
        if not isinstance(path, str) or not path.startswith(GATEWAY_PATH_PREFIX):
            raise ValueError("signed request path must start with %s" % GATEWAY_PATH_PREFIX)
        if any(char in path for char in " \t\r\n"):
            raise ValueError("signed request path must not contain whitespace")
        if method_value == "GET" and body is not None:
            raise ValueError("GET requests must not carry a body")
        if body is not None and not isinstance(body, Mapping):
            raise TypeError("request body must be a JSON object mapping or None")
        resolved_actor = actor if actor is not None else self._actor
        if resolved_actor is None:
            raise ValueError(
                "no actor available: pass actor or construct the adapter with a default actor"
            )
        headers = self.sign_headers(
            resolved_actor,
            method_value,
            path,
            request_id=request_id,
        )
        body_bytes = (
            json.dumps(
                dict(body),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if body is not None
            else None
        )
        url = self._config.nodes[node] + path
        status, body_text = self._transport.request(
            method_value,
            url,
            headers,
            body_bytes,
            float(timeout_s),
        )
        try:
            parsed = json.loads(body_text)
        except ValueError as error:
            raise ValueError("signed response is not valid JSON") from error
        if not isinstance(parsed, dict):
            raise ValueError("signed response is not a JSON object")
        return int(status), parsed, headers["x-request-id"]

    def signed_get(
        self,
        node: str,
        path: str,
        actor: Optional[Actor] = None,
        *,
        request_id: Optional[str] = None,
        timeout_s: float = 30.0,
    ) -> Tuple[int, Dict[str, Any], str]:
        """Compatibility wrapper for one signed read-only GET."""
        return self.signed_request(
            node,
            "GET",
            path,
            None,
            actor,
            request_id=request_id,
            timeout_s=timeout_s,
        )

    # -- Node log slice (read-only) --------------------------------------------

    def _remote_base_arg(self) -> str:
        """Remote base_dir argument for the fixed remote command.

        ``base_dir`` is validated to safe path characters only, so the
        remainder may safely sit next to an explicitly double-quoted
        ``$HOME`` (expanded by the remote login shell) or inside single
        quotes. No other interpolation ever happens.
        """
        base_dir = self._config.base_dir
        if base_dir.startswith("~"):
            return '"$HOME"' + base_dir[1:]
        return "'" + base_dir + "'"

    def read_log_lines(
        self, node: str, identifiers: Sequence[str], *, timeout_s: float = 120.0
    ) -> List[str]:
        """Raw server-log lines matching safe request/operation identifiers.

        ``node-b`` runs locally with direct argv; ``node-a``/``node-c`` run
        through SSH with BatchMode and fixed options. The fixed Python script
        is delivered via stdin; argv carries only the base directory, the
        fixed log file name, and a base64-encoded JSON identifier list, so no
        shell injection is possible. Identifiers must match the safe
        identifier alphabet; an empty identifier list returns ``[]`` without
        running any command. Only selected raw lines are returned -- no host
        targets or other metadata.
        """
        if node not in NODE_ALIASES:
            raise ValueError("node must be one of %s" % (", ".join(NODE_ALIASES),))
        if isinstance(identifiers, (str, bytes)):
            raise TypeError("identifiers must be a sequence of identifier strings")
        cleaned: List[str] = []
        for item in identifiers:
            if not isinstance(item, str) or not SAFE_ID.fullmatch(item):
                raise ValueError("log identifier must match the safe identifier alphabet")
            if item not in cleaned:
                cleaned.append(item)
        if not cleaned:
            return []
        payload = base64.b64encode(
            json.dumps(cleaned, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        name = LOG_FILE_BY_NODE[node]
        if node == "node-b":
            base = os.path.expanduser(self._config.base_dir)
            argv: List[str] = ["python3", "-", base, name, payload]
        else:
            remote = (
                "python3 - "
                + self._remote_base_arg()
                + " "
                + shlex.quote(name)
                + " "
                + shlex.quote(payload)
            )
            argv = [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                self._config.ssh[node],
                remote,
            ]
        result = self._runner.run(argv, stdin_text=_LOG_GREP_SCRIPT, timeout_s=float(timeout_s))
        if result.exit_code != 0:
            raise AdapterError("log_slice_failed", result.stderr[-300:], exit_code=result.exit_code)
        return result.stdout.splitlines()

    # -- Durable SELECT reconciliation helpers (sql only; no writes) -----------

    def head_state(self, aggregate_type: str, aggregate_id: int) -> List[List[str]]:
        """RULE_SET/CARD projection head rows (read-only SELECT via :meth:`sql`).

        2026-10 架构标注:DIAGNOSTIC-ONLY。canonical 发布证明以
        authorization_delta_event / authorization_projection_current 为准
        (e1_runner.projection_snapshot 即走该路径);legacy head 行不得作为
        发布证明引用(VALIDATION_PROTOCOL 全局规则)。
        """
        query = (
            "SELECT aggregate_type, aggregate_id, source_generation, revoke_fence "
            "FROM authorization_projection_head "
            "WHERE aggregate_type='%s' AND aggregate_id=%d"
            % (_aggregate_type(aggregate_type), _aggregate_id(aggregate_id))
        )
        return self.sql(query)

    def delta_states(
        self, tenant_id: int, aggregate_type: str, aggregate_id: int
    ) -> List[List[str]]:
        """Delta event (status, target_version) rows for one canonical
        ``(tenant_id, aggregate_type, aggregate_id)`` identity (read-only
        SELECT via :meth:`sql`)."""
        query = (
            "SELECT status, target_version FROM authorization_delta_event "
            "WHERE tenant_id=%d AND aggregate_type='%s' AND aggregate_id=%d "
            "ORDER BY target_version"
            % (
                _tenant_id(tenant_id),
                _aggregate_type(aggregate_type),
                _aggregate_id(aggregate_id),
            )
        )
        return self.sql(query)

    def delta_rows_for_operation(
        self, tenant_id: int, aggregate_type: str, aggregate_id: int, operation_id: str
    ) -> List[List[str]]:
        """Operation-attributed delta rows for one canonical aggregate.

        The result contains ``event_id, event_type, status, target_version,
        card_id`` and is SELECT-only. Callers must still validate row
        cardinality and all returned values before treating it as durable proof.
        """
        query = (
            "SELECT event_id, event_type, status, target_version, IFNULL(card_id,0) "
            "FROM authorization_delta_event "
            "WHERE tenant_id=%d AND aggregate_type='%s' AND aggregate_id=%d "
            "AND operation_id='%s' ORDER BY event_id"
            % (
                _tenant_id(tenant_id),
                _aggregate_type(aggregate_type),
                _aggregate_id(aggregate_id),
                _operation_id(operation_id),
            )
        )
        return self.sql(query)

    def outbox_rows(self, aggregate_type: str, aggregate_id: int) -> List[List[str]]:
        """Projection outbox rows for one aggregate (read-only SELECT via :meth:`sql`).

        2026-10 架构标注:DIAGNOSTIC-ONLY。outbox 行是写入侧关联/恢复日志,
        不是发布完成证明;当前发布证明见 canonical delta/current 读面。
        """
        query = (
            "SELECT outbox_id, source_generation, status, IFNULL(lease_owner,''), "
            "terminal_transitions, IFNULL(processed_by,''), IFNULL(attempts,0) "
            "FROM authorization_projection_outbox "
            "WHERE aggregate_type='%s' AND aggregate_id=%d ORDER BY outbox_id"
            % (_aggregate_type(aggregate_type), _aggregate_id(aggregate_id))
        )
        return self.sql(query)

    def projection_pointer(
        self, tenant_id: int, aggregate_type: str, aggregate_id: int
    ) -> List[List[str]]:
        """Read-gate pointer rows for one canonical
        ``(tenant_id, aggregate_type, aggregate_id)`` identity (read-only
        SELECT via :meth:`sql`)."""
        query = (
            "SELECT current_generation, status, revoke_fence, cas_version, "
            "event_id, operation_id, IFNULL(card_id,0) "
            "FROM authorization_projection_current "
            "WHERE tenant_id=%d AND aggregate_type='%s' AND aggregate_id=%d"
            % (
                _tenant_id(tenant_id),
                _aggregate_type(aggregate_type),
                _aggregate_id(aggregate_id),
            )
        )
        return self.sql(query)


class RoleActorProbe:
    """Actor-aware read-only probe view for E3 target/unrelated/cold samples.

    SQL/Redis reads use one shared adapter. Signed GETs use explicit per-role
    actors, and the requested sample card must equal the actor card in the
    signature. Query-only card changes can therefore never masquerade as three
    distinct authorization principals.
    """

    _ROLES = frozenset({"target", "unrelated", "cold"})

    def __init__(
        self,
        shared: NodeAdapter,
        adapters: Mapping[str, NodeAdapter],
        actors: Mapping[str, Actor],
    ) -> None:
        if not isinstance(shared, NodeAdapter):
            raise TypeError("shared must be a NodeAdapter")
        if set(adapters) != self._ROLES or set(actors) != self._ROLES:
            raise ValueError("role mappings must contain target, unrelated, and cold")
        for role in sorted(self._ROLES):
            if not isinstance(adapters[role], NodeAdapter):
                raise TypeError("every role adapter must be a NodeAdapter")
            if not isinstance(actors[role], Actor):
                raise TypeError("every role actor must be an Actor")
        self._shared = shared
        self._adapters = types.MappingProxyType(dict(adapters))
        self._actors = types.MappingProxyType(dict(actors))

    def sql(self, query: str) -> List[List[str]]:
        return self._shared.sql(query)

    def redis(self, verb: str, *args: str) -> str:
        return self._shared.redis(verb, *args)

    def signed_get(
        self,
        node: str,
        path: str,
    ) -> Tuple[int, Dict[str, Any], str]:
        actor = self._actors["target"]
        return self._adapters["target"].signed_get(node, path, actor=actor)

    def signed_get_for_role(
        self,
        role: str,
        card: str,
        node: str,
        path: str,
    ) -> Tuple[int, Dict[str, Any], str]:
        if role not in self._ROLES:
            raise ValueError("unknown decision role")
        actor = self._actors[role]
        if str(card) != actor.user_card:
            raise ValueError("sample card does not match the role actor signature")
        return self._adapters[role].signed_get(node, path, actor=actor)
