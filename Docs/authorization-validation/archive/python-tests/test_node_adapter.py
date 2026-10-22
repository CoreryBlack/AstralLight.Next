#!/usr/bin/env python3
"""Offline unit tests for node_adapter.py (Exec-L1; no services touched).

These tests use ONLY:

- an injected fake CommandRunner (records argv/stdin/timeout, returns canned
  CommandResult values),
- an injected fake HttpTransport,
- temporary files (for the HMAC secret fixture).

They never start services or containers, never open sockets, and never touch SSH,
MySQL, or Redis. The one exception is ``LogGrepScriptLiveTest``, which executes
``_LOG_GREP_SCRIPT`` through the local ``sys.executable`` against a temporary
log file; it uses no network or external service. The import-safety test
executes a freshly compiled node_adapter module body under audited I/O
primitives (all stdlib dependencies pre-warmed in sys.modules) to prove that
importing node_adapter performs zero file/env/network/subprocess I/O.

Run:  python -m unittest discover -s Docs/authorization-validation/tools
      -t Docs/authorization-validation/tools -p "test_node_adapter.py" -v
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses  # noqa: F401  (pre-warm for the audited import)
import hashlib
import hmac as hmac_module
import json
import os
import shlex
import socket  # noqa: F401  (pre-warm for the audited import)
import subprocess  # noqa: F401  (pre-warm for the audited import)
import sys
import tempfile
import time  # noqa: F401  (pre-warm for the audited import)
import types
import unittest
import urllib.error  # noqa: F401  (pre-warm for the audited import)
import urllib.request  # noqa: F401  (pre-warm for the audited import)
import uuid
from typing import Any, Dict, List, Mapping, Sequence, Tuple
from unittest import mock

_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

# Pre-import experiment_common so the audited import executes only
# node_adapter module code (every stdlib dependency is already cached).
import experiment_common  # noqa: E402

MYSQL_ROOT_SENTINEL = "mysql-root-secret-xyzzy"
REDIS_PASSWORD_SENTINEL = "redis-pass-secret-abcdef"
HMAC_SECRET_SENTINEL = "unit-test-hmac-secret-0123456789abcdef"

SECRET_SENTINELS = (MYSQL_ROOT_SENTINEL, REDIS_PASSWORD_SENTINEL, HMAC_SECRET_SENTINEL)
PRIVATE_SENTINELS = SECRET_SENTINELS + (
    "http://node-a.example.invalid:8081",
    "http://127.0.0.1:8082",
    "http://node-c.example.invalid:8083",
    "ops@node-a.example.invalid",
    "ops@node-c.example.invalid",
    "~/authz-validation-20260919-single-node-002",
    "astral_bench",
    "/run/secrets/hmac.txt",
    "8081",
    "8082",
    "8083",
)


def _load():
    import node_adapter

    return node_adapter


def _raw_config(**overrides: Any) -> Dict[str, Any]:
    raw: Dict[str, Any] = {
        "run_id": "authz-validation-20260919-single-node-002",
        "nodes": {
            "node-a": "http://node-a.example.invalid:8081",
            "node-b": "http://127.0.0.1:8082",
            "node-c": "http://node-c.example.invalid:8083",
        },
        "ssh": {"node-a": "ops@node-a.example.invalid", "node-c": "ops@node-c.example.invalid"},
        "base_dir": "~/authz-validation-20260919-single-node-002",
        "db": "astral_bench",
        "mysql_container": "astral_bench_mysql",
        "redis_container": "astral_bench_redis",
        "hmac_secret_file": "/run/secrets/hmac.txt",
        "mysql_root": MYSQL_ROOT_SENTINEL,
        "redis_password": REDIS_PASSWORD_SENTINEL,
        "binary_sha256": "a" * 64,
        "source_snapshot_sha256": "b" * 64,
        "source_git_rev": "c" * 40,
        "source_dirty_patch_sha256": "d" * 64,
        "bootstrap_bin_sha256": "e" * 64,
        "source_dirty": True,
        "git_rev": "f" * 40,
        "ports": {"node-a": 8081, "node-b": 8082, "node-c": 8083},
    }
    raw.update(overrides)
    return raw


def _actor(node_adapter_module):
    return node_adapter_module.Actor.from_mapping(
        {"user_id": "9031", "icard": "9041", "card": "9061", "domain": "9011", "tenant": "9001"}
    )


class FakeRunner:
    """Injected CommandRunner fake: records calls, returns canned results."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self._queued: List[Tuple[int, str, str]] = []

    def queue(self, exit_code: int = 0, stdout: str = "", stderr: str = "") -> None:
        self._queued.append((exit_code, stdout, stderr))

    def run(self, argv: Sequence[str], *, stdin_text: str = "", timeout_s: float = 60.0) -> Any:
        node_adapter = _load()
        self.calls.append(
            {"argv": tuple(str(part) for part in argv), "stdin": stdin_text, "timeout_s": timeout_s}
        )
        if self._queued:
            exit_code, stdout, stderr = self._queued.pop(0)
        else:
            exit_code, stdout, stderr = 0, "", ""
        return node_adapter.CommandResult(
            argv=tuple(str(part) for part in argv),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )


class FakeTransport:
    """Injected HttpTransport fake: records calls, returns canned responses."""

    def __init__(self, status: int = 200, body: str = '{"code":0,"data":{"allowed":true}}') -> None:
        self.calls: List[Dict[str, Any]] = []
        self.status = status
        self.body = body

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: Optional[bytes],
        timeout_s: float,
    ) -> Tuple[int, str]:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_s": timeout_s,
            }
        )
        return self.status, self.body


def _adapter_with_secret_file(node_adapter_module, runner=None, transport=None, **overrides):
    directory = tempfile.mkdtemp(prefix="node_adapter_test_")
    secret_path = os.path.join(directory, "hmac.txt")
    with open(secret_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(HMAC_SECRET_SENTINEL + "\n")
    raw = _raw_config(hmac_secret_file=secret_path, **overrides)
    config = node_adapter_module.load_config(raw)
    adapter = node_adapter_module.NodeAdapter(
        config,
        actor=_actor(node_adapter_module),
        runner=runner if runner is not None else FakeRunner(),
        transport=transport if transport is not None else FakeTransport(),
        clock=lambda: 1700000000.0,
        request_id_factory=lambda: "generated-req-id",
    )
    return adapter, config, directory


def _cleanup(directory: str) -> None:
    for name in os.listdir(directory):
        os.unlink(os.path.join(directory, name))
    os.rmdir(directory)


def _assert_no_private_sentinels(testcase, text: str, context: str) -> None:
    for sentinel in PRIVATE_SENTINELS:
        testcase.assertNotIn(
            sentinel, text, "private value %r leaked into %s" % (sentinel, context)
        )


# ---------------------------------------------------------------------------
# Import safety.
# ---------------------------------------------------------------------------


class _ForbiddenEnviron:
    """Stand-in for os.environ that records and rejects every access."""

    def __init__(self, events: List[str]) -> None:
        self._events = events

    def _hit(self, op: str, key: Any) -> None:
        self._events.append("os.environ.%s(%r)" % (op, key))
        raise AssertionError("os.environ touched during node_adapter import: %s %r" % (op, key))

    def __getitem__(self, key: Any) -> Any:
        self._hit("getitem", key)

    def __contains__(self, key: Any) -> bool:
        self._hit("contains", key)

    def get(self, key: Any, default: Any = None) -> Any:
        self._hit("get", key)

    def keys(self) -> Any:
        self._hit("keys", None)

    def items(self) -> Any:
        self._hit("items", None)

    def values(self) -> Any:
        self._hit("values", None)

    def __iter__(self) -> Any:
        self._hit("iter", None)


class ImportSafetyTest(unittest.TestCase):
    _AUDIT_PATCH_TARGETS = (
        "builtins.open",
        "os.getenv",
        "os.open",
        "os.listdir",
        "os.scandir",
        "os.stat",
        "os.getcwd",
        "os.mkdir",
        "os.makedirs",
        "os.remove",
        "os.unlink",
        "os.replace",
        "os.rename",
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "socket.socket",
        "socket.create_connection",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "urllib.request.urlopen",
    )

    def test_import_requires_no_config_and_performs_no_io(self):
        # Read and compile the source BEFORE the audit window (the test itself
        # may do I/O; the audited claim is about the module import executing).
        source_path = os.path.join(_TOOLS_DIR, "node_adapter.py")
        with open(source_path, "r", encoding="utf-8") as handle:
            compiled = compile(handle.read(), source_path, "exec")
        module = types.ModuleType("node_adapter")
        module.__file__ = source_path
        events: List[str] = []
        named: Dict[str, Any] = {}
        with contextlib.ExitStack() as stack:
            for target in self._AUDIT_PATCH_TARGETS:
                mocked = stack.enter_context(mock.patch(target))
                mocked.side_effect = AssertionError(
                    "forbidden I/O primitive fired during node_adapter import: %s" % target
                )
                named[target] = mocked
            stack.enter_context(mock.patch("os.environ", new=_ForbiddenEnviron(events)))
            # Every stdlib import in the module body is already in sys.modules
            # (pre-warmed at test-module import), so the module body below is
            # the ONLY code that executes. It must run with all I/O primitives
            # disabled; any file/env/network/subprocess access fails loudly.
            exec(compiled, module.__dict__)  # noqa: S102 - audited module import
            sys.modules["node_adapter"] = module
        self.assertEqual(events, [], "os.environ was touched during import")
        for target, mocked in named.items():
            self.assertEqual(mocked.call_count, 0, "%s fired during import" % target)
        self.assertIn("node_adapter", sys.modules)
        loaded = _load()
        self.assertTrue(hasattr(loaded, "NodeAdapter"))
        self.assertTrue(hasattr(loaded, "load_config"))

    def test_construction_performs_no_io_before_methods(self):
        node_adapter = _load()
        runner = FakeRunner()
        config = node_adapter.load_config(_raw_config())
        node_adapter.NodeAdapter(config, runner=runner, transport=FakeTransport())
        self.assertEqual(runner.calls, [])


# ---------------------------------------------------------------------------
# Configuration loader.
# ---------------------------------------------------------------------------


class ConfigLoaderTest(unittest.TestCase):
    def test_valid_flat_run_config_mapping_loads(self):
        node_adapter = _load()
        raw = _raw_config()
        config = node_adapter.load_config(raw)
        self.assertEqual(config.run_id, "authz-validation-20260919-single-node-002")
        self.assertEqual(config.db, "astral_bench")
        self.assertEqual(sorted(config.nodes), ["node-a", "node-b", "node-c"])
        self.assertEqual(config.mysql_root, MYSQL_ROOT_SENTINEL)
        self.assertEqual(config.redis_password, REDIS_PASSWORD_SENTINEL)

    def test_public_metadata_matches_experiment_common(self):
        node_adapter = _load()
        raw = _raw_config()
        config = node_adapter.load_config(raw)
        self.assertEqual(config.public_metadata(), experiment_common.public_provenance(raw))
        self.assertEqual(
            config.public_metadata(),
            {
                "runId": "authz-validation-20260919-single-node-002",
                "binarySha256": "a" * 64,
                "sourceSnapshotSha256": "b" * 64,
                "sourceGitRev": "c" * 40,
                "sourceDirty": True,
                "sourceDirtyPatchSha256": "d" * 64,
                "bootstrapBinSha256": "e" * 64,
                "nodeLabels": ["node-a", "node-b", "node-c"],
            },
        )

    def test_repr_and_str_keep_all_private_values_hidden(self):
        node_adapter = _load()
        config = node_adapter.load_config(_raw_config())
        for text, context in ((repr(config), "repr"), (str(config), "str")):
            self.assertIn("authz-validation-20260919-single-node-002", text)
            _assert_no_private_sentinels(self, text, "config %s" % context)

    def test_public_metadata_never_leaks_private_values(self):
        node_adapter = _load()
        config = node_adapter.load_config(_raw_config())

        def walk(value: Any, context: str) -> None:
            if isinstance(value, str):
                _assert_no_private_sentinels(self, value, context)
            elif isinstance(value, dict):
                for key, item in value.items():
                    _assert_no_private_sentinels(self, str(key), context + " key")
                    walk(item, context)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    walk(item, context)

        walk(config.public_metadata(), "public_metadata")

    def test_missing_and_malformed_fields_rejected(self):
        node_adapter = _load()
        cases = [
            ({key: value for key, value in _raw_config().items() if key != "db"}, "missing:db"),
            (_raw_config(run_id="../escape"), "invalid:run_id"),
            (_raw_config(binary_sha256="short"), "invalid:binary_sha256"),
            (_raw_config(source_git_rev="nothex"), "invalid:source_git_rev"),
            (_raw_config(nodes={"node-a": "http://x", "node-b": "http://y"}), "invalid:nodes"),
            (
                _raw_config(
                    nodes={"node-a": "ftp://h:1", "node-b": "http://b", "node-c": "http://c"}
                ),
                "invalid:nodes",
            ),
            (
                _raw_config(
                    nodes={
                        "node-a": "http://node-a.invalid:8081/",
                        "node-b": "http://node-b.invalid:8082",
                        "node-c": "http://node-c.invalid:8083",
                    }
                ),
                "invalid:nodes",
            ),
            (_raw_config(ssh={"node-a": "ops@h"}), "invalid:ssh"),
            (_raw_config(base_dir="../evil"), "invalid:base_dir"),
            (_raw_config(base_dir="has space"), "invalid:base_dir"),
            (_raw_config(db="bad-db"), "invalid:db"),
            (_raw_config(mysql_container="bad container"), "invalid:mysql_container"),
            (_raw_config(redis_container=""), "invalid:redis_container"),
            (_raw_config(hmac_secret_file=""), "invalid:hmac_secret_file"),
            (_raw_config(hmac_secret_file="has space"), "invalid:hmac_secret_file"),
            (_raw_config(mysql_root=""), "invalid:mysql_root"),
            (_raw_config(redis_password=""), "invalid:redis_password"),
            (_raw_config(git_rev="xyz"), "invalid:git_rev"),
            (_raw_config(ports={"node-a": 1, "node-b": 2}), "invalid:ports"),
            (_raw_config(ports={"node-a": True, "node-b": 2, "node-c": 3}), "invalid:ports"),
        ]
        for raw, expected_problem in cases:
            with self.assertRaises(node_adapter.ConfigError) as caught:
                node_adapter.load_config(raw)
            self.assertIn(
                expected_problem,
                caught.exception.problems,
                "expected %s in %r" % (expected_problem, caught.exception.problems),
            )
            _assert_no_private_sentinels(self, str(caught.exception), "config error message")

    def test_non_mapping_rejected(self):
        node_adapter = _load()
        with self.assertRaises(node_adapter.ConfigError):
            node_adapter.load_config("not-a-mapping")  # type: ignore[arg-type]

    def test_ports_and_mappings_are_read_only_views(self):
        node_adapter = _load()
        config = node_adapter.load_config(_raw_config())
        with self.assertRaises(TypeError):
            config.nodes["node-a"] = "http://evil"  # type: ignore[index]
        with self.assertRaises(TypeError):
            config.ports["node-a"] = 1  # type: ignore[index]


# ---------------------------------------------------------------------------
# Gateway v3 signing (exact vector and field order).
# ---------------------------------------------------------------------------

EXPECTED_PAYLOAD_FIELDS = [
    "astral-gateway-v3",
    "GET",
    "/main/api/v1/simulation/evaluate",
    "9031",
    "PLATFORM_USER",
    "",
    "9041",
    "9061",
    "9011",
    "9001",
    "",
    "",
    "",
    "",
    "1700000000000",
]

EXPECTED_HEADER_KEYS = {
    "x-request-id",
    "x-user-id",
    "x-principal-kind",
    "x-identity-card-id",
    "x-user-card-id",
    "x-user-card-domain-id",
    "x-user-card-tenant-id",
    "x-gateway-ts",
    "x-gateway-signature",
    "x-gateway-auth",
    "Content-Type",
}


class SignHeadersTest(unittest.TestCase):
    def _adapter(self):
        return _adapter_with_secret_file(_load())

    def test_payload_field_order_exact(self):
        node_adapter = _load()
        actor = _actor(node_adapter)
        payload = node_adapter.build_gateway_v3_payload(
            actor, "GET", "/main/api/v1/simulation/evaluate?card=9061", "1700000000000"
        )
        self.assertEqual(payload.split("\n"), EXPECTED_PAYLOAD_FIELDS)
        self.assertEqual(len(payload.split("\n")), 15)

    def test_exact_hmac_vector_and_header_set(self):
        node_adapter = _load()
        adapter, _config, directory = self._adapter()
        try:
            headers = adapter.sign_headers(
                _actor(node_adapter),
                "GET",
                "/main/api/v1/simulation/evaluate?card=9061",
                request_id="req-fixed-1",
            )
            expected_signature = hmac_module.new(
                HMAC_SECRET_SENTINEL.encode("utf-8"),
                "\n".join(EXPECTED_PAYLOAD_FIELDS).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            self.assertEqual(set(headers), EXPECTED_HEADER_KEYS)
            self.assertEqual(
                headers,
                {
                    "x-request-id": "req-fixed-1",
                    "x-user-id": "9031",
                    "x-principal-kind": "PLATFORM_USER",
                    "x-identity-card-id": "9041",
                    "x-user-card-id": "9061",
                    "x-user-card-domain-id": "9011",
                    "x-user-card-tenant-id": "9001",
                    "x-gateway-ts": "1700000000000",
                    "x-gateway-signature": expected_signature,
                    "x-gateway-auth": "verified",
                    "Content-Type": "application/json",
                },
            )
            self.assertNotIn(HMAC_SECRET_SENTINEL, json.dumps(headers))
        finally:
            _cleanup(directory)

    def test_field_order_is_load_bearing(self):
        node_adapter = _load()
        actor = _actor(node_adapter)
        payload = node_adapter.build_gateway_v3_payload(
            actor, "GET", "/main/api/v1/simulation/evaluate", "1700000000000"
        )
        swapped = "\n".join(
            [
                "astral-gateway-v3",
                "GET",
                "/main/api/v1/simulation/evaluate",
                "9031",
                "PLATFORM_USER",
                "",
                "9061",
                "9041",
                "9011",
                "9001",
                "",
                "",
                "",
                "",
                "1700000000000",
            ]
        )
        self.assertNotEqual(payload, swapped)
        key = HMAC_SECRET_SENTINEL.encode("utf-8")
        self.assertNotEqual(
            hmac_module.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest(),
            hmac_module.new(key, swapped.encode("utf-8"), hashlib.sha256).hexdigest(),
        )

    def test_actor_aliases_and_rejection(self):
        node_adapter = _load()
        actor = node_adapter.Actor.from_mapping(
            {"user_id": "1", "identity_card": "2", "user_card": "3", "domain": "4", "tenant": "5"}
        )
        self.assertEqual(
            (actor.user_id, actor.identity_card, actor.user_card, actor.domain, actor.tenant),
            ("1", "2", "3", "4", "5"),
        )
        with self.assertRaises(ValueError):
            node_adapter.Actor.from_mapping({"user_id": "1", "icard": "2", "card": "3"})
        with self.assertRaises(TypeError):
            node_adapter.Actor.from_mapping("nope")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            node_adapter.Actor(
                user_id="9\n031", identity_card="2", user_card="3", domain="4", tenant="5"
            )
        with self.assertRaises(ValueError):
            node_adapter.Actor(
                user_id="", identity_card="2", user_card="3", domain="4", tenant="5"
            )

    def test_invalid_method_path_and_request_id_rejected(self):
        node_adapter = _load()
        adapter, _config, directory = self._adapter()
        try:
            actor = _actor(node_adapter)
            with self.assertRaises(ValueError):
                adapter.sign_headers(actor, "GE T", "/main/api/v1/x")
            with self.assertRaises(ValueError):
                adapter.sign_headers(actor, "", "/main/api/v1/x")
            with self.assertRaises(ValueError):
                adapter.sign_headers(actor, "GET", "main/api/v1/x")
            with self.assertRaises(ValueError):
                adapter.sign_headers(actor, "GET", "/main/api/v1/x\ninjected: 1")
            with self.assertRaises(ValueError):
                adapter.sign_headers(actor, "GET", "/main/api/v1/x", request_id="bad id")
            with self.assertRaises(ValueError):
                adapter.sign_headers(actor, "GET", "/main/api/v1/x", request_id="x" * 65)
            headers = adapter.sign_headers(
                actor,
                "GET",
                "/main/api/v1/x",
                request_id="x" * 64,
            )
            self.assertEqual(headers["x-request-id"], "x" * 64)
        finally:
            _cleanup(directory)

    def test_hmac_secret_loaded_lazily_and_validated(self):
        node_adapter = _load()
        runner = FakeRunner()
        config = node_adapter.load_config(_raw_config(hmac_secret_file="/nonexistent/hmac.txt"))
        adapter = node_adapter.NodeAdapter(
            config,
            actor=_actor(node_adapter),
            runner=runner,
            transport=FakeTransport(),
            clock=lambda: 1700000000.0,
        )
        # A non-signed method runs without touching the (missing) secret file.
        runner.queue(stdout="1\tREADY\n")
        self.assertEqual(adapter.sql("SELECT 1"), [["1", "READY"]])
        self.assertEqual(len(runner.calls), 1)
        # A signed request is the only thing that loads the secret.
        with self.assertRaises(node_adapter.AdapterError) as caught:
            adapter.sign_headers(_actor(node_adapter), "GET", "/main/api/v1/x")
        self.assertEqual(caught.exception.kind, "hmac_secret_unreadable")

        empty_directory = tempfile.mkdtemp(prefix="node_adapter_test_")
        try:
            empty_path = os.path.join(empty_directory, "empty.txt")
            with open(empty_path, "w", encoding="utf-8") as handle:
                handle.write("   \n")
            config_empty = node_adapter.load_config(_raw_config(hmac_secret_file=empty_path))
            adapter_empty = node_adapter.NodeAdapter(
                config_empty,
                actor=_actor(node_adapter),
                runner=FakeRunner(),
                transport=FakeTransport(),
            )
            with self.assertRaises(node_adapter.AdapterError) as caught:
                adapter_empty.sign_headers(_actor(node_adapter), "GET", "/main/api/v1/x")
            self.assertEqual(caught.exception.kind, "hmac_secret_empty")
        finally:
            _cleanup(empty_directory)

    def test_secret_not_retained_on_adapter(self):
        node_adapter = _load()
        adapter, _config, directory = self._adapter()
        try:
            adapter.sign_headers(
                _actor(node_adapter), "GET", "/main/api/v1/x", request_id="req-1"
            )
            state_text = repr(adapter.__dict__)
            self.assertNotIn(HMAC_SECRET_SENTINEL, state_text)
            _assert_no_private_sentinels(self, repr(adapter), "adapter repr")
        finally:
            _cleanup(directory)


# ---------------------------------------------------------------------------
# MySQL SELECT-only path.
# ---------------------------------------------------------------------------


class SqlTest(unittest.TestCase):
    def _adapter(self, runner=None):
        node_adapter = _load()
        return node_adapter.NodeAdapter(
            node_adapter.load_config(_raw_config()),
            runner=runner if runner is not None else FakeRunner(),
            transport=FakeTransport(),
        )

    def test_fixed_argv_stdin_and_tsv_parse(self):
        node_adapter = _load()
        runner = FakeRunner()
        adapter = self._adapter(runner)
        runner.queue(stdout="a\t\tb\nc\tval\n")
        rows = adapter.sql("SELECT col_a, col_b, col_c FROM t")
        self.assertEqual(rows, [["a", "", "b"], ["c", "val"]])
        call = runner.calls[0]
        self.assertEqual(
            call["argv"],
            (
                "docker",
                "exec",
                "-i",
                "astral_bench_mysql",
                "sh",
                "-c",
                node_adapter._MYSQL_STDIN_SCRIPT,
                "sh",
                "astral_bench",
                "SELECT col_a, col_b, col_c FROM t",
            ),
        )
        self.assertEqual(call["stdin"], MYSQL_ROOT_SENTINEL)
        self.assertEqual(call["timeout_s"], 60.0)
        for part in call["argv"]:
            self.assertNotIn(MYSQL_ROOT_SENTINEL, part)

    def test_fixed_script_literal_shape(self):
        node_adapter = _load()
        self.assertEqual(
            node_adapter._MYSQL_STDIN_SCRIPT,
            'MYSQL_PWD="$(cat)" exec mysql -uroot -N -e "$2" "$1"',
        )
        self.assertIn("$(cat)", node_adapter._MYSQL_STDIN_SCRIPT)
        self.assertEqual(
            node_adapter._REDIS_STDIN_SCRIPT,
            'REDISCLI_AUTH="$(cat)" exec redis-cli "$@"',
        )
        self.assertIn('"$@"', node_adapter._REDIS_STDIN_SCRIPT)

    def test_select_only_guard(self):
        runner = FakeRunner()
        adapter = self._adapter(runner)
        rejected = [
            "UPDATE t SET a=1",
            "INSERT INTO t VALUES (1)",
            "DELETE FROM t",
            "DROP TABLE t",
            "SELECT 1; DROP TABLE t",
            "SELECT 1; SELECT 2",
            "SELECT * FROM t WHERE c=';'",
            "WITH cte AS (SELECT 1) SELECT * FROM cte",
            "SELECT 1 INTO OUTFILE '/tmp/x'",
            "SELECT 1 INTO DUMPFILE '/tmp/x'",
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t FOR SHARE",
            "SELECT * FROM t LOCK IN SHARE MODE",
            "SELECT GET_LOCK('e1', 1)",
            "SELECT RELEASE_LOCK('e1')",
            "",
            "   ",
        ]
        for query in rejected:
            with self.assertRaises(ValueError, msg=query):
                adapter.sql(query)
        self.assertEqual(runner.calls, [])
        # Allowed forms: plain SELECT, comments, one trailing semicolon.
        runner.queue(stdout="1\n")
        adapter.sql("  select 1  ")
        runner.queue(stdout="2\n")
        adapter.sql("/* hint */ SELECT 2 -- trailing")
        runner.queue(stdout="3\n")
        adapter.sql("SELECT 3;")
        self.assertEqual(len(runner.calls), 3)

    def test_sql_failure_raises_scrubbed_error(self):
        node_adapter = _load()
        runner = FakeRunner()
        adapter = self._adapter(runner)
        runner.queue(exit_code=1, stderr="ERROR at http://db.example.invalid:3306/secret")
        with self.assertRaises(node_adapter.AdapterError) as caught:
            adapter.sql("SELECT 1")
        self.assertEqual(caught.exception.kind, "sql_failed")
        self.assertEqual(caught.exception.exit_code, 1)
        self.assertNotIn("db.example.invalid", str(caught.exception))
        self.assertIn("[redacted-host]", str(caught.exception))
        self.assertNotIn(MYSQL_ROOT_SENTINEL, str(caught.exception))

    def test_missing_mysql_root_fails_closed_before_runner(self):
        node_adapter = _load()
        runner = FakeRunner()
        raw = _raw_config()
        del raw["mysql_root"]
        adapter = node_adapter.NodeAdapter(
            node_adapter.load_config(raw), runner=runner, transport=FakeTransport()
        )
        with self.assertRaises(node_adapter.AdapterError) as caught:
            adapter.sql("SELECT 1")
        self.assertEqual(caught.exception.kind, "mysql_root_missing")
        self.assertEqual(runner.calls, [])


# ---------------------------------------------------------------------------
# Redis read-only path.
# ---------------------------------------------------------------------------


class RedisTest(unittest.TestCase):
    def _adapter(self, runner=None):
        node_adapter = _load()
        return node_adapter.NodeAdapter(
            node_adapter.load_config(_raw_config()),
            runner=runner if runner is not None else FakeRunner(),
            transport=FakeTransport(),
        )

    def test_allowlist_verbs_and_fixed_argv(self):
        node_adapter = _load()
        runner = FakeRunner()
        adapter = self._adapter(runner)
        runner.queue(stdout="uuid-epoch-value\n")
        self.assertEqual(adapter.redis("GET", "astral:auth:cache_epoch"), "uuid-epoch-value")
        runner.queue(stdout="4\n")
        self.assertEqual(adapter.redis("LLEN", "astral:auth:queue"), "4")
        runner.queue(stdout="PONG\n")
        self.assertEqual(adapter.redis("PING"), "PONG")
        self.assertEqual(len(runner.calls), 3)
        get_call = runner.calls[0]
        self.assertEqual(
            get_call["argv"],
            (
                "docker",
                "exec",
                "-i",
                "astral_bench_redis",
                "sh",
                "-c",
                node_adapter._REDIS_STDIN_SCRIPT,
                "sh",
                "GET",
                "astral:auth:cache_epoch",
            ),
        )
        self.assertEqual(get_call["stdin"], REDIS_PASSWORD_SENTINEL)
        self.assertEqual(runner.calls[2]["argv"][-1], "PING")
        for call in runner.calls:
            for part in call["argv"]:
                self.assertNotIn(REDIS_PASSWORD_SENTINEL, part)

    def test_verbs_outside_allowlist_rejected_before_runner(self):
        runner = FakeRunner()
        adapter = self._adapter(runner)
        for verb in (
            "SET",
            "DEL",
            "CONFIG",
            "FLUSHALL",
            "FLUSHDB",
            "EVAL",
            "SETRANGE",
            "get ",
            "SETEX",
        ):
            with self.assertRaises(ValueError, msg=verb):
                adapter.redis(verb, "key")
        self.assertEqual(runner.calls, [])

    def test_arity_and_key_validation(self):
        runner = FakeRunner()
        adapter = self._adapter(runner)
        with self.assertRaises(ValueError):
            adapter.redis("GET")
        with self.assertRaises(ValueError):
            adapter.redis("GET", "k1", "k2")
        with self.assertRaises(ValueError):
            adapter.redis("LLEN")
        with self.assertRaises(ValueError):
            adapter.redis("PING", "extra")
        for bad_key in ("", "has space", "key\nname", "key;DEL x", "k" * 600):
            with self.assertRaises(ValueError, msg=bad_key):
                adapter.redis("GET", bad_key)
        self.assertEqual(runner.calls, [])
        adapter.redis("GET", "astral:auth:l2ev:9001:9061")

    def test_missing_redis_password_fails_closed(self):
        node_adapter = _load()
        runner = FakeRunner()
        raw = _raw_config()
        del raw["redis_password"]
        adapter = node_adapter.NodeAdapter(
            node_adapter.load_config(raw), runner=runner, transport=FakeTransport()
        )
        with self.assertRaises(node_adapter.AdapterError) as caught:
            adapter.redis("PING")
        self.assertEqual(caught.exception.kind, "redis_password_missing")
        self.assertEqual(runner.calls, [])

    def test_redis_failure_raises_scrubbed_error(self):
        node_adapter = _load()
        runner = FakeRunner()
        adapter = self._adapter(runner)
        runner.queue(exit_code=1, stderr="NOAUTH at redis://cache.example.invalid:6380")
        with self.assertRaises(node_adapter.AdapterError) as caught:
            adapter.redis("GET", "k1")
        self.assertEqual(caught.exception.kind, "redis_failed")
        self.assertNotIn("db.example.invalid", str(caught.exception))
        self.assertNotIn(REDIS_PASSWORD_SENTINEL, str(caught.exception))


# ---------------------------------------------------------------------------
# Signed read-only GET.
# ---------------------------------------------------------------------------


class SignedGetTest(unittest.TestCase):
    def _adapter(self, transport=None, with_default_actor=True):
        node_adapter = _load()
        adapter, _config, directory = _adapter_with_secret_file(
            node_adapter, runner=FakeRunner(), transport=transport
        )
        if not with_default_actor:
            adapter._actor = None
        return adapter, directory

    def test_returns_status_parsed_dict_and_request_id(self):
        transport = FakeTransport(status=200, body='{"code":0,"data":{"allowed":true}}')
        adapter, directory = self._adapter(transport)
        try:
            status, parsed, request_id = adapter.signed_get(
                "node-b", "/main/api/v1/simulation/evaluate", request_id="req-stable-7"
            )
            self.assertEqual(status, 200)
            self.assertEqual(parsed, {"code": 0, "data": {"allowed": True}})
            self.assertEqual(request_id, "req-stable-7")
            call = transport.calls[0]
            self.assertEqual(
                call["url"], "http://127.0.0.1:8082/main/api/v1/simulation/evaluate"
            )
            self.assertEqual(call["headers"]["x-request-id"], "req-stable-7")
            self.assertEqual(call["method"], "GET")
            self.assertIsNone(call["body"])
            self.assertEqual(call["headers"]["x-gateway-auth"], "verified")
            self.assertNotIn(HMAC_SECRET_SENTINEL, json.dumps(call["headers"]))
            self.assertNotIn(HMAC_SECRET_SENTINEL, call["url"])
        finally:
            _cleanup(directory)

    def test_path_restrictions(self):
        adapter, directory = self._adapter()
        try:
            for bad_path in (
                "/other/path",
                "/main/api/v1",
                "/main/api/v2/x",
                "/MAIN/API/V1/x",
                "//main/api/v1/x",
                "main/api/v1/x",
                "",
                "https://example.invalid/main/api/v1/x",
            ):
                with self.assertRaises(ValueError, msg=bad_path):
                    adapter.signed_get("node-b", bad_path)
        finally:
            _cleanup(directory)

    def test_node_alias_restrictions(self):
        adapter, directory = self._adapter()
        try:
            for alias in ("node-a", "node-b", "node-c"):
                adapter.signed_get(alias, "/main/api/v1/x", request_id="req-" + alias)
            for bad in ("gateway", "node-d", "NODE-A", "node_a", ""):
                with self.assertRaises(ValueError, msg=bad):
                    adapter.signed_get(bad, "/main/api/v1/x")
        finally:
            _cleanup(directory)

    def test_actor_source(self):
        node_adapter = _load()
        adapter, directory = self._adapter(with_default_actor=False)
        try:
            with self.assertRaises(ValueError):
                adapter.signed_get("node-b", "/main/api/v1/x")
        finally:
            _cleanup(directory)
        adapter2, directory2 = self._adapter()
        try:
            status, _parsed, request_id = adapter2.signed_get(
                "node-b",
                "/main/api/v1/x",
                actor=_actor(node_adapter),
                request_id="req-2",
            )
            self.assertEqual(status, 200)
            self.assertEqual(request_id, "req-2")
        finally:
            _cleanup(directory2)

    def test_signed_mutations_use_allowlisted_methods_and_deterministic_json(self):
        node_adapter = _load()
        transport = FakeTransport(status=200, body='{"success":true,"code":200,"data":{"id":9081}}')
        adapter, directory = self._adapter(transport)
        try:
            status, parsed, request_id = adapter.signed_request(
                "node-b",
                "POST",
                "/main/api/v1/rule-sets/9071/entries",
                {
                    "resource": "monitor",
                    "effect": "ALLOW",
                    "action": "read",
                    "priority": 10,
                    "conditionJson": None,
                },
                request_id="op-entry-add",
            )
            self.assertEqual((status, request_id), (200, "op-entry-add"))
            self.assertEqual(parsed["data"]["id"], 9081)
            post = transport.calls[0]
            self.assertEqual(post["method"], "POST")
            self.assertEqual(
                post["body"],
                b'{"action":"read","conditionJson":null,"effect":"ALLOW","priority":10,"resource":"monitor"}',
            )
            self.assertEqual(post["headers"]["x-request-id"], "op-entry-add")

            adapter.signed_request(
                "node-b",
                "DELETE",
                "/main/api/v1/rule-sets/9071/entries/9081",
                request_id="op-entry-delete",
            )
            deleted = transport.calls[1]
            self.assertEqual(deleted["method"], "DELETE")
            self.assertIsNone(deleted["body"])

            adapter.signed_request(
                "node-b",
                "PUT",
                "/main/api/v1/rule-sets/9071",
                {"name": "fixture"},
                request_id="op-rule-set-update",
            )
            self.assertEqual(transport.calls[2]["method"], "PUT")
        finally:
            _cleanup(directory)

    def test_signed_request_rejects_unallowlisted_or_malformed_inputs(self):
        transport = FakeTransport()
        adapter, directory = self._adapter(transport)
        try:
            for method in ("PATCH", "OPTIONS", "TRACE", "CONNECT", ""):
                with self.assertRaises(ValueError, msg=method):
                    adapter.signed_request(
                        "node-b", method, "/main/api/v1/x", request_id="req-safe"
                    )
            with self.assertRaises(ValueError):
                adapter.signed_request(
                    "node-b",
                    "GET",
                    "/main/api/v1/x",
                    {"unexpected": True},
                    request_id="req-safe",
                )
            with self.assertRaises(TypeError):
                adapter.signed_request(
                    "node-b",
                    "POST",
                    "/main/api/v1/x",
                    ["not", "an", "object"],
                    request_id="req-safe",
                )
            self.assertEqual(transport.calls, [])
        finally:
            _cleanup(directory)

    def test_non_json_rejection(self):
        for body in ("not-json", "[1,2,3]", "null"):
            adapter, directory = self._adapter(FakeTransport(body=body))
            try:
                with self.assertRaises(ValueError, msg=body):
                    adapter.signed_get("node-b", "/main/api/v1/x")
            finally:
                _cleanup(directory)


class RoleActorProbeTest(unittest.TestCase):
    def test_role_specific_signatures_and_card_binding(self):
        node_adapter = _load()
        transport = FakeTransport(
            status=200,
            body='{"success":true,"data":{"effect":"ALLOW","reason":"PUBLISHED_EVIDENCE_ALLOW"}}',
        )
        adapter, config, directory = _adapter_with_secret_file(
            node_adapter,
            runner=FakeRunner(),
            transport=transport,
        )
        try:
            actors = {
                role: node_adapter.Actor(
                    user_id="9031",
                    identity_card="9041",
                    user_card=card,
                    domain="9011",
                    tenant="9001",
                )
                for role, card in (("target", "9061"), ("unrelated", "9062"), ("cold", "9063"))
            }
            adapters = {
                role: node_adapter.NodeAdapter(
                    config,
                    actor=actor,
                    runner=FakeRunner(),
                    transport=transport,
                    clock=lambda: 1700000000.0,
                    request_id_factory=lambda role=role: "req-" + role,
                )
                for role, actor in actors.items()
            }
            probe = node_adapter.RoleActorProbe(adapter, adapters, actors)
            for role, actor in actors.items():
                status, body, request_id = probe.signed_get_for_role(
                    role,
                    actor.user_card,
                    "node-b",
                    "/main/api/v1/permission-rules/check?resourceType=monitor&actionCode=read&cardId="
                    + actor.user_card,
                )
                self.assertEqual(status, 200)
                self.assertEqual(body["data"]["effect"], "ALLOW")
                self.assertEqual(request_id, "req-" + role)
            self.assertEqual(
                [call["headers"]["x-user-card-id"] for call in transport.calls],
                ["9061", "9062", "9063"],
            )
            with self.assertRaises(ValueError):
                probe.signed_get_for_role(
                    "target",
                    "9062",
                    "node-b",
                    "/main/api/v1/permission-rules/check?cardId=9062",
                )
            with self.assertRaises(ValueError):
                probe.signed_get_for_role(
                    "unknown",
                    "9061",
                    "node-b",
                    "/main/api/v1/permission-rules/check?cardId=9061",
                )
            self.assertEqual(len(transport.calls), 3)
        finally:
            _cleanup(directory)

    def test_missing_role_mapping_is_rejected_before_any_io(self):
        node_adapter = _load()
        adapter = node_adapter.NodeAdapter(node_adapter.load_config(_raw_config()))
        with self.assertRaises(ValueError):
            node_adapter.RoleActorProbe(
                adapter,
                {"target": adapter},
                {"target": _actor(node_adapter)},
            )


# ---------------------------------------------------------------------------
# Node log slice.
# ---------------------------------------------------------------------------


class LogSliceTest(unittest.TestCase):
    def _adapter(self, runner=None):
        node_adapter = _load()
        return node_adapter.NodeAdapter(
            node_adapter.load_config(_raw_config()),
            runner=runner if runner is not None else FakeRunner(),
            transport=FakeTransport(),
            clock=lambda: 0.0,
        )

    def test_node_b_uses_local_direct_argv(self):
        node_adapter = _load()
        runner = FakeRunner()
        adapter = self._adapter(runner)
        runner.queue(stdout="evt line one\nevt line two\n")
        lines = adapter.read_log_lines("node-b", ["req-1"])
        self.assertEqual(lines, ["evt line one", "evt line two"])
        expected_payload = base64.b64encode(json.dumps(["req-1"]).encode("utf-8")).decode("ascii")
        call = runner.calls[0]
        self.assertEqual(
            call["argv"],
            (
                "python3",
                "-",
                os.path.expanduser("~/authz-validation-20260919-single-node-002"),
                "server_b.log",
                expected_payload,
            ),
        )
        self.assertEqual(call["stdin"], node_adapter._LOG_GREP_SCRIPT)
        self.assertNotIn("ssh", call["argv"][0])

    def test_node_a_and_c_use_ssh_batchmode_fixed_args(self):
        node_adapter = _load()
        runner = FakeRunner()
        adapter = self._adapter(runner)
        runner.queue(stdout="")
        runner.queue(stdout="")
        adapter.read_log_lines("node-a", ["op-1", "req-2"])
        adapter.read_log_lines("node-c", ["op-1"])
        self.assertEqual(len(runner.calls), 2)
        expected_payload = base64.b64encode(
            json.dumps(["op-1", "req-2"], separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        call = runner.calls[0]
        self.assertEqual(
            call["argv"][:5],
            ("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"),
        )
        self.assertEqual(call["argv"][5], "ops@node-a.example.invalid")
        remote = call["argv"][6]
        self.assertTrue(remote.startswith("python3 - "))
        self.assertIn('"$HOME"/authz-validation-20260919-single-node-002', remote)
        self.assertIn("server_a.log", remote)
        self.assertIn(shlex.quote(expected_payload), remote)
        # The fixed script travels via stdin; it must never appear in argv.
        self.assertNotIn("open(", remote)
        self.assertNotIn("_SAFE_ID", remote)
        self.assertEqual(call["stdin"], node_adapter._LOG_GREP_SCRIPT)
        self.assertEqual(runner.calls[1]["argv"][5], "ops@node-c.example.invalid")

    def test_identifiers_validated_and_empty_short_circuit(self):
        node_adapter = _load()
        runner = FakeRunner()
        adapter = self._adapter(runner)
        self.assertEqual(adapter.read_log_lines("node-a", []), [])

        self.assertEqual(runner.calls, [])
        for bad in (["bad id"], ["id\n"], ["x'; DROP"], ["", "ok"], [123], "req-1"):
            with self.assertRaises((ValueError, TypeError), msg=repr(bad)):
                adapter.read_log_lines("node-a", bad)
        self.assertEqual(runner.calls, [])
        adapter.read_log_lines("node-a", ["dup-1", "dup-1", "dup-2"])
        expected = base64.b64encode(
            json.dumps(["dup-1", "dup-2"], separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        self.assertIn(shlex.quote(expected), runner.calls[0]["argv"][-1])

    def test_failure_raises_error_without_host_target(self):
        node_adapter = _load()
        runner = FakeRunner()
        adapter = self._adapter(runner)
        runner.queue(exit_code=255, stderr="ssh: connect to host ops@node-a.example.invalid port 22")
        with self.assertRaises(node_adapter.AdapterError) as caught:
            adapter.read_log_lines("node-a", ["req-1"])
        self.assertEqual(caught.exception.kind, "log_slice_failed")
        self.assertEqual(caught.exception.exit_code, 255)
        self.assertNotIn("node-a.example.invalid", str(caught.exception))
        self.assertIn("[redacted-host]", str(caught.exception))

    def test_unknown_node_alias_rejected(self):
        node_adapter = _load()
        runner = FakeRunner()
        adapter = self._adapter(runner)
        with self.assertRaises(ValueError):
            adapter.read_log_lines("node-z", ["req-1"])
        self.assertEqual(runner.calls, [])


# ---------------------------------------------------------------------------
# Durable SELECT reconciliation helpers.
# ---------------------------------------------------------------------------


class ReconciliationTest(unittest.TestCase):
    def _adapter(self, runner=None):
        node_adapter = _load()
        return node_adapter.NodeAdapter(
            node_adapter.load_config(_raw_config()),
            runner=runner if runner is not None else FakeRunner(),
            transport=FakeTransport(),
        )

    def test_helpers_issue_select_only_queries_through_sql(self):
        runner = FakeRunner()
        adapter = self._adapter(runner)
        runner.queue(stdout="RULE_SET\t1\t3\t0\n")
        runner.queue(stdout="SUCCEEDED\t3\n")
        runner.queue(stdout="1\t1\tPROCESSED\t\t1\t\t0\n")
        runner.queue(stdout="evt-remove-1\tREMOVE\tSUCCEEDED\t4\t2\n")
        runner.queue(stdout="3\tREADY\t0\t9\tevt-remove-1\top-delete-1\t2\n")
        head = adapter.head_state("RULE_SET", 1)
        delta = adapter.delta_states(9001, "RULE_SET", 1)
        outbox = adapter.outbox_rows("RULE_SET", 1)
        operation = adapter.delta_rows_for_operation(9001, "RULE_SET", 1, "op-delete-1")
        pointer = adapter.projection_pointer(9001, "CARD", 2)
        self.assertEqual(len(runner.calls), 5)
        queries = [call["argv"][-1] for call in runner.calls]
        self.assertTrue(queries[0].startswith("SELECT"))
        self.assertIn("FROM authorization_projection_head", queries[0])
        self.assertIn("aggregate_type='RULE_SET' AND aggregate_id=1", queries[0])
        self.assertIn("FROM authorization_delta_event", queries[1])
        self.assertIn("tenant_id=9001 AND aggregate_type='RULE_SET' AND aggregate_id=1", queries[1])
        self.assertIn("FROM authorization_projection_outbox", queries[2])
        self.assertIn("FROM authorization_delta_event", queries[3])
        self.assertIn("tenant_id=9001 AND aggregate_type='RULE_SET' AND aggregate_id=1", queries[3])
        self.assertIn("operation_id='op-delete-1'", queries[3])
        self.assertIn("event_id, event_type, status, target_version, IFNULL(card_id,0)", queries[3])
        self.assertIn("FROM authorization_projection_current", queries[4])
        self.assertIn("tenant_id=9001 AND aggregate_type='CARD' AND aggregate_id=2", queries[4])
        self.assertIn("event_id, operation_id, IFNULL(card_id,0)", queries[4])
        for query in queries:
            for forbidden in ("UPDATE ", "INSERT ", "DELETE ", "DROP ", "ALTER "):
                self.assertNotIn(forbidden, query)
        self.assertEqual(head, [["RULE_SET", "1", "3", "0"]])
        self.assertEqual(delta, [["SUCCEEDED", "3"]])
        self.assertEqual(outbox, [["1", "1", "PROCESSED", "", "1", "", "0"]])
        self.assertEqual(operation, [["evt-remove-1", "REMOVE", "SUCCEEDED", "4", "2"]])
        self.assertEqual(pointer, [["3", "READY", "0", "9", "evt-remove-1", "op-delete-1", "2"]])

    def test_helper_input_validation(self):
        runner = FakeRunner()
        adapter = self._adapter(runner)
        with self.assertRaises(ValueError):
            adapter.head_state("RULE_SET; DROP TABLE x", 1)
        with self.assertRaises(ValueError):
            adapter.head_state("rule_set", 1)
        with self.assertRaises(ValueError):
            adapter.head_state("RULE_SET", "1 OR 1=1")
        with self.assertRaises(ValueError):
            adapter.delta_states(0, "RULE_SET", 1)
        with self.assertRaises(ValueError):
            adapter.delta_states(9001, "rule_set", 1)
        with self.assertRaises(ValueError):
            adapter.delta_states(9001, "RULE_SET", "1 OR 1=1")
        with self.assertRaises(ValueError):
            adapter.delta_states((1 << 63), "RULE_SET", 1)
        with self.assertRaises(ValueError):
            adapter.delta_states(9001, "RULE_SET", (1 << 63))
        with self.assertRaises(ValueError):
            adapter.delta_rows_for_operation(0, "RULE_SET", 1, "op-delete-1")
        with self.assertRaises(ValueError):
            adapter.delta_rows_for_operation(9001, "RULE_SET", 1, "bad operation id")
        with self.assertRaises(ValueError):
            adapter.delta_rows_for_operation(9001, "RULE_SET", 1, "x" * 65)
        with self.assertRaises(ValueError):
            adapter.outbox_rows("RULE_SET", 0)
        with self.assertRaises(ValueError):
            adapter.projection_pointer(0, "RULE_SET", 1)
        with self.assertRaises(ValueError):
            adapter.projection_pointer(9001, "RULE_SET", True)
        self.assertEqual(runner.calls, [])


# ---------------------------------------------------------------------------
# Injected transport contracts and error type hygiene.
# ---------------------------------------------------------------------------


class TransportContractTest(unittest.TestCase):
    def test_fakes_satisfy_protocols(self):
        node_adapter = _load()
        self.assertIsInstance(FakeRunner(), node_adapter.CommandRunner)
        self.assertIsInstance(FakeTransport(), node_adapter.HttpTransport)

    def test_command_result_shape(self):
        node_adapter = _load()
        result = node_adapter.CommandResult(argv=("a",), exit_code=0, stdout="out", stderr="err")
        self.assertEqual(result.argv, ("a",))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "out")
        self.assertEqual(result.stderr, "err")

    def test_subprocess_runner_exists_without_calling_subprocess(self):
        node_adapter = _load()
        runner = node_adapter.SubprocessRunner()
        self.assertTrue(callable(runner.run))

    def test_adapter_repr_hides_everything_private(self):
        node_adapter = _load()
        adapter, _config, directory = _adapter_with_secret_file(_load(), runner=FakeRunner())
        try:
            text = repr(adapter)
            self.assertIn("NodeAdapter", text)
            _assert_no_private_sentinels(self, text, "adapter repr")
        finally:
            _cleanup(directory)

    def test_adapter_rejects_bad_config_type(self):
        node_adapter = _load()
        with self.assertRaises(TypeError):
            node_adapter.NodeAdapter({"run_id": "x"})  # type: ignore[arg-type]

    def test_scrub_covers_url_ip_and_hostname(self):
        node_adapter = _load()
        scrubbed = node_adapter._scrub_text(
            "see http://h.example.internal/a and 10.1.2.3 and db.host.example.org end"
        )
        self.assertNotIn("http://", scrubbed)
        self.assertNotIn("10.1.2.3", scrubbed)
        self.assertNotIn("db.host.example.org", scrubbed)
        self.assertEqual(scrubbed.count("[redacted-host]"), 3)


class LogGrepScriptLiveTest(unittest.TestCase):
    """Execute the fixed log-slice script against a temporary local log."""

    def test_log_grep_script_uses_the_payload_emitted_by_read_log_lines(self) -> None:
        adapter_module = _load()
        fake_runner = FakeRunner()
        adapter = adapter_module.NodeAdapter(
            adapter_module.load_config(_raw_config()),
            runner=fake_runner,
            transport=FakeTransport(),
        )
        adapter.read_log_lines("node-b", ["req-1"])
        payload = fake_runner.calls[0]["argv"][-1]

        with tempfile.TemporaryDirectory(prefix="e1_slice_test_") as directory:
            log_path = os.path.join(directory, "server_b.log")
            with open(log_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    "\n".join(
                        [
                            json.dumps(
                                {
                                    "event": "decision_return",
                                    "request_id": "req-1",
                                    "allowed": True,
                                }
                            ),
                            "unrelated line",
                            "",
                        ]
                    )
                )
            completed = subprocess.run(
                [sys.executable, "-", directory, "server_b.log", payload],
                input=adapter_module._LOG_GREP_SCRIPT,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("decision_return", completed.stdout)
        self.assertNotIn("unrelated line", completed.stdout)

        malformed = subprocess.run(
            [sys.executable, "-", directory, "server_b.log", "%%%not-base64%%%"],
            input=adapter_module._LOG_GREP_SCRIPT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(malformed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
