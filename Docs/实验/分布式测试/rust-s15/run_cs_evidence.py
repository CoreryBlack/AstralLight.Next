#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rust 证据编排器：按安全顺序组织 rust-s15 各采集脚本，产出逐步 manifest。

职责边界：只组织 **Rust 侧**证据采集；不负责部署（deploy_dist.sh 由人显式
执行，SNAP_BIN 必填）、不重跑任何 Java 侧实验、不推送/提交。

每阶段写 manifest（cs_evidence_manifest.json，每步后原子覆写），条目含：
  step / 命令 argv / cwd / env 名称清单（**只记名称不记值**——run_config.json、
  jwt.env、hmac.txt 均含 run 级秘钥）/ start/end UTC / exit code / artifact
  路径 / postcondition 断言与结果 / verdict。

verdict 语义（对齐 AGENTS §7.1，exit 0 不等于业务 PASS）：
  PASS     rc==0 且 artifact 存在且 postcondition 断言成立
  FAIL     rc!=0，或 rc==0 但 postcondition 不成立（如实FAIL，不静默重分类）
  UNKNOWN  process-group timeout/termination, or a child self-reporting rc=4;
           the run must reconcile state before retrying
  SKIP     被 --skip/--only 显式排除（**--only 未选中的步骤也记 SKIP**，
           不再静默消失）
  BLOCKED  前置缺失（--run-config/setup provenance 缺失或非法、fresh-only
           out-dir 被占用、harness/TOCTOU/integration tree identity 不匹配、
           --ec-bin 缺失、OPA sidecar 不可达、integration 的 argv/cwd/required
           env 缺失、integration argv 含疑似内联秘钥、--skip/--only 含未知
           步骤名、**--only/--skip 过滤后 active 步骤集为空**）——整个编排
           不启动（exit 2），**绝不静默降级为 skip，绝不出现 0 步 PASS**。

overall 语义（M1）：
  PASS             默认全流程 11 步全部执行且全 PASS（任何 SKIP 都不得整体 PASS）
  PASS_WITH_SKIPS  显式 --only/--skip 的 scoped 运行：选中步骤全 PASS 且无
                   FAIL/UNKNOWN（manifest meta.scope="scoped" 显式标注，
                   不与全流程完成混淆）；任何情况下 0 个实际 PASS 步骤
                   一律 FAIL
  FAIL             存在 FAIL/UNKNOWN，或 PASS 但无实际 PASS 步骤（防御位）

安全顺序（故障注入在前、测量在后；写重在前、空闲读基线在后）——默认 11 步：
  1 s15_coordinator    S1–S15 一致性（SIGSTOP/kill/Redis 停机混沌；默认
                       --rounds 3，满足 S14/S15 样本量 >= 3）
  2 cluster_settle     轮间整组重启 + 存活/就绪守卫（api200+decision200，
                       任一节点未就绪退出码非零）
  3 f7_recheck         worker 链路稳定性（30 轮 add/remove）
  4 rq_settle          RQ 写入前整组重启 + projection/delta/impact/archive
                       排水守卫（队列静默且决策端点 200）
  5 rq_fill            CS_1–CS_8 + RQ2 梯度（RQ2-D 冲突密度为结构性 N/A；
                       RQ2 K/I 梯度逐点 ALLOW 收敛证据入 artifact，
                       postcondition 逐点校验）
  6 rq345 --phase rq34 写路径口径（增量/ADD-only 风暴/排水；403
                       AUTHORIZATION_PENDING 为预期 fail-closed，单列
                       pending_403 不要求 0，PASS 门禁只看 non_pending_errors==0
                       且 deltas_terminal）
  7 s15_perf           性能 P1–P4（要求节点空闲；P3.5有界排水内置；
                       P2 初始 ALLOW 30s 未收敛 → 直接 FAIL 退出）
  8 rq345 --phase rq5  读路径吞吐/缓存回填/旧令牌回放（要求节点空闲）
  9 toctou_race        RQ5 TOCTOU（默认开启，30 cycles x 12 readers，对同一
                       run_config）
 10 engine-comparison   引擎对比（--repeats 默认 5；显式 --output-dir=
                       {out}/engine-comparison，postcondition 直接断言该目录
                       run_meta.json（所有 JSON 步骤均带 pre-mtime 防陈旧），不做 newest 扫描；
                       执行 cwd 与 --ec-cwd 一致；OPA 为必需引擎，二进制在
                       sidecar 不可达时以非零码退出；不传 --allow-opa-skip）
 11 integration         真实 ignored integration（--integration-cmd 必须是
                       **JSON argv 列表**（不经 shell，无任意命令拼接），
                       --integration-cwd 与 --integration-env 显式给定；argv
                       经 secret-shape 检查——内联 --password/--token/凭据 URL/
                       Authorization 头/秘密 env 赋值一律 BLOCKED，秘钥只准经
                       --integration-env 以环境名称传递；子环境为 allowlist
                       （基础环境名 ∪ required env ∪ RUN_CONFIG_PATH），不继承
                       任意 env 以防环境中的 run 秘钥泄漏；任一前置缺失 →
                       整体 BLOCKED；result artifact **先按 rc 原子落盘再校验**
                       （带 pre-mtime 防陈旧））


用法（node-b；run_config.json 属 0600 run 秘密文件，留在 $HOME/$RUN_ID/，
**不要复制进源码目录**——经 --run-config 显式传入，编排在子进程环境里以
RUN_CONFIG_PATH 传递路径，manifest 只记录路径/sha256 与 env 名称，不记秘钥值）：
  python3 -u run_cs_evidence.py \
      --run-config "$HOME/$RUN_ID/run_config.json" \
      --out-dir "$HOME/$RUN_ID/evidence_<ts>" [--rounds 3]
      [--skip s15_perf,integration] [--only ...] [--keep-going]
      [--ec-bin /path/engine-comparison] [--ec-cwd DIR] [--ec-repeats 5]
      [--ec-opa http://127.0.0.1:8181]
      [--integration-cmd '["cargo","test","--locked","-p","astral-db","--test","authorization_projection_integration","--release","--","--ignored","--test-threads=1"]']
      [--integration-cwd /path/to/AstralLight-Next]
      [--integration-env RUST_INTEGRATION_REQUIRED,DATABASE_URL,...]
退出码：0 全部 PASS（默认全流程要求 11 步全执行无 SKIP；显式 --only/--skip
        的 scoped 运行无 FAIL/UNKNOWN 时为 PASS_WITH_SKIPS，也返回 0）；
        1 存在 FAIL/UNKNOWN/BLOCKED（含 0 个实际 PASS 步骤的防御位）；
        2 BLOCKED（前置缺失；--skip/--only 未知步骤名；过滤后 active 为空）。
"""
import argparse
import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python3"
TOCTOU_RACE = os.path.normpath(os.path.join(
    SCRIPT_DIR, "..", "..", "..", "..",
    "bench", "loadgen", "scripts", "toctou_race.py"))

# TOCTOU 默认口径：30 cycles x 12 readers（harness 审计修复要求的显式覆盖）。
TOCTOU_CYCLES = 30
TOCTOU_READERS = 12
INTEGRATION_EXPECTED_TESTS = 10
INTEGRATION_EXPECTED_TREE_FILES = 382

# L4：{out}/{rounds} 模板替换只对内部白名单步骤生效，绝不对任意 argv token 做
# 子串嗅探——外部 argv（engine-comparison 参数、integration 用户 JSON 列表）里
# 恰好含 "{out}" 子串的 token（如 "{outgoing}"）会被 str.format 误解析
# （KeyError 或意外替换），故一律原样传递。
_TEMPLATE_STEPS = frozenset({
    "s15_coordinator", "cluster_settle", "f7_recheck", "rq_settle", "rq_fill",
    "rq345_rq34", "s15_perf", "rq345_rq5", "toctou_race",
})

# Fixed harness allowlist: the campaign provenance must identify the exact
# scripts used, even though this experiment directory is not a Git checkout.
_SETUP_PROVENANCE_KEYS = frozenset({
    "run_id", "created_at_utc", "source_tar_sha256", "source_manifest_sha256",
    "dirty_patch_sha256", "source_git_rev", "trustgraph_sha256", "engine_sha256",
    "bootstrap_sha256", "harness_tar_sha256", "harness_manifest_file_sha256",
    "harness_combined_sha256", "routing_source_sha256", "routing_source_run_id",
    "toctou_sha256", "integration_tree_sha256", "integration_tree_files",
    "integration_user_write_probe", "integration_db",
    "integration_schema_dump_sha256", "integration_tables", "integration_migrations",
    "opa_container", "opa_port", "opa_image_id", "opa_repo_digest", "opa_version",
    "rabbit_vhost", "rabbit_connections", "rabbit_audit_consumers",
    "rabbit_dlx_consumers", "redis_container", "redis_port", "node_ports",
    "rustc_version", "cargo_version", "docker_version", "mysql_version",
})

_BASE_ENV_ALLOWLIST = (
    "PATH", "HOME", "USERPROFILE", "USER", "SHELL", "TERM", "LANG", "LC_ALL",
    "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "SYSTEMDRIVE", "HOMEDRIVE",
    "HOMEPATH", "COMSPEC", "PATHEXT", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES",
    "CARGO_HOME", "RUSTUP_HOME",
)

_HARNESS_FILES = (
    "deploy_dist.sh",
    "e2e-bootstrap-v2-main.rs",
    "f7_recheck.py",
    "rq345_20260903.py",
    "rq_fill_20260901.py",
    "run_cs_evidence.py",
    "s15_coordinator.py",
    "s15_perf.py",
    "seed_f4rust.sql",
    "README.md",
)


def harness_sha256():
    """Return the fixed harness allowlist hashes without reading secret files."""
    import hashlib
    files = {}
    missing = []
    for name in _HARNESS_FILES:
        path = os.path.join(SCRIPT_DIR, name)
        if not os.path.isfile(path):
            missing.append(name)
            continue
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
        except OSError:
            missing.append(name)
            continue
        files[name] = digest.hexdigest()
    manifest = hashlib.sha256()
    for name in _HARNESS_FILES:
        digest = files.get(name, "MISSING")
        manifest.update(name.encode("utf-8"))
        manifest.update(b"\0")
        manifest.update(digest.encode("ascii"))
        manifest.update(b"\n")
    return {"allowlist": list(_HARNESS_FILES), "files": files,
            "complete": not missing, "missing": missing,
            "manifest_sha256": manifest.hexdigest()}


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Campaign-time exact-secret rescans reuse the coordinator's harness-frozen
# scanner (stdin-transported, count-only output). The scan child gets an
# allowlisted env so secret-bearing caller variables never reach it.
_RUNTIME_SECRET_SCAN_SNIPPET = (
    "import json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import s15_coordinator as coordinator\n"
    "result = coordinator.runtime_secret_scan(extra_paths=sys.argv[2:])\n"
    "print(json.dumps(result, sort_keys=True))\n"
    "sys.exit(0 if result.get('ok') else 1)\n"
)

_SCAN_CHILD_ENV_ALLOWLIST = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT",
                             "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "APPDATA",
                             "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR")


def runtime_secret_scan_gate(run_config_path, extra_paths):
    """Return the coordinator scan result; values/lines are never echoed."""
    env = {key: os.environ[key] for key in _SCAN_CHILD_ENV_ALLOWLIST
           if key in os.environ}
    env["RUN_CONFIG_PATH"] = run_config_path
    try:
        proc = subprocess.run(
            [PY, "-c", _RUNTIME_SECRET_SCAN_SNIPPET, SCRIPT_DIR] + list(extra_paths),
            env=env, capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "error": type(exc).__name__}
    try:
        data = json.loads(proc.stdout.strip().splitlines()[-1])
        if not isinstance(data, dict):
            raise ValueError("scan output must be an object")
    except (ValueError, IndexError):
        data = {"ok": False, "error": "malformed_scan_output"}
    if proc.returncode != 0 and data.get("ok"):
        data = {"ok": False, "error": "scan_exit_%s" % proc.returncode}
    return data
    return digest.hexdigest()


def directory_tree_sha256(root):
    """Hash every regular file by normalized relative path; reject symlinks."""
    if not os.path.isdir(root):
        return None, "not_a_directory"
    entries = []
    try:
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs.sort()
            files.sort()
            for name in dirs:
                if os.path.islink(os.path.join(base, name)):
                    return None, "symlink_directory"
            for name in files:
                path = os.path.join(base, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    return None, "non_regular_file"
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                entries.append((rel, file_sha256(path)))
    except OSError as exc:
        return None, type(exc).__name__
    digest = hashlib.sha256()
    for rel, value in sorted(entries):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(value.encode("ascii"))
        digest.update(b"\n")
    return {"sha256": digest.hexdigest(), "files": len(entries)}, None


def runtime_input_snapshot(args, active_names):
    """Fence executable source inputs that live outside the harness directory."""
    snapshot = {}
    if "toctou_race" in active_names:
        if not os.path.isfile(TOCTOU_RACE):
            return None, "toctou_race_missing"
        try:
            snapshot["toctou_sha256"] = file_sha256(TOCTOU_RACE)
        except OSError as exc:
            return None, "toctou_race_%s" % type(exc).__name__
        if snapshot["toctou_sha256"].lower() != args.expected_toctou_sha256.lower():
            return None, "toctou_race_sha256_mismatch"
    if "integration" in active_names:
        tree, error = directory_tree_sha256(args.integration_cwd)
        if error:
            return None, "integration_tree_%s" % error
        snapshot["integration_tree_sha256"] = tree["sha256"]
        snapshot["integration_tree_files"] = tree["files"]
        if tree["sha256"].lower() != args.expected_integration_tree_sha256.lower():
            return None, "integration_tree_sha256_mismatch"
        if tree["files"] != INTEGRATION_EXPECTED_TREE_FILES:
            return None, "integration_tree_file_count_mismatch"
    return snapshot, None


def valid_sha256(value):
    return bool(isinstance(value, str)
                and re.fullmatch(r"[0-9a-fA-F]{64}", value))


def render_argv(name, argv_tpl, out_dir, rounds):
    """仅对内部模板步骤做 {out}/{rounds} 显式字符串替换（str.replace，不用
    str.format）；其余步骤（engine_comparison / integration 的显式 argv）
    原样传递。"""
    if name not in _TEMPLATE_STEPS:
        return list(argv_tpl)
    return [a.replace("{out}", out_dir).replace("{rounds}", str(rounds))
            if isinstance(a, str) else a for a in argv_tpl]


# L5：integration argv 进 manifest/日志前拒绝疑似内联秘钥——秘钥一律经
# --integration-env 以环境名称传递，值不得出现在 argv/manifest/log。
_SECRET_FLAG_RE = re.compile(
    r"(?i)^--?[^=]*(password|passwd|pass|pwd|token|secret|credential|authorization|"
    r"api[-_]?key|apikey|access[-_]?key|private[-_]?key)[^=]*(=|$)")
_CRED_URL_RE = re.compile(
    r"(?i)[a-z][a-z0-9+.\-]*://[^\s/@]+:[^\s/@]*@")     # scheme://user:pass@
_AUTH_HEADER_RE = re.compile(r"(?i)^\s*(proxy-?authorization|authorization)\s*:")
_ENV_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")
_SECRET_NAME_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[-_]?key|apikey|credential|"
    r"private[-_]?key|access[-_]?key)")


def validate_integration_argv(argv_list, integration_cwd=None):
    """Pin step 11 to the canonical ignored astral-db integration target."""
    problems = []
    if not argv_list or os.path.basename(argv_list[0]).lower() not in ("cargo", "cargo.exe"):
        return ["executable must be cargo"]
    expected_tail = [
        "--locked", "-p", "astral-db", "--test", "authorization_projection_integration",
        "--release", "--", "--ignored", "--test-threads=1",
    ]
    if len(argv_list) == len(expected_tail) + 2 \
            and argv_list[1] == "test" \
            and argv_list[2:] == expected_tail:
        return problems
    if len(argv_list) == len(expected_tail) + 4 \
            and argv_list[1] == "test" and argv_list[2] == "--manifest-path" \
            and argv_list[4:] == expected_tail:
        manifest = os.path.abspath(argv_list[3])
        expected_manifest = os.path.abspath(
            os.path.join(integration_cwd or "", "Cargo.toml"))
        if manifest != expected_manifest:
            problems.append("--manifest-path must match integration cwd Cargo.toml")
        return problems
    return ["argv shape differs from canonical astral-db ignored integration command"]


def integration_secret_findings(argv_list):
    """L5：返回 integration argv 中疑似内联秘钥的发现清单（只描述位置/形态，
    绝不回显可疑值本身）。空清单 = 通过。"""
    findings = []
    for i, tok in enumerate(argv_list):
        if not isinstance(tok, str) or not tok.strip():
            continue
        stripped = tok.strip()
        if _SECRET_FLAG_RE.match(stripped):
            flag = stripped.split("=", 1)[0]
            findings.append("argv[%d] 秘密形 flag（%s）——拒绝内联，要求经 "
                            "--integration-env 以环境名称传递" % (i, flag))
            continue
        if stripped in ("-p", "-P") and i + 1 < len(argv_list):
            if stripped == "-p" and argv_list[i + 1] == "astral-db":
                continue
            findings.append("argv[%d] 疑似短密码 flag——拒绝内联，要求经 "
                            "--integration-env 以环境名称传递" % i)
            continue
        if _CRED_URL_RE.search(tok):
            findings.append("argv[%d] 疑似带凭据 URL（user:pass@host）——拒绝内联"
                            % i)
            continue
        if _AUTH_HEADER_RE.match(tok):
            findings.append("argv[%d] 疑似 Authorization 头内联——拒绝" % i)
            continue
        m = _ENV_ASSIGN_RE.match(tok)
        if m and _SECRET_NAME_RE.search(m.group(1)):
            findings.append("argv[%d] 疑似秘密 env 内联赋值（%s=...）——拒绝，"
                            "要求经 --integration-env 以环境名称传递"
                            % (i, m.group(1)))
    return findings

STEPS = [
    # (name, argv 模板占位 {out}/{rounds}, 默认超时 s, postcondition 描述)
    ("s15_coordinator", [PY, "-u", "s15_coordinator.py", "--rounds", "{rounds}",
                         "--out", "{out}/s15_coordinator.json"], 6 * 3600,
     "summary.fail == 0（原始汇总，无静默重分类）"),
    ("cluster_settle", [PY, "-c",
                        "import sys; import s15_coordinator as C; sys.exit(C.cluster_settle())"],
     1800, "rc==0（三节点重启后 run-owned serving + api200+decision200 双门通过）"),
    ("f7_recheck", [PY, "-u", "f7_recheck.py", "--out", "{out}/f7_recheck.json"], 2 * 3600,
     "summary.all_ok true 且 head_monotonic"),
    ("rq_settle", [PY, "-c",
                    "import sys; import s15_coordinator as C; sys.exit(C.rq_settle())"],
     3600, "三节点重启后 projection/delta/impact/archive 队列静默且决策端点 200"),
    ("rq_fill", [PY, "-u", "rq_fill_20260901.py", "--out", "{out}/rq_fill.json"], 3 * 3600,
     "cs/rq2 各案例 ok 无 False，且 RQ2 K/I 梯度逐点 ok=True（ALLOW 收敛；"
     "RQ2-D 为显式 N/A，不计入分母）"),
    ("rq345_rq34", [PY, "-u", "rq345_20260903.py", "--phase", "rq34",
                    "--out", "{out}/rq345_rq34.json"], 4 * 3600,
     "rq3.high_freq_write 与 rq4.long_storm_60s：drain_complete==true、"
     "deltas_terminal==true、non_pending_errors==0（403 AUTHORIZATION_PENDING "
     "为预期 fail-closed，单列 pending_403 不要求 0；缺字段旧 artifact 拒收）"),
    ("s15_perf", [PY, "-u", "s15_perf.py", "--out", "{out}/s15_perf.json"], 3 * 3600,
     "json 含 P1/P2/P3/P4 与 pre_P4_drain"),
    ("rq345_rq5", [PY, "-u", "rq345_20260903.py", "--phase", "rq5",
                   "--out", "{out}/rq345_rq5.json"], 3 * 3600,
     "E11 anomalies==0（replay/cross-card 零越权、stale ts 被拒、cross_card_denied==3）"
     "且 E3+E5 各点 errors==0"),
]

TOCTOU_STEP_DEFAULTS = (
    "toctou_race", 2 * 3600,
    "verdict == PASS（PASS_WITH_ERRORS/UNKNOWN 也如实记录，verdict 字段原文）")

_UNKNOWN_RETURN_CODES = {
    "s15_coordinator": frozenset({4}),
    "toctou_race": frozenset({4}),
}


def build_toctou_step(run_config_path):
    return ("toctou_race",
            [PY, "-u", TOCTOU_RACE,
             "--run-config", run_config_path,
             "--cycles", str(TOCTOU_CYCLES),
             "--readers", str(TOCTOU_READERS),
             "--out", "{out}/toctou_race.json"],
            TOCTOU_STEP_DEFAULTS[1], TOCTOU_STEP_DEFAULTS[2])


def build_ec_step(args, out_dir):
    """engine-comparison 步骤：显式二进制 + 5 repeats + 显式 --output-dir（H-B）
    + OPA 必需（绝不传 --allow-opa-skip）。artifact 固定为
    {out}/engine-comparison/run_meta.json，不做 newest 扫描。"""
    ec_out = os.path.join(out_dir, "engine-comparison")
    return ("engine_comparison",
            [args.ec_bin, "--repeats=%d" % args.ec_repeats, "--opa=" + args.ec_opa,
             "--output-dir=" + ec_out],
            2 * 3600,
            "{ec_out}/run_meta.json: repeats=={r} 且 opa.required==true 且 "
            "opa.reachable==true".format(ec_out=ec_out, r=args.ec_repeats))


def build_integration_step(args):
    """真实 ignored integration 步骤（L2）：argv 为显式 JSON 列表（不经 shell），
    已过 preflight 的 secret-shape 检查（L5：疑似内联秘钥一律 BLOCKED，秘钥
    经 --integration-env 以环境名称传递）；子环境 allowlist 在 main() 构造；
    运行结果 artifact 进 manifest。
    （cmd 未给/未过 preflight 校验时为空 argv——preflight 会对 active 步骤
    BLOCKED，不会带空 argv 执行。）"""
    argv = list(args.integration_cmd_list) if args.integration_cmd_list else []
    return ("integration", argv, 4 * 3600,
            "integration_result.json: exit_code==0 且 passed==true"
            "（ignored integration 真实执行且全绿；artifact 先按 rc 落盘再校验）")


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def atomic_json(path, obj):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def load_setup_provenance(path):
    try:
        raw = open(path, "rb").read()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        return None, None, "%s: %s" % (type(exc).__name__, str(exc)[:180])
    if not isinstance(data, dict):
        return None, None, "setup provenance root must be an object"
    keys = set(data)
    if keys != _SETUP_PROVENANCE_KEYS:
        return None, None, "setup provenance key mismatch missing=%s extra=%s" % (
            sorted(_SETUP_PROVENANCE_KEYS - keys), sorted(keys - _SETUP_PROVENANCE_KEYS))
    return data, hashlib.sha256(raw).hexdigest(), None


def validate_setup_provenance(data, args, run_cfg):
    expected_vhost = "rust3n_dist_%s" % args.expected_run_id
    expected_redis = "astral_dist_redis_%s" % args.expected_run_id
    expected_opa = "astral-evidence-opa-%s" % args.expected_run_id
    try:
        expected_opa_port = urlparse(args.ec_opa).port
    except ValueError:
        expected_opa_port = None
    expected_ports = run_cfg.get("ports")
    checks = {
        "run_id": data.get("run_id") == args.expected_run_id,
        "source_tar_sha256": data.get("source_tar_sha256") == args.expected_source_tar_sha256,
        "source_manifest_sha256": data.get("source_manifest_sha256") == args.expected_source_sha256,
        "dirty_patch_sha256": data.get("dirty_patch_sha256") == args.expected_dirty_patch_sha256,
        "source_git_rev": data.get("source_git_rev") == args.expected_source_git_rev,
        "trustgraph_sha256": data.get("trustgraph_sha256") == args.expected_binary_sha256,
        "engine_sha256": data.get("engine_sha256") == args.expected_engine_sha256,
        "bootstrap_sha256": data.get("bootstrap_sha256") == args.expected_bootstrap_sha256,
        "harness_combined_sha256": data.get("harness_combined_sha256") ==
                                   args.harness_provenance.get("manifest_sha256") ==
                                   args.expected_harness_sha256,
        "routing_source_sha256": data.get("routing_source_sha256") ==
                                 args.expected_routing_source_sha256,
        "routing_source_run_id": data.get("routing_source_run_id") ==
                                 args.expected_routing_source_run_id,
        "toctou_sha256": data.get("toctou_sha256") == args.expected_toctou_sha256,
        "integration_tree_sha256": data.get("integration_tree_sha256") ==
                                   args.expected_integration_tree_sha256,
        "integration_tree_files": data.get("integration_tree_files") ==
                                  INTEGRATION_EXPECTED_TREE_FILES,
        "integration_user_write_probe": data.get("integration_user_write_probe") is True,
        "integration_db": data.get("integration_db") == args.expected_integration_db,
        "integration_tables": data.get("integration_tables") == 122,
        "integration_migrations": data.get("integration_migrations") == 46,
        "opa_container": data.get("opa_container") == expected_opa,
        "opa_port": data.get("opa_port") == expected_opa_port,
        "opa_image_id": data.get("opa_image_id") == args.expected_opa_image_id,
        "opa_repo_digest": data.get("opa_repo_digest") == args.expected_opa_repo_digest,
        "rabbit_vhost": data.get("rabbit_vhost") == expected_vhost
                        and run_cfg.get("rabbit_vhost") == expected_vhost,
        "rabbit_connections": isinstance(data.get("rabbit_connections"), int)
                              and data.get("rabbit_connections") >= 3,
        "rabbit_audit_consumers": data.get("rabbit_audit_consumers") == 3,
        "rabbit_dlx_consumers": data.get("rabbit_dlx_consumers") == 3,
        "redis_container": data.get("redis_container") == expected_redis
                           and run_cfg.get("redis_container") == expected_redis,
        "redis_port": data.get("redis_port") == run_cfg.get("redis_port"),
        "node_ports": data.get("node_ports") == expected_ports,
    }
    malformed_hashes = [name for name in (
        "source_tar_sha256", "source_manifest_sha256", "dirty_patch_sha256",
        "trustgraph_sha256", "engine_sha256", "bootstrap_sha256",
        "harness_tar_sha256", "harness_manifest_file_sha256",
        "harness_combined_sha256", "routing_source_sha256", "toctou_sha256",
        "integration_tree_sha256", "integration_schema_dump_sha256", "opa_image_id")
        if not valid_sha256(data.get(name))]
    if malformed_hashes:
        return ["malformed hashes: %s" % malformed_hashes]
    return [name for name, ok in checks.items() if not ok]


def load_run_config(path):
    """Load and hash the exact secret config without returning secret fields."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as stream:
            raw = stream.read()
        digest.update(raw)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        return None, None, "%s: %s" % (type(exc).__name__, str(exc)[:180])
    if not isinstance(data, dict):
        return None, None, "run_config root must be an object"
    required = ("run_id", "nodes", "db", "mysql_container", "hmac_secret_file")
    missing = [name for name in required if not data.get(name)]
    if missing:
        return None, None, "required fields missing: %s" % missing
    nodes = data.get("nodes")
    if not isinstance(nodes, dict) or any(name not in nodes for name in ("node-a", "node-b", "node-c")):
        return None, None, "nodes must contain node-a/node-b/node-c"
    return data, digest.hexdigest(), None


def terminate_process_group(proc, grace_s=5):
    """Stop the whole step process group, then reap the direct child."""
    if proc.poll() is not None:
        return {"method": "already_exited", "pid": proc.pid,
                "returncode": proc.returncode}
    evidence = {"method": None, "pid": proc.pid, "grace_s": grace_s,
                "returncode": None, "errors": []}
    if os.name == "nt":
        evidence["method"] = "taskkill_tree"
        try:
            killed = subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=max(10, grace_s + 5))
            evidence["taskkill_exit_code"] = killed.returncode
            if killed.returncode != 0 and proc.poll() is None:
                proc.kill()
                evidence["direct_kill_after_taskkill_failure"] = True
        except Exception as exc:
            evidence["errors"].append("taskkill:%s" % type(exc).__name__)
            try:
                proc.kill()
            except Exception as kill_exc:
                evidence["errors"].append("direct_kill:%s" % type(kill_exc).__name__)
    else:
        evidence["method"] = "posix_process_group"
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception as exc:
            evidence["errors"].append("sigterm:%s" % type(exc).__name__)
        try:
            proc.wait(timeout=grace_s)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as exc:
                evidence["errors"].append("sigkill:%s" % type(exc).__name__)
    try:
        evidence["returncode"] = proc.wait(timeout=max(5, grace_s))
    except subprocess.TimeoutExpired:
        evidence["reap_timeout"] = True
    except Exception as exc:
        evidence["errors"].append("reap:%s" % type(exc).__name__)
    evidence["terminated"] = proc.poll() is not None
    return evidence


def parse_cargo_test_summary(log_path):
    """Return aggregate Cargo test counts; unknown output never proves execution."""
    pattern = re.compile(
        r"test result:\s+(ok|FAILED)\.\s+(\d+) passed;\s+(\d+) failed;\s+"
        r"(\d+) ignored;\s+(\d+) measured;\s+(\d+) filtered out")
    summaries = []
    try:
        with open(log_path, encoding="utf-8", errors="replace") as stream:
            for line in stream:
                match = pattern.search(line)
                if match:
                    summaries.append({
                        "status": match.group(1),
                        "passed": int(match.group(2)),
                        "failed": int(match.group(3)),
                        "ignored": int(match.group(4)),
                        "measured": int(match.group(5)),
                        "filtered_out": int(match.group(6)),
                    })
    except OSError as exc:
        return {"ok": False, "error": type(exc).__name__, "summaries": []}
    passed = sum(item["passed"] for item in summaries)
    failed = sum(item["failed"] for item in summaries)
    return {"ok": bool(summaries and passed > 0 and failed == 0
                       and all(item["status"] == "ok" for item in summaries)),
            "passed": passed, "failed": failed,
            "ignored": sum(item["ignored"] for item in summaries),
            "summaries": summaries}


def run_step_process(argv, cwd, env, log_path, timeout_s):
    popen_kwargs = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                    if os.name == "nt" else {"start_new_session": True})
    with open(log_path, "xb") as logf:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=logf,
                                stderr=subprocess.STDOUT, **popen_kwargs)
        try:
            return proc.wait(timeout=timeout_s), None
        except subprocess.TimeoutExpired:
            return None, terminate_process_group(proc)
        except BaseException:
            terminate_process_group(proc)
            raise


def git_rev():
    """仓库 rev（尽力而为；找不到 .git 记 None，不硬失败）。"""
    d = SCRIPT_DIR
    while True:
        if os.path.isdir(os.path.join(d, ".git")):
            try:
                r = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"],
                                   capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    return r.stdout.strip()
            except Exception:
                pass
            return None
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def classify_step_verdict(name, rc, postcondition_ok, artifact_verdict=None):
    if name == "s15_perf" and rc == 2 and artifact_verdict == "BLOCKED":
        return "BLOCKED"
    if rc == 0 and postcondition_ok:
        return "PASS"
    if rc in _UNKNOWN_RETURN_CODES.get(name, frozenset()):
        return "UNKNOWN"
    return "FAIL"


def postcondition(name, path, args=None, entry=None):
    """按步骤解析 artifact 并断言业务 postcondition。返回 (ok, detail)。
    断言只读原始结果字段，不做任何重分类。"""
    if name in ("cluster_settle", "rq_settle"):
        return True, "rc==0（无 JSON artifact；队列静默/存活/就绪守卫以 rc 为准）"
    if not os.path.isfile(path):
        return False, "artifact missing: %s" % path
    # 防陈旧：artifact 必须比运行前已存在的同名文件更新。
    pre_mt_ns = (entry or {}).get("artifact_pre_mtime_ns")
    if pre_mt_ns is not None and os.stat(path).st_mtime_ns <= pre_mt_ns:
        return False, "artifact not newer than pre-run snapshot (%s)" % path
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, "artifact unparseable: %r" % e
    if not isinstance(data, dict):
        return False, "artifact root must be an object, got %s" % type(data).__name__
    if name == "s15_coordinator":
        s = data.get("summary") or {}
        complete = data.get("complete") is True
        rounds_ok = bool(
            args is not None and args.rounds >= 3
            and data.get("rounds_done") == args.rounds
            and s.get("rounds") == args.rounds)
        pass_count = s.get("pass")
        return (complete and rounds_ok and isinstance(pass_count, int)
                and pass_count > 0 and s.get("fail") == 0), \
            "complete=%s rounds=%s/%s pass=%s fail=%s na=%s fail_items=%s blocked_reason=%s" % (
                complete, data.get("rounds_done"), args.rounds if args else None,
                pass_count, s.get("fail"), s.get("na"), s.get("fail_items"),
                data.get("blocked_reason"))
    if name == "f7_recheck":
        s = data.get("summary") or data
        return bool(s.get("all_ok")) and bool(s.get("head_monotonic")), \
            "all_ok=%s head_monotonic=%s" % (s.get("all_ok"), s.get("head_monotonic"))
    if name == "rq_fill":
        cs = data.get("cs")
        rq2 = data.get("rq2")
        expected_cs = {
            "CS1_revoke_fence_blocks_allow",
            "CS2_source_oracle_matches_projected",
            "CS3_new_grant_projection_gate",
            "CS4_overlay_deny_precedence",
            "CS5_generation_supersession",
            "CS6_unbind_fence_propagates",
            "CS7_resource_type_isolation",
            "CS8_write_alias_semantics",
        }
        if not isinstance(cs, dict) or set(cs) != expected_cs:
            return False, "cs cases incomplete: got=%s want=%s" % (
                sorted(cs) if isinstance(cs, dict) else type(cs).__name__,
                sorted(expected_cs))
        bad_cs = [key for key, value in cs.items()
                  if not isinstance(value, dict) or value.get("ok") is not True]
        if bad_cs:
            return False, "cs cases not explicit ok=True: %s" % bad_cs
        if not isinstance(rq2, dict):
            return False, "rq2 group missing or non-object"
        summary_cases = ("RQ2K_gradient_convergence", "RQ2I_gradient_convergence")
        bad_summary = [key for key in summary_cases
                       if not isinstance(rq2.get(key), dict)
                       or rq2[key].get("ok") is not True]
        if bad_summary:
            return False, "rq2 summary cases not explicit ok=True: %s" % bad_summary
        d_case = rq2.get("D_conflict_density_gradient")
        if not isinstance(d_case, dict) or d_case.get("na") is not True:
            return False, "RQ2-D must be explicit structural N/A"
        cleanup = rq2.get("cleanup_drain")
        if not isinstance(cleanup, list) or not cleanup:
            return False, "rq2.cleanup_drain missing/empty"
        cleanup_problems = []
        for index, point in enumerate(cleanup):
            if not isinstance(point, dict):
                cleanup_problems.append("cleanup[%d] non-object" % index)
                continue
            if point.get("drain_ok") is not True or point.get("decision_ok") is not True:
                cleanup_problems.append("cleanup[%d] drain/decision not true" % index)
            if not isinstance(point.get("want_allowed"), bool):
                cleanup_problems.append("cleanup[%d] want_allowed missing/non-bool" % index)
            elif point["want_allowed"] is False and point.get("no_allow_ok") is not True:
                cleanup_problems.append("cleanup[%d] deny safety not true" % index)
        if cleanup_problems:
            return False, "; ".join(cleanup_problems[:6])
        na = ["D_conflict_density_gradient"]
        # M2：K/I 梯度逐点验证（存在性 + 固定自变量集合 + 每点 ok=True +
        # 收敛证据字段）；缺字段、额外点或空梯度均拒收。
        grad_problems = []
        expected_gradients = {
            "K_rule_count_gradient": ("entries", [1, 10, 50, 100, 200]),
            "I_reference_count_gradient": ("references", [1, 2, 4, 8]),
        }
        for gname, (label_key, expected_values) in expected_gradients.items():
            pts = rq2.get(gname)
            if not isinstance(pts, list) or len(pts) != len(expected_values):
                grad_problems.append("%s count=%s want=%d" % (
                    gname, len(pts) if isinstance(pts, list) else "missing",
                    len(expected_values)))
                continue
            observed_values = []
            for i, pt in enumerate(pts):
                if not isinstance(pt, dict):
                    grad_problems.append("%s[%d] non-object" % (gname, i))
                    continue
                missing = [key for key in ("ok", "error", "converge_ms", label_key)
                           if key not in pt]
                if missing:
                    grad_problems.append("%s[%d] missing %s" % (gname, i, missing))
                elif pt["ok"] is not True or pt["converge_ms"] is None:
                    grad_problems.append("%s[%d](%s=%s) unconverged: error=%s" % (
                        gname, i, label_key, pt.get(label_key), pt.get("error")))
                observed_values.append(pt.get(label_key))
            if observed_values != expected_values:
                grad_problems.append("%s values=%s want=%s" % (
                    gname, observed_values, expected_values))
        if grad_problems:
            exc = data.get("exception") or {}
            if isinstance(exc, dict) and exc:
                grad_problems.append(
                    "artifact.exception: phase=%s type=%s msg=%s" %
                    (exc.get("phase"), exc.get("type"), exc.get("message")))
            return False, "; ".join(grad_problems[:6])
        return True, "CS1-CS8 explicit PASS; RQ2 K/I fixed gradients converged; " \
                     "cleanup gates explicit; D structural N/A"
    if name == "rq345_rq34":
        # M-B + H-3：drain/终态/非预期错误口径全须安全；403 AUTHORIZATION_PENDING
        # 为预期 fail-closed，单列 pending_403，如实保留、不要求 0。缺
        # pending_403/non_pending_errors 字段 = 旧 schema artifact，一律拒收
        # （另有 pre-mtime 防陈旧）。
        rq3 = data.get("rq3") or {}
        hf = rq3.get("high_freq_write")
        rq4 = data.get("rq4") or {}
        ls = rq4.get("long_storm_60s")
        if not rq3 or not isinstance(hf, dict) or not isinstance(ls, dict):
            return False, "rq3.high_freq_write / rq4.long_storm_60s missing (rq3_keys=%s)" % sorted(rq3.keys())

        def h3_gate(tag, blk):
            need = ("drain_complete", "deltas_terminal", "pending_403",
                    "non_pending_errors")
            missing = [k for k in need if k not in blk]
            if missing:
                return "%s 缺字段 %s（陈旧/旧 schema artifact 拒收）" % (tag, missing)
            if blk["drain_complete"] is not True or blk["deltas_terminal"] is not True:
                return "%s drain_complete=%s deltas_terminal=%s" % (
                    tag, blk["drain_complete"], blk["deltas_terminal"])
            if blk["non_pending_errors"] != 0:
                return "%s non_pending_errors=%s（pending_403=%s 单列，不要求 0）" % (
                    tag, blk["non_pending_errors"], blk["pending_403"])
            return None

        prob = h3_gate("rq3.high_freq_write", hf) or h3_gate("rq4.long_storm_60s", ls)
        if prob:
            return False, prob
        return True, "drain/deltas_terminal 安全，non_pending_errors==0（pending_403=%s/%s 为预期 fail-closed，单列）" % (
            hf["pending_403"], ls["pending_403"])
    if name == "s15_perf":
        verdict_value = data.get("verdict")
        fail_reasons = data.get("fail_reasons")
        keys = [k for k in ("P1_read_baseline", "P2_propagation", "P3_storm",
                            "pre_P4_drain", "P4_read_scaling") if k in data]
        if len(keys) != 5:
            return False, "verdict=%s fail_reasons=%s keys=%s terminal_phase=%s" % (
                verdict_value, fail_reasons, keys, data.get("terminal_phase"))
        if verdict_value != "PASS":
            return False, "verdict=%s fail_reasons=%s terminal_phase=%s cleanup_ok=%s" % (
                verdict_value, fail_reasons, data.get("terminal_phase"),
                (data.get("preflight_cleanup") or {}).get("ok"))
        if fail_reasons != []:
            return False, "verdict=PASS but fail_reasons=%s" % fail_reasons
        return True, "keys ok + verdict==PASS + cleanup/teardown producer gates passed"
    if name == "rq345_rq5":
        rq5 = data.get("rq5") or {}
        need = [k for k in ("E4_cache_repopulation", "E11_stale_replay_context",
                            "E3E5_throughput") if k in rq5]
        if len(need) != 3:
            return False, "rq5_keys=%s" % need
        e11 = rq5.get("E11_stale_replay_context") or {}
        if e11.get("anomalies", 1) != 0 or e11.get("captured_replay_allow_anomalies", 1) != 0:
            return False, "E11 anomalies=%s replay_allows=%s" % (
                e11.get("anomalies"), e11.get("captured_replay_allow_anomalies"))
        if e11.get("stale_timestamp_rejected") is not True or e11.get("cross_card_denied", 0) != 3:
            return False, "E11 stale_ts_rejected=%s cross_card_denied=%s (want true/3)" % (
                e11.get("stale_timestamp_rejected"), e11.get("cross_card_denied"))
        pts = (rq5.get("E3E5_throughput") or {}).get("points") or []
        if not pts or any(p.get("errors", 1) != 0 for p in pts):
            return False, "E3E5 points=%s errors=%s" % (
                len(pts), [p.get("errors") for p in pts])
        return True, "E11 anomalies==0 且 E3+E5 各点 errors==0"
    if name == "toctou_race":
        v = data.get("verdict")
        return v == "PASS", "verdict=%s total_hard_stale=%s errors(net/http/parse)=%s/%s/%s hung=%s" % (
            v, data.get("total_hard_stale"), data.get("total_network_errors"),
            data.get("total_http_errors"), data.get("total_parse_errors"),
            data.get("total_hung_threads"))
    if name == "engine_comparison":
        if args is None:
            return False, "ec args missing"
        # H-B：直接断言 --output-dir 指定目录的 run_meta.json（无扫描）。
        if data.get("repeats") != args.ec_repeats:
            return False, "repeats=%s (want %s)" % (data.get("repeats"), args.ec_repeats)
        opa = data.get("opa") or {}
        if opa.get("required") is not True:
            return False, "opa.required=%s (want true)" % opa.get("required")
        if opa.get("reachable") is not True:
            return False, "opa.reachable=%s" % opa.get("reachable")
        return True, "repeats=%s opa(required=%s reachable=%s version=%s)" % (
            data.get("repeats"), opa.get("required"), opa.get("reachable"),
            opa.get("version"))
    if name == "integration":
        # The orchestrator-authored result must prove both rc==0 and >0 tests.
        counts = data.get("test_counts")
        if data.get("exit_code") != 0 or data.get("passed") is not True:
            return False, "exit_code=%s passed=%s" % (data.get("exit_code"), data.get("passed"))
        if not isinstance(counts, dict) or counts.get("ok") is not True \
                or counts.get("passed") != INTEGRATION_EXPECTED_TESTS \
                or counts.get("failed") != 0:
            return False, "ignored integration execution unproven: counts=%s expected=%s" % (
                counts, INTEGRATION_EXPECTED_TESTS)
        return True, "exit_code==0 tests_passed=%s failed=0" % counts.get("passed")
    return False, "unknown step %s" % name


def blocked(reason):
    print("BLOCKED: %s" % reason, flush=True)
    return 2


def finalize_overall(overall, verdicts, explicit_scope):
    """Fold step verdicts into the campaign verdict without hiding failures."""
    counts = {v: verdicts.count(v)
              for v in ("PASS", "FAIL", "UNKNOWN", "BLOCKED", "SKIP")
              if verdicts.count(v)}
    if counts.get("FAIL", 0) or counts.get("UNKNOWN", 0) or counts.get("BLOCKED", 0):
        return "FAIL", counts
    if counts.get("PASS", 0) < 1:
        return "FAIL", counts
    if counts.get("SKIP", 0):
        return ("PASS_WITH_SKIPS" if explicit_scope else "FAIL"), counts
    return "PASS", counts


def preflight(args, active_names):
    """BLOCKED preconditions are checked before any campaign step starts.

    Malformed or unreadable run config is rejected here, and the outer
    rq_settle timeout remains above its internal readiness plus drain budgets.
    """
    if args.rounds < 3:
        return blocked("--rounds 必须 >=3（S14/S15 最小样本口径；禁止空/退化运行）")
    if args.ec_repeats < 5 and "engine_comparison" in active_names:
        return blocked("--ec-repeats 必须 >=5（最终 campaign 固定重复次数）")
    if os.path.exists(args.out_dir) and not os.path.isdir(args.out_dir):
        return blocked("--out-dir 已存在但不是目录")
    if os.path.isdir(args.out_dir):
        allowed = set()
        if os.path.dirname(args.setup_provenance) == args.out_dir:
            allowed.add(os.path.basename(args.setup_provenance))
        unexpected = sorted(set(os.listdir(args.out_dir)) - allowed)
        if unexpected:
            return blocked("--out-dir 非 fresh-only，存在 campaign 产物: %s" % unexpected[:12])
    harness = harness_sha256()
    if not harness["complete"]:
        return blocked("harness allowlist 不完整: %s" % harness["missing"])
    if harness["manifest_sha256"].lower() != args.expected_harness_sha256.lower():
        return blocked("harness combined sha256 mismatch")
    args.harness_provenance = harness
    if not args.run_config:
        return blocked("缺 --run-config（run_config.json 属 0600 run 秘密文件，"
                       "留在 $HOME/$RUN_ID/，经 --run-config 显式传入；不复制进源码目录）")
    if not os.path.isfile(args.run_config):
        return blocked("run_config.json 不存在: %s（先在 node-b 执行 deploy_dist.sh "
                       "生成；本编排不负责部署）" % args.run_config)
    run_cfg, run_cfg_sha, config_error = load_run_config(args.run_config)
    if config_error:
        return blocked("run_config.json 不可读或非法: %s（不回显文件内容）" % config_error)
    args.run_config_data = run_cfg
    args.run_config_sha256 = run_cfg_sha
    provenance_required = ("binary_sha256", "source_snapshot_sha256", "source_git_rev",
                           "source_dirty_patch_sha256", "bootstrap_bin_sha256")
    provenance_missing = [name for name in provenance_required if not run_cfg.get(name)]
    if provenance_missing:
        return blocked("run_config provenance fields missing: %s" % provenance_missing)
    expected_hashes = {
        "binary_sha256": args.expected_binary_sha256,
        "source_snapshot_sha256": args.expected_source_sha256,
        "source_dirty_patch_sha256": args.expected_dirty_patch_sha256,
        "bootstrap_bin_sha256": args.expected_bootstrap_sha256,
    }
    invalid_hash_args = [name for name, value in expected_hashes.items()
                         if not valid_sha256(value)]
    if not valid_sha256(args.expected_source_tar_sha256):
        invalid_hash_args.append("source_tar_sha256")
    if not valid_sha256(args.expected_routing_source_sha256):
        invalid_hash_args.append("routing_source_sha256")
    if not valid_sha256(args.expected_harness_sha256):
        invalid_hash_args.append("harness_sha256")
    if not valid_sha256(args.expected_toctou_sha256):
        invalid_hash_args.append("toctou_sha256")
    if not valid_sha256(args.expected_integration_tree_sha256):
        invalid_hash_args.append("integration_tree_sha256")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", args.expected_routing_source_run_id or ""):
        invalid_hash_args.append("routing_source_run_id")
    if not valid_sha256(args.expected_opa_image_id):
        invalid_hash_args.append("opa_image_id")
    if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-fA-F]{64}",
                        args.expected_opa_repo_digest or ""):
        invalid_hash_args.append("opa_repo_digest")
    if not re.fullmatch(r"[A-Za-z0-9_]+", args.expected_integration_db or "") \
            or "test" not in args.expected_integration_db:
        invalid_hash_args.append("integration_db")
    if not valid_sha256(args.expected_engine_sha256):
        invalid_hash_args.append("engine_sha256")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", args.expected_source_git_rev or ""):
        invalid_hash_args.append("source_git_rev")
    if invalid_hash_args:
        return blocked("expected provenance identities malformed: %s" % invalid_hash_args)
    expected_identities = dict(expected_hashes)
    expected_identities["source_git_rev"] = args.expected_source_git_rev
    if run_cfg.get("run_id") != args.expected_run_id:
        return blocked("run_config run_id mismatch: got=%s expected=%s" %
                       (run_cfg.get("run_id"), args.expected_run_id))
    mismatches = [name for name, expected in expected_identities.items()
                  if str(run_cfg.get(name, "")).lower() != expected.lower()]
    if mismatches:
        return blocked("run_config provenance mismatch: %s" % mismatches)
    setup_data, setup_sha, setup_error = load_setup_provenance(args.setup_provenance)
    if setup_error:
        return blocked("setup provenance unavailable: %s" % setup_error)
    setup_problems = validate_setup_provenance(setup_data, args, run_cfg)
    if setup_problems:
        return blocked("setup provenance mismatch: %s" % setup_problems)
    args.setup_provenance_data = setup_data
    args.setup_provenance_sha256 = setup_sha
    if "engine_comparison" in active_names:
        if not args.ec_bin:
            return blocked("engine_comparison 步骤缺 --ec-bin（不提供即 BLOCKED；"
                           "确不采集该证据请显式 --skip engine_comparison，会在 manifest 记 SKIP）")
        if not os.path.isfile(args.ec_bin):
            return blocked("engine-comparison 二进制不存在: %s" % args.ec_bin)
        if not os.access(args.ec_bin, os.X_OK):
            return blocked("engine-comparison 二进制不可执行: %s" % args.ec_bin)
        engine_sha = file_sha256(args.ec_bin)
        args.engine_sha256 = engine_sha
        if engine_sha.lower() != args.expected_engine_sha256.lower():
            return blocked("engine-comparison sha256 mismatch")
        if not os.path.isdir(args.ec_cwd):
            return blocked("--ec-cwd 不是目录: %s" % args.ec_cwd)
        # OPA sidecar 软探测（二进制内 OPA 为必需引擎，不可达会 exit 2；此处
        # 提前 BLOCKED，避免空耗数小时编排）。
        try:
            import requests  # noqa: E402
            r = requests.get(args.ec_opa.rstrip("/") + "/health", timeout=5)
            if not 200 <= r.status_code < 300:
                return blocked("OPA sidecar 异常（%s/health -> %d）" % (args.ec_opa, r.status_code))
        except ImportError:
            print("WARN: 无 requests，跳过 OPA 预探测（由 engine-comparison 二进制自校验）", flush=True)
        except Exception as e:
            return blocked("OPA sidecar 不可达（%s/health: %r）——OPA 为必需引擎；"
                           "确不采集该证据请显式 --skip engine_comparison" % (args.ec_opa, e))
    if "integration" in active_names:
        # L2：命令必须是显式 argv 列表（JSON），不经 shell，防任意命令拼接。
        if not args.integration_cmd:
            return blocked("integration 步骤缺 --integration-cmd（JSON argv 列表；"
                           "确不采集请显式 --skip integration，会在 manifest 记 SKIP）")
        try:
            lst = json.loads(args.integration_cmd)
        except Exception:
            return blocked("--integration-cmd 不是合法 JSON（示例："
                           "'[\"cargo\",\"test\",\"--locked\",\"-p\",\"astral-db\","
                           "\"--test\",\"authorization_projection_integration\",\"--release\","
                           "\"--\",\"--ignored\",\"--test-threads=1\"]'）")
        if not (isinstance(lst, list) and lst and all(isinstance(x, str) and x for x in lst)):
            return blocked("--integration-cmd 必须是非空字符串数组（不含 shell 元语法）")
        # L5：argv 会进 manifest/log，先拒绝疑似内联秘钥（--password/--token/
        # 凭据 URL/Authorization 头/秘密 env 赋值）；秘钥走 --integration-env
        # 环境名称，值不入 argv/manifest/log。
        findings = integration_secret_findings(lst)
        if findings:
            return blocked("integration argv 含疑似内联秘钥/凭据：%s；秘钥一律经 "
                           "--integration-env 以环境名称传递，值不得进 "
                           "argv/manifest/log" % "; ".join(findings))
        argv_problems = validate_integration_argv(lst, args.integration_cwd)
        if argv_problems:
            return blocked("integration argv 非 canonical ignored test: %s" % argv_problems)
        conflicting_env = sorted(set(args.integration_env) & set(_BASE_ENV_ALLOWLIST))
        if conflicting_env:
            return blocked("--integration-env 不得重复基础环境名: %s" % conflicting_env)
        args.integration_cmd_list = lst
        if not args.integration_cwd:
            return blocked("integration 步骤缺 --integration-cwd")
        if not os.path.isdir(args.integration_cwd):
            return blocked("--integration-cwd 不是目录: %s" % args.integration_cwd)
        missing = [n for n in args.integration_env if not os.environ.get(n)]
        if missing:
            return blocked("integration required env 缺失: %s（值不入 manifest；"
                           "前置缺失整体 BLOCKED，不静默 skip）" % missing)
    runtime_inputs, runtime_error = runtime_input_snapshot(args, active_names)
    if runtime_error:
        return blocked("runtime source input fence failed: %s" % runtime_error)
    args.runtime_input_provenance = runtime_inputs
    return None


def append_remaining_skips(manifest, remaining_plan, only, skip, reason):
    for later in remaining_plan:
        later_name = later[0]
        if only and later_name not in only:
            detail = "not selected via --only"
        elif later_name in skip:
            detail = "excluded via --skip"
        else:
            detail = reason
        manifest["steps"].append({"step": later_name, "verdict": "SKIP",
                                  "detail": detail})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-config", required=True,
                    help="run_config.json 路径（0600 run 秘密文件，留在 $HOME/$RUN_ID/，"
                         "不复制进源码目录；经 RUN_CONFIG_PATH 传给全部子脚本）")
    ap.add_argument("--setup-provenance", required=True,
                    help="final6 setup_provenance.json（固定键、零秘密、每步哈希复核）")
    ap.add_argument("--expected-run-id", required=True,
                    help="本 campaign 的稳定 run id，必须与 run_config.run_id 完全一致")
    ap.add_argument("--expected-binary-sha256", required=True)
    ap.add_argument("--expected-source-sha256", required=True)
    ap.add_argument("--expected-source-tar-sha256", required=True)
    ap.add_argument("--expected-source-git-rev", required=True)
    ap.add_argument("--expected-dirty-patch-sha256", required=True)
    ap.add_argument("--expected-bootstrap-sha256", required=True)
    ap.add_argument("--expected-engine-sha256", required=True)
    ap.add_argument("--expected-harness-sha256", required=True)
    ap.add_argument("--expected-routing-source-sha256", required=True)
    ap.add_argument("--expected-routing-source-run-id", required=True)
    ap.add_argument("--expected-toctou-sha256", required=True)
    ap.add_argument("--expected-integration-tree-sha256", required=True)
    ap.add_argument("--expected-integration-db", required=True)
    ap.add_argument("--expected-opa-image-id", required=True)
    ap.add_argument("--expected-opa-repo-digest", required=True)
    ap.add_argument("--out-dir", default=os.path.join(SCRIPT_DIR, "evidence_%s" % time.strftime("%Y%m%d_%H%M%S")))
    ap.add_argument("--rounds", type=int, default=3,
                    help="s15_coordinator --rounds（默认 3，满足 S14/S15 样本量 >= 3）")
    ap.add_argument("--skip", default="", help="逗号分隔的步骤名（记为 SKIP）")
    ap.add_argument("--only", default=None, help="只跑这些步骤（未选中的步骤记 SKIP）")
    ap.add_argument("--keep-going", action="store_true", help="某步 FAIL 后继续后续步骤")
    # engine-comparison 步骤
    ap.add_argument("--ec-bin", default=None,
                    help="engine-comparison release 二进制路径（步骤必需，缺失即 BLOCKED）")
    ap.add_argument("--ec-cwd", default=None,
                    help="engine-comparison 执行 cwd（默认 --ec-bin 所在目录；--output-dir 仍指向 out-dir）")
    ap.add_argument("--ec-repeats", type=int, default=5,
                    help="engine-comparison --repeats（默认 5）")
    ap.add_argument("--ec-opa", default="http://127.0.0.1:8181",
                    help="OPA sidecar 基址（默认 http://127.0.0.1:8181；OPA 为必需引擎）")
    # 真实 ignored integration 步骤
    ap.add_argument("--integration-cmd", default=None,
                    help="integration 命令（JSON argv 列表，不经 shell；如 "
                         "'[\"cargo\",\"test\",\"--locked\",\"-p\",\"astral-db\","
                         "\"--test\",\"authorization_projection_integration\",\"--release\","
                         "\"--\",\"--ignored\",\"--test-threads=1\"]'；缺失即 BLOCKED）")
    ap.add_argument("--integration-cwd", default=None,
                    help="integration 命令工作目录（如 AstralLight-Next workspace 根）")
    ap.add_argument("--integration-env", default="",
                    help="逗号分隔的 required env 名称（只记名称不记值；任一未设置即 BLOCKED；"
                         "子环境按 allowlist 构建）")
    args = ap.parse_args()
    args.integration_env = [n.strip() for n in args.integration_env.split(",") if n.strip()]
    args.integration_cmd_list = None
    args.run_config_data = None
    args.run_config_sha256 = None
    args.engine_sha256 = None
    args.harness_provenance = None
    args.setup_provenance_data = None
    args.setup_provenance_sha256 = None
    args.runtime_input_provenance = None
    args.run_config = os.path.abspath(os.path.expanduser(args.run_config))
    args.setup_provenance = os.path.abspath(os.path.expanduser(args.setup_provenance))
    # out_dir 绝对化：engine-comparison --output-dir 需要确定路径（其执行 cwd
    # 是 --ec-cwd，相对路径会落到错误位置）。
    args.out_dir = os.path.abspath(args.out_dir)
    if args.ec_bin:
        args.ec_bin = os.path.abspath(args.ec_bin)
    if args.ec_cwd:
        args.ec_cwd = os.path.abspath(args.ec_cwd)
    if not args.ec_cwd and args.ec_bin:
        args.ec_cwd = os.path.dirname(args.ec_bin)

    plan = list(STEPS)
    plan.append(build_toctou_step(args.run_config))
    plan.append(build_ec_step(args, args.out_dir))
    plan.append(build_integration_step(args))
    skip = set(args.skip.split(",")) - {""}
    only = set(args.only.split(",")) if args.only else None
    plan_names = [s[0] for s in plan]

    # ---- BLOCKED 计划形状检查：未知步骤名 / 过滤后 active 为空一律不启动 ----
    # （M1：--skip 拼错会静默放过本应排除的步骤；--only 全不匹配则会产生
    # 0 步编排——两者都不允许，fail-closed。）
    unknown = sorted((skip | (only or set())) - set(plan_names))
    if unknown:
        return blocked("--skip/--only 含未知步骤名: %s（已知: %s）" % (unknown, plan_names))
    active = [n for n in plan_names if (only is None or n in only) and n not in skip]
    if not active:
        return blocked("--only/--skip 过滤后 active 步骤集为空：0 步编排不允许"
                       "（绝不出现 0 steps overall PASS；确需空集请勿运行编排）")
    rc = preflight(args, active)
    if rc is not None:
        return rc
    # preflight 通过后才把 integration 的显式 argv 装入计划（L2：执行 argv 只能
    # 是 preflight 校验过的 JSON 字符串数组，未经校验绝不下发）；integration
    # 未激活（--skip/--only）时 preflight 不解析 cmd，计划保持空 argv（不执行）。
    for i, step in enumerate(plan):
        if step[0] == "integration" and args.integration_cmd_list:
            plan[i] = (step[0], list(args.integration_cmd_list), step[2], step[3])

    # 子进程环境：RUN_CONFIG_PATH 显式指向 run_config（0600 秘密文件留在原位，
    # 不复制进源码目录）；manifest 只记录路径/sha256 与 env 名称，不记秘钥值。
    child_env = dict(os.environ)
    child_env["RUN_CONFIG_PATH"] = args.run_config
    # integration 专属 env（如 DATABASE_URL/RUST_INTEGRATION_REQUIRED）绝不进入
    # 其他步骤的子环境：astral-common 的 flat-env 契约会用 DATABASE_URL 覆盖
    # application.yml，协调器本地启动的 node-b 会被改道到隔离集成库（2026-09-04
    # 实测根因：node-b SUPERADMIN_INIT_FAILED 而 ssh 启动的 a/c 正常）。
    for _n in args.integration_env:
        child_env.pop(_n, None)

    # L2：integration 子环境 allowlist——不继承调用环境的任意变量（部署 shell
    # 里可能残留 MYSQL_ROOT/RABBIT_PASS 等秘钥），只有基础环境名 + 显式 required
    # env + RUN_CONFIG_PATH 进入子环境。
    integration_child_env = {key: os.environ[key]
                             for key in _BASE_ENV_ALLOWLIST if key in os.environ}
    for n in args.integration_env:
        integration_child_env[n] = os.environ[n]
    integration_child_env["RUN_CONFIG_PATH"] = args.run_config

    # run_config 已在 preflight 中读取并哈希；后续只使用同一内存快照，
    # 避免通过后再次解析失败或悄然换成另一份配置。
    run_cfg = args.run_config_data
    run_cfg_sha256 = args.run_config_sha256

    os.makedirs(args.out_dir, exist_ok=True)
    manifest = {
        "meta": {
            "started_at_utc": utc(),
            "host": socket.gethostname(),
            "python": sys.version.split()[0],
            "script_dir": SCRIPT_DIR,
            "git_rev": git_rev(),
            "env_names_only": True,   # 秘钥值永不入 manifest/日志
            "rounds": args.rounds,
            "plan": plan_names,
            "toctou": {"cycles": TOCTOU_CYCLES, "readers": TOCTOU_READERS,
                        "script": TOCTOU_RACE,
                        "sha256": args.runtime_input_provenance.get("toctou_sha256"),
                        "expected_sha256": args.expected_toctou_sha256},
            "engine_comparison": {"repeats": args.ec_repeats, "opa_base": args.ec_opa,
                                  "opa_required": True, "bin": args.ec_bin,
                                  "binary_sha256": args.engine_sha256,
                                  "expected_binary_sha256": args.expected_engine_sha256,
                                  "cwd": args.ec_cwd,
                                  "output_dir": os.path.join(args.out_dir, "engine-comparison")},
            "integration": {"argv": args.integration_cmd_list,
                            "cwd": args.integration_cwd,
                            "required_env_names": args.integration_env,
                            "env_allowlist_names": sorted(integration_child_env.keys()),
                            "tree_sha256": args.runtime_input_provenance.get(
                                "integration_tree_sha256"),
                            "tree_files": args.runtime_input_provenance.get(
                                "integration_tree_files"),
                            "expected_tree_sha256": args.expected_integration_tree_sha256},
            "run_config_path": args.run_config,
            "run_config_sha256": run_cfg_sha256,
            "setup_provenance_path": args.setup_provenance,
            "setup_provenance_sha256": args.setup_provenance_sha256,
            "setup_provenance": args.setup_provenance_data,
            "expected_run_id": args.expected_run_id,
            "expected_provenance": {
                "binary_sha256": args.expected_binary_sha256,
                "source_snapshot_sha256": args.expected_source_sha256,
                "source_tar_sha256": args.expected_source_tar_sha256,
                "source_git_rev": args.expected_source_git_rev,
                "source_dirty_patch_sha256": args.expected_dirty_patch_sha256,
                "bootstrap_bin_sha256": args.expected_bootstrap_sha256,
                "engine_binary_sha256": args.expected_engine_sha256,
                "harness_sha256": args.expected_harness_sha256,
                "routing_source_sha256": args.expected_routing_source_sha256,
                "routing_source_run_id": args.expected_routing_source_run_id,
                "toctou_sha256": args.expected_toctou_sha256,
                "integration_tree_sha256": args.expected_integration_tree_sha256,
                "integration_db": args.expected_integration_db,
                "opa_image_id": args.expected_opa_image_id,
                "opa_repo_digest": args.expected_opa_repo_digest,
            },
            "harness_provenance": args.harness_provenance,
            "runtime_input_provenance": args.runtime_input_provenance,
            "run_provenance": {k: run_cfg.get(k) for k in
                               ("run_id", "binary_sha256", "git_rev",
                                "source_snapshot_sha256", "source_git_rev",
                                "source_dirty", "source_dirty_patch_sha256",
                                "bootstrap_bin_sha256", "db", "redis_container",
                                "redis_port", "rabbit_vhost", "ports")},
        },
        "steps": [],
    }
    manifest_path = os.path.join(args.out_dir, "cs_evidence_manifest.json")
    atomic_json(manifest_path, manifest)
    print("manifest: %s" % manifest_path, flush=True)

    overall = "PASS"
    for idx, (name, argv_tpl, timeout_s, post_desc) in enumerate(plan):
        if only and name not in only:
            manifest["steps"].append({
                "step": name, "verdict": "SKIP",
                "detail": "not selected via --only（显式记录，不静默消失）"})
            atomic_json(manifest_path, manifest)
            print("[SKIP] %s (--only)" % name, flush=True)
            continue
        if name in skip:
            manifest["steps"].append({
                "step": name, "verdict": "SKIP", "detail": "excluded via --skip"})
            atomic_json(manifest_path, manifest)
            print("[SKIP] %s" % name, flush=True)
            continue

        setup_now, setup_sha_now, setup_error_now = load_setup_provenance(
            args.setup_provenance)
        if (setup_error_now or setup_now is None
                or setup_sha_now != args.setup_provenance_sha256):
            entry = {
                "step": name, "start_utc": utc(), "end_utc": utc(),
                "exit_code": None, "verdict": "BLOCKED",
                "detail": "setup provenance changed or became unreadable before dispatch",
                "setup_provenance_error": setup_error_now,
            }
            manifest["steps"].append(entry)
            atomic_json(manifest_path, manifest)
            overall = "FAIL"
            append_remaining_skips(
                manifest, plan[idx + 1:], only, skip,
                "not run: setup provenance BLOCKED before %s" % name)
            atomic_json(manifest_path, manifest)
            break

        current_harness = harness_sha256()
        if (not current_harness["complete"]
                or current_harness["manifest_sha256"] !=
                args.harness_provenance["manifest_sha256"]):
            entry = {
                "step": name, "start_utc": utc(), "end_utc": utc(),
                "exit_code": None, "verdict": "BLOCKED",
                "detail": "harness changed or became incomplete before dispatch",
                "harness_manifest_sha256": current_harness["manifest_sha256"],
            }
            manifest["steps"].append(entry)
            atomic_json(manifest_path, manifest)
            overall = "FAIL"
            append_remaining_skips(
                manifest, plan[idx + 1:], only, skip,
                "not run: harness BLOCKED before %s" % name)
            atomic_json(manifest_path, manifest)
            break

        current_runtime_inputs, runtime_input_error = runtime_input_snapshot(args, active)
        if (runtime_input_error or current_runtime_inputs !=
                args.runtime_input_provenance):
            entry = {
                "step": name, "start_utc": utc(), "end_utc": utc(),
                "exit_code": None, "verdict": "BLOCKED",
                "detail": "runtime source input changed or became unreadable before dispatch",
                "runtime_input_error": runtime_input_error,
                "runtime_inputs": current_runtime_inputs,
            }
            manifest["steps"].append(entry)
            atomic_json(manifest_path, manifest)
            overall = "FAIL"
            append_remaining_skips(
                manifest, plan[idx + 1:], only, skip,
                "not run: runtime source input BLOCKED before %s" % name)
            atomic_json(manifest_path, manifest)
            break

        # Re-hash before each dispatch: a campaign may not silently switch
        # run_config after the provenance snapshot was accepted.
        _, current_run_config_sha, config_error = load_run_config(args.run_config)
        if config_error or current_run_config_sha != run_cfg_sha256:
            entry = {
                "step": name, "start_utc": utc(), "end_utc": utc(),
                "exit_code": None, "verdict": "BLOCKED",
                "detail": "run_config changed or became unreadable before dispatch",
                "run_config_error": config_error,
            }
            manifest["steps"].append(entry)
            atomic_json(manifest_path, manifest)
            overall = "FAIL"
            append_remaining_skips(
                manifest, plan[idx + 1:], only, skip,
                "not run: run_config BLOCKED before %s" % name)
            atomic_json(manifest_path, manifest)
            break

        argv = render_argv(name, argv_tpl, args.out_dir, args.rounds)
        log_path = os.path.join(args.out_dir, "%s.log" % name)
        if name == "engine_comparison":
            # H-B：直接断言 --output-dir 指定目录的 run_meta.json
            artifact = os.path.join(args.out_dir, "engine-comparison", "run_meta.json")
            step_cwd = args.ec_cwd
        elif name == "integration":
            artifact = os.path.join(args.out_dir, "integration_result.json")
            step_cwd = args.integration_cwd
        else:
            artifact = os.path.join(args.out_dir, "%s.json" % name)
            step_cwd = SCRIPT_DIR
        step_env = integration_child_env if name == "integration" else child_env
        entry = {
            "step": name,
            "argv": argv,
            "cwd": step_cwd,
            "env_names": sorted(step_env.keys()),   # 仅名称；值不落盘
            "start_utc": utc(),
            "timeout_s": timeout_s,
            "log": log_path,
            "artifact": artifact,
            "postcondition": post_desc,
            "run_config_sha256_before": current_run_config_sha,
            "harness_manifest_sha256_before": current_harness["manifest_sha256"],
            "setup_provenance_sha256_before": setup_sha_now,
            "runtime_inputs_before": current_runtime_inputs,
        }
        # Every JSON-producing step rejects an artifact that predates this run.
        if name not in ("cluster_settle", "rq_settle") and os.path.isfile(artifact):
            entry["artifact_pre_mtime_ns"] = os.stat(artifact).st_mtime_ns
        print("== [%s] %s" % (name, " ".join(argv)), flush=True)
        verdict, rc, detail = "UNKNOWN", None, ""
        interrupted = False
        secret_stop = False
        try:
            rc, timeout_cleanup = run_step_process(
                argv, entry["cwd"], step_env, log_path, timeout_s)
            if timeout_cleanup is not None:
                entry["timeout_cleanup"] = timeout_cleanup
                detail = "timeout after %ss; process group terminated; result UNKNOWN, reconcile first" % timeout_s
                verdict = "UNKNOWN"
            else:
                if name == "integration":
                    test_counts = parse_cargo_test_summary(log_path)
                    atomic_json(entry["artifact"], {
                        "step": "integration",
                        "argv": args.integration_cmd_list,
                        "cwd": args.integration_cwd,
                        "required_env_names": args.integration_env,
                        "env_allowlist_names": sorted(integration_child_env.keys()),
                        "exit_code": rc,
                        "passed": rc == 0 and test_counts.get("ok") is True,
                        "test_counts": test_counts,
                        "log": log_path,
                        "start_utc": entry["start_utc"],
                        "end_utc": utc(),
                    })
                ok, pdetail = postcondition(name, entry["artifact"], args, entry)
                artifact_verdict = None
                if name == "s15_perf" and os.path.isfile(entry["artifact"]):
                    try:
                        artifact_mtime = os.stat(entry["artifact"]).st_mtime_ns
                        pre_mtime = entry.get("artifact_pre_mtime_ns")
                        if pre_mtime is None or artifact_mtime > pre_mtime:
                            with open(entry["artifact"], encoding="utf-8") as stream:
                                artifact_data = json.load(stream)
                            if isinstance(artifact_data, dict):
                                artifact_verdict = artifact_data.get("verdict")
                    except Exception:
                        artifact_verdict = None
                verdict = classify_step_verdict(name, rc, ok, artifact_verdict)
                detail = "rc=%s postcondition: %s" % (rc, pdetail)
                if verdict == "UNKNOWN":
                    detail += "; child self-reported UNKNOWN, reconcile before retry"
        except KeyboardInterrupt:
            interrupted = True
            rc = None
            detail = "orchestrator interrupted; process group terminated; result UNKNOWN"
            verdict = "UNKNOWN"
        except OSError as exc:
            rc = None
            detail = "step I/O or spawn failure: %s" % type(exc).__name__
            verdict = "FAIL"
        except Exception as exc:
            rc = rc if rc is not None else None
            detail = "step postprocessing failure: %s:%s" % (
                type(exc).__name__, str(exc)[:300])
            verdict = "FAIL"
        after_setup, after_setup_sha, after_setup_error = load_setup_provenance(
            args.setup_provenance)
        entry["setup_provenance_sha256_after"] = after_setup_sha
        if (after_setup_error or after_setup is None
                or after_setup_sha != args.setup_provenance_sha256):
            verdict = "BLOCKED"
            detail = "setup provenance changed or became unreadable during %s" % name
        after_harness = harness_sha256()
        entry["harness_manifest_sha256_after"] = after_harness["manifest_sha256"]
        if (not after_harness["complete"]
                or after_harness["manifest_sha256"] !=
                args.harness_provenance["manifest_sha256"]):
            verdict = "BLOCKED"
            detail = "harness changed or became incomplete during %s" % name
        after_runtime_inputs, after_runtime_error = runtime_input_snapshot(args, active)
        entry["runtime_inputs_after"] = after_runtime_inputs
        if (after_runtime_error or after_runtime_inputs !=
                args.runtime_input_provenance):
            entry["runtime_input_error_after"] = after_runtime_error
            verdict = "BLOCKED"
            detail = "runtime source input changed or became unreadable during %s" % name
        _, after_sha, after_error = load_run_config(args.run_config)
        entry["run_config_sha256_after"] = after_sha
        if after_error or after_sha != run_cfg_sha256:
            entry["run_config_error_after"] = after_error
            verdict = "BLOCKED"
            detail = "run_config changed or became unreadable during %s" % name
        scan_result = runtime_secret_scan_gate(args.run_config, [log_path])
        entry["runtime_secret_scan"] = scan_result
        if not scan_result.get("ok"):
            verdict = "FAIL"
            detail = (detail + "; runtime_secret_scan FAIL (counts withheld)")[:500]
            secret_stop = True
        entry.update({
            "end_utc": utc(),
            "exit_code": rc,
            "verdict": verdict,
            "detail": detail[:500],
        })
        manifest["steps"].append(entry)
        atomic_json(manifest_path, manifest)
        print("[%s] %s — %s" % (verdict, name, detail[:160]), flush=True)

        if verdict in ("FAIL", "UNKNOWN", "BLOCKED"):
            overall = "FAIL"
            if interrupted or not args.keep_going or secret_stop:
                # 安全顺序依赖前序成功（混沌恢复、空闲基线）；失败后默认停止，
                # 剩余步骤显式记 SKIP（不静默继续产出污染证据）。
                append_remaining_skips(
                    manifest, plan[idx + 1:], only, skip,
                    "not run: %s %s before" % (name, verdict))
                atomic_json(manifest_path, manifest)
                break

    final_config, final_sha, final_error = load_run_config(args.run_config)
    manifest["meta"]["run_config_sha256_final"] = final_sha
    manifest["meta"]["run_config_final_error"] = final_error
    config_final_ok = bool(final_config is not None and final_error is None
                           and final_sha == run_cfg_sha256)
    manifest["meta"]["run_config_final_match"] = config_final_ok
    final_setup, final_setup_sha, final_setup_error = load_setup_provenance(
        args.setup_provenance)
    setup_final_ok = bool(
        final_setup is not None and final_setup_error is None
        and final_setup_sha == args.setup_provenance_sha256
        and not validate_setup_provenance(final_setup, args, run_cfg))
    manifest["meta"]["setup_provenance_sha256_final"] = final_setup_sha
    manifest["meta"]["setup_provenance_final_error"] = final_setup_error
    manifest["meta"]["setup_provenance_final_match"] = setup_final_ok
    final_harness = harness_sha256()
    harness_final_ok = bool(
        final_harness["complete"]
        and final_harness["manifest_sha256"] ==
        args.harness_provenance["manifest_sha256"])
    manifest["meta"]["harness_manifest_sha256_final"] = final_harness["manifest_sha256"]
    manifest["meta"]["harness_final_match"] = harness_final_ok
    final_runtime_inputs, final_runtime_error = runtime_input_snapshot(args, active)
    runtime_inputs_final_ok = bool(
        final_runtime_error is None
        and final_runtime_inputs == args.runtime_input_provenance)
    manifest["meta"]["runtime_inputs_final"] = final_runtime_inputs
    manifest["meta"]["runtime_inputs_final_error"] = final_runtime_error
    manifest["meta"]["runtime_inputs_final_match"] = runtime_inputs_final_ok
    final_secret_scan = runtime_secret_scan_gate(args.run_config, [args.out_dir])
    manifest["meta"]["runtime_secret_scan_final"] = final_secret_scan
    secret_scan_final_ok = bool(final_secret_scan.get("ok"))
    manifest["meta"]["runtime_secret_scan_final_verdict"] = (
        "PASS" if secret_scan_final_ok else "FAIL")
    if not secret_scan_final_ok:
        overall = "FAIL"
    if not config_final_ok:
        overall = "FAIL"
        manifest["meta"]["run_config_final_verdict"] = "BLOCKED"
        manifest["meta"]["run_config_final_detail"] = (
            "run_config changed or became unreadable at campaign end")
    else:
        manifest["meta"]["run_config_final_verdict"] = "PASS"
    if not setup_final_ok:
        overall = "FAIL"
        manifest["meta"]["setup_provenance_final_verdict"] = "BLOCKED"
        manifest["meta"]["setup_provenance_final_detail"] = (
            "setup provenance changed, became invalid, or unreadable at campaign end")
    else:
        manifest["meta"]["setup_provenance_final_verdict"] = "PASS"
    if not harness_final_ok:
        overall = "FAIL"
        manifest["meta"]["harness_final_verdict"] = "BLOCKED"
        manifest["meta"]["harness_final_detail"] = (
            "harness changed or became incomplete at campaign end")
    else:
        manifest["meta"]["harness_final_verdict"] = "PASS"
    if not runtime_inputs_final_ok:
        overall = "FAIL"
        manifest["meta"]["runtime_inputs_final_verdict"] = "BLOCKED"
        manifest["meta"]["runtime_inputs_final_detail"] = (
            "runtime source input changed or became unreadable at campaign end")
    else:
        manifest["meta"]["runtime_inputs_final_verdict"] = "PASS"
    manifest["meta"]["finished_at_utc"] = utc()
    verdicts = [s.get("verdict") for s in manifest["steps"]]
    explicit_scope = bool(skip) or only is not None
    overall, counts = finalize_overall(overall, verdicts, explicit_scope)
    if (not config_final_ok or not setup_final_ok or not harness_final_ok
            or not runtime_inputs_final_ok or not secret_scan_final_ok):
        overall = "FAIL"
    manifest["meta"]["overall"] = overall
    # M1：scope 显式标注，scoped PASS_WITH_SKIPS 不与全流程完成混淆。
    manifest["meta"]["scope"] = "scoped" if explicit_scope else "full"
    manifest["meta"]["verdict_counts"] = counts
    atomic_json(manifest_path, manifest)
    print("EVIDENCE %s: %s" % (overall, counts), flush=True)
    return 0 if overall in ("PASS", "PASS_WITH_SKIPS") else 1


if __name__ == "__main__":
    sys.exit(main())
