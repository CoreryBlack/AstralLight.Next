import os
import subprocess
import sys

os.environ["RUN_CONFIG_PATH"] = "/home/xg/rust3n-dist-20260906-final9/run_config.json"
sys.path.insert(0, "/home/xg/cs-harness-20260906-final8/Docs/实验/分布式测试/rust-s15")
import s15_coordinator as C

kills = {n: C.node_kill(n) for n in C.NAMES}
print("kills:", kills, flush=True)

for cmd in (
    ["docker", "stop", C.RC],
    ["docker", "rm", C.RC],
    ["docker", "exec", "astral_bench_rabbitmq", "rabbitmqctl", "delete_vhost",
     C.CFG["rabbit_vhost"]],
):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    print(" ".join(cmd[:2]), "rc=", r.returncode, flush=True)

for node in C.NAMES:
    target = None if node == "node-b" else C.CFG["ssh"][node]
    run_dir = "~/rust3n-dist-20260906-final9"
    argv = (["bash", "-c", "rm -rf %s" % run_dir] if target is None else
            ["ssh", "-o", "BatchMode=yes", target, "rm -rf %s" % run_dir])
    r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    print("rm run dir", node, "rc=", r.returncode, flush=True)

r = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                   capture_output=True, text=True, timeout=60)
final9 = [n for n in r.stdout.splitlines() if "final9" in n]
print("final9 containers left:", final9, flush=True)
r = subprocess.run(["docker", "exec", "astral_bench_rabbitmq", "rabbitmqctl", "-q",
                    "list_vhosts", "name"], capture_output=True, text=True, timeout=60)
final9_vhosts = [v for v in r.stdout.splitlines() if "final9" in v]
print("final9 vhosts left:", final9_vhosts, flush=True)
print("FINAL9_RUNTIME_CLEANUP_DONE", flush=True)
