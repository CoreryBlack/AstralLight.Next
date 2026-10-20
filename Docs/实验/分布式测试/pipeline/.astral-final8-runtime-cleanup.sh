import json
import os
import shutil
import subprocess
import sys

os.environ["RUN_CONFIG_PATH"] = "/home/xg/rust3n-dist-20260906-final8/run_config.json"
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

prov_src = os.path.join(os.path.expanduser(C.CFG["base_dir"]), "provenance.json")
prov_dst = "/home/xg/astral-cs-final8-diag/final8-provenance.json"
shutil.copyfile(prov_src, prov_dst)
os.chmod(prov_dst, 0o644)
print("provenance archived (secret-free)", flush=True)

for node in C.NAMES:
    if node == "node-b":
        target = None
    else:
        target = C.CFG["ssh"][node]
    run_dir = "~/rust3n-dist-20260906-final8"
    argv = (["bash", "-c", "rm -rf %s" % run_dir] if target is None else
            ["ssh", "-o", "BatchMode=yes", target, "rm -rf %s" % run_dir])
    r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    print("rm run dir", node, "rc=", r.returncode, flush=True)

r = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                   capture_output=True, text=True, timeout=60)
leftover = [n for n in r.stdout.splitlines() if "final8" in n]
print("final8 containers left:", leftover, flush=True)
print("FINAL8_RUNTIME_CLEANUP_DONE", flush=True)
