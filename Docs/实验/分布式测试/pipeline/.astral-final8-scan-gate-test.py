import json
import os
import subprocess
import sys

snippet = (
    "import json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import s15_coordinator as coordinator\n"
    "result = coordinator.runtime_secret_scan(extra_paths=sys.argv[2:])\n"
    "print(json.dumps(result, sort_keys=True))\n"
    "sys.exit(0 if result.get('ok') else 1)\n"
)
proc = subprocess.run(
    [sys.executable, "-c", snippet, os.getcwd(),
     "/home/xg/astral-cs-final8-diag/diag_s15_perf.log"],
    capture_output=True, text=True, timeout=600)
print("rc:", proc.returncode)
print("stdout:", proc.stdout.strip())
print("stderr_tail:", proc.stderr.strip()[-200:] if proc.stderr else "")
