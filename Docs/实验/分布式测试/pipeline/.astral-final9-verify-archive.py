import hashlib
import os
import sys

local_root, remote_list = sys.argv[1], sys.argv[2]
entries = {}
for base, dirs, files in os.walk(local_root):
    dirs.sort()
    for name in sorted(files):
        path = os.path.join(base, name)
        rel = "/" + os.path.relpath(path, local_root).replace(os.sep, "/")
        with open(path, "rb") as stream:
            entries[rel] = hashlib.sha256(stream.read()).hexdigest()

remote = {}
with open(remote_list, encoding="utf-8") as handle:
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            continue
        digest, rel = line.split(" ", 1)
        remote[rel] = digest

digest_diffs = sorted(rel for rel in remote if remote[rel] != entries.get(rel))
missing = sorted(set(remote) ^ set(entries))
print("local_files:", len(entries), "remote_files:", len(remote))
print("digest_diffs:", digest_diffs)
print("path_diffs:", missing)
print("EVIDENCE_HASH_MATCH" if not digest_diffs and not missing else "MISMATCH")
