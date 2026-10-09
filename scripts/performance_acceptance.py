"""CPU benchmark output contracts; no service-throughput interpretation."""
from __future__ import annotations

import math
import re

UNITS = {"ps": 0.001, "ns": 1.0, "us": 1000.0, "\u00b5s": 1000.0,
         "\u03bcs": 1000.0, "ms": 1_000_000.0, "s": 1_000_000_000.0}
NUMBER = r"(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"
TIME = re.compile(rf"({NUMBER})\s*(ps|ns|us|\u00b5s|\u03bcs|ms|s)")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def check_criterion(suite, output, smoke=False):
    expected = set(suite["benchmark_cases"])
    seen = {}
    current = None
    for line in ANSI.sub("", output).splitlines():
        stripped = line.strip()
        if stripped.startswith("Testing "):
            stripped = stripped[len("Testing "):]
        for name in expected:
            if stripped == name or stripped.startswith(name + " "):
                current = name
                break
        if smoke and stripped == "Success":
            if current is None or current in seen:
                return {"status": "FAIL", "reason": "duplicate or unbound benchmark smoke result"}
            seen[current] = {"fixture": "executed; not measured"}
            current = None
        elif not smoke and "time:" in line:
            if current is None or current in seen:
                return {"status": "FAIL", "reason": "duplicate or unbound Criterion measurement"}
            pairs = TIME.findall(line.partition("time:")[2])
            if len(pairs) != 3:
                return {"status": "FAIL", "reason": "missing Criterion confidence interval"}
            values = [float(value) * UNITS[unit] for value, unit in pairs]
            if any(not math.isfinite(value) or value <= 0 for value in values) or values != sorted(values):
                return {"status": "FAIL", "reason": "invalid Criterion timing interval"}
            seen[current] = {"lower_ns": values[0], "estimate_ns": values[1], "upper_ns": values[2]}
            current = None
    if set(seen) != expected:
        return {"status": "FAIL", "reason": "benchmark output lacks the complete expected case set"}
    return {"status": "PASS", "reason": "complete benchmark fixture smoke" if smoke else "complete measured CPU Criterion cases; no HTTP/DB claim",
            "performance": {"scope": "fixture smoke only" if smoke else "CPU component only", "cases": len(seen), "measurements": seen}}


def check_divan(suite, output):
    expected = set(suite["benchmark_cases"])
    seen = {}
    current = None
    allocating = set(suite.get("allocation_cases", []))
    allocations = {}
    pending = None
    for line in ANSI.sub("", output).splitlines():
        line = re.sub(r"^[\s\u251c\u2514\u2570\u2500\u2502]+", "", line)
        cells = [cell.strip() for cell in line.split("\u2502")]
        label = cells[0]
        if pending is not None:
            unit = r"" if not pending[1] else r"\s*(B|KB|MB|GB|TB|KiB|MiB|GiB)"
            pattern = re.compile(rf"({NUMBER}){unit}")
            numbers = [pattern.fullmatch(cell) for cell in cells[:4]]
            if len(numbers) != 4 or not all(numbers) or any(
                not math.isfinite(float(value[1])) or float(value[1]) < 0 for value in numbers
            ):
                return {"status": "FAIL", "reason": "missing or invalid Divan allocation statistics"}
            pending[1].append(cells[:4])
            if len(pending[1]) == 2:
                allocations[current] = {"counts_per_iteration": pending[1][0], "bytes_per_iteration": pending[1][1]}
                pending = None
            continue
        if label not in expected:
            for name in expected:
                first_cell = re.fullmatch(rf"{re.escape(name)}\s+({TIME.pattern})", label)
                if first_cell:
                    cells = [name, first_cell[1], *cells[1:]]
                    label = name
                    break
        if label in expected:
            if label in seen or len(cells) < 7:
                return {"status": "FAIL", "reason": "duplicate or malformed Divan case"}
            pairs = [TIME.fullmatch(cell) for cell in cells[1:5]]
            if not all(pairs) or not cells[5].isdigit() or not cells[6].isdigit():
                return {"status": "FAIL", "reason": "missing Divan timing/sample evidence"}
            values = [float(pair[1]) * UNITS[pair[2]] for pair in pairs]
            if any(not math.isfinite(value) or value <= 0 for value in values) or int(cells[5]) < 15 or int(cells[6]) < 1:
                return {"status": "FAIL", "reason": "invalid Divan samples"}
            current = label
            seen[label] = {"fastest_ns": values[0], "slowest_ns": values[1], "median_ns": values[2], "mean_ns": values[3],
                           "samples": int(cells[5]), "iterations": int(cells[6])}
        elif current and label == "alloc:":
            if current in allocations:
                return {"status": "FAIL", "reason": "duplicate Divan allocation section"}
            pending = [current, []]
    if pending or set(seen) != expected or not allocating <= allocations.keys():
        return {"status": "FAIL", "reason": "Divan timing or allocation cases are incomplete"}
    return {"status": "PASS", "reason": "complete CPU allocation benchmark; no service-capacity claim",
            "performance": {"scope": "CPU/allocation component only; instrumented timing", "cases": len(seen),
                            "measurements": seen, "allocations": allocations}}
