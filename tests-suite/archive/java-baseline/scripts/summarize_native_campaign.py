#!/usr/bin/env python3
"""Aggregate retained benchmark attempts without pooling operation samples."""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path
from typing import Any


METRICS = ("mean_us", "p50_us", "p99_us", "tps", "error_ops", "total_ops")


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def median_absolute_deviation(values: list[float]) -> float:
    if not values:
        return math.nan
    center = statistics.median(values)
    return statistics.median(abs(value - center) for value in values)


def numeric(value: str) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def collect_metrics(attempt_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for csv_path in sorted(attempt_dir.rglob("*.csv")):
        if csv_path.name.startswith("raw_") or "_raw_" in csv_path.stem:
            continue
        if csv_path.stem.endswith("_summary") or csv_path.stem.startswith("hardware"):
            continue
        try:
            with csv_path.open(newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                if not reader.fieldnames:
                    continue
                fields = {field.strip() for field in reader.fieldnames}
                if not {"mean_us", "p99_us"}.issubset(fields):
                    continue
                for row_number, row in enumerate(reader, start=2):
                    parsed = {metric: numeric(row.get(metric, "")) for metric in METRICS}
                    if parsed["mean_us"] is None or parsed["p99_us"] is None:
                        continue
                    label = (row.get("label") or "").strip()
                    if not label:
                        dimensions = []
                        for field in (
                                "thread_count", "target_tps", "concurrency", "card_count",
                                "total_ops", "rules", "fields", "overlay", "base", "abac", "refs",

                        ):
                            value = (row.get(field) or "").strip()
                            if value:
                                dimensions.append(f"{field}={value}")
                        label = csv_path.stem
                        if dimensions:
                            label += "|" + "|".join(dimensions)
                    parsed.update(
                        {
                            "attempt_dir": str(attempt_dir),
                            "file": str(csv_path),
                            "row": row_number,
                            "label": label,
                        }
                    )
                    rows.append(parsed)
        except (OSError, UnicodeError, csv.Error):
            continue
    return rows


def summarize(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"n": 0, "mean": None, "sd": None, "median": None, "mad": None, "min": None, "max": None}
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "sd": statistics.stdev(values) if len(values) > 1 else 0.0,
        "median": statistics.median(values),
        "mad": median_absolute_deviation(values),
        "min": min(values),
        "max": max(values),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    attempts: list[dict[str, Any]] = []
    for status_path in sorted(args.campaign.rglob("status.json")):
        attempt_dir = status_path.parent
        try:
            status = read_json(status_path)
            manifest = read_json(attempt_dir / "manifest.json")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            attempts.append(
                {
                    "attempt_dir": str(attempt_dir),
                    "classification": "excluded",
                    "exclusion_reason": f"invalid metadata: {exc}",
                    "metrics": [],
                }
            )
            continue
        classification = str(status.get("classification", "unknown"))
        metrics = collect_metrics(attempt_dir) if classification == "complete" else []
        if classification == "complete" and not metrics:
            classification = "excluded"
            reason = "no compatible summary CSV rows"
        else:
            reason = ""
        attempts.append(
            {
                "attempt_dir": str(attempt_dir),
                "run_id": status.get("runId"),
                "protocol": status.get("protocol", manifest.get("campaignProtocol")),
                "replicate": status.get("replicate"),
                "attempt": status.get("attempt"),
                "classification": classification,
                "exit_code": status.get("exitCode"),
                "duration_seconds": status.get("durationSeconds"),
                "exclusion_reason": reason,
                "metrics": metrics,
            }
        )

    run_rows: list[dict[str, Any]] = []
    for attempt in attempts:
        for metric in attempt.pop("metrics", []):
            run_rows.append({**attempt, **metric})

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in run_rows:
        groups.setdefault((str(row.get("protocol", "")), str(row.get("label", ""))), []).append(row)

    summary_rows: list[dict[str, Any]] = []
    for (protocol, label), rows in sorted(groups.items()):
        summary = {"protocol": protocol, "label": label}
        for metric in METRICS:
            summary[metric] = summarize([row[metric] for row in rows if row.get(metric) is not None])
        summary["complete_run_rows"] = len({row["attempt_dir"] for row in rows})
        summary_rows.append(summary)

    complete_attempts = sum(attempt["classification"] == "complete" for attempt in attempts)
    counts: dict[str, int] = {}
    for attempt in attempts:
        classification = str(attempt["classification"])
        counts[classification] = counts.get(classification, 0) + 1
    result = {
        "formatVersion": 1,
        "campaign": str(args.campaign),
        "attemptedRuns": len(attempts),
        "completeRuns": complete_attempts,
        "successRate": complete_attempts / len(attempts) if attempts else 0.0,
        "runCounts": counts,
        "metricInterpretation": "Cross-run summaries operate on one summary row per complete attempt; P99 values are not pooled or averaged into a pooled percentile.",
        "attempts": attempts,
        "runLevelSummary": summary_rows,
    }

    output = args.output or args.campaign / "run-level-summary.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    print(output)
    print(json.dumps({"attemptedRuns": len(attempts), "completeRuns": complete_attempts, "runCounts": counts}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
