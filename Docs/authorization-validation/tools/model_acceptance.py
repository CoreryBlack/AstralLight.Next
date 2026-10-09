"""Structured acceptance for bounded models; not runtime integration proof."""
from __future__ import annotations

MODELS = {
    "single": "e5-bounded-model-check",
    "two": "e5-bounded-model-check-two-mutations",
}
MODES = {"bracket", "strict"}
PREMISES = {
    "pending_probe", "post_recheck", "final_reload", "exact_identity",
    "generation_revoke_fence", "host_mediation",
}


def verdict(status, reason):
    return {"status": status, "reason": reason}


def check_modes(modes):
    if not isinstance(modes, dict) or set(modes) != MODES:
        return verdict("UNKNOWN", "missing or unexpected abstract observation modes")
    for run in modes.values():
        if not isinstance(run, dict):
            return verdict("UNKNOWN", "malformed abstract mode evidence")
        violations = run.get("violations")
        if type(violations) is not int or violations < 0:
            return verdict("UNKNOWN", "missing abstract violation count")
        if violations or run.get("status") == "FAIL":
            return verdict("FAIL", "abstract full-contract safety violation")
        complete = run.get("explorationComplete", run.get("complete"))
        if run.get("status") != "PASS" or complete is not True:
            return verdict("UNKNOWN", "abstract full-contract exploration is incomplete")
    return verdict("PASS", "both abstract observation modes completely explored")


def check_full_contract(report, model_name):
    if not isinstance(report, dict) or report.get("model") != MODELS.get(model_name):
        return verdict("UNKNOWN", "missing or unexpected abstract model identity")
    full = report.get("fullContract", report)
    if not isinstance(full, dict):
        return verdict("UNKNOWN", "missing full-contract report")
    checked = check_modes(full.get("modes"))
    if checked["status"] != "PASS":
        return checked
    if report.get("status") == "FAIL" or full.get("status") == "FAIL":
        return verdict("FAIL", "abstract full-contract result is inconsistent")
    if report.get("status") != "PASS" or full.get("status") != "PASS":
        return verdict("UNKNOWN", "abstract full-contract result is unproven")
    omissions = report.get("omissions")
    if isinstance(omissions, list):
        names = [entry.get("premise") for entry in omissions if isinstance(entry, dict)]
    elif isinstance(omissions, dict):
        names = list(omissions)
    else:
        return verdict("UNKNOWN", "missing controlled-omission registry")
    if len(names) != len(PREMISES) or set(names) != PREMISES:
        return verdict("UNKNOWN", "incomplete or duplicate controlled-omission registry")
    return verdict("PASS", "complete abstract contract; omission counterexamples are independent")


def check_hypotheses(item, expected):
    if not isinstance(item, dict) or not isinstance(item.get("hypotheses"), list):
        return verdict("UNKNOWN", "missing abstract hypothesis registry")
    entries = item["hypotheses"]
    if len(entries) != len(expected) or any(not isinstance(entry, dict) for entry in entries):
        return verdict("UNKNOWN", "malformed abstract hypothesis registry")
    names = [entry.get("id") for entry in entries]
    if any(not isinstance(name, str) for name in names) or set(names) != set(expected):
        return verdict("UNKNOWN", "missing, duplicate or unexpected abstract hypotheses")
    if any(entry.get("status") == "FAIL" for entry in entries) or item.get("status") == "FAIL":
        return verdict("FAIL", "a decisive abstract hypothesis failed")
    if item.get("status") != "PASS" or any(entry.get("status") != "PASS" for entry in entries):
        return verdict("UNKNOWN", "an abstract hypothesis is unproven")
    return verdict("PASS", "complete abstract hypothesis registry")


def check_universal(report):
    if not isinstance(report, dict) or report.get("checker") != "universal-hypotheses-check":
        return verdict("UNKNOWN", "missing universal-checker identity")
    models = report.get("models")
    if not isinstance(models, dict) or set(models) != set(MODELS):
        return verdict("UNKNOWN", "universal report must contain exactly single and two models")
    for name, item in models.items():
        if not isinstance(item, dict) or item.get("modelName") != name or item.get("underlyingModel") != MODELS[name]:
            return verdict("UNKNOWN", "universal model identity mismatch")
        checked = check_hypotheses(item, {f"U{number}" for number in range(1, 11)})
        if checked["status"] != "PASS":
            return checked
        by_id = {entry["id"]: entry for entry in item["hypotheses"]}
        checked = check_modes(by_id["U9"].get("evidence"))
        if checked["status"] != "PASS":
            return checked
        safety = by_id["U1"].get("evidence")
        if not isinstance(safety, dict) or set(safety) != MODES or any(
            not isinstance(entry, dict) or entry.get("status") != "PASS"
            or entry.get("explorationComplete") is not True
            or type(entry.get("admittedStrictlyBefore")) is not int
            or entry["admittedStrictlyBefore"] != 0
            for entry in safety.values()
        ):
            return verdict("UNKNOWN", "universal safety explorations are incomplete")
        bounds = by_id["U8"].get("evidence", {})
        expected = {"full-bracket", "full-strict"} | {"without-" + premise for premise in PREMISES}
        if not isinstance(bounds, dict) or set(bounds) != expected or any(
            entry.get("completeAtRequired") is not True for entry in bounds.values()
        ):
            return verdict("UNKNOWN", "universal bound explorations are incomplete")
        lattice = by_id["U6"].get("evidence", {})
        policy, count = ("full", 62) if name == "single" else ("singles", 6)
        if lattice.get("latticePolicy") != policy or lattice.get("subsetsChecked") != count:
            return verdict("UNKNOWN", "universal premise lattice coverage differs from the command")
    if report.get("status") == "FAIL":
        return verdict("FAIL", "universal aggregate reports failure")
    if report.get("status") != "PASS":
        return verdict("UNKNOWN", "universal aggregate is unproven")
    return verdict("PASS", "U1-U10 complete for both bounded models; not deployment evidence")


def check_tenant(report):
    if not isinstance(report, dict) or report.get("model") != "tenant-isolation-bounded-model":
        return verdict("UNKNOWN", "missing tenant-model identity")
    return check_hypotheses(report, {"T1", "T3", "T4", "T5"})
