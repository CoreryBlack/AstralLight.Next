use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

const MODES: [&str; 2] = ["bracket", "strict"];
const PREMISES: [&str; 6] = [
    "pending_probe",
    "post_recheck",
    "final_reload",
    "exact_identity",
    "generation_revoke_fence",
    "host_mediation",
];
const MODEL_SINGLE: &str = "e5-bounded-model-check";
const MODEL_TWO: &str = "e5-bounded-model-check-two-mutations";

fn verdict(status: &str, reason: &str) -> Value {
    json!({"status": status, "reason": reason})
}

fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn check_modes(modes: &Value) -> Value {
    let Some(modes) = object(modes) else {
        return verdict(
            "UNKNOWN",
            "missing or unexpected abstract observation modes",
        );
    };
    let expected: BTreeSet<&str> = MODES.into_iter().collect();
    if modes.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return verdict(
            "UNKNOWN",
            "missing or unexpected abstract observation modes",
        );
    }
    for run in modes.values() {
        let Some(run) = object(run) else {
            return verdict("UNKNOWN", "malformed abstract mode evidence");
        };
        let Some(violations) = run.get("violations").and_then(Value::as_i64) else {
            return verdict("UNKNOWN", "missing abstract violation count");
        };
        if violations < 0 {
            return verdict("UNKNOWN", "missing abstract violation count");
        }
        if violations > 0 || run.get("status").and_then(Value::as_str) == Some("FAIL") {
            return verdict("FAIL", "abstract full-contract safety violation");
        }
        let complete = run
            .get("explorationComplete")
            .or_else(|| run.get("complete"))
            .and_then(Value::as_bool)
            == Some(true);
        if run.get("status").and_then(Value::as_str) != Some("PASS") || !complete {
            return verdict(
                "UNKNOWN",
                "abstract full-contract exploration is incomplete",
            );
        }
    }
    verdict(
        "PASS",
        "both abstract observation modes completely explored",
    )
}

pub fn check_full_contract(report: &Value, model_name: &str) -> Value {
    let expected_model = match model_name {
        "single" => MODEL_SINGLE,
        "two" => MODEL_TWO,
        _ => return verdict("UNKNOWN", "missing or unexpected abstract model identity"),
    };
    if report.get("model").and_then(Value::as_str) != Some(expected_model) {
        return verdict("UNKNOWN", "missing or unexpected abstract model identity");
    }
    let full = report.get("fullContract").unwrap_or(report);
    let Some(full) = object(full) else {
        return verdict("UNKNOWN", "missing full-contract report");
    };
    let checked = check_modes(full.get("modes").unwrap_or(&Value::Null));
    if checked["status"] != "PASS" {
        return checked;
    }
    if report.get("status").and_then(Value::as_str) == Some("FAIL")
        || full.get("status").and_then(Value::as_str) == Some("FAIL")
    {
        return verdict("FAIL", "abstract full-contract result is inconsistent");
    }
    if report.get("status").and_then(Value::as_str) != Some("PASS")
        || full.get("status").and_then(Value::as_str) != Some("PASS")
    {
        return verdict("UNKNOWN", "abstract full-contract result is unproven");
    }
    let Some(omissions) = report.get("omissions") else {
        return verdict("UNKNOWN", "missing controlled-omission registry");
    };
    let names = if let Some(entries) = omissions.as_array() {
        entries
            .iter()
            .filter_map(|entry| entry.get("premise").and_then(Value::as_str))
            .collect::<Vec<_>>()
    } else if let Some(entries) = omissions.as_object() {
        entries.keys().map(String::as_str).collect::<Vec<_>>()
    } else {
        return verdict("UNKNOWN", "missing controlled-omission registry");
    };
    let found: BTreeSet<&str> = names.iter().copied().collect();
    if names.len() != PREMISES.len() || found != PREMISES.into_iter().collect() {
        return verdict(
            "UNKNOWN",
            "incomplete or duplicate controlled-omission registry",
        );
    }
    verdict(
        "PASS",
        "complete abstract contract; omission counterexamples are independent",
    )
}

pub fn check_tenant(report: &Value) -> Value {
    if report.get("model").and_then(Value::as_str) != Some("tenant-isolation-bounded-model") {
        return verdict("UNKNOWN", "missing tenant-model identity");
    }
    check_hypotheses(report, &["T1", "T3", "T4", "T5"])
}

fn check_hypotheses(item: &Value, expected: &[&str]) -> Value {
    let Some(entries) = item.get("hypotheses").and_then(Value::as_array) else {
        return verdict("UNKNOWN", "missing abstract hypothesis registry");
    };
    if entries.len() != expected.len() || entries.iter().any(|entry| !entry.is_object()) {
        return verdict("UNKNOWN", "malformed abstract hypothesis registry");
    }
    let names: Vec<&str> = entries
        .iter()
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .collect();
    let expected_set: BTreeSet<&str> = expected.iter().copied().collect();
    if names.len() != entries.len()
        || names.iter().copied().collect::<BTreeSet<_>>() != expected_set
    {
        return verdict(
            "UNKNOWN",
            "missing, duplicate or unexpected abstract hypotheses",
        );
    }
    if item.get("status").and_then(Value::as_str) == Some("FAIL")
        || entries.iter().any(|entry| entry["status"] == "FAIL")
    {
        return verdict("FAIL", "a decisive abstract hypothesis failed");
    }
    if item.get("status").and_then(Value::as_str) != Some("PASS")
        || entries.iter().any(|entry| entry["status"] != "PASS")
    {
        return verdict("UNKNOWN", "an abstract hypothesis is unproven");
    }
    verdict("PASS", "complete abstract hypothesis registry")
}

pub fn check_universal(report: &Value) -> Value {
    if report.get("checker").and_then(Value::as_str) != Some("universal-hypotheses-check") {
        return verdict("UNKNOWN", "missing universal-checker identity");
    }
    let Some(models) = report.get("models").and_then(Value::as_object) else {
        return verdict(
            "UNKNOWN",
            "universal report must contain exactly single and two models",
        );
    };
    if models.len() != 2 || !models.contains_key("single") || !models.contains_key("two") {
        return verdict(
            "UNKNOWN",
            "universal report must contain exactly single and two models",
        );
    }
    for name in ["single", "two"] {
        let item = &models[name];
        let underlying = if name == "single" {
            MODEL_SINGLE
        } else {
            MODEL_TWO
        };
        if item.get("modelName").and_then(Value::as_str) != Some(name)
            || item.get("underlyingModel").and_then(Value::as_str) != Some(underlying)
        {
            return verdict("UNKNOWN", "universal model identity mismatch");
        }
        let expected_ids = ["U1", "U2", "U3", "U4", "U5", "U6", "U7", "U8", "U9", "U10"];
        let checked = check_hypotheses(item, &expected_ids);
        if checked["status"] != "PASS" {
            return checked;
        }
        let entries = item["hypotheses"].as_array().expect("validated array");
        let by_id = entries
            .iter()
            .filter_map(|entry| {
                entry
                    .get("id")
                    .and_then(Value::as_str)
                    .map(|id| (id, entry))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let checked = check_modes(by_id["U9"].get("evidence").unwrap_or(&Value::Null));
        if checked["status"] != "PASS" {
            return checked;
        }
        let Some(safety) = by_id["U1"].get("evidence").and_then(Value::as_object) else {
            return verdict("UNKNOWN", "universal safety explorations are incomplete");
        };
        if safety.len() != 2
            || MODES.iter().any(|mode| {
                let entry = &safety[*mode];
                entry.get("status").and_then(Value::as_str) != Some("PASS")
                    || entry.get("explorationComplete").and_then(Value::as_bool) != Some(true)
                    || entry.get("admittedStrictlyBefore").and_then(Value::as_u64) != Some(0)
            })
        {
            return verdict("UNKNOWN", "universal safety explorations are incomplete");
        }
        let bounds = by_id["U8"].get("evidence").and_then(Value::as_object);
        let Some(bounds) = bounds else {
            return verdict("UNKNOWN", "universal bound explorations are incomplete");
        };
        let mut expected_bounds: BTreeSet<String> =
            ["full-bracket".to_owned(), "full-strict".to_owned()]
                .into_iter()
                .collect();
        expected_bounds.extend(PREMISES.iter().map(|premise| format!("without-{premise}")));
        if bounds.keys().cloned().collect::<BTreeSet<_>>() != expected_bounds
            || bounds
                .values()
                .any(|entry| entry.get("completeAtRequired").and_then(Value::as_bool) != Some(true))
        {
            return verdict("UNKNOWN", "universal bound explorations are incomplete");
        }
        let lattice = by_id["U6"].get("evidence").and_then(Value::as_object);
        let Some(lattice) = lattice else {
            return verdict(
                "UNKNOWN",
                "universal premise lattice coverage is incomplete",
            );
        };
        let (policy, count) = if name == "single" {
            ("full", 62)
        } else {
            ("singles", 6)
        };
        if lattice.get("latticePolicy").and_then(Value::as_str) != Some(policy)
            || lattice.get("subsetsChecked").and_then(Value::as_u64) != Some(count)
        {
            return verdict(
                "UNKNOWN",
                "universal premise lattice coverage differs from the command",
            );
        }
    }
    if report.get("status").and_then(Value::as_str) == Some("FAIL") {
        return verdict("FAIL", "universal aggregate reports failure");
    }
    if report.get("status").and_then(Value::as_str) != Some("PASS") {
        return verdict("UNKNOWN", "universal aggregate is unproven");
    }
    verdict(
        "PASS",
        "U1-U10 complete for both bounded models; not deployment evidence",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full(model: &str, summary: bool) -> Value {
        let modes = json!({"bracket":{"status":"PASS","violations":0,"explorationComplete":true},"strict":{"status":"PASS","violations":0,"explorationComplete":true}});
        let omissions = PREMISES
            .iter()
            .map(|name| json!({"premise":name,"status":"FAIL"}))
            .collect::<Vec<_>>();
        if summary {
            json!({"model":model,"status":"PASS","modes":modes,"omissions":omissions.into_iter().map(|row| (row["premise"].as_str().unwrap().to_owned(), row["status"].clone())).collect::<serde_json::Map<_,_>>()})
        } else {
            json!({"model":model,"status":"PASS","fullContract":{"status":"PASS","modes":modes},"omissions":omissions})
        }
    }

    #[test]
    fn accepts_both_full_contract_wire_shapes_and_rejects_missing_modes() {
        assert_eq!(
            check_full_contract(&full(MODEL_SINGLE, false), "single")["status"],
            "PASS"
        );
        assert_eq!(
            check_full_contract(&full(MODEL_TWO, true), "two")["status"],
            "PASS"
        );
        assert_eq!(
            check_full_contract(&json!({"status":"PASS"}), "single")["status"],
            "UNKNOWN"
        );
        let mut bad = full(MODEL_SINGLE, false);
        bad["fullContract"]["modes"]["strict"]["violations"] = json!(1);
        assert_eq!(check_full_contract(&bad, "single")["status"], "FAIL");
    }

    fn universal() -> Value {
        let models = [("single", MODEL_SINGLE, "full", 62), ("two", MODEL_TWO, "singles", 6)]
            .into_iter()
            .map(|(name, underlying, policy, subsets)| {
                let hypotheses = (1..=10)
                    .map(|number| {
                        let id = format!("U{number}");
                        let evidence = match number {
                            1 => json!({
                                "bracket":{"status":"PASS","explorationComplete":true,"admittedStrictlyBefore":0},
                                "strict":{"status":"PASS","explorationComplete":true,"admittedStrictlyBefore":0}
                            }),
                            6 => json!({"latticePolicy":policy,"subsetsChecked":subsets}),
                            8 => {
                                let mut bounds = json!({
                                    "full-bracket":{"completeAtRequired":true},
                                    "full-strict":{"completeAtRequired":true}
                                });
                                for premise in PREMISES {
                                    bounds[format!("without-{premise}")] = json!({"completeAtRequired":true});
                                }
                                bounds
                            }
                            9 => json!({
                                "bracket":{"status":"PASS","violations":0,"explorationComplete":true},
                                "strict":{"status":"PASS","violations":0,"explorationComplete":true}
                            }),
                            _ => json!({}),
                        };
                        json!({"id":id,"status":"PASS","evidence":evidence})
                    })
                    .collect::<Vec<_>>();
                json!({
                    "modelName":name,
                    "underlyingModel":underlying,
                    "status":"PASS",
                    "hypotheses":hypotheses
                })
            })
            .map(|item| (item["modelName"].as_str().unwrap().to_owned(), item))
            .collect::<serde_json::Map<_, _>>();
        json!({"checker":"universal-hypotheses-check","status":"PASS","models":models})
    }

    #[test]
    fn tenant_hypotheses_require_the_exact_complete_registry() {
        let valid = json!({
            "model":"tenant-isolation-bounded-model",
            "status":"PASS",
            "hypotheses":[
                {"id":"T5","status":"PASS"},
                {"id":"T1","status":"PASS"},
                {"id":"T4","status":"PASS"},
                {"id":"T3","status":"PASS"}
            ]
        });
        assert_eq!(check_tenant(&valid)["status"], "PASS");

        let mut duplicate = valid.clone();
        duplicate["hypotheses"][1]["id"] = json!("T5");
        assert_eq!(check_tenant(&duplicate)["status"], "UNKNOWN");
        let mut extra = valid.clone();
        extra["hypotheses"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"T2","status":"PASS"}));
        assert_eq!(check_tenant(&extra)["status"], "UNKNOWN");
        let mut failed = valid;
        failed["hypotheses"][0]["status"] = json!("FAIL");
        assert_eq!(check_tenant(&failed)["status"], "FAIL");
        assert_eq!(
            check_tenant(&json!({"model":"wrong-model","status":"PASS","hypotheses":[]}))["status"],
            "UNKNOWN"
        );
    }

    #[test]
    fn full_contract_checks_identity_modes_counts_status_and_omissions() {
        assert_eq!(
            check_full_contract(&full(MODEL_SINGLE, false), "single")["status"],
            "PASS"
        );
        assert_eq!(
            check_full_contract(&full(MODEL_TWO, true), "two")["status"],
            "PASS"
        );
        assert_eq!(
            check_full_contract(&full(MODEL_TWO, false), "single")["status"],
            "UNKNOWN"
        );
        assert_eq!(
            check_full_contract(&full(MODEL_SINGLE, false), "other")["status"],
            "UNKNOWN"
        );

        for violations in [json!(false), json!(1.5), json!(-1), json!("0")] {
            let mut report = full(MODEL_SINGLE, false);
            report["fullContract"]["modes"]["strict"]["violations"] = violations;
            assert_ne!(check_full_contract(&report, "single")["status"], "PASS");
        }
        let mut failed_mode = full(MODEL_SINGLE, false);
        failed_mode["fullContract"]["modes"]["strict"]["status"] = json!("FAIL");
        assert_eq!(
            check_full_contract(&failed_mode, "single")["status"],
            "FAIL"
        );

        for mutate in [0, 1, 2, 3] {
            let mut report = full(MODEL_SINGLE, false);
            match mutate {
                0 => {
                    report["omissions"].as_array_mut().unwrap().pop();
                }
                1 => {
                    let duplicate = report["omissions"][0].clone();
                    report["omissions"].as_array_mut().unwrap().push(duplicate);
                }
                2 => {
                    report["omissions"][0]["premise"] = json!("unexpected");
                }
                _ => {
                    report["omissions"] = json!(null);
                }
            }
            assert_eq!(check_full_contract(&report, "single")["status"], "UNKNOWN");
        }
    }

    #[test]
    fn universal_acceptance_requires_exact_two_models_and_all_hypothesis_evidence() {
        let report = universal();
        assert_eq!(check_universal(&report)["status"], "PASS");

        let mut extra_model = report.clone();
        extra_model["models"]["third"] = extra_model["models"]["single"].clone();
        assert_eq!(check_universal(&extra_model)["status"], "UNKNOWN");

        let mut wrong_identity = report.clone();
        wrong_identity["models"]["two"]["underlyingModel"] = json!(MODEL_SINGLE);
        assert_eq!(check_universal(&wrong_identity)["status"], "UNKNOWN");

        for index in 0..10 {
            let mut missing = report.clone();
            missing["models"]["single"]["hypotheses"]
                .as_array_mut()
                .unwrap()
                .remove(index);
            assert_eq!(check_universal(&missing)["status"], "UNKNOWN");
        }

        let mut duplicate = report.clone();
        duplicate["models"]["two"]["hypotheses"][1]["id"] = json!("U1");
        assert_eq!(check_universal(&duplicate)["status"], "UNKNOWN");

        let mut failed = report.clone();
        failed["models"]["two"]["hypotheses"][3]["status"] = json!("FAIL");
        assert_eq!(check_universal(&failed)["status"], "FAIL");

        let mut bad_u1 = report.clone();
        bad_u1["models"]["single"]["hypotheses"][0]["evidence"]["strict"]
            ["admittedStrictlyBefore"] = json!(1);
        assert_eq!(check_universal(&bad_u1)["status"], "UNKNOWN");

        let mut bad_u9 = report.clone();
        bad_u9["models"]["two"]["hypotheses"][8]["evidence"]["strict"]["violations"] = json!(true);
        assert_eq!(check_universal(&bad_u9)["status"], "UNKNOWN");

        let mut bad_u8 = report.clone();
        bad_u8["models"]["single"]["hypotheses"][7]["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("without-host_mediation");
        assert_eq!(check_universal(&bad_u8)["status"], "UNKNOWN");

        let mut extra_u8 = report.clone();
        extra_u8["models"]["single"]["hypotheses"][7]["evidence"]["unexpected"] =
            json!({"completeAtRequired":true});
        assert_eq!(check_universal(&extra_u8)["status"], "UNKNOWN");

        for (model, expected_policy, expected_count) in
            [("single", "full", 62), ("two", "singles", 6)]
        {
            let mut bad_lattice = report.clone();
            bad_lattice["models"][model]["hypotheses"][5]["evidence"]["latticePolicy"] =
                json!(if expected_policy == "full" {
                    "singles"
                } else {
                    "full"
                });
            assert_eq!(check_universal(&bad_lattice)["status"], "UNKNOWN");
            let mut bad_count = report.clone();
            bad_count["models"][model]["hypotheses"][5]["evidence"]["subsetsChecked"] =
                json!(expected_count + 1);
            assert_eq!(check_universal(&bad_count)["status"], "UNKNOWN");
        }
    }
}
