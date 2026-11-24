//! Validation and reproducible paired tabulation for the current five-arm RQ3 run.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn audit(output: &str) -> Result<Value, String> {
    let mut rows = BTreeMap::new();
    let mut children = BTreeSet::new();
    let mut negatives = BTreeSet::new();
    for line in output.lines() {
        if let Some((_, text)) = line.split_once("ABC_CHILD case=") {
            let (case, exit) = text.split_once(" exit=").ok_or("malformed child")?;
            if exit.trim() != "Some(0)" || !children.insert(case.to_owned()) {
                return Err("failed or duplicate RQ3 child".into());
            }
        }
        if let Some((_, text)) = line.split_once("ABC_CONTROL ") {
            let parts: Vec<_> = text.split_whitespace().collect();
            if parts.len() != 3 {
                return Err("malformed control".into());
            }
            if parts[1] == "case=negative" {
                let arm = parts[0].strip_prefix("arm=").ok_or("missing control arm")?;
                if parts[2] != "outcome=Deny" || !negatives.insert(arm.to_owned()) {
                    return Err("invalid or duplicate negative control".into());
                }
            }
        }
        if let Some((_, text)) = line.split_once("ABC_RESULT ") {
            let row: Value =
                serde_json::from_str(text).map_err(|e| format!("invalid RQ3 JSON: {e}"))?;
            let number = |key: &str| row[key].as_u64().ok_or_else(|| format!("invalid {key}"));
            let mode = row["mode"].as_str().ok_or("invalid mode")?;
            let arm = row["arm"].as_str().ok_or("invalid arm")?;
            let rep = number("rep")?;
            let (readers, reads, writes) = match mode {
                "pure" => (4, 16384, 0),
                "unrelated" | "related" => (4, 16384, 32),
                "hot" => (8, 32768, 256),
                _ => return Err("unexpected mode".into()),
            };
            if !["A", "B", "C", "D", "E"].contains(&arm)
                || rep >= 6
                || number("readers")? != readers
                || number("reads")? != reads
                || number("writes")? != writes
                || number("writer_rejects")? != 0
            {
                return Err("invalid RQ3 dimensions or writer rejects".into());
            }
            let legal = number("legal")?;
            let allow = number("legal_allow")?;
            let wall = number("wall_ns")?;
            if legal != reads * 3 / 4
                || allow > legal
                || wall == 0
                || row["outcomes"] != json!([allow, reads - legal, legal - allow])
                || ((arm == "A" || mode == "pure") && allow != legal)
            {
                return Err("invalid outcomes, negative samples or timing".into());
            }
            let dist = |v: &Value, expected: u64| -> bool {
                if expected == 0 {
                    return v.is_null();
                }
                v.as_array().is_some_and(|a| {
                    a.len() == 4 && a.iter().all(Value::is_u64) && a[0].as_u64() == Some(expected)
                })
            };
            if !dist(&row["lat_ns"], reads)
                || row["lat_ns"][3].as_u64() == Some(0)
                || !dist(&row["writer_latency_ns"], writes)
                || !dist(&row["writer_native_ns"]["wait"], writes)
                || !dist(&row["writer_native_ns"]["hold"], writes)
            {
                return Err("invalid RQ3 distributions".into());
            }
            let d = &row["denominators"];
            let final_calls = d["final_calls"].as_u64().ok_or("missing final calls")?;
            let root = d["native_root_lock_samples"]
                .as_u64()
                .ok_or("missing root samples")?;
            if d["reads"].as_u64() != Some(reads)
                || d["legal_reads"].as_u64() != Some(legal)
                || root > final_calls
                || final_calls > reads
                || (arm == "C" && (allow > root || final_calls > legal))
            {
                return Err("invalid RQ3 denominators".into());
            }
            let key = (mode.to_owned(), arm.to_owned(), rep);
            if rows.insert(key, row).is_some() {
                return Err("duplicate RQ3 cell".into());
            }
        }
    }
    let expected_negative: BTreeSet<_> = ["A", "B", "C", "D", "E"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if negatives != expected_negative {
        return Err("missing negative controls".into());
    }
    let mut expected_children = BTreeSet::new();
    for arm in ["A", "B", "C", "D", "E"] {
        expected_children.insert(format!("{arm}:control:4096:0"));
        for mode in ["pure", "unrelated", "related", "hot"] {
            for rep in 0..6 {
                expected_children.insert(format!("{arm}:{mode}:4096:{rep}"));
                if !rows.contains_key(&(mode.to_owned(), arm.to_owned(), rep)) {
                    return Err("missing RQ3 cell".into());
                }
            }
        }
    }
    if children != expected_children || rows.len() != 120 {
        return Err("incomplete RQ3 children or rows".into());
    }
    let mut table = Vec::new();
    for mode in ["pure", "unrelated", "related", "hot"] {
        for arm in ["A", "B", "C", "D", "E"] {
            let mut delta = Vec::new();
            let mut useful = Vec::new();
            let mut paired_ratio = Vec::new();
            let mut pending = [0u64; 3];
            for rep in 0..6 {
                let row = &rows[&(mode.to_owned(), arm.to_owned(), rep)];
                let base = &rows[&(mode.to_owned(), "A".to_owned(), rep)];
                let n = |v: &Value, k: &str| v[k].as_u64().unwrap() as f64;
                let rate = 1_000_000.0 * n(row, "legal_allow") / n(row, "wall_ns");
                let base_rate = 1_000_000.0 * n(base, "legal_allow") / n(base, "wall_ns");
                useful.push(rate);
                delta.push(
                    100.0
                        * (n(row, "legal_allow") / n(row, "legal")
                            - n(base, "legal_allow") / n(base, "legal")),
                );
                paired_ratio.push(rate / base_rate);
                if arm == "C" {
                    let legal = row["legal"].as_u64().unwrap();
                    let final_calls = row["denominators"]["final_calls"].as_u64().unwrap();
                    let root = row["denominators"]["native_root_lock_samples"]
                        .as_u64()
                        .unwrap();
                    let allow = row["legal_allow"].as_u64().unwrap();
                    pending[0] += legal - final_calls;
                    pending[1] += final_calls - root;
                    pending[2] += root - allow;
                }
            }
            let median = |v: &mut Vec<f64>| {
                v.sort_by(f64::total_cmp);
                (v[2] + v[3]) / 2.0
            };
            let faster = paired_ratio.iter().filter(|r| **r > 1.0).count();
            table.push(json!({"mode":mode,"arm":arm,"rounds":6,"median_allow_delta_pp":median(&mut delta),"median_useful_kops":median(&mut useful),"paired_useful_rate_ratios":paired_ratio,"faster_rounds":faster,"pending_c_stages":pending}));
        }
    }
    Ok(
        json!({"observations":rows.into_values().collect::<Vec<_>>(),"children":125,"negative_controls":5,"table":table}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        let mut output = String::new();
        for arm in ["A", "B", "C", "D", "E"] {
            output.push_str(&format!("ABC_CONTROL arm={arm} case=negative outcome=Deny\nABC_CHILD case={arm}:control:4096:0 exit=Some(0)\n"));
            for mode in ["pure", "unrelated", "related", "hot"] {
                let (readers, reads, writes) = match mode {
                    "pure" => (4, 16384, 0),
                    "hot" => (8, 32768, 256),
                    _ => (4, 16384, 32),
                };
                let writer = if writes == 0 {
                    Value::Null
                } else {
                    json!([writes, 1, 1, 1])
                };
                for rep in 0..6 {
                    let legal = reads * 3 / 4;
                    let row = json!({"mode":mode,"arm":arm,"rep":rep,"readers":readers,"reads":reads,"writes":writes,"writer_rejects":0,"legal":legal,"legal_allow":legal,"wall_ns":100,"outcomes":[legal,reads-legal,0],"lat_ns":[reads,1,1,1],"writer_latency_ns":writer,"writer_native_ns":{"wait":writer,"hold":writer},"denominators":{"reads":reads,"legal_reads":legal,"final_calls":legal,"native_root_lock_samples":legal}});
                    output.push_str(&format!(
                        "ABC_RESULT {row}\nABC_CHILD case={arm}:{mode}:4096:{rep} exit=Some(0)\n"
                    ));
                }
            }
        }
        output
    }

    #[test]
    fn validates_complete_rounds_and_rejects_corruption() {
        let log = fixture();
        let result = audit(&log).unwrap();
        assert_eq!(result["observations"].as_array().unwrap().len(), 120);
        assert_eq!(result["table"].as_array().unwrap().len(), 20);
        assert!(
            audit(&log.replace("case=negative outcome=Deny", "case=negative outcome=Allow"))
                .is_err()
        );
        assert!(audit(&log.replacen("exit=Some(0)", "exit=Some(1)", 1)).is_err());
        assert!(audit(&log.replacen("ABC_RESULT ", "ABC_BAD ", 1)).is_err());
        assert!(audit(&format!(
            "{log}ABC_CHILD case=A:control:4096:0 exit=Some(0)\n"
        ))
        .is_err());
        assert!(audit(&format!("{log}ABC_RESULT {{\n")).is_err());
    }
}
