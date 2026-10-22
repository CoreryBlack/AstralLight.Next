use serde_json::{json, Value};

const GATES: [&str; 5] = [
    "tenant_scoped_cache_key",
    "tenant_scoped_record_validation",
    "tenant_scoped_probe",
    "tenant_scoped_watermark",
    "tenant_scoped_match",
];
const CONTAMINATION: [&str; 3] = [
    "admittedForeignGrant",
    "admittedContaminatedInputs",
    "deniedCrossTenantBlock",
];

fn subsets() -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    for mask in 1usize..((1usize << GATES.len()) - 1) {
        result.push(
            (0..GATES.len())
                .filter(|index| mask & (1 << index) != 0)
                .collect(),
        );
    }
    result
}

pub fn enumerate_tenant_traces(removed: &[usize]) -> [usize; 7] {
    let enabled = |gate: usize| !removed.contains(&gate);
    let mut counts = [0usize; 7];
    for cache_record in 0..2 {
        for probe_read in 0..2 {
            for manifest_source in 0..2 {
                for t1_narrowing in 0..2 {
                    for t2_narrowing in 0..2 {
                        let (served, rejected) = if enabled(0) {
                            (0, false)
                        } else {
                            (cache_record, cache_record == 1 && enabled(1))
                        };
                        let mut evidence = if rejected { 0 } else { served };
                        if evidence == 0 && !enabled(3) {
                            evidence = manifest_source;
                        }
                        let predicate_source = if enabled(2) { 0 } else { probe_read };
                        let pending = if predicate_source == 0 {
                            t1_narrowing == 1
                        } else {
                            t2_narrowing == 1
                        };
                        if pending {
                            let bucket = if predicate_source == 1
                                && t2_narrowing == 1
                                && t1_narrowing == 0
                            {
                                5
                            } else {
                                4
                            };
                            counts[bucket] += 1;
                            continue;
                        }
                        let selected = if enabled(4) {
                            if evidence == 0 {
                                0
                            } else {
                                counts[6] += 1;
                                continue;
                            }
                        } else if evidence == 1 {
                            1
                        } else {
                            0
                        };
                        let bucket = if selected == 1 {
                            1
                        } else if predicate_source == 1 || evidence != 0 {
                            2
                        } else {
                            0
                        };
                        counts[bucket] += 1;
                    }
                }
            }
        }
    }
    counts
}

pub fn tenant_report() -> Value {
    let full = enumerate_tenant_traces(&[]);
    let mut hypotheses = Vec::new();
    let t1_ok = full[1] == 0 && full[2] == 0 && full[5] == 0 && full[4] > 0;
    hypotheses.push(json!({"id":"T1","status":if t1_ok{"PASS"}else{"FAIL"},"evidence":{"traces":full.iter().sum::<usize>(),"admittedForeignGrant":full[1],"admittedContaminatedInputs":full[2],"deniedCrossTenantBlock":full[5],"deniedOwnPending":full[4]}}));
    let lattice = subsets()
        .into_iter()
        .map(|removed| {
            let counts = enumerate_tenant_traces(&removed);
            let observed = CONTAMINATION.iter().any(|name| {
                let index = match *name {
                    "admittedForeignGrant" => 1,
                    "admittedContaminatedInputs" => 2,
                    _ => 5,
                };
                counts[index] > 0
            });
            let probe_open = removed.contains(&2);
            let evidence_open =
                removed.contains(&3) || removed.contains(&0) && removed.contains(&1);
            let match_open = removed.contains(&4);
            let predicted = probe_open || evidence_open && match_open;
            let removed_names = removed
                .iter()
                .map(|index| GATES[*index])
                .collect::<Vec<_>>();
            json!({"removed":removed_names,"contaminating":observed,"predicted":predicted})
        })
        .collect::<Vec<_>>();
    let unexpected = lattice
        .iter()
        .filter(|entry| entry["contaminating"] == true && entry["predicted"] == false)
        .map(|entry| entry["removed"].clone())
        .collect::<Vec<_>>();
    let t3_ok = lattice
        .iter()
        .all(|entry| entry["contaminating"] == entry["predicted"]);
    let observed_single = GATES
        .iter()
        .enumerate()
        .map(|(index, gate)| {
            let counts = enumerate_tenant_traces(&[index]);
            let mut families = Vec::new();
            if counts[1] > 0 {
                families.push("admittedForeignGrant");
            }
            if counts[2] > 0 {
                families.push("admittedContaminatedInputs");
            }
            if counts[5] > 0 {
                families.push("deniedCrossTenantBlock");
            }
            (gate.to_string(), json!(families))
        })
        .collect::<serde_json::Map<_, _>>();
    let t4_ok = observed_single["tenant_scoped_cache_key"] == json!([])
        && observed_single["tenant_scoped_record_validation"] == json!([])
        && observed_single["tenant_scoped_probe"]
            == json!(["admittedContaminatedInputs", "deniedCrossTenantBlock"])
        && observed_single["tenant_scoped_watermark"] == json!([])
        && observed_single["tenant_scoped_match"] == json!([]);
    let t5_ok = std::iter::once(Vec::new()).chain(subsets()).all(|removed| {
        let counts = enumerate_tenant_traces(&removed);
        counts.iter().sum::<usize>() == 32
    });
    hypotheses.push(json!({"id":"T3","status":if t3_ok{"PASS"}else{"FAIL"},"evidence":{"subsetsChecked":lattice.len(),"contaminatingSubsets":lattice.iter().filter(|entry|entry["contaminating"]==true).count(),"unexpectedSafeSubsets":unexpected,"lattice":lattice}}));
    hypotheses.push(json!({"id":"T4","status":if t4_ok{"PASS"}else{"FAIL"},"evidence":{"observed":observed_single}}));
    hypotheses.push(json!({"id":"T5","status":if t5_ok{"PASS"}else{"FAIL"},"evidence":{"configurationsAudited":1+subsets().len()}}));
    let status = if hypotheses.iter().all(|entry| entry["status"] == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    json!({"model":"tenant-isolation-bounded-model","modelVersion":"1.0.0","hypotheses":hypotheses,"findings":[],"status":status,"scopeBoundary":"abstract bounded-model evidence only; not a proof of any implementation, deployment, or runtime behavior; live validation remains BLOCKED regardless of this result"})
}

pub fn verify_tenant_contract() -> Result<(), String> {
    let report = tenant_report();
    if report["status"] != "PASS" {
        return Err("tenant model hypotheses failed".into());
    }
    if report["hypotheses"][1]["evidence"]["subsetsChecked"] != 30 {
        return Err("tenant premise lattice count changed".into());
    }
    let lattice = report["hypotheses"][1]["evidence"]["lattice"]
        .as_array()
        .ok_or("tenant lattice missing")?;
    if lattice.len() != 30 || report["hypotheses"][3]["evidence"]["configurationsAudited"] != 31 {
        return Err("tenant lattice coverage is incomplete".into());
    }
    let observed = &report["hypotheses"][2]["evidence"]["observed"];
    if observed["tenant_scoped_probe"]
        != json!(["admittedContaminatedInputs", "deniedCrossTenantBlock"])
    {
        return Err("tenant omission semantics changed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tenant_lattice_and_conservation_contract() {
        let report = tenant_report();
        assert_eq!(report["status"], "PASS");
        assert_eq!(report["hypotheses"][1]["evidence"]["subsetsChecked"], 30);
        assert_eq!(
            report["hypotheses"][1]["evidence"]["contaminatingSubsets"],
            20
        );
        assert_eq!(
            report["hypotheses"][3]["evidence"]["configurationsAudited"],
            31
        );
        assert_eq!(verify_tenant_contract(), Ok(()));
    }

    #[test]
    fn cache_contamination_requires_the_complete_missing_gate_chain() {
        assert_eq!(enumerate_tenant_traces(&[0]).iter().sum::<usize>(), 32);
        assert!(enumerate_tenant_traces(&[0, 1, 4])[1] > 0);
        assert!(enumerate_tenant_traces(&[2])[2] > 0);
        assert!(enumerate_tenant_traces(&[2])[5] > 0);
    }
}
