use serde_json::{json, Map, Value};

use super::{
    run_model, validate_bound, Mode, Premises, MAX_BOUND, MIN_BOUND, MODEL_NAME, MODEL_VERSION,
    PREMISES, THEOREM_ID,
};

const SCOPE_LIMITATIONS: [&str; 21] = [
    "Abstract discrete-event model of ONE candidate grant and ONE revocation-class mutation with a single successor revision; not a mechanized proof of any Rust/Java implementation, deployment, or runtime behavior.",
    "The full contract fixes the admission checklist order (final load m0<p0<m1<p1 -> candidate match -> post-recheck -> admission; strict mode: atomic strict load -> match -> strict recheck -> admission). Free events -- including both publication sub-events and the rollback -- DO interleave between the last read and the admission step; the model does not suppress them, and NO gate is re-evaluated at the admission step: every gate is latched from read-time observations.",
    "There is NO admission-side watermark and NO admission-time pending re-derivation in this model: the current Rust implementation has neither. The final-read-to-admission window is closed by the latched read-time pending probes (and the post-recheck/fence/identity gates), not by any admission-time check.",
    "The theorem's final observation t_f is m0 -- the first authoritative observation that supplies the successful final evidence (strict mode: the atomic strict load) -- matching experiment_common.py's final_observation_interval.",
    "The final load's observation bracket is ordered m0 < p0 < m1 < p1 (bracket mode) with pending captured at p0/p1 read steps; the evidence is anchored at m0. The within-load cache fence-snapshot bracket (F0==F1) and the cache-miss fallback to the authoritative reader are abstracted: a mid-load manifest move is caught by the latched pending probes (incomplete publication) or the post-recheck agreement (completed publication), not by a modeled F0==F1 equality.",
    "The pending probes capture 'an incomplete mutation is in flight': commit begun but not durable, or durable but publication incomplete (publication completes only when BOTH the manifest advance and the evidence body advance have fired). Treating begun-but-not-durable as pending is conservative (deny-more) relative to a gate that only tracks durable-but-unpublished deltas.",
    "Publication is modeled as two independently scheduled sub-events after the durable commit: PUBLISH (manifest/version advance, which also advances the durable published head) and EVIDENCE_BODY_ADVANCE (evidence body advance). Consistent publication requires both; the torn states (g1, r0) and (g0, r1) exist between and around them.",
    "The mutation chain is a fixed total order (commit begin -> commit durable -> manifest advance -> rollback) with the evidence body advance scheduled freely after the durable commit; at most one rollback, only after the manifest advance.",
    "Steps are dense (every step fires one event); only relative order affects outcomes, and absolute timing/idle gaps are not modeled.",
    "Overlapping commit/final-observation intervals (the commit spans t_f: begun at/before m0, durable after) are classified UNKNOWN (outside the theorem domain) and are never counted as violations.",
    "Traces where the mutation commits strictly after t_f are outside the theorem premise (irreducible TOCTOU window) and are not violations.",
    "Each omission experiment removes exactly one premise; combined omissions are out of scope.",
    "Omission experiments run in bracket (pre-observation plus post-recheck cache observation pairs) mode; the full contract is checked in both bracket and strict observation modes.",
    "Omission entry statuses are independent single-premise results: an omission FAIL demonstrates the removed control is load-bearing within this model (and, for each control, a matching Rust E2 omission experiment exists); an omission PASS means not-independently-falsifiable within this model (the remaining controls close every enumerated schedule) and is NOT a claim that the control is useless in the real protocol.",
    "The top-level report status and fullContract.status describe ONLY the full contract (all modeled premises enabled); they are never an aggregate over the omission results.",
    "Status precedence: a concrete counterexample is decisive -- a run with at least one in-domain violation reports FAIL even when the exploration was otherwise incomplete (bound truncation); PASS requires a complete exploration with zero violations; UNKNOWN covers incomplete explorations without counterexamples and undecidable (overlap) trace domains. BLOCKED is reserved in the shared vocabulary for a checker that could not run; this in-process tool raises BoundError or exits with code 2 before any report exists and never emits BLOCKED.",
    "The rollback adversary performs at most one pointer rollback and only after the manifest advance.",
    "Cache reads observe the cache state at the read's completion step; the strict-observation mode models an atomic re-check and omits the separate pre-observation requirement of the bracket mode.",
    "Enumeration is a deterministic exhaustive merge of the event chains with fixed chain priority (checklist, pre-observation, mutation, evidence body, bypass); the first reported counterexample is minimal by (event count, lexicographic event tuple).",
    "A bound below a configuration's required bound (1 + alphabet size) yields an incomplete exploration reported UNKNOWN, never PASS.",
    "Full-contract PASS is an abstract bounded property only; it is not evidence about the production implementation by itself.",
];

const STATUS_SCOPE: &str = "The top-level status and fullContract.status describe ONLY the full contract (all modeled premises enabled). Each omissions[] entry carries its own independent single-premise status: an omission FAIL is an expected, informative result (the removed control is load-bearing within this model, with a matching Rust E2 omission experiment) and never changes the top-level status; an omission PASS means not-independently-falsifiable within this model, not that the control is useless in the real protocol.";

const STATUS_VOCABULARY: [(&str, &str); 4] = [
    (
        "PASS",
        "the property held in every explored trace of the bounded abstract model and the exploration was complete",
    ),
    (
        "FAIL",
        "at least one in-domain counterexample trace exists in the bounded abstract model; decisive even when the exploration was otherwise incomplete",
    ),
    (
        "BLOCKED",
        "reserved in the shared evidence vocabulary for a checker that could not run (e.g., invalid configuration); this in-process tool raises BoundError or exits with code 2 before any report exists, so no report produced by this tool ever carries BLOCKED",
    ),
    (
        "UNKNOWN",
        "the exploration was incomplete (bound below the configuration's required bound) without a counterexample, or the trace domain is undecidable (overlapping commit/final-observation intervals)",
    ),
];

const INTENDED_SCHEDULES: [&str; 6] = [
    "source-pending trace: the probes are gone, so a publication completing in the free window after the last read is never latched",
    "intra-load publication trace: the mutation fully publishes between m0 and p0, the m0-anchored evidence goes stale, and with no post-recheck nothing confronts it",
    "no-final-load trace: without the load there are no pending probes and no evidence; the pre-observation fallback admits the stale candidate (matches the Rust e2 final-reload-omission experiment)",
    "successor-revision trace",
    "pointer-rollback trace: below-head reads are accepted without the read gate",
    "unmediated bypass admission trace",
];

fn premise_description(premise: &str) -> &'static str {
    match premise {
        "pending_probe" => "the final load probes pending state at read time (p0 after m0 and p1 after m1 in the ordered m0<p0<m1<p1 bracket, or the strict load's atomic probe); any probe observing an incomplete mutation (commit begun but not durable, or durable but publication incomplete -- publication completes only when BOTH the manifest advance and the evidence body advance have fired) latches the admission fail-closed; publication completing after the probes does not resurrect a latched unsafe delta and there is no admission-time re-derivation",
        "post_recheck" => "cache pre/post bracket: valid pre-observation strictly before the durable commit, plus a post-recheck read (post-observation interval or strict observation) that is valid and agrees with the m0-anchored admission evidence",
        "final_reload" => "admission evidence must come from a valid final load -- the ordered m0/p0/m1/p1 observation sequence (bracket) or one atomic strict load -- anchored at m0, the theorem's t_f; removing it removes the pending probes with it (they run inside the load)",
        "exact_identity" => "candidate match requires evidence revision == candidate revision r0 (without it, grant-presence matching admits successor revisions)",
        "generation_revoke_fence" => "read gate ONLY (the Rust implementation has no admission-time watermark): reads whose observed manifest/body pair is mismatched (torn) or whose generation is below the published head are rejected fail-closed; a rejected read poisons admission",
        "host_mediation" => "all admission goes through the mediated checklist (no bypass path)",
        _ => "",
    }
}

fn omission_note(premise: &str) -> &'static str {
    match premise {
        "pending_probe" => "Without the pending probe the load observes only m0 and m1. A schedule where the source commit is durable before t_f (m0), the cache still serves the pre-invalidation pair (g0, r0) through the last read, and the publication completes in the free window after the last read and before admission leaves nothing latched: every remaining gate passes and the stale candidate is admitted. With the probe on, p0/p1 would have captured pending=true at read time and latched the admission fail-closed.",
        "post_recheck" => "Without the post-recheck, a schedule where the publication fully completes INSIDE the final load, between m0 and p0, survives: p0 and p1 then observe pending=false (the publication is complete at their read steps), the evidence stays anchored at the earlier m0 (g0, r0), and no later read confronts it. The admission is stale (the commit was durable before t_f) and every remaining gate passes. With the recheck on, the post-read disagrees with the m0-anchored evidence and denies -- this is the latched identity stability the real protocol enforces between observations.",
        "final_reload" => "Without the final load there are no pending probes (they run inside the load) and no m0-anchored evidence: the admission evidence falls back to the earlier pre-observation. A durable commit before that observation with the publication still incomplete at admission is admitted stale -- matching the Rust e2 final-reload-omission experiment, where omitting the final reload accepts the removed candidate while the full contract reloads.",
        "exact_identity" => "Without exact identity, a fully published successor revision (r1/g1) satisfies a grant-presence match for candidate r0; the probes observe pending=false (the publication is complete at their read steps), the recheck agrees, and the read gate passes. With identity off a rollback AFTER the last read also violates (the evidence was already read at g1, so no read re-observes the rolled-back cache). The full contract rejects both: exact identity denies the successor revision.",
        "generation_revoke_fence" => "Without the read gate, a pointer rollback to (g0, r0) after a complete publication is served to the final load below the published head and accepted: the evidence is the stale r0 body, the probes observe pending=false (the publication completed at their read steps), and every remaining gate passes. Torn manifest/body reads are also enumerated without the fence; in the theorem domain they are still denied (a torn pair implies an incomplete publication, which the probes latch, or a disagreement at the recheck), and the only admitted torn-read traces lie in the after-t_f TOCTOU domain (the mutation begins after m0, publishes, and a rollback restores the old cache so the recheck agrees again) -- outside the theorem, never violations. The reported counterexample is the minimal one.",
        "host_mediation" => "Without host mediation a bypass admission path exists that skips the entire mediated checklist; any schedule reaching it after a durable commit admits the stale candidate without any gate.",
        _ => "",
    }
}

pub fn build_report(bound: usize) -> Result<Value, String> {
    validate_bound(bound)?;
    let full_premises = Premises::default();
    let bracket = run_model(full_premises, Mode::Bracket, bound)?;
    let strict = run_model(full_premises, Mode::Strict, bound)?;
    let modes = json!({"bracket": bracket, "strict": strict});
    let mode_statuses = [
        modes["bracket"]["status"].as_str(),
        modes["strict"]["status"].as_str(),
    ];
    let full_status = if mode_statuses.contains(&Some("FAIL")) {
        "FAIL"
    } else if mode_statuses.contains(&Some("UNKNOWN")) {
        "UNKNOWN"
    } else {
        "PASS"
    };
    let mut omissions = Vec::with_capacity(PREMISES.len());
    let mut total_states = modes["bracket"]["exploredStates"]
        .as_u64()
        .unwrap_or_default()
        + modes["strict"]["exploredStates"]
            .as_u64()
            .unwrap_or_default();
    let mut total_traces = modes["bracket"]["exploredTraces"]
        .as_u64()
        .unwrap_or_default()
        + modes["strict"]["exploredTraces"]
            .as_u64()
            .unwrap_or_default();
    for (index, premise) in PREMISES.iter().enumerate() {
        let run = run_model(full_premises.without(premise)?, Mode::Bracket, bound)?;
        total_states += run["exploredStates"].as_u64().unwrap_or_default();
        total_traces += run["exploredTraces"].as_u64().unwrap_or_default();
        let has_counterexample = run["violations"].as_u64().unwrap_or_default() > 0;
        let complete = run["explorationComplete"].as_bool() == Some(true);
        let (status, finding) = if has_counterexample {
            ("FAIL", "counterexample_found")
        } else if complete {
            ("PASS", "not_independently_falsifiable")
        } else {
            ("UNKNOWN", "not_determined_incomplete_exploration")
        };
        omissions.push(json!({
            "premise": premise,
            "premiseRemoved": premise,
            "status": status,
            "finding": finding,
            "intendedSchedule": INTENDED_SCHEDULES[index],
            "counterexample": run["counterexample"],
            "note": omission_note(premise),
            "run": run,
        }));
    }
    let premise_descriptions = PREMISES
        .iter()
        .map(|premise| ((*premise).to_owned(), json!(premise_description(premise))))
        .collect::<Map<_, _>>();
    let status_vocabulary = STATUS_VOCABULARY
        .iter()
        .map(|(status, description)| ((*status).to_owned(), json!(description)))
        .collect::<Map<_, _>>();
    let scope_limitations = SCOPE_LIMITATIONS
        .iter()
        .map(|limitation| json!(limitation))
        .collect::<Vec<_>>();
    Ok(json!({
        "model": MODEL_NAME,
        "modelVersion": MODEL_VERSION,
        "theorem": THEOREM_ID,
        "method": "exhaustive depth-first enumeration of a finite explicit state model; no external solver, no subprocess, no network",
        "bound": bound,
        "boundValidation": {"min": MIN_BOUND, "max": MAX_BOUND, "valid": true},
        "exploredStates": total_states,
        "exploredTraces": total_traces,
        "fullContract": {
            "status": full_status,
            "meaning": "abstract bounded property only, conditional on every structural assumption in scopeLimitations (fixed checklist order; pending probes latched at read time inside the final load m0<p0<m1<p1 or the atomic strict load; t_f = m0; one mutation, one rollback, one successor revision; two sub-event publication; dense steps; NO admission-time re-derivation and NO admission-side watermark, matching the current Rust implementation): zero traces in this model where a mutation committed strictly before t_f AND a stale candidate reached host admission. The window between the last read and admission is FREE: a publication completing there is caught by the latched unsafe pending delta, not by any admission-time check. Out-of-domain (overlap/after) admissions are reported separately in admittedDomainCounts and are outside the theorem. This implies nothing beyond this model and is not evidence about the production implementation.",
            "modes": modes,
        },
        "omissions": omissions,
        "status": full_status,
        "statusScope": STATUS_SCOPE,
        "statusVocabulary": status_vocabulary,
        "premiseDescriptions": premise_descriptions,
        "scopeLimitations": scope_limitations,
    }))
}

pub fn format_text_report(report: &Value) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "{} v{} (theorem {}) -- abstract bounded-model evidence ONLY",
        report["model"].as_str().unwrap_or(MODEL_NAME),
        report["modelVersion"].as_str().unwrap_or(MODEL_VERSION),
        report["theorem"].as_str().unwrap_or(THEOREM_ID)
    ));
    lines.push(format!(
        "bound={} exploredStates={} exploredTraces={}",
        report["bound"], report["exploredStates"], report["exploredTraces"]
    ));
    lines.push(String::new());
    lines.push("Full contract (all six premises on):".into());
    for mode in ["bracket", "strict"] {
        let run = &report["fullContract"]["modes"][mode];
        lines.push(format!(
            "  [{mode}] status={} violations={} admitted={} denied={} overlapAdmitted={} complete={} requiredBound={}",
            run["status"].as_str().unwrap_or("UNKNOWN"),
            run["violations"].as_u64().unwrap_or_default(),
            run["admittedTraces"].as_u64().unwrap_or_default(),
            run["deniedTraces"].as_u64().unwrap_or_default(),
            run["admittedDomainCounts"]["overlapUnknown"].as_u64().unwrap_or_default(),
            if run["explorationComplete"].as_bool() == Some(true) {
                "True"
            } else {
                "False"
            },
            run["requiredBound"].as_u64().unwrap_or_default(),
        ));
        let window = &run["admissionWindow"];
        let mixed = &run["mixedManifestBody"];
        lines.push(format!(
            "      window: publish-after-last-read traces={} admitted={} publish-after-t_f traces={} admitted={}; torn M/b reads: traces={} admitted={}",
            window["publishAfterLastReadBeforeAdmissionTraces"].as_u64().unwrap_or_default(),
            window["admittedPublishAfterLastRead"].as_u64().unwrap_or_default(),
            window["publishAfterFinalObservationBeforeAdmissionTraces"].as_u64().unwrap_or_default(),
            window["admittedPublishAfterFinalObservation"].as_u64().unwrap_or_default(),
            mixed["tornReadTraces"].as_u64().unwrap_or_default(),
            mixed["admittedTornReadTraces"].as_u64().unwrap_or_default(),
        ));
        let denial_reasons = run["denialReasons"]
            .as_object()
            .map(|values| {
                values
                    .iter()
                    .map(|(name, count)| {
                        format!("\"{name}\": {}", count.as_u64().unwrap_or_default())
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        lines.push(format!("      latched denials: {{{denial_reasons}}}"));
    }
    lines.push(format!(
        "  => fullContract status: {}",
        report["fullContract"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN")
    ));
    lines.push(String::new());
    lines.push("Single-premise omission experiments (bracket mode):".into());
    if let Some(omissions) = report["omissions"].as_array() {
        for item in omissions {
            lines.push(format!(
                "  without {:24} status={} finding={}",
                item["premise"].as_str().unwrap_or(""),
                item["status"].as_str().unwrap_or("UNKNOWN"),
                item["finding"].as_str().unwrap_or(""),
            ));
            if let Some(trace) = item["counterexample"]["trace"].as_array() {
                let events = trace
                    .iter()
                    .filter_map(|entry| entry["event"].as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ");
                lines.push(format!(
                    "    counterexample: class={} events={} trace={}",
                    item["counterexample"]["scheduleClass"]
                        .as_str()
                        .unwrap_or(""),
                    item["counterexample"]["eventCount"]
                        .as_u64()
                        .unwrap_or_default(),
                    events,
                ));
            }
        }
    }
    lines.push(String::new());
    lines.push(format!(
        "Overall status: {}",
        report["status"].as_str().unwrap_or("UNKNOWN")
    ));
    lines.push("Status scope: top-level status reflects the full contract only;".into());
    lines.push("omission statuses are independent single-premise results.".into());
    lines.push(String::new());
    lines.push("Scope limitations:".into());
    if let Some(limitations) = report["scopeLimitations"].as_array() {
        lines.extend(
            limitations
                .iter()
                .filter_map(Value::as_str)
                .map(|item| format!("  - {item}")),
        );
    }
    lines.join("\n")
}
