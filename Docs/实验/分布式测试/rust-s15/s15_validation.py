"""Pure S15 selection and evidence-coverage predicates (no I/O)."""

from __future__ import annotations

from typing import Iterable, Mapping, Optional, Sequence, Set

SCENARIO_NAMES = tuple("S%d" % number for number in range(1, 16))
MIN_FULL_ROUNDS = 3

REQUIRED_CASES: Mapping[str, tuple[str, ...]] = {
    "S1": (
        "S1_both_concurrent_writes_200",
        "S1_all_nodes_allow_after_projection",
        "S1_unique_head_contiguous_generations",
    ),
    "S2": (
        "S2_revoke_commit_200",
        "S2_no_stale_allow_window",
        "S2_all_nodes_deny",
        "S2_deltas_succeeded_after_projection",
    ),
    "S3": (
        "S3_stale_replay_structurally_rejected",
        "S3_stale_replay_no_resurrect",
        "S3_pointer_unchanged_by_stale_replay",
        "S3_replayed_row_absent",
    ),
    "S4": (
        "S4_unbind_200",
        "S4_unbind_propagates_deny",
        "S4_revoke_fence_advanced",
        "S4_rebind_restores_allow",
    ),
    "S5": (
        "S5_baseline_written", "S5_baseline_drained", "S5_lease_claimed",
        "S5_reclaimed_by_other_node", "S5_single_terminal_transition",
        "S5_obsolete_owner_no_second_terminal", "S5_pointer_and_decisions_unchanged",
        "S5_outbox_all_terminal_after_reclaim", "S5_unbound_has_no_target_delta",
        "S5_drain_clean",
    ),
    "S6": (
        "S6_alternating_convergence", "S6_generation_strictly_increasing",
        "S6_outbox_integrity",
    ),
    "S7": ("S7_epoch_present", "S7_stale_residue_not_served"),
    "S8": ("S8_abac_attribute_change",),
    "S9": (
        "S9_storm_no_stale_allow", "S9_storm_converge_deny", "S9_generation_no_loss",
    ),
    "S10": (
        "S10_baseline_written", "S10_baseline_drained", "S10_lease_observed",
        "S10_second_projector_blocked", "S10_owner_completes_unique_terminal",
        "S10_obsolete_owner_no_second_terminal", "S10_pointer_and_decisions_unchanged",
        "S10_outbox_all_terminal_after_reclaim", "S10_unbound_has_no_target_delta",
        "S10_drain_clean",
    ),
    "S11": (
        "S11_grant_evidence_self_consistent", "S11_revoke_evidence_self_consistent",
    ),
    "S12": ("S12_arbiter_r1_fence_deny",),
    "S13": (
        "S13_arbiter_unprovable_defers", "S13_arbiter_empty_evidence_rejected",
        "S13_entry_gate_denies_after_cleanup",
    ),
    "S14": (
        "S14_process_restarted", "S14_no_stale_allow_during_down",
        "S14_node_c_ready_after_restart", "S14_all_nodes_deny_after_restart",
    ),
    "S15": (
        "S15_redis_stopped", "S15_redis_recovered",
        "S15_no_stale_allow_during_redis_down", "S15_no_stale_allow_after_restart",
        "S15_all_nodes_deny_final",
    ),
}


def validate_run_selection(rounds: object, only: Optional[Iterable[str]]) -> list[str]:
    """Return validation errors without accessing run configuration or services."""
    errors: list[str] = []
    if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds <= 0:
        errors.append("rounds_must_be_positive")
    if only is not None:
        selected = set(only)
        unknown = sorted(selected - set(SCENARIO_NAMES))
        if unknown:
            errors.append("unknown_only:" + ",".join(unknown))
        if not selected:
            errors.append("only_must_select_at_least_one_scenario")
    return errors


def missing_required_cases(
    selected: Iterable[str], recorded_names: Iterable[str]
) -> dict[str, list[str]]:
    """Return absent required case names for selected scenarios."""
    recorded: Set[str] = set(recorded_names)
    missing = {
        scenario: [name for name in REQUIRED_CASES[scenario] if name not in recorded]
        for scenario in sorted(set(selected))
        if scenario in REQUIRED_CASES
    }
    return {scenario: names for scenario, names in missing.items() if names}


def missing_nonpass_cases(
    selected: Iterable[str], round_verdicts: Mapping[str, str]
) -> dict[str, list[str]]:
    """Return required case labels whose observed verdict is not exactly PASS."""
    return {
        scenario: [
            name for name in REQUIRED_CASES[scenario]
            if round_verdicts.get(name) != "PASS"
        ]
        for scenario in sorted(set(selected))
        if scenario in REQUIRED_CASES
        and any(round_verdicts.get(name) != "PASS" for name in REQUIRED_CASES[scenario])
    }


def campaign_coverage(
    *,
    rounds: int,
    rounds_done: int,
    only: Optional[Sequence[str]],
    round_missing_cases: Sequence[Mapping[str, Sequence[str]]],
    round_case_verdicts: Optional[Sequence[Mapping[str, str]]] = None,
) -> dict[str, object]:
    """Summarize complete-vs-partial coverage; scoped runs never claim complete."""
    missing = [
        {name: list(cases) for name, cases in round_result.items()}
        for round_result in round_missing_cases
    ]
    partial = only is not None
    full_scope = not partial
    sufficient_repeats = rounds >= MIN_FULL_ROUNDS and rounds_done == rounds
    all_cases = len(missing) == rounds_done and all(not result for result in missing)
    positive_cases = round_case_verdicts is not None and len(round_case_verdicts) == rounds_done and all(
        verdicts.get(case) == "PASS"
        for verdicts in (round_case_verdicts or ())
        for scenario in (only or SCENARIO_NAMES)
        for case in REQUIRED_CASES.get(scenario, ())
    )
    complete = full_scope and sufficient_repeats and all_cases and positive_cases
    return {
        "scope": "partial" if partial or not sufficient_repeats else "full",
        "complete": complete,
        "roundsRequested": rounds,
        "roundsDone": rounds_done,
        "minimumFullRounds": MIN_FULL_ROUNDS,
        "selectedScenarios": list(only) if only is not None else list(SCENARIO_NAMES),
        "partial": partial or not sufficient_repeats or not all_cases or not positive_cases,
        "requiredCasePasses": positive_cases,
        "missingCasesByRound": missing,
    }
