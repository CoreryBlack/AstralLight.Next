# Python unittest 到 Rust 原生测试逐方法 crosswalk

> 状态：迁移审查账本（2026-10-24 建立，CURRENT V6 删除任务同步）。此表保留 25 个历史 unittest 模块的 622 个 `test_*` 方法来源，并登记保留的 Rust 行为合同或明确退役的能力。Python unittest/归档 Python 测试不运行。`EQUIVALENT` 仅指列出的离线行为断言等价；`PARTIAL` 指仍有关键断言差异；`BLOCKED` 指依赖或执行证据缺失；`RETIRED` 指 CURRENT V6 已物理删除原正向能力，所列 Rust 目标仅验证替代入口或拒绝旧配置，不计等价覆盖，也不表示测试 PASS。
>
> 证据状态补充：保留的 Chat/Learn runtime 记录和 Redis fixtures/reports 仅是历史基线、比较或退役兼容证据；不属于当前 runtime、当前 gate 或真实集成 `PASS`。直接 Monitor health 是服务直连观察，不等同受保护 Monitor contract。资源退役必须等待 canonical revoke、generation 和 published-evidence barriers；密码投递无 notifier handoff 时为 unavailable/`PENDING`；`UNKNOWN`/`PENDING` 及跨 aggregate completion 均须先完成完整 receipt/evidence 对账。

## 总体结论

- 历史 Python unittest 库存为 25 模块、622 方法，来源方法与分区保持不变。2026-10-24 的审查曾登记 621 EQUIVALENT、1 PARTIAL；该历史计数不再代表 CURRENT V6 的覆盖结论。CURRENT V6 当前清单为 599 EQUIVALENT、9 PARTIAL、0 BLOCKED、14 RETIRED，合计 622；各行状态以本表为准，执行数量和结果以对应 Cargo 日志与唯一任务证据为准。
- Redis profile、Redis adapter/command、执行协议 selector 和 Python 日志过滤器的正向合同已经退役；拒绝旧配置、SQL 只读、原生有界日志采集/过滤/脱敏及 UNKNOWN 状态保留为当前 Rust 断言。旧能力删除不计为等价迁移。
- `test_actor_switching_roles_and_cards` 仍为 PARTIAL；fake、受限本机子进程及 parser/reducer 断言均不证明真实依赖、HTTP campaign 或三节点部署通过。
- 已删除的 `experiments/tdsc/protocol-runner/test_run_performance.py` 以基线 `62b434937270352d54ea70c9be7081d616099b24` 的 Git blob `53839fda51d4fe8888da598810b7e75ffb5b18a7` 固定十个历史方法名；库存由 Rust guard 保存，当前独立统计 parser 测试只运行 `tdsc_performance.rs`，不恢复旧 runner。
- 手工 OPA 实验脚本、pipeline 扫描脚本、旧 Python campaign runner 实现不是 unittest 模块，不计入 25/622。OPA/pipeline 仅为工具/历史实验材料，不作为现行系统验收入口。

<!-- python-source: scripts/tests/test_test_campaign.py -->
## `scripts/tests/test_test_campaign.py`（67 方法）

| Python 方法 | 主要断言 / Rust 等价位置 | 状态和边界 |
|---|---|---|
| `test_all_series_are_registered` | `campaign.rs::tests::selection_uses_registered_profiles_and_series_families`; `manifest_entries_are_scoped_and_blocked_entries_are_not_dispatched` | EQUIVALENT：系列族与 manifest 登记。 |
| `test_default_does_not_request_live_dependencies` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：默认选 portable profiles、无 service、无 blocked suite。 |
| `test_instrumented_e_series_are_not_lost_by_consolidation` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：E1/E3/E4 observability argv 与 service。 |
| `test_explicit_all_profiles_retains_blocked_and_live_suites` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：全 profile 保留 blocked 与有服务项。 |
| `test_m_family_does_not_include_mt_or_compat` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：M 系列边界。 |
| `test_e_family_does_not_include_excluded_or_mt` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：E 系列不包含 historical excluded suite 与 MT。 |
| `test_exact_e2_has_five_runtime_targets` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：5 项、精确过滤和期望数量。 |
| `test_explicit_suite_overrides_default_profiles` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：显式 suite 选择。 |
| `test_owned_projection_suites_keep_their_execution_and_evidence_scope` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：worker-owned、service/scope、ignored argv、source 与 model boundary。 |
| `test_unknown_selection_fails` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：未知 profile/series/suite 拒绝。 |
| `test_empty_selection_fails` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：空选择拒绝。 |
| `test_test_services_equal_their_production_profile` | `selection_uses_registered_profiles_and_series_families`; `manifest_entries_are_scoped_and_blocked_entries_are_not_dispatched` | EQUIVALENT：服务拓扑一致。 |
| `test_service_contract_matches_offline_fault_profiles` | `dependency_profiles.rs::tests::all_profiles_pin_exact_services_dependencies_and_fault_membership`; `every_fault_dependency_and_matrix_entry_is_explicit`; `unknown_profiles_and_retired_redis_faults_fail_closed` | EQUIVALENT：离线注册表/profile 矩阵；不证明 live fault。 |
| `test_blocked_campaign_cannot_dispatch_legacy_command` | `manifest_entries_are_scoped_and_blocked_entries_are_not_dispatched` | EQUIVALENT：blocked entry argv 必为空。 |
| `test_missing_mt_e2_is_explicit` | `selection_uses_registered_profiles_and_series_families` | EQUIVALENT：单项存在并保持 blocked。 |
| `test_kernel_removes_all_live_credentials` | `campaign.rs::tests::native_environment_clears_live_credentials` | EQUIVALENT：离线 profile 清理 live env 并固定本地传输，移除继承的退役 selector。 |
| `test_projection_execution_mode_is_selected_by_suite_not_parent` | `campaign.rs::tests::native_profiles_select_only_declared_services_and_scrub_retired_selectors` | RETIRED：执行协议 selector 已删除；当前只有 WorkerOwned，Rust 断言仅验证继承 selector 被清除。 |
| `test_native_uses_only_mysql` | `campaign.rs::tests::native_profiles_select_only_declared_services_and_scrub_retired_selectors`; `preflight_requires_an_exact_isolated_database_and_loopback_service` | EQUIVALENT：service selection 和 MySQL 配置。 |
| `test_rabbit_uses_mysql_and_explicit_vhost_only` | `campaign.rs::tests::native_profiles_select_only_declared_services_and_scrub_retired_selectors` | EQUIVALENT：Rabbit profile 与显式 vhost。 |
| `test_native_environment_scrubs_retired_redis_inputs` | `campaign.rs::tests::native_environment_clears_live_credentials`; `campaign.rs::tests::native_profiles_select_only_declared_services_and_scrub_retired_selectors`; `dependency_profiles.rs::tests::unknown_profiles_and_retired_redis_faults_fail_closed` | RETIRED：Redis runtime/profile 已物理删除；当前断言清理继承的 Redis 输入并拒绝退役 profile，不再启用 Redis。 |
| `test_absent_live_prerequisite_is_blocked` | `campaign.rs::tests::preflight_requires_an_exact_isolated_database_and_loopback_service`; `campaign/run_tests.rs::tests::run_selected_collection_preflight_blocks_every_suite_for_missing_database` | EQUIVALENT：blocked preflight 全量 fail-before-dispatch。 |
| `test_nonisolated_database_and_extra_options_are_rejected` | `campaign.rs::tests::preflight_requires_an_exact_isolated_database_and_loopback_service` | EQUIVALENT：host/库名/端口/query fail-closed；Rust 额外也检查 fragment。 |
| `test_run_scoped_database_requires_exact_name_environment` | `campaign.rs::tests::preflight_requires_an_exact_isolated_database_and_loopback_service` | EQUIVALENT：run-scoped 名称前缀、匹配及格式。 |
| `test_dedicated_mapping_does_not_use_general_database` | `campaign.rs::tests::dedicated_identity_mapping_requires_its_exact_run_scoped_database` | EQUIVALENT：专用 DB 不回退通用 URL。 |
| `test_nonzero_is_fail_not_pass` | `campaign.rs::tests::explicit_status_and_process_outcomes_keep_fail_closed_precedence`; `acceptance.rs::tests::rust_summary_requires_nonempty_exact_and_unskipped_assertions` | EQUIVALENT：nonzero FAIL。 |
| `test_deadline_and_interrupt_are_unknown` | `campaign.rs::tests::explicit_status_and_process_outcomes_keep_fail_closed_precedence`; `campaign.rs::tests::execute_terminates_timed_out_process_group_and_returns_unknown` | EQUIVALENT：离线 synthetic timeout/process-group UNKNOWN。 |
| `test_empty_rust_exit_zero_fails` | `acceptance.rs::tests::rust_summary_requires_nonempty_exact_and_unskipped_assertions` | EQUIVALENT：缺 summary/零断言 FAIL。 |
| `test_exact_assertion_count_is_required` | `acceptance.rs::tests::rust_summary_requires_nonempty_exact_and_unskipped_assertions` | EQUIVALENT：exact/minimum test counts。 |
| `test_cargo_ignored_not_hidden_by_exit_zero` | `acceptance.rs::tests::rust_summary_requires_nonempty_exact_and_unskipped_assertions` | EQUIVALENT：ignored 保留 SKIP/count。 |
| `test_internal_skip_preserves_assertion_counts` | `acceptance.rs::tests::rust_summary_requires_nonempty_exact_and_unskipped_assertions`; `campaign.rs::tests::classify_output_requires_complete_evaluate_and_divan_evidence` | EQUIVALENT：internal SKIP 优先且保留 Rust summary counts。 |
| `test_python_requires_nonempty_ok_summary` | `campaign.rs::tests::retired_unittest_acceptance_never_mints_pass_from_python_output` | RETIRED：Python unittest summary 验收器已删除；替代断言保证旧 summary 不能生成 PASS。 |
| `test_expected_model_counterexample_is_not_whole_failure` | `campaign.rs::tests::model_dependency_and_required_output_acceptance_keep_contract_boundaries`; `model_acceptance.rs::tests::full_contract_checks_identity_modes_counts_status_and_omissions` | EQUIVALENT：预期 omission/counterexample 不等于 full-contract FAIL。 |
| `test_incomplete_and_missing_model_modes_not_pass` | `campaign.rs::tests::model_dependency_and_required_output_acceptance_keep_contract_boundaries`; `model_acceptance.rs::tests::accepts_both_full_contract_wire_shapes_and_rejects_missing_modes` | EQUIVALENT：缺模式 UNKNOWN。 |
| `test_model_violation_and_inconsistent_contract_fail` | `campaign.rs::tests::model_dependency_and_required_output_acceptance_keep_contract_boundaries`; `model_acceptance.rs::tests::full_contract_checks_identity_modes_counts_status_and_omissions` | EQUIVALENT：违规和不一致 FAIL；identity/count 检查。 |
| `test_two_mutation_summary_is_supported` | `campaign.rs::tests::model_dependency_and_required_output_acceptance_keep_contract_boundaries`; `model_acceptance.rs::tests::accepts_both_full_contract_wire_shapes_and_rejects_missing_modes` | EQUIVALENT：two-mutation summary wire shape。 |
| `test_hypothesis_unknown_is_not_proven` | `model_acceptance.rs::tests::universal_acceptance_requires_exact_two_models_and_all_hypothesis_evidence`; `universal_hypotheses.rs::tests::incomplete_model_evidence_never_mints_universal_pass` | EQUIVALENT：UNKNOWN 不能成 PASS。 |
| `test_native_dependency_tree_checks_actual_root_and_redis` | `campaign.rs::tests::model_dependency_and_required_output_acceptance_keep_contract_boundaries` | EQUIVALENT：要求正确 root 且拒绝 Redis。 |
| `test_required_command_postcondition_is_not_exit_code_only` | `campaign.rs::tests::model_dependency_and_required_output_acceptance_keep_contract_boundaries` | EQUIVALENT：命令必需 marker。 |
| `test_complete_evaluate_routes_to_strict_evidence_acceptance` | `campaign.rs::tests::classify_output_requires_complete_evaluate_and_divan_evidence`; `evaluate_acceptance.rs::tests::complete_policy_evaluate_protocol_is_accepted_without_speed_threshold` | EQUIVALENT：严格协议入口、scope/postcondition/test counts。 |
| `test_complete_evaluate_exit_zero_without_records_fails` | `campaign.rs::tests::classify_output_requires_complete_evaluate_and_divan_evidence` | EQUIVALENT：只有 Rust exit-0 summary 不够。 |
| `test_complete_evaluate_measurements_cannot_override_rust_nonpass` | `campaign.rs::tests::classify_output_requires_complete_evaluate_and_divan_evidence` | EQUIVALENT：FAIL/SKIP/UNKNOWN 优先，不解析证据覆盖状态。 |
| `test_complete_cpu_matrix_preserves_measurements` | `campaign.rs::tests::cpu_performance_matrix_requires_exact_unique_cases_and_fifteen_samples` | EQUIVALENT：原始 matrix 与 CPU-only scope 保留。 |
| `test_filtered_duplicate_or_empty_performance_is_not_pass` | `campaign.rs::tests::cpu_performance_matrix_requires_exact_unique_cases_and_fifteen_samples` | EQUIVALENT：filtered/empty/duplicate FAIL。 |
| `test_insufficient_performance_samples_fail` | `campaign.rs::tests::cpu_performance_matrix_requires_exact_unique_cases_and_fifteen_samples` | EQUIVALENT：15-sample 下限。 |
| `test_explicit_nonpass_state_overrides_exit_zero_success_output` | `campaign.rs::tests::explicit_status_and_process_outcomes_keep_fail_closed_precedence` | EQUIVALENT：大小写、stdout/stderr marker precedence。 |
| `test_pending_output_keeps_failure_and_interruption_precedence` | `campaign.rs::tests::explicit_status_and_process_outcomes_keep_fail_closed_precedence` | EQUIVALENT：nonzero FAIL 胜过 PENDING；interrupt/UNKNOWN 胜过。 |
| `test_lowercase_nonpass_markers_are_not_success` | `campaign.rs::tests::explicit_status_and_process_outcomes_keep_fail_closed_precedence` | EQUIVALENT：小写 marker。 |
| `test_pending_command_output_stops_both_phases_without_retry` | `campaign/run_tests.rs::tests::run_selected_pending_output_stops_both_phases_without_retry` | EQUIVALENT：本机 shell synthetic marker、两个 phase 不派发及 retries=0；不涉及真实依赖。 |
| `test_fold_preserves_nonpass_status` | `campaign.rs::tests::secrets_urls_and_status_folding_remain_fail_closed` | EQUIVALENT：折叠时 UNKNOWN/空集 fail-closed；其余非 PASS 由 phase 合同覆盖。 |
| `test_secret_and_connection_url_scrubbing` | `campaign.rs::tests::secrets_urls_and_status_folding_remain_fail_closed` | EQUIVALENT：env secret 与 URL 清理。 |
| `test_real_subprocess_only_writes_owned_temporary_logs` | `campaign.rs::tests::execute_waits_for_descendants_before_freezing_logs`; `campaign/run_tests.rs::tests::run_selected_publishes_owned_report_and_executes_only_local_contract_commands` | EQUIVALENT（范围限定）：Rust 仅执行本机受限命令、落在临时 owned dir；不把 Python command 执行行为映射为服务测试。 |
| `test_artifact_hashes_match_exact_written_bytes_after_redaction` | `campaign.rs::tests::execute_redacts_short_secrets_normalizes_newlines_and_hashes_exact_artifacts`; `execute_waits_for_descendant_stderr_and_hashes_the_frozen_bytes` | EQUIVALENT：stdout/stderr 脱敏、URL scrubbing、CRLF 归一化、最终落盘 bytes SHA-256 一致；未连接真实服务。 |
| `test_subprocess_deadline_is_unknown_without_retry` | `campaign.rs::tests::execute_terminates_timed_out_process_group_and_returns_unknown` | EQUIVALENT：本机 `/bin/sleep` timeout/UNKNOWN/stream_disconnect；子进程安全、无外部连接。 |
| `test_timeout_waits_for_delayed_descendant_stderr_before_hashing` | `campaign.rs::tests::execute_timeout_waits_for_delayed_descendant_stderr_before_hashing` | EQUIVALENT：timeout 后受控子进程组以 TERM 收尾，等完整 stderr 后冻结并 hash；本机 synthetic process only。 |
| `test_completed_parent_waits_for_descendant_output_before_pass` | `campaign.rs::tests::execute_waits_for_descendant_stderr_and_hashes_the_frozen_bytes`; `execute_waits_for_descendants_before_freezing_logs` | EQUIVALENT：父进程结束后等待后代 stderr，终态 PASS/complete、冻结后 bytes 稳定且 hash 相符；本机 synthetic process only。 |
| `test_unknown_stops_subsequent_dispatch_and_saves_evidence` | `campaign/run_tests.rs::tests::run_selected_fail_stops_on_every_nonpass_in_either_phase`; `run_selected_keeps_report_pending_until_every_phase_finishes` | EQUIVALENT：UNKNOWN 停派、保存终态和 phase 证据。 |
| `test_source_change_invalidates_result` | `campaign/run_tests.rs::tests::run_selected_marks_source_changes_before_or_during_dispatch_unknown` | EQUIVALENT：freeze 前/执行中 snapshot 漂移为 UNKNOWN。 |
| `test_every_nonpass_stops_and_fresh_rerun_restarts_the_selection` | `campaign/run_tests.rs::tests::run_selected_fail_stops_on_every_nonpass_in_either_phase`; `run_selected_fresh_run_reexecutes_the_original_full_selection` | EQUIVALENT：各状态 fail-stop、fresh run 重新全选；不缓存旧 PASS。 |
| `test_missing_collection_prerequisite_blocks_all_before_dispatch` | `campaign/run_tests.rs::tests::run_selected_collection_preflight_blocks_every_suite_for_missing_database` | EQUIVALENT：收集级 prerequisite 缺失时全部 BLOCKED 且 executor 调用数为零。 |
| `test_common_credential_names_are_redacted_even_for_short_values` | `campaign.rs::tests::secrets_urls_and_status_folding_remain_fail_closed`; `execute_redacts_short_secrets_normalizes_newlines_and_hashes_exact_artifacts` | EQUIVALENT：API_KEY、ACCESS_KEY、apiKey、PRIVATE_KEY 的短值皆移除，普通 `visible` 文本保留。 |
| `test_verify_items_reruns_every_suite_in_a_fresh_collection_directory` | `campaign/run_tests.rs::tests::run_selected_verify_items_reexecutes_in_fresh_phase_directories` | EQUIVALENT：两阶段按原顺序重跑、分目录、独立 stdout 路径。 |
| `test_unfinished_campaign_never_publishes_pass_between_phases` | `campaign/run_tests.rs::tests::run_selected_keeps_report_pending_until_every_phase_finishes` | EQUIVALENT：executor dispatch 时 report 尚未终态，active item PENDING、日志路径和 in-progress integrity；全部 phase 后 PASS。 |
| `test_item_failure_blocks_entire_collection` | `campaign/run_tests.rs::tests::run_selected_fail_stops_on_every_nonpass_in_either_phase` | EQUIVALENT：item 阶段首个非 PASS 会阻止后续 item 和整个 collection。 |
| `test_collection_failure_does_not_dispatch_later_targets` | `campaign/run_tests.rs::tests::run_selected_collection_failure_blocks_later_targets_after_items_pass` | EQUIVALENT：全部 item PASS 后，collection 首个 FAIL 停止后续 target。 |
| `test_existing_run_directory_is_never_overwritten` | `campaign/run_tests.rs::tests::run_selected_refuses_run_id_collision_and_invalid_artifact_scope` | EQUIVALENT：run dir collision 拒绝，不覆盖。 |
| `test_artifacts_cannot_enter_workspace` | `campaign/run_tests.rs::tests::run_selected_refuses_run_id_collision_and_invalid_artifact_scope`; `campaign.rs::tests::artifact_paths_resolve_relative_components_and_reject_workspace_symlinks` | EQUIVALENT：workspace/symlink 路径范围拒绝。 |
| `test_invalid_run_id_is_rejected` | `campaign/run_tests.rs::tests::run_selected_refuses_run_id_collision_and_invalid_artifact_scope` | EQUIVALENT：路径穿越 run ID 拒绝。 |

## 其余模块方法名与映射账本

以下各节按完整 Python source 路径隔离每个模块的逐方法记录。`EQUIVALENT` 仅表示列出的 Rust 离线合同覆盖该方法的断言；并不代表对应 live/deployment 证据通过。source marker 是 inventory guard 用来验证方法归属的分界，不改变人工语义审查要求。

<!-- python-source: scripts/tests/test_performance_acceptance.py -->
### `scripts/tests/test_performance_acceptance.py`（10）

| Python 方法 | Rust target / 对应测试 | 状态和边界 |
|---|---|---|
| `test_exact_complete_cases_and_units_are_preserved` | `acceptance.rs::tests::criterion_requires_complete_measured_cases_and_unit_conversion` | EQUIVALENT：完整 cases 和单位转换。 |
| `test_smoke_is_not_measured_acceptance` | `acceptance.rs::tests::python_test_smoke_is_not_measured_criterion_acceptance` | EQUIVALENT：smoke 不作测量验收。 |
| `test_partial_empty_and_duplicate_measurements_fail` | `acceptance.rs::tests::python_test_partial_empty_and_duplicate_criterion_measurements_fail` | EQUIVALENT：partial/empty/duplicate 拒绝。 |
| `test_nonpositive_reversed_and_unbound_intervals_fail` | `acceptance.rs::tests::python_test_criterion_rejects_nonpositive_reversed_and_unbound_intervals` | EQUIVALENT：区间边界与正值检查。 |
| `test_complete_cases_require_sample_counts_and_allocations` | `acceptance.rs::tests::divan_requires_complete_measured_cases_and_declared_allocation_evidence` | EQUIVALENT：Divan case、样本数与 allocation evidence。 |
| `test_filtered_and_empty_measurements_fail` | `acceptance.rs::tests::python_test_divan_parser_covers_native_table_and_all_allocation_edges` | EQUIVALENT：过滤/空测量拒绝。 |
| `test_divan_tree_output_with_fastest_in_name_column` | `acceptance.rs::tests::python_test_divan_parser_covers_native_table_and_all_allocation_edges` | EQUIVALENT：树形输出及 fastest 列解析。 |
| `test_rounded_terminal_branch_retains_full_coverage_checks` | `acceptance.rs::tests::python_test_divan_parser_covers_native_table_and_all_allocation_edges` | EQUIVALENT：四舍五入 terminal branch 仍要求完整覆盖。 |
| `test_native_table_format_does_not_accept_malformed_fastest_or_samples` | `acceptance.rs::tests::python_test_divan_parser_covers_native_table_and_all_allocation_edges` | EQUIVALENT：畸形 fastest/sample 值拒绝。 |
| `test_missing_samples_or_duplicate_cases_fail` | `acceptance.rs::tests::python_test_divan_parser_covers_native_table_and_all_allocation_edges` | EQUIVALENT：缺 sample/重复 case 拒绝。 |

<!-- python-source: scripts/tests/test_evaluate_performance_acceptance.py -->
### `scripts/tests/test_evaluate_performance_acceptance.py`（13）

| Python 方法 | Rust target / 对应测试 | 状态和边界 |
|---|---|---|
| `test_complete_no_benefit_protocol_passes_without_speed_threshold` | `evaluate_acceptance.rs::tests::complete_policy_evaluate_protocol_is_accepted_without_speed_threshold` | EQUIVALENT：无 speed threshold 的完整协议。 |
| `test_complete_regression_estimate_is_reported_but_does_not_fail_acceptance` | `evaluate_acceptance.rs::tests::paired_statistics_match_python_seeded_reference_and_report_regressions` | EQUIVALENT：回归估计报告但不单独判失败。 |
| `test_protocol_rejects_partial_duplicate_filtered_and_misplaced_records` | `evaluate_acceptance.rs::tests::incomplete_duplicate_reordered_and_ambiguous_json_records_fail` | EQUIVALENT：协议记录完整性和唯一性。 |
| `test_complete_protocol_accepts_exact_cargo_success_footer` | `evaluate_acceptance.rs::tests::python_test_rejects_footer_placement_and_count_mutations` | EQUIVALENT：Cargo 成功 footer 位置/计数。 |
| `test_protocol_requires_meta_first_and_end_after_all_cases` | `evaluate_acceptance.rs::tests::incomplete_duplicate_reordered_and_ambiguous_json_records_fail` | EQUIVALENT：meta/end 顺序。 |
| `test_parser_rejects_invalid_json_nonfinite_and_duplicate_keys` | `evaluate_acceptance.rs::tests::python_test_rejects_malformed_json_meta_topology_and_debug_markers` | EQUIVALENT：JSON/nonfinite/duplicate keys。 |
| `test_meta_rejects_topology_type_bool_controls_and_debug_build` | `evaluate_acceptance.rs::tests::python_test_rejects_malformed_json_meta_topology_and_debug_markers` | EQUIVALENT：meta topology、类型、bool controls 和 debug build。 |
| `test_case_rejects_workload_drift_bool_fields_and_changed_order` | `evaluate_acceptance.rs::tests::python_test_rejects_case_topology_boolean_and_order_mutations` | EQUIVALENT：workload、bool 和 case 顺序。 |
| `test_case_rejects_early_allow_deny_count_cache_read_and_timing_errors` | `evaluate_acceptance.rs::tests::python_test_rejects_measurement_count_cache_and_timing_mutations` | EQUIVALENT：决策计数、cache/read/timing。 |
| `test_deny_requires_one_read_and_zero_final_phase` | `evaluate_acceptance.rs::tests::python_test_deny_footer_and_wrong_input_preserve_fail_closed_results` | EQUIVALENT：deny read/final phase postcondition。 |
| `test_end_requires_exact_counts_and_all_nonvacuous_postconditions` | `evaluate_acceptance.rs::tests::measurement_and_end_postconditions_cannot_be_relaxed`; `python_test_deny_footer_and_wrong_input_preserve_fail_closed_results` | EQUIVALENT：精确计数和非空 postconditions。 |
| `test_paired_metrics_and_fixed_seed_bootstrap_are_reproducible` | `evaluate_acceptance.rs::tests::paired_statistics_match_python_seeded_reference_and_report_regressions`; `python_seeded_bootstrap_is_reproducible` | EQUIVALENT：paired metrics 和固定 seed bootstrap。 |
| `test_public_api_never_raises_for_wrong_stdout_type` | `evaluate_acceptance.rs::tests::public_acceptance_rejects_non_string_stdout_without_panicking` | EQUIVALENT：JSON-value API 对非字符串返回 `FAIL`、空 performance 和 `complete=false`，不 panic；typed `&str` API 保持不变。 |

<!-- python-source: scripts/tests/test_entrypoints.py -->
### `scripts/tests/test_entrypoints.py`（1）

| Python 方法 | Rust target / 对应测试 | 状态和边界 |
|---|---|---|
| `test_rust_fake_cargo_contracts_are_the_single_source_of_truth` | `campaign.rs::tests::shell_entrypoints_forward_selection_to_the_rust_cli`; `shell_entrypoints_propagate_cargo_failures_and_reject_before_dispatch` | EQUIVALENT：覆盖输出名、return code 与 stdout dispatch；不启动完整 campaign。 |

<!-- python-source: experiments/tdsc/protocol-runner/test_run_performance.py -->
### `experiments/tdsc/protocol-runner/test_run_performance.py`（10）

| Python 方法 | Rust target / 对应测试 | 状态和边界 |
|---|---|---|
| `test_status_classification_is_mutually_exclusive` | `tdsc_performance.rs::tests::test_status_classification_is_mutually_exclusive` | EQUIVALENT：状态互斥。 |
| `test_exception_classification_distinguishes_timeout` | `tdsc_performance.rs::tests::test_exception_classification_distinguishes_timeout` | EQUIVALENT：timeout 分类独立。 |
| `test_percentiles_are_interpolated` | `tdsc_performance.rs::tests::test_percentiles_are_interpolated` | EQUIVALENT：线性插值。 |
| `test_empty_percentile_is_none` | `tdsc_performance.rs::tests::test_empty_percentile_is_none` | EQUIVALENT：空集合返回空值。 |
| `test_percentile_rejects_invalid_range` | `tdsc_performance.rs::tests::test_percentile_rejects_invalid_range` | EQUIVALENT：非法 percentile 范围拒绝。 |
| `test_sample_row_matches_declared_schema` | `tdsc_performance.rs::tests::test_sample_row_matches_declared_schema` | EQUIVALENT：row schema。 |
| `test_schema_rejects_invalid_outcome` | `tdsc_performance.rs::tests::test_schema_rejects_invalid_outcome` | EQUIVALENT：非法 outcome 拒绝。 |
| `test_concurrency_parser_requires_unique_positive_values` | `tdsc_performance.rs::tests::test_concurrency_parser_requires_unique_positive_values` | EQUIVALENT：正值且唯一。 |
| `test_replicate_summary_has_rate_and_success_throughput_metrics` | `tdsc_performance.rs::tests::test_replicate_summary_has_rate_and_success_throughput_metrics` | EQUIVALENT：replicate rate/success throughput。 |
| `test_concurrency_summary_uses_replicate_level_metrics` | `tdsc_performance.rs::tests::test_concurrency_summary_uses_replicate_level_metrics` | EQUIVALENT：并发摘要由 replicate-level 指标聚合。Docker campaign 仍未执行。 |

<!-- python-source: Docs/实验/分布式测试/rust-s15/test_s15_validation.py -->
### `Docs/实验/分布式测试/rust-s15/test_s15_validation.py`（5）

| Python 方法 | Rust target / 对应测试 | 状态和边界 |
|---|---|---|
| `test_rejects_nonpositive_rounds_before_run_setup` | `s15_validation.rs::tests::test_rejects_nonpositive_rounds_before_run_setup` | EQUIVALENT：强类型入口覆盖 0/负数；JSON-value adapter 另对照 0、负数和 `true`（对应 Python bool-is-int edge）并在 setup 前拒绝。 |
| `test_rejects_unknown_empty_and_whitespace_only_scenarios` | `s15_validation.rs::tests::test_rejects_unknown_empty_and_whitespace_only_scenarios` | EQUIVALENT：未知/空/纯空白场景拒绝。 |
| `test_required_case_coverage_and_nonpass_are_distinct` | `s15_validation.rs::tests::test_required_case_coverage_and_nonpass_are_distinct` | EQUIVALENT：缺失和非 PASS 案例区分。 |
| `test_scoped_or_incomplete_runs_are_partial_not_complete` | `s15_validation.rs::tests::test_scoped_or_incomplete_runs_are_partial_not_complete` | EQUIVALENT：scope/incomplete 保持 partial。 |
| `test_full_scope_requires_three_rounds_and_positive_cases` | `s15_validation.rs::tests::test_full_scope_requires_three_rounds_and_positive_cases` | EQUIVALENT：三轮门槛及正样本要求。 |

另有 Rust-only `s15_validation::tests::test_required_case_inventory_is_exactly_fifteen_named_scenarios`，仅固定 15 场景必测 inventory，不冒充第六个 Python unittest 方法；S15 三节点 campaign 仍未执行。

## 19 个归档模块：逐方法索引

为避免把归档的执行/部署断言伪装成离线通过，每个 Python 方法在此按源码顺序登记。对映射到一个完整 Rust 离线 reducer/parser 的简单方法标记 `EQUIVALENT`；要求 runner/真实 I/O/报告文件/并行调度/完整全域探索的标记 `BLOCKED` 或 `PARTIAL`。Rust filter 的测试文件列名即 MANIFEST 对应 suite 的可执行目标。真实进程/网络能力仍未执行。

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_bounded_model_execution.py -->
### `test_bounded_model_execution.py`（10）

| Python 方法 | Rust 映射 | 状态 |
|---|---|---|
| `test_worker_budget_is_strict_and_bounded` | `bounded_execution_contract.rs::tests::worker_budget_is_integer_and_bounded` | EQUIVALENT |
| `test_e5_worker_budget_remains_finite` | `bounded_execution_contract.rs::tests::worker_budget_is_integer_and_bounded` | EQUIVALENT |
| `test_unregistered_model_is_rejected` | `bounded_execution_contract.rs::tests::only_registered_offline_models_are_accepted` | EQUIVALENT |
| `test_complete_duplicates_are_only_reused_inside_one_call` | `bounded_execution_contract.rs::tests::configuration_deduplication_is_ordered_and_call_scoped` | EQUIVALENT |
| `test_underbound_runs_retain_exact_bound_identity` | `bounded_execution_contract.rs::tests::complete_bound_key_collapses_above_required_but_underbounds_stay_distinct` | EQUIVALENT |
| `test_parallel_execution_preserves_reports_and_configuration_order` | `bounded_execution_contract.rs::tests::concurrent_configuration_runs_preserve_reports_and_input_order` | EQUIVALENT：两个线程并发执行完整 single-model 配置集合并按输入顺序合并，逐报告等于串行；不声称 Python ProcessPool 实现细节。 |
| `test_two_mutation_strict_worker_preserves_counts_and_counterexample` | `two_mutation_model.rs::tests::deterministic_model_shards_reproduce_complete_and_incomplete_python_reports`; `two_mutation_model.rs::tests::strict_full_contract_is_complete_repeatable_and_conserves_trace_counts` | EQUIVALENT：串行/分片完整报告与模型 count/counterexample 断言；未声称 ProcessPool dispatch parity。 |
| `test_two_mutation_shards_preserve_complete_report_and_counterexamples` | `two_mutation_model.rs::tests::deterministic_model_shards_reproduce_complete_and_incomplete_python_reports` | EQUIVALENT：在本进程顺序执行确定性前缀 shards，完整 strict bound 和默认 bracket bound 下对照串行完整报告，含 omission counterexample；不证明 ProcessPool 并行。 |
| `test_two_mutation_shards_preserve_underbound` | `two_mutation_model.rs::tests::deterministic_model_shards_preserve_underbound_reports` | EQUIVALENT：strict 下 bounds 2/3/6 的分片合并完整报告逐字段等于串行；对有反例的 run 要求 FAIL，对低 bound 无反例结果保留 UNKNOWN/非 PASS，不假定 required bound-1 必然截断；不证明 ProcessPool 并行。 |
| `test_missing_duplicate_reordered_or_drifted_model_shards_fail` | `bounded_execution_contract.rs::tests::shard_merge_requires_complete_unique_order_and_matching_configuration`; `two_mutation_model.rs::tests::model_shard_prefix_set_and_merge_reject_unknown_or_reordered_shards` | EQUIVALENT：generic manifest 检查缺失/重复/乱序/配置漂移；生成的真实 Rust shards 乱序后 merge 明确拒绝。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_classify_e1_properties.py -->
### `test_classify_e1_properties.py`（11）

| Python 方法 | Rust 映射 | 状态 |
|---|---|---|
| `test_p1_p2_p3_exhaustive_grid` | `e1_validation.rs::tests::classifier_matches_exhaustive_interval_oracle_and_domain_grid` | EQUIVALENT |
| `test_p4_boundary_flip_at_t_f` | `e1_validation.rs::tests::classifier_matches_exhaustive_interval_oracle_and_domain_grid` | EQUIVALENT |
| `test_p3_after_final_membership_is_exact` | `e1_validation.rs::tests::classifier_matches_exhaustive_interval_oracle_and_domain_grid` | EQUIVALENT |
| `test_multi_single_mutation_matches_single_classifier` | `e1_validation.rs::tests::multi_mutation_requires_representation_and_tracks_attribution` | EQUIVALENT |
| `test_multi_two_mutations_attributions` | `e1_validation.rs::tests::multi_mutation_requires_representation_and_tracks_attribution` | EQUIVALENT |
| `test_multi_requires_representation_for_every_hazard` | `e1_validation.rs::tests::multi_mutation_requires_only_pre_tf_hazards_and_reports_missing_indices` | EQUIVALENT |
| `test_multi_rejects_empty_mutations` | `e1_validation.rs::tests::multi_mutation_requires_only_pre_tf_hazards_and_reports_missing_indices` | EQUIVALENT |
| `test_identity_mismatch_raises` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT |
| `test_uncommitted_outcome_raises` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT |
| `test_fuzz_defects_fail_closed` | `e1_validation.rs::tests::fuzz_defects_fail_closed_individually` | EQUIVALENT：逐个复刻 duplicate sequence、跨 node、跨 epoch、decision/stable sequence 冲突及 candidate revision 缺失五种输入缺陷，并断言每项都 fail closed；Rust 断言与 Python 一样只要求抛出/返回分类错误，不扩展为完整 fuzz campaign。 |
| `test_non_allow_decision_raises` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_dependency_profiles.py -->
### `test_dependency_profiles.py`（7）

| Python 方法 | Rust 映射 | 状态 |
|---|---|---|
| `test_profile_contract_validates` | `dependency_profiles.rs::tests::all_profiles_pin_exact_services_dependencies_and_fault_membership` | EQUIVALENT |
| `test_canonical_profile_ids_and_services` | `dependency_profiles.rs::tests::all_profiles_pin_exact_services_dependencies_and_fault_membership` | RETIRED：原八 profile 库存包含 Redis 兼容项；当前七个原生 profile 的精确清单由替代断言固定。 |
| `test_default_native_profile_has_no_redis_or_rabbit` | `dependency_profiles.rs::tests::all_profiles_pin_exact_services_dependencies_and_fault_membership`; `unknown_profiles_and_retired_redis_faults_fail_closed` | EQUIVALENT：默认原生 profile 仅 MySQL。 |
| `test_native_fault_matrix_is_explicit_and_stable` | `dependency_profiles.rs::tests::every_fault_dependency_and_matrix_entry_is_explicit` | EQUIVALENT |
| `test_legacy_faults_are_compat_only` | `dependency_profiles.rs::tests::unknown_profiles_and_retired_redis_faults_fail_closed` | RETIRED：旧 Redis faults/profile 已删除，当前断言只证明拒绝它们。 |
| `test_unknown_profile_is_rejected` | `dependency_profiles.rs::tests::unknown_profiles_and_retired_redis_faults_fail_closed` | EQUIVALENT |
| `test_each_matrix_is_full_timing_cross_product` | `dependency_profiles.rs::tests::every_fault_dependency_and_matrix_entry_is_explicit` | EQUIVALENT |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_e1_runner.py -->
### `test_e1_runner.py`（46）

| Python 方法 | Rust 映射 | 状态 |
|---|---|---|
| `test_module_import_performs_no_io` | 静态 Rust library module；无等价 import side-effect contract | EQUIVALENT（N/A：Rust module load 不执行 Python import hook） |
| `test_plan_mode_never_builds_adapter_or_contacts_nodes` | `e1_runner_contract.rs::tests::plan_is_offline_and_operation_ids_are_safe_unique_and_ordered` | EQUIVALENT：plan API 不接收 adapter，仅写 plan.json/checksums 并在测试内验证，无节点调用。 |
| `test_run_mode_without_live_is_offline_and_blocked` | `e1_runner_contract.rs::tests::live_gate_requires_all_explicit_human_inputs` | EQUIVALENT：`live=false` 在 adapter 构造前返回 `live_not_enabled`。 |
| `test_standalone_live_cli_blocks_without_independent_validator` | `e1_runner_contract.rs::tests::live_gate_requires_all_explicit_human_inputs` | EQUIVALENT：完整人工材料但 `independent_validator=false` 返回 `independent_user_approval_not_verified`。 |
| `test_plan_operation_ids_safe_unique_and_ordered` | `e1_runner_contract.rs::tests::plan_is_offline_and_operation_ids_are_safe_unique_and_ordered` | EQUIVALENT：operationOrder/add-before-bind、UUIDv5 ID 长度/字符/唯一性。 |
| `test_preflight_uses_get_and_select_only_with_exact_paths` | `e1_runner_contract.rs::tests::preflight_uses_get_and_select_only_with_exact_paths` | EQUIVALENT：fake adapter 仅记录 GET，五条精确路径、actor card 与 SELECT count query。 |
| `test_readonly_gate_rejects_mutations` | `e1_runner_contract.rs::tests::readonly_gate_rejects_mutations` | EQUIVALENT：ReadOnlyGate 只暴露 GET/SQL，POST/DELETE 结构性拒绝。 |
| `test_preflight_blocks_on_every_dirty_precondition` | `e1_runner_contract.rs::tests::preflight_blocks_on_every_dirty_precondition`; `e1_runner_contract.rs::tests::invalid_admin_tenant_is_a_config_error` | EQUIVALENT：10 个 dirty fixture 的首个 problem label 与无 mutation 均断言；非法 tenant 由独立 config error 测试覆盖。 |
| `test_preflight_passes_on_clean_fixture` | `e1_runner_contract.rs::tests::preflight_passes_on_clean_fixture` | EQUIVALENT：clean fake fixture 的全部 preflight checks PASS。 |
| `test_campaign_requires_full_human_gate_and_never_infers_from_config` | `e1_runner_contract.rs::tests::live_gate_requires_all_explicit_human_inputs` | EQUIVALENT：五类缺项矩阵、approval run_id mismatch 与无独立 validator 均 BLOCKED。 |
| `test_cleanup_does_not_remove_foreign_binding_after_preflight_block` | `e1_runner_contract.rs::tests::cleanup_does_not_remove_foreign_binding_after_preflight_block` | EQUIVALENT：preflight BLOCKED 后 cleanup 只读检查 binding，保留 foreign binding 并记录 `binding_not_campaign_owned`，不发出 UNBIND。 |
| `test_candidate_identity_must_match_e0` | `e3_e4_events.rs::tests::e0_identity_is_exact_and_missing_or_changed_identity_stays_unproven` | EQUIVALENT（identity reducer 合同）。 |
| `test_ruleset_campaign_uses_only_the_ruleset_delta_chain` | `e1_durable_contract.rs::tests::ruleset_campaign_uses_only_the_ruleset_delta_chain` | EQUIVALENT：durable 查询仅使用 RULE_SET aggregate 且非 USER_CARD；CARD aggregate 明确拒绝。 |
| `test_campaign_durable_reconciliation_queries_are_tenant_scoped` | `e1_durable_contract.rs::tests::durable_queries_are_tenant_scoped` | EQUIVALENT：delta/pointer/audit 查询均带 tenant_id；entry count 由 rule_set/entry 精确限定。 |
| `test_e0_candidate_tenant_or_card_mismatch_blocks_campaign` | `e3_e4_events.rs::tests::e0_identity_is_exact_and_missing_or_changed_identity_stays_unproven` | EQUIVALENT（身份/tenant/card 不一致为未证明）。 |
| `test_campaign_clean_fixture_passes_and_cleans_up` | `e1_runner_contract.rs::tests::clean_campaign_adds_binds_reads_deletes_unbinds_and_writes_artifacts` | EQUIVALENT：注入 adapter 下 PASS、POST/DELETE 各两次且顺序正确、entries/binding/grant 清空、cycle/manifest/preflight/cleanup artifact 与 checksums 完整。 |
| `test_frozen_result_is_immutable` | `e1_frozen_result.rs::tests::frozen_result_rejects_mutation_and_preserves_the_frozen_snapshot` | EQUIVALENT：freeze 后对 item assignment、update、pop、clear、delete 及同类 mutators 拒绝写入，并核对原值不变；不涉及 E1 runner 或 campaign 生命周期。 |
| `test_stale_allow_reader_is_classified_violation_and_fails_campaign` | `e1_durable_contract.rs::tests::stale_allow_reader_is_classified_violation_and_fails_campaign` | EQUIVALENT：commit 早于 final observation 时 category=post-commit、staleAllowViolation=true，campaign=FAIL。 |
| `test_unknown_delete_is_reconciled_then_corrected_exactly_once` | `e1_durable_contract.rs::tests::unknown_delete_is_reconciled_then_corrected_once` | EQUIVALENT：unknown delete 不自动修正；仅 not_applied 允许一次 corrective delete。 |
| `test_unknown_reconciliation_is_never_retried` | `e4_protocol.rs::tests::apply_runs_once_recovery_runs_once_and_retry_requires_durable_proof` | EQUIVALENT（protocol retry eligibility）。 |
| `test_projection_never_converging_is_unknown_and_skips_the_race` | `e1_durable_contract.rs::tests::projection_never_converging_is_unknown_and_skips_the_race` | EQUIVALENT：never-converging projection 为 UNKNOWN 且 raceSkipped=true。 |
| `test_missing_delete_delta_prevents_pass_despite_quiescent_aggregate_tail` | `e1_durable_contract.rs::tests::missing_delete_delta_prevents_pass` | EQUIVALENT：缺 delete REMOVE delta 时 problems 含 missing_delete_delta，不 PASS。 |
| `test_stale_pointer_after_delete_delta_prevents_pass` | `e1_durable_contract.rs::tests::stale_pointer_after_delete_delta_prevents_pass` | EQUIVALENT：pointer operation/event 与 delete delta 不匹配时报 stale_pointer_after_delete_delta。 |
| `test_delete_audit_for_another_entry_cannot_prove_target_delete` | `e1_durable_contract.rs::tests::delete_audit_for_another_entry_cannot_prove_target_delete` | EQUIVALENT：其他 entry 的 DELETE audit 只能得到 scope mismatch，reconcile 保持 unknown。 |
| `test_delete_audit_with_wrong_aggregate_scope_cannot_prove_target_delete` | `e1_durable_contract.rs::tests::delete_audit_with_wrong_aggregate_scope_cannot_prove_target_delete` | EQUIVALENT：错误 aggregate scope 的 audit 不能证明目标 delete。 |
| `test_source_row_present_prevents_operation_publication_claim` | `e1_durable_contract.rs::tests::source_row_present_prevents_operation_publication_claim` | EQUIVALENT：source row 仍存在时禁止 operation publication claim。 |
| `test_empty_count_result_is_unknown_not_source_absence` | `e1_durable_contract.rs::tests::empty_count_result_is_unknown_not_source_absence` | EQUIVALENT：计数缺失为 unknown_source_row_count，reconcile 报 reconciliation_read_failed。 |
| `test_duplicate_matching_delete_audits_prevent_pass` | `e1_durable_contract.rs::tests::duplicate_matching_delete_audits_prevent_pass` | EQUIVALENT：多个 matching DELETE audit 报 duplicate_matching_delete_audits。 |
| `test_operation_delta_attribute_mismatches_prevent_pass` | `e1_durable_contract.rs::tests::operation_delta_attribute_mismatches_prevent_pass` | EQUIVALENT：delta status/target version 不合法时报 operation_delta_attribute_mismatch。 |
| `test_duplicate_operation_deltas_prevent_pass` | `e1_durable_contract.rs::tests::duplicate_operation_deltas_prevent_pass` | EQUIVALENT：同一 operation 多个 REMOVE delta 报 duplicate_operation_deltas。 |
| `test_pointer_card_mismatch_prevents_pass` | `e1_durable_contract.rs::tests::pointer_card_mismatch_prevents_pass` | EQUIVALENT：pointer card 与 campaign card 不一致时报 pointer_card_mismatch。 |
| `test_projection_snapshot_malformed_durable_rows_are_unknown` | `e1_durable_contract.rs::tests::projection_snapshot_malformed_durable_rows_are_unknown` | EQUIVALENT：malformed durable rows 报 malformed_durable_rows，不 PASS。 |
| `test_successful_empty_post_race_log_slice_is_unknown` | `e1_durable_contract.rs::tests::successful_empty_post_race_log_slice_is_unknown` | EQUIVALENT：空 post-race log slice 为 UNKNOWN 且记录 no_server_events_for_request。 |
| `test_missing_delete_audit_correlation_prevents_pass` | `e1_durable_contract.rs::tests::missing_delete_audit_correlation_prevents_pass` | EQUIVALENT：无 DELETE audit correlation 时阻断 publication claim。 |
| `test_classify_pre_commit_before_single_commit_interval` | `e1_validation.rs::tests::classifier_matches_exhaustive_interval_oracle_and_domain_grid` | EQUIVALENT |
| `test_classify_stale_allow_after_commit_is_violation` | `e1_validation.rs::tests::classifier_matches_exhaustive_interval_oracle_and_domain_grid` | EQUIVALENT |
| `test_classify_commit_overlapping_observation_stays_unknown` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT |
| `test_classify_pending_and_transport_failures` | `e1_durable_contract.rs::tests::classify_pending_and_transport_failures` | EQUIVALENT：403 pending 为 PENDING；transport failure 为 UNKNOWN 且保留 error。 |
| `test_classify_without_e0_identity_stays_unclassified` | `e3_e4_events.rs::tests::e0_identity_is_exact_and_missing_or_changed_identity_stays_unproven` | EQUIVALENT |
| `test_classify_without_commit_interval_stays_unclassified` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT |
| `test_classify_incomplete_request_events_stays_unknown` | `e1_durable_contract.rs::tests::classify_incomplete_request_events_stays_unknown` | EQUIVALENT：缺少 E0 identity 时为 unclassified-unknown + e0_identity_unproven。 |
| `test_plan_rotates_nodes_and_keeps_ids_unique_across_cycles` | `e1_runner_contract.rs::tests::plan_rotates_nodes_and_ids_across_cycles` | EQUIVALENT：两节点两 cycle 轮换且 8 个 operation IDs 唯一。 |
| `test_two_cycles_on_one_node_use_distinct_e0_request_ids` | `e1_runner_contract.rs::tests::two_cycle_campaign_uses_distinct_e0_request_ids_and_artifacts` | EQUIVALENT：两 cycle 均 PASS，E0 stats 请求 ID 按 cycle 区分且顺序正确，每 cycle artifact 的 `e0Grant.candidateIdentity` 完整。 |
| `test_cycle_exception_still_writes_per_cycle_cleanup_artifact` | `e1_runner_contract.rs::tests::cycle_exception_still_writes_per_cycle_cleanup_artifact` | EQUIVALENT：cycle 异常返回 UNKNOWN，cleanup artifact 仍写出且内容与返回 cleanup 一致。 |
| `test_reader_threads_active_blocks_cleanup_mutations` | `e1_runner_contract.rs::tests::reader_threads_active_blocks_cleanup_mutations` | EQUIVALENT：reader active 时 cleanup 记录 manual reconciliation、跳过 delete/unbind，且不发出任何 mutation。 |
| `test_cross_epoch_request_events_classify_unknown_not_stale` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence`; `e3_e4_events.rs::tests::e0_identity_is_exact_and_missing_or_changed_identity_stays_unproven` | EQUIVALENT（离线 epoch boundary；campaign 不运行）。 |

### 其余 15 个归档模块：逐方法状态账本

下表对剩余模块逐方法记录对应的 Rust 离线 contract suite 与边界。`EQUIVALENT` 限于该方法可离线表达的输入/输出、状态、错误和反例；`PARTIAL` 表示仍有关键合同差异或测试数量虽已映射、但断言未被独立覆盖；`BLOCKED` 表示原断言依赖 runner lifecycle、真实 subprocess/SSH/HTTP/节点部署或完整模型/并行执行，当前明确不宣称等价。每个 Python 来源与该来源分区中的逐方法行通过不可见 `python-source` 标记绑定；inventory guard 只验证源方法库存与分区归属，不把 `PARTIAL/BLOCKED` 折算为等价。

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_e3_e4.py -->
### `test_e3_e4.py`（57）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_fake_probe_satisfies_read_only_probe` | `e4_preconditions.rs::tests::happy_path_is_select_only_and_unconfigured_cache_epoch_is_skipped` | PARTIAL：当前端口只有 SQL；未配置可选 cache epoch 明确 SKIP，原 Redis probe 合同已删除。 |
| `test_fake_probe_satisfies_actor_aware_probe` | `node_adapter_contract.rs::tests::role_actor_and_decision_path_keep_exact_card_binding` | EQUIVALENT：actor-aware 输入与 card binding。 |
| `test_probe_without_redis_does_not_satisfy_protocol` | `e4_preconditions.rs::tests::cache_epoch_is_optional_sql_evidence_and_never_fabricated` | RETIRED：Redis capability 已删除；当前只读可选 SQL 证据未配置为 SKIP，无伪造 epoch。 |
| `test_redis_verb_allowlist_is_read_only` | `node_adapter_contract.rs::tests::retired_redis_fields_are_rejected_without_affecting_sql_or_metadata` | RETIRED：Redis command API 已物理删除；替代断言只拒绝旧配置。 |
| `test_accepts_select_statements` | `node_adapter_contract.rs::tests::sql_guard_and_fixed_argv_are_read_only_and_secret_stays_off_argv` | EQUIVALENT：只读 SELECT。 |
| `test_rejects_non_select_statements` | `node_adapter_contract.rs::tests::sql_guard_and_fixed_argv_are_read_only_and_secret_stays_off_argv` | EQUIVALENT：mutation statements 拒绝。 |
| `test_rejects_multiple_statements` | `node_adapter_contract.rs::tests::sql_guard_and_fixed_argv_are_read_only_and_secret_stays_off_argv` | EQUIVALENT：多语句拒绝。 |
| `test_happy_path_all_checks_pass` | `experiment_common_contract.rs::tests::happy_path_sampling_report_passes_all_checks` | EQUIVALENT：全部采样 PASS、queue=0、worker ready 时报告 PASS 且所有 check PASS。 |
| `test_node_aliases_never_stored_and_indexes_are_stable` | `e4_preconditions.rs::tests::node_labels_are_replaced_with_stable_aliases` | EQUIVALENT：匿名别名与稳定索引。 |
| `test_isolation_fallback_for_mysql57` | `e4_preconditions.rs::tests::mysql57_fallback_is_used_after_primary_query_failure` | EQUIVALENT：MySQL 5.7 fallback。 |
| `test_sql_error_is_unknown_and_leaks_no_error_text` | `e4_preconditions.rs::tests::sql_errors_empty_ambiguous_null_and_unexpected_shapes_stay_unknown` | EQUIVALENT：SQL error 转 UNKNOWN 并脱敏。 |
| `test_empty_and_ambiguous_results_are_unknown` | `e4_preconditions.rs::tests::sql_errors_empty_ambiguous_null_and_unexpected_shapes_stay_unknown` | EQUIVALENT：空/歧义结果 UNKNOWN。 |
| `test_unrecognized_isolation_is_unknown` | `e4_preconditions.rs::tests::invalid_isolation_and_clock_skew_fail_closed` | EQUIVALENT：未知隔离级别不通过。 |
| `test_clock_skew_beyond_threshold_fails` | `e4_preconditions.rs::tests::invalid_isolation_and_clock_skew_fail_closed` | EQUIVALENT：时钟偏差超阈值 FAIL。 |
| `test_fail_outranks_blocked_when_redis_capability_missing` | `e4_preconditions.rs::tests::clock_failure_and_fail_status_are_not_masked_by_unconfigured_cache_epoch` | PARTIAL：保留 FAIL/UNKNOWN 高于未配置 SKIP 的原生断言，Redis capability/BLOCKED 分支已删除。 |
| `test_cache_epoch_variants` | `e4_preconditions.rs::tests::cache_epoch_is_optional_sql_evidence_and_never_fabricated` | PARTIAL：仅保留显式 SQL 来源、未配置 SKIP、查询异常 UNKNOWN；Redis GET/缺 key 分支已删除。 |
| `test_unproven_checks_never_yield_overall_pass` | `e4_preconditions.rs::tests::sql_errors_empty_ambiguous_null_and_unexpected_shapes_stay_unknown` | EQUIVALENT：未证明前置不能 PASS。 |
| `test_input_validation` | `e4_preconditions.rs::tests::unsafe_inputs_are_rejected_before_any_probe_call` | EQUIVALENT：输入检查先于 probe。 |
| `test_no_hosts_or_secrets_in_report` | `e4_preconditions.rs::tests::hostnames_urls_node_aliases_and_probe_errors_are_not_retained` | EQUIVALENT：输出不保留 host/secret。 |
| `test_fixed_interval_happy_path` | `experiment_common_contract.rs::tests::fixed_interval_sampling_plan_matches_window` | EQUIVALENT：0.05s/0.02s 窗口产生 3 个采样且报告保留 3 个 duration。 |
| `test_publication_drain_requires_zero_queues_and_ready_endpoint` | `experiment_common_contract.rs::tests::publication_drain_requires_zero_queues_and_ready_worker` | EQUIVALENT：queue backlog 或 worker not ready 时 drain 未证明；两者满足才 PASS。 |
| `test_snapshot_only_limitations_always_present` | `e3_report.rs::tests::snapshot_report_keeps_evidence_limits_and_snapshot_only_status_note` | EQUIVALENT：offline boundary contract 核对 `NOT_CLAIMED`、snapshot-only status note、per-attempt limitation 及全部固定 SKIP 项；不构造 sampling report 或 runtime samples。 |
| `test_stop_event_stops_between_samples` | `experiment_common_contract.rs::tests::sampling_stop_event_stops_between_samples` | EQUIVALENT：stop 在样本边界生效，已产生的样本保留且不追加后续样本。 |
| `test_zero_duration_is_blocked_and_touches_nothing` | `experiment_common_contract.rs::tests::zero_duration_is_blocked_and_touches_nothing` | EQUIVALENT：零时长采样为 BLOCKED 且 probe 计数为 0。 |
| `test_missing_redis_capability_is_blocked_but_sampling_continues` | `experiment_common_contract.rs::tests::blocked_or_unknown_sample_does_not_abort_sampling` | PARTIAL：通用 BLOCKED/UNKNOWN 样本后的继续采样断言保留，Redis capability 分支退役。 |
| `test_missing_actor_aware_capability_is_blocked` | `experiment_common_contract.rs::tests::blocked_or_unknown_sample_does_not_abort_sampling` | EQUIVALENT：BLOCKED 样本不中止采样；能力缺失以样本状态表达。 |
| `test_signed_get_error_is_unknown_and_does_not_abort` | `experiment_common_contract.rs::tests::blocked_or_unknown_sample_does_not_abort_sampling` | EQUIVALENT：UNKNOWN 样本保留且后续采样继续。 |
| `test_http_200_without_allowed_true_is_unknown_classification` | `e3_e4_events.rs::tests::e1_request_selection_terminal_status_and_status_vocabulary_are_explicit` | EQUIVALENT：200 非 `allowed=true` 不产生 ALLOW。 |
| `test_plain_503_is_unknown_not_authorization_pending` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：transport 503 与 auth PENDING 分离。 |
| `test_role_and_card_pairs_bound_exactly` | `node_adapter_contract.rs::tests::role_actor_and_decision_path_keep_exact_card_binding` | EQUIVALENT：角色与卡片绑定精确。 |
| `test_probe_rejects_path_card_mismatch` | `node_adapter_contract.rs::tests::role_actor_and_decision_path_keep_exact_card_binding` | EQUIVALENT：path/card 不匹配拒绝。 |
| `test_percent_encoded_card_is_bound_in_path` | `node_adapter_contract.rs::tests::signed_request_restricts_path_method_body_and_parses_object_responses` | EQUIVALENT：编码路径与签名主体一致性。 |
| `test_default_decision_path_is_real_route` | `node_adapter_contract.rs::tests::default_decision_path_is_the_real_route` | EQUIVALENT：decision path 构造为 `cardId`/`card_id` 双参数并通过 signed request 真实路由计划。 |
| `test_ambiguous_responses_cannot_yield_pass` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：重复/歧义记录不 PASS。 |
| `test_api_response_envelope_end_to_end` | `node_adapter_contract.rs::tests::api_response_envelope_is_preserved_end_to_end` | EQUIVALENT：签名请求经 fake transport 返回 code/message/data envelope，字段逐一保留。 |
| `test_invalid_request_id_is_unknown` | `node_adapter_contract.rs::tests::log_slice_validates_and_deduplicates_ids_before_runner_dispatch` | EQUIVALENT：非法 request id 拒绝。 |
| `test_hostile_request_id_is_scrubbed_before_storage` | `node_adapter_contract.rs::tests::scrubber_redacts_url_ipv4_hostname_and_bounds_strings` | EQUIVALENT：敏感标识 scrub/bound。 |
| `test_sink_errors_are_counted_and_do_not_abort` | `experiment_common_contract.rs::tests::sink_errors_are_counted_without_aborting` | EQUIVALENT：sink 成功/失败分别累计，失败不改变后续记录流程。 |
| `test_worker_health_endpoint_recorded_when_configured` | `experiment_common_contract.rs::tests::worker_health_endpoint_recorded_when_configured` | EQUIVALENT：worker_ready=true 时 worker_health check PASS 且记录标志；否则 BLOCKED。 |
| `test_worker_health_accepts_two_and_three_tuple` | `e3_report.rs::tests::worker_health_response_accepts_two_or_three_fields_and_fails_closed` | EQUIVALENT：对 supplied values 接受 2/3 项结果，并核对 2xx + `healthy=true`；不发起 HTTP 请求。 |
| `test_worker_health_rejects_bad_arity` | `e3_report.rs::tests::worker_health_response_accepts_two_or_three_fields_and_fails_closed` | EQUIVALENT：tuple arity 非 2/3 映射为 UNKNOWN、`ValueError`，不产生健康结论。 |
| `test_worker_health_non_2xx_is_unknown` | `e3_report.rs::tests::worker_health_response_accepts_two_or_three_fields_and_fails_closed` | EQUIVALENT：非 2xx / 非整数 status / 未健康 body 均 UNKNOWN；无 transport evidence。 |
| `test_input_validation_and_config_rejection_touch_nothing` | `node_adapter_contract.rs::tests::config_is_validated_without_io_and_public_metadata_hides_private_topology`; `e4_preconditions.rs::tests::unsafe_inputs_are_rejected_before_any_probe_call` | EQUIVALENT：无效 config/input 在 I/O 前拒绝。 |
| `test_no_hosts_or_secrets_in_sampling_report` | `experiment_common_contract.rs::tests::sampling_report_has_no_hosts_or_secrets` | EQUIVALENT：采样报告序列化不含 hostname/IP/secret。 |
| `test_api_response_effect_matrix` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：effect status matrix。 |
| `test_reason_and_generation_field_extraction` | `e3_e4_events.rs::tests::e1_request_selection_terminal_status_and_status_vocabulary_are_explicit` | EQUIVALENT：reason/generation 字段提取与保守映射。 |
| `test_accepts_deny_and_pending_with_reason_codes` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：带原因码 DENY/PENDING 可识别。 |
| `test_rejects_allow_as_fail_closed_violation` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：不允许的 ALLOW 被判为违反。 |
| `test_rejects_unknown_outcome_as_unproven` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：未知 outcome 保持未证明。 |
| `test_rejects_absent_observed_and_missing_reason` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：缺 observed/reason 不通过。 |
| `test_expected_allow_and_expected_mismatch_are_rejected` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：期望 ALLOW 或不匹配设置拒绝。 |
| `test_empty_input_is_blocked` | `e4_fault_lifecycle.rs::tests::empty_fault_outcome_input_is_blocked` | EQUIVALENT：空 outcomes 明确返回 BLOCKED、0 total、无 accepted IDs/rejections。 |
| `test_non_mapping_entry_is_rejected` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：非映射输入拒绝。 |
| `test_fault_matrix_items_match_protocol_e4` | `e4_fault_lifecycle.rs::tests::fault_matrix_is_complete_only_when_every_registered_case_passes` | EQUIVALENT：E4 注册案例与完整矩阵要求。 |
| `test_inputs_are_never_mutated` | `e4_fault_lifecycle.rs::tests::outcome_validation_does_not_mutate_supplied_json` | EQUIVALENT：克隆完整 JSON outcomes，调用 validator 后逐值比较原输入，并核对其结果状态与接受计数。 |
| `test_module_imports_no_network_or_process_capability` | `experiment_common_contract.rs::tests::e3_e4_sources_have_no_network_or_process_capability` | EQUIVALENT：E3/E4 事件、precondition 与 node adapter 生产源不含 net/process/socket/client 能力。 |
| `test_self_test_entrypoint_exists_and_help_exits_cleanly` | `experiment_common_contract.rs::tests::self_test_help_exits_cleanly_without_execution` | EQUIVALENT：self-test help 返回 0 且明确不执行 sampling/fault/mutation。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_e3_runner.py -->
### `test_e3_runner.py`（63）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_import_performs_no_io` | `e3_campaign_model.rs::tests::e3_runner_module_has_no_import_time_process_or_network_capability` | EQUIVALENT：E3 runner 生产源不含 process/net/client 能力，模块装载不执行 I/O 或命令。 |
| `test_valid_config_loads` | `e3_config.rs::tests::valid_config_loads_with_safe_defaults` | EQUIVALENT：核对 run id、fixture、cards、sampling、attempts、timeout defaults、nodes 与 decision node。 |
| `test_missing_sections` | `e3_config.rs::tests::missing_sections_and_invalid_run_id_are_reported_before_nested_fields` | EQUIVALENT：run_id/e3/allowlist 缺失标签与 config 类型拒绝。 |
| `test_cards_must_be_distinct_and_safe` | `e3_config.rs::tests::cards_must_be_distinct_and_safe` | EQUIVALENT：三卡唯一性及不安全 card 格式。 |
| `test_isolated_fixture_required_bool` | `e3_config.rs::tests::isolated_fixture_must_be_a_boolean` | EQUIVALENT：缺失或非 bool fixture 标志拒绝。 |
| `test_sampling_bounds` | `e3_config.rs::tests::sampling_bounds_reject_out_of_range_and_boolean_values` | EQUIVALENT：sampling interval/window 边界、负值与 bool 类型。 |
| `test_sample_count_bound` | `e3_config.rs::tests::sample_count_bound_is_checked_per_window` | EQUIVALENT：窗口采样调度超过上限时拒绝。 |
| `test_attempt_count_bound` | `e3_config.rs::tests::attempt_count_bound_rejects_zero_excess_boolean_and_string` | EQUIVALENT：attempt 下限、最大值、bool 与字符串类型。 |
| `test_nodes_and_decision_node_bounds` | `e3_config.rs::tests::node_and_decision_node_bounds_are_enforced` | EQUIVALENT：nodes 非空/唯一及 decision node 非空边界。 |
| `test_plan_is_offline_and_stable` | `e3_runner_contract.rs::tests::plan_is_offline_and_stable` | EQUIVALENT：plan 状态/mode、两次运行 operationIds 稳定、outputCategories、markerContract timeSources、livePrimitiveStatus=BLOCKED、gateRequirements 与 checksums 均断言。 |
| `test_live_not_enabled` | `e3_runner_contract.rs::tests::live_gate_blocks_missing_live_self_supplied_and_non_isolated_fixture` | EQUIVALENT：`live=false` 返回 `live_not_enabled`，不进入 validator。 |
| `test_missing_approval_ref` | `e3_runner_contract.rs::tests::live_gate_blocks_missing_live_self_supplied_and_non_isolated_fixture` | EQUIVALENT：缺/不安全 approval ref 返回 `approval_ref_missing_or_unsafe`。 |
| `test_approval_record_run_id_mismatch` | `e3_runner_contract.rs::tests::live_gate_blocks_missing_live_self_supplied_and_non_isolated_fixture` | EQUIVALENT：record run_id 不匹配返回 `approval_record_run_id_mismatch`。 |
| `test_self_supplied_approval_record_is_insufficient` | `e3_runner_contract.rs::tests::cli_live_without_independent_validator_is_blocked` | EQUIVALENT：record 完整但无独立 validator 时返回 `independent_user_approval_not_verified`。 |
| `test_approval_record_from_file` | `e3_runner_contract.rs::tests::approval_record_from_file_is_loaded_and_validated`; `e3_campaign_model.rs::tests::approval_record_from_file_reaches_full_claim_pass` | EQUIVALENT：文件读取/解析/validator 通过后进入 full-claim PASS 模型。 |
| `test_fixture_not_isolated` | `e3_runner_contract.rs::tests::live_gate_blocks_missing_live_self_supplied_and_non_isolated_fixture` | EQUIVALENT：`isolated_fixture=false` 返回 `fixture_not_isolated`。 |
| `test_missing_probe_and_controller` | `e3_runner_contract.rs::tests::missing_probe_and_controller_are_blocked_with_limitation` | EQUIVALENT：缺 probe/controller 分别返回 `missing_probe`/`missing_injection_controller`，并保留 `real_platform_primitives=BLOCKED` limitation。 |
| `test_cli_live_without_injected_primitives_is_blocked` | `e3_runner_contract.rs::tests::cli_live_without_independent_validator_is_blocked` | EQUIVALENT：CLI 无独立 validator 时 BLOCKED，原因 `independent_user_approval_not_verified`。 |
| `test_full_claim_pass` | `e3_campaign_model.rs::tests::full_claim_pass_requires_all_categories_and_durable_evidence` | EQUIVALENT：四 category PASS、markers 完整、无 problems 时 status=PASS 且 claim=FULL，artifact 列表含 checksums。 |
| `test_actor_switching_roles_and_cards` | `e3_campaign_model.rs::tests::actor_switching_roles_and_cards_keep_distinct_bindings` | PARTIAL：静态 json 角色清单核对（3 张卡互异）；runner 级 (role,card) 绑定逐一送达探测面的验证未接线（cold 角色已入采样，actor switching 探测面未在 runner 断言） |
| `test_wall_clock_regression_is_unknown` | `e3_report.rs::tests::markers_refuse_non_monotonic_wall_and_overlapping_windows` | EQUIVALENT：wall clock 逆序拒绝。 |
| `test_missing_markers_on_abort` | `e3_report.rs::tests::missing_markers_on_abort_reports_unknown_and_active_drain` | EQUIVALENT：三 marker abort 返回 UNKNOWN，problems 含 `markers_missing:drain_end` 与 `drain_not_completed`，drain active=true、injection active=false。 |
| `test_begin_injection_failure_no_retry` | `e3_campaign_model.rs::tests::begin_injection_failure_stops_without_retry` | EQUIVALENT：begin injection 失败时仅一次调用、无 marker、两窗 skipped、状态 UNKNOWN 且需人工对账。 |
| `test_end_injection_failure_leaves_injection_active` | `e3_campaign_model.rs::tests::end_injection_failure_leaves_injection_active` | EQUIVALENT：end injection 失败时仅 begin+end 各一次，injection active=true，drain skipped，perEvent SKIP。 |
| `test_end_drain_failure_leaves_drain_active` | `e3_campaign_model.rs::tests::end_drain_failure_leaves_drain_active` | EQUIVALENT：end drain 失败时 drain active=true，perEvent note=drain_not_completed_after_abort:end_drain。 |
| `test_timeout_stops_without_retry` | `e3_campaign_model.rs::tests::timeout_stops_without_retry` | EQUIVALENT：controller timeout 只调用一次，problems/phaseFailures 精确记录，manual reconciliation=true。 |
| `test_backoff_tail_is_pending` | `e3_campaign_model.rs::tests::backoff_tail_is_pending` | EQUIVALENT：backoff tail 的 perEvent=PENDING，campaign=UNKNOWN 且 claim=NOT_CLAIMED。 |
| `test_missing_durable_row_is_unknown` | `e3_reconciliation.rs::tests::exact_durable_row_is_required_for_a_passing_terminal` | EQUIVALENT：缺 durable row 不 PASS。 |
| `test_durable_status_mismatch_is_unknown` | `e3_reconciliation.rs::tests::exact_durable_row_is_required_for_a_passing_terminal` | EQUIVALENT：durable row `QUARANTINED` 与 publish terminal `SUCCEEDED` 不匹配时 per-event `UNKNOWN`，unknown 含 `durable_status_mismatch`。 |
| `test_unknown_ack_is_unknown` | `e3_reconciliation.rs::tests::drain_tail_remains_pending_and_unknown_ack_never_passes` | EQUIVALENT：unknown ACK 保持 UNKNOWN/PENDING。 |
| `test_missing_logs_is_blocked` | `e3_report.rs::tests::empty_attempt_history_blocks_the_campaign_without_a_claim` | EQUIVALENT（reducer 范围）：空 attempt history 产生 per-event `BLOCKED`、总状态 `BLOCKED` 和 `NOT_CLAIMED`；不执行 collector/row-reader 获取。 |
| `test_collector_error_is_blocked` | `e3_campaign_model.rs::tests::collector_error_is_blocked` | EQUIVALENT：collector exception 使 perEvent BLOCKED，problems 含 collect_e3_lines 且不 PASS。 |
| `test_missing_row_reader_prevents_pass` | `e3_report.rs::tests::missing_durable_row_reader_blocks_the_campaign_without_a_claim` | EQUIVALENT（reducer 范围）：缺少 row reader 时 per-event/category 与总状态均 BLOCKED，unknown 含 `durable_row_reconciliation_unavailable`，claim=`NOT_CLAIMED`；不执行 reader capability 检测。 |
| `test_attempt_bound_exceeded` | `e3_reconciliation.rs::tests::identity_attempt_and_event_bounds_fail_closed` | EQUIVALENT：validator 对单卡 attempt 上限返回 UNKNOWN、记录 `attempt_bound_exceeded`，`campaign_problems` 聚合该原因。 |
| `test_event_id_bound_exceeded` | `e3_reconciliation.rs::tests::event_id_and_event_log_bounds_fail_closed` | EQUIVALENT：validator 对超过 `MAX_EVENT_IDS` 的唯一 event id 返回 BLOCKED、`event_id_bound_exceeded`，`campaign_problems` 聚合该原因。 |
| `test_event_log_bound_exceeded` | `e3_reconciliation.rs::tests::event_id_and_event_log_bounds_fail_closed` | EQUIVALENT：validator 对超过 `MAX_EVENTS` 的事件日志返回 BLOCKED、`event_log_bound_exceeded`，`campaign_problems` 聚合该原因。 |
| `test_request_side_skip_when_target_stays_allowed` | `e3_campaign_model.rs::tests::request_side_skip_when_target_stays_allowed` | EQUIVALENT：target 未出现 PENDING/DENY 时 request-side=SKIP，campaign=SKIP 且 claim=NOT_CLAIMED。 |
| `test_unrelated_pending_is_unknown` | `e3_report.rs::tests::unrelated_pending_decision_keeps_the_campaign_unknown` | EQUIVALENT（reducer 范围）：目标 PENDING 经 supplied host cross-check PASS 形成 request-side PASS；无关卡 PENDING 为 UNKNOWN，总状态 UNKNOWN 且 claim=`NOT_CLAIMED`；不执行 probe/event-log 或 campaign 生命周期。 |
| `test_publication_unknown_when_indicators_fail` | `e3_campaign_model.rs::tests::publication_unknown_when_indicators_fail` | EQUIVALENT：publication indicators UNKNOWN 时 category 与 campaign 均 UNKNOWN。 |
| `test_publication_skip_when_not_configured` | `e3_report.rs::tests::publication_not_configured_is_skip_without_a_full_claim` | EQUIVALENT（reducer 范围）：未配置 indicators 的 section status 为 SKIP，其他输入 PASS 时 status fold 为 SKIP 且 claim 保持 `NOT_CLAIMED`；没有运行 sampling/controller/artifact 生命周期。 |
| `test_actor_aware_probe_required_is_blocked` | `e3_campaign_model.rs::tests::actor_aware_probe_required_is_blocked` | EQUIVALENT：target/unrelated 决策均 BLOCKED 时两类与 campaign 均 BLOCKED。 |
| `test_zero_duration_windows_are_skipped` | `e3_report.rs::tests::zero_duration_windows_are_skipped_and_keep_the_campaign_blocked` | EQUIVALENT（reducer 范围）：两窗 duration=0 均为 `skipped`，在 per-event PASS、无 request ID 导致 host cross-check BLOCKED 的输入下总状态为 BLOCKED 且 claim=`NOT_CLAIMED`；不执行 E3 campaign。 |
| `test_probe_allow_without_admission_is_unknown` | `e3_reconciliation.rs::tests::host_allow_requires_one_later_matching_admission` | EQUIVALENT：ALLOW 必须有之后同 context admission。 |
| `test_probe_allow_host_denial_is_fail` | `e3_reconciliation.rs::tests::host_admission_contradictions_are_failures` | EQUIVALENT：host contradiction FAIL。 |
| `test_probe_pending_with_host_admission_is_fail` | `e3_reconciliation.rs::tests::host_admission_contradictions_are_failures` | EQUIVALENT：PENDING 与 host admission 矛盾时 FAIL。 |
| `test_no_request_log_collector_is_unknown_not_pass` | `e3_campaign_model.rs::tests::no_request_log_collector_is_unknown_not_pass` | EQUIVALENT：target PENDING、host cross-check SKIP 且 collector 缺失时 request-side/campaign 均 UNKNOWN。 |
| `test_module_source_has_no_deployment_constants` | `e3_report.rs::tests::e3_runner_source_contains_no_deployment_constants` | EQUIVALENT：Rust 直接对同一 E3 runner 源文件应用 IPv4 正则及完整禁用 token 列表；不执行 Python 或 runner。 |
| `test_outputs_are_scrubbed` | `e3_runner_contract.rs::tests::outputs_are_scrubbed_while_probe_keeps_raw_alias` | EQUIVALENT：stored settings 的 decisionNode 为 `[redacted-host]`，probe alias 保留原始 host，序列化不含 example.com。 |
| `test_cli_plan` | `e3_runner_contract.rs::tests::cli_plan_returns_zero_and_verifies_checksums` | EQUIVALENT：CLI plan 返回 0，plan.json status=PLANNED 且 checksums 验证通过。 |
| `test_cli_run_without_live_is_blocked` | `e3_runner_contract.rs::tests::cli_run_without_live_returns_one_with_blocked_manifest` | EQUIVALENT：无 live 时退出码 1，manifest status=BLOCKED 且 problems=["live_not_enabled"]。 |
| `test_cli_bad_config_exit_code` | `e3_runner_contract.rs::tests::cli_bad_config_returns_two` | EQUIVALENT：坏配置 CLI plan 返回 2。 |
| `test_approval_validator_receives_exact_canonical_config_hash` | `e3_runner_contract.rs::tests::approval_validator_receives_exact_canonical_hash` | EQUIVALENT：validator 仅收到一次 (run_id, approval_ref, canonical config hash)，且 hash 精确匹配。 |
| `test_approval_validator_hash_mismatch_blocks_before_probe_or_controller` | `e3_runner_contract.rs::tests::approval_validator_hash_mismatch_and_exception_fail_closed` | EQUIVALENT：validator 拒绝时返回 `independent_user_approval_not_verified`，probe/controller 端口调用保持 0。 |
| `test_approval_validator_exception_fails_closed` | `e3_runner_contract.rs::tests::approval_validator_hash_mismatch_and_exception_fail_closed` | EQUIVALENT：validator 抛错按拒绝处理，同样不触发 probe/controller。 |
| `test_marker_operation_id_mismatch_is_reported` | `e3_report.rs::tests::markers_require_complete_order_and_effect_ack_identity` | EQUIVALENT：marker/ack operation identity。 |
| `test_attempt_pairs_stay_within_one_observation_epoch` | `e3_reconciliation.rs::tests::attempt_pairs_stay_within_process_epoch` | EQUIVALENT：两个 process epoch 的 attempt 各自配对且累计耗时可加；terminal 早于后续 claim 记 UNKNOWN。 |
| `test_crosscheck_is_unknown_when_one_node_log_fails_to_parse` | `e3_campaign_model.rs::tests::crosscheck_is_unknown_when_one_node_log_fails_to_parse` | EQUIVALENT：单节点日志 parse failure 保留为 UNKNOWN，problem 含 request_log_parse_failed:node-a，limitation=UNKNOWN。 |
| `test_missing_unique_decision_return_cannot_pass` | `e3_reconciliation.rs::tests::host_allow_requires_one_later_matching_admission`; `e3_reconciliation.rs::tests::host_admission_requires_unique_context_and_complete_sampled_ids` | EQUIVALENT：缺 decision return 时 UNKNOWN 且 `unverified=1`；重复 decision return 为矛盾，上下文必须完整。 |
| `test_missing_invalid_duplicate_and_truncated_sample_ids_cannot_pass` | `e3_reconciliation.rs::tests::host_admission_requires_unique_context_and_complete_sampled_ids` | EQUIVALENT：complete 输入 PASS；duplicate decision return/context mismatch 为 FAIL；invalid/duplicate sample id 与 truncated 为 UNKNOWN，均不得 PASS。 |
| `test_duplicate_decision_return_is_a_contradiction` | `e3_reconciliation.rs::tests::host_admission_contradictions_are_failures` | EQUIVALENT：重复决策是矛盾证据。 |
| `test_allow_requires_later_admission_same_context_process` | `e3_reconciliation.rs::tests::host_allow_requires_one_later_matching_admission`; `e3_reconciliation.rs::tests::host_admission_requires_unique_context_and_complete_sampled_ids` | EQUIVALENT：缺失 admission 为 UNKNOWN；同 process/context 之外（含 card context 变化）为 FAIL。 |
| `test_effect_marker_requires_applied_identity_and_state` | `e3_report.rs::tests::markers_require_complete_order_and_effect_ack_identity` | EQUIVALENT：effect ACK state/operation identity。 |
| `test_reads_alone_do_not_prove_publication_drain` | `e3_reconciliation.rs::tests::queue_reads_alone_do_not_prove_publication_drain` | EQUIVALENT：queue 读取不能单独证明 drain。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_e4_fault_driver.py -->
### `test_e4_fault_driver.py`（76）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_missing_authorization_blocked` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：缺授权拒绝。 |
| `test_invalid_run_id_blocked` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：run-scoped ID 校验。 |
| `test_exec_level_must_be_l3` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：执行级别必须准确。 |
| `test_missing_isolate_token_blocked` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：缺 isolation token 拒绝。 |
| `test_token_not_run_scoped_blocked` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：token run id 绑定。 |
| `test_identical_tokens_blocked` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：隔离/审批 token 不可复用。 |
| `test_missing_approval_token_blocked` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：审批 token 缺失拒绝。 |
| `test_missing_approved_by_blocked` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：审批者缺失拒绝。 |
| `test_empty_allowlist_blocked` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：空 allowlist 拒绝。 |
| `test_fault_not_in_allowlist_blocked` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：fault 不在 allowlist 拒绝。 |
| `test_unknown_fault_id_refused` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：未知 fault id 拒绝。 |
| `test_validation_helper_reports_all_problems` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：同时返回所有授权问题。 |
| `test_valid_authorization_has_no_problems` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：有效授权无问题。 |
| `test_no_controller_blocked` | `e4_fault_lifecycle.rs::tests::runtime_preconditions_gate_mutation_and_leave_audit_free_of_controller_values` | EQUIVALENT：无 controller 时 mutation 不执行。 |
| `test_controller_missing_capability_hook_blocked` | `e4_fault_lifecycle.rs::tests::runtime_preconditions_gate_mutation_and_leave_audit_free_of_controller_values` | EQUIVALENT：缺 hook 能力 blocked。 |
| `test_unsupported_fault_blocked_before_prepare` | `e4_fault_lifecycle.rs::tests::runtime_preconditions_gate_mutation_and_leave_audit_free_of_controller_values` | EQUIVALENT（reducer 范围）：unsupported fault 后无 prepare/apply/restore/reconcile stage；不调用 controller。 |
| `test_read_only_preflight_not_declared_blocked` | `e4_protocol.rs::tests::preflight_must_be_read_only_run_scoped_and_fault_specific` | EQUIVALENT：读-only preflight 强制。 |
| `test_isolation_declaration_must_be_run_scoped` | `e4_protocol.rs::tests::preflight_must_be_read_only_run_scoped_and_fault_specific` | EQUIVALENT：隔离声明 run-scoped。 |
| `test_preflight_not_ok_blocked` | `e4_fault_lifecycle.rs::tests::prepare_is_a_hard_gate_and_unknown_prepare_runs_recovery_once` | EQUIVALENT：preflight 未 OK 阻断 apply。 |
| `test_controller_rejecting_authorization_tokens_blocked` | `e4_fault_lifecycle.rs::tests::runtime_preconditions_gate_mutation_and_leave_audit_free_of_controller_values` | EQUIVALENT（reducer 范围）：`authorization_ok=false` 得到拒绝并不生成 prepare/apply stage；不证明真实 token/controller 调用。 |
| `test_preflight_exception_blocked` | `e4_fault_lifecycle.rs::tests::runtime_preconditions_gate_mutation_and_leave_audit_free_of_controller_values` | EQUIVALENT（reducer 范围）：`HookResult::Error` 映射 BLOCKED，且没有 prepare/apply/recovery stage。 |
| `test_preflight_non_mapping_blocked` | `e4_fault_lifecycle.rs::tests::runtime_preconditions_gate_mutation_and_leave_audit_free_of_controller_values` | EQUIVALENT（reducer 范围）：non-mapping 映射 BLOCKED，且没有 prepare/apply/recovery stage。 |
| `test_prepare_refusal_blocked_without_recovery_calls` | `e4_fault_lifecycle.rs::tests::prepare_is_a_hard_gate_and_unknown_prepare_runs_recovery_once` | EQUIVALENT：refusal 不触发后续恢复副作用。 |
| `test_prepare_without_durable_ref_unknown` | `e4_fault_lifecycle.rs::tests::prepare_is_a_hard_gate_and_unknown_prepare_runs_recovery_once` | EQUIVALENT：缺 durable ref 时为 UNKNOWN，apply SKIP，recovery 各一次且 retries=0。 |
| `test_prepare_timeout_unknown_and_apply_skipped` | `e4_fault_lifecycle.rs::tests::prepare_timeout_skips_apply_and_runs_recovery_once` | EQUIVALENT：prepare timeout 为 UNKNOWN/`controller_timeout`，apply SKIP，restore/reconcile 各一次。 |
| `test_each_fault_case_passes` | `e4_fault_lifecycle.rs::tests::fault_matrix_is_complete_only_when_every_registered_case_passes` | EQUIVALENT：每个注册 case 必须 PASS。 |
| `test_matrix_all_six_passes_and_is_complete` | `e4_fault_lifecycle.rs::tests::fault_matrix_is_complete_only_when_every_registered_case_passes` | EQUIVALENT：完整六项矩阵。 |
| `test_matrix_subset_is_not_complete` | `e4_fault_lifecycle.rs::tests::fault_matrix_is_complete_only_when_every_registered_case_passes` | EQUIVALENT：子集不算 complete。 |
| `test_operation_ids_stable_and_distinct` | `e4_protocol.rs::tests::authorization_is_run_scoped_distinct_allowlisted_and_token_free` | EQUIVALENT：operation ID 稳定并唯一。 |
| `test_controller_receives_context_and_authorization` | `e4_fault_lifecycle.rs::tests::hook_context_carries_identity_and_authorization_without_mutation` | EQUIVALENT：hook context 携带 run_id/fault_id/operation_id/attempt/stage 与 authorization run_id，且不记录 token 值。 |
| `test_input_authorization_not_mutated` | `e4_protocol.rs::tests::authorization_validation_does_not_mutate_supplied_input`; `e4_fault_lifecycle.rs::tests::hook_context_carries_identity_and_authorization_without_mutation` | EQUIVALENT：validator 与 hook context 构造后原 Authorization 逐字段不变。 |
| `test_observed_allow_is_fail` | `e4_fault_lifecycle.rs::tests::case_evidence_requirements_and_observation_fail_closed_are_distinct` | EQUIVALENT：故障观察到 ALLOW 为 FAIL。 |
| `test_host_admission_allow_is_fail_even_when_decision_denies` | `e4_fault_lifecycle.rs::tests::case_evidence_requirements_and_observation_fail_closed_are_distinct` | EQUIVALENT：host ALLOW 即为矛盾失败。 |
| `test_observed_unknown_is_unknown` | `e4_fault_lifecycle.rs::tests::case_evidence_requirements_and_observation_fail_closed_are_distinct` | EQUIVALENT：UNKNOWN 不折为 PASS。 |
| `test_missing_observed_is_blocked_never_pass` | `e4_fault_lifecycle.rs::tests::case_evidence_requirements_and_observation_fail_closed_are_distinct` | EQUIVALENT：缺 observation 不通过。 |
| `test_missing_reason_code_is_blocked_never_pass` | `e4_protocol.rs::tests::observations_are_fail_closed_and_preserve_the_reason_gate` | EQUIVALENT：reason code 必需。 |
| `test_missing_host_admission_is_unknown_never_pass` | `e4_fault_lifecycle.rs::tests::case_evidence_requirements_and_observation_fail_closed_are_distinct` | EQUIVALENT：缺 host evidence 未证明。 |
| `test_host_admission_unknown_is_unknown` | `e4_fault_lifecycle.rs::tests::case_evidence_requirements_and_observation_fail_closed_are_distinct` | EQUIVALENT：host UNKNOWN 传播。 |
| `test_unrecognized_observed_value_blocked` | `e4_fault_lifecycle.rs::tests::case_evidence_requirements_and_observation_fail_closed_are_distinct` | EQUIVALENT：未知 observed outcome fail-closed。 |
| `test_pointer_movement_requires_generation_evidence` | `e4_fault_lifecycle.rs::tests::restore_reconcile_postcondition_and_outcome_aggregation_fail_closed` | EQUIVALENT：pointer move 需 generation evidence。 |
| `test_lease_expiry_requires_generation_evidence` | `e4_fault_lifecycle.rs::tests::restore_reconcile_postcondition_and_outcome_aggregation_fail_closed` | EQUIVALENT：lease expiry 需 generation evidence。 |
| `test_stale_hmac_requires_audit_evidence` | `e4_fault_lifecycle.rs::tests::restore_reconcile_postcondition_and_outcome_aggregation_fail_closed` | EQUIVALENT：stale HMAC 需 audit evidence。 |
| `test_unknown_ack_requires_durable_reconcile_proof` | `e4_protocol.rs::tests::apply_runs_once_recovery_runs_once_and_retry_requires_durable_proof` | EQUIVALENT：unknown ACK 先 reconcile 才能 retry。 |
| `test_cases_without_extra_evidence_are_skip` | `e4_fault_lifecycle.rs::tests::case_evidence_requirements_and_observation_fail_closed_are_distinct` | EQUIVALENT：非适用额外证据为 SKIP，而不是 PASS。 |
| `test_every_frozen_case_has_a_spec` | `e4_fault_lifecycle.rs::tests::fault_matrix_is_complete_only_when_every_registered_case_passes` | EQUIVALENT：每个冻结案例都有 spec。 |
| `test_apply_timeout_unknown_recovery_run_no_retry` | `e4_fault_lifecycle.rs::tests::apply_timeout_and_disconnect_are_unknown_without_retry` | EQUIVALENT：apply timeout 为 UNKNOWN，observe SKIP，restore/reconcile 各一次且 retries=0。 |
| `test_apply_disconnect_unknown` | `e4_fault_lifecycle.rs::tests::apply_timeout_and_disconnect_are_unknown_without_retry` | EQUIVALENT：apply disconnect 为 UNKNOWN，恢复路径各一次且不自动重试。 |
| `test_apply_generic_exception_unknown_with_error_class` | `e4_fault_lifecycle.rs::tests::restore_reconcile_postcondition_and_outcome_aggregation_fail_closed` | EQUIVALENT（reducer 范围）：supplied `ValueError` class 保留为 apply detail，整体 UNKNOWN、observe SKIP、restore/reconcile 各一次、无自动 retry；无实际异常抛出。 |
| `test_observe_disconnect_unknown_restore_still_runs` | `e4_fault_lifecycle.rs::tests::recovery_path_is_once_and_retry_requires_durable_reconciliation` | EQUIVALENT（reducer 范围）：observe disconnect 为 UNKNOWN/cross-check SKIP，restore 与 reconcile 各一次；不执行传输。 |
| `test_unknown_without_reconciliation_forbids_retry` | `e4_protocol.rs::tests::apply_runs_once_recovery_runs_once_and_retry_requires_durable_proof` | EQUIVALENT：无 durable reconcile proof 不 retry。 |
| `test_apply_refusal_blocked_with_recovery` | `e4_fault_lifecycle.rs::tests::recovery_path_is_once_and_retry_requires_durable_reconciliation` | EQUIVALENT（reducer 范围）：apply refusal 为 BLOCKED、observe SKIP、restore/reconcile 各一次且 retries=0；不调用真实 hook。 |
| `test_apply_unproven_without_ref_unknown` | `e4_fault_lifecycle.rs::tests::recovery_path_is_once_and_retry_requires_durable_reconciliation` | EQUIVALENT：无 durable reference 时 UNKNOWN。 |
| `test_restore_refused_is_unknown_never_pass` | `e4_fault_lifecycle.rs::tests::restore_reconcile_postcondition_and_outcome_aggregation_fail_closed` | EQUIVALENT：restore refusal 不 PASS。 |
| `test_restore_exception_is_unknown` | `e4_fault_lifecycle.rs::tests::restore_reconcile_postcondition_and_outcome_aggregation_fail_closed` | EQUIVALENT：restore error UNKNOWN。 |
| `test_reconcile_failure_is_unknown_and_forbids_retry` | `e4_protocol.rs::tests::apply_runs_once_recovery_runs_once_and_retry_requires_durable_proof` | EQUIVALENT：reconcile fail 禁止 retry。 |
| `test_reconcile_without_proof_ref_unknown` | `e4_protocol.rs::tests::apply_runs_once_recovery_runs_once_and_retry_requires_durable_proof` | EQUIVALENT：reconcile 无 proof 未证明。 |
| `test_postcondition_violation_is_fail` | `e4_fault_lifecycle.rs::tests::restore_reconcile_postcondition_and_outcome_aggregation_fail_closed` | EQUIVALENT：postcondition 违规 FAIL。 |
| `test_postcondition_exception_is_unknown` | `e4_fault_lifecycle.rs::tests::restore_reconcile_postcondition_and_outcome_aggregation_fail_closed` | EQUIVALENT：异常 postcondition UNKNOWN。 |
| `test_postcondition_unproven_is_unknown` | `e4_fault_lifecycle.rs::tests::restore_reconcile_postcondition_and_outcome_aggregation_fail_closed` | EQUIVALENT：postcondition 未证明 UNKNOWN。 |
| `test_no_hook_runs_twice_on_failing_run` | `e4_fault_lifecycle.rs::tests::recovery_path_is_once_and_retry_requires_durable_reconciliation` | EQUIVALENT：单次失败不自动重放 hook。 |
| `test_matrix_with_failures_never_retries` | `e4_fault_lifecycle.rs::tests::recovery_path_is_once_and_retry_requires_durable_reconciliation` | EQUIVALENT：矩阵失败不 retry。 |
| `test_retry_permitted_only_after_proven_reconciliation` | `e4_protocol.rs::tests::apply_runs_once_recovery_runs_once_and_retry_requires_durable_proof` | EQUIVALENT：仅 reconcile proof 可解锁 retry。 |
| `test_max_attempts_constant` | `e4_protocol.rs::tests::redaction_bounds_controller_text_and_plans_never_enable_execution` | EQUIVALENT：plan 的 `attempts` 精确等于 Rust `MAX_ATTEMPTS`；常量为 1。 |
| `test_default_live_gate_blocks_without_controller_contact` | `e4_fault_driver_contract.rs::tests::default_live_gate_blocks_without_controller_contact` | EQUIVALENT：默认 live gate 返回 BLOCKED/`allow_live_execution_false`，controller 调用计数保持 0。 |
| `test_matrix_default_live_gate_blocks_without_controller_contact` | `e4_fault_driver_contract.rs::tests::matrix_default_live_gate_blocks_without_controller_contact` | EQUIVALENT：矩阵默认 BLOCKED、integration_claim=BLOCKED，controller 调用计数 0。 |
| `test_native_live_execution_is_explicitly_blocked` | `e4_protocol.rs::tests::redaction_bounds_controller_text_and_plans_never_enable_execution` | EQUIVALENT：计划与 live execution 明确分离。 |
| `test_matrix_without_controller_blocked` | `e4_fault_lifecycle.rs::tests::runtime_preconditions_gate_mutation_and_leave_audit_free_of_controller_values` | EQUIVALENT：无 controller 全矩阵阻断。 |
| `test_matrix_bad_authorization_blocked_before_contact` | `e4_fault_driver_contract.rs::tests::matrix_bad_authorization_blocked_before_contact` | EQUIVALENT：非法 run_id 在 contact 前 BLOCKED，problems 含 `invalid:run_id`，controller 调用计数 0。 |
| `test_results_never_contain_authorization_token_values` | `e4_fault_lifecycle.rs::tests::runtime_preconditions_gate_mutation_and_leave_audit_free_of_controller_values` | EQUIVALENT：token 不进入结果/审计文本。 |
| `test_controller_derived_strings_are_scrubbed_and_bounded` | `e4_protocol.rs::tests::redaction_bounds_controller_text_and_plans_never_enable_execution` | EQUIVALENT：controller 文本 scrub 并限长。 |
| `test_plan_marks_every_case_planned_and_integration_blocked` | `e4_fault_driver_contract.rs::tests::plan_marks_every_case_planned_and_integration_blocked` | EQUIVALENT：cases 与 profile fault 表一致且均 PLANNED，integration BLOCKED，8 个 hook 顺序与首个 returns 精确匹配，plan 不含 controller。 |
| `test_module_integration_claim_is_blocked` | `e4_fault_driver_contract.rs::tests::module_integration_claim_is_blocked` | EQUIVALENT：`LIVE_FAULT_MATRIX_INTEGRATION=BLOCKED`，原因含 `test_control.rs`。 |
| `test_default_cli_prints_plan_and_blocked` | `e4_fault_driver_contract.rs::tests::default_cli_prints_plan_and_blocked` | EQUIVALENT：默认 CLI 退出 0，输出含 BLOCKED 与 memory_channel_suspect、不含 redis_unavailable，JSON plan kind/profile 正确。 |
| `test_plan_flag_prints_the_same_plan` | `e4_fault_driver_contract.rs::tests::plan_flag_prints_the_same_plan` | PARTIAL：当前原生 profile 的 `--plan` 输出保留 BLOCKED；`redis-compat` 被拒绝，原兼容 profile 正向合同退役。 |
| `test_no_execution_flag_exists` | `e4_fault_driver_contract.rs::tests::no_execution_flag_exists` | EQUIVALENT：`--run` 退出 2 且无 stdout。 |
| `test_help_exits_zero_without_executing_anything` | `e4_fault_driver_contract.rs::tests::help_exits_zero_without_executing_anything` | EQUIVALENT：`--help` 退出 0，输出含 "fault primitive" 与 "--plan"。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_e5_model_check.py -->
### `test_e5_model_check.py`（52）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_full_contract_pass_at_default_bound_both_modes` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：default-bound 报告精确匹配 reference fixture，并显式断言 fullContract=PASS、两个 mode 均 PASS/零 violation/complete/bound=DEFAULT_BOUND 且不小于 requiredBound。 |
| `test_full_contract_pass_at_two_bounds` | `e5_model.rs::tests::full_contract_passes_at_python_required_bound_and_required_bound_plus_four_in_both_modes` | EQUIVALENT：Python 的 `required_bound()`（bracket 必需步数）与该值 +4 均在 bracket/strict 模式断言 PASS、零 violation、complete 和 bound；逐 mode 另断言其 requiredBound。 |
| `test_no_in_domain_stale_admission_under_faithful_probes` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：两模式 strictly-before admission/violation 为 0，late stale publish window 非空且 admission 为 0，且各模式均存在 latch denial；bracket 另精确要求 P0/P1 各有 denial reason。 |
| `test_no_admission_time_mechanism_exists` | `e5_model.rs::tests::report_scope_limits_and_status_vocabulary_are_frozen` | EQUIVALENT：检查 fence/pending premise 描述和 report scope，并排除旧 counterfactual 字段。 |
| `test_out_of_domain_window_is_reported_honestly` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：两模式均有 after-t_f admission、publish-after-t_f window 且该域 violation=0；overlap 域 violation 也为 0。 |
| `test_full_contract_violations_only_from_in_domain_traces` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：两模式均将 violation 精确限制在 strictlyBefore，所有非该 domain 的 violation count 为 0。 |
| `test_final_load_is_ordered_m0_p0_m1_p1` | `e5_model.rs::tests::observation_modes_keep_the_ordered_read_and_latch_contract` | EQUIVALENT：bracket 顺序与 recheck。 |
| `test_strict_load_is_one_atomic_event_with_embedded_probe` | `e5_model.rs::tests::observation_modes_keep_the_ordered_read_and_latch_contract` | EQUIVALENT：strict 单事件与无 bracket pre。 |
| `test_probes_and_load_disappear_with_their_premises` | `e5_model.rs::tests::observation_modes_keep_the_ordered_read_and_latch_contract` | EQUIVALENT：premise 移除的 event list。 |
| `test_tf_anchor_is_m0_bracket_and_strict_load_strict` | `e5_model.rs::tests::observation_modes_keep_the_ordered_read_and_latch_contract`; `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：bracket checklist 精确从 `RELOAD_M0` 起、strict checklist 精确从单个 `STRICT_LOAD` 起；run 输出将其作为 domain anchor，且两模式完整报告均断言零 strictly-before violations。 |
| `test_probe_omission_admits_commit_durable_before_tf` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：pending-probe omission report status=FAIL，late stale-publish window admission>0；最小 source-pending trace 明确为 stale/ADMITTED 且属于 strictlyBefore。 |
| `test_probe_omission_minimal_trace_has_no_admission_time_check` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：最小反例断言 durable commit + ADMIT、无 PUBLISH/EVIDENCE_BODY_ADVANCE、pendingObservations 为空、outcome=ADMITTED；没有 admission-time gate 可执行。 |
| `test_latched_probes_survive_late_publication` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：late-publication trace 数大于 0、admitted stale count 为 0，且完整 report 独立要求 `RELOAD_P0` 与 `RELOAD_P1` 各自存在 latch denial reason。 |
| `test_cache_observation_consistent_states` | `e5_model.rs::tests::cache_observation_covers_consistent_torn_and_rollback_states` | EQUIVALENT：pre/post/boundary cache snapshots。 |
| `test_cache_observation_stale_body_under_current_manifest` | `e5_model.rs::tests::cache_observation_covers_consistent_torn_and_rollback_states` | EQUIVALENT：manifest ahead body stale。 |
| `test_cache_observation_converse_body_ahead_of_manifest` | `e5_model.rs::tests::cache_observation_covers_consistent_torn_and_rollback_states` | EQUIVALENT：body ahead manifest stale。 |
| `test_cache_observation_rollback_and_post_rollback_torn` | `e5_model.rs::tests::cache_observation_covers_consistent_torn_and_rollback_states` | EQUIVALENT：below-head rollback 与后续 torn。 |
| `test_cache_observation_without_fence_carries_torn_pairs_raw` | `e5_model.rs::tests::cache_observation_covers_consistent_torn_and_rollback_states` | EQUIVALENT：无 fence 的 raw torn state。 |
| `test_torn_states_enumerated_and_rejected_in_full_contract` | `e5_model.rs::tests::cache_observation_covers_consistent_torn_and_rollback_states`; `full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：两类 torn 可达且 admitted count 为零。 |
| `test_torn_reads_rejected_even_without_the_fence` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：generation-fence omission 下两类 torn read 均可达、admitted-torn 非零且仅在 after-final-observation；counterexample 为 stale-generation rollback，violation 仍精确限于 strictlyBefore。 |
| `test_pending_probe_omission_source_pending_trace` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：status/finding、counterexample class/domain/event count/outcome、durable commit、无 publication/body advance、空 pending observations 与 ADMIT 均有断言。 |
| `test_post_recheck_omission_intra_load_publication_trace` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：m0 < publication < p0、p0/p1 pending=false、m0=r0 而 m1=r1，且无 POST_OBS_END。 |
| `test_final_reload_omission_no_load_no_probes_trace` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：无 final-load/probe 事件、无 pending observation，durable source-pending counterexample 属 strictlyBefore。 |
| `test_exact_identity_omission_successor_revision_trace` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：publish 在 m0 前、无 rollback、pending/recheck/match 路径存在、m0 读到 g1/r1，并出现 stale-generation rollback 违规族。 |
| `test_generation_fence_omission_pointer_rollback_trace` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：publish < rollback < m0，反例在 strictlyBefore，且单一 violation class 为 stale-generation pointer rollback。 |
| `test_host_mediation_omission_bypass_trace` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：最短轨迹包含 durable commit、t_f 的 m0 与 BYPASS，不含 ADMIT，event count=5 且严格早于 t_f。 |
| `test_all_six_omissions_are_load_bearing` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：reference fixture 与显式断言固定六个 premise 顺序、全体 status=FAIL/finding=counterexample_found、violations 数、反例 schedule class/domain/event count/staleAtAdmission。 |
| `test_run_model_deterministic` | `e5_model.rs::tests::run_model_is_deterministic_for_full_exact_identity_and_host_mediation_modes` | EQUIVALENT：默认、exact_identity omission、host_mediation omission 三组固定输入均重复运行比较完整 Value；若存在 counterexample，另比较完整 trace。 |
| `test_full_report_deterministic` | `e5_model.rs::tests::default_report_and_individual_runs_are_deterministic` | EQUIVALENT：同一 DEFAULT_BOUND 下两次独立 build_report() 返回完整 Value 相等。 |
| `test_classify_domain_pure_cases` | `e5_model.rs::tests::domain_classification_keeps_overlap_outside_the_theorem` | EQUIVALENT：domain 分类边界。 |
| `test_admitted_overlap_traces_are_never_violations` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：host-mediation omission bracket run 明确要求 overlap admissions ≥1、overlap violations=0、total violations 等于 strictlyBefore admissions 及 strictlyBefore violation count。 |
| `test_valid_bounds_accepted` | `e5_model.rs::tests::bound_validation_and_fail_unknown_precedence_are_preserved` | EQUIVALENT：精确接受 MIN、MAX 和内部有效值 14。 |
| `test_invalid_bounds_rejected` | `e5_model.rs::tests::bound_validation_and_fail_unknown_precedence_are_preserved`; `e5_model_check_cli.rs::tests::invalid_bound_cli_exits_with_code_two_before_emitting_a_report` | EQUIVALENT：输入合同按 Python 列表逐类拒绝 0、负数、1、越界/大值、string、null、float、bool 和 list；Rust JSON adapter 覆盖动态 JSON 边界，CLI 另验证非法 argv 退出码与空 stdout。 |
| `test_bound_below_required_gives_unknown_not_pass` | `e5_model.rs::tests::bound_validation_and_fail_unknown_precedence_are_preserved` | EQUIVALENT：未完成无反例 UNKNOWN。 |
| `test_unknown_bounds_never_produce_pass` | `e5_model.rs::tests::aggregate_underbound_report_never_claims_pass` | EQUIVALENT：bound 8 下 aggregate `fullContract.status` 只可能 UNKNOWN/FAIL，绝不 PASS，并与 top-level status 相同。 |
| `test_below_bound_run_with_counterexample_reports_fail` | `e5_model.rs::tests::bound_validation_and_fail_unknown_precedence_are_preserved` | EQUIVALENT：不完整但有反例时 FAIL 优先。 |
| `test_no_subprocess_socket_or_network_imports` | `e5_model.rs::tests::model_sources_have_no_process_socket_or_network_coupling` | EQUIVALENT：对四个模型生产源扫描 process/net/socket/tokio/reqwest/hyper 依赖，均不存在。 |
| `test_no_module_level_side_effects` | `e5_model.rs::tests::model_sources_have_no_mutable_module_initializers` | EQUIVALENT：生产源无 `static mut`、lazy_static、once_cell、ctor 或 thread_local 初始化。 |
| `test_import_is_side_effect_free` | `e5_model.rs::tests::model_entrypoints_are_repeatable_without_environment_or_file_reads` | EQUIVALENT：生产源不读取 fs/env/process，入口重复运行结果逐字段一致。 |
| `test_docstring_states_abstract_evidence_boundary` | `e5_model.rs::tests::e5_source_documents_abstract_evidence_boundary` | EQUIVALENT：include 原工具源文件并检查 ABSTRACT BOUNDED-MODEL、非 mechanized proof、Rust/Java、deployment/runtime、版本与 scopeLimitations 声明。 |
| `test_required_top_level_fields` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：显式检查 Python 方法要求的 12 个顶层字段、模型/版本/theorem identity 与非零 explored counts，另与 reference fixture 精确比较。 |
| `test_status_vocabulary_distinguishes_all_four_statuses` | `e5_model.rs::tests::report_scope_limits_and_status_vocabulary_are_frozen` | EQUIVALENT：PASS/FAIL/BLOCKED/UNKNOWN 均为字符串，且 vocabulary 精确四项。 |
| `test_blocked_is_reserved_and_never_emitted` | `e5_model.rs::tests::report_scope_limits_and_status_vocabulary_are_frozen`; `e5_model.rs::tests::no_report_status_field_emits_blocked` | EQUIVALENT：BLOCKED 描述明确含 BoundError 与 code 2；API 无效 bound 返回 error；递归检查所有 report status 字段。 |
| `test_status_scope_separates_full_contract_from_omissions` | `e5_model.rs::tests::report_scope_limits_and_status_vocabulary_are_frozen` | EQUIVALENT：statusScope 明示 ONLY full contract、omissions 与 independent single-premise status；top/full 均 PASS、全部 6 omission 独立 FAIL。 |
| `test_scope_limitations_cover_structural_assumptions` | `e5_model.rs::tests::report_scope_limits_and_status_vocabulary_are_frozen` | EQUIVALENT：逐项断言 Python 所列 14 个结构假设关键词均存在于 scopeLimitations。 |
| `test_full_contract_meaning_is_qualified` | `e5_model.rs::tests::report_scope_limits_and_status_vocabulary_are_frozen` | EQUIVALENT：fullContract.meaning 逐项断言 bounded-only、scopeLimitations、无 admission re-derivation/watermark、latched delta、非生产证据及 strictly-before。 |
| `test_omission_entries_shape` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：逐项核对 6 个 omission key、premise identity/status vocabulary、counterexample 必需字段/domain/staleAtAdmission。 |
| `test_report_is_json_serializable` | `e5_model.rs::tests::full_contract_and_omission_counts_match_the_reference_checker` | EQUIVALENT：`serde_json::Value` 完整 report 序列化再解析，并核对 model 和 abstract-evidence scope。 |
| `test_json_cli_produces_parseable_report` | `e5_model_check_cli.rs::json_cli_emits_parseable_report_at_requested_bound` | EQUIVALENT：实际本机构建 binary exit success、stdout JSON 可解析、bound/status 正确。 |
| `test_text_cli_produces_summary` | `e5_model_check_cli.rs::text_cli_reports_incomplete_exploration_honestly` | EQUIVALENT：实际 binary exit success，underbound 文本包含 UNKNOWN、evidence-only 与 status-scope。 |
| `test_default_bound_flag_used` | `e5_model_check_cli.rs::default_bound_flag_is_used` | EQUIVALENT：实际 binary 默认报告 bound=28。 |
| `test_invalid_bound_cli_exits_with_code_2` | `e5_model_check_cli.rs::tests::invalid_bound_cli_exits_with_code_two_before_emitting_a_report` | EQUIVALENT：本机进程对 0/越界/非整数字符串均观察 exit code 2、空 stdout 与非空 stderr；这是 CLI argv 路径，不代替 Python `validate_bound()` 的动态类型 API 差异。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_e5_model_check_two_mutations.py -->
### `test_e5_model_check_two_mutations.py`（8）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_full_contract_strict_passes` | `two_mutation_model.rs::tests::strict_full_contract_is_complete_repeatable_and_conserves_trace_counts` | EQUIVALENT：strict 完整 PASS/零违反。 |
| `test_branch_backtracking_preserves_complete_strict_counts` | `two_mutation_model.rs::tests::strict_full_contract_is_complete_repeatable_and_conserves_trace_counts` | EQUIVALENT：重复运行确定性及 trace/domain count 守恒。 |
| `test_cross_mutation_torn_states_are_reachable_and_rejected` | `two_mutation_model.rs::tests::strict_model_exposes_torn_and_stale_windows_without_admitting_them` | EQUIVALENT：跨 mutation torn reachability/deny。 |
| `test_stale_commit_window_is_enumerated_and_always_denied` | `two_mutation_model.rs::tests::strict_model_exposes_torn_and_stale_windows_without_admitting_them` | EQUIVALENT：stale window 被枚举并 deny。 |
| `test_required_bound_completes` | `two_mutation_model.rs::tests::complete_bound_and_underbound_status_are_distinguished` | EQUIVALENT：required bound PASS，低一位不 PASS。 |
| `test_strict_mode_omissions_match_expected_outcomes` | `two_mutation_model.rs::tests::strict_omission_outcomes_and_counterexample_families_are_pinned` | EQUIVALENT：六项 omission 严格模式预期状态/类别。 |
| `test_bracket_mode_latch_and_recheck_omissions_fail` | `two_mutation_model.rs::tests::bracket_pending_probe_omission_has_a_bounded_hazard`; `bracket_post_recheck_omission_has_a_bounded_hazard` | EQUIVALENT：pending probe 与 recheck omission hazard。 |
| `test_violation_attribution_dimension_exists` | `two_mutation_model.rs::tests::two_mutation_violation_attribution_is_reported_by_family` | EQUIVALENT：violation mutation attribution。 |
<!-- python-source: Docs/authorization-validation/archive/python-tests/test_experiment_common.py -->
### `test_experiment_common.py`（46）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_three_node_runtime_preconditions_pass_with_rotation_journal` | `experiment_common_contract.rs::tests::three_node_runtime_preconditions_pass_with_rotation_journal` | EQUIVALENT：三节点 pool inventory、单一 epoch 与 rotation journal 满足时 PASS，observed=3。 |
| `test_missing_node_or_rotation_journal_is_blocked` | `experiment_common_contract.rs::tests::missing_node_or_rotation_journal_is_blocked` | EQUIVALENT：缺 node-c 观察与缺 rotation journal 同时 BLOCKED，并含两个预期标签。 |
| `test_non_primary_bad_clock_or_session_contract_fails` | `experiment_common_contract.rs::tests::non_primary_bad_clock_or_session_contract_fails` | EQUIVALENT：非 primary 且 session contract 失败进入 FAIL failures。 |
| `test_epoch_change_without_journal_is_blocked` | `experiment_common_contract.rs::tests::epoch_change_without_journal_is_blocked` | EQUIVALENT：epoch hash 变化且无 journal 时报 `cache_epoch_changed_without_rotation_journal`。 |
| `test_missing_pool_inventory_or_clock_interval_is_not_pass` | `experiment_common_contract.rs::tests::missing_pool_inventory_or_clock_interval_is_not_pass` | EQUIVALENT：缺 inventory 为 BLOCKED；invalid clock interval 为 UNKNOWN。 |
| `test_multiple_server_identities_need_a_route_journal` | `experiment_common_contract.rs::tests::route_journal_is_required_for_multiple_server_identities` | EQUIVALENT：单一 identity 可放行；多 identity 缺 journal 报 `route_journal_missing`，不完整报 `route_journal_incomplete`。 |
| `test_parser_and_validator_reject_malformed_inputs` | `e3_e4_events.rs::tests::e3_parser_filters_flattens_sorts_and_rejects_malformed_matching_records`; `experiment_common_contract.rs::tests::runtime_inputs_reject_empty_nodes_and_negative_clock_threshold` | EQUIVALENT：unknown 事件由 parser 拒绝；空 node set 与负 clock skew 阈值由 input validator 拒绝。 |
| `test_attempt_history_accepts_durable_retry_then_publish` | `e3_reconciliation.rs::tests::durable_publish_history_passes_and_attempt_time_is_advisory` | EQUIVALENT：durable retry 后 publish。 |
| `test_pending_retry_is_not_pass_and_unknown_terminal_is_preserved` | `e3_reconciliation.rs::tests::drain_tail_remains_pending_and_unknown_ack_never_passes` | EQUIVALENT：pending retry/unknown terminal 保留。 |
| `test_missing_claim_or_attempt_regression_is_unknown` | `e3_reconciliation.rs::tests::identity_attempt_and_event_bounds_fail_closed` | EQUIVALENT：claim 缺失/attempt 倒退为 UNKNOWN。 |
| `test_process_restart_pairs_each_attempt_inside_its_own_epoch` | `e3_reconciliation.rs::tests::attempt_pairs_stay_within_process_epoch` | EQUIVALENT：重启 epoch 内配对。 |
| `test_terminal_cannot_close_a_claim_from_another_process` | `e3_reconciliation.rs::tests::a_new_process_cannot_hide_an_unterminated_prior_claim` | EQUIVALENT：terminal 不能关闭其他 process claim。 |
| `test_attempt_gap_and_terminal_identity_drift_are_unknown` | `e3_reconciliation.rs::tests::identity_attempt_and_event_bounds_fail_closed` | EQUIVALENT：attempt gap/identity drift。 |
| `test_earlier_unknown_attempt_cannot_be_hidden_by_later_publish` | `e3_reconciliation.rs::tests::non_allow_reason_and_missing_logs_preserve_unknown_boundaries` | EQUIVALENT：后续成功不覆盖早期 UNKNOWN。 |
| `test_parser_rejects_unknown_event_and_duplicate_process_sequence` | `e3_e4_events.rs::tests::e3_parser_filters_flattens_sorts_and_rejects_malformed_matching_records` | EQUIVALENT：unknown/malformed/duplicate sequence fail-closed。 |
| `test_interval_relations_are_strict` | `e1_validation.rs::tests::classifier_matches_exhaustive_interval_oracle_and_domain_grid` | EQUIVALENT：严格区间关系。 |
| `test_invalid_interval_is_rejected` | `e1_validation.rs::tests::classifier_matches_exhaustive_interval_oracle_and_domain_grid` | EQUIVALENT：invalid interval 拒绝。 |
| `test_config_validation_and_public_provenance` | `node_adapter_contract.rs::tests::flat_config_loads_without_io_and_public_metadata_is_exact` | EQUIVALENT：flat config 校验与 8 字段 public provenance 精确匹配，private 值不外泄。 |
| `test_config_rejects_missing_nodes_and_bad_hash` | `node_adapter_contract.rs::tests::flat_config_loads_without_io_and_public_metadata_is_exact` | EQUIVALENT：缺 nodes 或非法 binary_sha256 均在 load_config 阶段拒绝。 |
| `test_stable_id_is_deterministic_and_validated` | `experiment_common_contract.rs::tests::stable_id_matches_python_uuid_v5_and_validation` | EQUIVALENT：同一 run_id/label 生成 Python 兼容 UUIDv5 精确向量，不同 label 不同，字符集安全。 |
| `test_atomic_json_and_checksums_use_lf_and_verify` | `experiment_common_contract.rs::tests::atomic_json_and_checksums_use_lf_and_verify` | EQUIVALENT：临时文件+rename 原子写、JSON/checksums 均 LF、校验和可检测篡改。 |
| `test_checksum_path_escape_is_rejected` | `readiness_contract.rs::tests::checksum_manifest_detects_tampering_bad_lines_and_path_escape` | EQUIVALENT：路径逃逸拒绝。 |
| `test_parser_flattens_filters_sorts_and_selects_request` | `e3_e4_events.rs::tests::e3_parser_filters_flattens_sorts_and_rejects_malformed_matching_records` | EQUIVALENT：过滤、flatten、sort。 |
| `test_parser_rejects_missing_request_and_duplicate_sequence` | `e3_e4_events.rs::tests::e3_parser_filters_flattens_sorts_and_rejects_malformed_matching_records` | EQUIVALENT：request ID 和 sequence 唯一性。 |
| `test_parser_requires_valid_process_observation_id` | `e3_e4_events.rs::tests::e3_parser_filters_flattens_sorts_and_rejects_malformed_matching_records` | EQUIVALENT：process/observation ID 校验。 |
| `test_parser_duplicate_sequence_is_scoped_to_one_process_epoch` | `e3_e4_events.rs::tests::e3_parser_filters_flattens_sorts_and_rejects_malformed_matching_records` | EQUIVALENT：sequence uniqueness scope。 |
| `test_strict_final_observation_uses_initial_pending_probe` | `experiment_common_contract.rs::tests::strict_final_observation_uses_initial_pending_probe` | EQUIVALENT：strict 最终观察使用唯一 pending probe 对，source=strict_db，interval=(10,20)。 |
| `test_cache_final_observation_requires_full_bracket_and_returns_m0` | `experiment_common_contract.rs::tests::cache_final_observation_requires_full_bracket_and_returns_m0` | EQUIVALENT：两个 manifest + 两个 pending 对必须 m0<p0<m1<p1，返回 m0 区间与 l1_cache。 |
| `test_cache_missing_second_observation_is_rejected` | `experiment_common_contract.rs::tests::cache_missing_second_observation_is_rejected` | EQUIVALENT：缺失第二组 manifest 观察时拒绝。 |
| `test_cache_misordered_bracket_is_rejected` | `experiment_common_contract.rs::tests::cache_misordered_bracket_is_rejected` | EQUIVALENT：bracket 顺序被破坏时拒绝。 |
| `test_pending_true_or_failed_observation_is_rejected` | `experiment_common_contract.rs::tests::pending_true_observation_is_rejected`; `e5_model.rs::tests::bound_validation_and_fail_unknown_precedence_are_preserved` | EQUIVALENT：pending=true 的观察被拒绝；模型层 latch 阻止准入。 |
| `test_post_commit_before_final_observation_is_theorem_violation` | `e5_model.rs::tests::domain_classification_keeps_overlap_outside_the_theorem` | EQUIVALENT：strict-before domain。 |
| `test_pre_commit_and_post_observation_are_outside_theorem_domain` | `e5_model.rs::tests::domain_classification_keeps_overlap_outside_the_theorem` | EQUIVALENT：not-stale/after observation domain。 |
| `test_overlapping_commit_interval_stays_unknown_subclass` | `e5_model.rs::tests::domain_classification_keeps_overlap_outside_the_theorem` | EQUIVALENT：overlap UNKNOWN。 |
| `test_unknown_commit_cross_process_and_duplicate_sequences_are_rejected` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT：commit 与 request/process identity 边界。 |
| `test_cross_epoch_mutation_is_rejected_even_with_unique_sequences` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT：cross-epoch mutation 拒绝。 |
| `test_cross_epoch_within_request_events_is_rejected` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT：request event 不跨 epoch 配对。 |
| `test_missing_epoch_is_rejected` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT：缺 epoch identity 未证明。 |
| `test_commit_interval_spanning_epochs_is_refused` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence` | EQUIVALENT：commit interval 不可跨 epoch。 |
| `test_identity_drift_and_unstable_recheck_are_rejected` | `e1_validation.rs::tests::classifier_fails_closed_on_identity_epoch_order_and_commit_evidence`; `experiment_common_contract.rs::tests::strict_final_observation_uses_initial_pending_probe` | EQUIVALENT：identity drift 与 unstable recheck 在分类器中拒绝；final observation 的 strict bracket 由独立合同覆盖。 |
| `test_allow_requires_host_admission` | `e3_reconciliation.rs::tests::host_allow_requires_one_later_matching_admission` | EQUIVALENT：ALLOW 必须匹配 host admission。 |
| `test_pending_deny_and_unknown_are_distinct` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：终态 status 区分。 |
| `test_classifier_categories_correspond_to_e5_domains` | `e1_validation.rs::tests::classifier_matches_exhaustive_interval_oracle_and_domain_grid`; `e5_model.rs::tests::domain_classification_keeps_overlap_outside_the_theorem` | EQUIVALENT：E5 domain 分类映射。 |
| `test_non_200_must_not_cross_host_admission` | `e3_e4_events.rs::tests::e1_request_selection_terminal_status_and_status_vocabulary_are_explicit` | EQUIVALENT：403 请求携带 host_admission 时 `validate_request_terminal` 明确拒绝。 |
| `test_status_vocabulary_is_closed` | `e3_e4_events.rs::tests::terminal_decisions_require_unique_records_and_preserve_status_mapping` | EQUIVALENT：status vocabulary closed。 |
| `test_required_parser_and_validator_symbols_remain_callable` | `experiment_common_contract.rs::tests::required_parser_and_validator_symbols_remain_callable` | EQUIVALENT：stable_id、final_observation_interval、runtime preconditions 与 route journal 均以明确函数指针类型可调用。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_experiment_register.py -->
### `test_experiment_register.py`（6）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_register_validates` | `experiment_register.rs::tests::registry_pins_stimulus_canary_capture_and_acceptance_surfaces` | EQUIVALENT：registry consistency。 |
| `test_stimulus_classes_complete_and_revocation_class` | `experiment_register.rs::tests::registry_pins_stimulus_canary_capture_and_acceptance_surfaces` | EQUIVALENT：刺激类型集合/revocation metadata。 |
| `test_e2_controls_cover_every_runtime_switch_premise` | `experiment_register.rs::tests::registry_links_every_runtime_e2_premise_to_a_native_rust_test` | EQUIVALENT：E2 premise 和 Rust test link。 |
| `test_canary_ground_truth_fixed_by_construction` | `experiment_register.rs::tests::registry_pins_stimulus_canary_capture_and_acceptance_surfaces` | EQUIVALENT：检测/误阻断率固定。 |
| `test_dependency_fault_matrix_is_full_cross_product` | `dependency_profiles.rs::tests::every_fault_dependency_and_matrix_entry_is_explicit` | EQUIVALENT：profile-filtered dependency×fault timing rows。 |
| `test_capture_and_acceptance_tables_present` | `experiment_register.rs::tests::registry_pins_stimulus_canary_capture_and_acceptance_surfaces` | EQUIVALENT：capture/acceptance field inventories。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_lifecycle_reducer.py -->
### `test_lifecycle_reducer.py`（9）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_complete_same_epoch_request_produces_stage_percentiles` | `lifecycle.rs::tests::e1_reduction_requires_complete_same_epoch_allow_and_uses_nearest_rank` | EQUIVALENT：阶段延迟与样本统计。 |
| `test_missing_initial_evidence_is_unknown_and_excluded` | `lifecycle.rs::tests::e1_reduction_requires_complete_same_epoch_allow_and_uses_nearest_rank` | EQUIVALENT：缺初始 evidence 不入样本并 UNKNOWN。 |
| `test_missing_or_ambiguous_final_evidence_is_unknown_and_excluded` | `lifecycle.rs::tests::e1_reduction_requires_complete_same_epoch_allow_and_uses_nearest_rank` | EQUIVALENT：缺失/歧义 final evidence 不计 sample。 |
| `test_cross_epoch_or_unproven_allow_is_unknown_without_sequence_comparison` | `lifecycle.rs::tests::e1_reduction_requires_complete_same_epoch_allow_and_uses_nearest_rank` | EQUIVALENT：跨 epoch/非 allow 不比较序号并 UNKNOWN。 |
| `test_cross_node_interval_requires_clock_offset_evidence` | `lifecycle.rs::tests::cross_node_time_needs_clock_proof_and_percentiles_are_bounded` | EQUIVALENT：跨节点需要 clock proof。 |
| `test_same_process_durable_claim_to_terminal_is_reduced` | `lifecycle.rs::tests::e3_reduction_refuses_restart_ambiguous_and_unproven_terminals` | EQUIVALENT：同 process durable claim/terminal 断言 PASS、`samples == 1`、p95 为 4,000 ns。 |
| `test_restart_boundary_does_not_pair_claim_and_terminal` | `lifecycle.rs::tests::e3_reduction_refuses_restart_ambiguous_and_unproven_terminals` | EQUIVALENT：跨 process restart 不配对。 |
| `test_duplicate_terminal_or_missing_durable_proof_is_unknown` | `lifecycle.rs::tests::e3_reduction_refuses_restart_ambiguous_and_unproven_terminals` | EQUIVALENT：duplicate terminal/未 durable 均 UNKNOWN。 |
| `test_nearest_rank_percentiles_are_conservative_and_fixed` | `lifecycle.rs::tests::cross_node_time_needs_clock_proof_and_percentiles_are_bounded` | EQUIVALENT：nearest-rank p50/p95/p99 与范围。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_model_acceptance.py -->
### `test_model_acceptance.py`（9）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_complete_contracts_and_expected_omission_failures` | `model_acceptance.rs::tests::accepts_both_full_contract_wire_shapes_and_rejects_missing_modes` | EQUIVALENT：single/two model summary/full wire shape 与 omissions。 |
| `test_missing_unexpected_and_incomplete_modes_are_unknown` | `model_acceptance.rs::tests::full_contract_checks_identity_modes_counts_status_and_omissions` | EQUIVALENT：缺失/额外/类型不符 mode UNKNOWN。 |
| `test_violation_is_fail_and_boolean_is_not_a_count` | `model_acceptance.rs::tests::full_contract_checks_identity_modes_counts_status_and_omissions` | EQUIVALENT：violation FAIL、bool count UNKNOWN。 |
| `test_identity_and_omission_registry_cannot_be_missing` | `model_acceptance.rs::tests::full_contract_checks_identity_modes_counts_status_and_omissions` | EQUIVALENT：model identity、遗漏/重复 registry 检查。 |
| `test_universal_requires_both_models_and_all_ten_hypotheses` | `model_acceptance.rs::tests::universal_acceptance_requires_exact_two_models_and_all_hypothesis_evidence` | EQUIVALENT：两模型×十条 hypothesis 精确集合。 |
| `test_universal_checks_mode_and_bound_evidence` | `model_acceptance.rs::tests::universal_acceptance_requires_exact_two_models_and_all_hypothesis_evidence` | EQUIVALENT：U1/U8/U9 mode/bound evidence。 |
| `test_lattice_policy_and_counts_are_exact` | `model_acceptance.rs::tests::universal_acceptance_requires_exact_two_models_and_all_hypothesis_evidence` | EQUIVALENT：62/6 subset lattice 策略和计数。 |
| `test_failed_hypothesis_is_fail_not_expected_omission` | `model_acceptance.rs::tests::universal_acceptance_requires_exact_two_models_and_all_hypothesis_evidence` | EQUIVALENT：失败 hypothesis 不当作预期 omission。 |
| `test_tenant_hypotheses_are_exact_not_u_series` | `model_acceptance.rs::tests::tenant_hypotheses_require_the_exact_complete_registry` | EQUIVALENT：tenant T hypothesis 独立精确集合。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_node_adapter.py -->
### `test_node_adapter.py`（49）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_import_requires_no_config_and_performs_no_io` | `node_adapter_contract.rs::tests::flat_config_loads_without_io_and_public_metadata_is_exact` | EQUIVALENT：flat config 在 hmac 文件不存在时仍可加载，构造阶段不读取文件。 |
| `test_construction_performs_no_io_before_methods` | `node_adapter_contract.rs::tests::config_is_validated_without_io_and_public_metadata_hides_private_topology` | EQUIVALENT：config validation 不触发 runner。 |
| `test_valid_flat_run_config_mapping_loads` | `node_adapter_contract.rs::tests::flat_config_loads_without_io_and_public_metadata_is_exact` | EQUIVALENT：完整 flat mapping 加载后 run_id、secret presence 与 private-config 状态均可查询。 |
| `test_public_metadata_matches_experiment_common` | `node_adapter_contract.rs::tests::flat_config_loads_without_io_and_public_metadata_is_exact` | EQUIVALENT：public metadata 的 8 个字段、hash、sourceDirty 与 nodeLabels 精确匹配且不含 private 值。 |
| `test_repr_and_str_keep_all_private_values_hidden` | `node_adapter_contract.rs::tests::config_is_validated_without_io_and_public_metadata_hides_private_topology` | EQUIVALENT：debug/public metadata 隐藏 secrets。 |
| `test_public_metadata_never_leaks_private_values` | `node_adapter_contract.rs::tests::config_is_validated_without_io_and_public_metadata_hides_private_topology` | EQUIVALENT：public metadata 不泄露 topology。 |
| `test_missing_and_malformed_fields_rejected` | `node_adapter_contract.rs::tests::config_shape_errors_are_constant_sorted_and_invalid_maps_fail_closed` | EQUIVALENT：缺失/畸形 config 拒绝。 |
| `test_non_mapping_rejected` | `node_adapter_contract.rs::tests::config_shape_errors_are_constant_sorted_and_invalid_maps_fail_closed` | EQUIVALENT：非 mapping 不接受。 |
| `test_ports_and_mappings_are_read_only_views` | `node_adapter_contract.rs::tests::flat_config_loads_without_io_and_public_metadata_is_exact` | EQUIVALENT：typed config 不暴露可变 map；public metadata 仅含固定 node labels，不泄露 ports/topology。 |
| `test_payload_field_order_exact` | `node_adapter_contract.rs::tests::actor_aliases_and_signed_payload_field_order_are_explicit` | EQUIVALENT：payload field order。 |
| `test_exact_hmac_vector_and_header_set` | `node_adapter_contract.rs::tests::gateway_v3_signature_matches_byte_exact_hmac_vector` | EQUIVALENT：精确 HMAC vector/header。 |
| `test_field_order_is_load_bearing` | `node_adapter_contract.rs::tests::gateway_v3_signature_matches_byte_exact_hmac_vector` | EQUIVALENT：签名前序列化顺序。 |
| `test_actor_aliases_and_rejection` | `node_adapter_contract.rs::tests::actor_aliases_and_signed_payload_field_order_are_explicit` | EQUIVALENT：actor alias 与非法输入。 |
| `test_invalid_method_path_and_request_id_rejected` | `node_adapter_contract.rs::tests::signed_request_restricts_path_method_body_and_parses_object_responses` | EQUIVALENT：method/path/request id 校验。 |
| `test_hmac_secret_loaded_lazily_and_validated` | `node_adapter_contract.rs::tests::fixed_sql_script_and_hmac_secret_load_lazily` | EQUIVALENT：secret 仅由显式 load 读取；缺失/空文件分别报 `hmac_secret_unreadable`/`hmac_secret_empty`；SQL plan 不读取 secret。 |
| `test_secret_not_retained_on_adapter` | `node_adapter_contract.rs::tests::fixed_sql_script_and_hmac_secret_load_lazily` | EQUIVALENT：签名后 config 的 Debug/public metadata 均不含 secret sentinel；secret 不进入配置对象。 |
| `test_fixed_argv_stdin_and_tsv_parse` | `node_adapter_contract.rs::tests::sql_command_has_fixed_argv_stdin_tsv_and_missing_root_guard` | EQUIVALENT：SQL argv/stdin/timeout 精确、secret 不出现在 argv、TSV 空列保留。 |
| `test_fixed_script_literal_shape` | `node_adapter_contract.rs::tests::fixed_sql_script_and_hmac_secret_load_lazily` | PARTIAL：MySQL 固定 stdin/凭据隔离断言保留，Redis 固定脚本已删除，不再声称两套脚本等价。 |
| `test_select_only_guard` | `node_adapter_contract.rs::tests::sql_guard_and_fixed_argv_are_read_only_and_secret_stays_off_argv` | EQUIVALENT：只读 SQL guard。 |
| `test_sql_failure_raises_scrubbed_error` | `node_adapter_contract.rs::tests::sql_and_log_failures_are_scrubbed_and_bounded` | EQUIVALENT：sql_failed 返回 scrubbed/bounded detail，host 与 secret 均不出现。 |
| `test_missing_mysql_root_fails_closed_before_runner` | `node_adapter_contract.rs::tests::sql_command_has_fixed_argv_stdin_tsv_and_missing_root_guard` | EQUIVALENT：缺 mysql_root 在 runner 调用前报 `mysql_root_missing`，calls 保持 0。 |
| `test_allowlist_verbs_and_fixed_argv` | `node_adapter_contract.rs::tests::retired_redis_fields_are_rejected_without_affecting_sql_or_metadata` | RETIRED：Redis command API 和 argv 构造器已删除；替代断言拒绝旧配置。 |
| `test_verbs_outside_allowlist_rejected_before_runner` | `node_adapter_contract.rs::tests::retired_redis_fields_are_rejected_without_affecting_sql_or_metadata` | RETIRED：Redis 端口已删除，不存在可派发命令。 |
| `test_arity_and_key_validation` | `node_adapter_contract.rs::tests::retired_redis_fields_are_rejected_without_affecting_sql_or_metadata` | RETIRED：旧 Redis verb/key/arity 合同已删除。 |
| `test_missing_redis_password_fails_closed` | `node_adapter_contract.rs::tests::retired_redis_fields_are_rejected_without_affecting_sql_or_metadata` | RETIRED：不再读取 Redis 密码或构造命令；旧配置字段被拒绝。 |
| `test_redis_failure_raises_scrubbed_error` | `node_adapter_contract.rs::tests::sql_and_log_failures_are_scrubbed_and_bounded` | RETIRED：Redis 执行/错误路径已删除；SQL 与日志错误脱敏单独保留，不计原 Redis 等价覆盖。 |
| `test_returns_status_parsed_dict_and_request_id` | `node_adapter_contract.rs::tests::signed_request_restricts_path_method_body_and_parses_object_responses` | EQUIVALENT：成功 status、JSON object、request id。 |
| `test_path_restrictions` | `node_adapter_contract.rs::tests::signed_request_restricts_path_method_body_and_parses_object_responses` | EQUIVALENT：路径 allowlist。 |
| `test_node_alias_restrictions` | `node_adapter_contract.rs::tests::node_alias_restrictions_apply_to_signed_requests` | EQUIVALENT：node-a/b/c 通过；gateway/node-d/NODE-A/node_a/空串均在 signing 前报 `invalid_node_alias`。 |
| `test_actor_source` | `node_adapter_contract.rs::tests::role_actor_and_decision_path_keep_exact_card_binding` | EQUIVALENT：actor source/角色/card。 |
| `test_signed_mutations_use_allowlisted_methods_and_deterministic_json` | `node_adapter_contract.rs::tests::signed_request_restricts_path_method_body_and_parses_object_responses` | EQUIVALENT：允许方法与 deterministic JSON。 |
| `test_signed_request_rejects_unallowlisted_or_malformed_inputs` | `node_adapter_contract.rs::tests::signed_request_restricts_path_method_body_and_parses_object_responses` | EQUIVALENT：bad method/path/body reject。 |
| `test_non_json_rejection` | `node_adapter_contract.rs::tests::signed_request_restricts_path_method_body_and_parses_object_responses` | EQUIVALENT：non-object/non-JSON response 未证明。 |
| `test_role_specific_signatures_and_card_binding` | `node_adapter_contract.rs::tests::role_actor_and_decision_path_keep_exact_card_binding`; `gateway_v3_signature_matches_byte_exact_hmac_vector` | EQUIVALENT：role-specific actor/signature binding。 |
| `test_missing_role_mapping_is_rejected_before_any_io` | `node_adapter_contract.rs::tests::role_actor_and_decision_path_keep_exact_card_binding` | EQUIVALENT：role mapping 不完整先拒绝。 |
| `test_node_b_uses_local_direct_argv` | `node_adapter_contract.rs::tests::log_slice_commands_use_bounded_raw_collection_and_rust_filtering` | PARTIAL：保留本地固定 argv，改用 `head -c` 有界原始采集和 Rust 过滤/脱敏；Python/script stdin 已删除。 |
| `test_node_a_and_c_use_ssh_batchmode_fixed_args` | `node_adapter_contract.rs::tests::log_slice_commands_use_bounded_raw_collection_and_rust_filtering` | PARTIAL：保留 BatchMode 固定 SSH argv，远端仅执行有界原始采集，过滤/判定在 Rust；旧远端 Python/payload 合同退役。 |
| `test_identifiers_validated_and_empty_short_circuit` | `node_adapter_contract.rs::tests::log_slice_validates_and_deduplicates_ids_before_runner_dispatch` | EQUIVALENT：空/非法 identifiers 先拒绝。 |
| `test_failure_raises_error_without_host_target` | `node_adapter_contract.rs::tests::sql_and_log_failures_are_scrubbed_and_bounded` | EQUIVALENT：log_slice_failed 的 detail 已 scrub，host 不出现且含 `[redacted-host]`。 |
| `test_unknown_node_alias_rejected` | `node_adapter_contract.rs::tests::config_shape_errors_are_constant_sorted_and_invalid_maps_fail_closed` | EQUIVALENT：未注册 node alias 拒绝。 |
| `test_helpers_issue_select_only_queries_through_sql` | `node_adapter_contract.rs::tests::durable_reconciliation_query_builders_are_select_only_and_reject_bad_inputs` | EQUIVALENT：query helper SELECT-only。 |
| `test_helper_input_validation` | `node_adapter_contract.rs::tests::durable_reconciliation_query_builders_are_select_only_and_reject_bad_inputs` | EQUIVALENT：query input allowlist。 |
| `test_fakes_satisfy_protocols` | `node_adapter_contract.rs::tests::fake_runner_and_transport_satisfy_the_declared_traits` | EQUIVALENT：FakeRunner/FakeTransport 通过 trait bound 被调用并返回 typed 结果。 |
| `test_command_result_shape` | `node_adapter_contract.rs::tests::command_result_shape_and_disabled_subprocess_runner` | EQUIVALENT：CommandResult 的 exit_code/stdout/stderr 字段形状断言。 |
| `test_subprocess_runner_exists_without_calling_subprocess` | `node_adapter_contract.rs::tests::command_result_shape_and_disabled_subprocess_runner` | EQUIVALENT：DisabledSubprocessRunner::run 存在且返回 `subprocess_execution_not_enabled`，不创建进程。 |
| `test_adapter_repr_hides_everything_private` | `node_adapter_contract.rs::tests::config_is_validated_without_io_and_public_metadata_hides_private_topology` | EQUIVALENT：debug/public metadata 不泄漏 private fields。 |
| `test_adapter_rejects_bad_config_type` | `node_adapter_contract.rs::tests::config_shape_errors_are_constant_sorted_and_invalid_maps_fail_closed` | EQUIVALENT：config 类型不符拒绝。 |
| `test_scrub_covers_url_ip_and_hostname` | `node_adapter_contract.rs::tests::scrubber_redacts_url_ipv4_hostname_and_bounds_strings` | EQUIVALENT：URL/IP/hostname scrub。 |
| `test_log_grep_script_uses_the_payload_emitted_by_read_log_lines` | `node_adapter_contract.rs::tests::log_slice_commands_use_bounded_raw_collection_and_rust_filtering` | RETIRED：Python grep script/base64 payload 已物理删除；替代 Rust 断言验证原始采集、ID 上限、过滤和脱敏，不计旧脚本等价。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_projection_owner_model.py -->
### `test_projection_owner_model.py`（14）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_default_bfs_is_reproducible_and_complete_in_finite_universe` | `projection_owner_model.rs::tests::default_bfs_is_reproducible_and_complete_in_the_finite_universe` | EQUIVALENT：有限 BFS 完整且可重复。 |
| `test_same_grant_predecessor_scenarios_have_liveness_witnesses` | `projection_owner_model.rs::tests::same_grant_predecessor_scenarios_have_conditional_liveness_witnesses` | EQUIVALENT：同 grant predecessor witness。 |
| `test_independent_grants_same_aggregate_reach_both_published` | `projection_owner_model.rs::tests::independent_grants_in_one_aggregate_can_both_publish` | EQUIVALENT：同 aggregate 独立 grant 均能发布。 |
| `test_claim_exec_failure_and_release_accounting_transitions` | `projection_owner_model.rs::tests::transition_counters_cover_claim_execution_failure_and_release` | EQUIVALENT：claim/exec failure/release counters。 |
| `test_unknown_requires_reconcile_before_retry` | `projection_owner_model.rs::tests::unknown_reconciliation_precedes_a_bounded_retry` | EQUIVALENT：unknown 先 reconcile。 |
| `test_unknown_blocks_publish_and_read_allow` | `projection_owner_model.rs::tests::unknown_blocks_publication_and_allow_until_durable_reconciliation` | EQUIVALENT：UNKNOWN 阻止 publish/ALLOW。 |
| `test_normal_atomic_publish_does_not_set_unknown` | `projection_owner_model.rs::tests::normal_atomic_publication_does_not_create_unknown_state` | EQUIVALENT：正常原子发布不建 UNKNOWN。 |
| `test_aggregate_predecessor_busy_is_zero_counter_for_exact_and_poll` | `projection_owner_model.rs::tests::aggregate_predecessor_busy_edges_do_not_charge_counters` | EQUIVALENT：busy edge 不计执行 counter。 |
| `test_source_7_then_64_cannot_publish_in_reverse_order` | `projection_owner_model.rs::tests::aggregate_ordering_does_not_publish_source_64_before_source_7` | EQUIVALENT：source predecessor order。 |
| `test_negative_controls_find_shortest_search_counterexamples` | `projection_owner_model.rs::tests::negative_controls_find_shortest_counterexamples` | EQUIVALENT：negative control 最短 trace。 |
| `test_epoch_omission_alone_is_not_asserted_as_vulnerability` | `projection_owner_model.rs::tests::removing_only_epoch_fence_is_not_reported_as_a_vulnerability` | EQUIVALENT：不把 epoch omission 单独称为漏洞。 |
| `test_cutoff_is_unknown_not_pass` | `projection_owner_model.rs::tests::search_cutoff_is_unknown_not_pass` | EQUIVALENT：cutoff UNKNOWN。 |
| `test_fixed_schedule_ablation_is_not_performance_claim` | `projection_owner_model.rs::tests::fixed_schedule_ablation_is_not_a_performance_claim` | EQUIVALENT：ablation 不称 performance。 |
| `test_finite_episode_limits_and_argument_validation` | `projection_owner_model.rs::tests::finite_episode_limits_and_search_bounds_are_pinned`; `premise_registry_rejects_unknown_names` | EQUIVALENT：bound 与 premise input。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_run_single_node_campaign.py -->
### `test_run_single_node_campaign.py`（28）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_import_does_not_create_campaign_or_run_commands` | `readiness_contract.rs::tests::readiness_sources_have_no_import_time_io_or_process_capability` | EQUIVALENT：readiness 生产源不含 fs/process/net/env/client 能力，模块装载不会创建 campaign 或执行命令。 |
| `test_existing_campaign_refused_without_writing` | `campaign/run_tests.rs::tests::run_selected_refuses_run_id_collision_and_invalid_artifact_scope` | EQUIVALENT：既有 run dir collision 不覆盖。 |
| `test_invalid_campaign_id_rejected_before_any_write` | `readiness_contract.rs::tests::campaign_ids_and_artifact_paths_reject_traversal_before_writes` | EQUIVALENT：非法 ID 在写入前拒绝。 |
| `test_missing_source_blocks_before_directory_creation` | `legacy_campaign_contract.rs::tests::missing_source_blocks_before_directory_creation` | EQUIVALENT：source preflight 在缺源时返回错误，调用方在创建目录前退出。 |
| `test_failed_required_gate_stops_later_commands_and_records_skip` | `legacy_campaign_contract.rs::tests::failed_required_gate_stops_later_commands_and_records_skip` | EQUIVALENT：首个 required FAIL 后停止派发，后续命令记录 SKIP。 |
| `test_scenario_blocks_are_reported_without_downgrading_local_readiness` | `readiness_contract.rs::tests::source_drift_invalidates_prior_passes_and_scenario_blocks_do_not_lower_local_ready` | EQUIVALENT：scenario blocked 不降低 local ready。 |
| `test_previous_attempt_points_to_latest_frozen_snapshot` | `legacy_campaign_contract.rs::tests::previous_attempt_points_to_latest_frozen_snapshot` | EQUIVALENT：previous attempt campaignId/status/localReady/reason 精确 pin。 |
| `test_changed_trustgraph_main_is_in_source_inventory` | `readiness_contract.rs::tests::source_inventory_is_unique_complete_and_hashes_exact_bytes` | EQUIVALENT：source list/hash inventory contract。 |
| `test_changed_permission_check_shared_is_in_source_inventory` | `readiness_contract.rs::tests::source_inventory_is_unique_complete_and_hashes_exact_bytes` | EQUIVALENT：inventory exactness。 |
| `test_changed_observability_and_lifecycle_sources_are_in_inventory` | `readiness_contract.rs::tests::source_inventory_is_unique_complete_and_hashes_exact_bytes` | EQUIVALENT：inventory exactness。 |
| `test_runtime_suites_execute_real_tests_without_no_run` | `legacy_campaign_contract.rs::tests::runtime_suites_execute_real_tests_without_no_run` | EQUIVALENT：四个 runtime suite 均为 required cargo test、expected `; 0 failed`、argv 不含 `--no-run`；compile-only workspace gate 保持独立。 |
| `test_runtime_suites_scenario_aggregates_command_status` | `legacy_campaign_contract.rs::tests::runtime_suites_scenario_aggregates_command_status` | EQUIVALENT：四个 runtime suite 中任一 FAIL 时 scenario=FAIL。 |
| `test_upgraded_verification_gates_are_registered` | `legacy_campaign_contract.rs::tests::upgraded_verification_gates_are_registered` | EQUIVALENT：两个 E5 gate 已注册，two-mutation/universal 标志与 timeout>1800 精确断言。 |
| `test_experiment_register_and_multi_classifier_importable` | `experiment_register.rs::tests::required_registry_symbols_are_importable` | EQUIVALENT：validate_register 与 classify_e1_allow 以明确函数指针类型可调用。 |
| `test_zero_python_tests_cannot_pass` | `readiness_contract.rs::tests::exit_zero_needs_markers_and_minimum_rust_tests` | RETIRED：Python summary 成功验收已删除；当前 Rust summary 必须满足非空断言、数量与状态要求。 |
| `test_e1_observability_failure_is_not_reported_as_skip` | `legacy_campaign_contract.rs::tests::e1_observability_failure_is_not_reported_as_skip` | EQUIVALENT：E1 观测 gate FAIL 时 scenario=FAIL，不降级为 SKIP。 |
| `test_missing_required_argument_exits_before_write` | `legacy_campaign_contract.rs::tests::missing_required_argument_exits_before_write` | EQUIVALENT：缺 --config 或 --out 时退出码 2，解析函数在任何写入前返回。 |
| `test_timeout_reports_unknown_with_incomplete_logs_and_partial_output` | `legacy_campaign_contract.rs::tests::timeout_and_os_error_keep_exact_evidence_fields` | EQUIVALENT：timeout 返回 UNKNOWN、exitCode=None、logComplete=false，并保留部分 stdout/stderr。 |
| `test_os_error_reports_blocked_without_a_fabricated_exit_code` | `legacy_campaign_contract.rs::tests::timeout_and_os_error_keep_exact_evidence_fields` | EQUIVALENT：spawn OSError 返回 BLOCKED、exitCode=None、stderr log=OSError。 |
| `test_e5_invalid_json_output_fails_with_unknown_model_status` | `campaign.rs::tests::model_dependency_and_required_output_acceptance_keep_contract_boundaries` | EQUIVALENT：malformed JSON UNKNOWN，不伪造 PASS。 |
| `test_e5_non_pass_full_contract_fails_but_keeps_reported_model_status` | `campaign.rs::tests::model_dependency_and_required_output_acceptance_keep_contract_boundaries`; `model_acceptance.rs::tests::accepts_both_full_contract_wire_shapes_and_rejects_missing_modes` | EQUIVALENT：模型 FAIL 传播并保留状态。 |
| `test_e5_report_without_full_contract_fails_closed` | `model_acceptance.rs::tests::accepts_both_full_contract_wire_shapes_and_rejects_missing_modes` | EQUIVALENT：缺 fullContract 为 UNKNOWN。 |
| `test_e5_complete_passing_report_passes` | `model_acceptance.rs::tests::full_contract_checks_identity_modes_counts_status_and_omissions` | EQUIVALENT：完整报告 PASS。 |
| `test_exit_zero_without_expected_marker_is_fail` | `campaign.rs::tests::model_dependency_and_required_output_acceptance_keep_contract_boundaries` | EQUIVALENT：marker/postcondition 必须出现。 |
| `test_checksum_verifier_detects_artifact_tampering` | `readiness_contract.rs::tests::checksum_manifest_detects_tampering_bad_lines_and_path_escape` | EQUIVALENT：篡改检测。 |
| `test_every_modeled_premise_maps_to_exactly_one_executed_command` | `experiment_register.rs::tests::registry_links_every_runtime_e2_premise_to_a_native_rust_test` | EQUIVALENT：5 个 runtime premise + host_mediation 完整覆盖 E5 premises；每个 premise/test id 唯一一次映射。 |
| `test_each_e2_command_targets_a_real_test_with_an_exact_marker` | `experiment_register.rs::tests::registry_links_every_runtime_e2_premise_to_a_native_rust_test` | EQUIVALENT：每个 E2 rust_test 均能在 astral-db/policy-engine 源中找到对应 `fn`，且注册表登记于 campaign 源。 |
| `test_host_mediation_has_no_claimed_omission_command` | `experiment_register.rs::tests::registry_links_every_runtime_e2_premise_to_a_native_rust_test` | EQUIVALENT：host_mediation 仅存在于 model-only premises，E2 premise/test id 均不含 host。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_tenant_isolation_model.py -->
### `test_tenant_isolation_model.py`（8）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_overall_status_pass` | `models.rs::tests::overall_tenant_model_status_is_pass` | EQUIVALENT：原生 bounded model 计算并要求 overall `PASS`；不代表 live/runtime tenancy proof。 |
| `test_every_hypothesis_passes` | `models.rs::tests::every_tenant_hypothesis_passes` | EQUIVALENT：逐项断言报告中的 T1/T3/T4/T5 均为 `PASS`，失败包含 hypothesis id 与 statement。 |
| `test_t1_full_scoping_is_contamination_free` | `models.rs::tests::t1_full_scoping_is_contamination_free` | EQUIVALENT：遍历全部 32 个 adversary assignments，精确断言 foreign grant、contaminated input、cross-tenant block 均为 0，且 own pending 大于 0。 |
| `test_t3_lattice_matches_chain_predicate` | `models.rs::tests::t3_lattice_matches_chain_predicate_for_every_proper_subset` | EQUIVALENT：核对 30 个非空真子集、20 个 contaminating subsets、空 unexpected-safe 集、逐项预测相等及 5 个单 gate omission。 |
| `test_t5_configuration_count_matches_audited_lattice` | `models.rs::tests::t5_configuration_count_matches_the_audited_lattice` | EQUIVALENT：要求 audited configuration 数为 31 且等于空集加 30 个非空真子集；额外确认每个配置的 32 条 trace 均守恒。 |
| `test_t4_defense_in_depth_table_locked` | `models.rs::tests::t4_defense_in_depth_table_is_locked` | EQUIVALENT：逐 gate 锁定观察到的 contamination family，包括 probe omission 的两个预期污染类别。 |
| `test_cache_vector_needs_both_gates_removed` | `models.rs::tests::cache_vector_needs_both_gates_removed` | EQUIVALENT：分别移除 cache key、再移除 record validation、再移除 match gate，核对 foreign admission 仅在完整缺 gate 链打开时出现。 |
| `test_cross_tenant_block_requires_unscoped_probe` | `models.rs::tests::cross_tenant_block_requires_an_unscoped_probe` | EQUIVALENT：逐条核对 unscoped-probe block trace 都是 T1 无 narrowing、T2 有 committed-unpublished narrowing，并确认全 gates-on 时没有该 bucket。 |

边界：以上仅证明 Rust bounded abstraction 的离线测试合同；不证明数据库、策略引擎、缓存、部署或运行时隔离行为。T2 不在 Python 报告/方法断言中，未伪造为独立测试项。

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_unbounded_confirmation.py -->
### `test_unbounded_confirmation.py`（5）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_overall_status_pass` | `unbounded_confirmation.rs::tests::c3_c4_remain_explicit_unknown_obligations` | EQUIVALENT：顶层 PASS 仅表示报告中可判定的 C1/C2 均通过；`statusMeaning` 明确 C3/C4 仍 UNKNOWN、未被证明。 |
| `test_decidable_checks_pass` | `unbounded_confirmation.rs::tests::c3_c4_remain_explicit_unknown_obligations` | EQUIVALENT：Rust 报告 C1/C2 均 PASS，且 C1 同时覆盖 single/two 链闭合、C2 按 Python 快速测试只运行 single。 |
| `test_c1_event_space_closure_clean` | `unbounded_confirmation.rs::tests::c3_c4_remain_explicit_unknown_obligations`; `event_chains_are_closed_without_duplicate_events`; `two_mutation_event_chains_are_closed_without_duplicate_events` | EQUIVALENT：两个模型的 C1 status 均 PASS、problem arrays 为空。 |
| `test_c2_bound_invariance_every_configuration` | `unbounded_confirmation.rs::tests::c3_c4_remain_explicit_unknown_obligations`; `finite_bound_does_not_change_single_model_full_contract` | EQUIVALENT：精确 single/bracket 与 single/strict 两项均检查 invariant、PASS 与默认/最大 bound 的 trace 数相同；不声称 two-model C2。 |
| `test_c3_c4_are_explicit_obligations_not_failures` | `unbounded_confirmation.rs::tests::c3_c4_remain_explicit_unknown_obligations` | EQUIVALENT：C3/C4 明确 UNKNOWN，C4 保留 TLAPS blocked 原因。 |

<!-- python-source: Docs/authorization-validation/archive/python-tests/test_universal_hypotheses_check.py -->
### `test_universal_hypotheses_check.py`（12）

| Python 方法 | Rust target | 状态 |
|---|---|---|
| `test_parallel_execution_preserves_every_hypothesis_and_report_field` | `universal_hypotheses.rs::tests::concurrent_single_model_evaluations_preserve_every_hypothesis_and_report_field`; `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model` | EQUIVALENT：两个 Rust 线程独立运行 single-model evaluator，报告逐字段相同且保留 10 个 hypothesis；Python workers=2 语义已覆盖，ProcessPool 是实现细节。 |
| `test_overall_status_pass` | `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model` | EQUIVALENT：实际 single-model bound=16 枚举 status=PASS；本 Python 方法只断言 single-model 报告。 |
| `test_every_hypothesis_passes` | `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model` | EQUIVALENT：实际 single-model U1–U10 全部 PASS。 |
| `test_no_findings` | `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model` | EQUIVALENT：实际 single-model report `findings=[]`。 |
| `test_u1_theorem_domain_safety_both_modes` | `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model` | EQUIVALENT：single-model bracket/strict 实际枚举 complete 且 `admittedStrictlyBefore=0`。 |
| `test_u3_window_enumerated_and_always_denied` | `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model`; `incomplete_model_evidence_never_mints_universal_pass` | EQUIVALENT：single-model 两模式实际枚举 stale traces>0、admitted=0 且 latch denials 非空。 |
| `test_u6_lattice_covers_all_62_proper_subsets` | `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model`; `evaluator_uses_six_singleton_two_model_lattice_and_all_62_single_model_subsets` | EQUIVALENT：实际 single-model evaluator 枚举 62 子集；two-model 的 singles policy 为 6 项。 |
| `test_u7_sharpness_mapping_locked` | `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model` | EQUIVALENT：六个 premise omission 的实际运行均 FAIL，`observedScheduleClass` 与预期映射逐一匹配。 |
| `test_u9_mode_independence` | `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model` | EQUIVALENT：single-model bracket/strict 两模式实际运行 PASS 且 complete。 |
| `test_full_contract_below_required_bound_is_unknown` | `universal_hypotheses.rs::tests::single_model_bound_discipline_and_incomplete_counterexample_match_python_checks`; `e5_model.rs::tests::bound_validation_and_fail_unknown_precedence_are_preserved` | EQUIVALENT：full bracket contract 在 required-1 的实际 run 返回 UNKNOWN、incomplete>0、zero violation；U8 真实报告另外确认每个被抽查的一步以下配置不 PASS，不假设安全上界紧致。 |
| `test_full_contract_complete_at_required_bound` | `universal_hypotheses.rs::tests::single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model`; `single_model_bound_discipline_and_incomplete_counterexample_match_python_checks` | EQUIVALENT：实际 single evaluator 的 U8 检查所有 8 配置 required-bound complete；bracket 与 strict full contract 逐项要求 zero violations。 |
| `test_omission_counterexample_is_decisive_when_incomplete` | `universal_hypotheses.rs::tests::single_model_bound_discipline_and_incomplete_counterexample_match_python_checks` | EQUIVALENT：真实 single-model `host_mediation` omission 使用其 bracket `required_bound - 1`，并断言状态为 FAIL 且 violations>0；未额外要求 Python 未检查的 incomplete/counterexample 字段。 |

### `test_e1_runner.py`（46）

`test_e1_runner.py` 的 46 个历史方法均保留在上方对应表中；每行只说明当前 Rust 离线断言范围。Rust parser/reducer 与注入 adapter 不构成 E1 campaign、live HTTP/DB 或节点运行证据。

## 非 unittest 文件分类

- `scripts/test_campaign.py`：已删除的旧 runner，不是 unittest；历史离线行为断言来源 `scripts/tests/test_test_campaign.py` 仍用于迁移库存，当前只运行 Rust contract suites。
- `Docs/实验/基准测试/scripts/opa_index_test.py` 与归档 Java baseline 的 `opa_index_test.py`：手工 OPA/索引实验脚本，不是 `unittest.TestCase` inventory。
- `Docs/实验/分布式测试/pipeline/.astral-final8-scan-gate-test.py`：历史 pipeline scan gate 工具，不是 Python unittest 模块，不计入 25/622。
- `tests-suite`/实验目录的其他 `test` 命名 Rust 文件是 Rust suites，不构成 Python unittest source。

## 证据/执行边界与剩余项

- 可以离线验证：campaign manifest/selection、环境隔离/前置检查、summary/status precedence、model/benchmark 解析、fake-Cargo 转发、有限模型/reducer/协议解析。
- 必须保持未执行/独立取证：E1/E3/E4 live runners/probes/HTTP/SQL/broker/SSH、真实 DB/RabbitMQ/Docker、TDSC HTTP load 与 S15 三节点部署。Python 原测试不运行；Redis 原正向能力已退役，不再作为 current integration 前置。
- 25/622 的来源行保留，不把 source/counter guard 或退役替代断言折算为等价。当前 `PARTIAL` 的具体边界见对应方法行；`RETIRED` 记录能力删除，无运行成功含义。
- 本次账本同步不改变授权、schema 或数据库事实；日志过滤、故障状态和原生读取合同的实际验证与风险统一记录在 V6-only 删除任务证据中。
