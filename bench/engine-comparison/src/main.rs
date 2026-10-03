//! 多引擎授权决策对比测试 v2（系统对比测试 · Rust canonical 版）
//!
//! 对齐 Java `AstralBenchmark`（BenchmarkRunner --comparison-mode）实验结构
//! （`Docs/实验/基准测试/scripts/README.md` v1.30）：
//!
//! - **RQ-Compare-1**（headline）：单点场景（50 卡 × 81 条目）四引擎读决策；
//! - **RQ-Compare-2**（双轴梯度）：卡数轴（10/50/200 @ 81 条目/卡）× 规则复杂度轴
//!   （81/405/810 条目/卡 @ 50 卡）；
//! - **rule_update_overhead**（写路径）：100 次 Add→Remove 单规则循环写延迟；
//! - **N× fresh-state 重复**（`--repeats`，默认 5）：聚合 mean±stddev；
//! - **CSV/LaTeX 落盘**：`results/comparison-{ts}/` 下 comparison_report.csv、
//!   summary.csv、write_overhead.csv、comparison_table.tex。
//!
//! 引擎建模（各按 vendor 推荐惯用法）：AstralLight=grant ledger（增量编译
//! HotState，决策走 `segment_content` O(1) 查找）；Casbin=策略行精确匹配；
//! Cedar=实体属性集合（官方大批量授权推荐形态）；OPA=data 文档 + sidecar
//! HTTP（真实部署形态，含 RTT）。
//!
//! 运行：`cargo run --release [-- --repeats=5] [--quick] [--opa=http://...] [--run-id=<id>] [--output-dir=<dir>]`
//!
//! 实验完整性（2026-09-04 重测审计；同日 harness 修复）：
//! - 每次运行在结果目录写 `run_meta.json`：runId、output_dir、host/CPU/OS、
//!   git rev+dirty、被测二进制路径+sha256（内建 SHA-256，无新增依赖）、crate
//!   锁定版本、OPA tag（/metrics 的 opa_build_info，尽力而为）、查询配比
//!   （2:1 ALLOW:default-DENY，数学不变式断言）与 write overhead 语义注记。
//! - **OPA 默认必需引擎**：sidecar 不可达时以非零码退出；确需跳过必须显式传
//!   `--allow-opa-skip`（结果如实标记 opa=skipped，exit 0 但元数据注明）。
//! - **退出码约定（fail-closed）**：0=成功；1=CLI 参数错误（--repeats 解析
//!   失败、未知参数、--output-dir/--run-id 目录冲突）；2=启动时 OPA 不可达且
//!   未显式 `--allow-opa-skip`；3=运行中途 OPA 失联/HTTP 错误/决策断言失败；
//!   4=本地落盘（原子 checkpoint）失败。OPA 运行中途失败**不 unwrap panic**：
//!   错误详情落盘 `error.json`，已采集证据先行原子 checkpoint 后再退出。
//! - **证据落盘**：run_meta.json 与全部 CSV/tex 以「同目录临时文件 + fsync +
//!   rename」原子写；每个 repeat 采集完成立即原子 checkpoint 完整 CSV 行与
//!   原始纳秒延迟样本（`raw/`），中途失败只损失进行中的样本，不丢既有数据。
//! - **编排器入口**：`--run-id=<id>`、`--output-dir=<dir>` 显式指定运行标识与
//!   输出目录；输出目录一律**不覆盖已存在目录**（冲突 exit 1）；仅 `--run-id`
//!   时输出目录取 `results/<run-id>`（环境变量 RUN_ID 仅作 run-id 元数据回退，
//!   不派生目录）。启动后在 stdout 输出 `RESULT_DIR <dir>`，run_meta.json 亦
//!   记录 output_dir，供 manifest 精确引用。
//! - 查询配比 2:1 为数学不变式：deny = total/3（下取整）、allow = total − deny；
//!   total % 3 == 0 时严格 2:1，任意总数下 default-deny 恒为少数臂
//!   （`mix_counts`/`assert_mix_invariants` + `mix_tests` 单测）。
//! - write overhead 为**纯内存**口径：Astral=进程内增量编译+CAS revision、
//!   Casbin/Cedar=进程内策略对象、OPA=sidecar 内存 data PUT；**不是 durable
//!   publication**（无 outbox/DB/MQ 写），不可当作落盘写延迟引用。
//! - 结果目录 `results/` 保持 gitignore；目录自包含 run_meta.json，整目录复制
//!   即可归档。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use astral_types::{
    BindingLayer, CanonicalGrant, DependencyVector, DependencyVersion, GrantDelta, GrantEffect,
    GrantId, GrantProvenance, GrantRevision, GrantSourceKind, GrantState, TenantScope,
    ValidityWindow,
};
use policy_engine::{AuthorizationCompiler, CompileOutcome, HotState};

const USER_ID: i64 = 42;
const TENANT_ID: i64 = 7;
const DOMAIN_ID: i64 = 11;
const ACTION: &str = "read";
/// 梯度单元格决策负载数（allow:deny = 2:1）。
const QUERIES: usize = 3000;
/// 写开销场景 Add→Remove 循环次数。
const WRITE_CYCLES: usize = 100;
/// 默认重复次数（fresh-state）。
const DEFAULT_REPEATS: usize = 5;

fn tenant() -> TenantScope {
    TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).unwrap()
}

fn dependencies() -> DependencyVector {
    DependencyVector::new(vec![DependencyVersion::new("rule-set", 3, 1).unwrap()]).unwrap()
}

fn grant_id(card: i64, index: usize) -> GrantId {
    GrantId::parse(&format!("00000000-0000-4000-8000-{card:04x}{index:08x}")).unwrap()
}

fn shared_grant(card: i64, index: usize) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: grant_id(card, index),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: tenant(),
        card_id: card,
        user_id: USER_ID,
        resource: format!("learn_subject:{index}"),
        action: ACTION.to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: "rule-set-shared".to_owned(),
            source_entry: Some(format!("entry-{index}")),
            binding_id: Some(format!("binding-{card}")),
            delegation_id: None,
            operation_id: format!("operation-{card}-{index}"),
            event_id: Some(format!("event-{card}-{index}")),
            actor_user_id: Some(USER_ID),
        },
    }
}

#[derive(Clone, Copy)]
struct Query {
    card: i64,
    resource: usize,
    allow: bool,
}

/// 2:1 ALLOW:default-DENY 配比拆分：default-deny 臂取 floor(total/3)，allow 臂
/// 取其余。total % 3 == 0 时严格 2:1；否则 allow > deny 仍恒成立（default-deny
/// 恒为少数臂），任意总数下约束明确。
fn mix_counts(total: usize) -> (usize, usize) {
    let deny = total / 3;
    (total - deny, deny)
}

/// 查询 mix 数学不变式（取代旧 `allow*2 == total` 断言——该式只在 1:1 成立，
/// 对 2:1 恒假）：
/// - allow + deny == total，deny == total/3（下取整），allow == total − deny；
/// - default-deny 臂恒为少数（allow > deny）；
/// - total % 3 == 0 时严格 2:1（allow == 2*deny）。
fn assert_mix_invariants(queries: &[Query]) {
    let allow = queries.iter().filter(|q| q.allow).count();
    let deny = queries.len() - allow;
    let (want_allow, want_deny) = mix_counts(queries.len());
    assert_eq!(
        allow, want_allow,
        "allow 臂必须为 total - total/3（2:1 ALLOW:default-DENY 拆分）"
    );
    assert_eq!(
        deny, want_deny,
        "default-deny 臂必须为 total/3（下取整；2:1 ALLOW:default-DENY 拆分）"
    );
    assert!(allow > deny, "default-deny 必须恒为少数臂（allow > deny）");
    if queries.len().is_multiple_of(3) {
        assert_eq!(
            allow,
            2 * deny,
            "total % 3 == 0 时必须严格 2:1 ALLOW:default-DENY"
        );
    }
}

fn query_mix(cards: i64, entries: usize) -> Vec<Query> {
    let (allows, denies) = mix_counts(QUERIES);
    let mut queries = Vec::with_capacity(QUERIES);
    for i in 0..allows {
        queries.push(Query {
            card: 1 + (i as i64) % cards,
            resource: i % entries,
            allow: true,
        });
    }
    for i in 0..denies {
        queries.push(Query {
            card: 1 + (i as i64) % cards,
            resource: entries + i % entries, // 越界资源 → default deny
            allow: false,
        });
    }
    queries
}

fn percentile(sorted: &[u64], p: f64) -> f64 {
    sorted[((p / 100.0) * (sorted.len() - 1) as f64).round() as usize] as f64
}

#[derive(Clone, Copy)]
struct ReadMetrics {
    load_ms: f64,
    mean_us: f64,
    p50_us: f64,
    p99_us: f64,
    qps: f64,
}

/// 延迟样本以**纳秒**采集（亚微秒决策的分辨率要求；微秒整型截断会把
/// ~0.2µs 的真实值显示为 0）。汇总时换算为微秒小数。
/// 计时开销注记：一对 `Instant::now()` 约 40ns，对 185-406ns 的决策样本
/// 占 10-20%，mean 由墙钟/QPS 独立印证，两者一致。
fn summarize(load_ms: f64, mut lat_ns: Vec<u64>, wall: Duration) -> ReadMetrics {
    lat_ns.sort_unstable();
    let n = lat_ns.len() as f64;
    ReadMetrics {
        load_ms,
        mean_us: lat_ns.iter().sum::<u64>() as f64 / n / 1000.0,
        p50_us: percentile(&lat_ns, 50.0) / 1000.0,
        p99_us: percentile(&lat_ns, 99.0) / 1000.0,
        qps: n / wall.as_secs_f64(),
    }
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn stddev(values: &[f64]) -> f64 {
    let m = mean(values);
    (values.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / values.len() as f64).sqrt()
}

// ===== AstralLight（policy-engine HotState） =====

fn astral_build(cards: i64, entries: usize) -> HotState {
    HotState::from_grants(
        tenant(),
        1,
        (1..=cards).flat_map(move |card| (0..entries).map(move |index| shared_grant(card, index))),
        dependencies(),
    )
    .unwrap()
}

/// 返回 (汇总指标, 原始纳秒延迟样本)——原始样本供逐 repeat checkpoint。
fn run_astral(cards: i64, entries: usize, queries: &[Query]) -> (ReadMetrics, Vec<u64>) {
    let t0 = Instant::now();
    let state = astral_build(cards, entries);
    let load_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(state.shared_entry_count(), entries);

    let mut lat = Vec::with_capacity(queries.len());
    let t1 = Instant::now();
    for q in queries {
        let t = Instant::now();
        let key = policy_engine::ProjectionKey {
            card_id: q.card,
            user_id: USER_ID,
            resource: format!("learn_subject:{}", q.resource),
            action: ACTION.to_owned(),
        };
        let allowed = state
            .segment_content(&key)
            .map(|segment| !segment.grants.is_empty())
            .unwrap_or(false);
        lat.push(t.elapsed().as_nanos() as u64);
        assert_eq!(
            allowed, q.allow,
            "astral 决策错误 card={} r={}",
            q.card, q.resource
        );
    }
    let wall = t1.elapsed();
    let metrics = summarize(load_ms, lat.clone(), wall);
    (metrics, lat)
}

/// 写开销：每周期唯一 grant_id 的 Add→Remove（真实增量 delta + CAS revision）。
fn astral_write(base: &HotState) -> (f64, f64) {
    let compiler = AuthorizationCompiler::new();
    let t0 = Instant::now();
    for index in 0..WRITE_CYCLES {
        let mut grant = shared_grant(999, 0);
        grant.grant_id = grant_id(999, 10_000 + index);
        let state = match compiler
            .compile_incremental(
                base,
                2,
                dependencies(),
                vec![GrantDelta::add(grant.clone())],
            )
            .unwrap()
        {
            CompileOutcome::Applied(candidate) => candidate.state,
            other => panic!("unexpected {other:?}"),
        };
        let _ = compiler
            .compile_incremental(
                &state,
                3,
                dependencies(),
                vec![GrantDelta::remove(grant.grant_id, GrantRevision::initial())],
            )
            .unwrap();
    }
    let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
    (total_ms, total_ms * 1000.0 / WRITE_CYCLES as f64)
}

// ===== Casbin（casbin-rs 进程内，策略行精确匹配） =====

const CASBIN_MODEL: &str = r#"
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"#;

fn casbin_policy_line(card: i64, index: usize) -> Vec<String> {
    vec![
        format!("card{card}"),
        format!("learn_subject:{index}"),
        ACTION.to_owned(),
    ]
}

fn run_casbin(
    rt: &tokio::runtime::Runtime,
    cards: i64,
    entries: usize,
    queries: &[Query],
) -> (ReadMetrics, Vec<u64>) {
    use casbin::{CoreApi, DefaultModel, Enforcer, MemoryAdapter, MgmtApi};
    let t0 = Instant::now();
    let enforcer = rt.block_on(async {
        let model = DefaultModel::from_str(CASBIN_MODEL).await.unwrap();
        let mut enforcer = Enforcer::new(model, MemoryAdapter::default())
            .await
            .unwrap();
        let policies: Vec<Vec<String>> = (1..=cards)
            .flat_map(|card| (0..entries).map(move |index| casbin_policy_line(card, index)))
            .collect();
        enforcer.add_policies(policies).await.unwrap();
        enforcer
    });
    let load_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let mut lat = Vec::with_capacity(queries.len());
    let t1 = Instant::now();
    for q in queries {
        let t = Instant::now();
        let allowed = enforcer
            .enforce((
                format!("card{}", q.card).as_str(),
                format!("learn_subject:{}", q.resource).as_str(),
                ACTION,
            ))
            .unwrap();
        lat.push(t.elapsed().as_nanos() as u64);
        assert_eq!(
            allowed, q.allow,
            "casbin 决策错误 card={} r={}",
            q.card, q.resource
        );
    }
    let wall = t1.elapsed();
    let metrics = summarize(load_ms, lat.clone(), wall);
    (metrics, lat)
}

fn casbin_write(rt: &tokio::runtime::Runtime) -> (f64, f64) {
    use casbin::{CoreApi, DefaultModel, Enforcer, MemoryAdapter, MgmtApi};
    rt.block_on(async {
        let model = DefaultModel::from_str(CASBIN_MODEL).await.unwrap();
        let mut enforcer = Enforcer::new(model, MemoryAdapter::default())
            .await
            .unwrap();
        let t0 = Instant::now();
        for index in 0..WRITE_CYCLES {
            let line = vec![
                "card999".to_owned(),
                format!("learn_subject:{}", 9000 + index),
                ACTION.to_owned(),
            ];
            enforcer.add_policy(line.clone()).await.unwrap();
            enforcer.remove_policy(line).await.unwrap();
        }
        let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
        (total_ms, total_ms * 1000.0 / WRITE_CYCLES as f64)
    })
}

// ===== Cedar（cedar-policy 进程内，实体属性集合） =====

const CEDAR_POLICY: &str =
    "permit(principal, action, resource) when { resource in principal.granted };";
const CEDAR_WRITE_POLICY: &str = r#"permit(principal == Card::"card999", action, resource) when { resource in principal.granted };"#;

fn run_cedar(cards: i64, entries: usize, queries: &[Query]) -> (ReadMetrics, Vec<u64>) {
    use cedar_policy::{
        Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet,
        Request,
    };
    use std::collections::HashSet;

    let t0 = Instant::now();
    let mut policies = PolicySet::new();
    policies.add(CEDAR_POLICY.parse().unwrap()).unwrap();

    let card_type: EntityTypeName = "Card".parse().unwrap();
    let resource_type: EntityTypeName = "Resource".parse().unwrap();
    let action_type: EntityTypeName = "Action".parse().unwrap();

    let resource_uid = |index: usize| {
        EntityUid::from_type_name_and_id(
            resource_type.clone(),
            EntityId::new(format!("learn_subject:{index}")),
        )
    };

    let mut entity_list: Vec<Entity> = Vec::new();
    for index in 0..entries {
        entity_list.push(Entity::new(resource_uid(index), HashMap::new(), HashSet::new()).unwrap());
    }
    entity_list.push(
        Entity::new(
            EntityUid::from_type_name_and_id(action_type, EntityId::new(ACTION)),
            HashMap::new(),
            HashSet::new(),
        )
        .unwrap(),
    );
    for card in 1..=cards {
        let set_items: Vec<cedar_policy::RestrictedExpression> = (0..entries)
            .map(|index| cedar_policy::RestrictedExpression::new_entity_uid(resource_uid(index)))
            .collect();
        let mut attrs = HashMap::new();
        attrs.insert(
            "granted".to_owned(),
            cedar_policy::RestrictedExpression::new_set(set_items),
        );
        entity_list.push(
            Entity::new(
                EntityUid::from_type_name_and_id(
                    card_type.clone(),
                    EntityId::new(format!("card{card}")),
                ),
                attrs,
                HashSet::new(),
            )
            .unwrap(),
        );
    }
    let entities = Entities::from_entities(entity_list, None).unwrap();
    let load_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let authorizer = Authorizer::default();
    let action = EntityUid::from_type_name_and_id("Action".parse().unwrap(), EntityId::new(ACTION));
    let mut lat = Vec::with_capacity(queries.len());
    let t1 = Instant::now();
    for q in queries {
        let t = Instant::now();
        let request = Request::new(
            EntityUid::from_type_name_and_id(
                "Card".parse().unwrap(),
                EntityId::new(format!("card{}", q.card)),
            ),
            action.clone(),
            resource_uid(q.resource),
            Context::empty(),
            None,
        )
        .unwrap();
        let response = authorizer.is_authorized(&request, &policies, &entities);
        let allowed = response.decision() == cedar_policy::Decision::Allow;
        lat.push(t.elapsed().as_nanos() as u64);
        assert_eq!(
            allowed, q.allow,
            "cedar 决策错误 card={} r={}",
            q.card, q.resource
        );
    }
    let wall = t1.elapsed();
    let metrics = summarize(load_ms, lat.clone(), wall);
    (metrics, lat)
}

fn cedar_write() -> (f64, f64) {
    use cedar_policy::PolicySet;
    // Cedar v4 无 PolicySet::remove：策略更新走"新 PolicySet 重建"。
    // 计时含 parse（真实写路径文本→策略对象）+ add；标注为重建语义。
    let t0 = Instant::now();
    for index in 0..WRITE_CYCLES {
        let policy: cedar_policy::Policy = CEDAR_WRITE_POLICY
            .replace("card999", &format!("card9{index:03}"))
            .parse()
            .unwrap();
        let mut set = PolicySet::new();
        set.add(policy).unwrap();
    }
    let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
    (total_ms, total_ms * 1000.0 / WRITE_CYCLES as f64)
}

// ===== OPA（sidecar HTTP） =====

const OPA_POLICY: &str = r#"
package astral

default allow := false

allow if {
    resources := data.astral.cards[sprintf("card%d", [input.card])]
    input.resource in resources
}
"#;

fn opa_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tcp_nodelay(true)
        .pool_idle_timeout(Duration::from_secs(75))
        .pool_max_idle_per_host(64)
        .build()
        .unwrap()
}

fn opa_available(rt: &tokio::runtime::Runtime, base: &str) -> bool {
    rt.block_on(async {
        opa_client()
            .get(format!("{base}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    })
}

/// OPA 读决策（sidecar HTTP）。任何 HTTP 请求/状态/解析/决策错误一律返回 Err
/// （fail-closed，绝不 unwrap panic）；调用方负责落盘 error.json 并按文档
/// 退出码 3 中止。
fn run_opa(
    rt: &tokio::runtime::Runtime,
    base: &str,
    cards: i64,
    entries: usize,
    queries: &[Query],
) -> Result<(ReadMetrics, Vec<u64>), String> {
    rt.block_on(async {
        let client = opa_client();
        let healthy = client
            .get(format!("{base}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if !healthy {
            return Err(format!("OPA sidecar 不可达（{base}）：/health 失败"));
        }

        let t0 = Instant::now();
        let resp = client
            .put(format!("{base}/v1/policies/astral"))
            .header("content-type", "text/plain")
            .body(OPA_POLICY)
            .send()
            .await
            .map_err(|e| format!("OPA PUT policy 请求失败：{e}"))?;
        resp.error_for_status()
            .map_err(|e| format!("OPA PUT policy HTTP 状态错误：{e}"))?;
        let mut card_map = HashMap::new();
        for card in 1..=cards {
            card_map.insert(
                format!("card{card}"),
                (0..entries)
                    .map(|index| format!("learn_subject:{index}"))
                    .collect::<Vec<_>>(),
            );
        }
        let resp = client
            .put(format!("{base}/v1/data/astral"))
            .json(&serde_json::json!({ "cards": card_map }))
            .send()
            .await
            .map_err(|e| format!("OPA PUT data 请求失败：{e}"))?;
        resp.error_for_status()
            .map_err(|e| format!("OPA PUT data HTTP 状态错误：{e}"))?;
        let load_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let mut lat = Vec::with_capacity(queries.len());
        let t1 = Instant::now();
        for q in queries {
            let t = Instant::now();
            let resp = client
                .post(format!("{base}/v1/data/astral/allow"))
                .json(&serde_json::json!({
                    "input": {"card": q.card, "resource": format!("learn_subject:{}", q.resource)}
                }))
                .send()
                .await
                .map_err(|e| format!("OPA 查询请求失败 card={} r={}：{e}", q.card, q.resource))?;
            let resp = resp.error_for_status().map_err(|e| {
                format!(
                    "OPA 查询 HTTP 状态错误 card={} r={}：{e}",
                    q.card, q.resource
                )
            })?;
            let body = resp.json::<serde_json::Value>().await.map_err(|e| {
                format!("OPA 查询响应解析失败 card={} r={}：{e}", q.card, q.resource)
            })?;
            let allowed = body
                .get("result")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    format!(
                        "OPA 查询 result 缺失或非布尔值 card={} r={}",
                        q.card, q.resource
                    )
                })?;
            lat.push(t.elapsed().as_nanos() as u64);
            if allowed != q.allow {
                return Err(format!(
                    "OPA 决策错误（期望 allow={} 实得 {allowed}）card={} r={}",
                    q.allow, q.card, q.resource
                ));
            }
        }
        let wall = t1.elapsed();
        let metrics = summarize(load_ms, lat.clone(), wall);
        Ok((metrics, lat))
    })
}

/// OPA 写探针（sidecar 内存 data PUT）。HTTP 错误一律返回 Err，不 unwrap panic。
fn opa_write(rt: &tokio::runtime::Runtime, base: &str) -> Result<(f64, f64), String> {
    rt.block_on(async {
        let client = opa_client();
        let t0 = Instant::now();
        for index in 0..WRITE_CYCLES {
            let payload =
                serde_json::json!({ "grants": [format!("learn_subject:{}", 9000 + index)] });
            let add = client
                .put(format!("{base}/v1/data/astral/write_probe"))
                .json(&payload)
                .send()
                .await;
            if let Err(e) = add.and_then(|r| r.error_for_status()) {
                return Err(format!("OPA write-probe Add 失败（cycle {index}）：{e}"));
            }
            let remove = client
                .put(format!("{base}/v1/data/astral/write_probe"))
                .json(&serde_json::json!({}))
                .send()
                .await;
            if let Err(e) = remove.and_then(|r| r.error_for_status()) {
                return Err(format!("OPA write-probe Remove 失败（cycle {index}）：{e}"));
            }
        }
        let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
        Ok((total_ms, total_ms * 1000.0 / WRITE_CYCLES as f64))
    })
}

// ===== provenance / run meta（run_meta.json；零新增依赖） =====

/// 最小 SHA-256（FIPS 180-4），仅用于 provenance 指纹（被测二进制/自身二进制）；
/// 不引入新依赖（保持 Cargo.lock 不动），标准测试向量见 sha256_tests。
mod sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let bitlen = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bitlen.to_be_bytes());
        for block in msg.as_chunks::<64>().0 {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[4 * i],
                    block[4 * i + 1],
                    block[4 * i + 2],
                    block[4 * i + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }
        let mut out = [0u8; 32];
        for (i, v) in h.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    pub fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod sha256_tests {
    use super::sha256;

    #[test]
    fn fips_vectors() {
        assert_eq!(
            sha256::hex(&sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256::hex(&sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 56 字节 FIPS 向量：padding 恰好跨入第二个块（多块路径）
        assert_eq!(
            sha256::hex(&sha256::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}

#[cfg(test)]
mod mix_tests {
    use super::*;

    #[test]
    fn mix_counts_holds_for_arbitrary_totals() {
        // 任意总数下约束明确：allow+deny==total、deny==total/3（下取整）、
        // default-deny 恒为少数臂；total%3==0 时严格 2:1。
        for total in 1..=97usize {
            let (allow, deny) = mix_counts(total);
            assert_eq!(allow + deny, total, "total={total}");
            assert_eq!(deny, total / 3, "total={total}");
            assert!(allow > deny, "total={total}: default-deny 必须恒为少数臂");
            if total % 3 == 0 {
                assert_eq!(allow, 2 * deny, "total={total}: 必须严格 2:1");
            }
        }
    }

    #[test]
    fn headline_mix_is_exact_two_to_one() {
        let (allow, deny) = mix_counts(QUERIES);
        assert_eq!((allow, deny), (2000, 1000));
        assert_eq!(allow, 2 * deny);
    }

    #[test]
    fn query_mix_satisfies_invariants_for_all_cells() {
        let mut cells = gradient_cells();
        cells.push((1, 1, "edge"));
        for (cards, entries, _) in cells {
            let queries = query_mix(cards, entries);
            assert_eq!(queries.len(), QUERIES);
            assert_mix_invariants(&queries);
            for q in &queries {
                assert!((1..=cards).contains(&q.card), "card 越界");
                if q.allow {
                    assert!(q.resource < entries, "allow 臂必须命中已授资源");
                } else {
                    assert!(
                        (entries..2 * entries).contains(&q.resource),
                        "deny 臂必须越界（走 default-deny）"
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "2:1")]
    fn one_to_one_mix_is_rejected() {
        // 回归防护：旧断言 allow*2 == total 只在 1:1 成立（对 2:1 恒假）。
        // 1:1 mix 必须被新不变式拒绝。
        let bad: Vec<Query> = vec![
            Query {
                card: 1,
                resource: 0,
                allow: true,
            },
            Query {
                card: 1,
                resource: 1,
                allow: true,
            },
            Query {
                card: 1,
                resource: 0,
                allow: false,
            },
            Query {
                card: 1,
                resource: 1,
                allow: false,
            },
        ];
        assert_mix_invariants(&bad);
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;

    #[test]
    fn opa_result_requires_a_boolean() {
        for value in [
            serde_json::json!({"result": true}),
            serde_json::json!({"result": false}),
        ] {
            assert!(value
                .get("result")
                .and_then(serde_json::Value::as_bool)
                .is_some());
        }
        for value in [
            serde_json::json!({}),
            serde_json::json!({"result": null}),
            serde_json::json!({"result": "false"}),
            serde_json::json!({"result": 0}),
        ] {
            assert_eq!(
                value.get("result").and_then(serde_json::Value::as_bool),
                None
            );
        }
    }

    #[test]
    fn sanitize_slug_rules() {
        assert_eq!(sanitize_slug("run-1_ok.v2").as_deref(), Some("run-1_ok.v2"));
        assert_eq!(sanitize_slug("a/b\\c:d*e").as_deref(), Some("a_b_c_d_e"));
        assert_eq!(sanitize_slug(""), None);
        assert_eq!(sanitize_slug("."), None);
        assert_eq!(sanitize_slug(".."), None);
    }

    #[test]
    fn atomic_write_replaces_and_cleans_tmp() {
        let dir = std::env::temp_dir().join(format!(
            "engine-comparison-atomic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe.json");
        let ps = path.to_str().unwrap();
        atomic_write(ps, "v1").unwrap();
        assert_eq!(std::fs::read_to_string(ps).unwrap(), "v1");
        // 覆盖写（rename 原子替换既有目标）且不残留 .tmp
        atomic_write(ps, "v2-longer-content").unwrap();
        assert_eq!(std::fs::read_to_string(ps).unwrap(), "v2-longer-content");
        assert!(!dir.join("probe.json.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

fn utc_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    // civil_from_days（公历换算），避免引入 chrono
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn cpu_desc() -> serde_json::Value {
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let model = std::env::var("PROCESSOR_IDENTIFIER")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split_once(':'))
                    .map(|(_, v)| v.trim().to_owned())
            })
        });
    serde_json::json!({ "logical_cpus": logical, "model": model })
}

fn git_info() -> serde_json::Value {
    // cargo run 的 cwd 是 crate 根；crate 位于仓库子目录，向上找 .git
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let mut dir = Some(cwd.as_path());
    while let Some(d) = dir {
        if d.join(".git").exists() {
            let rev = std::process::Command::new("git")
                .args(["-C"])
                .arg(d)
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
            let dirty = std::process::Command::new("git")
                .args(["-C"])
                .arg(d)
                .args(["status", "--porcelain"])
                .output()
                .ok()
                .map(|o| !o.stdout.is_empty());
            return serde_json::json!({ "rev": rev, "dirty": dirty });
        }
        dir = d.parent();
    }
    serde_json::json!({ "rev": null, "dirty": null })
}

/// 从 Cargo.lock 提取依赖锁定版本（cwd=crate 根时可用；否则 None，如实缺省）。
fn locked_version(name: &str) -> Option<String> {
    let lock = std::fs::read_to_string("Cargo.lock").ok()?;
    let mut matched = false;
    for line in lock.lines() {
        let t = line.trim();
        if t.starts_with("[[package]]") {
            matched = false;
        } else if t == format!("name = \"{name}\"") {
            matched = true;
        } else if matched && t.starts_with("version = ") {
            return Some(
                t.trim_start_matches("version = ")
                    .trim_matches('"')
                    .to_owned(),
            );
        }
    }
    None
}

fn crate_versions() -> serde_json::Value {
    serde_json::json!({
        "engine_comparison": env!("CARGO_PKG_VERSION"),
        "policy_engine": "path ../../policy-engine（版本随仓库 git rev）",
        "astral_types": "path ../../astral-types（版本随仓库 git rev）",
        "casbin": locked_version("casbin"),
        "cedar-policy": locked_version("cedar-policy"),
        "reqwest": locked_version("reqwest"),
        "tokio": locked_version("tokio"),
        "serde_json": locked_version("serde_json"),
    })
}

fn binary_info() -> serde_json::Value {
    match std::env::current_exe() {
        Ok(path) => {
            let size = std::fs::metadata(&path).ok().map(|m| m.len());
            let sha = std::fs::read(&path)
                .ok()
                .map(|bytes| sha256::hex(&sha256::digest(&bytes)));
            serde_json::json!({
                "path": path.to_string_lossy(),
                "size_bytes": size,
                "sha256": sha,
            })
        }
        Err(_) => serde_json::json!({ "path": null, "size_bytes": null, "sha256": null }),
    }
}

/// OPA 版本 tag（尽力而为）：OPA 无标准版本 REST，从 /metrics 的
/// opa_build_info{version="..."} 提取；取不到记 null（不伪造）。
fn opa_version(rt: &tokio::runtime::Runtime, base: &str) -> Option<String> {
    rt.block_on(async {
        let body = opa_client()
            .get(format!("{base}/metrics"))
            .send()
            .await
            .ok()?
            .text()
            .await
            .ok()?;
        let idx = body.find("opa_build_info")?;
        let seg = &body[idx..(idx + 400).min(body.len())];
        let key = "version=\"";
        let vidx = seg.find(key)? + key.len();
        let end = seg[vidx..].find('"')? + vidx;
        Some(seg[vidx..end].to_owned())
    })
}

// ===== 实验编排与输出 =====

#[derive(Debug)]
struct Aggregated {
    #[allow(dead_code)]
    engine: &'static str,
    #[allow(dead_code)]
    cards: i64,
    #[allow(dead_code)]
    entries: usize,
    load: (f64, f64),
    p50: (f64, f64),
    p99: (f64, f64),
    qps: (f64, f64),
}

fn aggregate(engine: &'static str, cards: i64, entries: usize, runs: &[ReadMetrics]) -> Aggregated {
    Aggregated {
        engine,
        cards,
        entries,
        load: (
            mean(&runs.iter().map(|r| r.load_ms).collect::<Vec<_>>()),
            stddev(&runs.iter().map(|r| r.load_ms).collect::<Vec<_>>()),
        ),
        p50: (
            mean(&runs.iter().map(|r| r.p50_us).collect::<Vec<_>>()),
            stddev(&runs.iter().map(|r| r.p50_us).collect::<Vec<_>>()),
        ),
        p99: (
            mean(&runs.iter().map(|r| r.p99_us).collect::<Vec<_>>()),
            stddev(&runs.iter().map(|r| r.p99_us).collect::<Vec<_>>()),
        ),
        qps: (
            mean(&runs.iter().map(|r| r.qps).collect::<Vec<_>>()),
            stddev(&runs.iter().map(|r| r.qps).collect::<Vec<_>>()),
        ),
    }
}

fn gradient_cells() -> Vec<(i64, usize, &'static str)> {
    vec![
        (10, 81, "card-axis"),
        (50, 81, "headline"),
        (200, 81, "card-axis"),
        (50, 405, "complexity-axis"),
        (50, 810, "complexity-axis"),
    ]
}

/// 引擎名 → 文件名安全 slug（raw 原始样本文件名用）。
fn engine_slug(engine: &str) -> &'static str {
    match engine {
        "AstralLight(Rust)" => "astral",
        "Casbin(rust)" => "casbin",
        "Cedar(rust)" => "cedar",
        "OPA(sidecar)" => "opa",
        _ => "unknown",
    }
}

fn summary_csv(rows: &[String]) -> String {
    format!(
        "scenario,cards,entries,engine,load_ms,p50_us,p99_us,qps\n{}",
        rows.join("\n")
    )
}

/// 原子写：同目录临时文件（run-scoped：仅本 run 目录内 `<name>.tmp`），写入、
/// fsync 后 rename 覆盖。Unix rename 与 Windows MoveFileEx(REPLACE_EXISTING)
/// 均为同卷原子替换；失败时清理临时文件。目录 fsync 无可移植 std 接口，崩溃
/// 极端情况可能丢最后一次 rename——对本地 benchmark 证据足够。
fn atomic_write(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let p = std::path::Path::new(path);
    let file_name = p.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = p.with_file_name(tmp_name);
    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, p)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// run-id → 文件名安全目录名：仅保留 ASCII 字母数字与 '-' '_' '.'，其余折叠为
/// '_'；空串、"."、".." 返回 None（调用方 fail-closed）。仅用于派生目录名；
/// run_meta.json 中的 run_id 保留原值。
fn sanitize_slug(raw: &str) -> Option<String> {
    let slug: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if slug.is_empty() || slug == "." || slug == ".." {
        None
    } else {
        Some(slug.chars().take(128).collect())
    }
}

/// 本地 I/O 失败（文档化退出码 4）：证据无法落盘时 fail-closed，绝不静默继续。
fn fail_io(context: &str, err: &std::io::Error) -> ! {
    eprintln!("本地 I/O 失败（exit 4）：{context}：{err}");
    std::process::exit(4);
}

/// 运行中途失败（文档化退出码，OPA=3）落盘后退出：先原子写入失败版 run_meta
/// （completed=false + failure 详情）、error.json、已采集的完整 CSV 行与 partial
/// summary，再退出——绝不 unwrap panic、绝不静默丢既有数据。
fn fail_run(
    out_dir: &str,
    run_meta: &mut serde_json::Value,
    report: &str,
    summary_rows: &[String],
    stage: &str,
    detail: &str,
    code: i32,
) -> ! {
    run_meta["completed"] = serde_json::json!(false);
    run_meta["failed"] = serde_json::json!(true);
    run_meta["failure"] = serde_json::json!({
        "stage": stage,
        "detail": detail,
        "exit_code": code,
        "at_utc": utc_now_iso(),
    });
    if let Ok(pretty) = serde_json::to_string_pretty(run_meta) {
        let _ = atomic_write(&format!("{out_dir}/run_meta.json"), &pretty);
    }
    let err_json = serde_json::to_string_pretty(&serde_json::json!({
        "stage": stage,
        "detail": detail,
        "exit_code": code,
        "at_utc": utc_now_iso(),
    }))
    .unwrap_or_else(|_| format!("{{\"detail\": {detail:?}}}"));
    let _ = atomic_write(&format!("{out_dir}/error.json"), &err_json);
    let _ = atomic_write(&format!("{out_dir}/comparison_report.csv"), report);
    if !summary_rows.is_empty() {
        let _ = atomic_write(
            &format!("{out_dir}/summary.csv"),
            &summary_csv(summary_rows),
        );
    }
    eprintln!(
        "中止（exit {code}）：{stage} —— {detail}；已采集证据已原子 checkpoint 到 \
         {out_dir}/（error.json 含错误详情，run_meta.json 标记 failed）"
    );
    std::process::exit(code);
}

fn main() {
    // ---- CLI 解析（fail-closed）：--repeats 解析失败/未知参数立即 exit 1，----
    // ---- 绝不静默回退默认值（防编排器拼写错误产出无标注的默认配置结果）。----
    let mut repeats_opt: Option<usize> = None;
    let mut quick = false;
    let mut allow_opa_skip = false;
    let mut opa_base = "http://127.0.0.1:8181".to_owned();
    let mut run_id_flag: Option<String> = None;
    let mut output_dir_flag: Option<String> = None;
    for arg in std::env::args().skip(1) {
        if let Some(v) = arg.strip_prefix("--repeats=") {
            match v.parse::<usize>() {
                Ok(n) if n >= 1 => repeats_opt = Some(n),
                _ => {
                    eprintln!(
                        "错误：--repeats 需要 ≥1 的整数，收到 {v:?}；拒绝静默回退默认值（exit 1）。"
                    );
                    std::process::exit(1);
                }
            }
        } else if arg == "--quick" {
            quick = true;
        } else if arg == "--allow-opa-skip" {
            allow_opa_skip = true;
        } else if let Some(v) = arg.strip_prefix("--opa=") {
            opa_base = v.to_owned();
        } else if let Some(v) = arg.strip_prefix("--run-id=") {
            run_id_flag = Some(v.to_owned());
        } else if let Some(v) = arg.strip_prefix("--output-dir=") {
            output_dir_flag = Some(v.to_owned());
        } else {
            eprintln!(
                "错误：未知参数 {arg:?}（exit 1）。支持：--repeats=<n≥1> --quick \
                 --allow-opa-skip --opa=<base> --run-id=<id> --output-dir=<dir>"
            );
            std::process::exit(1);
        }
    }
    let mut repeats = repeats_opt.unwrap_or(DEFAULT_REPEATS);
    if quick {
        repeats = 1;
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // ---- 输出目录与 run-id（编排器可显式传入；一律不覆盖已存在目录）----
    // 优先级：--output-dir > --run-id（→ results/<slug>）> 默认 results/comparison-<ts>。
    // 环境变量 RUN_ID 仅作为 run-id 元数据回退（保持既有语义，不派生目录）。
    let out_dir = match (&output_dir_flag, &run_id_flag) {
        (Some(dir), _) => dir.clone(),
        (None, Some(id)) => match sanitize_slug(id) {
            Some(slug) => format!("results/{slug}"),
            None => {
                eprintln!("错误：--run-id 无法归一为安全目录名：{id:?}（exit 1）");
                std::process::exit(1);
            }
        },
        (None, None) => {
            let mut dir = format!("results/comparison-{timestamp}");
            let mut n = 2;
            while std::path::Path::new(&dir).exists() {
                dir = format!("results/comparison-{timestamp}-{n}");
                n += 1;
            }
            dir
        }
    };
    if std::path::Path::new(&out_dir).exists() {
        eprintln!(
            "错误：输出目录已存在，拒绝覆盖：{out_dir}（exit 1）。\
             请换用 --output-dir/--run-id 或先清理旧目录。"
        );
        std::process::exit(1);
    }
    // ---- OPA 可达性门（审计 D）：OPA 是必需引擎，不可达非零退出；----
    // ---- 仅显式 --allow-opa-skip 允许缺引擎继续（结果如实标记 skipped）。----
    // ---- 门位于目录创建之前：exit 2 不留下任何空结果目录。----
    let opa_reachable = opa_available(&rt, &opa_base);
    if !opa_reachable && !allow_opa_skip {
        eprintln!(
            "OPA sidecar 不可达（{opa_base}）：OPA 为必需引擎，拒绝产出缺引擎结果。\
             请启动 OPA 后重跑；确需部分结果请显式传 --allow-opa-skip。"
        );
        std::process::exit(2);
    }

    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| fail_io(&format!("创建输出目录 {out_dir}"), &e));
    let run_id = run_id_flag
        .clone()
        .or_else(|| std::env::var("RUN_ID").ok())
        .unwrap_or_else(|| format!("comparison-{timestamp}"));

    // 查询配比（审计 D）：allow:default-deny = 2:1 数学不变式断言 + run_meta
    // 记录 + mix_tests 单测。每个梯度单元格在采集前同样断言（见主循环）。
    let mix_probe = query_mix(50, 81);
    assert_mix_invariants(&mix_probe);
    let mix_allow = mix_probe.iter().filter(|q| q.allow).count();
    let mix_deny = mix_probe.len() - mix_allow;

    let write_semantics = "纯内存写开销：Astral=进程内增量编译+CAS revision；Casbin/Cedar=进程内策略对象；OPA=sidecar 内存 data PUT。不是 durable publication（无 outbox/DB/MQ 落盘写），不得作为持久化写延迟引用";
    let mut run_meta = serde_json::json!({
        "run_id": run_id,
        "created_at_utc": utc_now_iso(),
        "output_dir": out_dir,
        "host": host_name(),
        "os": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        "cpu": cpu_desc(),
        "git": git_info(),
        "binary": binary_info(),
        "crate_versions": crate_versions(),
        "opa": {
            "base": opa_base,
            "required": !allow_opa_skip,
            "reachable": opa_reachable,
            "version": if opa_reachable { opa_version(&rt, &opa_base) } else { None },
        },
        "queries_mix": {
            "total": mix_probe.len(),
            "allow": mix_allow,
            "default_deny": mix_deny,
            "ratio": "2:1 ALLOW:default-DENY",
            "exact_2_1": mix_probe.len().is_multiple_of(3),
            "rule": "deny = total/3（下取整），allow = total - deny；total%3==0 时严格 2:1，任意总数下 default-deny 恒为少数臂",
            "note": "deny 臂=越界资源（entries 起偏移），走 default-deny 路径",
        },
        "repeats": repeats,
        "quick": quick,
        "write_overhead_semantics": write_semantics,
        "completed": false,
        "failed": false,
        "output_files": [],
    });
    atomic_write(
        &format!("{out_dir}/run_meta.json"),
        &serde_json::to_string_pretty(&run_meta).unwrap(),
    )
    .unwrap_or_else(|e| fail_io("写入 run_meta.json", &e));
    println!(
        "run_meta: run_id={} git={} binary_sha256={} opa(base={}, reachable={})",
        run_id,
        run_meta["git"]["rev"].as_str().unwrap_or("unknown"),
        run_meta["binary"]["sha256"].as_str().unwrap_or("unknown"),
        opa_base,
        opa_reachable
    );
    // 机器可读输出：编排器/manifest 精确引用输出路径（失败中止前也已输出）。
    println!("RESULT_DIR {out_dir}");

    let report_path = format!("{out_dir}/comparison_report.csv");
    let mut report =
        String::from("scenario,cards,entries,engine,repeat,load_ms,mean_us,p50_us,p99_us,qps\n");
    let mut summary_rows: Vec<String> = Vec::new();
    let mut tex_rows: Vec<String> = Vec::new();
    std::fs::create_dir_all(format!("{out_dir}/raw"))
        .unwrap_or_else(|e| fail_io("创建 raw 原始样本目录", &e));

    let cells = if quick {
        vec![(50, 81, "headline")]
    } else {
        gradient_cells()
    };

    for (cards, entries, scenario) in &cells {
        let queries = query_mix(*cards, *entries);
        assert_mix_invariants(&queries);
        for engine in [
            "AstralLight(Rust)",
            "Casbin(rust)",
            "Cedar(rust)",
            "OPA(sidecar)",
        ] {
            let mut runs: Vec<ReadMetrics> = Vec::new();
            for repeat in 0..repeats {
                let (metrics, raw) = match engine {
                    "AstralLight(Rust)" => run_astral(*cards, *entries, &queries),
                    "Casbin(rust)" => run_casbin(&rt, *cards, *entries, &queries),
                    "Cedar(rust)" => run_cedar(*cards, *entries, &queries),
                    _ => {
                        if !opa_reachable {
                            // 仅显式 --allow-opa-skip 时到达（否则启动已退出）
                            break;
                        }
                        match run_opa(&rt, &opa_base, *cards, *entries, &queries) {
                            Ok(pair) => pair,
                            Err(detail) => fail_run(
                                &out_dir,
                                &mut run_meta,
                                &report,
                                &summary_rows,
                                "read-phase OPA(sidecar)",
                                &detail,
                                3,
                            ),
                        }
                    }
                };
                // 每 repeat 采集后立即原子 checkpoint：原始纳秒样本 + 完整 CSV 行。
                // 之后任何中途失败（含 OPA 失联）只损失进行中的样本，既有数据已在盘。
                let raw_path = format!(
                    "{out_dir}/raw/c{cards}_e{entries}_{scenario}_{}_r{repeat}.csv",
                    engine_slug(engine)
                );
                let mut raw_csv = String::with_capacity(16 + raw.len() * 8);
                raw_csv.push_str("latency_ns\n");
                for v in &raw {
                    raw_csv.push_str(&v.to_string());
                    raw_csv.push('\n');
                }
                atomic_write(&raw_path, &raw_csv)
                    .unwrap_or_else(|e| fail_io(&format!("checkpoint {raw_path}"), &e));
                report.push_str(&format!(
                    "{scenario},{cards},{entries},{engine},{repeat},{:.3},{:.3},{:.3},{:.3},{:.1}\n",
                    metrics.load_ms, metrics.mean_us, metrics.p50_us, metrics.p99_us, metrics.qps
                ));
                atomic_write(&report_path, &report)
                    .unwrap_or_else(|e| fail_io("checkpoint comparison_report.csv", &e));
                runs.push(metrics);
            }
            if runs.is_empty() {
                if engine == "OPA(sidecar)" && !opa_reachable {
                    summary_rows.push(format!(
                        "{scenario},{cards},{entries},{engine},skipped,--allow-opa-skip"
                    ));
                }
                continue;
            }
            let a = aggregate(engine, *cards, *entries, &runs);
            summary_rows.push(format!(
                "{scenario},{cards},{entries},{engine},{:.1}±{:.1},{:.3}±{:.3},{:.3}±{:.3},{:.0}±{:.0}",
                a.load.0, a.load.1, a.p50.0, a.p50.1, a.p99.0, a.p99.1, a.qps.0, a.qps.1
            ));
            if *scenario == "headline" {
                tex_rows.push(format!(
                    "{} & {:.3} & {:.3} & {:.0} & {:.1} \\\\",
                    engine, a.p50.0, a.p99.0, a.qps.0, a.load.0
                ));
            }
            println!(
                "[done] {scenario} {engine} cards={cards} entries={entries} p50={:.2}µs qps={:.0}",
                a.p50.0, a.qps.0
            );
        }
    }

    // 写开销（headline 规模；OPA 不可达且已显式 --allow-opa-skip 时标记 skipped；
    // OPA write-probe 失败不 panic：如实标记 failed，其余产物照常落盘后 exit 3）
    let mut opa_write_failure: Option<String> = None;
    let base = astral_build(50, 81);
    let (a_total, a_per) = astral_write(&base);
    let (c_total, c_per) = casbin_write(&rt);
    let (cd_total, cd_per) = cedar_write();
    let (o_total, o_per) = if opa_reachable {
        match opa_write(&rt, &opa_base) {
            Ok(v) => v,
            Err(detail) => {
                opa_write_failure = Some(detail);
                (0.0, 0.0)
            }
        }
    } else {
        (0.0, 0.0)
    };
    let opa_row = if !opa_reachable {
        "OPA(sidecar),skipped,unreachable --allow-opa-skip,unreachable\n".to_owned()
    } else if let Some(d) = &opa_write_failure {
        format!("OPA(sidecar),failed,{},\n", d.replace(',', ";"))
    } else {
        format!("OPA(sidecar),{WRITE_CYCLES},{o_total:.3},{o_per:.1}\n")
    };
    let write_csv = format!(
        "engine,cycles,total_ms,per_op_us\nAstralLight(Rust),{WRITE_CYCLES},{a_total:.3},{a_per:.1}\nCasbin(rust),{WRITE_CYCLES},{c_total:.3},{c_per:.1}\nCedar(rust),{WRITE_CYCLES},{cd_total:.3},{cd_per:.1}\n{opa_row}"
    );

    atomic_write(&report_path, &report).unwrap_or_else(|e| fail_io("写 comparison_report.csv", &e));
    atomic_write(
        &format!("{out_dir}/summary.csv"),
        &summary_csv(&summary_rows),
    )
    .unwrap_or_else(|e| fail_io("写 summary.csv", &e));
    atomic_write(&format!("{out_dir}/write_overhead.csv"), &write_csv)
        .unwrap_or_else(|e| fail_io("写 write_overhead.csv", &e));
    atomic_write(
        &format!("{out_dir}/comparison_table.tex"),
        &format!(
            "\\begin{{tabular}}{{lrrrr}}\n\\toprule\nEngine & P50(µs) & P99(µs) & QPS & Load(ms) \\\\\n\\midrule\n{}\n\\bottomrule\n\\end{{tabular}}\n",
            tex_rows.join("\n")
        ),
    )
    .unwrap_or_else(|e| fail_io("写 comparison_table.tex", &e));
    // 终版 run_meta：completed/failed + 产物清单（目录自包含，整目录复制即可归档）
    if let Some(d) = &opa_write_failure {
        run_meta["completed"] = serde_json::json!(false);
        run_meta["failed"] = serde_json::json!(true);
        run_meta["failure"] = serde_json::json!({
            "stage": "write-overhead OPA(sidecar)",
            "detail": d,
            "exit_code": 3,
            "at_utc": utc_now_iso(),
        });
        let _ = atomic_write(
            &format!("{out_dir}/error.json"),
            &serde_json::to_string_pretty(&serde_json::json!({
                "stage": "write-overhead OPA(sidecar)",
                "detail": d,
                "exit_code": 3,
                "at_utc": utc_now_iso(),
            }))
            .unwrap_or_else(|_| format!("{{\"detail\": {d:?}}}")),
        );
        eprintln!("OPA write-probe 失败（exit 3）：{d}；其余产物已落盘 {out_dir}/");
    } else {
        run_meta["completed"] = serde_json::json!(true);
        run_meta["finished_at_utc"] = serde_json::json!(utc_now_iso());
    }
    run_meta["output_files"] = serde_json::json!([
        "run_meta.json",
        "comparison_report.csv",
        "summary.csv",
        "write_overhead.csv",
        "comparison_table.tex",
        "raw/（每 cell×engine×repeat 一个 latency_ns 原始样本 CSV）",
    ]);
    atomic_write(
        &format!("{out_dir}/run_meta.json"),
        &serde_json::to_string_pretty(&run_meta).unwrap(),
    )
    .unwrap_or_else(|e| fail_io("写终版 run_meta.json", &e));
    println!(
        "结果目录：{out_dir}/（含 run_meta.json；结果目录保持 gitignore，整目录复制即可归档）"
    );
    if opa_write_failure.is_some() {
        std::process::exit(3);
    }
}
