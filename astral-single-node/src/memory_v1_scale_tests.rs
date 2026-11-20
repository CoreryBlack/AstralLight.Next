//! memory—v1: Validate independently installed shard fixtures and profile
//! process-local requests and context loads. No MySQL, listener or shard routing.

use std::collections::BTreeSet;
use std::time::Instant;

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus, RuleSetVersionRow,
    TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_digest::MAX_ROOT_DIGEST_KEYS;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::{
    install_isolated_test_root_with_phases, install_process_root, ManagementMutationV2,
    MutationPrecondition,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};
use policy_engine::PolicyEngine;
use sha2::{Digest, Sha256};

mod profile;

// ─── Deterministic RNG (xorshift over a fixed seed; no external crates) ───

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

// ─── Scale parameters ───

const TOTAL_USERS: usize = 500_000;
const USERS_PER_SHARD: usize = 600;
const SHARDS: usize = TOTAL_USERS.div_ceil(USERS_PER_SHARD); // 834
const GLOBAL_RULE_SETS: usize = 40;
const FAMILY_RULE_SETS_PER: usize = 6;
const FAMILY_COUNT: usize = 10;
const TOTAL_RULE_SETS: usize = GLOBAL_RULE_SETS + FAMILY_COUNT * FAMILY_RULE_SETS_PER;

const RESOURCES: [&str; 12] = [
    "document",
    "workspace",
    "dataset",
    "pipeline",
    "dashboard",
    "report",
    "connector",
    "template",
    "quota",
    "secret",
    "audit_log",
    "billing",
];

const ACTIONS: [&str; 3] = ["read", "write", "approve"];

fn id(kind: u8, value: u64) -> [u8; 16] {
    let mut result = [kind; 16];
    result[8..].copy_from_slice(&value.to_be_bytes());
    result
}

fn wide_id(kind: u8, shard: usize, index: usize) -> [u8; 16] {
    let mut result = [kind; 16];
    result[2..6].copy_from_slice(&(shard as u32).to_be_bytes());
    result[8..].copy_from_slice(&(index as u64).to_be_bytes());
    result
}

fn content_hash(rule_set: u64, content: &[u8]) -> RuleSetVersionRow {
    let version_bytes = vec![1u8];
    let timestamp = vec![1u8];
    let hash_input = canonical_version_bytes(&version_bytes, content, &timestamp);
    RuleSetVersionRow {
        rule_set_id: id(5, rule_set),
        version_bytes,
        content_bytes: content.to_vec(),
        timestamp_bytes: timestamp,
        hash_input_bytes: hash_input.clone(),
        hash_bytes: Sha256::digest(&hash_input).to_vec(),
    }
}

// ─── Rule-set pool: three layers with deterministic overlap ───

struct RuleSetPool {
    // (rule_set_id, content) for every pool member.
    entries: Vec<(u64, Vec<u8>)>,
}

impl RuleSetPool {
    // Global: shared by every shard. Family: shared inside one family.
    // Private: unique per shard. The id space is disjoint by construction.
    fn build() -> Self {
        let mut entries = Vec::with_capacity(TOTAL_RULE_SETS);
        for index in 0..GLOBAL_RULE_SETS {
            entries.push((
                id_of_layer(Layer::Global, index),
                render_rules(Layer::Global, index, 0),
            ));
        }
        for family in 0..FAMILY_COUNT {
            for index in 0..FAMILY_RULE_SETS_PER {
                entries.push((
                    id_of_layer(Layer::Family, family * FAMILY_RULE_SETS_PER + index),
                    render_rules(Layer::Family, index, family),
                ));
            }
        }
        Self { entries }
    }

    fn global(&self) -> impl Iterator<Item = &(u64, Vec<u8>)> {
        self.entries.iter().take(GLOBAL_RULE_SETS)
    }

    fn family(&self, family: usize) -> impl Iterator<Item = &(u64, Vec<u8>)> {
        let start = GLOBAL_RULE_SETS + family * FAMILY_RULE_SETS_PER;
        self.entries.iter().skip(start).take(FAMILY_RULE_SETS_PER)
    }
}

#[derive(Clone, Copy)]
enum Layer {
    Global,
    Family,
    Private,
}

fn id_of_layer(layer: Layer, index: usize) -> u64 {
    let tag = match layer {
        Layer::Global => 0x50_00_00_00,
        Layer::Family => 0x50_10_00_00,
        Layer::Private => 0x50_20_00_00,
    };
    (tag | (index as u64 & 0xFF_FF)) << 8 | 0x5D
}

fn render_rules(layer: Layer, index: usize, family: usize) -> Vec<u8> {
    // Deterministic per (layer, index, family): a random-looking but fixed
    // rule body inside the frozen grammar. 70% ALLOW / 30% DENY.
    let mut rng = Rng::new(
        0x00D5_0000
            ^ match layer {
                Layer::Global => 1,
                Layer::Family => 2,
                Layer::Private => 3,
            }
            ^ ((index as u64) << 8)
            ^ ((family as u64) << 16),
    );
    let rule_count = 1 + rng.below(8);
    let mut json = String::from(r#"{"rules":["#);
    for rule in 0..rule_count {
        if rule > 0 {
            json.push(',');
        }
        let resource = RESOURCES[rng.below(RESOURCES.len())];
        let action = ACTIONS[rng.below(ACTIONS.len())];
        let effect = if rng.below(10) < 7 { "ALLOW" } else { "DENY" };
        let scope = match rng.below(4) {
            0 => r#","ownerScope":"all""#,
            1 => r#","tenantScope":"self+descendants""#,
            2 => r#","ownerScope":"all","tenantScope":"self+descendants""#,
            _ => "",
        };
        json.push_str(&format!(
            r#"{{"ruleId":"R{rule}","resource":"{resource}","action":"{action}","effect":"{effect}"{scope}}}"#
        ));
    }
    json.push_str("]}");
    json.into_bytes()
}

// ─── Shard fixture generator ───

// memory—v1: (user_id, identity_card_id, card_id, tenant_id) per principal.
type PrincipalId = ([u8; 16], [u8; 16], [u8; 16], [u8; 16]);

struct ShardFixture {
    rows: CandidateRows,
    selections: Vec<CurrentSelection>,
    // Per user, generation order.
    principals: Vec<PrincipalId>,
    // (layer, rule_set_id) for every set the shard chose, in generation order.
    rule_set_layers: Vec<(Layer, u64)>,
}

fn shard_fixture(shard: usize) -> ShardFixture {
    let pool = RuleSetPool::build();
    let family = shard % FAMILY_COUNT;
    let mut rng = Rng::new(0x50_00_5C_A1 ^ ((shard as u64) << 24));
    let mut rows = CandidateRows::default();
    let mut selections = Vec::new();
    let mut principals = Vec::new();

    // Tenants: one root tenant per shard plus one child; family shares the
    // root tenant id space so tenant-family rule sets stay consistent.
    let root_tenant = id(3, family as u64);
    let child_tenant = wide_id(4, shard, 0);
    rows.tenants.push(TenantRow {
        tenant_id: root_tenant,
        parent_tenant_id: None,
    });
    rows.tenants.push(TenantRow {
        tenant_id: child_tenant,
        parent_tenant_id: Some(root_tenant),
    });

    // Rule sets: 2 global + 1 family + 1 private (4 sets per shard keeps the
    // key budget for 600 users), with change confirmations and selections.
    let mut chosen: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut change_confirmation_rows = Vec::new();
    let mut rule_set_layers = Vec::new();
    // memory—v1: The global layer is shared by design, so the picks use a
    // deterministic modular coverage pattern instead of the shard rng (whose
    // first outputs cluster when the seeds differ only in high bits): shard k
    // takes {k % 40, (k+13) % 40}, so the first 40 shards cover the whole
    // global layer and later shards re-share it heavily.
    chosen.push({
        let (set_id, content) = pool.global().nth(shard % GLOBAL_RULE_SETS).unwrap();
        (*set_id, content.clone())
    });
    chosen.push({
        let (set_id, content) = pool.global().nth((shard + 13) % GLOBAL_RULE_SETS).unwrap();
        (*set_id, content.clone())
    });
    // The family layer repeats inside its family: member j of the family
    // (shard = family + 10*j) takes family set j % 6, covering all six after
    // six members of the same family.
    chosen.push({
        let member = shard / FAMILY_COUNT;
        let (set_id, content) = pool
            .family(family)
            .nth(member % FAMILY_RULE_SETS_PER)
            .unwrap();
        (*set_id, content.clone())
    });
    let private_id = id_of_layer(Layer::Private, shard);
    let private_content = {
        // A private body unique to this shard.
        let mut rng = Rng::new(0x00D5_0003 ^ ((shard as u64) << 20));
        let rule_count = 1 + rng.below(8);
        let mut json = String::from(r#"{"rules":["#);
        for rule in 0..rule_count {
            if rule > 0 {
                json.push(',');
            }
            let resource = RESOURCES[rng.below(RESOURCES.len())];
            let action = ACTIONS[rng.below(ACTIONS.len())];
            let effect = if rng.below(10) < 7 { "ALLOW" } else { "DENY" };
            json.push_str(&format!(
                r#"{{"ruleId":"P{rule}","resource":"{resource}","action":"{action}","effect":"{effect}"}}"#
            ));
        }
        json.push_str("]}");
        json.into_bytes()
    };
    chosen.push((private_id, private_content));
    for (position, (rule_set_id, content)) in chosen.iter().enumerate() {
        let rule_set_id = *rule_set_id;
        let layer = match position {
            0 | 1 => Layer::Global,
            2 => Layer::Family,
            _ => Layer::Private,
        };
        rule_set_layers.push((layer, rule_set_id));
        rows.rule_sets.push(RuleSetRow {
            rule_set_id: id(5, rule_set_id),
            owner_tenant_id: root_tenant,
            current_version_bytes: vec![1],
            status: RuleSetStatus::Active,
        });
        rows.rule_set_versions
            .push(content_hash(rule_set_id, content));
        // memory—v1: The confirmer must close against an existing user; the
        // shard's first principal is generated in the user block below, so
        // defer this row until after that block.
        change_confirmation_rows.push(RuleSetChangeConfirmationRow {
            confirmation_id: wide_id(9, shard, position),
            rule_set_id: id(5, rule_set_id),
            version_bytes: vec![1],
            confirmer_user_id: wide_id(1, shard, 0),
            affected_scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
        selections.push(CurrentSelection {
            rule_set_id: id(5, rule_set_id),
            version_bytes: vec![1],
        });
    }

    // Users: 600 per shard, one identity and one card each; 25% of cards
    // bind onto the child tenant instead of the root (the rule sets stay
    // root-owned, so child-tenant cards must bind a child-owned set — those
    // users simply keep root-tenant cards and the child tenant hosts only
    // extra cards for cross-tenant denial testing).
    for user_index in 0..USERS_PER_SHARD {
        let user_id = wide_id(1, shard, user_index);
        let identity_id = wide_id(2, shard, user_index);
        let card_id = wide_id(6, shard, user_index);
        rows.users.push(UserRow { user_id });
        rows.identity_cards.push(IdentityCardRow {
            identity_card_id: identity_id,
            user_id,
        });
        rows.user_cards.push(UserCardRow {
            user_card_id: card_id,
            user_id,
            tenant_id: root_tenant,
            status: UserCardStatus::Active,
        });
        // One binding per card onto a random chosen rule set, confirmed.
        let binding_id = wide_id(7, shard, user_index);
        rows.bindings.push(BindingRow {
            binding_id,
            user_card_id: card_id,
            rule_set_id: id(5, chosen[rng.below(chosen.len())].0),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::SelfUser,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        });
        rows.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: wide_id(8, shard, user_index),
            binding_id,
            rule_set_id: rows.bindings.last().unwrap().rule_set_id,
            version_bytes: vec![1],
            confirmer_user_id: wide_id(1, shard, 0),
            scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
        principals.push((user_id, identity_id, card_id, root_tenant));
    }
    rows.rule_set_change_confirmations
        .extend(change_confirmation_rows);

    ShardFixture {
        rows,
        selections,
        principals,
        rule_set_layers,
    }
}

// ─── Reference oracle: independently decide a request from the fixture rows ───

/// The expected outcome class computed straight from the fixture tables.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expected {
    Allow,
    Deny,
    Pending,
}

// The oracle walks the fixture rows directly (no HAMT): find the card's
// active confirmed bindings, match the request against the selected version
// content, apply the strictest owner/tenant scope for object-bearing reads.
fn oracle_decide(
    fixture: &ShardFixture,
    card_id: [u8; 16],
    resource: &str,
    action: &str,
    target_owner: Option<&[u8; 16]>,
    target_tenant: Option<&[u8; 16]>,
) -> Expected {
    let card = fixture
        .rows
        .user_cards
        .iter()
        .find(|c| c.user_card_id == card_id);
    let Some(card) = card else {
        return Expected::Pending;
    };
    if card.status != UserCardStatus::Active {
        return Expected::Deny;
    }
    // Gather the card's active, confirmed bindings; DENY wins.
    let mut allow = false;
    let mut deny = false;
    let mut scope_denied = false;
    for binding in fixture
        .rows
        .bindings
        .iter()
        .filter(|b| b.user_card_id == card_id && b.removed_at.is_none())
    {
        let confirmed = fixture.rows.binding_confirmations.iter().any(|c| {
            c.binding_id == binding.binding_id
                && c.rule_set_id == binding.rule_set_id
                && c.version_bytes == vec![1]
                && c.revoked_at.is_none()
        });
        if !confirmed {
            continue;
        }
        let Some(rule_set) = fixture
            .rows
            .rule_sets
            .iter()
            .find(|s| s.rule_set_id == binding.rule_set_id)
        else {
            continue;
        };
        if rule_set.status != RuleSetStatus::Active {
            continue;
        }
        let Some(version) = fixture
            .rows
            .rule_set_versions
            .iter()
            .find(|v| v.rule_set_id == binding.rule_set_id && v.version_bytes == vec![1])
        else {
            continue;
        };
        // Parse the rule content with serde through the same grammar type the
        // engine uses, but decide independently.
        let Ok(content) = serde_json::from_slice::<
            astral_authorization_root::memory_v1_rules::MemoryV1RuleSetContent,
        >(&version.content_bytes) else {
            continue;
        };
        for hit in content.rule_hits(resource, action) {
            // memory—v1 §4.10: the strictest of the rule's and the binding's
            // owner/tenant scopes decides; the engine runs the same predicate.
            let owner_effective = match (hit.owner_scope, binding.owner_scope) {
                (astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::SelfUser, _)
                | (_, astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::SelfUser) => {
                    astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::SelfUser
                }
                _ => astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::AllUsers,
            };
            let tenant_effective = match (hit.tenant_scope, binding.tenant_scope) {
                (
                    astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfTenant,
                    _,
                )
                | (
                    _,
                    astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfTenant,
                ) => astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfTenant,
                _ => {
                    astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfAndDescendants
                }
            };
            let owner_ok = match owner_effective {
                astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::AllUsers => true,
                astral_authorization_root::memory_v1_rules::MemoryV1OwnerScope::SelfUser => {
                    matches!(target_owner, Some(owner) if owner == &card_owner_id(fixture, card_id))
                }
            };
            let tenant_ok = match tenant_effective {
                astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfAndDescendants => {
                    matches!(
                        target_tenant,
                        Some(t) if tenant_reachable(fixture, card_tenant_id(fixture, card_id), t)
                    )
                }
                astral_authorization_root::memory_v1_rules::MemoryV1TenantScope::SelfTenant => {
                    matches!(target_tenant, Some(t) if t == &card_tenant_id(fixture, card_id))
                }
            };
            match hit.effect {
                astral_authorization_root::memory_v1_rules::MemoryV1RuleEffect::Deny => deny = true,
                astral_authorization_root::memory_v1_rules::MemoryV1RuleEffect::Allow => {
                    if owner_ok && tenant_ok {
                        allow = true;
                    } else {
                        scope_denied = true;
                    }
                }
            }
        }
    }
    if deny {
        Expected::Deny
    } else if allow {
        Expected::Allow
    } else {
        // No hit, or a hit whose owner/tenant scope denied it: either way the
        // request is refused (deny-wins aggregation with no surviving ALLOW).
        let _ = scope_denied;
        Expected::Deny
    }
}

// The owning user of the card, from the fixture's card table.
fn card_owner_id(fixture: &ShardFixture, card_id: [u8; 16]) -> [u8; 16] {
    fixture
        .rows
        .user_cards
        .iter()
        .find(|card| card.user_card_id == card_id)
        .map(|card| card.user_id)
        .unwrap_or([0; 16])
}

// The card's tenant, from the fixture's card table.
fn card_tenant_id(fixture: &ShardFixture, card_id: [u8; 16]) -> [u8; 16] {
    fixture
        .rows
        .user_cards
        .iter()
        .find(|card| card.user_card_id == card_id)
        .map(|card| card.tenant_id)
        .unwrap_or([0; 16])
}

// Whether the object tenant equals the card tenant or hangs below it in the
// fixture's tenant tree (one parent hop covers the fixture's two levels).
fn tenant_reachable(
    fixture: &ShardFixture,
    card_tenant: [u8; 16],
    object_tenant: &[u8; 16],
) -> bool {
    if object_tenant == &card_tenant {
        return true;
    }
    fixture.rows.tenants.iter().any(|tenant| {
        tenant.tenant_id == *object_tenant && tenant.parent_tenant_id == Some(card_tenant)
    })
}

// ─── The scale battery ───

#[test]
#[ignore = "memory-v1 500k-user scale battery; run explicitly with --ignored"]
fn scale_shards_and_requests_report() {
    const CHILD: &str = "ASTRAL_MEMORY_V1_SCALE_CHILD";
    if let Ok(role) = std::env::var(CHILD) {
        match role.as_str() {
            "behavior" => run_behavior_child(),
            "shards" => run_shard_validation_child(SHARDS),
            "profile" => {
                // Standalone before/after comparison with the cold sample included.
                run_shard_validation_child(12);
                profile::run();
            }
            "context-profile" => profile::run(),
            other => panic!("unknown scale child role {other}"),
        }
        return;
    }
    // Parent: child-isolated repetition, forwarding only `scale:` rows.
    for (role, expected_passes) in [("shards", 1usize), ("behavior", 1), ("context-profile", 1)] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "memory_v1_scale_tests::scale_shards_and_requests_report",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, role)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains(&format!("{expected_passes} passed")),
            "scale child {role} failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        for line in stdout.lines().filter(|line| line.starts_with("scale:")) {
            println!("{line}");
        }
    }
}

// Child 1: install-validate every shard fixture (834 shards), then prove the
// overlap structure (global sets repeat across shards, private sets are unique).
fn run_shard_validation_child(shards: usize) {
    let started = Instant::now();
    let mut phases = profile::Samples::default();
    let mut global_ids_seen: BTreeSet<u64> = BTreeSet::new();
    let mut private_ids: BTreeSet<u64> = BTreeSet::new();
    let mut family_ids: BTreeSet<u64> = BTreeSet::new();
    let mut total_keys = 0usize;
    for shard in 0..shards {
        let mut sample = phases.sample();
        let fixture = shard_fixture(shard);
        sample.mark("fixture");
        let keys = fixture.rows.table_counts().total().unwrap() + fixture.selections.len();
        let owner = install_isolated_test_root_with_phases(
            fixture.rows,
            fixture.selections,
            CandidateBudget {
                max_table_rows: MAX_ROOT_DIGEST_KEYS,
                max_bindings_per_read: 256,
            },
            |phase| sample.mark(phase),
        )
        .unwrap_or_else(|error| panic!("shard {shard} failed to install: {error:?}"));
        assert!(keys <= MAX_ROOT_DIGEST_KEYS, "shard {shard} keys {keys}");
        total_keys += keys;
        sample.mark("capacity");
        drop(owner);
        sample.mark("drop");
        // Track id spaces by the layer recorded at generation time.
        for (layer, rule_set_id) in &fixture.rule_set_layers {
            match layer {
                Layer::Global => {
                    global_ids_seen.insert(*rule_set_id);
                }
                Layer::Family => {
                    family_ids.insert(*rule_set_id);
                }
                Layer::Private => {
                    private_ids.insert(*rule_set_id);
                }
            }
        }
        sample.mark("overlap");
        sample.finish();
    }
    if shards == SHARDS {
        assert_eq!(global_ids_seen.len(), GLOBAL_RULE_SETS);
        assert_eq!(family_ids.len(), FAMILY_COUNT * FAMILY_RULE_SETS_PER);
    }
    assert_eq!(private_ids.len(), shards);
    phases.report("shard_candidate");
    println!(
        "scale: shards={} users={} keys_per_shard_mean={} global_shared={} family_sets={} private_unique={} elapsed_ms={}",
        shards,
        shards * USERS_PER_SHARD,
        total_keys / shards,
        global_ids_seen.len(),
        family_ids.len(),
        private_ids.len(),
        started.elapsed().as_millis()
    );
}

// Child 2: shard 0 behavior battery — seeded request distribution against the
// oracle, service-period context loads, replay/refusal/CAS-race cases.
fn run_behavior_child() {
    let started = Instant::now();
    let mut fixture = shard_fixture(0);
    let budget = CandidateBudget {
        max_table_rows: MAX_ROOT_DIGEST_KEYS,
        max_bindings_per_read: 256,
    };
    // Reserve headroom for context loads: drop some rows from the base so the
    // battery can merge a missing block of 200 users onto the same root.
    fixture.rows.users.truncate(400);
    fixture.rows.identity_cards.truncate(400);
    fixture.rows.user_cards.truncate(400);
    fixture.rows.bindings.truncate(400);
    fixture.rows.binding_confirmations.truncate(400);
    fixture.principals.truncate(400);
    let owner = install_process_root(fixture.rows.clone(), fixture.selections.clone(), budget)
        .expect("shard 0 installs");
    let declarations = RESOURCES
        .iter()
        .map(|resource| RegistryDeclaration {
            resource: (*resource).to_owned(),
            actions: ACTIONS.iter().map(|action| (*action).to_owned()).collect(),
        })
        .collect::<Vec<_>>();
    owner
        .install_registry(&declarations)
        .expect("the resource registry installs");
    let serving = owner.adopt_serving_for_isolated_tests().expect("serving");
    let handle = owner.handle();
    assert_eq!(
        serving.status,
        astral_authorization_root::memory_v1_root::RootStatus::Serving
    );

    // Request battery: seeded distribution against the oracle.
    let mut rng = Rng::new(0x50_00_B3_A7);
    let engine = PolicyEngine::new();
    let authority =
        astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let evaluations = 10_000;
    let mut counts = [0usize; 3];
    let mut mismatches = 0usize;
    let mut latencies = Vec::with_capacity(evaluations);
    for _ in 0..evaluations {
        let (user_id, identity_id, card_id, tenant_id) = *rng.pick(&fixture.principals);
        let (resource, action) = {
            let resource = RESOURCES[rng.below(RESOURCES.len())];
            let action = ACTIONS[rng.below(ACTIONS.len())];
            (resource, action)
        };
        // Object-bearing with host attribution from fixture facts.
        let target_owner = if rng.below(100) < 60 {
            user_id // own object
        } else {
            fixture.principals[rng.below(fixture.principals.len())].0 // another user's object
        };
        let target_tenant = if rng.below(100) < 85 {
            tenant_id
        } else {
            id(3, 999)
        };
        let expected = oracle_decide(
            &fixture,
            card_id,
            resource,
            action,
            Some(&target_owner),
            Some(&target_tenant),
        );
        let scope = RequestRootScopeShim::new(handle.clone());
        let root = scope.extension();
        let credential = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(
                astral_types::memory_v1::CandidateIdentity {
                    user_id: astral_types::memory_v1::MemoryId::from_bytes(user_id),
                    identity_card_id: astral_types::memory_v1::MemoryId::from_bytes(identity_id),
                    user_card_id: astral_types::memory_v1::MemoryId::from_bytes(card_id),
                    tenant_id: astral_types::memory_v1::MemoryId::from_bytes(tenant_id),
                },
                now - 60,
                3600,
            )
            .unwrap()
            .credential()
            .to_owned();
        let session = authority
            .verifier()
            .verify_and_bind(&credential, now, &root)
            .unwrap();
        let started = Instant::now();
        let result = engine.evaluate_memory_v1(
            &root,
            &session,
            &MemoryV1Request {
                resource,
                action,
                target: Some(b"object"),
                target_tenant: Some(&target_tenant),
                target_owner: Some(&target_owner),
                operation_id: b"scale-request",
                operation_fingerprint: b"scale-fingerprint",
            },
        );
        latencies.push(u64::try_from(started.elapsed().as_nanos()).unwrap());
        let actual = match result.decision {
            MemoryV1Decision::Allow => Expected::Allow,
            MemoryV1Decision::Deny => Expected::Deny,
            MemoryV1Decision::Pending => Expected::Pending,
        };
        // The oracle only models type-level outcomes for root-tenant objects;
        // cross-tenant and unregistered projections are compared structurally.
        let oracle_view = expected;
        if actual != oracle_view {
            if mismatches < 5 {
                println!(
                    "scale: MISMATCH user={user_id:?} card={card_id:?} {resource}/{action} owner={target_owner:?} tenant={target_tenant:?} oracle={expected:?} engine={actual:?}"
                );
            }
            mismatches += 1;
        }
        match actual {
            Expected::Allow => counts[0] += 1,
            Expected::Deny => counts[1] += 1,
            Expected::Pending => counts[2] += 1,
        }
        drop(scope);
    }
    assert_eq!(mismatches, 0, "the oracle and the engine must agree");
    latencies.sort_unstable();
    let percentile = |times: &[u64], p: usize| {
        times
            .get((times.len() * p).div_ceil(100).saturating_sub(1))
            .copied()
            .unwrap_or_default()
    };
    println!(
        "scale: requests={} allow={} deny={} pending={} mismatch=0 p50_us={} p95_us={} p99_us={}",
        evaluations,
        counts[0],
        counts[1],
        counts[2],
        percentile(&latencies, 50) / 1_000,
        percentile(&latencies, 95) / 1_000,
        percentile(&latencies, 99) / 1_000,
    );

    // Service-period context load: 200 missing users merge onto the serving
    // root, then the loaded card evaluates on the same root.
    let before = handle.metadata().unwrap();
    let mut missing = CandidateRows::default();
    for index in 0..200 {
        let user_id = wide_id(1, 999, index);
        missing.users.push(UserRow { user_id });
        missing.identity_cards.push(IdentityCardRow {
            identity_card_id: wide_id(2, 999, index),
            user_id,
        });
        missing.user_cards.push(UserCardRow {
            user_card_id: wide_id(6, 999, index),
            user_id,
            tenant_id: id(3, 0),
            status: UserCardStatus::Active,
        });
        missing.bindings.push(BindingRow {
            binding_id: wide_id(7, 999, index),
            user_card_id: wide_id(6, 999, index),
            rule_set_id: id(5, id_of_layer(Layer::Global, 0)),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::SelfUser,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        });
        missing.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: wide_id(8, 999, index),
            binding_id: wide_id(7, 999, index),
            rule_set_id: id(5, id_of_layer(Layer::Global, 0)),
            version_bytes: vec![1],
            // The confirmer closes inside the loaded block itself.
            confirmer_user_id: wide_id(1, 999, 0),
            scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
    }
    let mutation = ManagementMutationV2::ContextLoad {
        rows: missing,
        selections: Vec::new(),
    };
    let load_started = Instant::now();
    let loaded = owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &mutation,
            &MutationPrecondition {
                evaluated_root_version: before.version,
            },
        )
        .expect("the missing 200-user block merges onto the serving root");
    let load_ns = load_started.elapsed().as_nanos();
    assert_eq!(loaded.version, before.version + 1);
    println!(
        "scale: context_load users=200 version={} -> {} row_count={} -> {} mutation_ns={load_ns}",
        before.version, loaded.version, before.row_count, loaded.row_count
    );

    // The entire batch adds nothing and is refused without advancing the root.
    let replay_error = owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &mutation,
            &MutationPrecondition {
                evaluated_root_version: loaded.version,
            },
        )
        .expect_err("a replayed load adds nothing");
    assert!(matches!(
        replay_error,
        astral_authorization_root::memory_v1_root::MutationError::Runtime(
            astral_authorization_root::memory_v1_hamt_runtime::RuntimeError::UnsafeMerge(_)
        ) | astral_authorization_root::memory_v1_root::MutationError::Candidate(_)
    ));
    assert_eq!(owner.handle().metadata().unwrap(), loaded);

    // The loaded card evaluates ALLOW on the same root without any further
    // load; a card that never loaded anywhere still pends fail-closed.
    let loaded_scope = RequestRootScopeShim::new(handle.clone());
    let loaded_root = loaded_scope.extension();
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(
            astral_types::memory_v1::CandidateIdentity {
                user_id: astral_types::memory_v1::MemoryId::from_bytes(wide_id(1, 999, 0)),
                identity_card_id: astral_types::memory_v1::MemoryId::from_bytes(wide_id(2, 999, 0)),
                user_card_id: astral_types::memory_v1::MemoryId::from_bytes(wide_id(6, 999, 0)),
                tenant_id: astral_types::memory_v1::MemoryId::from_bytes(id(3, 0)),
            },
            now - 30,
            300,
        )
        .unwrap();
    let credential = issued.credential();
    let session = authority
        .verifier()
        .verify_and_bind(credential, now, &loaded_root)
        .unwrap();
    // memory—v1: The post-load request reads the rule the loaded binding
    // actually carries: take the first rule of the bound global set so the
    // expected decision follows from the fixture, not from a guessed pair.
    let bound_set = id(5, id_of_layer(Layer::Global, 0));
    let bound_version = fixture
        .rows
        .rule_set_versions
        .iter()
        .find(|version| version.rule_set_id == bound_set)
        .expect("the bound global set is in shard 0's chosen pool");
    let bound_content: astral_authorization_root::memory_v1_rules::MemoryV1RuleSetContent =
        serde_json::from_slice(&bound_version.content_bytes).unwrap();
    let first_rule = bound_content.rules.first().expect("the set has rules");
    let result = engine.evaluate_memory_v1(
        &loaded_root,
        &session,
        &MemoryV1Request {
            resource: &first_rule.resource,
            action: &first_rule.action,
            target: Some(b"object"),
            target_tenant: Some(&id(3, 0)),
            target_owner: Some(&wide_id(1, 999, 0)),
            operation_id: b"post-load",
            operation_fingerprint: b"post-load",
        },
    );
    let expected_decision = match first_rule.effect {
        astral_authorization_root::memory_v1_rules::MemoryV1RuleEffect::Allow => {
            MemoryV1Decision::Allow
        }
        astral_authorization_root::memory_v1_rules::MemoryV1RuleEffect::Deny => {
            MemoryV1Decision::Deny
        }
    };
    assert_eq!(result.decision, expected_decision, "{result:?}");
    drop(loaded_scope);

    // CAS race: a withdrawal published after the observed version beats a
    // load that planned against the stale version.
    let stale = handle.metadata().unwrap();
    owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::BindingRemove {
                binding_id: wide_id(7, 999, 0),
                removed_at: now,
                removed_by: id(1, 0),
            },
            &MutationPrecondition {
                evaluated_root_version: stale.version,
            },
        )
        .unwrap();
    let race = owner.execute_mutation_with_precondition_for_isolated_tests(
        &ManagementMutationV2::ContextLoad {
            rows: CandidateRows::default(),
            selections: Vec::new(),
        },
        &MutationPrecondition {
            evaluated_root_version: stale.version,
        },
    );
    assert!(matches!(
        race,
        Err(astral_authorization_root::memory_v1_root::MutationError::ConcurrentModification)
    ));
    println!(
        "scale: behavior_total merge=ok replay=refused post_load={:?} stale_cas=refused elapsed_ms={}",
        result.decision,
        started.elapsed().as_millis()
    );
}

// ─── Request-scope shim for the battery ───

use astral_authorization_root::memory_v1_request::RequestRootScope;

struct RequestRootScopeShim(RequestRootScope);

impl RequestRootScopeShim {
    fn new(handle: astral_authorization_root::memory_v1_root::RootHandle) -> Self {
        Self(RequestRootScope::new(handle, uuid::Uuid::new_v4()))
    }

    fn extension(&self) -> astral_authorization_root::memory_v1_request::RequestRootExtension {
        self.0.extension()
    }
}
