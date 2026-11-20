//! memory—v1: Rule-level admission model for Theorem 1 (USENIX Security 2027 draft).
//!
//! Claim scope. The model checks Theorem 1 at rule level: one principal, one card, one session, one
//! request q = (r, a), no target object, no owner or tenant scope, no tenant hierarchy and no
//! exhaustion path. Premises 1 and 2 (identity, tenant hierarchy) are not exercised, and Theorem 2
//! (local sufficiency) is not in this file. The model is a bounded abstraction. Its validator is
//! checked against an oracle written from the paper's Permit; it is not production code.
//!
//! Universe (the appendix quotes this block; change it only together with the appendix):
//! - Clock T in 0..=TMAX with TMAX = 4. The initial stage runs at T0 in 0..=T0_MAX = 3. Tick and
//!   Rollback move the clock by one.
//! - Windows are half-open [from, until); absent endpoints are unbounded. The menu WINDOWS is
//!   0 unbounded, 1 until 3, 2 from 2, 3 [1,3), 4 degenerate [2,2).
//! - One card (active flag), one session (revoked flag and optional expiry), one registry flag for
//!   (r,a), one serving flag and one global write fence (open flag and revision counter).
//! - NB = 2 binding slots, each Absent or Present{rule, Confirmed | Pending | Revoked, removed,
//!   window}. A removed slot stays Present with removed = true and never returns to Absent.
//! - NR = 2 rule sets, each with one current version: effect in {NoEffect, Allow, Deny} and a window.
//! - Initial family: 38,400 configurations, exhaustive over these cores. slot0 in {Absent,
//!   Confirmed(rule 0, w) for w in WINDOWS}; slot1 in {Absent, Confirmed(rule 1, unbounded),
//!   Confirmed(rule 1, until 3), Confirmed(rule 1, from 2), Pending(rule 0, unbounded)};
//!   rule0 in {Allow(unbounded), Allow(until 3), Allow(from 2), Deny(unbounded)}; rule1 in
//!   {NoEffect(unbounded), Deny(unbounded), Deny(until 3), Deny(from 2), Allow(until 3)}.
//!   Session in {live, revoked} x expiry {none, 3}; flags serving, card, registry and fence open
//!   (16 combinations). The family is a hand-picked subset of the universe: it has no Revoked or
//!   removed slot at T0 and no slot reuse. Each configuration is taken at every T0 in 0..=T0_MAX.
//! - Generation identities. The dependency record stores these and the final check compares them.
//!   - card: the card-level dependency generation. Advanced by BindingCreate, BindingRemove, every
//!     ConfirmationSet that changes a slot, and CardToggle. It stands for membership, confirmation
//!     and card status. Production advances its card dependency generation in with_binding_insert,
//!     with_binding_removed, with_confirmation_insert, with_confirmation_revoked,
//!     with_confirmations_batch and with_user_card_status (astral-authorization-root/src/
//!     memory_v1_hamt.rs).
//!   - session and registry. The registry is one flag here; production compares the whole registry
//!     version.
//!   - slot[NB]: advanced by every change of that slot. rule[NR]: advanced by every RuleSetPublish,
//!     including a NoEffect publication. unrelated: advanced by Unrelated and never compared. root:
//!     advanced by every writer and compared only by the whole-root comparator.
//!
//!   The membership identity is the card generation. The recorded-binding loop compares, for every
//!   recorded member, its slot generation and its rule-set generation. There is no independent
//!   enumeration in the correct validator; EnumerateMembers adds one as an extra guard.
//! - Writers: 57 events. BindingCreate (rule x window, 10), BindingRemove (2), ConfirmationSet
//!   (slot x {Confirmed, Pending, Revoked}, 6), RuleSetPublish (rule x {Allow, Deny, NoEffect} x
//!   window, 30), CardToggle, SessionRevoke, RegistryToggle, Unrelated, ServingOff. Clock: Tick and
//!   Rollback. Fence: FenceOpen and FenceClose. An event is enabled only if it changes state.
//! - Schedules: each leaf is a word over the events and the check steps Obs1, Sample and Obs2, taken
//!   in that order and ending with Obs2, with at most L events. Default L = 2; L = 3 is an ignored
//!   test.
//!
//! Permit, the envelope and precision. The oracle computes Permit(X,q,T) = C and K and U and E+
//! nonempty and E- empty by scanning every clock value, and it shares no function with the evaluator
//! or the validator. The evaluator records the envelope I_q = [T0, b) intersected with every winning
//! window, where b is the least recorded threshold. The validator admits only inside I_q at the
//! sample. The envelope abstains wherever Permit still holds, for two reasons. The recorded
//! thresholds include dormant Allow starts and empty windows, which are sound but conservative (X2
//! and X3). The intersection of all winning windows requires every winning window to hold even when
//! one would suffice (M4 is sound and more permissive; guarantee.tex line 24). Precision
//! is claimed relative to I_q and session liveness only. "In envelope" below means inside I_q and
//! with the session live at that clock. The uniform-schedule equality is definitional, because the
//! envelope is built from the same record. The Permit-relative measure is abstain_uniform, and the
//! state-level abstention scan and the two examples measure the gap against Permit.
//!
//! Rollback. The validator detects a clock below T0 at the sample only and keeps no history.
//! Rollback-then-return to T0 is accepted and is sound, because I_q is fixed at T0 and the facts are
//! unchanged. guarantee.tex premise 4 (a detectable rollback prevents admission) is therefore
//! stronger than the model needs. A grep of the memory-v1 production modules found no clock
//! high-water mark; the only production check on a sample below T0 is the test at
//! policy-engine/src/memory_v1_formal.rs:2450-2453. Production rollback-then-return was not run.
//!
//! Fence. The model uses one global key with one revision. The governed writer in production
//! opens one owned window over the affected existing rule set; the registry uses per-object
//! revisions with a history floor. The model does not exercise target resolution, journal ordering,
//! guard ownership or isolation between different rule sets; those belong to composition tests.
//!
//! Production mapping (ManagementMutationV2 in astral-authorization-root/src/memory_v1_root.rs,
//! lines 1496-1548; eleven variants):
//! - BindingCreate -> BindingCreate (confirmed only; Pending is set by ConfirmationSet).
//! - BindingRemove -> BindingRemove.
//! - ConfirmationCreate -> ConfirmationSet to Confirmed or Pending.
//! - ConfirmationRevoke -> ConfirmationSet to Revoked.
//! - RuleSetChangeConfirmationRevoke -> none. Unmodelled: it revokes the change-confirmation state of a
//!   rule set (Active, Withdrawn, Missing or Invalid; memory_v1_rules.rs:333-345), written by
//!   with_change_confirmation_revoked (memory_v1_hamt.rs:2033). The model has no such state.
//! - ConfirmationBatch -> a sequence of ConfirmationSet steps. Its atomicity is assumed, not modelled.
//! - UserCardCreate -> Unrelated. It creates a card other than q's card, and no fact of q's card changes.
//! - UserCardStatus -> CardToggle.
//! - RuleSetCreate -> Unrelated. A new rule set is referenced by no existing binding, so applicability
//!   changes only through BindingCreate and RuleSetPublish.
//! - RuleSetRetire -> RuleSetPublish to NoEffect. An approximation: production records a retired
//!   status (with_rule_set_retired, memory_v1_hamt.rs:2429), which the model reads as no effect.
//! - VersionPublish -> RuleSetPublish to Allow, Deny or NoEffect.
//! - Binding confirmation: production has Active, Withdrawn and Invalid (memory_v1_rules.rs:288-299).
//!   The model's Confirmed is Active, Revoked is Withdrawn and Pending is Invalid (it blocks K).
//!   Production has no Pending state, and the model's ConfirmationSet to Pending has no direct
//!   production writer.
//!
//! Necessity. Each row of the mutant table states its reason. In summary, shown by a depth-two
//! counterexample: card generation (M7 BindingCreate, M11 CardToggle, FC1 final check); rule-set
//! generation (M10 publish, FC2 final check; FC4 shows the recorded-membership loop is needed for it);
//! registry generation (M13, M17); serving and session liveness (M16, M18); the rollback gate (M20);
//! the clock read at the sample (M19); the fence observed before and after the sample, with the
//! revision comparison (M21, M22, FC5); and the nonempty dormant denial thresholds (M1, M3, M6). The
//! root generation is not needed by the correct validator. Equivalent or redundant within the
//! bounds: M8, M9, M12, M14, X5, X6, FC3, FC6, and the enumeration of applicable bindings (X1).
//! Sound but not premises: M4, X2 and X3 (more permissive), and X4 and P1 (more conservative).
//!
//! Outside the model (argued or unchecked):
//! 1. Unreadable or unresolved facts. No state represents them, so fail-closed behaviour for an
//!    unreadable binding or rule set is not tested.
//! 2. Digests and canonical encoding (the content identity of premise 3).
//! 3. Generation exhaustion. u8 generations never reach 255 in these bounds; only the wrap mutant M15
//!    is run.
//! 4. Failed or contended sample, clock failure and lock discipline. Premise 4 is modelled by
//!    detection at the sample. Production holds the session, root and registry read guards through
//!    the sample and fails closed on contention or clock failure.
//! 5. Per-key fence revisions, history-floor eviction, and fences opened by production writers
//!    (none exist in the shipped composition).
//! 6. Tenant hierarchy, owner and tenant scope, target object and instance identity. The scope
//!    conjuncts of C are omitted, so Permit is abstract at rule level.
//! 7. Non-atomic writers. Every event is one atomic step, as premise 3 assumes.
//! 8. The Missing and Invalid change-confirmation states, and the change-confirmation writers that
//!    produce them. UserCardCreate and RuleSetCreate are mapped to Unrelated above; the model has no
//!    card-creation or rule-set-creation event.
//! 9. Slot reuse. No event creates a binding in a removed slot, so identity reuse is covered only by
//!    the wrap mutant M15.
//! 10. Clock jumps of more than one unit. The clock moves by one per event, so a writer followed by a
//!     two-unit jump needs depth three.
//! 11. Entry unavailability for a dormant lookup. Entries are always visible here. Production records
//!     the binding start for a dormant binding; that recording is modelled by X4, not the
//!     unavailability itself.
//! 12. Coarser production checks. The model's membership identity is card-level, as production's is,
//!     so binding and confirmation changes on the card reject even when they do not apply to q, in
//!     both. The model's rule-set and registry identities are per rule set and per flag, which is
//!     finer than production's registry-version comparison.
//! 13. Common-mode limitation. This model checks refinement of the validator against a fixed fixture
//!     predicate (Permit as written here). It does not check the correctness of that predicate, and
//!     the evaluator and oracle read the same Live encoding.

const TMAX: u8 = 4;
const T0_MAX: u8 = 3;
const NB: usize = 2;
const NR: usize = 2;
const WINNER_SLOTS: usize = NB * NR;
const DEFAULT_DEPTH: usize = 2;
const DEEP_DEPTH: usize = 3;
// memory—v1: Accept count of the correct validator at depth two. Other rows pin their own counts
// against this value through the relation they declare.
const CORRECT_ACCEPTS: usize = 2_308_736;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Window {
    from: Option<u8>,
    until: Option<u8>,
}

// memory—v1: Five-window menu over the bounded clock (see the module universe).
const WINDOWS: [Window; 5] = [
    Window {
        from: None,
        until: None,
    },
    Window {
        from: None,
        until: Some(3),
    },
    Window {
        from: Some(2),
        until: None,
    },
    Window {
        from: Some(1),
        until: Some(3),
    },
    Window {
        from: Some(2),
        until: Some(2),
    },
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Effect {
    #[default]
    Inert,
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Conf {
    Confirmed,
    Pending,
    Revoked,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Slot {
    #[default]
    Absent,
    Present {
        rule: usize,
        conf: Conf,
        removed: bool,
        window: Window,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RuleSet {
    effect: Effect,
    window: Window,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Session {
    revoked: bool,
    expires: Option<u8>,
}

// memory—v1: Generation identities of the model (see the module universe). membership identity is
// the card generation; there is no separate membership counter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Gens {
    card: u8,
    session: u8,
    registry: u8,
    unrelated: u8,
    root: u8,
    slot: [u8; NB],
    rule: [u8; NR],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Live {
    serving: bool,
    session: Session,
    card_active: bool,
    registry_on: bool,
    slots: [Slot; NB],
    rules: [RuleSet; NR],
    fence_open: bool,
    fence_rev: u8,
    gens: Gens,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Obs {
    open: bool,
    rev: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Member {
    slot_gen: u8,
    rule: usize,
    rule_gen: u8,
}

// memory—v1: Dependency record of the initial stage. Members hold every applicable binding by
// slot, with its slot generation and the generation of the rule set it consults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Record {
    t0: u8,
    gens: Gens,
    members: [Option<Member>; NB],
    winners: [Option<Window>; WINNER_SLOTS],
    threshold: Option<u8>,
}

// memory—v1: Premise-necessity mutants. Each variant changes exactly one evaluator, writer or
// validator behaviour. Correct is the validator with production's guard set. The rows that follow
// the Expect table classify each one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutant {
    Correct,
    // memory—v1: Evaluator and envelope.
    EnvelopeNoThresholds,
    EnvelopeClosedUntil,
    ThresholdOffByOne,
    FirstWindowOnly,
    EvaluatorNoDormant,
    DropAllowThresholds,
    DropEmptyThresholds,
    ProductionRecording,
    // memory—v1: Writers.
    NoCardBumpCreate,
    NoCardBumpRemove,
    NoCardBumpConfirm,
    NoCardBumpToggle,
    NoSlotBumpRemove,
    NoSlotBumpConfirm,
    NoRuleBumpPublish,
    NoSessionBump,
    NoRegistryBump,
    UnrelatedNoBump,
    WrapGensMod2,
    // memory—v1: Final check.
    NoCardGenCheck,
    NoRuleGenCheck,
    NoSlotGenCheck,
    NoMembershipCheck,
    NoSessionGenCheck,
    NoLiveSession,
    NoRegistryRevalidation,
    NoServing,
    SampleAtT0,
    NoRollbackCheck,
    NoFenceRevCheck,
    FenceAfterOnly,
    FenceBeforeOnly,
    EnumerateMembers,
    WholeRootVersion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    BindingCreate {
        rule: usize,
        window: usize,
    },
    BindingRemove {
        slot: usize,
    },
    ConfirmationSet {
        slot: usize,
        conf: Conf,
    },
    RuleSetPublish {
        rule: usize,
        effect: Effect,
        window: usize,
    },
    CardToggle,
    SessionRevoke,
    RegistryToggle,
    Unrelated,
    ServingOff,
    Tick,
    Rollback,
    FenceOpen,
    FenceClose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Ev(usize),
    Obs1,
    Sample,
    Obs2,
}

// memory—v1: Final-check gates in the fixed evaluation order; a rejection is attributed to the
// first failing gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    Serving,
    Session,
    Generation,
    Membership,
    Rollback,
    Envelope,
    Fence,
}

const GATE_NAMES: [&str; 7] = [
    "serving",
    "session",
    "generation",
    "membership",
    "rollback",
    "envelope",
    "fence",
];

// memory—v1: Declared effect of a mutant row relative to the correct validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Relation {
    // memory—v1: The row has a shortest unsound accept (a counterexample).
    Killed,
    // memory—v1: Sound, and accepts exactly the schedules the correct validator accepts.
    Equal,
    // memory—v1: Sound, and accepts strictly more schedules (less conservative; not a premise).
    MorePermissive,
    // memory—v1: Sound, and accepts strictly fewer schedules (more conservative; not a premise).
    MoreConservative,
}

// memory—v1: The 57-entry event menu in a fixed enumeration order.
fn menu() -> Vec<Event> {
    let mut v = Vec::new();
    for rule in 0..NR {
        for window in 0..WINDOWS.len() {
            v.push(Event::BindingCreate { rule, window });
        }
    }
    for slot in 0..NB {
        v.push(Event::BindingRemove { slot });
    }
    for slot in 0..NB {
        for conf in [Conf::Confirmed, Conf::Pending, Conf::Revoked] {
            v.push(Event::ConfirmationSet { slot, conf });
        }
    }
    for rule in 0..NR {
        for effect in [Effect::Allow, Effect::Deny, Effect::Inert] {
            for window in 0..WINDOWS.len() {
                v.push(Event::RuleSetPublish {
                    rule,
                    effect,
                    window,
                });
            }
        }
    }
    v.extend([
        Event::CardToggle,
        Event::SessionRevoke,
        Event::RegistryToggle,
        Event::Unrelated,
        Event::ServingOff,
        Event::Tick,
        Event::Rollback,
        Event::FenceOpen,
        Event::FenceClose,
    ]);
    v
}

// memory—v1: Advance one generation. The WrapGensMod2 mutant reuses values modulo two.
fn bump(g: &mut u8, m: Mutant) {
    *g = if m == Mutant::WrapGensMod2 {
        (*g + 1) % 2
    } else {
        *g + 1
    };
}

// memory—v1: Membership of a slot as the evaluator records it and the validator compares it.
fn member_at(x: &Live, s: usize) -> Option<Member> {
    match x.slots[s] {
        Slot::Present {
            rule,
            conf,
            removed: false,
            ..
        } if conf != Conf::Revoked => Some(Member {
            slot_gen: x.gens.slot[s],
            rule,
            rule_gen: x.gens.rule[rule],
        }),
        _ => None,
    }
}

// memory—v1: Session liveness at a clock value in interval form.
fn session_live(s: Session, t: u8) -> bool {
    !s.revoked && s.expires.is_none_or(|e| t < e)
}

// memory—v1: Interval intersection of a binding window with an entry window.
fn intersect(a: Window, b: Window) -> Window {
    Window {
        from: match (a.from, b.from) {
            (Some(x), Some(y)) => Some(x.max(y)),
            (x, None) => x,
            (None, y) => y,
        },
        until: match (a.until, b.until) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, None) => x,
            (None, y) => y,
        },
    }
}

// memory—v1: Evaluator-side point test in interval form.
fn contains(w: Window, t: u8) -> bool {
    w.from.is_none_or(|f| t >= f) && w.until.is_none_or(|u| t < u)
}

// memory—v1: A window whose lower endpoint is not below its upper endpoint contains no clock value.
fn empty_window(w: Window) -> bool {
    matches!((w.from, w.until), (Some(f), Some(u)) if f >= u)
}

// memory—v1: Oracle-side window as a bitmask over every integer clock value (no interval
// arithmetic). The precision classifier reuses this helper.
fn tick_mask(w: Window) -> u8 {
    let mut mask = 0u8;
    for x in 0..=TMAX {
        let started = match w.from {
            None => true,
            Some(f) => x >= f,
        };
        let open = match w.until {
            None => true,
            Some(u) => x < u,
        };
        if started && open {
            mask |= 1u8 << x;
        }
    }
    mask
}

// memory—v1: Window rendering for counterexample strings.
fn win(w: Window) -> String {
    let lo = w.from.map_or_else(|| "-inf".to_string(), |v| v.to_string());
    let hi = w
        .until
        .map_or_else(|| "+inf".to_string(), |v| v.to_string());
    format!("[{lo},{hi})")
}

// memory—v1: One-line rendering of a live configuration and its clock for pinned strings.
fn describe(x: &Live, clock: u8) -> String {
    let slot = |s: &Slot| match s {
        Slot::Absent => "-".to_string(),
        Slot::Present {
            rule,
            conf,
            removed,
            window,
        } => format!(
            "r{rule}:{conf:?}{}{}",
            if *removed { "x" } else { "" },
            win(*window)
        ),
    };
    let rule = |r: &RuleSet| format!("{:?}{}", r.effect, win(r.window));
    let expires = x
        .session
        .expires
        .map_or_else(|| "-".to_string(), |e| e.to_string());
    format!(
        "T={clock} srv={} card={} reg={} sessRev={} exp={expires} fence={} s0={} s1={} r0={} r1={}",
        u8::from(x.serving),
        u8::from(x.card_active),
        u8::from(x.registry_on),
        u8::from(x.session.revoked),
        u8::from(x.fence_open),
        slot(&x.slots[0]),
        slot(&x.slots[1]),
        rule(&x.rules[0]),
        rule(&x.rules[1]),
    )
}

// memory—v1: Apply one event to the live state and clock. None when the event is disabled.
// Writers bump their keys and the root version; clock and fence events do not bump the root.
fn apply(x: &Live, clock: u8, ev: Event, m: Mutant) -> Option<(Live, u8)> {
    let mut y = *x;
    let mut c = clock;
    let mut writer = true;
    match ev {
        Event::BindingCreate { rule, window } => {
            let s = x.slots.iter().position(|slot| *slot == Slot::Absent)?;
            y.slots[s] = Slot::Present {
                rule,
                conf: Conf::Confirmed,
                removed: false,
                window: WINDOWS[window],
            };
            bump(&mut y.gens.slot[s], m);
            if m != Mutant::NoCardBumpCreate {
                bump(&mut y.gens.card, m);
            }
        }
        Event::BindingRemove { slot } => {
            let Slot::Present {
                rule,
                conf,
                removed: false,
                window,
            } = x.slots[slot]
            else {
                return None;
            };
            y.slots[slot] = Slot::Present {
                rule,
                conf,
                removed: true,
                window,
            };
            if m != Mutant::NoSlotBumpRemove {
                bump(&mut y.gens.slot[slot], m);
            }
            if m != Mutant::NoCardBumpRemove {
                bump(&mut y.gens.card, m);
            }
        }
        Event::ConfirmationSet { slot, conf } => {
            let Slot::Present {
                rule,
                conf: old,
                removed: false,
                window,
            } = x.slots[slot]
            else {
                return None;
            };
            if old == conf {
                return None;
            }
            y.slots[slot] = Slot::Present {
                rule,
                conf,
                removed: false,
                window,
            };
            if m != Mutant::NoSlotBumpConfirm {
                bump(&mut y.gens.slot[slot], m);
            }
            if m != Mutant::NoCardBumpConfirm {
                bump(&mut y.gens.card, m);
            }
        }
        Event::RuleSetPublish {
            rule,
            effect,
            window,
        } => {
            let next = RuleSet {
                effect,
                window: WINDOWS[window],
            };
            if x.rules[rule] == next {
                return None;
            }
            y.rules[rule] = next;
            if m != Mutant::NoRuleBumpPublish {
                bump(&mut y.gens.rule[rule], m);
            }
        }
        Event::CardToggle => {
            y.card_active = !x.card_active;
            if m != Mutant::NoCardBumpToggle {
                bump(&mut y.gens.card, m);
            }
        }
        Event::SessionRevoke => {
            if x.session.revoked {
                return None;
            }
            y.session.revoked = true;
            if m != Mutant::NoSessionBump {
                bump(&mut y.gens.session, m);
            }
        }
        Event::RegistryToggle => {
            y.registry_on = !x.registry_on;
            if m != Mutant::NoRegistryBump {
                bump(&mut y.gens.registry, m);
            }
        }
        Event::Unrelated => {
            if m != Mutant::UnrelatedNoBump {
                bump(&mut y.gens.unrelated, m);
            }
        }
        Event::ServingOff => {
            if !x.serving {
                return None;
            }
            y.serving = false;
        }
        Event::Tick => {
            writer = false;
            if clock >= TMAX {
                return None;
            }
            c = clock + 1;
        }
        Event::Rollback => {
            writer = false;
            if clock == 0 {
                return None;
            }
            c = clock - 1;
        }
        Event::FenceOpen => {
            writer = false;
            if x.fence_open {
                return None;
            }
            y.fence_open = true;
            y.fence_rev += 1;
        }
        Event::FenceClose => {
            writer = false;
            if !x.fence_open {
                return None;
            }
            y.fence_open = false;
            y.fence_rev += 1;
        }
    }
    if writer {
        bump(&mut y.gens.root, m);
    }
    Some((y, c))
}

// memory—v1: Window shorthand for the family enumeration.
fn rs(effect: Effect, w: usize) -> RuleSet {
    RuleSet {
        effect,
        window: WINDOWS[w],
    }
}

// memory—v1: Enumerate the exhaustive initial family in a fixed order (see the module universe).
fn family() -> Vec<Live> {
    let mut slot0 = vec![Slot::Absent];
    for window in WINDOWS {
        slot0.push(Slot::Present {
            rule: 0,
            conf: Conf::Confirmed,
            removed: false,
            window,
        });
    }
    let slot1 = [
        Slot::Absent,
        Slot::Present {
            rule: 1,
            conf: Conf::Confirmed,
            removed: false,
            window: WINDOWS[0],
        },
        Slot::Present {
            rule: 1,
            conf: Conf::Confirmed,
            removed: false,
            window: WINDOWS[1],
        },
        Slot::Present {
            rule: 1,
            conf: Conf::Confirmed,
            removed: false,
            window: WINDOWS[2],
        },
        Slot::Present {
            rule: 0,
            conf: Conf::Pending,
            removed: false,
            window: WINDOWS[0],
        },
    ];
    let rule0 = [
        rs(Effect::Allow, 0),
        rs(Effect::Allow, 1),
        rs(Effect::Allow, 2),
        rs(Effect::Deny, 0),
    ];
    let rule1 = [
        rs(Effect::Inert, 0),
        rs(Effect::Deny, 0),
        rs(Effect::Deny, 1),
        rs(Effect::Deny, 2),
        rs(Effect::Allow, 1),
    ];
    let sessions = [
        Session {
            revoked: false,
            expires: None,
        },
        Session {
            revoked: false,
            expires: Some(3),
        },
        Session {
            revoked: true,
            expires: None,
        },
        Session {
            revoked: true,
            expires: Some(3),
        },
    ];
    let mut out = Vec::with_capacity(38_400);
    for &s0 in &slot0 {
        for &s1 in &slot1 {
            for &r0 in &rule0 {
                for &r1 in &rule1 {
                    for &session in &sessions {
                        for flags in 0..16u8 {
                            out.push(Live {
                                serving: (flags & 1) != 0,
                                card_active: (flags & 2) != 0,
                                registry_on: (flags & 4) != 0,
                                fence_open: (flags & 8) != 0,
                                session,
                                slots: [s0, s1],
                                rules: [r0, r1],
                                fence_rev: 0,
                                gens: Gens::default(),
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

// memory—v1: Recorded-binding identity at the sample. A recorded member must still be an applicable
// member with the same rule, slot generation and rule generation. An applicable binding that was not
// recorded is accepted here, because the card generation already rejects every membership change;
// EnumerateMembers rejects it as an extra guard.
fn member_same(recorded: Option<Member>, now: Option<Member>, m: Mutant) -> bool {
    match (recorded, now) {
        (Some(a), Some(b)) => {
            a.rule == b.rule
                && (m == Mutant::NoSlotGenCheck || a.slot_gen == b.slot_gen)
                && (m == Mutant::NoRuleGenCheck || a.rule_gen == b.rule_gen)
        }
        (None, Some(_)) => m != Mutant::EnumerateMembers,
        (Some(_), None) => false,
        (None, None) => true,
    }
}

// memory—v1: Initial stage at T0. Returns the candidate with its dependency record, or None when
// the positive result fails (serving, session, card, registry, fence, Pending evidence, or a
// denial active at T0, or no winning allow).
fn evaluate(x: &Live, t0: u8, m: Mutant) -> Option<Record> {
    if !x.serving
        || !session_live(x.session, t0)
        || !x.card_active
        || !x.registry_on
        || x.fence_open
    {
        return None;
    }
    if x.slots.iter().any(|s| {
        matches!(
            s,
            Slot::Present {
                conf: Conf::Pending,
                removed: false,
                ..
            }
        )
    }) {
        return None;
    }
    let mut rec = Record {
        t0,
        gens: x.gens,
        ..Record::default()
    };
    let mut winners = 0usize;
    let mut negative = false;
    for s in 0..NB {
        rec.members[s] = member_at(x, s);
        let Slot::Present {
            rule,
            conf: Conf::Confirmed,
            removed: false,
            window,
        } = x.slots[s]
        else {
            continue;
        };
        let r = x.rules[rule];
        if r.effect == Effect::Inert {
            continue;
        }
        let w = intersect(window, r.window);
        if contains(w, t0) {
            match r.effect {
                Effect::Allow => {
                    rec.winners[winners] = Some(w);
                    winners += 1;
                }
                Effect::Deny => negative = true,
                Effect::Inert => {}
            }
        } else if let Some(start) = w.from.filter(|&f| f > t0) {
            // memory—v1: Dormant pair. EvaluatorNoDormant omits the start of a binding that is itself
            // dormant at T0 (M6). DropAllowThresholds and DropEmptyThresholds (X2, X3) omit allow
            // starts and empty windows, which are sound but conservative. ProductionRecording (X4)
            // records the binding start B for a dormant binding instead of max(B, E), as production
            // does; B is at most max(B, E), so the threshold is earlier and the envelope smaller.
            let dormant_binding = window.from.is_some_and(|f| f > t0);
            let skipped = (m == Mutant::EvaluatorNoDormant && dormant_binding)
                || (m == Mutant::DropAllowThresholds && r.effect == Effect::Allow)
                || (m == Mutant::DropEmptyThresholds && empty_window(w));
            if !skipped {
                let at = match window.from {
                    Some(b) if m == Mutant::ProductionRecording && dormant_binding => b,
                    _ => start,
                };
                rec.threshold = Some(rec.threshold.map_or(at, |b| b.min(at)));
            }
        }
    }
    if negative || winners == 0 {
        return None;
    }
    Some(rec)
}

// memory—v1: Final check at the guarded sample. Ok means accept. Err names the first failing
// gate in the fixed order. The time envelope is computed by interval arithmetic. The generation
// gate compares the card (membership and card status), session, and registry generations; the
// recorded-binding loop compares slot and rule-set generations of every recorded member.
fn validate(rec: &Record, obs1: Obs, sample: (Live, u8), obs2: Obs, m: Mutant) -> Result<(), Gate> {
    let (x, raw) = sample;
    let t = if m == Mutant::SampleAtT0 { rec.t0 } else { raw };
    if m != Mutant::NoServing && !x.serving {
        return Err(Gate::Serving);
    }
    if m != Mutant::NoLiveSession && !session_live(x.session, t) {
        return Err(Gate::Session);
    }
    let (g, r) = (x.gens, rec.gens);
    let card_ok = m == Mutant::NoCardGenCheck || g.card == r.card;
    let session_ok = m == Mutant::NoSessionGenCheck || g.session == r.session;
    let registry_ok = m == Mutant::NoRegistryRevalidation || g.registry == r.registry;
    let root_ok = m != Mutant::WholeRootVersion || g.root == r.root;
    if !(card_ok && session_ok && registry_ok && root_ok) {
        return Err(Gate::Generation);
    }
    if m != Mutant::NoMembershipCheck {
        for s in 0..NB {
            if !member_same(rec.members[s], member_at(&x, s), m) {
                return Err(Gate::Membership);
            }
        }
    }
    if m != Mutant::NoRollbackCheck && t < rec.t0 {
        return Err(Gate::Rollback);
    }
    let mut lo = 0u8;
    let mut hi = if m == Mutant::EnvelopeNoThresholds {
        None
    } else {
        rec.threshold.map(|b| {
            if m == Mutant::ThresholdOffByOne {
                b + 1
            } else {
                b
            }
        })
    };
    let take = if m == Mutant::FirstWindowOnly {
        1
    } else {
        WINNER_SLOTS
    };
    for w in rec.winners.iter().flatten().take(take) {
        if let Some(f) = w.from {
            lo = lo.max(f);
        }
        if let Some(u) = w.until {
            let u = if m == Mutant::EnvelopeClosedUntil {
                u + 1
            } else {
                u
            };
            hi = Some(hi.map_or(u, |h: u8| h.min(u)));
        }
    }
    if t < lo || hi.is_some_and(|h| t >= h) {
        return Err(Gate::Envelope);
    }
    let fence_ok = match m {
        Mutant::FenceAfterOnly => !obs2.open,
        Mutant::FenceBeforeOnly => !obs1.open,
        Mutant::NoFenceRevCheck => !obs1.open && !obs2.open,
        _ => !obs1.open && !obs2.open && obs1.rev == obs2.rev,
    };
    if fence_ok {
        Ok(())
    } else {
        Err(Gate::Fence)
    }
}

// memory—v1: Sequential Permit(X,q,T) written from the paper: C and K and U and E+ nonempty and
// E- empty. Every clock value is scanned; no interval arithmetic and no validator helper.
fn oracle(x: &Live, t: u8) -> bool {
    let mut session_ticks = 0u8;
    for y in 0..=TMAX {
        let before_expiry = match x.session.expires {
            None => true,
            Some(e) => y < e,
        };
        if !x.session.revoked && before_expiry {
            session_ticks |= 1u8 << y;
        }
    }
    let c = x.serving && ((session_ticks >> t) & 1) == 1 && x.card_active && x.registry_on;
    let k = !x.slots.iter().any(|s| {
        matches!(
            s,
            Slot::Present {
                conf: Conf::Pending,
                removed: false,
                ..
            }
        )
    });
    let u = !x.fence_open;
    let (mut pos, mut neg) = (false, false);
    for s in &x.slots {
        if let Slot::Present {
            rule,
            conf: Conf::Confirmed,
            removed: false,
            window,
        } = *s
        {
            let r = x.rules[rule];
            if r.effect == Effect::Inert {
                continue;
            }
            let mask = tick_mask(window) & tick_mask(r.window);
            if ((mask >> t) & 1) == 1 {
                match r.effect {
                    Effect::Allow => pos = true,
                    Effect::Deny => neg = true,
                    Effect::Inert => {}
                }
            }
        }
    }
    c && k && u && pos && !neg
}

// memory—v1: Clock values inside the recorded envelope (T0 or later, before the threshold,
// inside every winning window), computed by scanning every clock value.
fn envelope_mask(rec: &Record) -> u8 {
    let mut mask = 0u8;
    for t in 0..=TMAX {
        let inside = rec
            .winners
            .iter()
            .flatten()
            .all(|w| ((tick_mask(*w) >> t) & 1) == 1);
        let below = rec.threshold.is_none_or(|b| t < b);
        if t >= rec.t0 && below && inside {
            mask |= 1u8 << t;
        }
    }
    mask
}

// memory—v1: Observation of the write fence (open flag and revision).
fn observe(x: &Live) -> Obs {
    Obs {
        open: x.fence_open,
        rev: x.fence_rev,
    }
}

// memory—v1: Semantic equality of two live states, ignoring generations and fence revision. Used
// to detect a change that was restored before the sample.
fn semantic_eq(a: &Live, b: &Live) -> bool {
    a.serving == b.serving
        && a.session == b.session
        && a.card_active == b.card_active
        && a.registry_on == b.registry_on
        && a.slots == b.slots
        && a.rules == b.rules
        && a.fence_open == b.fence_open
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Stats {
    configs: usize,
    pairs: usize,
    candidates: usize,
    differential_mismatch: usize,
    leaves: usize,
    accepts: usize,
    unsound: usize,
    rejects: [usize; 7],
    accepts_across_unrelated: usize,
    accepts_moved_clock: usize,
    reject_exact_threshold: usize,
    reject_membership_change: usize,
    reject_restore: usize,
    reject_transient_fence: usize,
    uniform_leaves: usize,
    uniform_inenv: usize,
    uniform_accept_correct: usize,
    uniform_accept_root: usize,
    uniform_mismatch: usize,
    uniform_abstain: usize,
}

// memory—v1: Depth-first explorer. The walk visits every word over the events and the three
// final-check steps, with Obs2 last, at most max_events events. Each leaf is one schedule.
struct Explorer<'a> {
    menu: &'a [Event],
    mutant: Mutant,
    max_events: usize,
    stop_on_violation: bool,
    stop: bool,
    origin: Live,
    origin_clock: u8,
    rec: Record,
    path: Vec<Step>,
    stats: Stats,
    violation: Option<(usize, String)>,
}

// memory—v1: Explorer methods: the depth-first walk and the per-schedule scoring.
impl Explorer<'_> {
    // memory—v1: Advance the next check step or take an enabled event. done counts the check
    // steps already taken (0 before Obs1, 1 before Sample, 2 before Obs2).
    fn dfs(
        &mut self,
        live: Live,
        clock: u8,
        done: u8,
        obs1: Obs,
        sample: (Live, u8),
        events: usize,
    ) {
        if self.stop {
            return;
        }
        match done {
            0 => {
                self.path.push(Step::Obs1);
                let o = observe(&live);
                self.dfs(live, clock, 1, o, (live, clock), events);
                self.path.pop();
            }
            1 => {
                self.path.push(Step::Sample);
                self.dfs(live, clock, 2, obs1, (live, clock), events);
                self.path.pop();
            }
            _ => {
                self.path.push(Step::Obs2);
                let obs2 = observe(&live);
                self.leaf(obs1, sample, obs2);
                self.path.pop();
            }
        }
        if events < self.max_events {
            for i in 0..self.menu.len() {
                let ev = self.menu[i];
                if let Some((next, next_clock)) = apply(&live, clock, ev, self.mutant) {
                    self.path.push(Step::Ev(i));
                    self.dfs(next, next_clock, done, obs1, sample, events + 1);
                    self.path.pop();
                    if self.stop {
                        return;
                    }
                }
            }
        }
    }

    // memory—v1: Score one complete schedule: soundness against the oracle, gate attribution,
    // witnesses and, for uniform schedules, the precision comparison.
    fn leaf(&mut self, obs1: Obs, sample: (Live, u8), obs2: Obs) {
        self.stats.leaves += 1;
        let (live, clock) = sample;
        let verdict = validate(&self.rec, obs1, sample, obs2, self.mutant);
        let moved = clock != self.origin_clock;
        let mut unrelated = false;
        let mut membership_event = false;
        let mut uniform = true;
        for step in &self.path {
            if let Step::Ev(i) = step {
                let kind = self.menu[*i];
                match kind {
                    Event::Unrelated => unrelated = true,
                    Event::BindingCreate { .. }
                    | Event::BindingRemove { .. }
                    | Event::ConfirmationSet { .. } => membership_event = true,
                    _ => {}
                }
                if !matches!(kind, Event::Unrelated | Event::Tick) {
                    uniform = false;
                }
            }
        }
        // memory—v1: Permit is needed only for an accept (soundness) and for a uniform schedule
        // (abstention); other rejects skip the oracle scan.
        let permit = if verdict.is_ok() || uniform {
            oracle(&live, clock)
        } else {
            false
        };
        match verdict {
            Ok(()) => {
                self.stats.accepts += 1;
                if unrelated {
                    self.stats.accepts_across_unrelated += 1;
                }
                if moved {
                    self.stats.accepts_moved_clock += 1;
                }
                if !permit {
                    self.stats.unsound += 1;
                    self.found(&live, clock);
                }
            }
            Err(gate) => {
                self.stats.rejects[gate as usize] += 1;
                if gate == Gate::Envelope && self.rec.threshold == Some(clock) {
                    self.stats.reject_exact_threshold += 1;
                }
                // memory—v1: Membership changes are rejected by the card generation (Generation
                // gate, which runs first), so the witness counts both gates.
                if membership_event && matches!(gate, Gate::Generation | Gate::Membership) {
                    self.stats.reject_membership_change += 1;
                }
                if matches!(gate, Gate::Generation | Gate::Membership)
                    && semantic_eq(&live, &self.origin)
                {
                    self.stats.reject_restore += 1;
                }
                if gate == Gate::Fence && !live.fence_open && !obs1.open && !obs2.open {
                    self.stats.reject_transient_fence += 1;
                }
            }
        }
        if uniform {
            self.stats.uniform_leaves += 1;
            // memory—v1: "In-envelope" for the precision claim means the clock is inside I_q and
            // the live session is still valid at that clock (conjunct C of Permit).
            let in_env =
                ((envelope_mask(&self.rec) >> clock) & 1) == 1 && session_live(live.session, clock);
            let ok = verdict.is_ok();
            if in_env {
                self.stats.uniform_inenv += 1;
            }
            if ok {
                self.stats.uniform_accept_correct += 1;
            }
            if ok != in_env {
                self.stats.uniform_mismatch += 1;
            }
            // memory—v1: Permit-relative abstention: Permit holds at the sample but the validator
            // rejects. Unlike uniform_mismatch, this does not use the envelope.
            if permit && !ok {
                self.stats.uniform_abstain += 1;
            }
            if validate(&self.rec, obs1, sample, obs2, Mutant::WholeRootVersion).is_ok() {
                self.stats.uniform_accept_root += 1;
            }
        }
    }

    // memory—v1: Record the first unsound accept with its event count and readable schedule.
    fn found(&mut self, live: &Live, clock: u8) {
        if self.violation.is_none() {
            let len = self
                .path
                .iter()
                .filter(|s| matches!(s, Step::Ev(_)))
                .count();
            let steps: Vec<String> = self
                .path
                .iter()
                .map(|s| match s {
                    Step::Ev(i) => format!("{:?}", self.menu[*i]),
                    Step::Obs1 => "Obs1".to_string(),
                    Step::Sample => "Sample".to_string(),
                    Step::Obs2 => "Obs2".to_string(),
                })
                .collect();
            let text = format!(
                "start: {} | schedule: {} | final: {}",
                describe(&self.origin, self.origin_clock),
                steps.join(" ; "),
                describe(live, clock)
            );
            self.violation = Some((len, text));
        }
        if self.stop_on_violation {
            self.stop = true;
        }
    }
}

// memory—v1: Run the explorer over the whole family at every T0. Differential property: the
// candidate exists exactly when the oracle holds at the initial state. Returns the statistics
// and the first unsound accept, if any.
fn run(
    mutant: Mutant,
    max_events: usize,
    stop_on_violation: bool,
) -> (Stats, Option<(usize, String)>) {
    let menu = menu();
    let mut ex = Explorer {
        menu: &menu,
        mutant,
        max_events,
        stop_on_violation,
        stop: false,
        origin: Live::default(),
        origin_clock: 0,
        rec: Record::default(),
        path: Vec::new(),
        stats: Stats::default(),
        violation: None,
    };
    'family: for x0 in family() {
        ex.stats.configs += 1;
        for t0 in 0..=T0_MAX {
            ex.stats.pairs += 1;
            let cand = evaluate(&x0, t0, mutant);
            if cand.is_some() != oracle(&x0, t0) {
                ex.stats.differential_mismatch += 1;
            }
            if let Some(rec) = cand {
                ex.stats.candidates += 1;
                ex.rec = rec;
                ex.origin = x0;
                ex.origin_clock = t0;
                ex.dfs(x0, t0, 0, Obs::default(), (x0, t0), 0);
                if ex.stop {
                    break 'family;
                }
            }
        }
    }
    (ex.stats, ex.violation)
}

// memory—v1: Shortest unsound accept by budgeted search: budgets 0, 1, 2 in turn. A budget-b
// search that is the first to find a violation returns a schedule with exactly b events. When no
// violation exists the budget-2 run is a full depth-2 scan, and its statistics are returned.
fn shortest(mutant: Mutant) -> (Option<(usize, String)>, Stats) {
    let mut last = Stats::default();
    for budget in 0..=DEFAULT_DEPTH {
        let (stats, found) = run(mutant, budget, true);
        if let Some(found) = found {
            return (Some(found), stats);
        }
        last = stats;
    }
    (None, last)
}

#[test]
// memory—v1: Theorem 1 on the bounded universe at depth two: exhaustive over the family, every T0
// and every schedule of at most two events with the final check. The differential, soundness and
// witness assertions do not depend on the pinned counts, which record this universe's output.
fn theorem1_depth2_exhaustive() {
    let (s, violation) = run(Mutant::Correct, DEFAULT_DEPTH, false);
    println!(
        "correct validator, depth {DEFAULT_DEPTH}: {} configurations, {} (config, T0) pairs, {} candidates",
        s.configs, s.pairs, s.candidates
    );
    println!(
        "leaves={} accepts={} unsound={}",
        s.leaves, s.accepts, s.unsound
    );
    for (name, count) in GATE_NAMES.iter().zip(s.rejects) {
        println!("  reject at {name:<11} {count}");
    }
    println!(
        "precision: uniform leaves={} in-envelope={} correct accepts={} root accepts={} permit-but-rejected={} mismatch={}",
        s.uniform_leaves,
        s.uniform_inenv,
        s.uniform_accept_correct,
        s.uniform_accept_root,
        s.uniform_abstain,
        s.uniform_mismatch
    );
    println!(
        "witnesses: across-unrelated={} moved-clock={} exact-threshold={} membership={} restore={} transient-fence={}",
        s.accepts_across_unrelated,
        s.accepts_moved_clock,
        s.reject_exact_threshold,
        s.reject_membership_change,
        s.reject_restore,
        s.reject_transient_fence
    );
    assert!(violation.is_none(), "unsound accept: {violation:?}");
    assert_eq!(
        s.differential_mismatch, 0,
        "candidate exists iff Permit holds at T0"
    );
    assert_eq!(s.configs, 38_400);
    assert_eq!(s.pairs, 153_600);
    assert_eq!(s.candidates, 828);
    assert_eq!(s.leaves, 9_741_900);
    assert_eq!(s.accepts, CORRECT_ACCEPTS);
    assert_eq!(
        s.rejects,
        [288_216, 337_110, 2_631_144, 3_867_136, 85_688, 30_830, 193_040]
    );
    assert_eq!(s.leaves, s.accepts + s.rejects.iter().sum::<usize>());
    // memory—v1: Non-vacuity witnesses for the premises.
    assert!(
        s.accepts_across_unrelated > 0,
        "accept across an unrelated writer"
    );
    assert!(
        s.accepts_moved_clock > 0,
        "accept after a clock move inside the envelope"
    );
    assert!(
        s.reject_exact_threshold > 0,
        "reject at the exact deny start"
    );
    assert!(
        s.reject_membership_change > 0,
        "reject on a membership change"
    );
    assert!(s.reject_restore > 0, "reject on change-and-restore");
    assert!(s.reject_transient_fence > 0, "reject on a transient fence");
    assert_eq!(s.accepts_across_unrelated, 183_932);
    assert_eq!(s.accepts_moved_clock, 54_936);
    assert_eq!(s.reject_exact_threshold, 12_820);
    assert_eq!(s.reject_membership_change, 2_472_280);
    assert_eq!(s.reject_restore, 70_248);
    assert_eq!(s.reject_transient_fence, 1_656);
    // memory—v1: Precision. Uniform schedules (Unrelated writes and clock ticks only) are accepted
    // exactly when the sample is inside the envelope and the session is live; the whole-root
    // comparator accepts only those without any Unrelated write.
    assert_eq!(s.uniform_leaves, 25_284);
    assert_eq!(s.uniform_mismatch, 0);
    assert_eq!(s.uniform_inenv, 18_504);
    assert_eq!(s.uniform_accept_correct, 18_504);
    assert_eq!(s.uniform_accept_root, 8_532);
    assert!(s.uniform_accept_root < s.uniform_accept_correct);
    // memory—v1: Completeness gap measured against Permit (not against the envelope): uniform
    // schedules where Permit holds at the sample and the validator rejects. These are envelope cuts
    // (see the abstention examples and the state-level scan); the validator is sound, not complete.
    assert_eq!(s.uniform_abstain, 1_101);
}

// memory—v1: Permit-relative abstention of the correct validator on the unchanged state. For every
// configuration, every candidate T0 and every clock value where Permit holds, the final check runs
// with the same live state and no event in between. Every rejection is attributed to the rollback
// gate (clock below T0), to the recorded threshold (clock at or after it), or to a winning window
// (clock outside the intersection). No other gate may reject, and no accept may lack Permit.
#[test]
fn envelope_abstention_unchanged_state() {
    let (mut permit, mut accepted, mut rollback) = (0usize, 0usize, 0usize);
    let (mut threshold_cut, mut winner_cut, mut other, mut unsound) =
        (0usize, 0usize, 0usize, 0usize);
    for x0 in family() {
        for t0 in 0..=T0_MAX {
            let Some(rec) = evaluate(&x0, t0, Mutant::Correct) else {
                continue;
            };
            for t in 0..=TMAX {
                let permit_here = oracle(&x0, t);
                let verdict = validate(&rec, observe(&x0), (x0, t), observe(&x0), Mutant::Correct);
                if verdict.is_ok() && !permit_here {
                    unsound += 1;
                }
                if permit_here {
                    permit += 1;
                    match verdict {
                        Ok(()) => accepted += 1,
                        Err(Gate::Rollback) => rollback += 1,
                        Err(Gate::Envelope) if rec.threshold.is_some_and(|b| t >= b) => {
                            threshold_cut += 1;
                        }
                        Err(Gate::Envelope) => winner_cut += 1,
                        Err(_) => other += 1,
                    }
                }
            }
        }
    }
    println!(
        "unchanged-state scan: permit={permit} accepted={accepted} rollback={rollback} \
         threshold_cut={threshold_cut} winner_cut={winner_cut} other={other} unsound={unsound}"
    );
    assert_eq!(unsound, 0, "accept without Permit");
    assert_eq!(
        other, 0,
        "only the rollback and envelope gates may reject with no event"
    );
    assert_eq!(
        permit,
        accepted + rollback + threshold_cut + winner_cut,
        "every Permit point is accepted or attributed"
    );
    assert_eq!(permit, 2_210);
    assert_eq!(accepted, 1_408);
    assert_eq!(rollback, 618);
    assert_eq!(threshold_cut, 152);
    assert_eq!(winner_cut, 32);
}

#[test]
// memory—v1: Abstention example 1. Slot 0 is a dormant Allow binding (from 2) under an unbounded
// Allow rule, so its start is recorded as a threshold although Allow cannot falsify Permit. Permit
// holds at every clock value, and the validator admits only 0 and 1. Dropping dormant Allow starts
// (X2) admits 2 as well, which is sound: the conservatism is in the envelope, not in the premise.
fn abstention_example_dormant_allow_threshold() {
    let x = Live {
        serving: true,
        card_active: true,
        registry_on: true,
        slots: [
            Slot::Present {
                rule: 0,
                conf: Conf::Confirmed,
                removed: false,
                window: WINDOWS[2],
            },
            Slot::Present {
                rule: 1,
                conf: Conf::Confirmed,
                removed: false,
                window: WINDOWS[0],
            },
        ],
        rules: [rs(Effect::Allow, 0), rs(Effect::Allow, 1)],
        ..Live::default()
    };
    let rec = evaluate(&x, 0, Mutant::Correct).expect("candidate at T0 = 0");
    assert_eq!(rec.threshold, Some(2));
    for t in 0..=TMAX {
        assert!(oracle(&x, t), "Permit holds at clock {t}");
        let verdict = validate(&rec, observe(&x), (x, t), observe(&x), Mutant::Correct);
        let expected = if t < 2 { Ok(()) } else { Err(Gate::Envelope) };
        assert_eq!(verdict, expected, "clock {t}");
    }
    let dropped = evaluate(&x, 0, Mutant::DropAllowThresholds).expect("candidate");
    assert_eq!(dropped.threshold, None);
    assert_eq!(
        validate(&dropped, observe(&x), (x, 2), observe(&x), Mutant::Correct),
        Ok(())
    );
    assert!(oracle(&x, 2));
}

#[test]
// memory—v1: Abstention example 2. Slot 0 is a Deny binding with the empty window [2,2) under an
// unbounded Deny rule. The window contains no clock value, so it never denies, yet its start is
// recorded as a threshold at 2. Permit holds at 2 because the Allow binding (until 3) is positive
// there, so the validator abstains at 2. Dropping empty-window thresholds (X3) admits 2, soundly.
fn abstention_example_empty_deny_window() {
    let x = Live {
        serving: true,
        card_active: true,
        registry_on: true,
        slots: [
            Slot::Present {
                rule: 0,
                conf: Conf::Confirmed,
                removed: false,
                window: WINDOWS[4],
            },
            Slot::Present {
                rule: 1,
                conf: Conf::Confirmed,
                removed: false,
                window: WINDOWS[0],
            },
        ],
        rules: [rs(Effect::Deny, 0), rs(Effect::Allow, 1)],
        ..Live::default()
    };
    let rec = evaluate(&x, 0, Mutant::Correct).expect("candidate at T0 = 0");
    assert_eq!(rec.threshold, Some(2));
    assert!(oracle(&x, 2), "Permit holds at clock 2");
    assert_eq!(
        validate(&rec, observe(&x), (x, 2), observe(&x), Mutant::Correct),
        Err(Gate::Envelope)
    );
    let dropped = evaluate(&x, 0, Mutant::DropEmptyThresholds).expect("candidate");
    assert_eq!(dropped.threshold, None);
    assert_eq!(
        validate(&dropped, observe(&x), (x, 2), observe(&x), Mutant::Correct),
        Ok(())
    );
}

#[test]
// memory—v1: Rollback then return. From T0 = 2 the schedule Rollback then Tick leaves the clock at
// 2 with every fact unchanged, and the validator admits it. This is sound: I_q is fixed at T0 and
// Permit holds at 2. A sample at 1, below T0, is refused by the rollback gate. Premise 4 as written
// (a detectable rollback prevents admission) is stronger than the model requires.
fn rollback_then_return_is_accepted_and_sound() {
    let x = Live {
        serving: true,
        card_active: true,
        registry_on: true,
        slots: [
            Slot::Absent,
            Slot::Present {
                rule: 1,
                conf: Conf::Confirmed,
                removed: false,
                window: WINDOWS[0],
            },
        ],
        rules: [rs(Effect::Allow, 0), rs(Effect::Allow, 1)],
        ..Live::default()
    };
    let rec = evaluate(&x, 2, Mutant::Correct).expect("candidate at T0 = 2");
    let (down, c1) = apply(&x, 2, Event::Rollback, Mutant::Correct).expect("rollback enabled");
    assert_eq!(c1, 1);
    let (back, c2) = apply(&down, c1, Event::Tick, Mutant::Correct).expect("tick enabled");
    assert_eq!(c2, 2);
    assert_eq!(back, x, "clock events leave the facts unchanged");
    let obs = observe(&x);
    assert_eq!(
        validate(&rec, obs, (back, c2), obs, Mutant::Correct),
        Ok(())
    );
    assert!(oracle(&back, c2));
    assert_eq!(
        validate(&rec, obs, (down, c1), obs, Mutant::Correct),
        Err(Gate::Rollback)
    );
}

// memory—v1: Expected outcome of one premise-necessity mutant within depth two. violation is the
// shortest unsound accept (its event count and readable text) or None when the full depth-two scan
// finds no unsound accept. accepts pins the accept count of a mutant without a counterexample, and
// relation states how that count compares with the correct validator.
struct Expect {
    mutant: Mutant,
    label: &'static str,
    violation: Option<(usize, &'static str)>,
    accepts: Option<usize>,
    relation: Relation,
}

// memory—v1: The mutant table with pinned shortest counterexamples and pinned accept counts. Each
// row has a comment that states why it is killed, equivalent, or sound and more or less precise.
const EXPECTS: [Expect; 35] = [
    // memory—v1: Killed: the envelope must include the threshold of a dormant denial.
    Expect { mutant: Mutant::EnvelopeNoThresholds, label: "M1 envelope ignores thresholds", violation: Some((1, "start: T=1 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Confirmed[-inf,+inf) s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Deny[2,+inf) | schedule: Obs1 ; Tick ; Sample ; Obs2 | final: T=2 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Confirmed[-inf,+inf) s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Deny[2,+inf)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: the envelope upper endpoint is exclusive.
    Expect { mutant: Mutant::EnvelopeClosedUntil, label: "M2 envelope upper endpoint closed", violation: Some((1, "start: T=2 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; Tick ; Sample ; Obs2 | final: T=3 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: a deny that starts at the sample is seen only at the exact threshold.
    Expect { mutant: Mutant::ThresholdOffByOne, label: "M3 threshold off by one", violation: Some((1, "start: T=1 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Confirmed[-inf,+inf) s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Deny[2,+inf) | schedule: Obs1 ; Tick ; Sample ; Obs2 | final: T=2 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Confirmed[-inf,+inf) s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Deny[2,+inf)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Sound and more permissive. Intersecting all winning windows is conservative
    // (guarantee.tex line 24); the first window alone is not a premise.
    Expect { mutant: Mutant::FirstWindowOnly, label: "M4 first winning window only (sound, more permissive; not a premise)", violation: None, accepts: Some(2_309_858), relation: Relation::MorePermissive },
    // memory—v1: Killed: a dormant binding's own start must be recorded.
    Expect { mutant: Mutant::EvaluatorNoDormant, label: "M6 evaluator omits dormant binding start", violation: Some((1, "start: T=1 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Confirmed[-inf,+inf) s1=r1:Confirmed[2,+inf) r0=Allow[-inf,+inf) r1=Deny[-inf,+inf) | schedule: Obs1 ; Tick ; Sample ; Obs2 | final: T=2 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Confirmed[-inf,+inf) s1=r1:Confirmed[2,+inf) r0=Allow[-inf,+inf) r1=Deny[-inf,+inf)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Sound and more permissive: an allow start cannot falsify Permit, so recording it
    // is conservative (see abstention example 1).
    Expect { mutant: Mutant::DropAllowThresholds, label: "X2 allow starts not recorded (sound, more permissive; not a premise)", violation: None, accepts: Some(2_313_935), relation: Relation::MorePermissive },
    // memory—v1: Sound and more permissive: an empty window never denies (see abstention example 2).
    Expect { mutant: Mutant::DropEmptyThresholds, label: "X3 empty-window thresholds not recorded (sound, more permissive; not a premise)", violation: None, accepts: Some(2_310_224), relation: Relation::MorePermissive },
    // memory—v1: Sound and more conservative: production records the binding start B for a dormant
    // binding, which is no later than max(B, E), so the envelope is smaller.
    Expect { mutant: Mutant::ProductionRecording, label: "X4 production recording: binding start for dormant (sound, more conservative)", violation: None, accepts: Some(2_308_376), relation: Relation::MoreConservative },
    // memory—v1: Control for the rows below: the correct validator itself, the recorded-only final
    // check with card generation kept. The enumeration of applicable bindings is not a premise
    // (M5 is the correct validator; X1 adds the enumeration back).
    Expect { mutant: Mutant::Correct, label: "M5 membership enumeration omitted, card generation kept (negative; is Correct)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Sound and identical to Correct: a new applicable binding changes the card generation
    // first, so the enumeration guard is redundant under card-level identity.
    Expect { mutant: Mutant::EnumerateMembers, label: "X1 enumeration of applicable bindings as extra guard (sound, redundant)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Killed: BindingCreate adds an applicable binding that the recorded loop cannot see,
    // so the card generation is the only membership identity that detects it.
    Expect { mutant: Mutant::NoCardBumpCreate, label: "M7 BindingCreate omits card generation (killed)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Deny[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; BindingCreate { rule: 0, window: 0 } ; Sample ; Obs2 | final: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Confirmed[-inf,+inf) s1=r1:Confirmed[-inf,+inf) r0=Deny[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Equivalent: a removed slot never returns to Absent, member_at is None for it, and a
    // removal of a recorded member is caught by the recorded loop (slot generation not needed).
    Expect { mutant: Mutant::NoSlotBumpRemove, label: "M8 BindingRemove omits slot generation (equivalent)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Equivalent: every confirmation change also bumps the card generation, which the
    // Generation gate checks first, so the slot generation adds no decision.
    Expect { mutant: Mutant::NoSlotBumpConfirm, label: "M9 ConfirmationSet omits slot generation (equivalent given card generation)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Killed: a RuleSetPublish changes the effect of a recorded member's rule set, and only
    // the rule generation sees it. Production also compares the selected version of each recorded
    // binding's rule, so the production check is redundant with this one.
    Expect { mutant: Mutant::NoRuleBumpPublish, label: "M10 RuleSetPublish omits rule generation (killed)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; RuleSetPublish { rule: 1, effect: Allow, window: 2 } ; Sample ; Obs2 | final: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[2,+inf)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: the validator does not read card_active at the sample, so the card generation
    // is the only card check. Production reads card status at the sample, so this is redundant there.
    Expect { mutant: Mutant::NoCardBumpToggle, label: "M11 CardToggle omits card generation (killed; redundant in production)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; CardToggle ; Sample ; Obs2 | final: T=0 srv=1 card=0 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Equivalent: a revoke is absorbing and makes the session dead at the sample, which the
    // Session gate checks before the Generation gate.
    Expect { mutant: Mutant::NoSessionBump, label: "M12 SessionRevoke omits session generation (equivalent)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Killed: the validator does not read registry_on at the sample.
    Expect { mutant: Mutant::NoRegistryBump, label: "M13 RegistryToggle omits registry generation (killed)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; RegistryToggle ; Sample ; Obs2 | final: T=0 srv=1 card=1 reg=0 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Control, equivalent: the correct validator never compares the unrelated generation,
    // so a writer that does not bump it cannot change a decision.
    Expect { mutant: Mutant::UnrelatedNoBump, label: "M14 control: Unrelated omits its generation (equivalent; never compared)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Equivalent: removal of a recorded member is caught by the recorded loop, and removing
    // a non-member changes no decision. The card bump on removal is defence in depth.
    Expect { mutant: Mutant::NoCardBumpRemove, label: "X5 BindingRemove omits card generation (equivalent)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Equivalent within the family: only BindingCreate can gain membership, and the family
    // has no Revoked slot at T0, so a ConfirmationSet never makes a non-member applicable.
    Expect { mutant: Mutant::NoCardBumpConfirm, label: "X6 ConfirmationSet omits card generation (equivalent within the family)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Killed: generations wrap modulo two, so change-and-restore is invisible.
    Expect { mutant: Mutant::WrapGensMod2, label: "M15 generations wrap modulo two (killed)", violation: Some((2, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; BindingCreate { rule: 0, window: 0 } ; ConfirmationSet { slot: 0, conf: Pending } ; Sample ; Obs2 | final: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Pending[-inf,+inf) s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: the card generation is the only membership and card-status identity checked.
    Expect { mutant: Mutant::NoCardGenCheck, label: "FC1 final check skips card generation (killed)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; CardToggle ; Sample ; Obs2 | final: T=0 srv=1 card=0 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: rule-set publication is seen only by the rule generation of a recorded member.
    Expect { mutant: Mutant::NoRuleGenCheck, label: "FC2 final check skips rule generation (killed)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; RuleSetPublish { rule: 1, effect: Allow, window: 2 } ; Sample ; Obs2 | final: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[2,+inf)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Equivalent: every slot change also bumps the card generation.
    Expect { mutant: Mutant::NoSlotGenCheck, label: "FC3 final check skips slot generation (equivalent given card generation)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Killed: without the recorded loop, a rule-set publication is missed.
    Expect { mutant: Mutant::NoMembershipCheck, label: "FC4 final check skips the recorded-membership loop (killed)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; RuleSetPublish { rule: 1, effect: Allow, window: 2 } ; Sample ; Obs2 | final: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[2,+inf)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: a fence opened and closed between the two observations is seen only by the
    // revision comparison (Lemma 1).
    Expect { mutant: Mutant::NoFenceRevCheck, label: "FC5 final check skips fence revision equality (killed)", violation: Some((2, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; FenceOpen ; Sample ; FenceClose ; Obs2 | final: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=1 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Equivalent: a session generation changes only on revoke, which the Session gate sees.
    Expect { mutant: Mutant::NoSessionGenCheck, label: "FC6 final check skips session generation (equivalent)", violation: None, accepts: Some(2_308_736), relation: Relation::Equal },
    // memory—v1: Killed: the final check must read the live session at the sample.
    Expect { mutant: Mutant::NoLiveSession, label: "M16 no live session check (killed)", violation: Some((1, "start: T=2 srv=1 card=1 reg=1 sessRev=0 exp=3 fence=0 s0=r0:Confirmed[-inf,+inf) s1=- r0=Allow[-inf,+inf) r1=Inert[-inf,+inf) | schedule: Obs1 ; Tick ; Sample ; Obs2 | final: T=3 srv=1 card=1 reg=1 sessRev=0 exp=3 fence=0 s0=r0:Confirmed[-inf,+inf) s1=- r0=Allow[-inf,+inf) r1=Inert[-inf,+inf)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: the registry generation is the only registry check the validator makes.
    Expect { mutant: Mutant::NoRegistryRevalidation, label: "M17 no registry generation check (killed)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; RegistryToggle ; Sample ; Obs2 | final: T=0 srv=1 card=1 reg=0 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: the serving flag must be read at the sample.
    Expect { mutant: Mutant::NoServing, label: "M18 no serving check (killed)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; ServingOff ; Sample ; Obs2 | final: T=0 srv=0 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: time checks must use the sample clock, not T0.
    Expect { mutant: Mutant::SampleAtT0, label: "M19 time checks use T0 (killed; stale clock)", violation: Some((1, "start: T=2 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; Tick ; Sample ; Obs2 | final: T=3 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: a sample below T0 must be refused (the envelope does not cover it).
    Expect { mutant: Mutant::NoRollbackCheck, label: "M20 no rollback check (killed)", violation: Some((1, "start: T=3 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Confirmed[-inf,+inf) s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Deny[-inf,3) | schedule: Obs1 ; Rollback ; Sample ; Obs2 | final: T=2 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=r0:Confirmed[-inf,+inf) s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Deny[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed at length 2: a fence open and close around the sample needs both observations.
    Expect { mutant: Mutant::FenceAfterOnly, label: "M21 fence observed after only (killed)", violation: Some((2, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; FenceOpen ; Sample ; FenceClose ; Obs2 | final: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=1 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Killed: a fence opened after the first observation is seen only by the second.
    Expect { mutant: Mutant::FenceBeforeOnly, label: "M22 fence observed before only (killed)", violation: Some((1, "start: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=0 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3) | schedule: Obs1 ; FenceOpen ; Sample ; Obs2 | final: T=0 srv=1 card=1 reg=1 sessRev=0 exp=- fence=1 s0=- s1=r1:Confirmed[-inf,+inf) r0=Allow[-inf,+inf) r1=Allow[-inf,3)")), accepts: None, relation: Relation::Killed },
    // memory—v1: Sound and more conservative: comparing the whole root version rejects every
    // unrelated publication, which the correct validator accepts (a precision comparator, not a premise).
    Expect { mutant: Mutant::WholeRootVersion, label: "P1 whole-root comparator (sound, more conservative; not a premise)", violation: None, accepts: Some(1_612_532), relation: Relation::MoreConservative },
];

#[test]
// memory—v1: Premise-necessity mutants within depth two. A killed mutant must yield an unsound accept
// whose shortest event count and readable text are pinned. A sound mutant must yield no unsound accept
// over the full depth-two scan, and its accept count must stand in the declared relation to the
// correct validator. The table is printed before any assertion so that the pins can be read.
fn premise_necessity_mutants_depth2() {
    let mut results = Vec::with_capacity(EXPECTS.len());
    for case in EXPECTS {
        let (found, stats) = shortest(case.mutant);
        results.push((case, found, stats));
    }
    for (case, found, stats) in &results {
        let shown = found
            .as_ref()
            .map_or_else(|| "-".to_string(), |(len, _)| len.to_string());
        println!(
            "{:<96} shortest={:<2} accepts={:<9} unsound={} rel={:?}",
            case.label, shown, stats.accepts, stats.unsound, case.relation
        );
        if let Some((_, text)) = found {
            println!("    {text}");
        }
    }
    for (case, found, stats) in results {
        match (case.violation, found) {
            (Some((len, text)), Some((got_len, got))) => {
                assert_eq!(case.relation, Relation::Killed, "{}", case.label);
                assert_eq!(got_len, len, "{}: shortest length", case.label);
                assert_eq!(got, text, "{}: pinned counterexample", case.label);
            }
            (None, None) => {
                assert_ne!(case.relation, Relation::Killed, "{}", case.label);
                assert_eq!(stats.unsound, 0, "{}", case.label);
                let accepts = case.accepts.expect("sound row pins its accept count");
                assert_eq!(stats.accepts, accepts, "{}: accept count", case.label);
                match case.relation {
                    Relation::Equal => assert_eq!(
                        stats.accepts, CORRECT_ACCEPTS,
                        "{}: equal to the correct validator",
                        case.label
                    ),
                    Relation::MorePermissive => assert!(
                        stats.accepts > CORRECT_ACCEPTS,
                        "{}: more permissive",
                        case.label
                    ),
                    Relation::MoreConservative => assert!(
                        stats.accepts < CORRECT_ACCEPTS,
                        "{}: more conservative",
                        case.label
                    ),
                    Relation::Killed => unreachable!("killed rows have a counterexample"),
                }
            }
            (expected, got) => panic!("{}: expected {expected:?}, found {got:?}", case.label),
        }
    }
}

#[test]
#[ignore]
// memory—v1: Depth-three exhaustive run of the correct validator. Not part of the default run
// because it is heavy in debug builds. Command:
// cargo test --locked --offline -p test-harness --test memory_v1_admission_rule_model -- --ignored --nocapture depth3_exhaustive_correct_validator
fn depth3_exhaustive_correct_validator() {
    let (s, violation) = run(Mutant::Correct, DEEP_DEPTH, false);
    assert!(
        violation.is_none(),
        "unsound accept at depth three: {violation:?}"
    );
    assert_eq!(s.differential_mismatch, 0);
    assert_eq!(s.leaves, 706_376_460);
    assert_eq!(s.accepts, 105_517_813);
    assert_eq!(s.uniform_mismatch, 0);
    assert!(s.accepts_across_unrelated > 0);
    assert!(s.reject_restore > 0);
    assert!(s.reject_transient_fence > 0);
    println!(
        "depth {DEEP_DEPTH}: leaves={} accepts={} unsound={} uniform_mismatch={}",
        s.leaves, s.accepts, s.unsound, s.uniform_mismatch
    );
}
