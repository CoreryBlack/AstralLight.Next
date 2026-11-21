//! memory—v1: Journal protocol model v3 for the Computers & Security DarkStar paper.
//!
//! Scope. An explicit-state model of the response and recovery protocol of the C&S
//! paper (`sections/02-model.tex`, `03-protocol.tex`, `04-implementation.tex`). It is
//! std-only, performs no I/O, uses no clock or randomness, and explores every reachable
//! state of a finite configuration by breadth-first search with a visited set. A passing
//! run is a bounded result under the abstractions A1–A5 below. It is not an inductive
//! proof and not a refinement proof of the Rust code.
//!
//! Variables (paper letters first; `S` is the physical addition). `n` is the number of
//! registered frames (log length `|L|`). `w` is the written prefix. `S` is the physically
//! stable prefix: the bytes that survive power loss. `d` is the implementation's
//! confirmed-durable claim (`durable_end`). `b` is the database's committed prefix as it
//! physically is; recovery reads it back. `bc` is the protocol's belief about that prefix
//! (client side). `db` is the database policy bit and `live` the published root policy bit.
//! `unsure` marks an uncertain database commit that awaits read-back. `round` is the
//! captured end `u` of the one in-flight sync round and `tainted` is the sticky
//! uncertain-sync flag. `pending` is a sorted multiset of at most `PEND` DENY observations
//! taken and not yet appended, each held as its observed prefix. `acked` is the set of
//! positions for which a response was issued; responses survive crashes because clients
//! hold them. `muts` and `denies` are used budgets. `recoveries` counts completed
//! recoveries (the epoch is `recoveries + 1`). `crashed` marks the crashed phase.
//!
//! Frames. `Set(v)` is a governance mutation. `Deny{obs, seen}` is an audit frame: `obs` is
//! the bound prefix (`seen` under `ObservedPrefix`, the tail `n` under `AuditTail`) and `seen`
//! is the observed prefix recorded with the observation. `seen` is a ghost field used only
//! by the binding check I4b. `Abort{target}` is the repair frame that cancels a failed
//! publish. A `Deny` frame does not change the reducer.
//!
//! Abstractions and assumptions. Each is a statement the paper must make explicitly.
//! * A1 Observation identity. An observation is identified by its observed prefix only.
//!   The request, reason and digest of `Member(i, deny, q, O, h)` are not represented, so two
//!   observations with equal prefix are interchangeable here. The `Deny` frame carries no
//!   request identifier.
//! * A2 Observation correspondence H(O). While `live` is false the evaluator denies, and the
//!   model lets the observed prefix be any `k <= n` with `R(k) = false`. This over-approximates
//!   the evaluator's views. That the root read corresponds to a specific prefix is assumed;
//!   `04-implementation.tex` lists it as an open obligation. I4 checks only the binding of the
//!   audit frame to the recorded observation and the value of that recorded prefix.
//! * A3 Database. Committing frame `bc` moves the physical database to `bc + 1` and sets its
//!   value by `DbApply`. Read-back returns the physical `b`. Uncertain commits are modelled by
//!   `DbCommit`; the database is not otherwise replayed except through `DbApply::Reducer`.
//! * A4 Publish order. `Publish::Split { ordered: false }` lets any queued frame publish next.
//!   `PublishGate::Any` drops any durability precondition (abstract order).
//!   `PublishGate::Durable` requires `index < d` (implemented: publish after the receipt,
//!   `governance_owner.rs:233–239` and `289`). Every result under `Any` is also a result under
//!   `Durable`, because the gate only removes transitions.
//! * A5 Repair contract. The abort repair keeps a failed `Set` frame in the log and neutralises
//!   it with an `Abort` frame later. A replayable failed record therefore exists until the abort
//!   (`witness_repair_leaves_a_replayable_failed_record`). This contradicts `03-protocol.tex`
//!   step 1 as written ("neither the new state nor a replayable committed record"), so the paper
//!   needs either an amended step 1 or a compensation argument.
//!
//! Positions. The paper numbers frames from 1, so its `i <= d` is the model's `k < d` for a
//! 0-based index `k`. The same holds for the database guard `b + 1 <= d`, which the model writes
//! as `bc < d` for the frame at index `bc`.
//!
//! Reducer. `R(k)` folds the `Set` frames among the first `k` frames in log order, skipping any
//! `Set` frame targeted by an `Abort` inside those `k` frames. `Deny` and `Abort` frames are
//! otherwise the identity. `R(n)` is the registered truth (`LiveFacts`) and `R(b)` the database
//! truth (`DBFacts`).
//!
//! Transitions, serving phase.
//! * `Append`: `Publish::Atomic` appends and publishes in one step (`live := value`).
//!   `Publish::Split` appends with status `Queued` and leaves `live` unchanged. The value is the
//!   negation of the last registered `Set` value.
//! * `Publish{ok}` (split only): the root CAS outcome for one queued frame. `ordered` restricts
//!   the choice to the oldest queued frame; `PublishGate::Durable` requires `index < d`. Failure
//!   gives `Failed` with the abort repair and `Abandoned` without it. Not gated by the sticky
//!   flag, because the root write is in memory.
//! * `Abort` (repair only): for a `Failed` frame, appends `Abort{target}` and marks the target
//!   `Aborted`. Blocked while tainted.
//! * `Observe{prefix}`: while `live` is false, a slot is free and budget remains, takes any
//!   `k <= n` with `R(k) = false` into `pending`.
//! * `AppendDeny`: removes one pending observation `seen` and appends `Deny{obs, seen}` with
//!   `obs = seen` (`ObservedPrefix`) or `obs = n` (`AuditTail`). Blocked while tainted.
//! * `Write`: `w := w + 1`. Blocked while tainted.
//! * `SyncStart`: needs no round in flight and `w > d`; captures `u := w`. Under `Sticky` it is
//!   blocked while tainted.
//! * `SyncOk`: `d := u` (`AtStart`) or `d := w` (`AtCompletion`); `S := max(S, u)` unless
//!   tainted. Under `Advances` a retry after a taint leaves `S` unchanged and clears the taint.
//! * `SyncUncertain`: the round ends unconfirmed; the taint is set and `S` is unchanged.
//! * `Ack{index}`: a governance success needs `Published` and `index < d` (or `< w` under
//!   `Written`). A DENY response needs `index < d` as well. Both are blocked while tainted (the
//!   sticky fence).
//! * `DbCommit` for frame `index = bc`: needs `!unsure` and `bc < d` (or `bc < w`, or the frame
//!   resolved). `Acked` persists the frame and sets `b = bc + 1` and `bc = bc + 1`. Under
//!   `DbCommit::ReadBack` an uncertain outcome (`UncertainPersisted` or `UncertainLost`) either
//!   advances the physical `b` or does nothing, sets `unsure`, and leaves `bc` unchanged. Under
//!   `DbCommit::NoReadBack` the client assumes success, so `bc := bc + 1` after an uncertain
//!   outcome whatever happened.
//! * `ReadBack`: while `unsure`, sets `bc := b` and clears `unsure`.
//! * `Crash{kind, r}`: allowed while the crash budget lasts, with `r` in `[S, w]`. The log is
//!   truncated to `r`, so `n = w = r`. `Process` keeps `S` (the page cache survives). `PowerLoss`
//!   sets `S := r`. Volatile fields are cleared, and `d := b`, `bc := b`, `unsure := false`.
//! * `Recover`: `live := R(r)` (or the incremental fold from `db` under the incremental apply
//!   variants). `d` is set by the open variant: `MarkDurable` (`d := r`), `SyncAtOpen`
//!   (`d := S := r`) or `FromCheckpoint` (`d := b`). `bc := b`, because the checkpoint is read
//!   back. Statuses are rebuilt for the retained log; pending, round, taint and `unsure` are
//!   cleared.
//!
//! Invariants, checked in every reachable state unless a clause says otherwise.
//! * I1: `b <= d <= w <= n` and `d <= S <= w`. In a crashed state, `b <= n` and `S <= n`.
//! * I2a: `live = R(n)` whenever no frame is `Queued` or `Failed`. Definitional under
//!   `Publish::Atomic`, where `live` is set to the newest `Set` value, which equals `R(n)` when
//!   no `Abort` exists. It is a real check only under `Split`.
//! * I2b: `db = R(b)`. Definitional under `DbApply::Reducer`, where the database stores the
//!   reducer value at its own position. It is a real check under the incremental apply variants.
//! * I2c: `bc = b` whenever `unsure` is false. This is the independent database oracle: the
//!   protocol's belief is compared with the physical database position. It is non-trivial once
//!   commits can be uncertain and the belief is not reconciled (`NoReadBack`).
//! * I3 (S-form, physical): every acked `k < S`, and an acked governance frame is `Published`.
//! * I3d (d-form, serving states only): every acked `k < d`. This is the paper's `eq:success` and
//!   `eq:deny` guard in 0-based form. `SyncAtOpen` satisfies it over the whole target graph, and
//!   the implemented open corresponds to it: since the 2026-11-21 reopen fix, the open
//!   synchronizes the retained file before claiming the scanned prefix. `FromCheckpoint` refutes
//!   it at recovery (depth 7). `MarkDurable`, the pre-sync open retained as a fault model, also
//!   refutes it, at depth 7 after a second process crash that truncates an acked but unsynced frame
//!   (`witness_mark_durable_open_without_sync_loses_an_acked_frame_on_a_second_crash`). The d-form
//!   therefore cannot certify physical safety by itself; the S-form I3 catches the same flaw at the
//!   ack (depth 5).
//! * I4: an acked `Deny{obs}` at `k` has `obs <= k` and `R(obs) = false`.
//! * I4b: an acked `Deny{obs, seen}` has `obs = seen`: the bound prefix is the prefix recorded
//!   with its observation. This is the binding check, and it does not depend on values.
//! * I5: every acked position lies in the current log, so `acked ⊆ [0, n)`. I3 implies I5 in
//!   every state, because `k >= n` implies `k >= S` (since `S <= n`). I5 therefore never fires
//!   alone and is kept only as the paper's statement.
//!
//! Bounds. `M` governance mutations, `D` DENY observations and `C` crashes are budgets over the
//! whole history, across epochs. Frames ever created are at most `M + D` in the atomic target
//! and `M + D + M` under split publish with aborts, because each abort follows a failed publish
//! and each failed publish uses a mutation. The slot guard in `successors` never prunes a
//! transition when that total is at most `SLOTS`. A larger total would be capped silently by the
//! guard and must not be read as a bound. The packed state is a `u128` with 126 bits.
//!
//! Implementation facts that the variants model. These line numbers are those recorded in the
//! original task A3 at the working tree of that time. The successor task did not re-verify them;
//! a reader must re-check them against the current tree before citing them. Commit path,
//! `astral-single-node/src/memory_v1_governance_owner.rs`: binding validation at 172, verified
//! admission against the root at 179–182, journal lock at 187–191, ledger claim at 212–221,
//! `prepare_mutation` at 224–232, `into_durable_receipt` (waits for the sync) at 233–239, lock
//! released at 261, root publish at 289 (after the lock is released). The publish CAS precondition
//! is the freshly read version in `astral-single-node/src/memory_v1_root_writer.rs` at 154–163,
//! not the version admitted at 119–133. DENY path, same file: journal lock at 364–367,
//! `prepare_deny` at 402–404, lock released before the wait at 405, both proofs minted from the one
//! frame receipt at 434–449, the state-prefix proof bound to the frame's own identity and tail
//! (445–448), and the watermark taken at registration (371–375). Durable journal,
//! `astral-single-node/src/memory_v1_durable_journal.rs`: `ensure_durable` captures the target at
//! 358, sets the confirmed end to the captured target at 383, and sets the sticky failure at
//! 398; `flush_upto` calls `sync_data` at 425 and checks the length floor at 431–434; `open`
//! synchronizes the verified retained file through `flush_upto` at 650 and plants the confirmed
//! end at 651 (the 2026-11-21 reopen fix; the pre-fix open claimed the scanned end without a sync
//! and is modeled by `MarkDurable`); the replay receipts return `durable_end = file_position` at
//! 766 and 895 and pass the `ensure_durable` fast path at 355–356 with no sync; the record cap is
//! shared by governance and DENY appends at 771 and 900; `ensure_ready` refuses prepares after a
//! known flush failure at 1066. The durable-journal numbers were re-verified at the reopen fix;
//! the governance-owner and root-writer numbers above were not re-verified.
//!
//! The file is one module of the test harness. Each test's comment lists what it establishes.
//! `cargo test -p test-harness --locked --offline --test memory_v1_journal_protocol_model` runs
//! the default suite. The ignored larger explorations document their command on the test.

use std::collections::{hash_map::Entry, HashMap, HashSet, VecDeque};
use std::sync::OnceLock;

/// memory—v1: Frame slots in the packed state. The largest default configuration needs
/// `M + D + M = 8` slots (split publish with aborts).
const SLOTS: usize = 8;

/// memory—v1: Pending DENY observation slots. Every configuration in this file has `D <= PEND`.
const PEND: usize = 3;

/// memory—v1: Four-bit marker for an absent round or an empty pending slot.
const NONE4: u8 = 15;

/// memory—v1: Violation bits, one per invariant identifier.
const I1: u16 = 1;
const I2A: u16 = 2;
const I2B: u16 = 4;
const I2C: u16 = 8;
const I3: u16 = 16;
const I3D: u16 = 32;
const I4: u16 = 64;
const I4B: u16 = 128;
const I5: u16 = 256;
const ALL: u16 = I1 | I2A | I2B | I2C | I3 | I3D | I4 | I4B | I5;

/// memory—v1: Render a violation mask as a comma-separated identifier list.
fn names(mask: u16) -> String {
    let table = [
        (I1, "I1"),
        (I2A, "I2a"),
        (I2B, "I2b"),
        (I2C, "I2c"),
        (I3, "I3"),
        (I3D, "I3d"),
        (I4, "I4"),
        (I4B, "I4b"),
        (I5, "I5"),
    ];
    table
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Queued,
    Failed,
    Published,
    Abandoned,
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame {
    Empty,
    Set { value: bool, status: Status },
    Deny { obs: u8, seen: u8 },
    Abort { target: u8 },
}

// memory—v1: Encode one frame slot in eight bits: kind in bits 0–1, payload above. A Deny carries `obs` in bits 2–4 and `seen` in bits 5–7.
fn encode(frame: Frame) -> u8 {
    match frame {
        Frame::Set { value, status } => {
            let code = match status {
                Status::Queued => 0,
                Status::Failed => 1,
                Status::Published => 2,
                Status::Abandoned => 3,
                Status::Aborted => 4,
            };
            (u8::from(value) << 2) | (code << 3)
        }
        Frame::Deny { obs, seen } => {
            assert!(obs <= 7 && seen <= 7, "deny prefixes fit in three bits");
            1 | (obs << 2) | (seen << 5)
        }
        Frame::Abort { target } => {
            assert!(target <= 7, "abort target fits in three bits");
            2 | (target << 2)
        }
        Frame::Empty => 3,
    }
}

// memory—v1: Decode one frame slot; the inverse of `encode` on every canonical byte.
fn decode(byte: u8) -> Frame {
    match byte & 3 {
        0 => {
            let status = match (byte >> 3) & 7 {
                0 => Status::Queued,
                1 => Status::Failed,
                2 => Status::Published,
                3 => Status::Abandoned,
                4 => Status::Aborted,
                other => panic!("non-canonical status code {other}"),
            };
            Frame::Set {
                value: byte & 4 != 0,
                status,
            }
        }
        1 => Frame::Deny {
            obs: (byte >> 2) & 7,
            seen: (byte >> 5) & 7,
        },
        2 => Frame::Abort {
            target: (byte >> 2) & 7,
        },
        _ => Frame::Empty,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Publish {
    /// Append and publish are one step, as in the original model.
    Atomic,
    /// The implemented order: append and sync first, then a separate publish.
    Split { abort: bool, ordered: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishGate {
    /// Any queued frame may publish (abstract order, no durability precondition).
    Any,
    /// A frame publishes only once it lies below the durable claim (implemented).
    Durable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Capture {
    AtStart,
    AtCompletion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncRetry {
    /// A failed round is sticky: nothing advances after it (implemented).
    Sticky,
    /// A later successful round may advance the claim (fault variant).
    Advances,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Open {
    /// The confirmed end is set to the scanned end with no sync (fault model
    /// of the pre-2026-11-21 open; the implemented open now corresponds to
    /// `SyncAtOpenMoment`).
    MarkDurable,
    /// A sync at open makes the scanned prefix stable (the implemented open).
    SyncAtOpenMoment,
    /// The claim restarts at the database checkpoint.
    FromCheckpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DenyBinding {
    /// The audit binds the prefix recorded at observation (target).
    ObservedPrefix,
    /// The audit binds the tail at registration (the implemented watermark).
    AuditTail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    Durable,
    Written,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DbGate {
    Durable,
    Written,
    /// Durable, and frame `bc` must be resolved (published or aborted).
    DurableResolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DbApply {
    /// Deterministic replay of the verified prefix (the paper's assumption).
    Reducer,
    /// Each step sets the database to its own frame value, whatever the status.
    Incremental,
    /// Each step sets the database to its own frame value only when the frame is `Published`
    /// at apply time; otherwise the database is unchanged.
    IncrementalPublished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DbCommit {
    /// Every commit is acknowledged; no uncertain outcome exists.
    Certain,
    /// An uncertain outcome blocks further commits until a read-back reconciles the belief (target).
    ReadBack,
    /// An uncertain outcome is taken as success without a read-back (fault variant).
    NoReadBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DbOutcome {
    Acked,
    UncertainPersisted,
    UncertainLost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashKind {
    Process,
    PowerLoss,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Crashes {
    Both,
    PowerLossOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Config {
    publish: Publish,
    publish_gate: PublishGate,
    capture: Capture,
    sync_retry: SyncRetry,
    open: Open,
    deny: DenyBinding,
    ack_gate: Gate,
    /// Whether a governance ack requires `Published` (the target does).
    ack_requires_publish: bool,
    db_gate: DbGate,
    db_apply: DbApply,
    db_commit: DbCommit,
    crashes: Crashes,
    /// Recovery is terminal, as in the original single-epoch model.
    halt_after_recovery: bool,
    mutations: u8,
    denies: u8,
    crash_budget: u8,
}

impl Config {
    // memory—v1: The target: atomic publish-first order as the frozen contract, sticky sync failure, durable gates, an uncertain database commit reconciled by read-back, and the chosen open variant.
    fn target(open: Open) -> Config {
        Config {
            publish: Publish::Atomic,
            publish_gate: PublishGate::Durable,
            capture: Capture::AtStart,
            sync_retry: SyncRetry::Sticky,
            open,
            deny: DenyBinding::ObservedPrefix,
            ack_gate: Gate::Durable,
            ack_requires_publish: true,
            db_gate: DbGate::Durable,
            db_apply: DbApply::Reducer,
            db_commit: DbCommit::ReadBack,
            crashes: Crashes::Both,
            halt_after_recovery: false,
            mutations: 3,
            denies: 2,
            crash_budget: 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct St {
    frames: [Frame; SLOTS],
    n: u8,
    w: u8,
    s: u8,
    d: u8,
    /// Physical database prefix (read back by recovery).
    b: u8,
    /// The protocol's belief about the database prefix.
    bc: u8,
    db: bool,
    live: bool,
    tainted: bool,
    crashed: bool,
    /// An uncertain database commit awaits read-back.
    unsure: bool,
    round: Option<u8>,
    /// Sorted pending DENY observations (observed prefixes); `NONE4` marks an empty slot.
    pending: [u8; PEND],
    acked: u8,
    muts: u8,
    denies: u8,
    recoveries: u8,
}

/// memory—v1: Bit writer for the packed `u128` state, most significant first.
struct Packer(u128);

impl Packer {
    // memory—v1: Append a field of `bits` width; the value must fit.
    fn push(&mut self, value: u8, bits: u32) {
        debug_assert!(u32::from(value) < (1u32 << bits), "field overflow");
        self.0 = (self.0 << bits) | u128::from(value);
    }
}

/// memory—v1: Bit reader in the reverse order of `Packer::push`.
struct Unpacker(u128);

impl Unpacker {
    // memory—v1: Remove the least significant field of `bits` width.
    fn pop(&mut self, bits: u32) -> u8 {
        let mask = (1u128 << bits) - 1;
        let value = (self.0 & mask) as u8;
        self.0 >>= bits;
        value
    }
}

impl St {
    // memory—v1: The empty log with zero budgets, no round, no pending observation, and belief equal to the database.
    fn initial() -> St {
        St {
            frames: [Frame::Empty; SLOTS],
            n: 0,
            w: 0,
            s: 0,
            d: 0,
            b: 0,
            bc: 0,
            db: false,
            live: false,
            tainted: false,
            crashed: false,
            unsure: false,
            round: None,
            pending: [NONE4; PEND],
            acked: 0,
            muts: 0,
            denies: 0,
            recoveries: 0,
        }
    }

    // memory—v1: Pack the state into 126 bits of a `u128` (the visited-set key). The push order is the reverse of the pop order in `unpack`.
    fn pack(&self) -> u128 {
        let mut out = Packer(0);
        for frame in self.frames {
            out.push(encode(frame), 8);
        }
        for field in [self.n, self.w, self.s, self.d, self.b, self.bc] {
            out.push(field, 4);
        }
        for flag in [self.db, self.live, self.tainted, self.crashed, self.unsure] {
            out.push(u8::from(flag), 1);
        }
        out.push(self.round.unwrap_or(NONE4), 4);
        for slot in self.pending {
            out.push(slot, 4);
        }
        out.push(self.acked, 8);
        for budget in [self.muts, self.denies, self.recoveries] {
            out.push(budget, 3);
        }
        out.0
    }

    // memory—v1: Unpack a key produced by `pack`; the round trip is asserted on every new state.
    fn unpack(key: u128) -> St {
        let mut input = Unpacker(key);
        let recoveries = input.pop(3);
        let denies = input.pop(3);
        let muts = input.pop(3);
        let acked = input.pop(8);
        let mut pending = [NONE4; PEND];
        for slot in (0..PEND).rev() {
            pending[slot] = input.pop(4);
        }
        let round = input.pop(4);
        let unsure = input.pop(1) != 0;
        let crashed = input.pop(1) != 0;
        let tainted = input.pop(1) != 0;
        let live = input.pop(1) != 0;
        let db = input.pop(1) != 0;
        let bc = input.pop(4);
        let b = input.pop(4);
        let d = input.pop(4);
        let s = input.pop(4);
        let w = input.pop(4);
        let n = input.pop(4);
        let mut frames = [Frame::Empty; SLOTS];
        for slot in (0..SLOTS).rev() {
            frames[slot] = decode(input.pop(8));
        }
        St {
            frames,
            n,
            w,
            s,
            d,
            b,
            bc,
            db,
            live,
            tainted,
            crashed,
            unsure,
            round: (round != NONE4).then_some(round),
            pending,
            acked,
            muts,
            denies,
            recoveries,
        }
    }

    // memory—v1: The frame at a registered position; positions at or past `n` are Empty.
    fn frame(&self, index: u8) -> Frame {
        self.frames[usize::from(index)]
    }

    // memory—v1: Append one frame at position `n`; the caller checks the slot is free.
    fn push(&mut self, frame: Frame) {
        self.frames[usize::from(self.n)] = frame;
        self.n += 1;
    }

    // memory—v1: Change the status of a Set frame; setting a status on a non-Set frame is a model error.
    fn set_status(&mut self, index: u8, status: Status) {
        match self.frame(index) {
            Frame::Set { value, .. } => {
                self.frames[usize::from(index)] = Frame::Set { value, status };
            }
            other => panic!("status change on {other:?}"),
        }
    }

    // memory—v1: Whether an Abort frame inside the first `prefix` positions targets `index`.
    fn aborted_within(&self, prefix: u8, index: u8) -> bool {
        (0..prefix).any(|j| self.frame(j) == Frame::Abort { target: index })
    }

    // memory—v1: Sequential reference reducer R(k): Set values in log order, aborted targets skipped inside the prefix, Deny and Abort as identity.
    fn reduce(&self, prefix: u8) -> bool {
        let mut value = false;
        for k in 0..prefix {
            if let Frame::Set { value: v, .. } = self.frame(k) {
                if !self.aborted_within(prefix, k) {
                    value = v;
                }
            }
        }
        value
    }

    // memory—v1: The value a new mutation toggles from: the last registered Set value, default false.
    fn intent(&self) -> bool {
        (0..self.n)
            .rev()
            .find_map(|k| match self.frame(k) {
                Frame::Set { value, .. } => Some(value),
                _ => None,
            })
            .unwrap_or(false)
    }

    // memory—v1: The oldest unpublished governance position, which ordered publish must take next.
    fn first_queued(&self) -> Option<u8> {
        (0..self.n).find(|&k| {
            matches!(
                self.frame(k),
                Frame::Set {
                    status: Status::Queued,
                    ..
                }
            )
        })
    }

    // memory—v1: Rebuild replay statuses for the retained log: Aborted iff an Abort frame in the log targets the position, otherwise Published.
    fn rebuild_statuses(&mut self) {
        for k in 0..self.n {
            if let Frame::Set { value, .. } = self.frame(k) {
                let aborted = self.aborted_within(self.n, k);
                let status = if aborted {
                    Status::Aborted
                } else {
                    Status::Published
                };
                self.frames[usize::from(k)] = Frame::Set { value, status };
            }
        }
    }

    // memory—v1: The pending observations in ascending order, without the empty markers.
    fn pending_values(&self) -> Vec<u8> {
        self.pending
            .iter()
            .copied()
            .take_while(|&h| h != NONE4)
            .collect()
    }

    // memory—v1: The number of pending observations.
    fn pending_len(&self) -> usize {
        self.pending_values().len()
    }

    // memory—v1: Replace the pending multiset; the caller passes at most `PEND` values in ascending order.
    fn set_pending(&mut self, values: &[u8]) {
        debug_assert!(values.len() <= PEND, "pending multiset exceeds its slots");
        let mut slots = [NONE4; PEND];
        for (slot, value) in slots.iter_mut().zip(values) {
            *slot = *value;
        }
        self.pending = slots;
    }

    // memory—v1: Add one observed prefix to the pending multiset, keeping it sorted.
    fn add_pending(&mut self, prefix: u8) {
        let mut values = self.pending_values();
        values.push(prefix);
        values.sort_unstable();
        self.set_pending(&values);
    }

    // memory—v1: Evaluate I1–I5 (and I2c, I3d, I4b) on this state; the returned mask lists every violated identifier.
    fn violations(&self) -> u16 {
        let mut mask: u16 = 0;
        let ordered = self.b <= self.d
            && self.d <= self.w
            && self.w <= self.n
            && self.d <= self.s
            && self.s <= self.w;
        let retained = self.b <= self.n && self.s <= self.n;
        if (self.crashed && !retained) || (!self.crashed && !ordered) {
            mask |= I1;
        }
        let pending = (0..self.n).any(|k| {
            matches!(
                self.frame(k),
                Frame::Set {
                    status: Status::Queued | Status::Failed,
                    ..
                }
            )
        });
        if !self.crashed && !pending && self.live != self.reduce(self.n) {
            mask |= I2A;
        }
        if self.db != self.reduce(self.b) {
            mask |= I2B;
        }
        if !self.unsure && self.bc != self.b {
            mask |= I2C;
        }
        for k in 0..SLOTS as u8 {
            if self.acked & (1u8 << k) == 0 {
                continue;
            }
            if k >= self.n {
                mask |= I5;
            }
            if k >= self.s {
                mask |= I3;
            }
            if !self.crashed && k >= self.d {
                mask |= I3D;
            }
            if k < self.n {
                match self.frame(k) {
                    Frame::Set { status, .. } => {
                        if status != Status::Published {
                            mask |= I3;
                        }
                    }
                    Frame::Deny { obs, seen } => {
                        if obs > k || self.reduce(obs) {
                            mask |= I4;
                        }
                        if obs != seen {
                            mask |= I4B;
                        }
                    }
                    _ => mask |= I3,
                }
            }
        }
        mask
    }

    // memory—v1: Model integrity, asserted in tests and debug builds: slot discipline, abort/status agreement, Deny ordering and pending canonical form. Protocol properties such as `b <= n` after a crash are deliberately not here: they are the violations I1 reports.
    fn well_formed(&self) -> bool {
        let n = self.n;
        let slots_ok = (0..SLOTS as u8).all(|k| (k < n) || self.frame(k) == Frame::Empty);
        let frames_ok = (0..n).all(|k| match self.frame(k) {
            Frame::Set { status, .. } => (status == Status::Aborted) == self.aborted_within(n, k),
            Frame::Abort { target } => {
                target < k
                    && matches!(
                        self.frame(target),
                        Frame::Set {
                            status: Status::Aborted,
                            ..
                        }
                    )
            }
            Frame::Deny { obs, seen } => seen <= obs && obs <= k,
            Frame::Empty => false,
        });
        let pending = self.pending_values();
        let pending_ok =
            pending.iter().all(|&h| h <= n) && pending.windows(2).all(|p| p[0] <= p[1]);
        let tail_ok = self.pending[pending.len()..].iter().all(|&h| h == NONE4);
        slots_ok
            && frames_ok
            && pending_ok
            && tail_ok
            && self.w <= n
            && self.s <= self.w
            && self.round.is_none_or(|u| u <= self.w)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Append {
        value: bool,
        index: u8,
        atomic: bool,
    },
    Publish {
        index: u8,
        ok: bool,
    },
    Abort {
        target: u8,
        index: u8,
    },
    Observe {
        prefix: u8,
    },
    AppendDeny {
        index: u8,
        obs: u8,
        seen: u8,
    },
    Write {
        index: u8,
    },
    SyncStart {
        target: u8,
    },
    SyncOk,
    SyncUncertain,
    Ack {
        index: u8,
        deny: bool,
    },
    DbCommit {
        index: u8,
        outcome: DbOutcome,
    },
    ReadBack {
        to: u8,
    },
    Crash {
        kind: CrashKind,
        retained: u8,
    },
    Recover,
}

impl Step {
    // memory—v1: Readable label used in the pinned counterexample traces.
    fn label(self) -> String {
        match self {
            Step::Append {
                value,
                index,
                atomic,
            } => {
                let verb = if atomic { "append+publish" } else { "append" };
                format!("{verb} set({value})@{index}")
            }
            Step::Publish { index, ok } => {
                format!("publish@{index} {}", if ok { "ok" } else { "fail" })
            }
            Step::Abort { target, index } => format!("abort@{target} as {index}"),
            Step::Observe { prefix } => format!("observe prefix {prefix}"),
            Step::AppendDeny { index, obs, seen } => {
                if obs == seen {
                    format!("append deny@{index} obs={obs}")
                } else {
                    format!("append deny@{index} obs={obs} seen={seen}")
                }
            }
            Step::Write { index } => format!("write@{index}"),
            Step::SyncStart { target } => format!("sync start u={target}"),
            Step::SyncOk => "sync ok".to_string(),
            Step::SyncUncertain => "sync uncertain".to_string(),
            Step::Ack { index, deny } => {
                format!("ack {}@{index}", if deny { "deny" } else { "gov" })
            }
            Step::DbCommit { index, outcome } => match outcome {
                DbOutcome::Acked => format!("db apply@{index}"),
                DbOutcome::UncertainPersisted => format!("db apply@{index} uncertain persisted"),
                DbOutcome::UncertainLost => format!("db apply@{index} uncertain lost"),
            },
            Step::ReadBack { to } => format!("read back b={to}"),
            Step::Crash { kind, retained } => {
                let name = match kind {
                    CrashKind::Process => "process",
                    CrashKind::PowerLoss => "power",
                };
                format!("crash {name} retain={retained}")
            }
            Step::Recover => "recover".to_string(),
        }
    }
}

// memory—v1: The database value after committing frame `index`, which moves the database position to `index + 1`.
fn db_after_commit(st: &St, index: u8, apply: DbApply) -> bool {
    match apply {
        DbApply::Reducer => st.reduce(index + 1),
        DbApply::Incremental => match st.frame(index) {
            Frame::Set { value, .. } => value,
            _ => st.db,
        },
        DbApply::IncrementalPublished => match st.frame(index) {
            Frame::Set {
                value,
                status: Status::Published,
            } => value,
            _ => st.db,
        },
    }
}

// memory—v1: Recovery from a crashed state: read back the database checkpoint, replay the retained log, and set the claim by the open variant.
fn recover(st: &St, cfg: &Config) -> St {
    let r = st.n;
    let mut next = *st;
    next.live = match cfg.db_apply {
        DbApply::Reducer => st.reduce(r),
        DbApply::Incremental | DbApply::IncrementalPublished => {
            let mut value = st.db;
            for k in st.b..r {
                if let Frame::Set { value: v, .. } = st.frame(k) {
                    if !st.aborted_within(r, k) {
                        value = v;
                    }
                }
            }
            value
        }
    };
    next.d = match cfg.open {
        Open::MarkDurable | Open::SyncAtOpenMoment => r,
        Open::FromCheckpoint => st.b,
    };
    if cfg.open == Open::SyncAtOpenMoment {
        next.s = r;
    }
    next.w = r;
    next.bc = st.b;
    next.unsure = false;
    next.round = None;
    next.tainted = false;
    next.pending = [NONE4; PEND];
    next.crashed = false;
    next.recoveries += 1;
    next.rebuild_statuses();
    next
}

// memory—v1: Every enabled transition of one state, in a fixed order; the crashed phase has only Recover.
fn successors(st: &St, cfg: &Config, out: &mut Vec<(Step, St)>) {
    out.clear();
    if st.crashed {
        out.push((Step::Recover, recover(st, cfg)));
        return;
    }
    if cfg.halt_after_recovery && st.recoveries > 0 {
        return;
    }
    let free = usize::from(st.n) < SLOTS;

    if st.muts < cfg.mutations && free && !st.tainted {
        let value = !st.intent();
        let atomic = cfg.publish == Publish::Atomic;
        let mut next = *st;
        next.push(Frame::Set {
            value,
            status: if atomic {
                Status::Published
            } else {
                Status::Queued
            },
        });
        next.muts += 1;
        if atomic {
            next.live = value;
        }
        out.push((
            Step::Append {
                value,
                index: st.n,
                atomic,
            },
            next,
        ));
    }

    if let Publish::Split { abort, ordered } = cfg.publish {
        for k in 0..st.n {
            if !matches!(
                st.frame(k),
                Frame::Set {
                    status: Status::Queued,
                    ..
                }
            ) {
                continue;
            }
            if ordered && st.first_queued() != Some(k) {
                continue;
            }
            if cfg.publish_gate == PublishGate::Durable && k >= st.d {
                continue;
            }
            if let Frame::Set { value, .. } = st.frame(k) {
                let mut ok = *st;
                ok.set_status(k, Status::Published);
                ok.live = value;
                out.push((Step::Publish { index: k, ok: true }, ok));
                let mut failed = *st;
                failed.set_status(
                    k,
                    if abort {
                        Status::Failed
                    } else {
                        Status::Abandoned
                    },
                );
                out.push((
                    Step::Publish {
                        index: k,
                        ok: false,
                    },
                    failed,
                ));
            }
        }
        if abort && free && !st.tainted {
            for k in 0..st.n {
                if matches!(
                    st.frame(k),
                    Frame::Set {
                        status: Status::Failed,
                        ..
                    }
                ) {
                    let mut next = *st;
                    next.set_status(k, Status::Aborted);
                    let index = next.n;
                    next.push(Frame::Abort { target: k });
                    out.push((Step::Abort { target: k, index }, next));
                }
            }
        }
    }

    if !st.live && st.denies < cfg.denies && free && st.pending_len() < PEND {
        for prefix in 0..=st.n {
            if !st.reduce(prefix) {
                let mut next = *st;
                next.add_pending(prefix);
                next.denies += 1;
                out.push((Step::Observe { prefix }, next));
            }
        }
    }

    if free && !st.tainted {
        let values = st.pending_values();
        for (i, &seen) in values.iter().enumerate() {
            if i > 0 && values[i - 1] == seen {
                continue;
            }
            let obs = match cfg.deny {
                DenyBinding::ObservedPrefix => seen,
                DenyBinding::AuditTail => st.n,
            };
            let mut rest = values.clone();
            rest.remove(i);
            let mut next = *st;
            next.push(Frame::Deny { obs, seen });
            next.set_pending(&rest);
            out.push((
                Step::AppendDeny {
                    index: st.n,
                    obs,
                    seen,
                },
                next,
            ));
        }
    }

    if st.w < st.n && !st.tainted {
        let mut next = *st;
        next.w += 1;
        out.push((Step::Write { index: st.w }, next));
    }

    let may_start = !st.tainted || cfg.sync_retry == SyncRetry::Advances;
    if st.round.is_none() && st.w > st.d && may_start {
        let mut next = *st;
        next.round = Some(st.w);
        out.push((Step::SyncStart { target: st.w }, next));
    }

    if let Some(u) = st.round {
        let mut ok = *st;
        ok.round = None;
        ok.d = match cfg.capture {
            Capture::AtStart => u,
            Capture::AtCompletion => st.w,
        };
        if st.tainted {
            ok.tainted = false;
        } else {
            ok.s = st.s.max(u);
        }
        out.push((Step::SyncOk, ok));
        let mut bad = *st;
        bad.round = None;
        bad.tainted = true;
        out.push((Step::SyncUncertain, bad));
    }

    if !st.tainted {
        let bound = match cfg.ack_gate {
            Gate::Durable => st.d,
            Gate::Written => st.w,
        };
        for k in 0..bound.min(st.n) {
            if st.acked & (1u8 << k) != 0 {
                continue;
            }
            let (eligible, deny) = match st.frame(k) {
                Frame::Set { status, .. } => (
                    status == Status::Published || !cfg.ack_requires_publish,
                    false,
                ),
                Frame::Deny { .. } => (true, true),
                _ => (false, false),
            };
            if eligible {
                let mut next = *st;
                next.acked |= 1u8 << k;
                out.push((Step::Ack { index: k, deny }, next));
            }
        }
    }

    let bound = match cfg.db_gate {
        DbGate::Written => st.w,
        DbGate::Durable | DbGate::DurableResolved => st.d,
    };
    if !st.unsure && st.bc < bound {
        let index = st.bc;
        let resolved = !matches!(
            st.frame(index),
            Frame::Set {
                status: Status::Queued | Status::Failed | Status::Abandoned,
                ..
            }
        );
        if cfg.db_gate != DbGate::DurableResolved || resolved {
            let value = db_after_commit(st, index, cfg.db_apply);
            let mut acked = *st;
            acked.b = index + 1;
            acked.bc = index + 1;
            acked.db = value;
            out.push((
                Step::DbCommit {
                    index,
                    outcome: DbOutcome::Acked,
                },
                acked,
            ));
            if cfg.db_commit != DbCommit::Certain {
                let mut persisted = *st;
                persisted.b = index + 1;
                persisted.db = value;
                let mut lost = *st;
                match cfg.db_commit {
                    DbCommit::ReadBack => {
                        persisted.unsure = true;
                        lost.unsure = true;
                    }
                    DbCommit::NoReadBack => {
                        persisted.bc = index + 1;
                        lost.bc = index + 1;
                    }
                    DbCommit::Certain => {}
                }
                out.push((
                    Step::DbCommit {
                        index,
                        outcome: DbOutcome::UncertainPersisted,
                    },
                    persisted,
                ));
                out.push((
                    Step::DbCommit {
                        index,
                        outcome: DbOutcome::UncertainLost,
                    },
                    lost,
                ));
            }
        }
    }

    if st.unsure {
        let mut next = *st;
        next.bc = st.b;
        next.unsure = false;
        out.push((Step::ReadBack { to: st.b }, next));
    }

    if st.recoveries < cfg.crash_budget {
        let kinds: &[CrashKind] = match cfg.crashes {
            Crashes::Both => &[CrashKind::Process, CrashKind::PowerLoss],
            Crashes::PowerLossOnly => &[CrashKind::PowerLoss],
        };
        for r in st.s..=st.w {
            for &kind in kinds {
                let mut next = *st;
                for slot in usize::from(r)..SLOTS {
                    next.frames[slot] = Frame::Empty;
                }
                next.n = r;
                next.w = r;
                if kind == CrashKind::PowerLoss {
                    next.s = r;
                }
                next.d = st.b;
                next.live = false;
                next.tainted = false;
                next.round = None;
                next.pending = [NONE4; PEND];
                next.unsure = false;
                next.bc = st.b;
                next.crashed = true;
                next.rebuild_statuses();
                out.push((Step::Crash { kind, retained: r }, next));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Witness {
    ack_governance: u64,
    ack_deny_at_zero: u64,
    ack_deny_after_mutation: u64,
    batch_confirm: u64,
    sync_ok_after_taint: u64,
    uncertain_states: u64,
    withheld_visible: u64,
    volatile_loss: u64,
    retained_beyond_durable: u64,
    second_epoch_acked: u64,
    db_persisted_uncertain: u64,
    db_lost_uncertain: u64,
    read_back_corrects: u64,
    read_back_confirms: u64,
    two_pending_states: u64,
}

#[derive(Clone, Debug)]
struct Found {
    ids: u16,
    depth: u32,
    trace: String,
}

#[derive(Clone, Debug, Default)]
struct Run {
    states: usize,
    edges: usize,
    max_depth: u32,
    stopped: bool,
    found: Vec<Found>,
    witness: Witness,
    same_frontier_live: usize,
    same_frontier_with_w_live: usize,
    i5_states: usize,
    i5_without_i3: usize,
    goal: Option<(u32, String)>,
}

impl Run {
    // memory—v1: The union of violated identifiers over every recorded state; each new bit is recorded once, so the union is the union over all states.
    fn violated_bits(&self) -> u16 {
        self.found.iter().fold(0, |acc, found| acc | found.ids)
    }
}

// memory—v1: Edge counters: necessity witnesses, batch confirmation, uncertain database outcomes and the fault mechanisms.
fn count_edge(st: &St, step: Step, next: &St, cfg: &Config, witness: &mut Witness) {
    match step {
        Step::SyncOk => {
            if st.tainted {
                witness.sync_ok_after_taint += 1;
            }
            if next.d >= st.d + 2 {
                witness.batch_confirm += 1;
            }
        }
        Step::Ack { index, deny } => {
            if deny {
                if let Frame::Deny { obs, .. } = st.frame(index) {
                    if obs == 0 {
                        witness.ack_deny_at_zero += 1;
                    } else {
                        witness.ack_deny_after_mutation += 1;
                    }
                }
            } else {
                witness.ack_governance += 1;
            }
        }
        Step::Crash { retained, .. } => {
            if retained > st.d {
                witness.retained_beyond_durable += 1;
            }
            let recovered = recover(next, cfg);
            if st.live != st.reduce(st.d) && recovered.live != st.live {
                witness.volatile_loss += 1;
            }
        }
        Step::Recover => {
            if next.recoveries >= 2 && next.acked != 0 {
                witness.second_epoch_acked += 1;
            }
        }
        Step::DbCommit {
            outcome: DbOutcome::UncertainPersisted,
            ..
        } => witness.db_persisted_uncertain += 1,
        Step::DbCommit {
            outcome: DbOutcome::UncertainLost,
            ..
        } => witness.db_lost_uncertain += 1,
        Step::ReadBack { .. } => {
            if st.bc != st.b {
                witness.read_back_corrects += 1;
            } else {
                witness.read_back_confirms += 1;
            }
        }
        _ => {}
    }
}

// memory—v1: A withheld governance success that is already visible: the newest Set frame is published, unacked and live equals its value.
fn withheld(st: &St) -> bool {
    (0..st.n)
        .rev()
        .find_map(|k| match st.frame(k) {
            Frame::Set { value, status } => Some((k, value, status)),
            _ => None,
        })
        .is_some_and(|(k, value, status)| {
            status == Status::Published && st.acked & (1u8 << k) == 0 && st.live == value
        })
}

// memory—v1: The shortest path to a state, rebuilt from the parent links in BFS order.
fn trace_of(parent: &HashMap<u128, Option<(u128, Step)>>, key: u128) -> String {
    let mut steps = Vec::new();
    let mut cursor = key;
    while let Some(Some((previous, step))) = parent.get(&cursor) {
        steps.push(*step);
        cursor = *previous;
    }
    steps.reverse();
    steps
        .iter()
        .map(|step| step.label())
        .collect::<Vec<_>>()
        .join(" -> ")
}

enum Visited {
    Traced(HashMap<u128, Option<(u128, Step)>>),
    Compact(HashSet<u128>),
}

impl Visited {
    // memory—v1: Deduplicate by the same packed key; keep predecessors only for trace runs.
    fn insert(&mut self, key: u128, previous: impl FnOnce() -> Option<(u128, Step)>) -> bool {
        match self {
            Self::Traced(parent) => match parent.entry(key) {
                Entry::Occupied(_) => false,
                Entry::Vacant(entry) => {
                    entry.insert(previous());
                    true
                }
            },
            Self::Compact(seen) => seen.insert(key),
        }
    }

    // memory—v1: A compact failure still records the exact packed state and BFS depth.
    fn witness(&self, key: u128) -> String {
        match self {
            Self::Traced(parent) => trace_of(parent, key),
            Self::Compact(_) => format!("state={key:032x} {:?}", St::unpack(key)),
        }
    }
}

// memory—v1: Breadth-first search over packed states. It stops at the first state whose violations intersect `stop` (`stop == 0` explores the whole graph) or, when given, at the first state satisfying `goal`.
fn explore_with(cfg: Config, stop: u16, goal: Option<fn(&St) -> bool>) -> Run {
    explore_with_visited(cfg, stop, goal, Visited::Traced(HashMap::new()), false)
}

// memory—v1: Share transitions, invariants and FIFO traversal between both storage modes.
fn explore_with_visited(
    cfg: Config,
    stop: u16,
    goal: Option<fn(&St) -> bool>,
    mut visited: Visited,
    progress: bool,
) -> Run {
    assert!(
        usize::from(cfg.denies) <= PEND,
        "pending slots must cover the DENY budget"
    );
    let initial = St::initial();
    let mut run = Run::default();
    let mut queue: VecDeque<(St, u32)> = VecDeque::new();
    let mut frontier: HashMap<(u8, u8, u8), u8> = HashMap::new();
    let mut frontier_w: HashMap<(u8, u8, u8, u8), u8> = HashMap::new();
    let mut seen_ids = 0u16;
    let mut buffer = Vec::new();
    visited.insert(initial.pack(), || None);
    queue.push_back((initial, 0));
    while let Some((state, depth)) = queue.pop_front() {
        run.states += 1;
        run.max_depth = run.max_depth.max(depth);
        if progress && run.states.is_multiple_of(1_000_000) {
            eprintln!(
                "repair full progress: states={} transitions={} depth={} queued={}",
                run.states,
                run.edges,
                run.max_depth,
                queue.len()
            );
        }
        if !state.crashed {
            let bit = 1u8 << u8::from(state.live);
            *frontier.entry((state.b, state.d, state.s)).or_default() |= bit;
            *frontier_w
                .entry((state.b, state.d, state.s, state.w))
                .or_default() |= bit;
        }
        if state.tainted {
            run.witness.uncertain_states += 1;
        }
        if !state.crashed && withheld(&state) {
            run.witness.withheld_visible += 1;
        }
        if state.pending_len() >= 2 {
            run.witness.two_pending_states += 1;
        }
        successors(&state, &cfg, &mut buffer);
        for (step, next) in buffer.drain(..) {
            run.edges += 1;
            count_edge(&state, step, &next, &cfg, &mut run.witness);
            let key = next.pack();
            if !visited.insert(key, || Some((state.pack(), step))) {
                continue;
            }
            debug_assert!(next.well_formed(), "malformed model state {next:?}");
            debug_assert_eq!(St::unpack(key), next, "packing is not a bijection");
            let ids = next.violations();
            if ids & I5 != 0 {
                run.i5_states += 1;
                if ids & I3 == 0 {
                    run.i5_without_i3 += 1;
                }
            }
            if ids != 0 && ids & !seen_ids != 0 {
                seen_ids |= ids;
                run.found.push(Found {
                    ids,
                    depth: depth + 1,
                    trace: visited.witness(key),
                });
            }
            if ids & stop != 0 {
                run.stopped = true;
                return run;
            }
            if goal.is_some_and(|reached| reached(&next)) {
                run.goal = Some((depth + 1, visited.witness(key)));
                return run;
            }
            queue.push_back((next, depth + 1));
        }
    }
    run.same_frontier_live = frontier.values().filter(|&&mask| mask == 3).count();
    run.same_frontier_with_w_live = frontier_w.values().filter(|&&mask| mask == 3).count();
    run
}

// memory—v1: Breadth-first search with a violation stop mask and no goal.
fn explore(cfg: Config, stop: u16) -> Run {
    explore_with(cfg, stop, None)
}

// memory—v1: The reachable goal with the shortest depth and its trace; panics if the goal is not reached within the bounds.
fn goal_trace(cfg: Config, goal: fn(&St) -> bool) -> (u32, String) {
    explore_with(cfg, 0, Some(goal))
        .goal
        .expect("the goal is reachable within the bounds")
}

// memory—v1: Goal: two DENY observations are pending at distinct observed prefixes.
fn two_distinct_pending(st: &St) -> bool {
    let values = st.pending_values();
    values.len() == 2 && values[0] != values[1]
}

// memory—v1: Goal: a Set frame is Failed below the durable claim, so a replayable failed record exists until its abort.
fn replayable_failed_record(st: &St) -> bool {
    (0..st.d).any(|k| {
        matches!(
            st.frame(k),
            Frame::Set {
                status: Status::Failed,
                ..
            }
        )
    })
}

// memory—v1: Configuration of the target with sync-on-open, explored once and cached for all target and witness tests.
fn target_sync_on_open() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| explore(Config::target(Open::SyncAtOpenMoment), 0))
}

// memory—v1: The target with recovery from the database checkpoint, explored once and cached.
fn target_from_checkpoint() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| explore(Config::target(Open::FromCheckpoint), 0))
}

// memory—v1: Target (sync-on-open, uncertain database commits reconciled by read-back) satisfies every invariant in every reachable state; the explored graph and I5 are pinned. I2a and I2b are definitional for this configuration (see the module doc), so the non-trivial content is I1, I2c, I3, I3d, I4 and I4b.
#[test]
fn target_sync_on_open_satisfies_every_invariant_over_the_full_graph() {
    let run = target_sync_on_open();
    println!(
        "target sync-on-open: {} states, {} transitions, depth {}",
        run.states, run.edges, run.max_depth
    );
    assert!(!run.stopped);
    assert!(run.found.is_empty(), "violations: {:?}", run.found);
    assert_eq!(
        (run.states, run.edges),
        (455_582, 2_776_180),
        "pinned target graph"
    );
    assert_eq!(run.max_depth, 28, "pinned depth");
    assert_eq!(run.i5_states, 0, "I5 never fires in the target");
    assert_eq!(run.i5_without_i3, 0, "I5 never fires without I3");
}

// memory—v1: The from-checkpoint open keeps the S-form invariants and the database invariants, and refutes only the d-form I3d (at recovery; see the fault test). Pins the explored graph.
#[test]
fn from_checkpoint_keeps_the_s_form_and_refutes_only_the_d_form() {
    let run = target_from_checkpoint();
    println!(
        "target from-checkpoint: {} states, {} transitions, depth {}",
        run.states, run.edges, run.max_depth
    );
    assert!(!run.stopped);
    assert_eq!(
        names(run.violated_bits()),
        names(I3D),
        "only the d-form fails"
    );
    assert_eq!(
        (run.states, run.edges),
        (603_278, 3_312_072),
        "pinned from-checkpoint graph"
    );
    assert_eq!(run.max_depth, 29, "pinned from-checkpoint depth");
}

// memory—v1: F7-style structural note: sticky failure blocks SyncStart and Ack while tainted, so no successful round follows an uncertain round in the target. This is a consequence of the guard, not evidence; the non-structural counterpart is `fault_retry_after_uncertain_round_advances_the_claim`.
#[test]
fn target_uncertain_round_is_sticky_structurally_and_never_followed_by_a_success() {
    let run = target_sync_on_open();
    assert!(
        run.witness.uncertain_states > 0,
        "uncertain states are reachable"
    );
    assert_eq!(run.witness.sync_ok_after_taint, 0);
}

// memory—v1: Target database uncertainty is exercised and reconciled: persisted and lost uncertain commits are reachable, and read-back corrects the belief after a persisted commit and confirms it after a lost one.
#[test]
fn target_database_uncertainty_is_reconciled_by_read_back() {
    let run = target_sync_on_open();
    let w = run.witness;
    println!(
        "db uncertainty: persisted {}, lost {}, read-back corrects {}, read-back confirms {}",
        w.db_persisted_uncertain, w.db_lost_uncertain, w.read_back_corrects, w.read_back_confirms
    );
    assert!(w.db_persisted_uncertain > 0);
    assert!(w.db_lost_uncertain > 0);
    assert!(w.read_back_corrects > 0);
    assert!(w.read_back_confirms > 0);
}

// memory—v1: Run one configuration until a state violates `stop`; return the record of that stopping state.
fn stopping_violation(cfg: Config, stop: u16) -> Found {
    let run = explore(cfg, stop);
    assert!(
        run.stopped,
        "no violation of {} within the bounds",
        names(stop)
    );
    run.found
        .last()
        .cloned()
        .expect("a stopping run records its violation")
}

// memory—v1: Assert the identifiers, the shortest depth and the readable shortest trace of one violation.
fn expect_violation(found: &Found, ids: u16, depth: u32, trace: &str) {
    assert_eq!(names(found.ids), names(ids), "violated identifiers");
    assert_eq!(found.depth, depth, "shortest depth");
    assert_eq!(found.trace, trace, "shortest trace");
}

// memory—v1: The target with the implemented split publish (no durability precondition, abstract order), varying only the abort repair and the ordering.
fn split(abort: bool, ordered: bool) -> Config {
    Config {
        publish: Publish::Split { abort, ordered },
        publish_gate: PublishGate::Any,
        ..Config::target(Open::SyncAtOpenMoment)
    }
}

// memory—v1: The split publish with the production durability gate (publish only below the durable claim).
fn gated_split(abort: bool, ordered: bool) -> Config {
    Config {
        publish_gate: PublishGate::Durable,
        ..split(abort, ordered)
    }
}

// memory—v1: F1 under the abstract order: a failed publish with no abort leaves a durable frame that live never applied (I2a at depth 2). Asserts current behaviour disclosed as a gap; update when fixed. Gap: governance_owner.rs:289–291 returns after a durable append with no abort frame. The depth is abstract: the publish needs no durability in this order.
#[test]
fn witness_current_append_first_publish_failure_breaks_i2a() {
    let found = stopping_violation(split(false, false), ALL);
    expect_violation(&found, I2A, 2, "append set(true)@0 -> publish@0 fail");
}

// memory—v1: F1 under the production durability gate: the failed publish comes after the sync, and no abort frame follows, so I2a is violated at depth 5. Asserts current behaviour disclosed as a gap; update when fixed. Gap: governance_owner.rs:233–239 waits for the receipt, then 289–291 returns with no abort.
#[test]
fn witness_gated_append_first_publish_failure_breaks_i2a() {
    let found = stopping_violation(gated_split(false, false), ALL);
    expect_violation(
        &found,
        I2A,
        5,
        "append set(true)@0 -> write@0 -> sync start u=1 -> sync ok -> publish@0 fail",
    );
}

// memory—v1: F2 under the abstract order: publish order may differ from journal order (I2a at depth 4). Asserts current behaviour disclosed as a gap; update when fixed. Gap: publish runs after the journal lock is released (governance_owner.rs:261 then 289). The depth is abstract.
#[test]
fn witness_current_publish_order_may_differ_from_journal_order() {
    let found = stopping_violation(split(true, false), ALL);
    expect_violation(
        &found,
        I2A,
        4,
        "append set(true)@0 -> append set(false)@1 -> publish@1 ok -> publish@0 ok",
    );
}

// memory—v1: F2 under the production durability gate: both frames must be below the claim before they publish, so the reordering needs two writes and one sync (I2a at depth 8). Asserts current behaviour disclosed as a gap; update when fixed. Gap: governance_owner.rs:261 releases the lock before publish at 289, so a delayed publisher can run after a later frame's publish.
#[test]
fn witness_gated_publish_order_may_differ_from_journal_order() {
    let found = stopping_violation(gated_split(true, false), ALL);
    expect_violation(
        &found,
        I2A,
        8,
        "append set(true)@0 -> append set(false)@1 -> write@0 -> write@1 -> sync start u=2 -> sync ok -> publish@1 ok -> publish@0 ok",
    );
}

// memory—v1: F3a, ordered publish without the abort repair: a failed publish still leaves a durable frame with no resolution (I2a at depth 2, abstract order).
#[test]
fn fault_ordered_publish_without_abort_still_breaks_i2a() {
    let found = stopping_violation(split(false, true), ALL);
    expect_violation(&found, I2A, 2, "append set(true)@0 -> publish@0 fail");
}

// memory—v1: F12, a governance success issued for a queued frame before its publish: the published clause of I3 fails (depth 5).
#[test]
fn fault_ack_before_publish_breaks_the_published_clause() {
    let cfg = Config {
        ack_requires_publish: false,
        ..split(true, true)
    };
    let run = explore(cfg, I3);
    assert!(run.stopped);
    let found = run.found.last().expect("I3 stopping state");
    expect_violation(
        found,
        I3,
        5,
        "append set(true)@0 -> write@0 -> sync start u=1 -> sync ok -> ack gov@0",
    );
}

// memory—v1: Candidate repair (abort plus ordered publish, reducer database) at the reduced bounds used by the default run (M=2, D=2, C=2) under the abstract publish order, which implies the durable gate. No violation in the bounded graph. Pins the explored graph; the default bounds are in the ignored test below.
#[test]
fn repair_abort_plus_ordered_publish_reduced_bounds_has_no_violation() {
    let cfg = Config {
        mutations: 2,
        denies: 2,
        crash_budget: 2,
        ..split(true, true)
    };
    let run = explore(cfg, 0);
    println!(
        "repair abort+ordered reduced: {} states, {} transitions, depth {}",
        run.states, run.edges, run.max_depth
    );
    assert!(!run.stopped);
    assert!(run.found.is_empty(), "violations: {:?}", run.found);
    assert_eq!(
        (run.states, run.edges),
        (2_467_413, 17_250_886),
        "pinned reduced repair graph"
    );
    assert_eq!(run.max_depth, 31, "pinned reduced repair depth");
    let compact = explore_with_visited(cfg, 0, None, Visited::Compact(HashSet::new()), false);
    assert_eq!(
        (compact.states, compact.edges, compact.max_depth),
        (run.states, run.edges, run.max_depth)
    );
    assert_eq!(compact.witness, run.witness);
    assert_eq!(compact.violated_bits(), run.violated_bits());
    assert!(!compact.stopped);
}

// memory—v1: Candidate repair at the full default bounds (M=3, D=2, C=2) under the same
// abstract publish order. Store only the visited keys for this no-violation exploration;
// a failure records its packed state and depth, not a predecessor chain. No result is pinned.
#[test]
#[ignore = "far larger than the default budget; run explicitly with a resource limit"]
fn repair_abort_plus_ordered_publish_full_bounds_has_no_violation() {
    let run = explore_with_visited(
        split(true, true),
        0,
        None,
        Visited::Compact(HashSet::new()),
        true,
    );
    println!(
        "repair abort+ordered: {} states, {} transitions, depth {}",
        run.states, run.edges, run.max_depth
    );
    assert!(!run.stopped);
    assert!(run.found.is_empty(), "violations: {:?}", run.found);
}

// memory—v1: A5, the abort repair against step 1: a publish that fails before the frame is durable leaves a Failed frame that the next sync makes durable. The record is then replayable until its Abort frame is appended, which contradicts `03-protocol.tex` step 1 as written ("neither the new state nor a replayable committed record"). The shortest such state is at depth 5. The repair is therefore a compensation, not the step as stated.
#[test]
fn witness_repair_leaves_a_replayable_failed_record() {
    let (depth, trace) = goal_trace(split(true, false), replayable_failed_record);
    assert_eq!(depth, 5, "shortest depth of a replayable failed record");
    assert_eq!(
        trace, "append set(true)@0 -> publish@0 fail -> write@0 -> sync start u=1 -> sync ok",
        "shortest trace"
    );
}

// memory—v1: F11, the repair with an incremental database apply: the frame applied after its abort is already in the log takes the aborted value, so the database fact diverges from R(b) (I2b at depth 9). The naive apply ignores the status, so the abort cannot undo it.
#[test]
fn fault_incremental_database_apply_cannot_undo_an_aborted_frame() {
    let cfg = Config {
        db_apply: DbApply::Incremental,
        ..split(true, true)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I2B,
        9,
        "append set(true)@0 -> publish@0 fail -> abort@0 as 1 -> write@0 -> write@1 -> sync start u=2 -> sync ok -> db apply@0 -> db apply@1",
    );
}

// memory—v1: F3d, the candidate repair of F11 with a resolved database gate: the gate admits the aborted frame because it is resolved, so the same I2b state appears (depth 9), and recovery from the checkpoint then carries the aborted value into live (I2a at depth 10). Refuted candidate: the resolved gate alone is not a repair.
#[test]
fn candidate_resolved_gate_with_incremental_apply_is_refuted() {
    let cfg = Config {
        db_apply: DbApply::Incremental,
        db_gate: DbGate::DurableResolved,
        ..split(true, true)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I2B,
        9,
        "append set(true)@0 -> publish@0 fail -> abort@0 as 1 -> write@0 -> write@1 -> sync start u=2 -> sync ok -> db apply@0 -> db apply@1",
    );
    let run = explore(cfg, I2A);
    let found = run.found.last().expect("I2a stopping state");
    expect_violation(
        found,
        I2A,
        10,
        "append set(true)@0 -> publish@0 fail -> abort@0 as 1 -> write@0 -> write@1 -> sync start u=2 -> sync ok -> db apply@0 -> crash process retain=2 -> recover",
    );
}

// memory—v1: F13, a status-aware incremental apply with the durable gate: a frame that is durable but not yet published is skipped by the database, so the database misses a registered frame (I2b at depth 5). Refuted candidate.
#[test]
fn candidate_published_only_apply_with_durable_gate_is_refuted() {
    let cfg = Config {
        db_apply: DbApply::IncrementalPublished,
        ..split(true, true)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I2B,
        5,
        "append set(true)@0 -> write@0 -> sync start u=1 -> sync ok -> db apply@0",
    );
}

// memory—v1: F14 continued: after the database skips the aborted frame, a crash that retains only that frame and drops the unconfirmed abort makes recovery set live from the checkpoint, so live disagrees with R(n) (I2a at depth 9, with I2b also present). Refuted candidate.
#[test]
fn candidate_published_only_apply_loses_the_abort_on_recovery() {
    let cfg = Config {
        db_apply: DbApply::IncrementalPublished,
        db_gate: DbGate::DurableResolved,
        ..split(true, true)
    };
    let run = explore(cfg, I2A);
    assert!(run.stopped);
    let found = run.found.last().expect("I2a stopping state");
    expect_violation(
        found,
        I2A | I2B,
        9,
        "append set(true)@0 -> publish@0 fail -> abort@0 as 1 -> write@0 -> sync start u=1 -> sync ok -> db apply@0 -> crash process retain=1 -> recover",
    );
}

// memory—v1: F14, a status-aware incremental apply with the resolved gate: an abort beyond the checkpoint is not yet durable, so the database skips a frame that the reducer still counts in R(b) (I2b at depth 7). Refuted candidate: the status used by an apply must come from the checkpoint's own prefix. The recovery consequence is pinned in the test above.
#[test]
fn candidate_published_only_apply_with_resolved_gate_is_refuted() {
    let cfg = Config {
        db_apply: DbApply::IncrementalPublished,
        db_gate: DbGate::DurableResolved,
        ..split(true, true)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I2B,
        7,
        "append set(true)@0 -> publish@0 fail -> abort@0 as 1 -> write@0 -> sync start u=1 -> sync ok -> db apply@0",
    );
}

// memory—v1: F4, capturing the end at completion instead of at start: the claim passes the physically stable prefix (I1 at depth 6).
#[test]
fn fault_capture_at_completion_puts_the_claim_beyond_the_stable_prefix() {
    let cfg = Config {
        capture: Capture::AtCompletion,
        ..Config::target(Open::SyncAtOpenMoment)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I1,
        6,
        "append+publish set(true)@0 -> append+publish set(false)@1 -> write@0 -> sync start u=1 -> write@1 -> sync ok",
    );
}

// memory—v1: F5, the MarkDurable fault model — the pre-2026-11-21 open that claimed the scanned
// end without a sync — with process crashes: the recovered claim is set beyond the stable prefix
// at recovery (I1 at depth 4). Pins the fault model, not the current build: the implemented open
// now synchronizes the retained file at open and corresponds to `SyncAtOpenMoment`, whose full
// target graph is pinned by `target_sync_on_open_satisfies_every_invariant_over_the_full_graph`.
#[test]
fn witness_mark_durable_open_without_sync_claims_an_unsynced_prefix() {
    let cfg = Config::target(Open::MarkDurable);
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I1,
        4,
        "append+publish set(true)@0 -> write@0 -> crash process retain=1 -> recover",
    );
}

// memory—v1: F5 continued: after a process crash the recovered frame is acknowledged while still
// not stable; the claim (I1) and the ack (I3) are both violated at depth 5. Pins the MarkDurable
// fault model after the 2026-11-21 reopen-sync fix; the implemented open is compared against
// `SyncAtOpenMoment`.
#[test]
fn witness_mark_durable_open_without_sync_acks_a_recovered_unsynced_frame() {
    let cfg = Config::target(Open::MarkDurable);
    let run = explore(cfg, I3);
    assert!(run.stopped);
    let found = run.found.last().expect("I3 stopping state");
    expect_violation(
        found,
        I1 | I3,
        5,
        "append+publish set(true)@0 -> write@0 -> crash process retain=1 -> recover -> ack gov@0",
    );
}

// memory—v1: The d-form and a second crash: under the MarkDurable fault model an unsynced frame
// can be acked (the S-form fails at depth 5, see above). The d-form is only violated after a
// second process crash retains less than the acked frame: the claim resets to the scanned end,
// which lies below the acked position, so the acked frame is outside the log (I3d, with I3 and
// I5, at depth 7). The d-form therefore certifies only an open that synchronizes before claiming;
// the implemented open now does, and this fault model is retained for comparison.
#[test]
fn witness_mark_durable_open_without_sync_loses_an_acked_frame_on_a_second_crash() {
    let cfg = Config::target(Open::MarkDurable);
    let found = stopping_violation(cfg, I3D);
    expect_violation(
        &found,
        I3 | I3D | I5,
        7,
        "append+publish set(true)@0 -> write@0 -> crash process retain=1 -> recover -> ack gov@0 -> crash process retain=0 -> recover",
    );
}

// memory—v1: The database outruns the retained log under the MarkDurable fault model: a frame
// applied while only the claim (not the stable prefix) covers it is truncated by a process
// crash, so after the crash the checkpoint lies beyond the log (I1 in the crashed state) and the
// database policy no longer equals R(b) (I2b), at depth 6. Pins the fault model after the
// 2026-11-21 reopen-sync fix; the implemented open synchronizes before its confirmed end is used
// by the database gate.
#[test]
fn witness_mark_durable_open_without_sync_lets_the_database_outrun_the_retained_log() {
    let cfg = Config::target(Open::MarkDurable);
    let found = stopping_violation(cfg, I2B);
    expect_violation(
        &found,
        I1 | I2B,
        6,
        "append+publish set(true)@0 -> write@0 -> crash process retain=1 -> recover -> db apply@0 -> crash process retain=0",
    );
}

// memory—v1: The d-form refutation: the from-checkpoint open resets the claim to the database checkpoint, so an acked frame lies at or beyond the claim after recovery (I3d at depth 7; the crash state itself is exempt because the claim is volatile there). The S-form still holds, since the process crash keeps S.
#[test]
fn fault_from_checkpoint_open_breaks_the_d_form_at_recovery() {
    let cfg = Config::target(Open::FromCheckpoint);
    let found = stopping_violation(cfg, I3D);
    expect_violation(
        &found,
        I3D,
        7,
        "append+publish set(true)@0 -> write@0 -> sync start u=1 -> sync ok -> ack gov@0 -> crash process retain=1 -> recover",
    );
}

// memory—v1: F10, a power-loss-only model with the same open: the surviving bytes are stable, so the claim never exceeds S and no violation appears in the full bounded graph. Pins the explored graph.
#[test]
fn fault_power_loss_only_mark_durable_is_not_refuted() {
    let cfg = Config {
        crashes: Crashes::PowerLossOnly,
        ..Config::target(Open::MarkDurable)
    };
    let run = explore(cfg, 0);
    println!(
        "power-loss-only mark-durable: {} states, {} transitions, depth {}",
        run.states, run.edges, run.max_depth
    );
    assert!(!run.stopped);
    assert!(run.found.is_empty(), "violations: {:?}", run.found);
    assert_eq!(
        (run.states, run.edges),
        (441_822, 2_227_402),
        "pinned F10 graph"
    );
    assert_eq!(run.max_depth, 28, "pinned F10 depth");
}

// memory—v1: F6, an audit that binds the tail at registration rather than the observed prefix: a restoration between observation and audit makes the acked DENY bind a different prefix (I4b) whose value is true (I4), at depth 8. Asserts current behaviour disclosed as a gap; update when fixed. Gap: governance_owner.rs:371–375 takes the watermark at registration and 445–448 builds the prefix proof from the frame's own tail, not from H(O).
#[test]
fn witness_current_deny_binding_uses_the_registration_tail() {
    let cfg = Config {
        deny: DenyBinding::AuditTail,
        ..Config::target(Open::SyncAtOpenMoment)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I4 | I4B,
        8,
        "observe prefix 0 -> append+publish set(true)@0 -> append deny@1 obs=1 seen=0 -> write@0 -> write@1 -> sync start u=2 -> sync ok -> ack deny@1",
    );
}

// memory—v1: F7, a successful retry after an uncertain round advances the claim without advancing the stable prefix (I1 at depth 6). This is the non-structural counterpart of the sticky guard: sync ok follows an uncertain round.
#[test]
fn fault_retry_after_uncertain_round_advances_the_claim() {
    let cfg = Config {
        sync_retry: SyncRetry::Advances,
        ..Config::target(Open::SyncAtOpenMoment)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I1,
        6,
        "append+publish set(true)@0 -> write@0 -> sync start u=1 -> sync uncertain -> sync start u=1 -> sync ok",
    );
}

// memory—v1: F8, the database gate on written frames: the database can commit a frame that is not yet durable (I1 at depth 3).
#[test]
fn fault_database_gate_on_written_frames_lets_b_outrun_d() {
    let cfg = Config {
        db_gate: DbGate::Written,
        ..Config::target(Open::SyncAtOpenMoment)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I1,
        3,
        "append+publish set(true)@0 -> write@0 -> db apply@0",
    );
}

// memory—v1: F9, the response gate on written frames: a governance success is issued before its frame is stable (I3 at depth 3). The same ack is also beyond the durable claim, so the d-form I3d fires at the same depth.
#[test]
fn fault_response_gate_on_written_frames_acks_an_unstable_frame() {
    let cfg = Config {
        ack_gate: Gate::Written,
        ..Config::target(Open::SyncAtOpenMoment)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I3 | I3D,
        3,
        "append+publish set(true)@0 -> write@0 -> ack gov@0",
    );
}

// memory—v1: F15, the database commit without read-back: after an uncertain commit that did not persist, the client's belief runs ahead of the physical database (I2c at depth 5). The reconciled target has no such state. Refuted fault.
#[test]
fn fault_commit_without_read_back_breaks_the_database_claim() {
    let cfg = Config {
        db_commit: DbCommit::NoReadBack,
        ..Config::target(Open::SyncAtOpenMoment)
    };
    let found = stopping_violation(cfg, ALL);
    expect_violation(
        &found,
        I2C,
        5,
        "append+publish set(true)@0 -> write@0 -> sync start u=1 -> sync ok -> db apply@0 uncertain lost",
    );
}

// memory—v1: Two DENY observations are pending at distinct observed prefixes at once (depth 4), so one flush can confirm frames that were observed at different prefixes. Witness for the multiset of pending observations.
#[test]
fn witness_two_distinct_observations_can_be_pending_together() {
    let (depth, trace) = goal_trace(Config::target(Open::SyncAtOpenMoment), two_distinct_pending);
    assert_eq!(
        depth, 4,
        "shortest depth with two distinct pending prefixes"
    );
    assert_eq!(
        trace,
        "append+publish set(true)@0 -> append+publish set(false)@1 -> observe prefix 0 -> observe prefix 2",
        "shortest trace"
    );
}

// memory—v1: Checker sensitivity: a claim beyond S with an acked frame at the same position reports exactly I1 and I3.
#[test]
fn checker_flags_claim_and_ack_beyond_the_stable_prefix() {
    let mut st = St::initial();
    st.push(Frame::Set {
        value: true,
        status: Status::Published,
    });
    st.w = 1;
    st.d = 1;
    st.s = 0;
    st.live = true;
    st.acked = 1;
    assert_eq!(names(st.violations()), names(I1 | I3));
}

// memory—v1: Checker sensitivity: an ack at a position beyond the durable claim, but below S, reports exactly the d-form I3d.
#[test]
fn checker_flags_an_ack_beyond_the_durable_claim() {
    let mut st = St::initial();
    st.push(Frame::Set {
        value: true,
        status: Status::Published,
    });
    st.w = 1;
    st.d = 0;
    st.s = 1;
    st.live = true;
    st.acked = 1;
    assert_eq!(names(st.violations()), names(I3D));
}

// memory—v1: Checker sensitivity: a publish that failed with no abort path leaves live short of the registered truth, which is exactly I2a.
#[test]
fn checker_flags_an_abandoned_publish_as_stale_live() {
    let mut st = St::initial();
    st.push(Frame::Set {
        value: true,
        status: Status::Abandoned,
    });
    st.w = 1;
    st.s = 1;
    st.d = 1;
    assert_eq!(names(st.violations()), names(I2A));
}

// memory—v1: Checker sensitivity: a Deny whose recorded observation shows the restoration is exactly I4 (its binding holds: obs equals seen).
#[test]
fn checker_flags_a_deny_bound_to_a_restoring_prefix() {
    let mut st = St::initial();
    st.push(Frame::Set {
        value: true,
        status: Status::Published,
    });
    st.push(Frame::Deny { obs: 1, seen: 1 });
    st.w = 2;
    st.s = 2;
    st.d = 2;
    st.live = true;
    st.acked = 0b10;
    assert_eq!(names(st.violations()), names(I4));
}

// memory—v1: Checker sensitivity: a Deny bound to a prefix other than its recorded observation, whose value is false, is exactly I4b. The value check passes, so the binding check is independent of values (the A1 and I4b point).
#[test]
fn checker_flags_a_deny_bound_to_another_observation() {
    let mut st = St::initial();
    st.push(Frame::Set {
        value: false,
        status: Status::Published,
    });
    st.push(Frame::Deny { obs: 1, seen: 0 });
    st.w = 2;
    st.s = 2;
    st.d = 2;
    st.live = false;
    st.acked = 0b10;
    assert_eq!(names(st.violations()), names(I4B));
}

// memory—v1: Checker sensitivity: an ack at a position at or beyond the log reports I5 together with I3 and I3d, which shows that I5 is implied by I3 and never fires alone.
#[test]
fn checker_i5_comes_with_i3_and_i3d() {
    let mut st = St::initial();
    st.acked = 1;
    assert_eq!(names(st.violations()), names(I3 | I3D | I5));
}

// memory—v1: Reducer semantics: an aborted target contributes nothing once the abort is inside the prefix, but not before it; Deny is the identity.
#[test]
fn reducer_skips_aborted_targets_only_inside_the_prefix() {
    let mut st = St::initial();
    st.push(Frame::Set {
        value: true,
        status: Status::Aborted,
    });
    st.push(Frame::Abort { target: 0 });
    st.push(Frame::Deny { obs: 0, seen: 0 });
    assert!(!st.reduce(3));
    assert!(!st.reduce(2));
    assert!(st.reduce(1));
}

// memory—v1: Necessity (a): two reachable target executions with identical (b, d, S) admit different live policies (a revocation registered but not written).
#[test]
fn necessity_same_storage_frontiers_admit_different_live_policies() {
    let run = target_sync_on_open();
    println!(
        "frontier (b,d,S): {} keys with both live values; (b,d,S,w): {}",
        run.same_frontier_live, run.same_frontier_with_w_live
    );
    assert!(run.same_frontier_live > 0);
    assert!(run.same_frontier_with_w_live > 0);
    assert_eq!(run.same_frontier_live, 15, "pinned count of (b, d, S) keys");
    assert_eq!(
        run.same_frontier_with_w_live, 35,
        "pinned count of (b, d, S, w) keys"
    );
}

// memory—v1: Necessity (b): a reachable state with live policy beyond the durable prefix that a crash rolls back (volatile loss).
#[test]
fn necessity_live_policy_beyond_the_durable_prefix_is_rolled_back_by_a_crash() {
    let run = target_sync_on_open();
    println!("volatile-loss crash edges: {}", run.witness.volatile_loss);
    assert!(run.witness.volatile_loss > 0);
    assert_eq!(run.witness.volatile_loss, 312_554, "pinned count");
}

// memory—v1: Necessity (c): a reachable serving state where a governance success is still withheld while the mutation is already visible to ordinary admission. Crashed states are excluded: a crash clears live, so their visibility is not ordinary admission.
#[test]
fn necessity_withheld_success_is_already_visible() {
    let run = target_sync_on_open();
    println!(
        "withheld-but-visible serving states: {}",
        run.witness.withheld_visible
    );
    assert!(run.witness.withheld_visible > 0);
    assert_eq!(run.witness.withheld_visible, 328_109, "pinned count");
}

// memory—v1: The reachable witnesses for DENY at zero, DENY after mutations, one flush confirming several frames, a crash retaining frames beyond the claim, acks surviving a second recovery (the third epoch, counting from one), and the database uncertainty kinds. The full counter struct is pinned.
#[test]
fn necessity_reachable_witness_kinds_are_exercised() {
    let w = target_sync_on_open().witness;
    println!("{w:?}");
    assert!(w.ack_deny_at_zero > 0);
    assert!(w.ack_deny_after_mutation > 0);
    assert!(w.batch_confirm > 0);
    assert!(w.retained_beyond_durable > 0);
    assert!(w.second_epoch_acked > 0);
    assert!(w.two_pending_states > 0);
    assert_eq!(
        w,
        Witness {
            ack_governance: 336_114,
            ack_deny_at_zero: 131_542,
            ack_deny_after_mutation: 57_940,
            batch_confirm: 31_419,
            sync_ok_after_taint: 0,
            uncertain_states: 79_225,
            withheld_visible: 328_109,
            volatile_loss: 312_554,
            retained_beyond_durable: 531_484,
            second_epoch_acked: 15_962,
            db_persisted_uncertain: 121_368,
            db_lost_uncertain: 121_368,
            read_back_corrects: 121_368,
            read_back_confirms: 121_368,
            two_pending_states: 3_534,
        },
        "pinned witness counters"
    );
}

// memory—v1: Restricted bounds of the earlier journal submodel (two mutations, one DENY, one crash, power loss only, one-shot recovery) under this encoding. The earlier 2,969 states and 4,623 transitions come from a different transition relation (the old `memory_v1_authority_model.rs`), so they are not reproduced here. This encoding pins its own counts.
#[test]
fn restricted_original_bounds_encoding_is_pinned() {
    let cfg = Config {
        crashes: Crashes::PowerLossOnly,
        halt_after_recovery: true,
        mutations: 2,
        denies: 1,
        crash_budget: 1,
        db_commit: DbCommit::Certain,
        ..Config::target(Open::MarkDurable)
    };
    let run = explore(cfg, 0);
    println!(
        "restricted original bounds: {} states, {} transitions (earlier model: 2,969 and 4,623)",
        run.states, run.edges
    );
    assert!(run.found.is_empty(), "violations: {:?}", run.found);
    assert_eq!(
        (run.states, run.edges),
        (1_174, 3_165),
        "pinned restricted counts"
    );
}

// memory—v1: Larger crash budget for the publish-first target (M=3, D=2, C=3). The atomic target needs at most M + D frames, so the slot guard is not reached. The larger M=4, D=3 bound is not run here. Pins the explored graph.
#[test]
fn larger_publish_first_target_bounds() {
    let cfg = Config {
        crash_budget: 3,
        ..Config::target(Open::SyncAtOpenMoment)
    };
    let run = explore(cfg, 0);
    println!(
        "larger target: {} states, {} transitions, depth {}",
        run.states, run.edges, run.max_depth
    );
    assert!(run.found.is_empty(), "violations: {:?}", run.found);
    assert_eq!(
        (run.states, run.edges),
        (624_056, 3_982_466),
        "pinned larger target graph"
    );
    assert_eq!(run.max_depth, 30, "pinned larger target depth");
}
