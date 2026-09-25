--------------------------- MODULE AdmissionSafety ---------------------------
(***************************************************************************)
(* Independent evidence-admission safety model.                         *)
(*                                                                         *)
(* STATUS: DRAFT -- UNVERIFIED. No TLC run exists in this repository yet.  *)
(* This file is NOT evidence until a pinned tla2tools run of the full-     *)
(* contract configuration passes and the omission configurations produce   *)
(* their expected counterexamples (see formal/README.md). It shares no      *)
(* model logic with other specifications; only the TLC tooling is common.   *)
(*                                                                         *)
(* Protocol (mirrors experiment_common.py :: final_observation_interval     *)
(* and e5_model_check.py v2.1.0, independently re-expressed):               *)
(*                                                                         *)
(*  - one candidate grant r0 is published (head g0, body r0);              *)
(*  - one revocation-class source mutation commits, then a successor       *)
(*    re-grant r1 publishes through two INDEPENDENT sub-events: the        *)
(*    manifest/head advance (g0 -> g1) and the evidence body advance       *)
(*    (r0 -> r1); both orders are reachable, so torn cache pairs are       *)
(*    first-class states;                                                  *)
(*  - an adversarial rollback can reset the read-path cache to (0, 0)      *)
(*    while the durable published head stays 1 (at most once);             *)
(*  - each reader performs ONE final load that observes the cache pair     *)
(*    and the in-flight mutation state AT ITS READ STEP (t_f anchor);      *)
(*    pending state and fence rejection are LATCHED fail-closed;           *)
(*  - admission is mediated through a checklist evaluated from the         *)
(*    latched read-time observations only; there is NO admission-time      *)
(*    re-derivation and NO admission-side watermark (the Rust production   *)
(*    path has neither).                                                   *)
(*                                                                         *)
(* Out of scope by design: cryptography (HMAC/JWT), concrete Redis/MySQL,  *)
(* wall-clock values, E3 backoff/parking timing, Byzantine storage,        *)
(* multi-writer replica divergence, effect atomicity, liveness/fairness    *)
(* (a fairness-bearing configuration must be a separate cfg with explicit  *)
(* assumptions; eventual publication is NOT unconditional here).           *)
(***************************************************************************)
EXTENDS Integers, Naturals, TLC

CONSTANTS
  \* Reader identifiers. Full-contract cfg: Readers = {1, 2}.
  Readers,
  \* Premise switches. Full contract: all TRUE. Omission cfgs flip exactly
  \* one to FALSE and TLC is EXPECTED to find the corresponding violation.
  PENDING_PROBE,   \* the final load probes in-flight state at read time
  GEN_FENCE,       \* reads of torn/stale-head cache pairs poison admission
  EXACT_IDENTITY,  \* candidate match requires the original revision r0
  HOST_MEDIATION   \* admission only through the mediated checklist

-----------------------------------------------------------------------------
(***************************************************************************)
(* State                                                                   *)
(***************************************************************************)

VARIABLES
  commitBegin,      \* BOOLEAN: source mutation transaction begun
  commitDurable,    \* BOOLEAN: source commit durable; revocation effective
  publishedHead,    \* 0..1: durable published manifest generation (monotone)
  cacheGen,         \* 0..1: manifest generation visible on the read path
  cacheBody,        \* 0..1: evidence body revision visible on the read path
  rolledBack,       \* BOOLEAN: the adversarial rollback fired (at most once)
  loadDone,         \* [r |-> BOOLEAN]: final load completed
  loadBeforeCommit, \* [r |-> BOOLEAN]: load preceded the durable commit
  obsGen,           \* [r |-> 0..1]: manifest generation observed at load
  obsBody,          \* [r |-> 0..1]: body revision observed at load
  pendingLatched,   \* [r |-> BOOLEAN]: in-flight mutation seen at read time
  fenceRejected,    \* [r |-> BOOLEAN]: torn/stale-head read poisoned the load
  matched,          \* [r |-> BOOLEAN]: candidate matched
  admitted,         \* [r |-> BOOLEAN]: host admission happened
  admittedVia       \* [r |-> "none" / "mediated" / "bypass"]

vars == <<commitBegin, commitDurable, publishedHead, cacheGen, cacheBody,
          rolledBack, loadDone, loadBeforeCommit, obsGen, obsBody,
          pendingLatched, fenceRejected, matched, admitted, admittedVia>>

CachePair == <<cacheGen, cacheBody>>

PublicationComplete == cacheGen = 1 /\ cacheBody = 1

Torn(r) == obsGen[r] # obsBody[r]

StaleHead(r) == obsGen[r] < publishedHead

AdmittedStaleR0(r) ==
    /\ admitted[r]
    /\ admittedVia[r] = "mediated"
    /\ loadBeforeCommit[r]
    /\ obsBody[r] = 0           \* the admission anchored the ORIGINAL candidate

-----------------------------------------------------------------------------
(***************************************************************************)
(* Initial state: r0 published (head 0, body 0); no mutation, no readers.  *)
(***************************************************************************)

Init ==
  /\ commitBegin = FALSE
  /\ commitDurable = FALSE
  /\ publishedHead = 0
  /\ cacheGen = 0
  /\ cacheBody = 0
  /\ rolledBack = FALSE
  /\ loadDone = [r \in Readers |-> FALSE]
  /\ loadBeforeCommit = [r \in Readers |-> FALSE]
  /\ obsGen = [r \in Readers |-> 0]
  /\ obsBody = [r \in Readers |-> 0]
  /\ pendingLatched = [r \in Readers |-> FALSE]
  /\ fenceRejected = [r \in Readers |-> FALSE]
  /\ matched = [r \in Readers |-> FALSE]
  /\ admitted = [r \in Readers |-> FALSE]
  /\ admittedVia = [r \in Readers |-> "none"]

-----------------------------------------------------------------------------
(***************************************************************************)
(* Mutation chain                                                          *)
(***************************************************************************)

CommitBegin ==
  /\ ~commitBegin
  /\ commitBegin' = TRUE
  /\ UNCHANGED <<commitDurable, publishedHead, cacheGen, cacheBody,
                 rolledBack, loadDone, loadBeforeCommit, obsGen, obsBody,
                 pendingLatched, fenceRejected, matched, admitted, admittedVia>>

CommitDurable ==
  /\ commitBegin
  /\ ~commitDurable
  /\ commitDurable' = TRUE
  /\ UNCHANGED <<commitBegin, publishedHead, cacheGen, cacheBody,
                 rolledBack, loadDone, loadBeforeCommit, obsGen, obsBody,
                 pendingLatched, fenceRejected, matched, admitted, admittedVia>>

\* Manifest/head advance becomes visible on the read path (independent of
\* the body advance; either publication order is reachable).
PublishManifest ==
  /\ commitDurable
  /\ publishedHead = 0
  /\ publishedHead' = 1
  /\ cacheGen' = 1
  /\ UNCHANGED <<commitBegin, commitDurable, cacheBody, rolledBack,
                 loadDone, loadBeforeCommit, obsGen, obsBody,
                 pendingLatched, fenceRejected, matched, admitted, admittedVia>>

\* Successor body becomes visible on the read path.
AdvanceBody ==
  /\ commitDurable
  /\ cacheBody = 0
  /\ cacheBody' = 1
  /\ UNCHANGED <<commitBegin, commitDurable, publishedHead, cacheGen,
                 rolledBack, loadDone, loadBeforeCommit, obsGen, obsBody,
                 pendingLatched, fenceRejected, matched, admitted, admittedVia>>

\* Adversarial read-path reset: the cache pair returns to (0, 0) while the
\* durable published head stays 1. At most one rollback.
Rollback ==
  /\ publishedHead = 1
  /\ ~rolledBack
  /\ rolledBack' = TRUE
  /\ cacheGen' = 0
  /\ cacheBody' = 0
  /\ UNCHANGED <<commitBegin, commitDurable, publishedHead,
                 loadDone, loadBeforeCommit, obsGen, obsBody,
                 pendingLatched, fenceRejected, matched, admitted, admittedVia>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Reader actions (independent per reader; the decision tail after the     *)
(* last read stays free -- nothing is re-derived at admission)             *)
(***************************************************************************)

\* The final load: ONE step that observes the cache pair and the in-flight
\* state at its read step and LATCHES both fail-closed. t_f is this step.
FinalLoadRead(r) ==
  /\ ~loadDone[r]
  /\ obsGen' = [obsGen EXCEPT ![r] = cacheGen]
  /\ obsBody' = [obsBody EXCEPT ![r] = cacheBody]
  /\ pendingLatched' =
       [pendingLatched EXCEPT ![r] =
           PENDING_PROBE /\ commitBegin /\ ~PublicationComplete]
  /\ fenceRejected' =
       [fenceRejected EXCEPT ![r] =
           GEN_FENCE /\ (Torn(r) \/ StaleHead(r))]
  /\ loadDone' = [loadDone EXCEPT ![r] = TRUE]
  /\ loadBeforeCommit' = [loadBeforeCommit EXCEPT ![r] = commitDurable]
  /\ UNCHANGED <<commitBegin, commitDurable, publishedHead, cacheGen,
                 cacheBody, rolledBack, matched, admitted, admittedVia>>

\* Candidate match. With exact identity only the original revision r0
\* matches; without it, grant presence is enough, so the successor r1 also
\* matches (the successor-substitution hole).
CandidateMatches(r) == IF EXACT_IDENTITY THEN obsBody[r] = 0 ELSE TRUE

Match(r) ==
  /\ loadDone[r]
  /\ ~matched[r]
  /\ CandidateMatches(r)
  /\ matched' = [matched EXCEPT ![r] = TRUE]
  /\ UNCHANGED <<commitBegin, commitDurable, publishedHead, cacheGen,
                 cacheBody, rolledBack, loadDone, loadBeforeCommit, obsGen,
                 obsBody, pendingLatched, fenceRejected, admitted, admittedVia>>

\* Mediated admission: every gate is evaluated from the LATCHED read-time
\* observations only. A publication completing after the last read cannot
\* resurrect a latched unsafe delta.
MediatedAdmit(r) ==
  /\ HOST_MEDIATION
  /\ matched[r]
  /\ ~admitted[r]
  /\ ~pendingLatched[r]
  /\ ~fenceRejected[r]
  /\ admitted' = [admitted EXCEPT ![r] = TRUE]
  /\ admittedVia' = [admittedVia EXCEPT ![r] = "mediated"]
  /\ UNCHANGED <<commitBegin, commitDurable, publishedHead, cacheGen,
                 cacheBody, rolledBack, loadDone, loadBeforeCommit, obsGen,
                 obsBody, pendingLatched, fenceRejected, matched>>

\* Unmediated admission: exists only when host mediation is removed.
Bypass(r) ==
  /\ ~HOST_MEDIATION
  /\ matched[r]
  /\ ~admitted[r]
  /\ admitted' = [admitted EXCEPT ![r] = TRUE]
  /\ admittedVia' = [admittedVia EXCEPT ![r] = "bypass"]
  /\ UNCHANGED <<commitBegin, commitDurable, publishedHead, cacheGen,
                 cacheBody, rolledBack, loadDone, loadBeforeCommit, obsGen,
                 obsBody, pendingLatched, fenceRejected, matched>>

Next ==
  \/ CommitBegin
  \/ CommitDurable
  \/ PublishManifest
  \/ AdvanceBody
  \/ Rollback
  \/ \E r \in Readers :
        \/ FinalLoadRead(r)
        \/ Match(r)
        \/ MediatedAdmit(r)
        \/ Bypass(r)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

TypeOK ==
  /\ commitBegin \in BOOLEAN
  /\ commitDurable \in BOOLEAN
  /\ publishedHead \in {0, 1}
  /\ cacheGen \in {0, 1}
  /\ cacheBody \in {0, 1}
  /\ rolledBack \in BOOLEAN
  /\ loadDone \in [Readers -> BOOLEAN]
  /\ loadBeforeCommit \in [Readers -> BOOLEAN]
  /\ obsGen \in [Readers -> {0, 1}]
  /\ obsBody \in [Readers -> {0, 1}]
  /\ pendingLatched \in [Readers -> BOOLEAN]
  /\ fenceRejected \in [Readers -> BOOLEAN]
  /\ matched \in [Readers -> BOOLEAN]
  /\ admitted \in [Readers -> BOOLEAN]
  /\ admittedVia \in [Readers -> {"none", "mediated", "bypass"}]

\* The core conditional guarantee: no reader admits the original candidate
\* r0 through the mediated path when the mutation was already durable at
\* the reader's final observation (t_f).
NoStaleAdmissionForPreObservationCommit ==
  \A r \in Readers : ~AdmittedStaleR0(r)

\* Exact-candidate binding: with the premise on, an admitted reader can
\* never have matched a successor revision.
ExactCandidateAdmission ==
  \A r \in Readers :
    admitted[r] => (EXACT_IDENTITY => obsBody[r] = 0)

\* A torn or stale-head cache observation never reaches admission while
\* the generation/revoke read fence holds.
TornCacheNeverAdmitted ==
  \A r \in Readers :
    admitted[r] => (GEN_FENCE => ~Torn(r) /\ ~StaleHead(r))

\* Admission always goes through the mediated checklist.
AdmissionRequiresMediation ==
  \A r \in Readers : admitted[r] => admittedVia[r] # "bypass"

\* A latched unsafe pending delta or a fence-poisoned load never admits.
UnknownNeverAdmits ==
  \A r \in Readers :
    admitted[r] =>
      ((PENDING_PROBE => ~pendingLatched[r])
          /\ (GEN_FENCE => ~fenceRejected[r]))

=============================================================================
