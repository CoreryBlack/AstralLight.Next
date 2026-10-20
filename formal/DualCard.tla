---------------------------- MODULE DualCard ----------------------------
EXTENDS FiniteSets, Naturals, Sequences

(******************************************************************************)
(* Bounded authorization-context state machine.                               *)
(*                                                                            *)
(* This module intentionally excludes JWTs, refresh sessions, Redis, gateway  *)
(* forwarding, and recovery behavior. Those implementation concerns are       *)
(* validated by the protocol integration experiments.                         *)
(******************************************************************************)

CONSTANTS Users, CardIds, Resources, Actions, NULL

Statuses == {"UNASSIGNED", "ACTIVE", "DISABLED", "REVOKED", "EXPIRED"}
Effects == {"ALLOW", "DENY"}
PermissionTuples == Resources \X Actions \X Effects
AuditKinds == {"REGISTER", "ISSUE", "ACTIVATE", "REVOKE", "BIND"}
AuditEvents == AuditKinds \X Users \X CardIds

VARIABLES icMap,
          ucMap,
          activeMap,
          cardOwner,
          cardStatus,
          rules,
          auditLog

vars == <<icMap, ucMap, activeMap, cardOwner, cardStatus, rules, auditLog>>

IdentityCards == {c \in CardIds : \E u \in Users : icMap[u] = c}
UserCards == UNION {ucMap[u] : u \in Users}

TypeOK ==
  /\ icMap \in [Users -> CardIds \cup {NULL}]
  /\ ucMap \in [Users -> SUBSET CardIds]
  /\ activeMap \in [Users -> CardIds \cup {NULL}]
  /\ cardOwner \in [CardIds -> Users \cup {NULL}]
  /\ cardStatus \in [CardIds -> Statuses]
  /\ rules \in [CardIds -> SUBSET PermissionTuples]
  /\ auditLog \in SUBSET AuditEvents

INV1_IdentityCardUnique ==
  \A u, v \in Users:
    /\ u # v
    /\ icMap[u] # NULL
    /\ icMap[v] # NULL
    => icMap[u] # icMap[v]

INV2_ActiveBelongsToUser ==
  \A u \in Users: activeMap[u] # NULL => activeMap[u] \in ucMap[u]

INV3_ActiveCardIsActive ==
  \A u \in Users: activeMap[u] # NULL => cardStatus[activeMap[u]] = "ACTIVE"

INV6_ContextIdGloballyUnique ==
  \A c \in CardIds:
    Cardinality({u \in Users : c \in ucMap[u]}) <= 1

INV_OwnerMapping ==
  \A c \in CardIds:
    /\ cardOwner[c] = NULL <=> c \notin (IdentityCards \cup UserCards)
    /\ cardOwner[c] # NULL =>
      ((icMap[cardOwner[c]] = c) \/ (c \in ucMap[cardOwner[c]]))

INV5_AuditTraceability ==
  /\ \A u \in Users:
       icMap[u] # NULL => \E c \in CardIds : <<"REGISTER", u, c>> \in auditLog
  /\ \A u \in Users, c \in ucMap[u]: <<"ISSUE", u, c>> \in auditLog
  /\ \A u \in Users, c \in ucMap[u]:
       cardStatus[c] = "REVOKED" => <<"REVOKE", u, c>> \in auditLog

EvalFrom(ruleMap, card, resource, action) ==
  IF \E effect \in Effects : <<resource, action, effect>> \in ruleMap[card]
  THEN IF <<resource, action, "DENY">> \in ruleMap[card] THEN "DENY" ELSE "ALLOW"
  ELSE "DENY"

ActiveAlternatives(user, target) ==
  {c \in (ucMap[user] \ {target}) : cardStatus[c] = "ACTIVE"}

Register(user, newCard) ==
  /\ icMap[user] = NULL
  /\ cardOwner[newCard] = NULL
  /\ icMap' = [icMap EXCEPT ![user] = newCard]
  /\ cardOwner' = [cardOwner EXCEPT ![newCard] = user]
  /\ cardStatus' = [cardStatus EXCEPT ![newCard] = "ACTIVE"]
  /\ auditLog' = auditLog \cup {<<"REGISTER", user, newCard>>}
  /\ UNCHANGED <<ucMap, activeMap, rules>>

IssueCard(user, newCard) ==
  /\ icMap[user] # NULL
  /\ cardOwner[newCard] = NULL
  /\ ucMap' = [ucMap EXCEPT ![user] = @ \cup {newCard}]
  /\ activeMap' = IF activeMap[user] = NULL
                   THEN [activeMap EXCEPT ![user] = newCard]
                   ELSE activeMap
  /\ cardOwner' = [cardOwner EXCEPT ![newCard] = user]
  /\ cardStatus' = [cardStatus EXCEPT ![newCard] = "ACTIVE"]
  /\ rules' = [rules EXCEPT ![newCard] = {}]
  /\ auditLog' = auditLog \cup {<<"ISSUE", user, newCard>>}
  /\ UNCHANGED icMap

Activate(user, target) ==
  /\ target \in ucMap[user]
  /\ cardStatus[target] = "ACTIVE"
  /\ activeMap' = [activeMap EXCEPT ![user] = target]
  /\ auditLog' = auditLog \cup {<<"ACTIVATE", user, target>>}
  /\ UNCHANGED <<icMap, ucMap, cardOwner, cardStatus, rules>>

Revoke(user, target) ==
  /\ target \in ucMap[user]
  /\ cardStatus[target] # "REVOKED"
  /\ cardStatus' = [cardStatus EXCEPT ![target] = "REVOKED"]
  /\ rules' = [rules EXCEPT ![target] = {}]
  /\ activeMap' = IF activeMap[user] = target
                   THEN IF ActiveAlternatives(user, target) = {}
                        THEN [activeMap EXCEPT ![user] = NULL]
                        ELSE [activeMap EXCEPT ![user] =
                              CHOOSE c \in ActiveAlternatives(user, target) : TRUE]
                   ELSE activeMap
  /\ auditLog' = auditLog \cup {<<"REVOKE", user, target>>}
  /\ UNCHANGED <<icMap, ucMap, cardOwner>>

BindRule(user, target, resource, action, effect) ==
  /\ target \in ucMap[user]
  /\ cardStatus[target] = "ACTIVE"
  /\ rules' = [rules EXCEPT ![target] = @ \cup {<<resource, action, effect>>}]
  /\ auditLog' = auditLog \cup {<<"BIND", user, target>>}
  /\ UNCHANGED <<icMap, ucMap, activeMap, cardOwner, cardStatus>>

RuleIsolation ==
  \A user \in Users, target \in ucMap[user], other \in (ucMap[user] \ {target}),
    resource \in Resources, action \in Actions:
      EvalFrom(rules, target, resource, action) =
        EvalFrom([rules EXCEPT ![other] = {}], target, resource, action)

Init ==
  /\ icMap = [u \in Users |-> NULL]
  /\ ucMap = [u \in Users |-> {}]
  /\ activeMap = [u \in Users |-> NULL]
  /\ cardOwner = [c \in CardIds |-> NULL]
  /\ cardStatus = [c \in CardIds |-> "UNASSIGNED"]
  /\ rules = [c \in CardIds |-> {}]
  /\ auditLog = {}

Next ==
  \/ \E user \in Users, newCard \in CardIds: Register(user, newCard)
  \/ \E user \in Users, newCard \in CardIds: IssueCard(user, newCard)
  \/ \E user \in Users, target \in CardIds: Activate(user, target)
  \/ \E user \in Users, target \in CardIds: Revoke(user, target)
  \/ \E user \in Users, target \in CardIds, resource \in Resources,
        action \in Actions, effect \in Effects:
       BindRule(user, target, resource, action, effect)

Spec == Init /\ [][Next]_vars

=============================================================================
