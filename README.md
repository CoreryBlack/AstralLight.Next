# AstralLight Rust

AstralLight Rust is a Rust backend for **centralized, tenant-scoped authorization across API services**. It brings identity and session handling, gateway authentication, policy evaluation, durable authorization evidence, governance, messaging, and audit into one workspace. Instead of letting each application invent its own role checks or read permission tables directly, services use a shared authorization decision path.

The project is for teams building multi-tenant services where access depends on **who is acting, which authorization card they use, which tenant owns the data, and what resource/action is requested**. It is not a frontend application or a drop-in, preconfigured production deployment: this repository provides the Rust implementation, integration SDKs, schemas, Rust tests, and technical documentation. It does not include credentials or private infrastructure, and published test assets do not mean every live integration or deployment has been accepted. Project tests, harness assertions, test helpers, and result evaluation are implemented in Rust; retained Python files are historical or independent mathematical/statistical references. They are not current runtime tools, test gates or acceptance evidence; current validation uses Rust `test-campaign` and `tests-suite/MANIFEST.toml`.

## Project overview

AstralLight is a backend for applications that need a shared, tenant-aware way to decide whether an authenticated user may perform an action. It combines identity and session services with a gateway, a policy engine, durable authorization projections, governance services, and integration tooling. An application keeps ownership of its business data and handlers; AstralLight supplies the identity context and authorization decision path those services can use.

### The authorization model

The project distinguishes identity from the authority used to access data:

- An **identity card** represents who the user is and anchors their session.
- A **user card** carries an authorization context, including its tenant/domain scope and permission bindings. It is not interchangeable with an identity card, and identity alone does not grant business permissions.
- A decision applies to a registered **resource and action**, within the user's valid scope. For an individual object, the application service must resolve and validate the object's owner; the caller cannot authorize itself by supplying an unverified target or tenant.

This model is intended for systems where one person may act through different authorization contexts, data is partitioned by tenant or domain, and access must be checked consistently across multiple services. Applications do not grant access by checking a role string, trusting client-supplied identity headers, or reading a stale permission snapshot themselves.

### How a request is authorized

```text
User / application
  -> Gateway validates the session, removes untrusted identity headers,
     and establishes signed identity context
  -> Service verifies the Gateway context and resolves the target resource's owner
  -> PolicyEngine.evaluate() checks identity, user card, tenant, resource/action,
     and current published authorization evidence
  -> Service continues only when the decision is ALLOW
```

`PolicyEngine.evaluate()` is the normal authorization entry point. Gateway authentication establishes who is making the request; the owning service supplies the business-specific target facts; the policy engine decides whether the current evidence permits that exact operation. These responsibilities are deliberately separate, so a valid login or a trusted gateway header is not by itself permission to read or change an object.

### What the workspace provides

- **Identity and sessions:** account-facing identity and session lifecycle, including the identity-card and user-card context used by protected requests.
- **Gateway boundary:** external request authentication and signed context propagation to backend services. Downstream services verify the signature instead of trusting client-provided internal headers.
- **Policy evaluation:** shared resource/action validation and authorization decisions with tenant and card scope. Missing or inconsistent facts do not silently widen access.
- **Authorization projection:** database-backed source records, versioned published evidence, and workers that materialize approved permission changes. This separates a durable permission change from the read model used to make fast decisions.
- **Governance and operations:** TrustGraph services for authorization administration and governance, with audit and monitoring support. Published diagnostics and simulation remain non-authorizing; neither is an alternate path for granting normal requests.
- **Application integration:** Rust SDK contract, client, and Axum helper crates for services that need to request signed authorization decisions. SDK integration uses explicitly approved application scope and identity mapping; it does not automatically import an application's roles as platform permissions.
- **Development and validation:** workspace crates, schemas, test harnesses, validation tools, and benchmark sources for inspecting and checking the implementation. Their presence is not a claim that every real database, message-broker, migration, or deployment scenario has passed acceptance.

### Permission changes and fail-closed behavior

Permission changes follow a durable lifecycle: the source change and its audit/outbox correlation are recorded first; projection workers then publish versioned authorization evidence; the decision path checks that the evidence is current, complete, and ready. This helps keep permission updates, revocation, and authorization reads aligned even when asynchronous work is delayed or fails. If required evidence is missing, stale, failed, or unproven, the result is `PENDING` or `DENY`. The normal production decision path does not fall back to raw source rows, an old snapshot, or a cache entry to grant access.

### CURRENT V6 cleanup boundary

The former Chat/Learn runtime paths and service crates are historical baseline
material only. They are retired, physically absent from this checkout, and not
current Rust Gateway routes, supported APIs, or runtime dependencies. The
independent SDK consumer samples under `integrations/` do not restore those
services. Retained Redis fixtures and reports are historical comparisons or
retired compatibility evidence only; they are not current runtime dependencies,
authorization gates, or real-integration `PASS` evidence.

Monitor health has two distinct contracts: service-direct health probes are
operational observations, while the protected Monitor routes remain the signed
and permission-checked monitor contract. A direct health response does not prove
authorization, deployment readiness, or end-to-end acceptance. Resource
retirement remains fail-closed until canonical revoke, generation, and
published-evidence barriers are proven. Password-reset token creation does not
prove password delivery; delivery is unavailable or `PENDING` unless a notifier
handoff is proven. `UNKNOWN` and `PENDING` are never success states, and
cross-aggregate completion requires a complete owned receipt/evidence barrier,
not an ACK, status row, latest pointer, or partial aggregate observation.

### Where to explore next

- [Architecture index](Docs/架构/Rust架构设计/README.md) for service responsibilities and design boundaries.
- [Backend API reference](Docs/API/后端接口参考_V1.md) for registered routes and Gateway exposure.
- [SDK integration guide](Docs/SDK接入V1.md) for the application-side authorization contract and Axum examples.
- [Tests and evidence](tests-suite/README.md) for test profiles and their dependency/acceptance boundaries.

This repository is the Rust implementation and its supporting code, schemas, and documentation—not a packaged, preconfigured production deployment. Live integration, migration, and deployment acceptance require their own approved environment and evidence. The repository does not include credentials or private infrastructure; see [Repository boundary](#repository-boundary) for what is and is not included.

The public repository is designed for engineers who need to understand or extend the authorization path, run local checks, reproduce published test contracts, integrate a Rust application, or evaluate the implementation against comparison engines. It does not include historical experiment archives.

## What is protected

The runtime's authorization root is `PolicyEngine::evaluate()`. A decision must
be supported by the current identity, an active user card, the requested
resource/action scope, tenant isolation, projection generation and dependency
readiness, and published evidence. For object-level resources, the owning service
must resolve and validate the target owner before evaluation; actor identity or an
unresolved target scope cannot grant access. Missing, stale, failed, or unproven
projection state fails closed as `PENDING` or `DENY`; raw source reads, old
snapshots, and cache fallbacks do not grant access.

Projectors and workers materialize approved durable mutations only. Their
contracts include operation identity, idempotency, ownership, CAS leases,
generation/token fencing, bounded retries, audit correlation, and durable proof
before acknowledgement. `CARD` refresh and `ELIGIBILITY` cache eviction remain
separate lifecycle events.

## Repository boundary

This repository is a filesystem copy of the Rust source boundary at source
commit `c3077e28075561b2774aebab15715ecf20720529`. The source repository was not
moved or modified. The standalone checkout includes Rust runtime and test code,
selected Rust documentation and schema, authorization validation harnesses, and
comparison benchmark source.

It intentionally excludes Java application services, web clients, patent
materials, production deployment state, credentials, private keys, generated
logs, frozen evidence archives, host routes, binaries, and build output.

The production Rust runtime crates `astral-chat` and `astral-learn`, their
Gateway route registrations/proxies, and their production API contracts are
retired and physically removed from this checkout. They are not current
supported services or API contracts. Independent public SDK consumer samples
under [`integrations/`](integrations/README.md) remain available for reference
and testing; they are not replacements for or deployments of those production
services. The active members and dependency policy are defined in
[`Cargo.toml`](Cargo.toml).

## Quick start

Requirements for the local workspace checks:

- Rust toolchain compatible with the checked-in workspace and `Cargo.lock`;
- a working Cargo registry/cache; and
- no database, RabbitMQ, Docker, or external service for the default
  unit/check commands. Redis is not part of the CURRENT V6 runtime contract.

Run the default workspace gate from the repository root:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

The Rust `test-harness` crate is the single execution owner; shell and matrix commands
are selection aliases, not independent runners:

```bash
bash scripts/run-tests.sh --all
bash scripts/run-tests.sh --campaign --list --json
bash scripts/run-tests.sh --integration
bash scripts/run-tests.sh --rabbit
```

`--all` verifies every selected portable suite first, then reruns the full collection
from its first suite under the same frozen source hash. The portable selection includes
kernel tests, offline models, and measured CPU benchmarks. The first non-PASS stops
later dispatch. Fix or reconcile that target, rerun it individually, then restart the
original full collection with a new run ID; no historical PASS is reused.

`--full` selects every registered profile. All prerequisites are checked before any
command is started, so missing live infrastructure or an explicitly BLOCKED campaign
blocks the entire full-profile collection. Outside-selection entries remain visible
in the report and are never counted as passed.

No test entrypoint provisions services, starts Docker, migrates, or deletes containers.
Real integration requires an approved, already migrated loopback database on port 3308,
`TEST_USE_EXISTING=1`, `ASTRAL_MIGRATION_ENV=isolated`, and
`RUST_INTEGRATION_REQUIRED=1`. Ordinary MySQL suites require a run-scoped
`astral_rehearsal_<suffix>` database whose exact name is also supplied through
`ASTRAL_TEST_DATABASE_NAME`; source and shared rehearsal databases are rejected.
Native transport is local; Rabbit transport is an explicit profile and requires
loopback port 5673 with an explicit vhost. Redis compatibility is not a current
AstralLight runtime profile; any retained comparative Redis fixture is isolated from
the V6 runtime and does not supply equivalent cross-instance performance or metrics.
The dedicated identity-mapping suite uses
`INTEGRATION_IDENTITY_MAPPING_DATABASE_URL` and a matching
`INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE` with the `sdk_identity_mapping_test_*`
prefix. Provisioning and destructive migration approval remain separate operations.
Credentials stay in the process environment and must never be committed.
Full phase logs, commands, exit codes and source hashes are retained outside the
repository. UNKNOWN requires reconciliation before retry. See
[tests-suite](tests-suite/README.md) for exact profiles and evidence boundaries.

The consolidated Rust runner indexes RQ1-RQ5, authorization assumptions M1-M5,
E1-E5, MT, performance, compatibility, and excluded suites against explicit
production deployment profiles:

```bash
bash scripts/run-tests.sh --campaign --list --json
bash scripts/run-tests.sh --campaign --run --profile native-kernel --series E2
bash scripts/run-tests.sh --campaign --run --profile offline-validation --suite offline-validation-tools
bash scripts/run-tests.sh --campaign --run --profile native-single-node --suite native-projection-lifecycle
```

It never provisions or migrates, and uses only approved,
already migrated isolated dependencies (`TEST_USE_EXISTING=1`). Native integration
uses only MySQL and in-process buses; Rabbit transport remains an explicit
profile. Each indexed command carries its owner, dependency
contract, source snapshot, assertion count and proof boundary. Empty, ignored,
skipped or interrupted checks are not silently promoted to `PASS`. Local component
coverage and offline models never stand in for a full RQ, live E1-E4, or HTTP
performance campaign. Historical Redis/OPA comparative harnesses and fixtures, where
retained, are not current AstralLight runtime dependencies or authorization gates;
their status remains whatever the historical evidence records. Remaining excluded
crates are not covered by the root workspace gate. See [tests-suite](tests-suite/README.md)
for the exact matrix.

For organization-scope migration inspection, set `ORG_MYSQL_URL` to a TCP MySQL
URI for the isolated test database, then run the read-only preflight:

```bash
: "${ORG_MYSQL_URL:?set the isolated test database URI in the environment}"
bash scripts/org_scope_preflight.sh preflight
```

The same script has a destructive rollback mode. It is an Exec-L3 operation and
requires its own backup, approval, and explicit data-loss flag; it is not part
of the default test commands.

## Workspace layout

- `policy-engine/`: policy evaluation, authorization compiler, strict published-evidence gate, and semantic tests.
- `astral-types/`: shared domain and wire types.
- `astral-common/`: configuration, errors, middleware, audit, signatures, and observability.
- `astral-db/`: SQLx repositories, migrations, projection persistence, evidence, and tenant-scoped access.
- `astral-mq/`: messaging contracts, delivery, DLX, and idempotency helpers.
- `astral-gateway/`: gateway authentication and request forwarding.
- `astral-identity/`: identity and session lifecycle.
- `astral-trustgraph/`: governance, authority, audit, and projection services.
- `astral-monitor/`: monitoring and alerting.
- `astral-single-node/`: composite single-process runtime assembled from the Gateway, Identity, and TrustGraph services.
- `astral-sdk-contracts/`, `astral-sdk/`, and `astral-sdk-axum/`: signed authorization-manifest contracts, a Rust client, and Axum integration helpers for application services.
- `e2e-bootstrap/`: isolated bootstrap entry point.
- `bench/`: Rust comparison and load-generation crates, each outside the default members when documented by its manifest.
- `testsuite/` (under `tests-suite/`): workspace member carrying the consolidated new suites (multi-tenant extreme, security premises).
- `Docs/`: Rust engineering rules, architecture, migrations, schemas, authorization validation protocols, and reproducibility boundaries.
- `tests-suite/`: consolidated classified test suite (manifest, new multi-tenant extreme and security suites, benchmark orchestration) with the retired Java comparison baseline archived under `tests-suite/archive/java-baseline/`.

## Tests and reproducibility code

The repository publishes test source, not an unconditional claim that every live
campaign has passed:

- crate unit and integration tests, including tenant isolation, organization
  scope, projection, cache, identity, trustgraph, and audit coverage;
- authorization compiler contracts and policy-engine benchmarks;
- `scripts/run-tests.sh` and `scripts/org_scope_preflight.sh`;
- Rust E1–E5 runner contracts and bounded models under `test-harness`; historical
  algorithm inputs retained under [`Docs/authorization-validation/tools/`](Docs/authorization-validation/tools/)
  are reference material and do not provide runtime compatibility or test entrypoints;
- bounded authorization safety-model inputs under [`Docs/authorization-validation/formal/`](Docs/authorization-validation/formal/),
  currently marked `BLOCKED` until a pinned TLC run exists;
- distributed validation harness source under
  [`Docs/实验/分布式测试/rust-s15/`](Docs/实验/分布式测试/rust-s15/);
- Rust comparison benchmark orchestration and fixtures under
  [`tests-suite/bench/`](tests-suite/bench/), with the retired Java comparison
  baseline and its scripts archived under
  [`tests-suite/archive/java-baseline/`](tests-suite/archive/java-baseline/);
- multi-tenant mixed extreme suites and security premises under
  [`tests-suite/`](tests-suite/README.md);
- the implementation coverage map at
  [`Docs/authorization-validation/IMPLEMENTATION_MAP.md`](Docs/authorization-validation/IMPLEMENTATION_MAP.md);
- three tracked historical integration reports, which are records of earlier
  runs rather than current verification.

The production-path race checks, recovery and fault-injection runners,
database-backed ignored tests, Java benchmark execution, and TLA+ model checking
require separate approved environments and durable postcondition evidence. The
repository does not silently convert missing infrastructure into `PASS`.

## Documentation

Start with [`AGENTS.md`](AGENTS.md) for execution gates and safety rules, then
use [`Docs/README.md`](Docs/README.md) for the Rust documentation index.
[`PROVENANCE.md`](PROVENANCE.md) records the copy boundary and excluded runtime
artifacts. The authorization validation protocols and model boundaries are under
[`Docs/authorization-validation/`](Docs/authorization-validation/).

For cross-cutting implementation analysis and measured performance, see the
[2026-10-25 technical-topic analysis](Docs/技术专题解析与架构取舍_2026-10-25.md)
and the [PolicyEngine execution-time capability curve](Docs/实验/基准测试/授权执行期能力曲线_20261025.md).
The first distinguishes current Rust evidence from migration decisions and candidates;
the second is a local CPU fixture measurement, not HTTP throughput or production capacity.

## Licensing

Code that the licensor is entitled to license is offered under the GNU Affero
General Public License, version 3 or any later version (`AGPL-3.0-or-later`).
The complete standard license text is included in [`LICENSE`](LICENSE), and the
official SPDX entry is
[AGPL-3.0-or-later](https://spdx.org/licenses/AGPL-3.0-or-later.html).

Anyone may use, study, modify, deploy, fork, and distribute covered code under
the AGPL, including for commercial purposes, subject to the AGPL's terms. No
project fee, registration, approval, reporting, royalty, or revenue share is
required merely to exercise AGPL rights. Users who meet their AGPL obligations
do not need a separate commercial license just because their use is commercial.
A fork's operation and revenue are not subject to this project's revenue-sharing
policy.

A customer may request a separately negotiated commercial alternative only for
material specifically listed in a signed agreement and only where the licensor
owns the relevant rights or has written authority from the rights holder to
sublicense those commercial rights. The alternative is for customers who elect
rights outside the AGPL terms, such as proprietary distribution without the
AGPL's applicable source-offer obligations. See
[`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md) and [`LEGAL.md`](LEGAL.md).
The commercial document is a negotiation template, not an executed grant.
Contact `3095506226@qq.com`; do not send credentials or production secrets in
an initial enquiry.

Contributions intended for this repository are offered to the community under
the AGPL while contributors retain their rights. A pull request, merge,
attribution, or AGPL publication does not by itself authorize commercial
relicensing of a contributor's code. Commercial relicensing requires explicit
written authority from the relevant rights holder; see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

For official commercial projects operated by the licensor or project, the policy
intent is to allocate 100% of the revenue attributed to a named feature to that
feature's contributor group under a separate written agreement. The default
operational design is a low-cost virtual subledger recording an amount payable,
not a bank escrow, trust, or legal custody account. The record itself does not
put funds in the project's possession. Under the signed payer arrangement, the
commercial customer or designated payment provider should pay contributors
directly where permitted. If internal shares are unresolved, the payer records
the amount as payable under its contract and does not distribute it pending the
agreed resolution process; the project does not hold or personally redistribute
the money.

The contributor group negotiates internal shares. The written agreement must set
a negotiation deadline, neutral mediation, and subsequent independent
adjudication or arbitration. The project does not decide individual shares or
apply a code-line/PR-count formula. Custodian/payment provider, permitted fees,
interest, tax withholding/reporting, attribution, and applicable law must be
settled with qualified advisers in that agreement. The non-executed starting form
is [`FEATURE-REVENUE-AGREEMENT.md`](FEATURE-REVENUE-AGREEMENT.md). This README is
not a payment promise, custody agreement, or tax conclusion. Independent forks
are outside this arrangement, and it never conditions AGPL rights.

Third-party dependencies, copied benchmark code, fixtures, and other material
with their own notices remain subject to their respective licenses. The root
license, Cargo metadata, or presence in this repository does not prove that the
licensor may commercially sublicense those materials.

## Security and responsible use

Do not commit passwords, tokens, private keys, database URLs, server addresses,
run manifests, or generated evidence. Report security issues through a private
channel rather than opening a public issue containing a vulnerability or secret.
The public test harnesses include explicit remote, Docker, fault-injection, and
cleanup paths; run them only against an approved isolated environment and
follow the execution gates in [`AGENTS.md`](AGENTS.md).
