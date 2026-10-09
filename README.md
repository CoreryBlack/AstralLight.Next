# AstralLight Rust

AstralLight Rust is a standalone Rust workspace for multi-tenant authorization and
its surrounding runtime: identity, gateway authentication, durable projection,
policy evaluation, messaging, persistence, and monitoring.

The public repository is designed for engineers who need to inspect the
authorization path, run the local unit suite, reproduce the published test
contracts, or evaluate the Rust implementation against comparison engines. It
is not a packaged production deployment and does not include credentials,
private infrastructure, or historical experiment archives.

## What is protected

The runtime's authorization root is `PolicyEngine::evaluate()`. A decision must
be supported by the current identity, an active user card, the requested
resource/action scope, tenant isolation, projection generation and dependency
readiness, and published evidence. Missing, stale, failed, or unproven
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

`astral-chat` and `astral-learn` are retained as frozen Rust source for migration
and compatibility review, but remain excluded from the default workspace. The
active members and dependency policy are defined in [`Cargo.toml`](Cargo.toml).

## Quick start

Requirements for the local workspace checks:

- Rust toolchain compatible with the checked-in workspace and `Cargo.lock`;
- a working Cargo registry/cache; and
- no database, Redis, RabbitMQ, Docker, or external service for the default
  unit/check commands.

Run the default workspace gate from the repository root:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

The single execution owner is `scripts/test_campaign.py`; shell and matrix commands
are selection aliases, not independent runners:

```bash
bash scripts/run-tests.sh --all
python -B scripts/test_campaign.py --list --json
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
Native transport is local; Redis is disabled.
Rabbit requires loopback port 5673 and an explicit vhost; compatibility Redis requires
loopback port 6380. The dedicated identity-mapping suite uses
`INTEGRATION_IDENTITY_MAPPING_DATABASE_URL` and a matching
`INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE` with the `sdk_identity_mapping_test_*`
prefix. Provisioning and destructive migration approval remain separate operations.
Credentials stay in the process environment and must never be committed.
Full phase logs, commands, exit codes and source hashes are retained outside the
repository. UNKNOWN requires reconciliation before retry. See
[tests-suite](tests-suite/README.md) for exact profiles and evidence boundaries.

The consolidated runner indexes RQ1-RQ5, authorization assumptions M1-M5,
E1-E5, MT, performance, compatibility, and excluded suites against explicit
production deployment profiles:

```bash
python -B scripts/test_campaign.py --list --json
bash scripts/run-tests.sh --campaign --run --profile native-kernel --series E2
python -B scripts/test_campaign.py --run --profile offline-validation --suite offline-validation-tools
python -B scripts/test_campaign.py --run --profile native-single-node --suite native-projection-lifecycle
```

It requires Python 3.11+, never provisions or migrates, and uses only approved,
already migrated isolated dependencies (`TEST_USE_EXISTING=1`). Native integration
uses only MySQL and in-process buses; Rabbit transport and Redis compatibility
remain explicit profiles. Each indexed command carries its owner, dependency
contract, source snapshot, assertion count and proof boundary. Empty, ignored,
skipped or interrupted checks are not silently promoted to `PASS`. Local component
coverage and offline models never stand in for a full RQ, live E1-E4, or HTTP
performance campaign. Legacy Redis/OPA distributed harnesses remain non-dispatched
`BLOCKED` entries until adapted; frozen/excluded crates are not covered by the root
workspace gate. See [tests-suite](tests-suite/README.md) for the exact matrix.

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
- `astral-cache/`: excluded, self-contained Redis compatibility archive; not a native dependency.
- `astral-mq/`: messaging contracts, delivery, DLX, and idempotency helpers.
- `astral-gateway/`: gateway authentication and request forwarding.
- `astral-identity/`: identity and session lifecycle.
- `astral-trustgraph/`: governance, authority, audit, and projection services.
- `astral-monitor/`: monitoring and alerting.
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
- compiler/oracle tests and policy-engine benchmarks;
- `scripts/run-tests.sh`, `scripts/org_scope_preflight.sh`, and
  `scripts/verify-excluded-services.ps1`;
- E1-E5 validation tools and offline tests under
  [`Docs/authorization-validation/tools/`](Docs/authorization-validation/tools/);
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
