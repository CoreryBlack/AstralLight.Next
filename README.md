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

The isolated test runner makes infrastructure explicit:

```bash
./scripts/run-tests.sh --check
./scripts/run-tests.sh unit
./scripts/run-tests.sh --integration
```

`--check` runs Cargo checks and clippy without starting services. Both `unit`
and `--integration` start the isolated `docker-compose.test.yml` stack and
apply Rust-owned migrations; `unit` runs workspace library tests, while
`--integration` also runs ignored integration tests serially. The real
integration gate requires MySQL/Redis/RabbitMQ connection variables,
`ASTRAL_MIGRATION_ENV=isolated`, and `RUST_INTEGRATION_REQUIRED=1`. Credentials
must be supplied through the process environment and must never be committed.
A missing required dependency is a failed or blocked gate, not a green skip.

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
- `astral-cache/`: Redis cache and idempotency support.
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
