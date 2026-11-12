# Contributing to AstralLight Rust

Thank you for considering a contribution. This guide describes the project's
current proposed intake policy. It is not a signed contributor agreement or a
patent assignment, and the project may require a separately signed agreement
before accepting contributions intended for commercial relicensing.

## Getting started

`main` holds the stable reference design and is open for maintenance and
experiments; the maintainer's redesign lives in the `memroy-v1` branch. New here?
Pick an issue labeled
[`good first issue`](https://github.com/CoreryBlack/AstralLight.Next/labels/good%20first%20issue)
or [`help wanted`](https://github.com/CoreryBlack/AstralLight.Next/labels/help%20wanted),
or open an issue to discuss an idea before writing code.

### Build and test

```bash
cargo test --workspace --locked
cargo run --locked -p test-harness --bin test-campaign -- --list --json
scripts/run-tests.sh --campaign --run --profile native-kernel
```

The first command runs the workspace tests, the second lists every suite in
[`tests-suite/MANIFEST.toml`](tests-suite/MANIFEST.toml), and the third runs the
pure component regression profile. Suites that need MySQL or RabbitMQ require
an environment you prepare yourself; if a dependency was unavailable, say so and
do not report the run as passing. All tests and test verdicts are written in
Rust only (coding standard §10.0).

### Branches, commits, and pull requests

The full workflow is in the
[Git and GitHub collaboration standard](Docs/规范/Git与GitHub协作规范_V1.0.md). In short:

- Fork the repository and branch from the latest `main` as
  `<type>/<issue-id>-<short-desc>`, for example `fix/41-revoke-fence-timeout`.
  Never push to `main` or force-push shared branches.
- Commit messages use `<type>(<scope>): <subject>`, where type is one of
  `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, and the subject is
  lowercase, imperative, and at most 72 characters. Mark breaking changes with
  `BREAKING CHANGE:` as described in coding standard §14.
- Open the pull request against `main`, link the issue, list the checks you ran
  and their environment, and include the AGPL confirmation below. `Rust CI`
  (fmt, check, clippy with `-D warnings`, tests, docs) must pass, and a
  maintainer reviews and merges.

### The one rule not to break

Every change must keep authorization fail-closed: decisions go through
`PolicyEngine::evaluate()`, and missing, stale, or unproven evidence yields
`PENDING` or `DENY`, never a fallback to raw rows, old snapshots, or caches.
See the [Rust backend coding standard](Docs/规范/Rust后端编码规范_V1.0.md) for
layering, error handling, testing, and security rules.

## Community license

Contributions accepted into this repository are offered to the community under
the GNU Affero General Public License, version 3 or any later version
(`AGPL-3.0-or-later`), on the terms in [`LICENSE`](LICENSE). Contributors retain
their rights; submitting a pull request or having it merged does not transfer
copyright to the project.

Forking, studying, modifying, deploying, and distributing AGPL-covered code are
not conditioned on paying the project, joining a revenue-sharing plan, obtaining
project approval, or reporting revenue. Independent forks are not automatically
bound by the project's feature-revenue arrangements.

## Commercial relicensing is a separate opt-in

An AGPL grant does not by itself authorize the project to sublicense a
contribution under a proprietary commercial alternative. A contribution will
only be included in such an alternative if the actual rights holder gives
explicit written permission that covers the relevant commercial licensing
scope. Permission may need to come from an employer, client, or other rights
holder rather than the individual author.

A pull request, commit author field, copyright notice, attribution, code review,
merge, or AGPL publication is not commercial-relicensing permission. Without a
recorded written authorization, a contribution remains excluded from commercial
license scopes and available only under the rights actually granted to the
community.

When opening a pull request, the contributor must confirm this statement or
explain the rights basis for a different arrangement:

> I confirm that I have the right to submit this contribution and grant the
> project the rights needed to publish and maintain it under AGPL-3.0-or-later.
> I retain my rights. This confirmation does not authorize commercial
> relicensing; that requires my separate, explicit written permission or written
> permission from the actual rights holder.

The project may ask an authorized rights holder to sign a separate commercial
permission before including a contribution in a customer agreement. The signer
should receive the exact scope and terms before deciding. Commercial permission
is optional and separate from submitting an AGPL contribution.

## Feature revenue sharing

The project policy intent for an official commercial feature is to allocate
100% of the revenue attributed to that feature to its contributor group. A
low-cost virtual subledger may record the amount payable; it is not represented
as bank escrow or a trust, and the record itself does not put funds in the
project's possession. The signed payer arrangement should provide for the
commercial customer or designated payment provider to pay contributors directly
where permitted. If internal shares are unresolved, the payer may retain the
amount as a payable only as provided by its signed contract; the project does not
hold or personally redistribute it.

Contributors negotiate internal shares. Before participating, the group must
agree in writing to a negotiation deadline, neutral mediation, and subsequent
independent adjudication or arbitration. The project does not decide individual
shares or impose code-line/PR-count weights. The actual payer, recordkeeping,
fees, interest, tax reporting/withholding, and payment mechanics remain items for
the signed agreement and qualified local advice. This arrangement is separate from commercial-relicensing consent, does not apply
to independent forks, and never conditions AGPL rights. The non-executed starting
form is [`FEATURE-REVENUE-AGREEMENT.md`](FEATURE-REVENUE-AGREEMENT.md).

## Contributor checks

Before submitting, confirm that:

- you wrote the contribution or have permission from the rights holder to submit
  it under AGPL;
- your employer, client, school, or contract does not own or restrict the work;
- you have identified copied code, generated assets, fixtures, or dependencies
  and preserved their applicable notices;
- you disclose patent claims or other restrictions you know apply to the
  contribution; and
- you have not included secrets, private data, or credentials.

If you cannot grant the AGPL rights needed for the project to publish and
maintain the contribution, do not submit it until the rights holder has
clarified the permission. For security-sensitive issues, follow the private
reporting guidance in [`README.md`](README.md) rather than posting secrets in a
public pull request.

## Technical review

Include focused tests for behavior changes and describe any required external
services. Database-backed or distributed tests must state their environment and
must not be represented as passing if required dependencies were unavailable.
Follow the execution and evidence gates in [`AGENTS.md`](AGENTS.md).
