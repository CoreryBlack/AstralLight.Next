# Contributing to AstralLight Rust

Thank you for considering a contribution. This guide describes the project's
current proposed intake policy. It is not a signed contributor agreement or a
patent assignment, and the project may require a separately signed agreement
before accepting contributions intended for commercial relicensing.

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
