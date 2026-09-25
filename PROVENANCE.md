# Provenance

- Source repository: `AstralLight`
- Source path: `AstralLight-Rust/`
- Source commit: `c3077e28075561b2774aebab15715ecf20720529`
- Copy mode: filesystem copy; the source repository remains intact
- New repository path: `E:\OfficialVersion\AstralLight-Next`
- Remote: none configured

## Published boundary

The standalone repository intentionally excludes Java application services, web,
patent, deployment state, frozen experiment evidence archives, runtime
configuration, credentials, generated runtime logs, IDE state, and build output.
It includes executable Rust tests, authorization validation tools and formal inputs, the
 distributed validation harness source, comparison benchmark scripts/fixtures, and
 Java comparison benchmark source/tests under `evaluation/benchmark-java`. The copied
 Rust source includes the frozen `astral-chat` and `astral-learn` crates, while the
 default Cargo workspace continues to exclude them.

## Licensing and rights-control boundary

The default public license for material cleared for project publication is
`AGPL-3.0-or-later`; see [`LICENSE`](LICENSE), [`LEGAL.md`](LEGAL.md), and
[`CONTRIBUTING.md`](CONTRIBUTING.md). AGPL use, forks, and commercial activity
under AGPL are not subject to project revenue sharing or a commercial-license
fee.

The copy record and Cargo license metadata describe publication intent; they do
not prove copyright ownership or authority to commercially sublicense each
file. A commercial alternative may include only exact files/features for which
the licensor owns the relevant rights or has explicit written authority from
the actual rights holder. Community contributions without separate written
commercial-relicensing permission, third-party dependencies, copied benchmark
adapters, fixtures, Maven components, and other externally licensed material
must be excluded from commercial scopes unless separately cleared and listed in
a signed rights schedule.

Any feature-revenue arrangement for an official project is separate from a
commercial code license. The policy design is a virtual, auditable payable ledger
rather than a representation that the project holds money in bank escrow or
trust. The commercial payer or designated payment provider should pay the
contributors directly under a signed arrangement; unresolved shares are not
withdrawn or distributed by the project and may remain recorded as a payer
payable only as its contract permits. Contributors must pre-agree to negotiation,
neutral mediation, and independent adjudication/arbitration; the project does not
unilaterally assign shares. Independent forks are outside the arrangement, and
it never conditions AGPL rights. Actual payment, tax, fee, custodian, and dispute
terms remain subject to the executed agreement and applicable professional
advice. The non-executed starting form is
[`FEATURE-REVENUE-AGREEMENT.md`](FEATURE-REVENUE-AGREEMENT.md). Do not publish
private contributor permissions or other confidential rights records in this
repository.
