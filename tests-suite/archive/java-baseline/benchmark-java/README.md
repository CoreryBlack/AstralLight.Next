# Java Comparison Benchmark Boundary

`evaluation/benchmark-java/` contains the copied Java comparison benchmark source
and JUnit test source from the source repository. It is evaluation code only; it
is not a Cargo workspace member and it is not the Rust runtime.

## Build inputs

- The Java module retains its upstream `pom.xml` and baseline adapters for
  Casbin, OPA, Cedar and SpiceDB.
- The source repository's Java parent modules are intentionally not copied. A
  public build therefore requires an external Java parent/dependency supply or
  a future standalone Maven parent extraction.
- Runtime credentials are environment-only (`BENCH_MYSQL_PASSWORD`,
  `BENCH_JWT_SECRET`, and related variables). No `application-benchmark.yml`,
  Maven `target/`, result CSV, hardware snapshot or historical benchmark
  archive is included.
- The comparison scripts and Docker/SQL fixtures are under
  [`../../Docs/实验/基准测试/scripts/`](../../Docs/实验/基准测试/scripts/). They
  default to `evaluation/benchmark-java` for the JAR and keep generated output
  outside tracked source.

## License boundary

This directory contains evaluation code copied from another project. Its
presence here, the root `LICENSE`, and Cargo package metadata do not by themselves
relicense the copied Java source, its parent modules, any contributor work, or
external Maven dependencies. Preserve source notices and follow each applicable
license. No copied item may enter a commercial-license allowlist unless its
actual rights holder has given explicit written authority for that commercial
sublicense and the item is identified in the signed rights schedule.

The repository's default `AGPL-3.0-or-later` applies only to material that is
cleared for project publication under that license; a signed commercial
agreement covers only project-controlled items it expressly identifies. It
does not grant rights to Casbin, OPA, Cedar, SpiceDB, Spring, MySQL, Redis, the
missing Java parent modules, or other third-party components.

## Safety and evidence

The scripts include cluster and fault-injection entry points because they are
part of the public test code, but remote SSH, Docker stop/start, destructive
cleanup, migrations and external publication are explicit runtime actions. They
must be run only against an approved isolated environment with the required
Exec-L3 preflight and approval. This checkout has not run those campaigns.

Rust comparison code remains available in
[`../../bench/engine-comparison/`](../../bench/engine-comparison/), with Rust
workspace checks independent of this Java module. Java benchmark results must
not be presented as current evidence until the exact dependency, environment,
workload, repeat count and postconditions are recorded.
