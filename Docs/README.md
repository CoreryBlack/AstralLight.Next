# Rust Documentation

This directory contains documentation selected for the standalone Rust backend repository.

## Engineering

- [Rust 后端编码规范](规范/Rust后端编码规范_V1.0.md)
- [统一消息协议与智能层消息规范](规范/统一消息协议与智能层消息规范_2026-03-18.md)
- [统一接口路径规范](规范/统一接口路径规范_V5.md)
- [License and publication policy](../LEGAL.md)
- [Commercial license negotiation template](../COMMERCIAL-LICENSE.md)
- [Contribution and licensing policy](../CONTRIBUTING.md)
- [Feature revenue participation template](../FEATURE-REVENUE-AGREEMENT.md)

## Architecture

- [Rust architecture index](架构/Rust架构设计/README.md)
- [Access-control overview and adjustment route](架构/Rust架构设计/Rust访问控制总览与调整路线_V1.0.md)
- [Projection snapshots and version fences](架构/Rust架构设计/Rust权限投影快照与版本栅栏_V1.0.md)
- [Incremental rebuild and realtime authorization boundary](架构/Rust架构设计/Rust增量重建与实时授权边界_V1.0.md)
- [Multi-tenant organization scope](架构/Rust架构设计/Rust多租户聚合分区与组织层级设计_V0.1.md)
- [Dual-card identity and authorization context](架构/Rust架构设计/Rust双卡身份与授权上下文_V1.0.md)
- [Gateway chain](架构/Rust架构设计/Rust-Gateway当前实际链路与解耦对照设计_V1.0.md)
- [Rule and ruleset semantics](架构/Rust架构设计/Rust权限判定与规则集语义_V1.0.md)
- [Arbiter and GlobalAdmin governance](架构/Rust架构设计/RustArbiter与GlobalAdmin治理链_V1.0.md)

## SDK Integration

- [SDK 接入 V1](SDK接入V1.md): independent SDK, mandatory identity mapping, registered application scope, and Chat/Learn contract samples. Not a production cutover acceptance record.
- [SDK V1 实施证据](SDK接入V1_实施证据.md): five-chain review, isolated verification commands, ignored tests and acceptance limits.

## Migration and Operations

- [Migration index](迁移/README.md)
- [Rust migration architecture decision](迁移/Rust后端迁移架构决策_V1.0.md)
- [ORG_SCOPE migration and rollback runbook](迁移/ORG_SCOPE迁移与回滚操作手册_V0.1.md)

## Schema

- [`full_schema_v4.sql`](sql/full_schema_v4.sql) is the isolated integration-test baseline. It contains schema definitions only; credentials are supplied through environment variables.

## Tests and Evidence

All tracked Rust test assets are published with the standalone workspace: crate unit/integration tests, organization-scope and projection integration tests, policy-engine oracle fixtures, benchmarks, test runners, migration preflight checks, the local login probe, and historical integration-test reports. Reports are historical artifacts only; current verification must be rerun from the target checkout with the required isolated infrastructure.

- Workspace/check entry point: [`../scripts/run-tests.sh`](../scripts/run-tests.sh)
- Organization-scope preflight: [`../scripts/org_scope_preflight.sh`](../scripts/org_scope_preflight.sh)
- Integration compose file: [`../docker-compose.test.yml`](../docker-compose.test.yml)
- Login probe: [`../test_login.ps1`](../test_login.ps1)
- Historical reports: [`../integration_test_result_20260707_174605.txt`](../integration_test_result_20260707_174605.txt), [`../integration_test_result_20260707_192539.txt`](../integration_test_result_20260707_192539.txt), [`../integration_test_result_20260707_193124.txt`](../integration_test_result_20260707_193124.txt)

## Authorization Validation Code

- [Validation tools and read-only probes](authorization-validation/tools/README_READONLY_PROBES.md)
- [Validation protocol](authorization-validation/VALIDATION_PROTOCOL.md)
- [Bounded safety-model inputs](authorization-validation/formal/README.md)
- [Implementation coverage and limits](authorization-validation/IMPLEMENTATION_MAP.md)
- [Distributed validation harness](实验/分布式测试/rust-s15/README.md)
- [Comparison benchmark scripts](实验/基准测试/scripts/README.md)
- [Java comparison benchmark boundary](../evaluation/benchmark-java/README.md)

The sources above are published for local validation and reruns. Historical run
records, credentials, host routing, binaries, and generated results are intentionally
excluded. Live runs remain subject to `AGENTS.md` status and approval gates.

## License boundary

The default license for project-owned material is [`AGPL-3.0-or-later`](../LICENSE). Commercial alternatives are described in [`COMMERCIAL-LICENSE.md`](../COMMERCIAL-LICENSE.md) and [`LEGAL.md`](../LEGAL.md). Third-party dependencies and copied evaluation material retain their own licenses and notices.
