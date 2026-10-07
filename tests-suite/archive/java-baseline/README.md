# 归档:Java 对比基准基线(retired 2026-10-07)

## 归档理由

1. 本仓库的权威对比基准已由 Rust canonical 实现承担:
   `bench/engine-comparison`(AstralLight vs Casbin/Cedar 进程内 + OPA sidecar,
   2026-10-06 已完成 5×5 全量运行,证据见 tests-suite 证据目录)。
2. Java 套件在本 checkout 中**按发布边界不可构建**:pom 依赖 15 个未随本仓库
   发布的内部 `Astral*` 父模块(`evaluation/benchmark-java/README.md` 原文:
   "intentionally not copied")。
3. 架构决策(2026-10-07):对比基线不再包含旧的 Java 基线;所有活跃基准编排
   迁至 `tests-suite/bench/` 与 `bench/` 下的 Rust crate。

## 内容

- `benchmark-java/`:原 `evaluation/benchmark-java` 完整快照(git mv,历史可溯)。
- `scripts/`:原 `Docs/实验/基准测试/scripts/` 中硬编码 Maven/JAR 的 Java 战役
  脚本(run_native_*、run_comparison_*、run_tests*、parse_5x* 等)。

## 边界

- 归档内容**不参与** workspace gate、不保证可构建、不再维护。
- 其中引用 Casbin/OPA/Cedar/SpiceDB/Spring/MySQL 的第三方许可边界声明
  见 `benchmark-java/README.md`(License boundary 一节),继续有效。
- 若未来需要重建 Java 对比能力,须先解决外部父模块供给,并按
  `Docs/迁移` 的测试迁移规范重新登记。
