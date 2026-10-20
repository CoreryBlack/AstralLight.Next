# TDSC post-claim gate（Java 归档）

本目录继承私有仓库 `AstralLight/AstralIdentity` 的 TDSC 实验专用组件：

- `TdscPostClaimGateTest`：5 个 JUnit 测试，覆盖 arm/release、nonce 拒绝、
  有界超时、完成后不可重复 arm、lease-loss 记录。
- `TdscPostClaimGate` / `TdscPostClaimGateController`：仅在 `tdsc-fault` profile
  和显式 property 下装配的测试控制点，不是生产默认 Bean。
- `SessionProjectionPostClaimGate`：gate 的最小接口。

## 边界

- 这是**归档资产**，不参与当前 Cargo workspace，也不保证可独立构建；它依赖
  Java `AstralIdentity` 父模块、Spring 和 `BusinessScanIgnore`。
- 未运行 Java 测试；复制不构成 Java 编译或行为验证通过。
- 测试中的 `test-nonce` 是测试占位值，不是运行时密钥；没有复制部署凭据。
- Rust 侧当前只有 worker claim/readback 与 lease 语义的部分映射，没有同名
  post-claim gate；如需等价覆盖，应单独移植到 Rust 测试。
