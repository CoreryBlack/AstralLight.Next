# E5 全量战役证据归档（e5-all-20261008）

本目录存放 2026-10-08/09 E5 全量测试战役（run `e5-all-20261008-a11-v02`）的原始证据压缩包。

- **压缩包**：`e5-all-20261008-a11-evidence-bundle-20261010.tar.gz`（28,315,174 字节）
- **整体 sha256**：`93fafe0f83271f5e820324cf9818b3330b582be3811b267aed986b64634450e0`
- **战役结论**：verify-items 逐项 60/60 + collection 独立重跑 60/60 双阶段 PASS；测试源码冻结快照 `82336d6b`，对应提交 `674792e`（PR #9 合并入 main）。
- **包内容**：120 份套件日志（items+collection）、战役 result.json、Criterion 基准原始工件、克隆预置证据（dump/校验 SQL）、本地逐项报告与三轮源码快照；包内 `MANIFEST.md` 有完整清单与安全审查记录，`SHA256SUMS.txt` 覆盖全部内容文件。
- **安全说明**：打包前已执行全量 IP/凭据 URL/口令扩散扫描；含真实口令的 `campaign-a11.env` 原件未纳入，包内仅保留值已脱敏的 `campaign-a11.env.redacted`。

解包：`tar xzf e5-all-20261008-a11-evidence-bundle-20261010.tar.gz`，先读包内 `MANIFEST.md`。
