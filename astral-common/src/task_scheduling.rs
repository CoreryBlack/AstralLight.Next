//! 前台/后台任务的核心分配调度。
//!
//! 能效曲线依据（ceiling probe 实测，4P+6E 异构机）：
//! - 前台判定线程 ×2/×4/×10 的扩展效率为 96%/90%/59%——超过 P 核数后
//!   新增线程落在 E 核（同负载吞吐仅 P 核 ~42%）且 p99 从 2.9ms 翻倍到
//!   6.7ms：吞吐仍增，但延迟质量崩坏。
//! - 后台批处理（段编码、失效 fanout、审计重放、归档）是延迟容忍的：
//!   它们占满剩余容量不影响正确性，只需不让前台尾延迟恶化。
//!
//! 调度规则（阈值 = 物理性能核数）：
//! - 前台池（授权判定、证据装配）：`foreground_budget()` 个线程——
//!   恰好铺满 P 核，p99 处于曲线最优段；
//! - 后台池（延迟容忍 worker）：剩余核（`background_budget()`），
//!   吞吐用满 E 核的 ~42% 仍高于闲置。
//!
//! 两个预算只做容量规划；OS 绑定由部署层（taskset/QoS/numactl）执行，
//! 本模块不绑定线程，避免与运行时调度器打架。

/// 前台工作线程预算（判定/装配等延迟敏感路径）。
///
/// macOS：`hw.perflevel0.physicalcpu`（P 核数）；其他平台：可用并行度
/// （同构核下 P=E，前台=全部——异质性不存在时"分池"退化为单池，曲线
/// 依旧成立）。解析失败回退 1，绝不放大。
pub fn foreground_budget() -> usize {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sysctl")
            .arg("-n")
            .arg("hw.perflevel0.physicalcpu")
            .output();
        if let Ok(output) = output {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if let Ok(count) = text.trim().parse::<usize>() {
                    if count > 0 {
                        return count;
                    }
                }
            }
        }
    }
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1)
}

/// 后台工作线程预算（延迟容忍路径）：总核数减前台预算，下限 0。
pub fn background_budget() -> usize {
    let total = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    total.saturating_sub(foreground_budget())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_are_consistent_and_nonzero() {
        let foreground = foreground_budget();
        let background = background_budget();
        assert!(foreground >= 1);
        let total = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1);
        assert_eq!(foreground + background, total);
    }
}
