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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TaskBudgets {
    foreground: usize,
    background: usize,
}

static TASK_BUDGETS: std::sync::OnceLock<TaskBudgets> = std::sync::OnceLock::new();

fn parse_performance_core_count(stdout: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(stdout).ok()?;
    text.trim().parse::<usize>().ok().filter(|count| *count > 0)
}

fn compute_budgets(total: usize, performance_cores: Option<usize>, macos: bool) -> TaskBudgets {
    let total = total.max(1);
    let foreground = if macos {
        performance_cores
            .filter(|count| *count > 0)
            .map(|count| count.min(total))
            .unwrap_or(1)
    } else {
        total
    };
    TaskBudgets {
        foreground,
        background: total.saturating_sub(foreground),
    }
}

fn detect_budgets() -> TaskBudgets {
    let total = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    #[cfg(target_os = "macos")]
    let performance_cores = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("hw.perflevel0.physicalcpu")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| parse_performance_core_count(&output.stdout));
    #[cfg(not(target_os = "macos"))]
    let performance_cores = None;

    compute_budgets(total, performance_cores, cfg!(target_os = "macos"))
}

fn task_budgets() -> &'static TaskBudgets {
    TASK_BUDGETS.get_or_init(detect_budgets)
}

/// 前台工作线程预算（判定/装配等延迟敏感路径）。
///
/// macOS：`hw.perflevel0.physicalcpu`（P 核数）；其他平台：可用并行度
/// （同构核下 P=E，前台=全部——异质性不存在时"分池"退化为单池，曲线
/// 依旧成立）。macOS 查询或解析失败回退 1，绝不放大。预算在首次查询后
/// 缓存，避免每次调用都启动 `sysctl`。
pub fn foreground_budget() -> usize {
    task_budgets().foreground
}

/// 后台工作线程预算（延迟容忍路径）：总核数减前台预算，下限 0。
pub fn background_budget() -> usize {
    task_budgets().background
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

    #[test]
    fn sysctl_parser_accepts_only_positive_utf8_integers() {
        assert_eq!(parse_performance_core_count(b" 4\n"), Some(4));
        assert_eq!(parse_performance_core_count(b"0"), None);
        assert_eq!(parse_performance_core_count(b"-1"), None);
        assert_eq!(parse_performance_core_count(b"nope"), None);
        assert_eq!(parse_performance_core_count(&[0xff]), None);
    }

    #[test]
    fn macos_budget_uses_validated_core_count_and_falls_back_to_one() {
        assert_eq!(
            compute_budgets(10, Some(4), true),
            TaskBudgets {
                foreground: 4,
                background: 6,
            }
        );
        assert_eq!(
            compute_budgets(10, None, true),
            TaskBudgets {
                foreground: 1,
                background: 9,
            }
        );
        assert_eq!(
            compute_budgets(10, Some(0), true),
            TaskBudgets {
                foreground: 1,
                background: 9,
            }
        );
    }

    #[test]
    fn budgets_respect_total_core_boundaries() {
        assert_eq!(
            compute_budgets(8, Some(16), true),
            TaskBudgets {
                foreground: 8,
                background: 0,
            }
        );
        assert_eq!(
            compute_budgets(0, Some(0), true),
            TaskBudgets {
                foreground: 1,
                background: 0,
            }
        );
        assert_eq!(
            compute_budgets(8, None, false),
            TaskBudgets {
                foreground: 8,
                background: 0,
            }
        );
    }
}
