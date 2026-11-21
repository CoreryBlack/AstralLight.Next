//! memory—v1: Estimate additional allocatable work, never a reservation or admission proof.

use astral_db::memory_v1_candidate_loader::CaptureBudget;

const RESERVE: u64 = 64 * 1024 * 1024;

// memory—v1: Old readers and the current root already occupy memory. Do not add RSS
// back to available RAM. Leave room for journal, audit, network and allocator churn.
fn usable(available: u64) -> Option<usize> {
    let available = available.checked_sub(RESERVE.max(available / 8))?;
    usize::try_from(available).ok().filter(|n| *n > 0)
}

pub(super) fn capture_budget() -> Option<CaptureBudget> {
    let bytes = headroom()?;
    Some(CaptureBudget {
        max_rows: bytes / 4096,
        max_bytes: bytes / 16,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
// memory—v1: Re-sample every applicable limit; never cache an admission.
pub(super) fn headroom() -> Option<usize> {
    use rustix::process::{getrlimit, Resource};
    use sysinfo::System;
    #[cfg(target_os = "macos")]
    let mut available = {
        use sysinfo::{MemoryRefreshKind, RefreshKind};
        let system = System::new_with_specifics(
            RefreshKind::nothing().with_memory(MemoryRefreshKind::nothing().with_ram()),
        );
        // The same sample's immediately free non-speculative pages are a lower bound.
        system.available_memory().max(system.free_memory())
    };
    #[cfg(target_os = "linux")]
    let mut available = linux_group_available(mem_available(
        &std::fs::read_to_string("/proc/meminfo").ok()?,
    )?)?;
    // For a finite data/address-space limit, total VM is a conservative upper
    // bound on process data. Reject unknown usage instead of assuming zero.
    if let Some(limit) = [Resource::As, Resource::Data]
        .into_iter()
        .filter_map(|r| getrlimit(r).current)
        .min()
    {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate};
        let pid = sysinfo::get_current_pid().ok()?;
        let mut process = System::new();
        process.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            false,
            ProcessRefreshKind::nothing().with_memory(),
        );
        let used = process.process(pid)?.virtual_memory();
        if used == 0 {
            return None;
        }
        available = available.min(limit.saturating_sub(used));
    }
    usable(available)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn headroom() -> Option<usize> {
    None
}

// memory—v1: The supported Linux v2 kernels report host headroom in KiB.
// Read only this quantity, without constructing a process/CPU inventory.
#[cfg(any(test, target_os = "linux"))]
fn mem_available(sample: &str) -> Option<u64> {
    let mut entries = sample
        .lines()
        .filter_map(|line| line.strip_prefix("MemAvailable:"));
    let mut fields = entries.next()?.split_ascii_whitespace();
    let kib = fields.next()?.parse::<u64>().ok()?;
    if fields.next()? != "kB" || fields.next().is_some() || entries.next().is_some() {
        return None;
    }
    kib.checked_mul(1024)
}

// memory—v1: Resolve the process's v2 membership, not the mount root alone.
// Refuse unsupported v1 memory controllers or hidden/nonstandard mount roots.
#[cfg(target_os = "linux")]
fn linux_group_available(bytes: u64) -> Option<u64> {
    use std::{fs, path::Path};
    let membership = fs::read_to_string("/proc/self/cgroup").ok()?;
    let mounts = fs::read_to_string("/proc/self/mountinfo").ok()?;
    if !mounts.lines().any(|line| {
        line.split_once(" - ").is_some_and(|(pre, post)| {
            let mut fields = pre.split_ascii_whitespace().skip(3);
            fields.next() == Some("/")
                && fields.next() == Some("/sys/fs/cgroup")
                && post.starts_with("cgroup2 ")
        })
    }) {
        return None;
    }
    let available = hierarchy_headroom(bytes, &membership, Path::new("/sys/fs/cgroup"), |p| {
        fs::read_to_string(p)
    })?;
    (membership == fs::read_to_string("/proc/self/cgroup").ok()?).then_some(available)
}

// memory—v1: Ancestors share their limit across descendants. Unknown levels fail closed.
#[cfg(any(test, target_os = "linux"))]
fn hierarchy_headroom(
    mut bytes: u64,
    membership: &str,
    base: &std::path::Path,
    read: impl Fn(&std::path::Path) -> std::io::Result<String>,
) -> Option<u64> {
    use std::path::{Component, Path};
    let mut unified = None;
    for line in membership.lines() {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let group = parts.next()?;
        if controllers.split(',').any(|c| c == "memory") {
            return None;
        }
        if hierarchy == "0" && controllers.is_empty() {
            unified = Some(group);
        }
    }
    let group = unified?;
    let relative = Path::new(group).strip_prefix("/").ok()?;
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return None;
    }
    let full = base.join(relative);
    for path in full.ancestors().take_while(|p| p.starts_with(base)) {
        let max = match read(&path.join("memory.max")) {
            Ok(value) => value,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // An existing hierarchy level may have no delegated memory controller.
                read(&path.join("cgroup.controllers")).ok()?;
                continue;
            }
            Err(_) => return None,
        };
        if max.trim() != "max" {
            let limit: u64 = max.trim().parse().ok()?;
            let used: u64 = read(&path.join("memory.current"))
                .ok()?
                .trim()
                .parse()
                .ok()?;
            bytes = bytes.min(limit.saturating_sub(used));
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    // memory—v1: A leaf without a cap cannot overrule a nearly full ancestor.
    fn workload_headroom_includes_every_visible_cgroup_limit() {
        use std::{io, path::Path};
        let base = Path::new("/cgroup");
        let probe = |path: &Path| {
            Ok(match path.to_str().unwrap() {
                "/cgroup/group/leaf/memory.max" => "max",
                "/cgroup/group/memory.max" => "100",
                "/cgroup/group/memory.current" => "94",
                "/cgroup/cgroup.controllers" => "memory",
                _ => return Err(io::ErrorKind::NotFound.into()),
            }
            .to_owned())
        };
        assert_eq!(
            hierarchy_headroom(1000, "0::/group/leaf", base, probe),
            Some(6)
        );
        assert_eq!(
            hierarchy_headroom(3, "0::/group/leaf", base, probe),
            Some(3)
        );
        for membership in ["0::/unknown", "0::/../other", "1:memory:/group", ""] {
            assert_eq!(hierarchy_headroom(1000, membership, base, probe), None);
        }
    }

    #[test]
    // memory—v1: An unknown host sample cannot turn free pages or another unit into headroom.
    fn host_sample_requires_an_unambiguous_checked_kib_value() {
        assert_eq!(
            mem_available("MemFree: 99999 kB\nMemAvailable:    7 kB\n"),
            Some(7168)
        );
        assert_eq!(mem_available("MemAvailable: 0 kB"), Some(0));
        for sample in [
            "MemFree: 123 kB",
            "MemAvailable: 2",
            "MemAvailable: -1 kB",
            "MemAvailable: 2 MB",
            "MemAvailable: 3 kB extra",
            "MemAvailable: 18446744073709551615 kB",
            "MemAvailable: 3 kB\nMemAvailable: 9 kB",
        ] {
            assert_eq!(mem_available(sample), None, "{sample}");
        }
    }

    #[test]
    fn pressure_keeps_the_reserve_and_does_not_wrap() {
        assert_eq!(usable(0), None);
        assert_eq!(usable(RESERVE), None);
        assert_eq!(usable(RESERVE + 1), Some(1));
        assert_eq!(usable(16 * RESERVE), Some(14 * RESERVE as usize));
    }
}
