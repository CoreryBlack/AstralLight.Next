//! 平台原生的整组进程抽象（POSIX process group / Windows Job Object）。
//!
//! 两侧语义对齐，满足 campaign 执行的 fail-closed 要求：
//! - spawn 时原子归属：POSIX 用 `process_group(0)`；Windows 先 CREATE_SUSPENDED
//!   挂起启动，把进程指派进 kill-on-close Job Object 后再恢复主线程，
//!   后代进程无法在归属前逃逸。
//! - 存活探测：POSIX `kill(-pgid, 0)`；Windows 查询 Job 的 ActiveProcesses。
//! - 整组终止：POSIX SIGTERM → 宽限 → SIGKILL → 等待组退出；Windows 没有等价
//!   的进程级温和信号，直接 `TerminateJobObject` 整树终止（SIGKILL 语义）并
//!   等待组内全部退出，组未在窗口内退干净按"日志完整性未知"上报。
//! - 句柄关闭时 kill-on-close 兜底终止 Job 内残留进程。

use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

/// 子进程与其"进程组"（POSIX pgid / Windows Job Object）的绑定句柄。
pub struct OwnedProcess {
    child: Child,
    group: imp::GroupHandle,
}

impl OwnedProcess {
    pub fn spawn(command: &mut Command) -> Result<Self, String> {
        imp::spawn(command)
    }

    pub fn child(&mut self) -> &mut Child {
        &mut self.child
    }

    /// 组内是否仍有存活成员（对应 POSIX `kill(-pgid, 0)` 探测）。
    pub fn group_alive(&self) -> Result<bool, String> {
        self.group.alive()
    }

    /// 终止整组，返回 (child 终态, 组是否完全退出)。
    pub fn stop_group(&mut self) -> Result<(ExitStatus, bool), String> {
        self.group.stop(&mut self.child)
    }
}

/// 有界等待子进程退出；超时返回 None。
pub fn wait_child(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("wait child: {error}"))?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
mod imp {
    use super::*;

    pub(super) struct GroupHandle {
        pid: u32,
    }

    impl GroupHandle {
        pub(super) fn alive(&self) -> Result<bool, String> {
            let result = unsafe { libc::kill(-(self.pid as i32), 0) };
            if result == 0 {
                return Ok(true);
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ESRCH) => Ok(false),
                Some(libc::EPERM) => Ok(true),
                _ => Err(format!("inspect owned process group: {error}")),
            }
        }

        fn signal_group(&self, signal: i32) -> Result<(), String> {
            let result = unsafe { libc::kill(-(self.pid as i32), signal) };
            if result == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(format!("signal owned process group: {error}"))
            }
        }

        pub(super) fn stop(&self, child: &mut Child) -> Result<(ExitStatus, bool), String> {
            self.signal_group(libc::SIGTERM)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut child_status = None;
            let group_stopped = loop {
                if child_status.is_none() {
                    child_status = child
                        .try_wait()
                        .map_err(|error| format!("wait terminated child: {error}"))?;
                }
                let stopped = !self.alive()?;
                if child_status.is_some() && stopped {
                    break stopped;
                }
                if Instant::now() >= deadline {
                    break stopped;
                }
                thread::sleep(Duration::from_millis(50));
            };
            if !group_stopped {
                self.signal_group(libc::SIGKILL)?;
            }
            if child_status.is_none() {
                child_status = Some(
                    child
                        .wait()
                        .map_err(|error| format!("wait terminated child: {error}"))?,
                );
            }
            let group_stopped = if group_stopped {
                true
            } else {
                wait_group_exit(self, Duration::from_secs(15))?
            };
            Ok((
                child_status.expect("child status is reconciled"),
                group_stopped,
            ))
        }
    }

    fn wait_group_exit(group: &GroupHandle, timeout: Duration) -> Result<bool, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if !group.alive()? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub(super) fn spawn(command: &mut Command) -> Result<OwnedProcess, String> {
        use std::os::unix::process::CommandExt;
        let mut child = command
            .process_group(0)
            .spawn()
            .map_err(|error| format!("spawn suite: {error}"))?;
        let group = GroupHandle { pid: child.id() };
        Ok(OwnedProcess { child, group })
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{
        OpenThread, ResumeThread, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
    };

    pub(super) struct GroupHandle {
        job: windows_sys::Win32::Foundation::HANDLE,
    }

    impl Drop for GroupHandle {
        fn drop(&mut self) {
            // kill-on-close 兜底：句柄关闭时 Job 内残留进程一律终止。
            unsafe { CloseHandle(self.job) };
        }
    }

    impl GroupHandle {
        fn adopt(child: &Child) -> Result<Self, String> {
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return Err(format!(
                        "create suite job object: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ) == 0
                {
                    let error = std::io::Error::last_os_error();
                    CloseHandle(job);
                    return Err(format!("configure suite job object: {error}"));
                }
                if AssignProcessToJobObject(job, child.as_raw_handle()) == 0 {
                    let error = std::io::Error::last_os_error();
                    CloseHandle(job);
                    return Err(format!("assign suite to job object: {error}"));
                }
                Ok(Self { job })
            }
        }

        /// 恢复挂起启动的子进程主线程；子进程此刻只有一个线程，恢复失败
        /// 按 fail-closed 处理（由调用方终止并回收）。
        fn resume_main_thread(&self, pid: u32) -> Result<(), String> {
            unsafe {
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
                    return Err(format!(
                        "snapshot suite threads: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                let mut entry: THREADENTRY32 = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                let mut resumed = 0usize;
                if Thread32First(snapshot, &mut entry) != 0 {
                    loop {
                        if entry.th32OwnerProcessID == pid {
                            let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                            if !thread.is_null() {
                                if ResumeThread(thread) != u32::MAX {
                                    resumed += 1;
                                }
                                CloseHandle(thread);
                            }
                        }
                        if Thread32Next(snapshot, &mut entry) == 0 {
                            break;
                        }
                    }
                }
                CloseHandle(snapshot);
                if resumed == 0 {
                    return Err("resume suspended suite main thread: no thread resumed".into());
                }
                Ok(())
            }
        }

        pub(super) fn alive(&self) -> Result<bool, String> {
            unsafe {
                let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
                if QueryInformationJobObject(
                    self.job,
                    JobObjectBasicAccountingInformation,
                    &mut accounting as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                ) == 0
                {
                    return Err(format!(
                        "query suite job object: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                Ok(accounting.ActiveProcesses > 0)
            }
        }

        /// Windows 没有进程级温和信号：直接整树终止（SIGKILL 等价），
        /// 等待组内全部退出后回收 child 终态。
        pub(super) fn stop(&self, child: &mut Child) -> Result<(ExitStatus, bool), String> {
            unsafe {
                if TerminateJobObject(self.job, u32::MAX) == 0 {
                    return Err(format!(
                        "terminate suite job object: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            let deadline = Instant::now() + Duration::from_secs(15);
            let group_stopped = loop {
                let stopped = !self.alive()?;
                if stopped || Instant::now() >= deadline {
                    break stopped;
                }
                thread::sleep(Duration::from_millis(50));
            };
            let status = child
                .wait()
                .map_err(|error| format!("wait terminated child: {error}"))?;
            Ok((status, group_stopped))
        }
    }

    pub(super) fn spawn(command: &mut Command) -> Result<OwnedProcess, String> {
        command.creation_flags(CREATE_SUSPENDED);
        let mut child = command
            .spawn()
            .map_err(|error| format!("spawn suite: {error}"))?;
        let group = match GroupHandle::adopt(&child) {
            Ok(group) => group,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        if let Err(error) = group.resume_main_thread(child.id()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok(OwnedProcess { child, group })
    }
}
