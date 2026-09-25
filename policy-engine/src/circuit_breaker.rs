//! 断路器状态

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// 断路器自动切换参数
pub const CB_THRESHOLD: u32 = 10;
pub const CB_RECOVERY_MS: u64 = 30_000;

/// 断路器状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen(u32),
}

/// 带自动切换的断路器
pub struct AutoCircuitBreaker {
    state: std::sync::RwLock<CircuitBreakerState>,
    failures: AtomicU32,
    last_failure_time: Mutex<Option<Instant>>,
}

impl AutoCircuitBreaker {
    pub fn new() -> Self {
        Self {
            state: std::sync::RwLock::new(CircuitBreakerState::Closed),
            failures: AtomicU32::new(0),
            last_failure_time: Mutex::new(None),
        }
    }

    /// 返回是否应拒绝本次请求；HalfOpen 只允许有限数量的并发探针。
    pub fn is_open(&self) -> bool {
        let Ok(mut state) = self.state.write() else {
            return true;
        };

        if *state == CircuitBreakerState::Open {
            if let Ok(last_fail) = self.last_failure_time.lock() {
                if last_fail
                    .map(|time| time.elapsed().as_millis() as u64 >= CB_RECOVERY_MS)
                    .unwrap_or(false)
                {
                    *state = CircuitBreakerState::HalfOpen(3);
                }
            }
        }

        match *state {
            CircuitBreakerState::Open => true,
            CircuitBreakerState::HalfOpen(ref mut remaining) => {
                if *remaining == 0 {
                    true
                } else {
                    *remaining -= 1;
                    false
                }
            }
            CircuitBreakerState::Closed => false,
        }
    }

    pub fn record_failure(&self) {
        let count = self.failures.fetch_add(1, Ordering::Release) + 1;
        if let Ok(mut last) = self.last_failure_time.lock() {
            *last = Some(Instant::now());
        }
        if count >= CB_THRESHOLD {
            if let Ok(mut state) = self.state.write() {
                match *state {
                    CircuitBreakerState::Closed => {
                        *state = CircuitBreakerState::Open;
                    }
                    // HalfOpen 探测失败：立即重新 Open，重新计时恢复窗口。
                    // 避免长期停留在探针态，导致每次探测都放行到已故障的仓库。
                    CircuitBreakerState::HalfOpen(_) => {
                        *state = CircuitBreakerState::Open;
                    }
                    CircuitBreakerState::Open => {}
                }
            }
        }
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Release);
        if let Ok(mut state) = self.state.write() {
            if matches!(*state, CircuitBreakerState::HalfOpen(_)) {
                *state = CircuitBreakerState::Closed;
            }
        }
    }

    pub fn state(&self) -> CircuitBreakerState {
        self.state
            .read()
            .map(|g| g.clone())
            .unwrap_or(CircuitBreakerState::Closed)
    }
}

impl Default for AutoCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_breaker() -> AutoCircuitBreaker {
        let breaker = AutoCircuitBreaker::new();
        for _ in 0..CB_THRESHOLD {
            breaker.record_failure();
        }
        assert_eq!(breaker.state(), CircuitBreakerState::Open);
        breaker
    }

    #[test]
    fn closed_opens_after_threshold_failures() {
        let breaker = open_breaker();
        assert_eq!(breaker.state(), CircuitBreakerState::Open);
        assert!(breaker.is_open());
    }

    #[test]
    fn half_open_allows_only_probe_budget() {
        let breaker = open_breaker();
        *breaker.state.write().unwrap() = CircuitBreakerState::HalfOpen(3);
        assert!(!breaker.is_open());
        assert!(!breaker.is_open());
        assert!(!breaker.is_open());
        assert!(breaker.is_open());
    }
    #[test]
    fn half_open_failure_reopens_instead_of_sticking() {
        let mut breaker = open_breaker();
        // 模拟 Open 超时后进入 HalfOpen 探针态。
        breaker.state = std::sync::RwLock::new(CircuitBreakerState::HalfOpen(3));
        assert!(!breaker.is_open());

        // HalfOpen 探测失败应重新 Open（重新计时恢复窗口），而不是长期停在探针态。
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitBreakerState::Open);
    }

    #[test]
    fn half_open_success_closes() {
        let mut breaker = open_breaker();
        breaker.state = std::sync::RwLock::new(CircuitBreakerState::HalfOpen(3));
        breaker.record_success();
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);
        assert_eq!(breaker.failures.load(Ordering::Relaxed), 0);
    }
}
