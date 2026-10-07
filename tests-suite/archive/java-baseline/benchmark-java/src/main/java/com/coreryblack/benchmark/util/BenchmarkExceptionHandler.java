package com.coreryblack.benchmark.util;

import lombok.extern.slf4j.Slf4j;

/**
 * Unified exception handler for benchmark operations.
 * Replaces empty catch blocks with proper logging, ensuring exceptions
 * are never silently swallowed while maintaining benchmark performance.
 */
@Slf4j
public class BenchmarkExceptionHandler {

    /**
     * Handle a benchmark exception that is expected/harmless but should be logged.
     * Logs at TRACE level to avoid performance impact in hot loops.
     */
    public void onExpected(String operation, Exception e) {
        if (log.isTraceEnabled()) {
            log.trace("Benchmark [{}] expected exception: {}", operation, e.getMessage());
        }
    }

    /**
     * Handle an InterruptedException properly: log and restore interrupt status.
     */
    public void onInterrupt(String operation, InterruptedException e) {
        if (log.isDebugEnabled()) {
            log.debug("Benchmark [{}] interrupted: {}", operation, e.getMessage());
        }
        Thread.currentThread().interrupt();
    }

    /**
     * Handle an unexpected exception that indicates a real problem.
     * Logs at WARN level with full stack trace.
     */
    public void onUnexpected(String operation, Exception e) {
        log.warn("Benchmark [{}] unexpected exception", operation, e);
    }
}
