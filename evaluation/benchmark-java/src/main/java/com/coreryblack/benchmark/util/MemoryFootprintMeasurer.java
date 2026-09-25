package com.coreryblack.benchmark.util;

import lombok.extern.slf4j.Slf4j;

/**
 * Runtime memory footprint measurement across authorization systems.
 *
 * <h3>P2: Fairness Validation — Memory Footprint</h3>
 * Measures whether AstralLight trades memory for speed. Each system's
 * heap usage is captured after initialization and after sustained load.
 *
 * <h3>Metrics</h3>
 * <ul>
 *   <li><b>Init Heap</b> — Heap used after data loading, before any evaluations</li>
 *   <li><b>Steady Heap</b> — Heap used after sustained workload (JIT stable)</li>
 *   <li><b>Peak Heap</b> — Maximum heap observed during benchmark</li>
 *   <li><b>Non-Heap</b> — Metaspace, code cache, etc.</li>
 * </ul>
 */
@Slf4j
public class MemoryFootprintMeasurer {

    /**
     * Baseline heap before any adapter is loaded. Subtracted from all measurements
     * to report Δ footprint (engine-only cost, excluding Spring/GC overhead).
     */
    private static long baselineHeapBytes = 0;

    /** Call once before loading any adapters to establish the empty-process baseline. */
    public static void captureBaseline() {
        MemorySnapshot baseline = MemorySnapshot.capture();
        baselineHeapBytes = baseline.heapUsedBytes;
        log.info("Memory baseline: {} MB (Spring Boot + JVM overhead)", baseline.heapUsedMB);
    }

    /**
     * Memory snapshot captured via Runtime MXBean + GC.
     */
    public static class MemorySnapshot {
        public final long heapUsedBytes;
        public final long heapMaxBytes;
        public final long nonHeapUsedBytes;
        public final long nonHeapMaxBytes;
        public final long heapUsedMB;
        public final long heapMaxMB;

        public MemorySnapshot() {
            Runtime rt = Runtime.getRuntime();
            this.heapUsedBytes = rt.totalMemory() - rt.freeMemory();
            this.heapMaxBytes = rt.maxMemory();
            this.nonHeapUsedBytes = 0; // Requires JMX; populated below if available
            this.nonHeapMaxBytes = 0;
            this.heapUsedMB = heapUsedBytes / (1024 * 1024);
            this.heapMaxMB = heapMaxBytes / (1024 * 1024);
        }

        public static MemorySnapshot capture() {
            // Force a GC to get more accurate "live" heap
            System.gc();
            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            return new MemorySnapshot();
        }

        public String toCsvRow(String systemLabel) {
            return String.format("%s,%d,%d,%d,%d",
                systemLabel, heapUsedBytes, heapMaxBytes,
                nonHeapUsedBytes, nonHeapMaxBytes);
        }

        public static String csvHeader() {
            return "system,heap_used_bytes,heap_max_bytes,nonheap_used_bytes,nonheap_max_bytes";
        }
    }

    /**
     * Result of a memory footprint measurement session.
     */
    public static class FootprintResult {
        public String systemLabel;
        public MemorySnapshot afterInit;
        public MemorySnapshot afterWarmup;
        public MemorySnapshot steadyState;
        public MemorySnapshot peak;
        public long peakBytes;       // raw peak for precise tracking
        public long peakMB;          // peak in MB
        public long deltaPeakMB;     // Δ peak excluding baseline (engine-only cost)
        public int policyCount;      // total policies/entries loaded
        public long initTimeMs;      // initialization wall clock

        public String toLatexRow() {
            return String.format("%s & %d & %d & %d & %d \\\\",
                systemLabel,
                afterInit != null ? afterInit.heapUsedMB : -1,
                peakMB > 0 ? peakMB : (peak != null ? peak.heapUsedMB : -1),
                steadyState != null ? steadyState.heapUsedMB : -1,
                policyCount);
        }

        public static String latexHeader() {
            return "\\textbf{System} & \\textbf{Init (MB)} & " +
                "\\textbf{Peak (MB)} & \\textbf{Steady (MB)} & \\textbf{Policies} \\\\";
        }
    }

    /**
     * Captures the current memory state. Call this from the main benchmark thread
     * after each phase (init, warmup, steady).
     */
    public static FootprintResult measure(
            String systemLabel,
            Runnable initPhase,
            Runnable warmupPhase,
            Runnable steadyPhase,
            int policyCount) {

        FootprintResult result = new FootprintResult();
        result.systemLabel = systemLabel;
        result.policyCount = policyCount;

        long initStart = System.currentTimeMillis();

        // Phase 1: Initialize and measure
        initPhase.run();
        result.afterInit = MemorySnapshot.capture();
        result.initTimeMs = System.currentTimeMillis() - initStart;

        // Phase 2: Warmup
        if (warmupPhase != null) {
            warmupPhase.run();
        }
        result.afterWarmup = MemorySnapshot.capture();

        // Phase 3: Steady state — track peak across all phases
        long peakBytes = result.afterInit.heapUsedBytes;
        if (result.afterWarmup != null && result.afterWarmup.heapUsedBytes > peakBytes) {
            peakBytes = result.afterWarmup.heapUsedBytes;
        }

        if (steadyPhase != null) {
            steadyPhase.run();
            result.steadyState = MemorySnapshot.capture();
            if (result.steadyState.heapUsedBytes > peakBytes) {
                peakBytes = result.steadyState.heapUsedBytes;
            }
        } else {
            result.steadyState = result.afterWarmup != null ? result.afterWarmup : result.afterInit;
        }

        // Peak reflects maximum observed across all phases, not just steady state
        result.peakBytes = peakBytes;
        result.peakMB = peakBytes / (1024 * 1024);
        result.deltaPeakMB = (peakBytes - baselineHeapBytes) / (1024 * 1024);

        log.info("{} memory: init={}MB, peak={}MB (Δ{}MB), steady={}MB, policies={}",
            systemLabel,
            result.afterInit.heapUsedMB,
            result.peakMB,
            result.deltaPeakMB,
            result.steadyState.heapUsedMB,
            policyCount);

        return result;
    }
}
