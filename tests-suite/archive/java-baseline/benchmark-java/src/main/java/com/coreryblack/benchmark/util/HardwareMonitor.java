package com.coreryblack.benchmark.util;

import lombok.extern.slf4j.Slf4j;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryPoolMXBean;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Hardware usage monitor for benchmark runs.
 * Periodically samples CPU, memory, disk, GC, and cache efficiency metrics
 * and produces a summary suitable for inclusion in benchmark reports.
 *
 * <h3>Efficiency Metrics</h3>
 * <ul>
 *   <li><b>CPU Efficiency</b> — ratio of process CPU to system CPU (how much system CPU is consumed by the JVM process)</li>
 *   <li><b>Memory Efficiency</b> — ratio of active heap data to physical memory consumed</li>
 *   <li><b>GC Efficiency</b> — ratio of application time to total elapsed time (1 - GC overhead)</li>
 *   <li><b>Cache Efficiency</b> — hit rate from Redis L1/L2 cache layers (supplied externally)</li>
 *   <li><b>Storage Efficiency</b> — ratio of benchmark data growth to total disk consumed</li>
 * </ul>
 *
 * <h3>Usage</h3>
 * <pre>
 * HardwareMonitor monitor = new HardwareMonitor();
 * monitor.start("RQ2");                          // begins periodic sampling
 * // ... run benchmark ...
 * HardwareMonitor.HardwareSummary summary = monitor.stop(tps, meanLatencyUs, cacheHitRate);
 * HardwareMonitor.writeSummaryCsv(path, summaries);
 * </pre>
 */
@Slf4j
public class HardwareMonitor {

    private static final com.sun.management.OperatingSystemMXBean OS_BEAN =
            (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
    private static final MemoryMXBean MEM_BEAN = ManagementFactory.getMemoryMXBean();
    private static final List<GarbageCollectorMXBean> GC_BEANS =
            ManagementFactory.getGarbageCollectorMXBeans();
    private static final List<MemoryPoolMXBean> MEM_POOL_BEANS =
            ManagementFactory.getMemoryPoolMXBeans();

    /** Interval between samples in seconds (default: 2) */
    private final long sampleIntervalSec;
    /** Path to monitor for disk usage; defaults to current working directory */
    private final Path diskPath;

    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> scheduledTask;
    /** Thread-safe sample list — CopyOnWriteArrayList avoids data races between scheduler and main threads */
    private final CopyOnWriteArrayList<HardwareSnapshot> samples = new CopyOnWriteArrayList<>();
    private volatile String label = "";

    /** GC counts/times captured at start of monitoring, for delta computation */
    private long gcStartCount = 0;
    private long gcStartTimeMs = 0;
    private long wallClockStartMs = 0;

    public HardwareMonitor() {
        this(2, Path.of("."));
    }

    public HardwareMonitor(long sampleIntervalSec, Path diskPath) {
        this.sampleIntervalSec = sampleIntervalSec;
        this.diskPath = diskPath;
    }

    // ────────────── Snapshot ──────────────

    /**
     * Single point-in-time hardware usage snapshot including GC and efficiency metrics.
     */
    public record HardwareSnapshot(
            double cpuProcessPercent,   // JVM process CPU usage 0-100
            double cpuSystemPercent,    // System-wide CPU usage 0-100
            long heapUsedMb,            // JVM heap used (MB)
            long heapCommittedMb,       // JVM heap committed (MB)
            long heapMaxMb,             // JVM heap max (MB)
            long nonHeapUsedMb,         // JVM non-heap (metaspace etc.) used (MB)
            long physicalFreeMb,        // OS free physical memory (MB)
            long physicalTotalMb,       // OS total physical memory (MB)
            long diskUsableGb,          // Disk usable space (GB)
            long diskTotalGb,           // Disk total space (GB)
            long gcTotalCount,          // Cumulative GC collection count
            long gcTotalTimeMs,         // Cumulative GC time (ms)
            long edenUsedMb,            // Eden space used (MB)
            long oldGenUsedMb,          // Old gen space used (MB)
            long survivorUsedMb,        // Survivor space used (MB)
            long metaspaceUsedMb,       // Metaspace used (MB)
            long timestampMs            // Epoch millis of this snapshot
    ) {
        public long physicalUsedMb() {
            return physicalTotalMb - physicalFreeMb;
        }

        public double physicalUsedPercent() {
            return physicalTotalMb > 0 ? (physicalUsedMb() * 100.0 / physicalTotalMb) : 0;
        }

        public double heapUsedPercent() {
            return heapMaxMb > 0 ? (heapUsedMb * 100.0 / heapMaxMb) : 0;
        }

        public long diskUsedGb() {
            return diskTotalGb - diskUsableGb;
        }

        public double diskUsedPercent() {
            return diskTotalGb > 0 ? (diskUsedGb() * 100.0 / diskTotalGb) : 0;
        }
    }

    /**
     * Aggregated hardware usage summary over a monitoring period,
     * including derived efficiency metrics.
     */
    public record HardwareSummary(
            String label,
            // CPU
            double cpuProcessAvg, double cpuProcessMax,
            double cpuSystemAvg, double cpuSystemMax,
            double cpuEfficiency,           // CPU efficiency: process_cpu / system_cpu
            // Memory
            long heapUsedAvgMb, long heapUsedMaxMb, long heapMaxMb,
            long physicalUsedAvgMb, long physicalUsedMaxMb, long physicalTotalMb,
            double memoryEfficiency,        // Memory efficiency: heap_used / physical_used
            // Disk / Storage
            long diskUsedStartGb, long diskUsedEndGb, long diskTotalGb,
            double storageEfficiency,       // Storage efficiency: data_growth / disk_total
            // GC
            long gcTotalCount, long gcTotalTimeMs,
            double gcEfficiency,            // GC efficiency: 1 - gc_overhead_ratio
            double gcOverheadPct,           // GC overhead as percentage
            double gcPauseAvgMs,            // Average GC pause duration (ms)
            // Cache (supplied externally)
            double cacheEfficiency,         // Cache hit rate (0.0 - 1.0)
            // Metadata
            int sampleCount,
            long wallClockMs,
            HardwareSnapshot first, HardwareSnapshot last
    ) {
        public String toCsvRow() {
            return String.format("%s,%.1f,%.1f,%.1f,%.1f,%.4f," +
                            "%d,%d,%d,%d,%d,%d,%.4f," +
                            "%d,%d,%d,%.4f," +
                            "%d,%d,%.4f,%.2f,%.1f," +
                            "%.4f," +
                            "%d,%d",
                    label,
                    cpuProcessAvg, cpuProcessMax,
                    cpuSystemAvg, cpuSystemMax,
                    cpuEfficiency,
                    heapUsedAvgMb, heapUsedMaxMb, heapMaxMb,
                    physicalUsedAvgMb, physicalUsedMaxMb, physicalTotalMb,
                    memoryEfficiency,
                    diskUsedStartGb, diskUsedEndGb, diskTotalGb,
                    storageEfficiency,
                    gcTotalCount, gcTotalTimeMs,
                    gcEfficiency, gcOverheadPct, gcPauseAvgMs,
                    cacheEfficiency,
                    sampleCount, wallClockMs);
        }

        public static String csvHeader() {
            return "label," +
                    "cpu_process_avg_pct,cpu_process_max_pct,cpu_system_avg_pct,cpu_system_max_pct,cpu_efficiency," +
                    "heap_used_avg_mb,heap_used_max_mb,heap_max_mb,phys_used_avg_mb,phys_used_max_mb,phys_total_mb,memory_efficiency," +
                    "disk_used_start_gb,disk_used_end_gb,disk_total_gb,storage_efficiency," +
                    "gc_total_count,gc_total_time_ms,gc_efficiency,gc_overhead_pct,gc_pause_avg_ms," +
                    "cache_efficiency," +
                    "sample_count,wall_clock_ms";
        }
    }

    // ────────────── Capture ──────────────

    /**
     * Capture a single hardware usage snapshot including GC and memory pool details.
     */
    public static HardwareSnapshot capture() {
        return capture(Path.of("."));
    }

    public static HardwareSnapshot capture(Path diskPath) {
        double cpuProcess = OS_BEAN.getProcessCpuLoad() * 100.0;
        double cpuSystem = OS_BEAN.getSystemCpuLoad() * 100.0;

        long heapUsed = MEM_BEAN.getHeapMemoryUsage().getUsed() / (1024 * 1024);
        long heapCommitted = MEM_BEAN.getHeapMemoryUsage().getCommitted() / (1024 * 1024);
        long heapMax = MEM_BEAN.getHeapMemoryUsage().getMax() / (1024 * 1024);
        long nonHeapUsed = MEM_BEAN.getNonHeapMemoryUsage().getUsed() / (1024 * 1024);

        long physicalFree = OS_BEAN.getFreePhysicalMemorySize() / (1024 * 1024);
        long physicalTotal = OS_BEAN.getTotalPhysicalMemorySize() / (1024 * 1024);

        long diskUsable = 0, diskTotal = 0;
        try {
            FileStore store = Files.getFileStore(diskPath.toAbsolutePath());
            diskUsable = store.getUsableSpace() / (1024 * 1024 * 1024);
            diskTotal = store.getTotalSpace() / (1024 * 1024 * 1024);
        } catch (IOException e) {
            log.warn("Failed to read disk usage for {}: {}", diskPath, e.getMessage());
        }

        // GC statistics
        long gcCount = 0, gcTimeMs = 0;
        for (GarbageCollectorMXBean gcBean : GC_BEANS) {
            long c = gcBean.getCollectionCount();
            if (c >= 0) gcCount += c;
            long t = gcBean.getCollectionTime();
            if (t >= 0) gcTimeMs += t;
        }

        // Memory pool details
        long edenUsed = 0, oldGenUsed = 0, survivorUsed = 0, metaspaceUsed = 0;
        for (MemoryPoolMXBean pool : MEM_POOL_BEANS) {
            String name = pool.getName().toLowerCase();
            var usage = pool.getUsage();
            if (usage == null) continue;
            long used = usage.getUsed() / (1024 * 1024);
            if (name.contains("eden")) edenUsed += used;
            else if (name.contains("old") || name.contains("tenured")) oldGenUsed += used;
            else if (name.contains("survivor")) survivorUsed += used;
            else if (name.contains("metaspace")) metaspaceUsed += used;
        }

        return new HardwareSnapshot(
                Math.max(0, cpuProcess), Math.max(0, cpuSystem),
                heapUsed, heapCommitted, heapMax, nonHeapUsed,
                physicalFree, physicalTotal,
                diskUsable, diskTotal,
                gcCount, gcTimeMs,
                edenUsed, oldGenUsed, survivorUsed, metaspaceUsed,
                System.currentTimeMillis());
    }

    // ────────────── Periodic Monitoring ──────────────

    /**
     * Start periodic hardware sampling in a background thread.
     * @param label Label for this monitoring session (e.g., "RQ2", "full_suite")
     */
    public void start(String label) {
        this.label = label;
        this.samples.clear();

        // Capture baseline GC counters for delta computation
        HardwareSnapshot initial = capture(diskPath);
        this.gcStartCount = initial.gcTotalCount();
        this.gcStartTimeMs = initial.gcTotalTimeMs();
        this.wallClockStartMs = System.currentTimeMillis();
        samples.add(initial);

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "hw-monitor-" + label);
            t.setDaemon(true);
            return t;
        });

        scheduledTask = scheduler.scheduleAtFixedRate(() -> {
            try {
                HardwareSnapshot snap = capture(diskPath);
                samples.add(snap);
            } catch (Exception e) {
                log.warn("Hardware sample capture failed: {}", e.getMessage());
            }
        }, sampleIntervalSec, sampleIntervalSec, TimeUnit.SECONDS);

        log.info("[HW-Monitor] Started monitoring '{}' (interval={}s, disk={})",
                label, sampleIntervalSec, diskPath.toAbsolutePath());
    }

    /**
     * Stop periodic monitoring and return the aggregated summary.
     * Cache efficiency defaults to 0 (unknown).
     */
    public HardwareSummary stop() {
        return stop(0);
    }

    /**
     * Stop periodic monitoring and return the aggregated summary with cache hit rate.
     *
     * @param cacheHitRate Overall cache hit rate (0.0 - 1.0), or -1 if unknown
     */
    public HardwareSummary stop(double cacheHitRate) {
        if (scheduledTask != null) {
            scheduledTask.cancel(false);
        }
        if (scheduler != null) {
            scheduler.shutdown();
            try {
                boolean terminated = scheduler.awaitTermination(5, TimeUnit.SECONDS);
                if (!terminated) {
                    log.warn("[HW-Monitor] Scheduler did not terminate within 5s, forcing shutdown");
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                scheduler.shutdownNow();
            }
        }

        // Capture final snapshot (scheduler is now stopped, no race)
        HardwareSnapshot finalSnap = capture(diskPath);
        samples.add(finalSnap);

        long wallClockMs = System.currentTimeMillis() - wallClockStartMs;
        List<HardwareSnapshot> snapshotList = new ArrayList<>(samples);
        HardwareSummary summary = aggregate(label, snapshotList, wallClockMs,
                gcStartCount, gcStartTimeMs, cacheHitRate);

        log.info("[HW-Monitor] Stopped '{}': CPU(proc)={}/{}%, CPU(sys)={}/{}%, " +
                        "Heap={}/{}/{}MB, Phys={}/{}/{}MB, Disk={}/{}GB, " +
                        "GC={}/{}ms/{}%, Eff=[cpu={},mem={},gc={},cache={},storage={}] ({} samples)",
                label,
                String.format("%.1f", summary.cpuProcessAvg), String.format("%.1f", summary.cpuProcessMax),
                String.format("%.1f", summary.cpuSystemAvg), String.format("%.1f", summary.cpuSystemMax),
                summary.heapUsedAvgMb, summary.heapUsedMaxMb, summary.heapMaxMb,
                summary.physicalUsedAvgMb, summary.physicalUsedMaxMb, summary.physicalTotalMb,
                summary.diskUsedStartGb, summary.diskUsedEndGb,
                summary.gcTotalCount, summary.gcTotalTimeMs, String.format("%.2f", summary.gcOverheadPct),
                String.format("%.4f", summary.cpuEfficiency), String.format("%.4f", summary.memoryEfficiency),
                String.format("%.4f", summary.gcEfficiency), String.format("%.4f", summary.cacheEfficiency),
                String.format("%.4f", summary.storageEfficiency),
                summary.sampleCount);

        return summary;
    }

    /**
     * Aggregate a list of snapshots into a summary with derived efficiency metrics.
     */
    public static HardwareSummary aggregate(String label, List<HardwareSnapshot> samplesList,
                                             long wallClockMs,
                                             long baselineGcCount, long baselineGcTimeMs,
                                             double cacheHitRate) {
        if (samplesList == null || samplesList.isEmpty()) {
            return new HardwareSummary(label, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0, 0,
                    0,
                    0, 0, null, null);
        }

        double cpuProcSum = 0, cpuProcMax = 0;
        double cpuSysSum = 0, cpuSysMax = 0;
        long heapUsedSum = 0, heapUsedMax = 0, heapMaxVal = 0;
        long physUsedSum = 0, physUsedMax = 0, physTotalVal = 0;
        long diskTotalVal = 0;

        for (HardwareSnapshot s : samplesList) {
            cpuProcSum += s.cpuProcessPercent();
            cpuProcMax = Math.max(cpuProcMax, s.cpuProcessPercent());
            cpuSysSum += s.cpuSystemPercent();
            cpuSysMax = Math.max(cpuSysMax, s.cpuSystemPercent());

            heapUsedSum += s.heapUsedMb();
            heapUsedMax = Math.max(heapUsedMax, s.heapUsedMb());
            heapMaxVal = Math.max(heapMaxVal, s.heapMaxMb());

            long physUsed = s.physicalUsedMb();
            physUsedSum += physUsed;
            physUsedMax = Math.max(physUsedMax, physUsed);
            physTotalVal = Math.max(physTotalVal, s.physicalTotalMb());

            diskTotalVal = Math.max(diskTotalVal, s.diskTotalGb());
        }

        int n = samplesList.size();
        HardwareSnapshot first = samplesList.get(0);
        HardwareSnapshot last = samplesList.get(n - 1);

        double cpuProcAvg = cpuProcSum / n;
        double cpuSysAvg = cpuSysSum / n;

        // ── CPU Efficiency ──
        // Ratio of JVM process CPU to system CPU: how much of the system's CPU
        // is consumed by the benchmark process. Higher = more CPU dedicated to our workload.
        // When system CPU is low (idle system), this metric approaches 1.0 naturally.
        double cpuEfficiency;
        if (cpuSysAvg > 0) {
            cpuEfficiency = Math.min(1.0, cpuProcAvg / cpuSysAvg);
        } else {
            cpuEfficiency = 0;
        }

        // ── Memory Efficiency ──
        // Ratio of active heap data to physical memory consumed by the JVM.
        // Higher = less memory overhead (GC metadata, off-heap, thread stacks, etc.)
        double memoryEfficiency;
        if (physUsedSum > 0) {
            double heapAvg = (double) heapUsedSum / n;
            double physAvg = (double) physUsedSum / n;
            memoryEfficiency = heapAvg / physAvg;
        } else {
            memoryEfficiency = 0;
        }

        // ── Storage Efficiency ──
        // Ratio of benchmark data growth to total disk space.
        // Measures how much disk the benchmark consumed relative to available capacity.
        long diskDeltaGb = last.diskUsedGb() - first.diskUsedGb();
        double storageEfficiency;
        if (diskTotalVal > 0 && diskDeltaGb > 0) {
            // Positive growth: efficiency = growth / total (how much of disk was consumed by benchmark data)
            storageEfficiency = (double) diskDeltaGb / diskTotalVal;
        } else if (diskTotalVal > 0) {
            // No growth or shrinkage: report current utilization
            storageEfficiency = (double) first.diskUsedGb() / diskTotalVal;
        } else {
            storageEfficiency = 0;
        }

        // ── GC Efficiency ──
        // Fraction of wall-clock time NOT spent in GC.
        // Fix #5: use count delta (not time>0) as the condition guard.
        long gcDeltaCount = last.gcTotalCount() - baselineGcCount;
        long gcDeltaTimeMs = last.gcTotalTimeMs() - baselineGcTimeMs;
        // Guard against negative deltas (GC bean reset in rare cases)
        if (gcDeltaCount < 0) gcDeltaCount = 0;
        if (gcDeltaTimeMs < 0) gcDeltaTimeMs = 0;

        double gcOverheadPct = wallClockMs > 0
                ? (gcDeltaTimeMs * 100.0 / wallClockMs)
                : 0;
        double gcEfficiency = Math.max(0, 1.0 - (gcOverheadPct / 100.0));
        double gcPauseAvgMs = gcDeltaCount > 0
                ? (double) gcDeltaTimeMs / gcDeltaCount
                : 0;

        // ── Cache Efficiency (externally supplied) ──
        double cacheEff = cacheHitRate >= 0 ? cacheHitRate : 0;

        // Debug: log raw calculation values to verify formulas
        log.info("[HW-Debug] aggregate '{}': n={}, cpuProc={}, cpuSys={} → cpuEff={}, " +
                "diskFirst={}, diskLast={}, diskTotal={}, diskDelta={} → storageEff={}, " +
                "cacheHitRate={} → cacheEff={}",
                label, n, cpuProcAvg, cpuSysAvg, cpuEfficiency,
                first.diskUsedGb(), last.diskUsedGb(), diskTotalVal, diskDeltaGb, storageEfficiency,
                cacheHitRate, cacheEff);

        HardwareSummary summary = new HardwareSummary(
                label,
                cpuProcAvg, cpuProcMax,
                cpuSysAvg, cpuSysMax,
                cpuEfficiency,
                heapUsedSum / n, heapUsedMax, heapMaxVal,
                physUsedSum / n, physUsedMax, physTotalVal,
                memoryEfficiency,
                first.diskUsedGb(), last.diskUsedGb(), diskTotalVal,
                storageEfficiency,
                gcDeltaCount, gcDeltaTimeMs,
                gcEfficiency, gcOverheadPct, gcPauseAvgMs,
                cacheEff,
                n, wallClockMs,
                first, last);

        // Debug: verify summary fields match computed values
        log.info("[HW-Verify] summary.cpuEff={}, summary.memEff={}, summary.gcEff={}, summary.cacheEff={}, summary.storageEff={}, summary.sampleCount={}",
                summary.cpuEfficiency(), summary.memoryEfficiency(), summary.gcEfficiency(),
                summary.cacheEfficiency(), summary.storageEfficiency(), summary.sampleCount());

        return summary;
    }

    // ────────────── File Output ──────────────

    /**
     * Write hardware summary to a CSV file.
     */
    public static void writeSummaryCsv(String path, List<HardwareSummary> summaries) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println(HardwareSummary.csvHeader());
            for (HardwareSummary s : summaries) {
                pw.println(s.toCsvRow());
            }
        }
    }

    /**
     * Write full time-series samples to a CSV file.
     */
    public static void writeTimeSeriesCsv(String path, String label, List<HardwareSnapshot> sampleList) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("label,timestamp_ms,cpu_process_pct,cpu_system_pct," +
                    "heap_used_mb,heap_committed_mb,heap_max_mb,non_heap_used_mb," +
                    "phys_free_mb,phys_total_mb,disk_usable_gb,disk_total_gb," +
                    "gc_count,gc_time_ms,eden_mb,old_gen_mb,survivor_mb,metaspace_mb");
            for (HardwareSnapshot s : sampleList) {
                pw.printf("%s,%d,%.1f,%.1f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d%n",
                        label, s.timestampMs(),
                        s.cpuProcessPercent(), s.cpuSystemPercent(),
                        s.heapUsedMb(), s.heapCommittedMb(), s.heapMaxMb(), s.nonHeapUsedMb(),
                        s.physicalFreeMb(), s.physicalTotalMb(),
                        s.diskUsableGb(), s.diskTotalGb(),
                        s.gcTotalCount(), s.gcTotalTimeMs(),
                        s.edenUsedMb(), s.oldGenUsedMb(), s.survivorUsedMb(), s.metaspaceUsedMb());
            }
        }
    }

    /**
     * Write a LaTeX table summarizing hardware usage and efficiency across all benchmark phases.
     */
    public static void writeLatexHardwareTable(String path, List<HardwareSummary> summaries) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("% Hardware Usage & Efficiency During Benchmark - Auto-generated " + java.time.LocalDateTime.now());
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Hardware Resource Utilization and Efficiency During Benchmark Execution}");
            pw.println("\\label{tab:hardware-usage}");
            pw.println("\\begin{tabular}{lrrrrrrrrr}");
            pw.println("\\toprule");
            pw.println("\\textbf{Phase} & \\textbf{CPU Avg\\%} & \\textbf{CPU Max\\%} & " +
                    "\\textbf{Heap Max} & \\textbf{Phys Max} & " +
                    "\\textbf{Disk $\\Delta$} & \\textbf{GC Overhead\\%} & " +
                    "\\textbf{CPU Eff} & \\textbf{Mem Eff} & \\textbf{GC Eff} \\\\");
            pw.println("\\midrule");
            for (HardwareSummary s : summaries) {
                pw.printf("%s & %.1f & %.1f & %d MB & %d MB & %d GB & %.2f & %.3f & %.3f & %.3f \\\\%n",
                        s.label(), s.cpuProcessAvg(), s.cpuProcessMax(),
                        s.heapUsedMaxMb(), s.physicalUsedMaxMb(),
                        s.diskUsedEndGb() - s.diskUsedStartGb(),
                        s.gcOverheadPct(),
                        s.cpuEfficiency(), s.memoryEfficiency(), s.gcEfficiency());
            }
            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println();
            pw.println("% CPU: JVM process CPU utilization");
            pw.println("% Heap Max: Peak JVM heap usage during phase");
            pw.println("% Phys Max: Peak physical memory usage during phase");
            pw.println("% Disk Delta: Disk space consumed during phase");
            pw.println("% GC Overhead: Percentage of wall-clock time spent in GC");
            pw.println("% CPU Eff: process_cpu / system_cpu (how much system CPU is our process)");
            pw.println("% Mem Eff: heap_used / physical_used (how much physical memory is active heap data)");
            pw.println("% GC Eff: 1 - GC overhead ratio (fraction of time NOT in GC)");
            pw.println("\\end{table}");
        }
    }

    /**
     * Write a dedicated LaTeX table for efficiency metrics.
     */
    public static void writeLatexEfficiencyTable(String path, List<HardwareSummary> summaries) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("% Efficiency Metrics - Auto-generated " + java.time.LocalDateTime.now());
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Resource Efficiency Metrics Across Benchmark Phases}");
            pw.println("\\label{tab:efficiency-metrics}");
            pw.println("\\begin{tabular}{lrrrrr}");
            pw.println("\\toprule");
            pw.println("\\textbf{Phase} & \\textbf{CPU Eff} & \\textbf{Mem Eff} & " +
                    "\\textbf{GC Eff} & \\textbf{Cache Eff} & \\textbf{Storage Eff} \\\\");
            pw.println("\\midrule");
            for (HardwareSummary s : summaries) {
                pw.printf("%s & %.3f & %.3f & %.3f & %.3f & %.3f \\\\%n",
                        s.label(),
                        s.cpuEfficiency(), s.memoryEfficiency(),
                        s.gcEfficiency(), s.cacheEfficiency(), s.storageEfficiency());
            }
            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println();
            pw.println("% CPU Eff: process_cpu / system_cpu (fraction of system CPU consumed by JVM)");
            pw.println("% Mem Eff: heap_used / physical_used (fraction of physical memory that is active heap data)");
            pw.println("% GC Eff: 1 - GC overhead ratio (fraction of time NOT in GC)");
            pw.println("% Cache Eff: Cache hit rate from L1/L2 cache layers");
            pw.println("% Storage Eff: benchmark data growth / total disk capacity");
            pw.println("\\end{table}");
        }
    }

    /**
     * Write a LaTeX table for GC statistics.
     */
    public static void writeLatexGcTable(String path, List<HardwareSummary> summaries) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("% GC Statistics - Auto-generated " + java.time.LocalDateTime.now());
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Garbage Collection Statistics During Benchmark Execution}");
            pw.println("\\label{tab:gc-stats}");
            pw.println("\\begin{tabular}{lrrrrr}");
            pw.println("\\toprule");
            pw.println("\\textbf{Phase} & \\textbf{GC Count} & \\textbf{GC Time (ms)} & " +
                    "\\textbf{GC Overhead\\%} & \\textbf{Avg Pause (ms)} & \\textbf{Wall Clock (s)} \\\\");
            pw.println("\\midrule");
            for (HardwareSummary s : summaries) {
                pw.printf("%s & %d & %d & %.2f & %.1f & %.1f \\\\%n",
                        s.label(),
                        s.gcTotalCount(), s.gcTotalTimeMs(),
                        s.gcOverheadPct(), s.gcPauseAvgMs(),
                        s.wallClockMs() / 1000.0);
            }
            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println("\\end{table}");
        }
    }

    /**
     * Get the current samples collected so far (without stopping the monitor).
     */
    public List<HardwareSnapshot> getCurrentSamples() {
        return new ArrayList<>(samples);
    }
}
