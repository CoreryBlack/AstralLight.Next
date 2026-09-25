package com.coreryblack.benchmark.config;

import lombok.Builder;
import lombok.Data;

import java.lang.management.ManagementFactory;

@Data
@Builder
public class SandboxConfig {

    @Builder.Default
    private String cpuModel = detectCpuModel();
    @Builder.Default
    private int cpuCores = Runtime.getRuntime().availableProcessors();
    @Builder.Default
    private int jvmHeapGb = (int) (Runtime.getRuntime().maxMemory() / (1024 * 1024 * 1024));
    @Builder.Default
    private int totalMemoryGb = detectTotalMemoryGb();
    @Builder.Default
    private int availableMemoryGb = detectAvailableMemoryGb();
    @Builder.Default
    private String memoryType = "N/A (auto-detected)";
    @Builder.Default
    private String jvmFlags = detectJvmFlags();
    @Builder.Default
    private String redisVersion = "7.x";
    @Builder.Default
    private String redisTopology = "single-node (Docker)";
    @Builder.Default
    private int redisMaxMemoryMb = 800;
    @Builder.Default
    private String mysqlVersion = "8.0.45";
    @Builder.Default
    private int mysqlBufferPoolMb = 1024;
    @Builder.Default
    private String os = System.getProperty("os.name") + " " + System.getProperty("os.version");
    @Builder.Default
    private String jdkVersion = System.getProperty("java.vm.name") + " " + System.getProperty("java.vm.version");
    @Builder.Default
    private int warmupIterations = 10;
    @Builder.Default
    private int measurementIterations = 20;
    @Builder.Default
    private int warmupTimeMs = 5000;
    @Builder.Default
    private int measurementTimeMs = 10000;
    @Builder.Default
    private int forkCount = 3;
    @Builder.Default
    private int threads = 8;

    private static String detectCpuModel() {
        try {
            java.lang.management.OperatingSystemMXBean osBean =
                java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            return osBean.getName() != null ? osBean.getName() : "Unknown CPU";
        } catch (Exception e) {
            return "Unknown CPU";
        }
    }

    private static int detectTotalMemoryGb() {
        try {
            com.sun.management.OperatingSystemMXBean osBean =
                (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
            long totalBytes = osBean.getTotalPhysicalMemorySize();
            return totalBytes > 0 ? (int) (totalBytes / (1024 * 1024 * 1024)) : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private static int detectAvailableMemoryGb() {
        try {
            com.sun.management.OperatingSystemMXBean osBean =
                (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
            long freeBytes = osBean.getFreePhysicalMemorySize();
            return freeBytes > 0 ? (int) (freeBytes / (1024 * 1024 * 1024)) : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private static String detectJvmFlags() {
        try {
            java.util.List<String> args = java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments();
            return String.join(" ", args);
        } catch (Exception e) {
            return "N/A";
        }
    }

    public String toLatexTable() {
        return """
            \\begin{table}[htbp]
            \\centering
            \\caption{Experimental Environment Specification}
            \\label{tab:sandbox}
            \\begin{tabular}{ll}
            \\toprule
            \\textbf{Component} & \\textbf{Specification} \\\\
            \\midrule
            CPU & %s (%d cores) \\\\
            JVM Heap & %d GB \\\\
            JVM Flags & %s \\\\
            JDK & %s \\\\
            Redis & %s (%s, maxmemory=%dMB) \\\\
            MySQL & %s (buffer_pool=%dMB) \\\\
            OS & %s \\\\
            JMH Forks & %d \\\\
            JMH Warmup & %d iter × %dms \\\\
            JMH Measurement & %d iter × %dms \\\\
            Concurrency & %d threads \\\\
            \\bottomrule
            \\end{tabular}
            \\end{table}
            """.formatted(cpuModel, cpuCores, jvmHeapGb, jvmFlags, jdkVersion,
                redisVersion, redisTopology, redisMaxMemoryMb,
                mysqlVersion, mysqlBufferPoolMb, os,
                forkCount, warmupIterations, warmupTimeMs,
                measurementIterations, measurementTimeMs, threads);
    }
}
