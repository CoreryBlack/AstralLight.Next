package com.coreryblack.benchmark.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class LatencyRecorder {

    private final ConcurrentLinkedQueue<Long> samples = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<Long> errorSamples = new ConcurrentLinkedQueue<>();
    private final AtomicLong totalCount = new AtomicLong(0);
    private final AtomicLong errorCount = new AtomicLong(0);
    private final TimeUnit unit;
    private final AtomicLong wallClockStartNanos = new AtomicLong(0);
    private final AtomicLong wallClockEndNanos = new AtomicLong(0);
    /** First-call (cold) latency in nanoseconds; 0 if not yet recorded */
    private final AtomicLong coldStartNanos = new AtomicLong(0);

    public LatencyRecorder() {
        this(TimeUnit.NANOSECONDS);
    }

    public LatencyRecorder(TimeUnit unit) {
        this.unit = unit;
        // Measurement starts explicitly on the first measured operation (or via
        // wallClockStart()).  Starting in the constructor would include warmup
        // and dataset preparation time in TPS.
        this.wallClockStartNanos.set(0L);
    }

    public void record(long value) {
        samples.add(value);
        totalCount.incrementAndGet();
    }

    /**
     * Records one failed operation without adding it to the latency sample.
     * Callers must not invoke stop() for the same operation afterwards.
     */
    public void recordError() {
        errorCount.incrementAndGet();
        totalCount.incrementAndGet();
    }

    /**
     * Records one failed operation and keeps its elapsed time out of the
     * successful-latency percentiles.  Error latency can be reported separately
     * by the caller when required; it must not be followed by stop().
     */
    public void recordError(long elapsedNanos) {
        if (elapsedNanos >= 0) {
            errorSamples.add(elapsedNanos);
        }
        recordError();
    }

    public void recordSample(long elapsedNanos) {
        record(elapsedNanos);
    }

    /**
     * Explicitly mark the wall-clock start. Useful for concurrent benchmarks
     * where threads are synchronized via CountDownLatch before measurement.
     */
    public void wallClockStart() {
        wallClockStartNanos.compareAndSet(0, System.nanoTime());
    }

    public long start() {
        wallClockStartNanos.compareAndSet(0, System.nanoTime());
        return System.nanoTime();
    }

    public long stop(long startNanos) {
        long elapsed = System.nanoTime() - startNanos;
        record(elapsed);
        wallClockEndNanos.set(System.nanoTime());
        return elapsed;
    }

    public LatencySnapshot snapshot() {
        List<Long> copy = new ArrayList<>(samples);
        long[] arr = copy.stream().mapToLong(Long::longValue).toArray();
        long[] errorArr = errorSamples.stream().mapToLong(Long::longValue).toArray();
        long wcStart = wallClockStartNanos.get();
        long wcEnd = wallClockEndNanos.get();
        long wallClock = wcStart > 0 ? wcEnd - wcStart : 0;
        if (wallClock <= 0 && wcStart > 0) {
            wallClock = System.nanoTime() - wcStart;
        }
        long coldNanos = coldStartNanos.get();
        double coldUs = coldNanos > 0 ? coldNanos / 1000.0 : -1.0;
        return new LatencySnapshot(arr, errorArr, unit, totalCount.get(), errorCount.get(), wallClock, coldUs);
    }

    public void reset() {
        samples.clear();
        errorSamples.clear();
        totalCount.set(0);
        errorCount.set(0);
        coldStartNanos.set(0);
        wallClockStartNanos.set(0L);
        wallClockEndNanos.set(0);
    }

    /**
     * Record the first-call (cold) latency. Only the first call takes effect;
     * subsequent calls are ignored to prevent warm iterations from overwriting.
     */
    public void recordColdStart(long elapsedNanos) {
        coldStartNanos.compareAndSet(0, elapsedNanos);
    }

    public static class LatencySnapshot {

        private final long[] sortedNanos;
        private final long[] errorNanos;
        private final TimeUnit unit;
        private final long totalOps;
        private final long errorOps;
        private final long wallClockNanos;

        /** First-call (cold) latency in microseconds; -1 if not recorded */
        public final double coldStartUs;

        private LatencySnapshot(long[] sortedNanos, TimeUnit unit, long totalOps, long errorOps, long wallClockNanos) {
            this(sortedNanos, new long[0], unit, totalOps, errorOps, wallClockNanos, -1.0);
        }

        private LatencySnapshot(long[] sortedNanos, long[] errorNanos, TimeUnit unit,
                                long totalOps, long errorOps, long wallClockNanos,
                                double coldStartUs) {
            Arrays.sort(sortedNanos);
            Arrays.sort(errorNanos);
            this.sortedNanos = sortedNanos;
            this.errorNanos = errorNanos;
            this.unit = unit;
            this.totalOps = totalOps;
            this.errorOps = errorOps;
            this.wallClockNanos = wallClockNanos;
            this.coldStartUs = coldStartUs;
        }

        public static LatencySnapshot empty(TimeUnit unit) {
            return new LatencySnapshot(new long[0], unit, 0, 0, 0);
        }

        public double meanUs() {
            if (sortedNanos.length == 0) return 0;
            double sum = 0.0;
            for (long v : sortedNanos) sum += v;
            return sum / sortedNanos.length / 1000.0;
        }

        /** Mean latency of failed operations, kept separate from success percentiles. */
        public double errorMeanUs() {
            if (errorNanos.length == 0) return 0;
            double sum = 0.0;
            for (long v : errorNanos) sum += v;
            return sum / errorNanos.length / 1000.0;
        }

        public double p50Us() { return percentileUs(50); }
        public double p90Us() { return percentileUs(90); }
        public double p95Us() { return percentileUs(95); }
        public double p99Us() { return percentileUs(99); }
        public double p999Us() { return percentileUs(99.9); }
        public double minUs() { return sortedNanos.length == 0 ? 0 : sortedNanos[0] / 1000.0; }
        public double maxUs() { return sortedNanos.length == 0 ? 0 : sortedNanos[sortedNanos.length - 1] / 1000.0; }

        /**
         * Sample standard deviation of raw samples in microseconds.
         * Uses two-pass algorithm for numerical stability, Bessel's correction (n-1).
         */
        public double stddevUs() {
            if (sortedNanos.length < 2) return 0;
            double mean = meanUs();
            double sumSq = 0;
            for (long v : sortedNanos) {
                double d = v / 1000.0 - mean;
                sumSq += d * d;
            }
            return Math.sqrt(sumSq / (sortedNanos.length - 1));
        }

        /** Margin of error for 95% confidence interval (mean ± moeUs). */
        public double moe95Us() {
            if (sortedNanos.length < 2) return 0;
            return 1.96 * stddevUs() / Math.sqrt(sortedNanos.length);
        }

        /** Lower bound of 95% confidence interval for the mean. */
        public double ci95LowUs() {
            return meanUs() - moe95Us();
        }

        /** Upper bound of 95% confidence interval for the mean. */
        public double ci95HighUs() {
            return meanUs() + moe95Us();
        }

        public double percentileUs(double pct) {
            if (sortedNanos.length == 0) return 0;
            int index = (int) Math.ceil(pct / 100.0 * sortedNanos.length) - 1;
            index = Math.max(0, Math.min(index, sortedNanos.length - 1));
            return sortedNanos[index] / 1000.0;
        }

        public double tps() {
            if (totalOps <= 0) return 0;
            if (wallClockNanos > 0) {
                return totalOps * 1_000_000_000.0 / wallClockNanos;
            }
            if (sortedNanos.length < 2) return 0;
            long totalNanos = 0;
            for (long v : sortedNanos) {
                totalNanos += v;
            }
            if (totalNanos == 0) return 0;
            return sortedNanos.length * 1_000_000_000.0 / totalNanos;
        }

        public long totalOps() { return totalOps; }
        public long errorOps() { return errorOps; }
        public int sampleCount() { return sortedNanos.length; }

        public List<Long> rawSamples() {
            List<Long> list = new ArrayList<>(sortedNanos.length);
            for (long v : sortedNanos) {
                list.add(v);
            }
            return list;
        }

        public String toCsvRow(String label) {
            ConfidenceInterval ci = confidenceInterval95Us();
            return String.format("%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d,%.0f,%.2f,%.2f",
                label, meanUs(), stddevUs(), p50Us(), p95Us(), p99Us(), p999Us(),
                minUs(), maxUs(), totalOps, errorOps, tps(), ci.lower, ci.upper);
        }

        public static String csvHeader() {
            return "label,mean_us,stddev_us,p50_us,p95_us,p99_us,p999_us,min_us,max_us,total_ops,error_ops,tps,ci95_low_us,ci95_high_us";
        }

        /**
         * Formatted tabular row: mean +/- stddev with P95 and P99.
         */
        public String toLatexRowWithStddev(String system, String scale) {
            return String.format("%s & %s & $%.1f \\pm %.1f$ & %.1f & %.1f & %.1f & %.0f \\\\",
                system, scale, meanUs(), stddevUs(), p95Us(), p99Us(), maxUs(), tps());
        }

        public ConfidenceInterval confidenceInterval95Us() {
            // Bootstrap percentile method with 10000 resamples.
            return bootstrapCI(10_000, 0.95);
        }

        private ConfidenceInterval bootstrapCI(int resamples, double confidence) {
            if (sortedNanos.length < 2) {
                double mean = meanUs();
                return new ConfidenceInterval(mean, mean, mean);
            }

            java.util.Random rng = new java.util.Random(42);
            double[] bootstrapMeans = new double[resamples];
            int n = sortedNanos.length;

            for (int b = 0; b < resamples; b++) {
                long sum = 0;
                for (int i = 0; i < n; i++) {
                    int idx = rng.nextInt(n);
                    sum += sortedNanos[idx];
                }
                bootstrapMeans[b] = (double) sum / n / 1000.0;
            }

            Arrays.sort(bootstrapMeans);
            double alpha = 1.0 - confidence;
            int lowerIdx = (int) Math.floor(resamples * alpha / 2.0);
            int upperIdx = (int) Math.ceil(resamples * (1.0 - alpha / 2.0)) - 1;
            lowerIdx = Math.max(0, lowerIdx);
            upperIdx = Math.min(resamples - 1, upperIdx);

            return new ConfidenceInterval(meanUs(), bootstrapMeans[lowerIdx], bootstrapMeans[upperIdx]);
        }

        /**
         * Merges multiple snapshots from repeat runs into one aggregate.
         * Combines raw samples and sums total/error/wall-clock counters.
         */
        public static LatencySnapshot merge(TimeUnit unit, LatencySnapshot... snapshots) {
            if (snapshots == null || snapshots.length == 0) return empty(unit);
            if (snapshots.length == 1) return snapshots[0];

            int totalSamples = 0;
            long totalOps = 0, totalErrors = 0, totalWallClock = 0;
            for (LatencySnapshot s : snapshots) {
                totalSamples += s.sortedNanos.length;
                totalOps += s.totalOps;
                totalErrors += s.errorOps;
                totalWallClock += s.wallClockNanos;
            }

            long[] merged = new long[totalSamples];
            int off = 0;
            for (LatencySnapshot s : snapshots) {
                System.arraycopy(s.sortedNanos, 0, merged, off, s.sortedNanos.length);
                off += s.sortedNanos.length;
            }

            return new LatencySnapshot(merged, unit, totalOps, totalErrors, totalWallClock);
        }
    }

    public static class ConfidenceInterval {
        public final double mean;
        public final double lower;
        public final double upper;

        public ConfidenceInterval(double mean, double lower, double upper) {
            this.mean = mean;
            this.lower = lower;
            this.upper = upper;
        }
    }
}
