package com.coreryblack.benchmark.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class LatencyRecorderTest {

    @Test
    void shouldRecordSingleSample() {
        LatencyRecorder recorder = new LatencyRecorder();
        long start = recorder.start();
        recorder.stop(start);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        assertEquals(1, snapshot.sampleCount());
        assertEquals(1, snapshot.totalOps());
        assertTrue(snapshot.meanUs() >= 0);
    }

    @Test
    void shouldRecordMultipleSamples() {
        LatencyRecorder recorder = new LatencyRecorder();
        for (int i = 0; i < 100; i++) {
            long start = recorder.start();
            recorder.stop(start);
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        assertEquals(100, snapshot.sampleCount());
        assertEquals(100, snapshot.totalOps());
    }

    @Test
    void shouldCalculatePercentilesCorrectly() {
        LatencyRecorder recorder = new LatencyRecorder();
        for (int i = 0; i < 100; i++) {
            recorder.record((i + 1) * 1000L);
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        assertEquals(50.5, snapshot.meanUs(), 1.0);
        assertEquals(50.0, snapshot.p50Us(), 1.0);
        assertEquals(90.0, snapshot.p90Us(), 1.0);
        assertEquals(95.0, snapshot.p95Us(), 1.0);
        assertEquals(99.0, snapshot.p99Us(), 1.0);
        assertEquals(1.0, snapshot.minUs(), 0.01);
        assertEquals(100.0, snapshot.maxUs(), 0.01);
    }

    @Test
    void shouldHandleEmptySamples() {
        LatencyRecorder recorder = new LatencyRecorder();
        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();

        assertEquals(0, snapshot.sampleCount());
        assertEquals(0, snapshot.totalOps());
        assertEquals(0.0, snapshot.meanUs());
        assertEquals(0.0, snapshot.p50Us());
        assertEquals(0.0, snapshot.tps());
    }

    @Test
    void shouldTrackErrorCount() {
        LatencyRecorder recorder = new LatencyRecorder();
        recorder.recordError();
        recorder.recordError();
        recorder.recordSample(1000L);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        assertEquals(3, snapshot.totalOps());
        assertEquals(2, snapshot.errorOps());
        assertEquals(1, snapshot.sampleCount());
    }

    @Test
    void shouldResetCorrectly() {
        LatencyRecorder recorder = new LatencyRecorder();
        recorder.record(1000L);
        recorder.record(2000L);
        recorder.recordError();

        recorder.reset();

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        assertEquals(0, snapshot.sampleCount());
        assertEquals(0, snapshot.totalOps());
        assertEquals(0, snapshot.errorOps());
    }

    @Test
    void shouldRecordAfterReset() {
        LatencyRecorder recorder = new LatencyRecorder();
        recorder.record(1000L);
        recorder.reset();
        recorder.record(5000L);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        assertEquals(1, snapshot.sampleCount());
        assertEquals(5000.0 / 1000.0, snapshot.meanUs(), 0.01);
    }

    @Test
    void shouldCalculateTPSFromWallClock() {
        LatencyRecorder recorder = new LatencyRecorder();
        for (int i = 0; i < 1000; i++) {
            recorder.record(1000L);
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        double tps = snapshot.tps();
        assertTrue(tps > 0, "TPS should be positive, got: " + tps);
    }

    @Test
    void shouldCalculateTPSWhenOnlyRecordUsedWithoutStartStop() {
        LatencyRecorder recorder = new LatencyRecorder(TimeUnit.NANOSECONDS);
        recorder.record(1000_000L);
        recorder.record(2000_000L);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        double tps = snapshot.tps();
        assertTrue(tps > 0, "TPS should fall back to sample-based calculation");
    }

    @Test
    void shouldBeThreadSafeInConcurrentEnvironment() throws Exception {
        int threadCount = 8;
        int samplesPerThread = 1000;
        LatencyRecorder recorder = new LatencyRecorder();
        CountDownLatch latch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        List<Exception> errors = new ArrayList<>();
        for (int t = 0; t < threadCount; t++) {
            executor.submit(() -> {
                try {
                    for (int i = 0; i < samplesPerThread; i++) {
                        long start = recorder.start();
                        recorder.stop(start);
                    }
                } catch (Exception e) {
                    synchronized (errors) {
                        errors.add(e);
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        executor.shutdown();
        assertTrue(latch.await(10, TimeUnit.SECONDS), "Test timed out");
        assertTrue(errors.isEmpty(), "Concurrent errors: " + errors);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        assertEquals(threadCount * samplesPerThread, snapshot.totalOps());
        assertEquals(threadCount * samplesPerThread, snapshot.sampleCount());
    }

    @Test
    void shouldMaintainWallClockIntegrityUnderConcurrency() throws Exception {
        int threadCount = 4;
        int iterationsPerThread = 500;
        LatencyRecorder recorder = new LatencyRecorder();
        CountDownLatch latch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (int t = 0; t < threadCount; t++) {
            executor.submit(() -> {
                try {
                    Thread.sleep(5);
                    for (int i = 0; i < iterationsPerThread; i++) {
                        long start = recorder.start();
                        recorder.stop(start);
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    latch.countDown();
                }
            });
        }

        executor.shutdown();
        assertTrue(latch.await(10, TimeUnit.SECONDS), "Test timed out");

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        double tps = snapshot.tps();
        assertTrue(Double.isFinite(tps) && tps > 0,
            "TPS should be finite and positive, got: " + tps);
    }

    @Test
    void shouldComputeConfidenceInterval() {
        LatencyRecorder recorder = new LatencyRecorder();
        for (int i = 0; i < 100; i++) {
            recorder.record((i + 1) * 1000L);
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        LatencyRecorder.ConfidenceInterval ci = snapshot.confidenceInterval95Us();

        assertTrue(ci.lower <= ci.mean, "Lower bound should be <= mean");
        assertTrue(ci.mean <= ci.upper, "Mean should be <= upper bound");
        assertTrue(ci.lower > 0, "Lower bound should be positive");
    }

    @Test
    void shouldProduceCsvRow() {
        LatencyRecorder recorder = new LatencyRecorder();
        for (int i = 0; i < 10; i++) {
            recorder.record(1000L);
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        String csv = snapshot.toCsvRow("test");
        assertTrue(csv.startsWith("test,"));
        assertTrue(csv.contains(","));
    }

    @Test
    void shouldProduceLatexRow() {
        LatencyRecorder recorder = new LatencyRecorder();
        for (int i = 0; i < 10; i++) {
            recorder.record(1000L);
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        String latex = snapshot.toLatexRowWithStddev("AstralLight", "1K");
        assertTrue(latex.contains("AstralLight"));
        assertTrue(latex.contains("1K"));
    }

    @Test
    void shouldReturnRawSamples() {
        LatencyRecorder recorder = new LatencyRecorder();
        recorder.record(1000L);
        recorder.record(2000L);
        recorder.record(3000L);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        List<Long> raw = snapshot.rawSamples();
        assertEquals(3, raw.size());
        assertTrue(raw.contains(1000L));
        assertTrue(raw.contains(2000L));
        assertTrue(raw.contains(3000L));
    }
}