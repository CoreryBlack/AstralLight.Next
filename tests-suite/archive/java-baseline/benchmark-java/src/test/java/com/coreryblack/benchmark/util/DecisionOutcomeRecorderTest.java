package com.coreryblack.benchmark.util;

import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DecisionOutcomeRecorderTest {

    @Test
    void recordsDecisionAndExpectedOutcomeMismatch() {
        NativeDataGenerator.NativeEvalRequest request = new NativeDataGenerator.NativeEvalRequest();
        request.cardId = 1L;
        request.userId = 2L;
        request.resourceType = "learn_subject";
        request.actionCode = "read";
        request.expectedCardOnlyHit = true;
        request.expectedCardOnlyEffect = "ALLOW";

        DecisionOutcomeRecorder recorder = new DecisionOutcomeRecorder();
        recorder.recordDecision("NORMAL", 0, request,
                PolicyDecision.builder().allowed(false).reason("DEFAULT_DENY").build(), 10_000L);

        assertEquals(1, recorder.deniedCount());
        assertEquals(1, recorder.expectedAllowMismatchCount());
        assertEquals(0, recorder.expectedDenyMismatchCount());
        assertEquals("DENY", recorder.snapshot().get(0).outcome());
        assertEquals("DEFAULT_DENY", recorder.snapshot().get(0).reason());
    }

    @Test
    void circuitOpenIsAnObservableDenyNotAnError() {
        DecisionOutcomeRecorder recorder = new DecisionOutcomeRecorder();
        recorder.recordCircuitOpen("CB_OPEN", 3, null, 5_000L);

        assertEquals(1, recorder.deniedCount());
        assertEquals(0, recorder.failureCount());
        assertFalse(recorder.snapshot().get(0).allowed());
        assertEquals("CIRCUIT_BREAKER_OPEN", recorder.snapshot().get(0).reason());
        assertEquals("BENCHMARK_SHORT_CIRCUIT", recorder.snapshot().get(0).decisionSource());
    }

    @Test
    void recordsPolicyEngineCircuitBreakerSeparatelyFromHarnessShortCircuit() {
        DecisionOutcomeRecorder recorder = new DecisionOutcomeRecorder();
        recorder.recordDecision("REDIS_DOWN", 0, null,
                PolicyDecision.builder().allowed(false).reason("CIRCUIT_BREAKER_OPEN").build(), 2_000L);

        assertEquals("POLICY_ENGINE_CIRCUIT_BREAKER", recorder.snapshot().get(0).decisionSource());
    }

    @Test
    void auditsRequiredPhasesAndCircuitBreakerSafety() {
        DecisionOutcomeRecorder recorder = new DecisionOutcomeRecorder();
        PolicyDecision returned = PolicyDecision.builder()
                .allowed(false)
                .reason("DEFAULT_DENY")
                .build();
        recorder.recordDecision("NORMAL", 0, null, returned, 1_000L);
        recorder.recordDecision("REDIS_DOWN", 0, null, returned, 1_000L);
        recorder.recordCircuitOpen("CB_OPEN", 0, null, 1_000L);
        recorder.recordDecision("RECOVERY", 0, null, returned, 1_000L);
        DecisionOutcomeRecorder.AuditResult audit = DecisionOutcomeRecorder.audit(recorder.snapshot());
        assertTrue(audit.valid(), audit.detail());
    }

    @Test
    void rejectsIncompleteDecisionCampaign() {
        DecisionOutcomeRecorder recorder = new DecisionOutcomeRecorder();
        recorder.recordCircuitOpen("NORMAL", 0, null, 1_000L);
        DecisionOutcomeRecorder.AuditResult audit = DecisionOutcomeRecorder.audit(recorder.snapshot());
        assertFalse(audit.valid());
        assertTrue(audit.detail().contains("missing"));
    }

    @Test
    void writesEscapedDecisionCsv() throws Exception {
        DecisionOutcomeRecorder recorder = new DecisionOutcomeRecorder();
        recorder.recordFailure("REDIS_DOWN", 1, null,
                new IllegalStateException("redis, unavailable"), 2_000L);

        Path output = Files.createTempFile("decision-outcomes-", ".csv");
        try {
            DecisionOutcomeRecorder.writeCsv(output, recorder.snapshot());
            String csv = Files.readString(output);
            assertTrue(csv.startsWith(DecisionOutcomeRecorder.DecisionOutcome.csvHeader()));
            assertTrue(csv.contains("REDIS_DOWN"));
            assertTrue(csv.contains("IllegalStateException"));
        } finally {
            Files.deleteIfExists(output);
        }
    }
}
