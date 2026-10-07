package com.coreryblack.benchmark.util;

import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClusterRunContextTest {

    private NativeDataGenerator.NativeEvalRequest request(long cardId, String effect, boolean expectedHit) {
        NativeDataGenerator.NativeEvalRequest req = new NativeDataGenerator.NativeEvalRequest();
        req.cardId = cardId;
        req.userId = 1001L;
        req.resourceType = "learn_subject";
        req.actionCode = "read";
        req.resourceId = 1L;
        req.expectedCardOnlyHit = expectedHit;
        req.expectedCardOnlyEffect = effect;
        return req;
    }

    @Test
    void traceFingerprintIsDeterministicAndOrderSensitive() {
        List<NativeDataGenerator.NativeEvalRequest> trace = List.of(
                request(1L, "ALLOW", true),
                request(2L, "DENY", true),
                request(3L, null, false));
        String first = ClusterRunContext.traceFingerprint(trace);
        String second = ClusterRunContext.traceFingerprint(trace);
        assertEquals(first, second, "fingerprint must be deterministic");

        List<NativeDataGenerator.NativeEvalRequest> reordered = List.of(
                request(3L, null, false),
                request(1L, "ALLOW", true),
                request(2L, "DENY", true));
        assertNotEquals(first, ClusterRunContext.traceFingerprint(reordered),
                "fingerprint must be order-sensitive so partition mismatches are detected");
    }

    @Test
    void traceFingerprintOfEmptyTraceIsStable() {
        assertEquals("empty", ClusterRunContext.traceFingerprint(List.of()));
    }

    @Test
    void singleNodeDefaultsToNoFaultControlPhaseWithoutClusterIdentity() {
        ClusterRunContext ctx = ClusterRunContext.singleNode();
        assertEquals(ClusterRunContext.PHASE_NO_FAULT_CONTROL, ctx.phase());
        assertFalse(ctx.coordinator());
        assertEquals(0L, ctx.globalSequence(0) & 0xFFFFFFFFFFL,
                "local request index is preserved in the low bits");
    }

    @Test
    void globalSequencePartitionsByPhaseOrdinal() {
        ClusterRunContext ctx = new ClusterRunContext("c1", "r1", 1, 1, "node-a",
                ClusterRunContext.HW_XEON_E5_2690_V3, ClusterRunContext.ROLE_WRITER,
                "perm-1", ClusterRunContext.PHASE_MUTATION, "42", false);
        long phaseBase = ctx.globalSequence(0);
        long first = ctx.globalSequence(1);
        long second = ctx.globalSequence(2);
        assertTrue(second > first, "sequence must increase with local index");
        assertTrue(first > phaseBase);

        ClusterRunContext otherPhase = ctx.withPhase(ClusterRunContext.PHASE_VISIBILITY);
        long otherBase = otherPhase.globalSequence(0);
        assertTrue(otherBase > phaseBase, "later phases must produce higher global sequences");
        // Same phase ordinal, different nodes must not collide on index 0.
        ClusterRunContext anotherNode = new ClusterRunContext("c1", "r1", 1, 1, "node-b",
                ClusterRunContext.HW_RYZEN_7_7735HS, ClusterRunContext.ROLE_READER_A,
                "perm-1", ClusterRunContext.PHASE_MUTATION, "42", false);
        assertEquals(phaseBase, anotherNode.globalSequence(0),
                "global sequence is node-independent; per-node request index disambiguates");
    }

    @Test
    void partialClusterPropertiesFailClosed() {
        String previous = System.getProperty("benchmark.cluster.node-id");
        try {
            System.setProperty("benchmark.cluster.node-id", "node-a");
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    ClusterRunContext::fromSystemProperties);
            assertTrue(failure.getMessage().contains("campaign-id"));
        } finally {
            if (previous == null) {
                System.clearProperty("benchmark.cluster.node-id");
            } else {
                System.setProperty("benchmark.cluster.node-id", previous);
            }
        }
    }

    @Test
    void invalidClusterHardwareAndRoleAreRejected() {
        String[] names = {
                "benchmark.cluster.campaign-id", "benchmark.cluster.run-id",
                "benchmark.cluster.replicate", "benchmark.cluster.attempt",
                "benchmark.cluster.node-id", "benchmark.cluster.hardware-label",
                "benchmark.cluster.node-role", "benchmark.cluster.role-permutation",
                "benchmark.cluster.protocol-version", "benchmark.cluster.coordinator"
        };
        java.util.Map<String, String> previous = new java.util.HashMap<>();
        for (String name : names) {
            previous.put(name, System.getProperty(name));
        }
        try {
            System.setProperty("benchmark.cluster.campaign-id", "campaign");
            System.setProperty("benchmark.cluster.run-id", "run");
            System.setProperty("benchmark.cluster.replicate", "1");
            System.setProperty("benchmark.cluster.attempt", "1");
            System.setProperty("benchmark.cluster.node-id", "node-a");
            System.setProperty("benchmark.cluster.hardware-label", "unknown");
            System.setProperty("benchmark.cluster.node-role", ClusterRunContext.ROLE_WRITER);
            System.setProperty("benchmark.cluster.role-permutation", "perm");
            System.setProperty("benchmark.cluster.protocol-version", ClusterRunContext.PROTOCOL_VERSION);
            System.setProperty("benchmark.cluster.coordinator", "true");
            assertThrows(IllegalStateException.class, ClusterRunContext::fromSystemProperties);
        } finally {
            for (var entry : previous.entrySet()) {
                if (entry.getValue() == null) {
                    System.clearProperty(entry.getKey());
                } else {
                    System.setProperty(entry.getKey(), entry.getValue());
                }
            }
        }
    }

    @Test
    void withPhasePreservesIdentity() {
        ClusterRunContext original = new ClusterRunContext("campaign", "run", 1, 2,
                "node-a", ClusterRunContext.HW_XEON_PLATINUM_8000,
                ClusterRunContext.ROLE_WRITER, "perm-1",
                ClusterRunContext.PHASE_PREPARE, "42", true);
        ClusterRunContext changed = original.withPhase(ClusterRunContext.PHASE_RECOVERY);
        assertEquals(original.campaignId(), changed.campaignId());
        assertEquals(original.runId(), changed.runId());
        assertEquals(original.replicate(), changed.replicate());
        assertEquals(original.attempt(), changed.attempt());
        assertEquals(original.nodeId(), changed.nodeId());
        assertEquals(original.hardwareLabel(), changed.hardwareLabel());
        assertEquals(original.nodeRole(), changed.nodeRole());
        assertEquals(original.rolePermutation(), changed.rolePermutation());
        assertEquals(original.seed(), changed.seed());
        assertEquals(original.coordinator(), changed.coordinator());
        assertEquals(ClusterRunContext.PHASE_RECOVERY, changed.phase());
    }

    @Test
    void absentClusterPropertiesFallBackToSingleNode() {
        ClusterRunContext ctx = ClusterRunContext.fromSystemProperties();
        // No cluster properties set in this JVM, so fall back to single-node.
        assertFalse(ctx.coordinator());
    }
}
