package com.coreryblack.benchmark.util;

import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Immutable context describing one node's role inside a heterogeneous
 * three-node benchmark campaign.
 *
 * <p>The three machines (Intel Xeon Platinum 8000, Xeon E5-2690 v3, Ryzen 7
 * 7735HS) are crossed against the workload roles so that hardware effects are
 * estimated from within-node no-fault baselines and distributed-consistency
 * effects from paired phase deltas, never by averaging P99 across different
 * hardware.</p>
 *
 * <p>When the cluster properties are absent the context degrades to a
 * single-node run, so the existing single-host benchmarks keep their
 * behavior.</p>
 */
public record ClusterRunContext(
        String campaignId,
        String runId,
        int replicate,
        int attempt,
        String nodeId,
        String hardwareLabel,
        String nodeRole,
        String rolePermutation,
        String phase,
        String seed,
        boolean coordinator) {

    public static final String PROTOCOL_VERSION = "rq4-cluster-3nodes-v2";

    // Hardware labels for the three-node heterogeneous campaign.
    public static final String HW_XEON_PLATINUM_8000 = "xeon-platinum-8000";
    public static final String HW_XEON_E5_2690_V3 = "xeon-e5-2690-v3";
    public static final String HW_RYZEN_7_7735HS = "ryzen-7-7735hs";

    // Workload roles. The coordinator is the only node allowed to perform
    // destructive cleanup and dataset persistence; readers verify fingerprints
    // read-only.
    public static final String ROLE_COORDINATOR = "COORDINATOR";
    public static final String ROLE_WRITER = "WRITER";
    public static final String ROLE_READER_A = "READER_A";
    public static final String ROLE_READER_B = "READER_B";

    // Fixed phase schedule shared by every node. Phase transitions use
    // barrier acknowledgements so no node can outrun the coordinator.
    public static final String PHASE_PREFLIGHT = "PREFLIGHT";
    public static final String PHASE_PREPARE = "PREPARE";
    public static final String PHASE_FINGERPRINT_VERIFY = "FINGERPRINT_VERIFY";
    public static final String PHASE_COLD_CACHE = "COLD_CACHE";
    public static final String PHASE_WARM_READONLY = "WARM_READONLY";
    public static final String PHASE_NO_FAULT_CONTROL = "NO_FAULT_CONTROL";
    public static final String PHASE_MUTATION = "MUTATION";
    public static final String PHASE_VISIBILITY = "VISIBILITY";
    public static final String PHASE_FAULT_INJECTION = "FAULT_INJECTION";
    public static final String PHASE_FAULT_STEADY = "FAULT_STEADY";
    public static final String PHASE_HEAL = "HEAL";
    public static final String PHASE_RECOVERY = "RECOVERY";
    public static final String PHASE_POSTCONDITION_AUDIT = "POSTCONDITION_AUDIT";

    public static final String[] PHASES = {
            PHASE_PREFLIGHT, PHASE_PREPARE, PHASE_FINGERPRINT_VERIFY, PHASE_COLD_CACHE,
            PHASE_WARM_READONLY, PHASE_NO_FAULT_CONTROL, PHASE_MUTATION, PHASE_VISIBILITY,
            PHASE_FAULT_INJECTION, PHASE_FAULT_STEADY, PHASE_HEAL, PHASE_RECOVERY,
            PHASE_POSTCONDITION_AUDIT
    };

    /**
     * Single-node default: no cluster properties present, no coordinator role.
     */
    public static ClusterRunContext singleNode() {
        return new ClusterRunContext(null, null, 0, 0, null, null, null, null,
                PHASE_NO_FAULT_CONTROL, null, false);
    }

    private static final String[] CLUSTER_PROPERTY_NAMES = {
            "benchmark.cluster.campaign-id",
            "benchmark.cluster.run-id",
            "benchmark.cluster.replicate",
            "benchmark.cluster.attempt",
            "benchmark.cluster.node-id",
            "benchmark.cluster.hardware-label",
            "benchmark.cluster.node-role",
            "benchmark.cluster.role-permutation",
            "benchmark.cluster.phase",
            "benchmark.cluster.coordinator",
            "benchmark.cluster.protocol-version"
    };

    public static boolean clusterPropertiesPresent() {
        for (String propertyName : CLUSTER_PROPERTY_NAMES) {
            if (System.getProperty(propertyName) != null) {
                return true;
            }
        }
        return false;
    }

    private static boolean knownHardwareLabel(String hardwareLabel) {
        return HW_XEON_PLATINUM_8000.equals(hardwareLabel)
                || HW_XEON_E5_2690_V3.equals(hardwareLabel)
                || HW_RYZEN_7_7735HS.equals(hardwareLabel);
    }

    private static boolean supportedNodeRole(String nodeRole) {
        return ROLE_WRITER.equals(nodeRole)
                || ROLE_READER_A.equals(nodeRole)
                || ROLE_READER_B.equals(nodeRole);
    }

    /**
     * Builds the context from {@code -Dbenchmark.cluster.*} system properties.
     * Missing properties fall back to the single-node context, so existing
     * single-host runs are unaffected. A partially specified cluster context
     * is rejected rather than silently becoming a single-node run.
     */
    public static ClusterRunContext fromSystemProperties() {
        String campaignId = System.getProperty("benchmark.cluster.campaign-id");
        String runId = System.getProperty("benchmark.cluster.run-id");
        int replicate = Integer.getInteger("benchmark.cluster.replicate", 0);
        int attempt = Integer.getInteger("benchmark.cluster.attempt", 0);
        String nodeId = System.getProperty("benchmark.cluster.node-id");
        String hardwareLabel = System.getProperty("benchmark.cluster.hardware-label");
        String nodeRole = System.getProperty("benchmark.cluster.node-role");
        String rolePermutation = System.getProperty("benchmark.cluster.role-permutation");
        String phase = System.getProperty("benchmark.cluster.phase", PHASE_NO_FAULT_CONTROL);
        String seed = System.getProperty("benchmark.seed", "42");
        boolean coordinator = Boolean.getBoolean("benchmark.cluster.coordinator");
        String protocolVersion = System.getProperty("benchmark.cluster.protocol-version");
        if (!clusterPropertiesPresent()) {
            return singleNode();
        }
        requireClusterProperty("benchmark.cluster.campaign-id", campaignId);
        requireClusterProperty("benchmark.cluster.run-id", runId);
        requireClusterProperty("benchmark.cluster.node-id", nodeId);
        requireClusterProperty("benchmark.cluster.hardware-label", hardwareLabel);
        requireClusterProperty("benchmark.cluster.node-role", nodeRole);
        requireClusterProperty("benchmark.cluster.role-permutation", rolePermutation);
        requireClusterProperty("benchmark.cluster.protocol-version", protocolVersion);
        if (!PROTOCOL_VERSION.equals(protocolVersion)) {
            throw new IllegalStateException("Unsupported cluster protocol version: " + protocolVersion);
        }
        if (replicate < 1 || attempt < 1) {
            throw new IllegalStateException("Cluster replicate and attempt must be positive");
        }
        if (!knownHardwareLabel(hardwareLabel)) {
            throw new IllegalStateException("Unsupported cluster hardware label: " + hardwareLabel);
        }
        if (!isPhase(phase)) {
            throw new IllegalStateException("Unsupported cluster phase: " + phase);
        }
        if (!supportedNodeRole(nodeRole)) {
            throw new IllegalStateException("Unsupported cluster node role: " + nodeRole);
        }
        if (coordinator != ROLE_WRITER.equals(nodeRole)) {
            throw new IllegalStateException("Cluster coordinator flag must match WRITER role");
        }
        return new ClusterRunContext(campaignId, runId, replicate, attempt,
                nodeId, hardwareLabel, nodeRole, rolePermutation, phase, seed, coordinator);
    }

    public boolean isClusterRun() {
        return campaignId != null || nodeId != null;
    }

    private static void requireClusterProperty(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for a cluster run");
        }
    }

    private static boolean isPhase(String phase) {
        for (String candidate : PHASES) {
            if (candidate.equals(phase)) {
                return true;
            }
        }
        return false;
    }

    public ClusterRunContext withPhase(String newPhase) {
        return new ClusterRunContext(campaignId, runId, replicate, attempt, nodeId,
                hardwareLabel, nodeRole, rolePermutation, newPhase, seed, coordinator);
    }

    /**
     * Deterministic fingerprint of a generated request trace. Every node in a
     * cluster must verify the same fingerprint before measuring, otherwise the
     * runs are not comparable.
     */
    public static String traceFingerprint(List<NativeDataGenerator.NativeEvalRequest> requests) {
        if (requests == null || requests.isEmpty()) {
            return "empty";
        }
        MessageDigest digest = sha256();
        for (NativeDataGenerator.NativeEvalRequest request : requests) {
            digest.update((request.cardId + "|" + request.userId + "|" + request.resourceType
                    + "|" + request.actionCode + "|" + request.resourceId + "|"
                    + request.expectedCardOnlyHit + "|" + request.expectedCardOnlyEffect)
                    .getBytes(StandardCharsets.UTF_8));
        }
        return toHex(digest.digest());
    }

    /**
     * Global operation sequence for one request on this node. Using the phase
     * ordinal as the high bits keeps the per-phase partition deterministic
     * across processes instead of each JVM numbering from zero independently.
     */
    public long globalSequence(int localIndex) {
        int phaseOrdinal = ordinal(phase);
        return ((long) phaseOrdinal << 40) | (Integer.toUnsignedLong(localIndex));
    }

    private static int ordinal(String phase) {
        if (phase == null) {
            return 0;
        }
        for (int i = 0; i < PHASES.length; i++) {
            if (PHASES[i].equals(phase)) {
                return i;
            }
        }
        return 0;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
