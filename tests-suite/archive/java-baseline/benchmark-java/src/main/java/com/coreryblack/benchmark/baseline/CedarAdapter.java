package com.coreryblack.benchmark.baseline;

import com.cedarpolicy.BasicAuthorizationEngine;
import com.cedarpolicy.AuthorizationEngine;
import com.cedarpolicy.model.AuthorizationRequest;
import com.cedarpolicy.model.AuthorizationResponse;
import com.cedarpolicy.model.Context;
import com.cedarpolicy.model.entity.Entities;
import com.cedarpolicy.model.entity.Entity;
import com.cedarpolicy.model.policy.PolicySet;
import com.cedarpolicy.value.EntityUID;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cedar authorization adapter using the official cedar-java SDK with
 * template-level policy sharing via {@code principal in Group} syntax.
 *
 * <p>Uses {@code com.cedarpolicy:cedar-java} which embeds the Rust-based
 * Cedar authorization engine via JNI. This provides the same evaluation
 * semantics as Amazon Verified Permissions and the Cedar CLI.</p>
 *
 * <h3>Template-Level Sharing</h3>
 * <p>Instead of generating per-card permit/forbid statements (MxN explosion),
 * this adapter generates one policy per template rule using
 * {@code permit(principal in CardGroup::"template_X", ...)} syntax.
 * Cards are entities with {@code parents: [CardGroup::"template_X"]}.</p>
 *
 * <p>Policy count: O(templates × rules) instead of O(cards × rules).
 * For 50K cards × 3 templates × 45 rules: 135 policies (vs 2.25M).</p>
 *
 * <h3>Cedar Policy Mapping</h3>
 * <ul>
 *   <li>ALLOW rule → {@code permit(principal in CardGroup::"template_X", action, resource);}</li>
 *   <li>DENY rule → {@code forbid(principal in CardGroup::"template_X", action, resource);}</li>
 * </ul>
 * <p>Cedar's deny-override semantics naturally match AstralLight's rule evaluation.</p>
 */
@Slf4j
public class CedarAdapter {

    private final AuthorizationEngine authEngine = new BasicAuthorizationEngine();

    // Shared PolicySet (template-level policies, loaded once)
    private PolicySet sharedPolicySet;
    private Entities sharedEntities;

    // Entity UID caches for fast request construction
    private final Map<String, EntityUID> principalUidCache = new ConcurrentHashMap<>();
    private final Map<String, EntityUID> actionUidCache = new ConcurrentHashMap<>();
    private final Map<String, EntityUID> resourceUidCache = new ConcurrentHashMap<>();

    /**
     * Per-card minimal entity slice: the card principal + its CardGroup parent +
     * all actions + all resource types. Cedar resolves {@code principal in
     * CardGroup::"template_X"} purely from this slice, so the engine only ever
     * serializes a constant-sized entity set per request instead of the full
     * card store. This is the documented Cedar production pattern for entity
     * slicing (pass only the entities relevant to the authorization query) and
     * preserves the exact same decisions as passing the full store.
     */
    private final Map<Long, Entities> cardEntitySliceCache = new ConcurrentHashMap<>();
    private final Map<String, EntityUID> groupUidCache = new ConcurrentHashMap<>();

    private final boolean optimized;
    private boolean initialized = false;
    private int lastPolicyCount;
    private int lastEntityCount;

    public CedarAdapter(boolean optimized) {
        this.optimized = optimized;
    }

    // ────────────── Initialization ──────────────

    public void initialize(DataGenerator.GeneratedDataSet dataset) {
        // Clear previous scale's caches to prevent OOM accumulation across scales
        principalUidCache.clear();
        actionUidCache.clear();
        resourceUidCache.clear();
        cardEntitySliceCache.clear();
        groupUidCache.clear();
        sharedPolicySet = null;
        sharedEntities = null;
        System.gc();

        initializeWithTemplateSharing(dataset);
        initialized = true;
        log.info("Cedar {} initialized using official cedar-java SDK (template-shared): policies={}, entities={}",
            optimized ? "(Optimized)" : "(Default)", lastPolicyCount, lastEntityCount);
        // Prove the entity-slice optimization preserves decisions before any
        // measurement is taken. If the slice ever diverges from the full store,
        // the benchmark must not proceed with possibly wrong Cedar numbers.
        verifySliceEquivalence(dataset, 10);
    }

    /**
     * Evaluates a single request against the given entity store.
     */
    private boolean evalWithEntities(long cardId, String resource, String action, Entities entities) {
        String principalKey = "card_" + cardId;
        EntityUID principalUid = principalUidCache.get(principalKey);
        EntityUID actionUid = actionUidCache.get(action);
        EntityUID resourceUid = resourceUidCache.get(resource);
        if (principalUid == null || actionUid == null || resourceUid == null) {
            return false;
        }
        try {
            AuthorizationRequest request = new AuthorizationRequest(
                principalUid, actionUid, resourceUid, new Context());
            AuthorizationResponse response = authEngine.isAuthorized(
                request, sharedPolicySet, entities);
            return extractDecision(response);
        } catch (Exception e) {
            log.debug("Cedar evaluation error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Compares the entity-slice path against the full entity store on a small
     * sample. A single divergence aborts initialization: the comparison numbers
     * for Cedar would otherwise be meaningless.
     */
    private void verifySliceEquivalence(DataGenerator.GeneratedDataSet dataset, int sampleCount) {
        int n = Math.min(sampleCount, dataset.evalRequests.size());
        for (int i = 0; i < n; i++) {
            DataGenerator.EvalRequest req = dataset.evalRequests.get(i);
            boolean full = evalWithEntities(req.cardId, req.resourceType, req.actionCode, sharedEntities);
            boolean sliced = evalWithEntities(req.cardId, req.resourceType, req.actionCode,
                buildEntitySlice(req.cardId));
            if (full != sliced) {
                throw new IllegalStateException(
                    "Cedar entity-slice equivalence check FAILED: card=" + req.cardId
                        + " resource=" + req.resourceType + " action=" + req.actionCode
                        + " fullEntities=" + full + " slice=" + sliced
                        + " — the slice optimization changed semantics; benchmark aborted.");
            }
        }
        log.info("Cedar entity-slice equivalence verified on {} request(s) (slice == full store)",
            n);
    }

    /**
     * Initialize with template-level policy sharing.
     *
     * <p>Generates one Cedar policy per template rule using
     * {@code principal in CardGroup::"template_X"} syntax.
     * Cards are entities with parent groups matching their template.</p>
     */
    private void initializeWithTemplateSharing(DataGenerator.GeneratedDataSet dataset) {
        StringBuilder policyBuilder = new StringBuilder();
        int policyId = 0;

        // Generate template-level policies (one per rule, not per card)
        if (dataset.allBaseEntries != null) {
            for (int t = 0; t < dataset.allBaseEntries.size(); t++) {
                String group = "CardGroup::\"template_" + t + "\"";

                // Base rules for this template
                if (dataset.allBaseEntries.get(t) != null) {
                    for (var entry : dataset.allBaseEntries.get(t)) {
                        String action = "Action::\"" + entry.getActionCode() + "\"";
                        String resource = entry.getResourceType() + "::\"*\"";
                        if ("DENY".equalsIgnoreCase(entry.getEffect())) {
                            policyBuilder.append("forbid(principal in ").append(group)
                                .append(", action == ").append(action)
                                .append(", resource == ").append(resource).append(");\n");
                        } else {
                            policyBuilder.append("permit(principal in ").append(group)
                                .append(", action == ").append(action)
                                .append(", resource == ").append(resource).append(");\n");
                        }
                        policyId++;
                    }
                }

                // Overlay rules for this template (flat injection for common semantic subset)
                if (dataset.allOverlayEntries != null && t < dataset.allOverlayEntries.size()
                    && dataset.allOverlayEntries.get(t) != null) {
                    for (var entry : dataset.allOverlayEntries.get(t)) {
                        String action = "Action::\"" + entry.getActionCode() + "\"";
                        String resource = entry.getResourceType() + "::\"*\"";
                        if ("DENY".equalsIgnoreCase(entry.getEffect())) {
                            policyBuilder.append("forbid(principal in ").append(group)
                                .append(", action == ").append(action)
                                .append(", resource == ").append(resource).append(");\n");
                        } else {
                            policyBuilder.append("permit(principal in ").append(group)
                                .append(", action == ").append(action)
                                .append(", resource == ").append(resource).append(");\n");
                        }
                        policyId++;
                    }
                }
            }
        }

        lastPolicyCount = policyId;

        try {
            sharedPolicySet = PolicySet.parsePolicies(policyBuilder.toString());
        } catch (Exception e) {
            log.error("Failed to parse Cedar policy set ({} policies): {}", policyId, e.getMessage());
            sharedPolicySet = new PolicySet();
        }

        // Build entity hierarchy with CardGroup parents
        sharedEntities = buildEntitiesWithGroups(dataset);
    }

    /**
     * Build Cedar entity hierarchy with CardGroup parents for template-level sharing.
     *
     * <p>Each card entity has its CardGroup as a parent:
     * {@code Card::"card_0" → parents: [CardGroup::"template_0"]}</p>
     *
     * <p>This enables {@code principal in CardGroup::"template_X"} to match
     * all cards belonging to that template.</p>
     */
    private Entities buildEntitiesWithGroups(DataGenerator.GeneratedDataSet dataset) {
        Set<Entity> entitySet = new HashSet<>();

        // Add CardGroup entities (one per template)
        int templateCount = dataset.allBaseEntries != null ? dataset.allBaseEntries.size() : 0;
        for (int t = 0; t < templateCount; t++) {
            EntityUID groupUid = EntityUID.parse("CardGroup::\"template_" + t + "\"").orElse(null);
            if (groupUid != null) {
                entitySet.add(new Entity(groupUid));
            }
        }

        // Add card entities with CardGroup parents
        for (DataGenerator.CardBinding binding : dataset.bindings) {
            String principalKey = "card_" + binding.cardId;
            EntityUID principalUid = EntityUID.parse("Card::\"" + principalKey + "\"").orElse(null);
            EntityUID parentUid = EntityUID.parse("CardGroup::\"template_" + binding.templateIdx + "\"").orElse(null);

            if (principalUid != null) {
                Set<EntityUID> parents = new HashSet<>();
                if (parentUid != null) {
                    parents.add(parentUid);
                }
                entitySet.add(new Entity(principalUid, parents));
                principalUidCache.put(principalKey, principalUid);
                if (parentUid != null) {
                    groupUidCache.put(principalKey, parentUid);
                }
            }
        }

        // Add action entities
        for (String action : DataGenerator.ACTIONS) {
            EntityUID uid = EntityUID.parse("Action::\"" + action + "\"").orElse(null);
            if (uid != null) {
                entitySet.add(new Entity(uid));
                actionUidCache.put(action, uid);
            }
        }

        // Add resource type entities
        for (String resourceType : DataGenerator.RESOURCE_TYPES) {
            EntityUID uid = EntityUID.parse(resourceType + "::\"*\"").orElse(null);
            if (uid != null) {
                entitySet.add(new Entity(uid));
                resourceUidCache.put(resourceType, uid);
            }
        }

        lastEntityCount = entitySet.size();
        return new Entities(entitySet);
    }

    // ────────────── Evaluation ──────────────

    /**
     * Evaluate authorization using the official Cedar engine with a per-card
     * entity slice. Cedar's deny-override semantics: forbid wins over permit.
     */
    public boolean isAuthorized(long cardId, String resource, String action) {
        String principalKey = "card_" + cardId;

        EntityUID principalUid = principalUidCache.computeIfAbsent(principalKey,
            k -> EntityUID.parse("Card::\"" + k + "\"").orElse(null));
        EntityUID actionUid = actionUidCache.computeIfAbsent(action,
            k -> EntityUID.parse("Action::\"" + k + "\"").orElse(null));
        EntityUID resourceUid = resourceUidCache.computeIfAbsent(resource,
            k -> EntityUID.parse(k + "::\"*\"").orElse(null));

        if (principalUid == null || actionUid == null || resourceUid == null) {
            return false;
        }

        try {
            Entities slice = cardEntitySliceCache.computeIfAbsent(cardId,
                k -> buildEntitySlice(cardId));
            // Use the EntityUID-based constructor; Cedar resolves the principal's
            // CardGroup membership from the slice (constant size per request).
            AuthorizationRequest request = new AuthorizationRequest(
                principalUid, actionUid, resourceUid, new Context());
            AuthorizationResponse response = authEngine.isAuthorized(
                request, sharedPolicySet, slice);
            return extractDecision(response);
        } catch (Exception e) {
            log.debug("Cedar evaluation error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Builds the minimal entity slice for one card: the card principal, its
     * CardGroup parent, and every action/resource type entity. The slice is
     * cached per card; size is O(1) w.r.t. card count, so per-request
     * serialization stays constant instead of O(cards).
     */
    private Entities buildEntitySlice(long cardId) {
        String principalKey = "card_" + cardId;
        EntityUID principalUid = principalUidCache.get(principalKey);
        EntityUID groupUid = groupUidCache.get(principalKey);

        Set<Entity> slice = new HashSet<>();
        if (groupUid != null) {
            slice.add(new Entity(groupUid));
        }
        if (principalUid != null) {
            Set<EntityUID> parents = new HashSet<>();
            if (groupUid != null) {
                parents.add(groupUid);
            }
            slice.add(new Entity(principalUid, parents));
        }
        // Every action and resource type (constant, ~21 entities) must be in the
        // slice so the engine can match action/resource entities in policies.
        for (EntityUID uid : actionUidCache.values()) {
            if (uid != null) {
                slice.add(new Entity(uid));
            }
        }
        for (EntityUID uid : resourceUidCache.values()) {
            if (uid != null) {
                slice.add(new Entity(uid));
            }
        }
        return new Entities(slice);
    }

    /**
     * Extract the allow/deny decision from Cedar's AuthorizationResponse.
     */
    private boolean extractDecision(AuthorizationResponse response) {
        if (response.type == AuthorizationResponse.SuccessOrFailure.Success
            && response.success.isPresent()) {
            return response.success.get().isAllowed();
        }
        return false;
    }

    // ────────────── Benchmark ──────────────

    private static final int WARMUP = 1000;

    public LatencyRecorder.LatencySnapshot benchmarkEval(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        if (!initialized) {
            initialize(dataset);
        }

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        // Warmup
        for (int i = 0; i < WARMUP; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            isAuthorized(req.cardId, req.resourceType, req.actionCode);
        }

        // Measurement
        for (int i = 0; i < iterations; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            long start = recorder.start();
            isAuthorized(req.cardId, req.resourceType, req.actionCode);
            recorder.stop(start);
        }

        return recorder.snapshot();
    }

    public LatencyRecorder.LatencySnapshot benchmarkComplexity(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        return benchmarkEval(dataset, iterations);
    }

    public boolean isAvailable() {
        return initialized;
    }

    public String getSystemLabel() {
        return "Cedar" + (optimized ? "(Optimized)" : "(Default)");
    }

    public void reset() {
        sharedPolicySet = null;
        sharedEntities = null;
        principalUidCache.clear();
        actionUidCache.clear();
        resourceUidCache.clear();
        cardEntitySliceCache.clear();
        groupUidCache.clear();
        initialized = false;
    }
}
