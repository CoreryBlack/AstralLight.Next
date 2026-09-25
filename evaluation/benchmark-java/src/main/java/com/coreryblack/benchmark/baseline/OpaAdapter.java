package com.coreryblack.benchmark.baseline;

import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

/**
 * OPA authorization adapter using template-level data grouping.
 *
 * <p>Instead of the previous MxN per-card binding model (each card copies all
 * template rules), this adapter pushes two separate data structures:</p>
 * <ul>
 *   <li>{@code data.astralbench.templates[t].rules} — per-template rule set (loaded once)</li>
 *   <li>{@code data.astralbench.bindings} — card_id → template_id mapping (one per card)</li>
 * </ul>
 *
 * <p>This reduces data volume from O(cards × rules) to O(cards + templates × rules),
 * eliminating the 530ms/5K-card bottleneck caused by Rego's linear scan over
 * hundreds of thousands of flat bindings.</p>
 *
 * <h3>Rego Evaluation</h3>
 * <p>The Rego policy first resolves the card's template via bindings lookup,
 * then scans only that template's rules — O(1) card lookup + O(N) rule scan
 * where N is rules per template (typically ~45), not total bindings.</p>
 */
@Slf4j
public class OpaAdapter {

    private final String opaUrl;
    private final String policyName;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    /**
     * Retained for constructor compatibility only. This adapter always evaluates
     * via the OPA REST API; there is no WASM compilation path. The label and the
     * artifact manifest always say OPA(REST) regardless of this flag, so a true
     * value can never be mistaken for WASM execution.
     */
    private final boolean useCompiledWasm;
    private final boolean disableCache;
    private int lastBindingCount;
    private int lastTemplateCount;
    private int lastRuleCount;
    private long cacheBusterCounter;

    public OpaAdapter(String opaUrl, boolean useCompiledWasm) {
        this(opaUrl, useCompiledWasm, true);
    }

    public OpaAdapter(String opaUrl, boolean useCompiledWasm, boolean disableCache) {
        this.opaUrl = opaUrl;
        this.policyName = "astralbench";
        this.useCompiledWasm = useCompiledWasm;
        this.disableCache = disableCache;
        this.cacheBusterCounter = 0;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
        this.objectMapper = new ObjectMapper();
    }

    public void initialize(DataGenerator.GeneratedDataSet dataset) {
        try {
            pushPolicy();
            pushData(dataset);
            verifyData(dataset);
            log.info("OPA initialized: url={}, wasm={}, bindings={}, templates={}, rules={}, disableCache={}",
                opaUrl, useCompiledWasm, lastBindingCount, lastTemplateCount,
                lastRuleCount, disableCache);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize OPA", e);
        }
    }

    /**
     * Push Rego policy with template-level rule lookup.
     *
     * <p>Evaluation flow:</p>
     * <ol>
     *   <li>Resolve card → template via bindings (O(1) with Rego partial eval)</li>
     *   <li>Scan template rules for deny match</li>
     *   <li>Scan template rules for allow match (only if no deny)</li>
     * </ol>
     *
     * <p>Deny-override semantics: any matching deny rule overrides all allow rules,
     * matching AstralLight's flat deny-override for the common semantic subset.</p>
     */
    private void pushPolicy() throws Exception {
        String rego = """
            package astralbench

            default allow := false

            # Card → template lookup: O(1) object key lookup instead of linear array scan
            # bindings is an object: {"card_0": "0", "card_1": "1", ...}
            card_template[card_id] := tpl if {
                tpl := data.astralbench.bindings[card_id]
            }

            # Deny check: scan the card's template rules for a matching deny
            deny_exists if {
                tpl := card_template[input.card_id]
                some j
                data.astralbench.templates[tpl].rules[j].resource == input.resource
                data.astralbench.templates[tpl].rules[j].action == input.action
                data.astralbench.templates[tpl].rules[j].effect == "deny"
            }

            # Allow check: matching allow with no deny override
            allow if {
                tpl := card_template[input.card_id]
                some j
                data.astralbench.templates[tpl].rules[j].resource == input.resource
                data.astralbench.templates[tpl].rules[j].action == input.action
                data.astralbench.templates[tpl].rules[j].effect == "allow"
                not deny_exists
            }

            # Diagnostic: count of card→template bindings
            binding_count := count(data.astralbench.bindings)

            # Diagnostic: count of templates
            template_count := count(data.astralbench.templates)
            """;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(opaUrl + "/v1/policies/" + policyName))
            .header("Content-Type", "text/plain")
            .PUT(HttpRequest.BodyPublishers.ofString(rego))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            log.error("OPA policy push FAILED: status={}, body={}", response.statusCode(), response.body());
        } else {
            log.info("OPA policy push: status=200 (template-grouped)");
        }
    }

    /**
     * Push template-grouped data to OPA.
     *
     * <p>Structure pushed:</p>
     * <pre>
     * {
     *   "astralbench": {
     *     "templates": {
     *       "0": { "rules": [{resource, action, effect, priority}, ...] },
     *       "1": { "rules": [{resource, action, effect, priority}, ...] }
     *     },
     *     "bindings": [
     *       {"card_id": "card_0", "template_id": "0"},
     *       {"card_id": "card_1", "template_id": "1"},
     *       ...
     *     ]
     *   }
     * }
     * </pre>
     *
     * <p>Data volume: bindings = cardCount (1 per card), rules = rulesPerTemplate × templateCount.
     * For 50K cards × 3 templates × 45 rules: 50K bindings + 135 rules (vs old 2.25M flat bindings).</p>
     */
    private void pushData(DataGenerator.GeneratedDataSet dataset) throws Exception {
        // Build templates: each template has its own rule set
        ObjectNode templates = objectMapper.createObjectNode();
        int totalRules = 0;

        if (dataset.allBaseEntries != null) {
            for (int t = 0; t < dataset.allBaseEntries.size(); t++) {
                ObjectNode templateNode = objectMapper.createObjectNode();
                ArrayNode rulesArray = objectMapper.createArrayNode();

                // Base rules for this template
                if (dataset.allBaseEntries.get(t) != null) {
                    for (RuleSetEntry entry : dataset.allBaseEntries.get(t)) {
                        ObjectNode rule = objectMapper.createObjectNode();
                        rule.put("resource", entry.getResourceType());
                        rule.put("action", entry.getActionCode());
                        rule.put("effect", entry.getEffect().equalsIgnoreCase("DENY") ? "deny" : "allow");
                        rule.put("priority", entry.getPriority() != null ? entry.getPriority() : 0);
                        rulesArray.add(rule);
                        totalRules++;
                    }
                }

                // Overlay rules for this template (flat injection for common semantic subset)
                if (dataset.allOverlayEntries != null && t < dataset.allOverlayEntries.size()
                    && dataset.allOverlayEntries.get(t) != null) {
                    for (RuleSetEntry entry : dataset.allOverlayEntries.get(t)) {
                        ObjectNode rule = objectMapper.createObjectNode();
                        rule.put("resource", entry.getResourceType());
                        rule.put("action", entry.getActionCode());
                        rule.put("effect", entry.getEffect().equalsIgnoreCase("DENY") ? "deny" : "allow");
                        rule.put("priority", entry.getPriority() != null ? entry.getPriority() : 0);
                        rulesArray.add(rule);
                        totalRules++;
                    }
                }

                templateNode.set("rules", rulesArray);
                templates.set(String.valueOf(t), templateNode);
            }
        }

        lastTemplateCount = templates.size();
        lastRuleCount = totalRules;

        // Build bindings: object map for O(1) lookup {"card_0": "0", "card_1": "1", ...}
        ObjectNode bindings = objectMapper.createObjectNode();
        for (DataGenerator.CardBinding binding : dataset.bindings) {
            bindings.put("card_" + binding.cardId, String.valueOf(binding.templateIdx));
        }

        lastBindingCount = bindings.size();

        // Assemble root data structure
        ObjectNode data = objectMapper.createObjectNode();
        data.set("templates", templates);
        data.set("bindings", bindings);

        ObjectNode root = objectMapper.createObjectNode();
        root.set(policyName, data);

        String jsonBody = objectMapper.writeValueAsString(root);
        long jsonSizeKb = jsonBody.length() / 1024;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(opaUrl + "/v1/data"))
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(jsonBody))
            .timeout(Duration.ofSeconds(30))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        log.info("OPA data push: status={}, bindings={}, templates={}, rules={}, jsonSize={}KB",
            response.statusCode(), lastBindingCount, lastTemplateCount, lastRuleCount, jsonSizeKb);
    }

    /**
     * Verify data was loaded correctly by checking binding and template counts.
     * Also performs an end-to-end health check query after data recomputation.
     */
    private void verifyData(DataGenerator.GeneratedDataSet dataset) throws Exception {
        // Check binding count
        HttpRequest bindingRequest = HttpRequest.newBuilder()
            .uri(URI.create(opaUrl + "/v1/data/" + policyName + "/binding_count"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(10))
            .POST(HttpRequest.BodyPublishers.ofString("{\"input\":{}}"))
            .build();

        HttpResponse<String> bindingResponse = httpClient.send(bindingRequest, HttpResponse.BodyHandlers.ofString());
        JsonNode bindingResult = objectMapper.readTree(bindingResponse.body());
        int actualBindings = bindingResult.path("result").asInt(-1);

        if (actualBindings != dataset.bindings.size()) {
            log.warn("OPA DATA MISMATCH: actual bindings={}, expected={} — results may be invalid!",
                actualBindings, dataset.bindings.size());
        } else {
            log.info("OPA data verified: {} bindings match expected count", actualBindings);
        }

        // Check template count
        HttpRequest templateRequest = HttpRequest.newBuilder()
            .uri(URI.create(opaUrl + "/v1/data/" + policyName + "/template_count"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(10))
            .POST(HttpRequest.BodyPublishers.ofString("{\"input\":{}}"))
            .build();

        HttpResponse<String> templateResponse = httpClient.send(templateRequest, HttpResponse.BodyHandlers.ofString());
        JsonNode templateResult = objectMapper.readTree(templateResponse.body());
        int actualTemplates = templateResult.path("result").asInt(-1);

        if (actualTemplates != lastTemplateCount) {
            log.warn("OPA TEMPLATE MISMATCH: actual={}, expected={}", actualTemplates, lastTemplateCount);
        }

        // End-to-end health check: verify the first card can be evaluated
        if (!dataset.bindings.isEmpty() && !dataset.evalRequests.isEmpty()) {
            DataGenerator.EvalRequest firstReq = dataset.evalRequests.get(0);
            long healthStart = System.nanoTime();
            boolean healthResult = enforce(firstReq.cardId, firstReq.resourceType, firstReq.actionCode);
            long healthMs = (System.nanoTime() - healthStart) / 1_000_000;

            if (healthMs > 3000) {
                log.warn("OPA health check SLOW: {}ms for first query — data recomputation may be ongoing. Waiting 5s...",
                    healthMs);
                Thread.sleep(5000);
            } else {
                log.info("OPA health check OK: {}ms, result={}", healthMs, healthResult);
            }
        }
    }

    public boolean enforce(long cardId, String resource, String action) throws Exception {
        ObjectNode input = objectMapper.createObjectNode();
        input.put("card_id", "card_" + cardId);
        input.put("resource", resource);
        input.put("action", action);
        if (disableCache) {
            input.put("_cache_buster", cacheBusterCounter++);
        }

        ObjectNode body = objectMapper.createObjectNode();
        body.set("input", input);

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(opaUrl + "/v1/data/" + policyName + "/allow"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(10));

        if (disableCache) {
            requestBuilder.header("Cache-Control", "no-cache, no-store, max-age=0")
                .header("Pragma", "no-cache");
        }

        HttpRequest request = requestBuilder
            .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
            .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        JsonNode result = objectMapper.readTree(response.body());
        return result.path("result").asBoolean(false);
    }

    private static final int WARMUP = 1000;

    public LatencyRecorder.LatencySnapshot benchmarkEval(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            try {
                enforce(req.cardId, req.resourceType, req.actionCode);
            } catch (Exception ignored) {}
        }

        for (int i = 0; i < iterations; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            long start = recorder.start();
            try {
                enforce(req.cardId, req.resourceType, req.actionCode);
                recorder.stop(start);
            } catch (Exception e) {
                recorder.recordError(System.nanoTime() - start);
            }
        }

        return recorder.snapshot();
    }

    public LatencyRecorder.LatencySnapshot benchmarkComplexity(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            try {
                enforce(req.cardId, req.resourceType, req.actionCode);
            } catch (Exception ignored) {}
        }

        for (int i = 0; i < iterations; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            long start = recorder.start();
            try {
                enforce(req.cardId, req.resourceType, req.actionCode);
                recorder.stop(start);
            } catch (Exception e) {
                recorder.recordError(System.nanoTime() - start);
            }
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        log.info("  OPA complexity: rules/card={}, bindings={}, templates={}, rules={}, mean={}us, p99={}us",
            dataset.config.getBaseRulesPerCard(), lastBindingCount, lastTemplateCount, lastRuleCount,
            String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p99Us()));
        return snapshot;
    }

    public boolean isAvailable() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(opaUrl + "/v1/data"))
                .timeout(Duration.ofSeconds(3))
                .GET()
                .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception e) {
            log.debug("OPA availability check failed: {}", e.getMessage());
            return false;
        }
    }

    public String getSystemLabel() {
        // Always truthful: this adapter evaluates via REST only. The
        // useCompiledWasm constructor flag never changes the execution path.
        return "OPA(REST)";
    }
}
