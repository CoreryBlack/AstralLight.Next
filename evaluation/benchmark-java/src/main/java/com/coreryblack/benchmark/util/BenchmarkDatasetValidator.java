package com.coreryblack.benchmark.util;

import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Deterministic checks and fingerprinting for generated benchmark datasets.
 *
 * <p>The fingerprint deliberately excludes database-generated timestamps and
 * IDs that are not part of the request semantics. It is intended to bind a
 * result artifact to the actual policy/request input, not to replace a full
 * archive of that input.</p>
 */
public final class BenchmarkDatasetValidator {

    private BenchmarkDatasetValidator() {
    }

    public static void requireNativeContextConsistency(
            NativeDataGenerator.NativeGeneratedDataSet dataset) {
        Objects.requireNonNull(dataset, "dataset");
        Map<Long, NativeDataGenerator.NativeCardBinding> byCard = dataset.bindings.stream()
            .collect(Collectors.toMap(binding -> binding.cardId, binding -> binding));

        for (NativeDataGenerator.NativeEvalRequest request : dataset.evalRequests) {
            NativeDataGenerator.NativeCardBinding binding = byCard.get(request.cardId);
            if (binding == null) {
                throw new IllegalArgumentException("Request references unknown card: " + request.cardId);
            }
            if (request.userId != binding.userId
                    || request.domainId != binding.domainId
                    || request.tenantId != binding.tenantId
                    || request.templateId != binding.templateId) {
                throw new IllegalArgumentException(
                    "Request context differs from card binding for card " + request.cardId);
            }
        }

        for (NativeDataGenerator.NativeCardBinding binding : dataset.bindings) {
            if (binding.baseRef != null && binding.baseRef.getTenantId() != binding.tenantId) {
                throw new IllegalArgumentException("BASE ref tenant differs for card " + binding.cardId);
            }
            for (var ref : binding.overlayRefs) {
                if (ref.getTenantId() != binding.tenantId) {
                    throw new IllegalArgumentException("OVERLAY ref tenant differs for card " + binding.cardId);
                }
            }
        }
    }

    /** Returns a stable SHA-256 fingerprint of request-relevant generated input. */
    public static String nativeFingerprint(NativeDataGenerator.NativeGeneratedDataSet dataset) {
        requireNativeContextConsistency(dataset);
        List<String> rows = new ArrayList<>();
        dataset.bindings.stream()
            .sorted(Comparator.comparingLong(binding -> binding.cardId))
            .forEach(binding -> rows.add(String.join("|",
                "B", String.valueOf(binding.cardId), String.valueOf(binding.userId),
                String.valueOf(binding.domainId), String.valueOf(binding.tenantId),
                String.valueOf(binding.templateId), String.valueOf(binding.cardType),
                String.valueOf(binding.cardStatus))));
        dataset.entries.stream()
            .sorted(Comparator.comparingLong(entry -> entry.getEntryId()))
            .forEach(entry -> rows.add(String.join("|",
                "E", String.valueOf(entry.getRuleSetId()), String.valueOf(entry.getTenantId()),
                String.valueOf(entry.getResourceType()), String.valueOf(entry.getResourceId()),
                String.valueOf(entry.getActionCode()), String.valueOf(entry.getEffect()),
                String.valueOf(entry.getPriority()))));
        if (dataset.permissionRules != null) {
            dataset.permissionRules.stream()
                .sorted(Comparator.comparingLong(rule -> rule.getRuleId()))
                .forEach(rule -> rows.add(String.join("|",
                    "P", String.valueOf(rule.getRuleId()), String.valueOf(rule.getCardId()),
                    String.valueOf(rule.getTenantId()), String.valueOf(rule.getResourceType()),
                    String.valueOf(rule.getResourceId()), String.valueOf(rule.getActionCode()),
                    String.valueOf(rule.getEffect()), String.valueOf(rule.getPriority()))));
        }
        dataset.evalRequests.stream()
            .forEach(request -> rows.add(String.join("|",
                "Q", String.valueOf(request.cardId), String.valueOf(request.userId),
                String.valueOf(request.domainId), String.valueOf(request.tenantId),
                String.valueOf(request.templateId), String.valueOf(request.resourceType),
                String.valueOf(request.resourceId), String.valueOf(request.actionCode),
                String.valueOf(request.expectedCardOnlyHit),
                String.valueOf(request.expectedCardOnlyRuleId),
                String.valueOf(request.expectedCardOnlyEffect),
                request.abacContext == null ? "" : String.valueOf(request.abacContext.currentTime))));

        return sha256(String.join("\n", rows));
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JRE does not provide SHA-256", e);
        }
    }
}
