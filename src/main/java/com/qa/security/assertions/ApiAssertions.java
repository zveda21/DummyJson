package com.qa.security.assertions;

import io.restassured.response.Response;

import java.util.*;

public final class ApiAssertions {

    private static final List<String> SENSITIVE_FIELD_PATHS = List.of(
            "password",
            "ssn",
            "ein",
            "bank.cardNumber",
            "bank.iban",
            "crypto.wallet",
            "macAddress"
    );

    private ApiAssertions() {
    }

    public static void assertStatus(
            Response response,
            int expectedStatus,
            String context
    ) {

        int actual = response.statusCode();

        if (actual != expectedStatus) {
            throw new AssertionError(
                    "%s%n  Expected: %d%n  Actual:   %d%n  Response body: [REDACTED]"
                            .formatted(
                                    context,
                                    expectedStatus,
                                    actual
                            )
            );
        }
    }

    public static List<String> findSensitiveFields(Response response) {

        return SENSITIVE_FIELD_PATHS.stream()
                .filter(path -> response.jsonPath().get(path) != null)
                .toList();
    }

    /**
     * Asserts that a response body deserializes cleanly into the given
     * model class AND that every field in {@code requiredFields} is
     * actually present in the raw JSON.
     * <p>
     * Deserialization alone is NOT enough to prove a contract: Jackson
     * silently defaults a missing field to null (or 0 for a primitive),
     * so a response with half its fields missing would still deserialize
     * "successfully". The explicit jsonPath presence check is what
     * actually catches a missing/renamed field.
     * <p>
     * This intentionally reuses the same response model classes the rest
     * of the framework already uses (LoginResponse, UserSummary, ...)
     * rather than introducing a separate schema format, so there is one
     * source of truth for "what a resource looks like".
     *
     * @return the deserialized model, so callers can use it immediately
     * without a second response.as(...) call
     */
    public static <T> T assertMatchesContract(
            Response response,
            Class<T> modelClass,
            List<String> requiredFields,
            String context
    ) {

        T model;

        try {
            model = response.as(modelClass);
        } catch (Exception e) {
            throw new AssertionError(
                    "%s%n  Response body could not be deserialized into %s: %s"
                            .formatted(context, modelClass.getSimpleName(), e.getMessage())
            );
        }

        List<String> missingFields = requiredFields.stream()
                .filter(field -> response.jsonPath().get(field) == null)
                .toList();

        if (!missingFields.isEmpty()) {
            throw new AssertionError(
                    "%s%n  Model: %s%n  Missing required field(s): %s"
                            .formatted(context, modelClass.getSimpleName(), missingFields)
            );
        }

        return model;
    }

    /**
     * Returns the names of any known sensitive fields present in ANY item of
     * a JSON array within the response (e.g. the "users" array returned by
     * GET /users). Bulk exposure across a whole collection is treated as a
     * distinct finding from single-record exposure because it multiplies
     * the blast radius of the same underlying issue.
     *
     * @param response       the API response
     * @param collectionPath jsonPath expression for the array, e.g. "users"
     */
    @SuppressWarnings("unchecked")
    public static List<String> findSensitiveFieldsInCollection(
            Response response,
            String collectionPath
    ) {

        List<Map<String, Object>> items = (List<Map<String, Object>>) (List<?>)
                response.jsonPath().getList(collectionPath, Map.class);

        Set<String> leaked = new LinkedHashSet<>();

        if (items == null) {
            return new ArrayList<>(leaked);
        }

        for (Map<String, Object> item : items) {
            for (String path : SENSITIVE_FIELD_PATHS) {
                if (resolveNested(item, path) != null) {
                    leaked.add(path);
                }
            }
        }

        return new ArrayList<>(leaked);
    }

    /**
     * Resolves a dotted field path (e.g. "bank.cardNumber") against a
     * plain Map, used when items come back as raw Jackson maps rather
     * than through RestAssured's own JsonPath on the full response.
     */
    @SuppressWarnings("unchecked")
    private static Object resolveNested(Map<String, Object> item, String dottedPath) {

        Object current = item;

        for (String segment : dottedPath.split("\\.")) {

            if (!(current instanceof Map)) {
                return null;
            }

            current = ((Map<String, Object>) current).get(segment);
        }

        return current;
    }
}