package com.qa.security.matrix;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves {{placeholder}} tokens in a security matrix row's path parameters
 * against runtime values captured during test setup.
 * <p>
 * Example:
 * <p>
 * "id": "{{userB.id}}"
 * <p>
 * can be resolved from:
 * <p>
 * context.put("userB.id", 15);
 * <p>
 * resulting in:
 * <p>
 * "id": 15
 */
public class MatrixContext {

    private static final Pattern PLACEHOLDER =
            Pattern.compile("\\{\\{(.+?)}}");

    private final Map<String, Object> values = new HashMap<>();

    public void put(String key, Object value) {
        values.put(key, value);
    }

    public boolean contains(String key) {
        return values.containsKey(key);
    }

    public int getInt(String key) {

        Object value = values.get(key);

        if (value == null) {
            throw new IllegalStateException(
                    "Runtime context value not found: " + key
            );
        }

        if (!(value instanceof Number number)) {
            throw new IllegalStateException(
                    "Runtime context value for '%s' is not numeric: %s"
                            .formatted(key, value)
            );
        }

        return number.intValue();
    }

    public SecurityMatrixRow resolve(SecurityMatrixRow row) {

        Map<String, Object> resolvedParams = new HashMap<>();

        if (row.pathParams() != null) {
            row.pathParams().forEach(
                    (key, value) -> resolvedParams.put(
                            key,
                            resolveValue(value)
                    )
            );
        }

        return new SecurityMatrixRow(
                row.caseId(),
                row.roleKey(),
                row.method(),
                row.endpointTemplate(),
                resolvedParams,
                row.body(),
                row.expectedStatus(),
                row.expectationType(),
                row.priority(),
                row.description(),
                row.owaspCategories(),
                row.rationale()
        );
    }

    private Object resolveValue(Object raw) {

        if (!(raw instanceof String value)) {
            return raw;
        }

        Matcher matcher = PLACEHOLDER.matcher(value);

        if (!matcher.matches()) {
            return raw;
        }

        String key = matcher.group(1);

        if (!values.containsKey(key)) {
            throw new IllegalStateException(
                    "Matrix row references '%s' but it was never captured in MatrixContext."
                            .formatted(key)
            );
        }

        return values.get(key);
    }
}