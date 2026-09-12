package com.qa.security.matrix;

import java.util.List;
import java.util.Map;

/**
 * One row of the data-driven security matrix.
 *
 * The matrix describes:
 * - who is performing the request
 * - what endpoint/method is being accessed
 * - what secure behaviour is expected
 * - why that behaviour is expected
 */
public record SecurityMatrixRow(
        String caseId,
        String roleKey,
        String method,
        String endpointTemplate,
        Map<String, Object> pathParams,
        Object body,
        int expectedStatus,
        String expectationType,
        String priority,
        String description,
        List<String> owaspCategories,
        String rationale
) {

    public String resolvedEndpoint() {
        String endpoint = endpointTemplate;

        if (pathParams != null) {
            for (Map.Entry<String, Object> entry : pathParams.entrySet()) {
                endpoint = endpoint.replace(
                        "{" + entry.getKey() + "}",
                        String.valueOf(entry.getValue())
                );
            }
        }

        return endpoint;
    }

    @Override
    public String toString() {
        return "[%s] %s %s as %s -> expect %d [%s/%s]"
                .formatted(
                        caseId,
                        method,
                        endpointTemplate,
                        roleKey,
                        expectedStatus,
                        expectationType,
                        priority
                );
    }


}