package com.qa.security.utils;

import io.qameta.allure.Allure;
import io.qameta.allure.SeverityLevel;

import java.util.List;

public final class AllureTestReporter {

    private AllureTestReporter() {
    }

    public static void setMatrixTestDetails(
            String caseId,
            String roleKey,
            String method,
            String endpoint,
            int expectedStatus,
            String expectationType,
            String priority,
            String description,
            List<String> owaspCategories,
            String rationale
    ) {

        String testName =
                "%s | %s | %s %s"
                        .formatted(
                                caseId,
                                roleKey,
                                method,
                                endpoint
                        );

        String owaspSection =
                owaspCategories == null || owaspCategories.isEmpty()
                        ? "Not applicable"
                        : owaspCategories.stream()
                        .map(category -> "- " + category)
                        .reduce(
                                (first, second) -> first + "\n" + second
                        )
                        .orElse("Not applicable");

        SeverityLevel severity = mapSeverity(priority);

        Allure.getLifecycle().updateTestCase(testResult -> {

            testResult.setName(testName);
            testResult.getLabels().add(
                    new io.qameta.allure.model.Label()
                            .setName("severity")
                            .setValue(severity.value())
            );

            testResult.setDescription(
                    """
                            %s
                            
                            ---
                            
                            **Case ID:** %s
                            
                            **Actor:** %s
                            
                            **Request:** %s %s
                            
                            **Expected HTTP Status:** %d
                            
                            **Expectation Type:** %s
                            
                            **Priority:** %s
                            
                            **OWASP API Security Top 10:**
                            %s
                            
                            **Security Rationale:** %s
                            """.formatted(
                            description,
                            caseId,
                            roleKey,
                            method,
                            endpoint,
                            expectedStatus,
                            expectationType,
                            priority,
                            owaspSection,
                            rationale
                    )
            );
        });
    }

    private static SeverityLevel mapSeverity(String priority) {

        if (priority == null) {
            return SeverityLevel.NORMAL;
        }

        return switch (priority.toUpperCase()) {
            case "CRITICAL" -> SeverityLevel.BLOCKER;
            case "HIGH" -> SeverityLevel.CRITICAL;
            case "MEDIUM" -> SeverityLevel.NORMAL;
            case "LOW" -> SeverityLevel.MINOR;
            default -> SeverityLevel.NORMAL;
        };
    }
}