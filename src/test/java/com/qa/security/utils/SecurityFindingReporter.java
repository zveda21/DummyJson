package com.qa.security.utils;

import io.qameta.allure.Allure;

import java.util.List;

public final class SecurityFindingReporter {

    private SecurityFindingReporter() {
    }

    public static void report(
            String caseId,
            String actor,
            String method,
            String endpoint,
            int expectedStatus,
            int actualStatus,
            String expectationType,
            String priority,
            String description,
            String rationale
    ) {

        String finding = """
                
                SECURITY FINDING
                
                Case: %s
                Actor: %s
                Request: %s %s
                
                Description:
                %s
                
                Expected security behavior:
                HTTP %d
                
                Actual behavior:
                HTTP %d
                
                Classification:
                %s
                
                Priority:
                %s
                
                Security Rationale:
                %s
                
                Security Assessment:
                The target API behavior does not satisfy the expected
                security boundary defined by this test case.
                """.formatted(
                caseId,
                actor,
                method,
                endpoint,
                description,
                expectedStatus,
                actualStatus,
                expectationType,
                priority,
                rationale
        );

        Allure.step(
                "SECURITY FINDING | "
                        + caseId
                        + " | "
                        + priority
                        + " | "
                        + method
                        + " "
                        + endpoint
        );

        Allure.addAttachment(
                caseId + " - Security Finding",
                "text/plain",
                finding,
                ".txt"
        );
    }

    public static void reportSensitiveDataExposure(
            String caseId,
            String actor,
            String method,
            String endpoint,
            String priority,
            List<String> exposedFields,
            String description,
            String rationale
    ) {

        String finding = """
                
                SECURITY FINDING
                =================
                
                Finding Type:
                Sensitive Data Exposure
                
                Case: %s
                Actor: %s
                Request: %s %s
                
                Description:
                %s
                
                Expected Security Behavior:
                Sensitive personal, credential, and financial
                information must not be unnecessarily exposed
                through the API response.
                
                Actual Behavior:
                The API response contains the following sensitive fields:
                %s
                
                Priority:
                %s
                
                Security Rationale:
                %s
                
                Security Impact:
                Sensitive information is unnecessarily exposed
                through the API response. This may increase the
                risk of credential compromise, privacy violations,
                or financial information disclosure.
                
                Evidence:
                Sensitive field names are reported for assessment
                purposes. Actual sensitive values are intentionally
                redacted.
                """.formatted(
                caseId,
                actor,
                method,
                endpoint,
                description,
                exposedFields,
                priority,
                rationale
        );

        Allure.step(
                "SECURITY FINDING | "
                        + caseId
                        + " | Sensitive Data Exposure"
        );

        Allure.addAttachment(
                caseId + " - Sensitive Data Exposure",
                "text/plain",
                finding,
                ".txt"
        );
    }

    public static void reportPass(
            String caseId,
            String actor,
            String method,
            String endpoint
    ) {

        Allure.step(
                "SECURITY PASS | "
                        + caseId
                        + " | actor="
                        + actor
                        + " | "
                        + method
                        + " "
                        + endpoint
        );
    }
}