package com.qa.security.test;

import com.qa.security.assertions.ApiAssertions;
import com.qa.security.client.ApiClient;
import com.qa.security.client.AuthContextFactory;
import com.qa.security.constants.ApiEndpoints;
import com.qa.security.matrix.MatrixContext;
import com.qa.security.matrix.SecurityMatrixRow;
import com.qa.security.utils.AllureReportCleaner;
import com.qa.security.utils.AllureTestReporter;
import com.qa.security.utils.LoggerManager;
import com.qa.security.utils.SecurityFindingReporter;
import io.qameta.allure.Allure;
import io.restassured.response.Response;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeSuite;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Base class for security tests.
 * <p>
 * TestNG creates one instance of this class per test subclass.
 * <p>
 * Authentication contexts and runtime user IDs are resolved lazily.
 * A test class only authenticates the roles it actually needs.
 */
public abstract class BaseSecurityTest {

    private static final Pattern CONTEXT_PLACEHOLDER =
            Pattern.compile("\\{\\{(.+?)}}");
    protected final Logger logger =
            LoggerManager.getLogger(getClass());
    protected AuthContextFactory authFactory;
    protected MatrixContext matrixContext;

    @BeforeSuite(alwaysRun = true)
    public void cleanAllureResults() {
        AllureReportCleaner.cleanResults();
    }

    @BeforeClass(alwaysRun = true)
    public void setUpAuthContexts() {
        authFactory = new AuthContextFactory();
        matrixContext = new MatrixContext();
    }

    protected ApiClient getClient(String roleKey) {

        if ("anonymous".equals(roleKey)) {
            return authFactory.anonymous();
        }

        return authFactory.forRole(roleKey);
    }

    protected void registerUserId(String roleKey) {

        String contextKey = roleKey + ".id";

        if (matrixContext.contains(contextKey)) {
            return;
        }

        ApiClient client = getClient(roleKey);

        int userId = client
                .get(ApiEndpoints.AUTH_ME)
                .jsonPath()
                .getInt("id");

        matrixContext.put(contextKey, userId);

        stepInfo(
                "Runtime Context | " + contextKey + "=" + userId
        );
    }

    protected void prepareMatrixContext(SecurityMatrixRow row) {

        if (row.pathParams() == null) {
            return;
        }

        for (Object value : row.pathParams().values()) {

            if (!(value instanceof String stringValue)) {
                continue;
            }

            Matcher matcher = CONTEXT_PLACEHOLDER.matcher(stringValue);

            if (!matcher.matches()) {
                continue;
            }

            String contextKey = matcher.group(1);

            if (!contextKey.endsWith(".id")) {
                continue;
            }

            String roleKey =
                    contextKey.substring(
                            0,
                            contextKey.length() - ".id".length()
                    );

            registerUserId(roleKey);
        }
    }

    protected void runRow(SecurityMatrixRow rawRow) {

        /*
         * Resolve only the runtime context values required
         * by this particular matrix row.
         */
        prepareMatrixContext(rawRow);

        SecurityMatrixRow row =
                matrixContext.resolve(rawRow);

        /*
         * Configure the Allure test name and description
         * using the resolved runtime values.
         */
        AllureTestReporter.setMatrixTestDetails(
                row.caseId(),
                row.roleKey(),
                row.method(),
                row.resolvedEndpoint(),
                row.expectedStatus(),
                row.expectationType(),
                row.priority(),
                row.description(),
                row.owaspCategories(),
                row.rationale()
        );

        stepInfo(
                "Security Test | case=" + row.caseId()
                        + " | actor=" + row.roleKey()
                        + " | method=" + row.method()
                        + " | endpoint=" + row.resolvedEndpoint()
        );

        ApiClient client =
                getClient(row.roleKey());

        Response response =
                dispatch(client, row);

        int actualStatus = response.statusCode();

        stepInfo(
                "Security Validation | case=" + row.caseId()
                        + " | expected=" + row.expectedStatus()
                        + " | actual=" + actualStatus
                        + " | classification=" + row.expectationType()
        );

        /*
         * Expected HTTP status was received.
         */
        if (actualStatus == row.expectedStatus()) {

            /*
             * AUTH-004 has an additional identity validation.
             *
             * HTTP 200 alone does not prove that /auth/me returned
             * the identity associated with the authenticated user.
             */
            if ("AUTH-004".equals(row.caseId())) {

                validateAuthenticatedIdentity(
                        row,
                        response
                );
            }

            /*
             * EXP-001 has an additional sensitive-data validation.
             *
             * HTTP 200 alone does not mean the response is secure.
             */
            if ("EXP-001".equals(row.caseId())) {

                validateSensitiveDataExposure(
                        row,
                        response
                );
            }

            SecurityFindingReporter.reportPass(
                    row.caseId(),
                    row.roleKey(),
                    row.method(),
                    row.resolvedEndpoint()
            );

            return;
        }

        /*
         * Security hypotheses and security expectations
         * represent production-security assumptions.
         *
         * If the target API violates the expected behavior,
         * create the Allure security finding first and then
         * fail the TestNG invocation.
         */
        boolean securityExpectation =
                "SECURITY_HYPOTHESIS".equals(row.expectationType())
                        || "SECURITY_EXPECTATION".equals(
                        row.expectationType()
                );

        if (securityExpectation) {

            SecurityFindingReporter.report(
                    row.caseId(),
                    row.roleKey(),
                    row.method(),
                    row.resolvedEndpoint(),
                    row.expectedStatus(),
                    actualStatus,
                    row.expectationType(),
                    row.priority(),
                    row.description(),
                    row.rationale()
            );

            logger.warn(
                    "SECURITY FINDING | case={} | actor={} | method={} | endpoint={} | expected={} | actual={} | priority={}",
                    row.caseId(),
                    row.roleKey(),
                    row.method(),
                    row.resolvedEndpoint(),
                    row.expectedStatus(),
                    actualStatus,
                    row.priority()
            );

            /*
             * Important:
             *
             * Do NOT return here.
             *
             * The security violation must be reported as
             * a FAILED test while preserving the Allure
             * security finding attachment created above.
             */
            throw new AssertionError(
                    "SECURITY FINDING | case=%s | actor=%s | method=%s | endpoint=%s | expected=%d | actual=%d | priority=%s"
                            .formatted(
                                    row.caseId(),
                                    row.roleKey(),
                                    row.method(),
                                    row.resolvedEndpoint(),
                                    row.expectedStatus(),
                                    actualStatus,
                                    row.priority()
                            )
            );
        }

        /*
         * DOCUMENTED_CONTRACT mismatch.
         *
         * This is an actual automation/test failure because
         * the API did not satisfy its documented contract.
         */
        String context =
                "Case %s [%s] %s %s".formatted(
                        row.caseId(),
                        row.roleKey(),
                        row.method(),
                        row.resolvedEndpoint()
                )
                        + " - "
                        + row.rationale();

        ApiAssertions.assertStatus(
                response,
                row.expectedStatus(),
                context
        );
    }

    /**
     * Validates that a successful user-resource response
     * does not expose sensitive information.
     * <p>
     * A detected sensitive field is treated as a security
     * finding and fails the test invocation.
     */
    private void validateSensitiveDataExposure(
            SecurityMatrixRow row,
            Response response
    ) {

        List<String> exposedFields =
                ApiAssertions.findSensitiveFields(response);

        if (exposedFields.isEmpty()) {

            stepInfo(
                    "Security Validation | case="
                            + row.caseId()
                            + " | sensitiveData=NOT_DETECTED"
            );

            return;
        }

        /*
         * Create the detailed Allure security finding first.
         */
        SecurityFindingReporter.reportSensitiveDataExposure(
                row.caseId(),
                row.roleKey(),
                row.method(),
                row.resolvedEndpoint(),
                row.priority(),
                exposedFields,
                row.description(),
                row.rationale()
        );

        logger.warn(
                "SECURITY FINDING | case={} | type=SENSITIVE_DATA_EXPOSURE | actor={} | endpoint={} | fields={}",
                row.caseId(),
                row.roleKey(),
                row.resolvedEndpoint(),
                exposedFields
        );

        /*
         * Fail the test after the Allure finding has been
         * created so the report contains both the evidence
         * and the FAILED test status.
         */
        throw new AssertionError(
                "SECURITY FINDING | case=%s | Sensitive fields exposed: %s"
                        .formatted(
                                row.caseId(),
                                exposedFields
                        )
        );
    }

    private Response dispatch(
            ApiClient client,
            SecurityMatrixRow row
    ) {

        String endpoint = row.resolvedEndpoint();

        return switch (row.method().toUpperCase()) {

            case "GET" -> client.get(endpoint);

            case "POST" -> client.post(endpoint, row.body());

            case "PUT" -> client.put(endpoint, row.body());

            case "PATCH" -> client.patch(endpoint, row.body());

            case "DELETE" -> client.delete(endpoint);

            default -> throw new IllegalArgumentException(
                    "Unsupported method: "
                            + row.method()
            );
        };
    }

    protected void stepInfo(String message) {
        Allure.step(message);
        logger.info(message);
    }

    /**
     * Validates that /auth/me returns the identity associated
     * with the authenticated security context.
     * <p>
     * HTTP 200 only confirms that authentication was accepted.
     * This validation confirms that the authenticated identity
     * is also correct.
     */
    private void validateAuthenticatedIdentity(
            SecurityMatrixRow row,
            Response response
    ) {

        String roleKey = row.roleKey();
        String contextKey = roleKey + ".id";

        /*
         * AUTH-004 has no path parameter such as {{userB.id}},
         * therefore prepareMatrixContext() does not automatically
         * register the runtime identity.
         */
        registerUserId(roleKey);

        int expectedUserId =
                matrixContext.getInt(contextKey);

        int actualUserId =
                response.jsonPath().getInt("id");

        stepInfo(
                "Identity Validation | case=" + row.caseId()
                        + " | role=" + roleKey
                        + " | expectedUserId=" + expectedUserId
                        + " | actualUserId=" + actualUserId
        );

        if (expectedUserId != actualUserId) {

            logger.warn(
                    "SECURITY FINDING | case={} | type=AUTHENTICATED_IDENTITY_MISMATCH | "
                            + "actor={} | expectedUserId={} | actualUserId={}",
                    row.caseId(),
                    roleKey,
                    expectedUserId,
                    actualUserId
            );

            throw new AssertionError(
                    "SECURITY FINDING | case=%s | Authenticated identity mismatch | "
                            + "role=%s | expectedUserId=%d | actualUserId=%d"
                            .formatted(
                                    row.caseId(),
                                    roleKey,
                                    expectedUserId,
                                    actualUserId
                            )
            );
        }

        stepInfo(
                "Identity Validation | case=" + row.caseId()
                        + " | identity=MATCHED"
        );
    }
}