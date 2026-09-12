package com.qa.security.test;

import com.qa.security.assertions.ApiAssertions;
import com.qa.security.client.ApiClient;
import com.qa.security.constants.ApiEndpoints;
import com.qa.security.constants.HttpStatusCodes;
import com.qa.security.models.request.auth.LoginRequest;
import com.qa.security.services.auth.AuthService;
import com.qa.security.utils.SecurityFindingReporter;
import io.restassured.response.Response;
import org.testng.annotations.Test;

import java.util.List;

public class SensitiveDataExposureTest extends BaseSecurityTest {

    /**
     * Verifies that the public user directory does not expose sensitive fields
     * across the returned user collection.
     */
    @Test(description = "EXP-002 - Verify the public user directory does not expose sensitive fields in bulk")
    public void verifyUserDirectoryDoesNotExposeSensitiveFieldsInBulk() {

        stepInfo("Request | GET " + ApiEndpoints.USERS + "?limit=0 | authentication=ANONYMOUS");
        Response response = ApiClient.anonymous().get(ApiEndpoints.USERS + "?limit=0");

        ApiAssertions.assertStatus(
                response,
                HttpStatusCodes.OK,
                "EXP-002 | anonymous | GET " + ApiEndpoints.USERS + " | Verify directory is accessible"
        );

        stepInfo("Security validation | Verify no sensitive fields are exposed across the returned collection");
        List<String> exposedFields =
                ApiAssertions.findSensitiveFieldsInCollection(response, "users");

        int total = response.jsonPath().getInt("total");

        if (!exposedFields.isEmpty()) {

            SecurityFindingReporter.reportSensitiveDataExposure(
                    "EXP-002",
                    "anonymous",
                    "GET",
                    ApiEndpoints.USERS,
                    "CRITICAL",
                    exposedFields,
                    "Verify that the public, unauthenticated user directory does not expose "
                            + "sensitive fields across its " + total + " returned records",
                    "Sensitive fields exposed on a single record are a HIGH-priority finding "
                            + "(see EXP-001). The same fields exposed across an entire, "
                            + "unauthenticated directory listing (" + total + " records observed) "
                            + "multiply the blast radius from one account to the full user base and "
                            + "are therefore escalated to CRITICAL."
            );

            logger.warn(
                    "SECURITY FINDING | case=EXP-002 | type=BULK_SENSITIVE_DATA_EXPOSURE | actor=anonymous | endpoint={} | recordCount={} | fields={}",
                    ApiEndpoints.USERS,
                    total,
                    exposedFields
            );

            throw new AssertionError(
                    "EXP-002 | Sensitive fields exposed across %d directory records: %s"
                            .formatted(total, exposedFields)
            );
        }

        SecurityFindingReporter.reportPass("EXP-002", "anonymous", "GET", ApiEndpoints.USERS);
    }

    /**
     * Verifies that the login response does not expose sensitive account data
     * beyond the expected authentication and profile fields.
     */
    @Test(description = "EXP-003 - Verify the login response does not expose sensitive fields beyond the issued tokens")
    public void verifyLoginResponseDoesNotExposeSensitiveFields() {

        stepInfo("Authentication | actor=userA | authentication=ANONYMOUS -> AUTHENTICATED");
        com.qa.security.client.TestUserResolver resolver = new com.qa.security.client.TestUserResolver();
        AuthService authService = new AuthService(ApiClient.anonymous());

        stepInfo("Request | POST " + ApiEndpoints.AUTH_LOGIN);
        Response response = authService.login(
                new LoginRequest(
                        resolver.getUsername("userA"),
                        resolver.getPassword("userA"),
                        60
                )
        );

        ApiAssertions.assertStatus(
                response,
                HttpStatusCodes.OK,
                "EXP-003 | userA | POST " + ApiEndpoints.AUTH_LOGIN + " | Verify login succeeds"
        );

        stepInfo("Security validation | Verify sensitive fields are not exposed in the login response");
        List<String> exposedFields = ApiAssertions.findSensitiveFields(response);

        if (!exposedFields.isEmpty()) {

            SecurityFindingReporter.reportSensitiveDataExposure(
                    "EXP-003",
                    "userA",
                    "POST",
                    ApiEndpoints.AUTH_LOGIN,
                    "HIGH",
                    exposedFields,
                    "Verify that the authentication response returns only the issued session "
                            + "tokens and public profile fields, not credential or financial material",
                    "The login response is returned to every successful caller and is the "
                            + "highest-traffic authenticated response in the API; it must not echo "
                            + "back the submitted password or any other sensitive account field."
            );

            logger.warn(
                    "SECURITY FINDING | case=EXP-003 | type=SENSITIVE_DATA_EXPOSURE | actor=userA | endpoint={} | fields={}",
                    ApiEndpoints.AUTH_LOGIN,
                    exposedFields
            );

            throw new AssertionError(
                    "EXP-003 | Sensitive fields exposed in login response: " + exposedFields
            );
        }

        SecurityFindingReporter.reportPass("EXP-003", "userA", "POST", ApiEndpoints.AUTH_LOGIN);
    }
}
