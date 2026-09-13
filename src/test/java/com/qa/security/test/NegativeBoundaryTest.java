package com.qa.security.test;

import com.qa.security.assertions.ApiAssertions;
import com.qa.security.client.ApiClient;
import com.qa.security.client.TestUserResolver;
import com.qa.security.constants.ApiEndpoints;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.Test;

public class NegativeBoundaryTest extends BaseSecurityTest {

    private final TestUserResolver userResolver = new TestUserResolver();

    /**
     * Verifies that a syntactically malformed JSON request body is rejected safely. * * Security expectation:
     * - The malformed request must not be accepted as a successful operation.
     * - The server must reject the request with a client-side 4xx response.
     * - The malformed input must not trigger an unhandled 5xx server error.
     */
    @Test(description = "NEG-004 - Verify a syntactically invalid JSON body is rejected safely")
    public void verifyMalformedJsonBodyIsRejected() {
        String roleKey = "userA";
        ApiClient client = getClient(roleKey);
        registerUserId(roleKey);
        int ownId = matrixContext.getInt(roleKey + ".id");
        String malformedJson = "{ \"firstName\": \"Test\", ";

        stepInfo("Negative Boundary | case=NEG-004" + " | actor=" + roleKey
                + " | authentication=AUTHENTICATED" + " | action=PATCH malformed JSON");

        stepInfo("Request | PATCH " + ApiEndpoints.USER_BY_ID.replace("{id}", String.valueOf(ownId)) + " | Content-Type=application/json");
        Response response = client.sendRaw("PATCH", ApiEndpoints.USER_BY_ID
                .replace("{id}", String.valueOf(ownId)), malformedJson, "application/json");
        int actualStatus = response.statusCode();

        stepInfo("Response | case=NEG-004" + " | actor=" + roleKey + " | status=" + actualStatus);
        if (actualStatus >= 500) {
            logger.warn("SECURITY FINDING | case=NEG-004" + " | type=UNHANDLED_SERVER_ERROR"
                            + " | actor={}" + " | method=PATCH" + " | endpoint={}" + " | actualStatus={}",
                    roleKey, ApiEndpoints.USER_BY_ID, actualStatus);
            throw new AssertionError("SECURITY FINDING | case=NEG-004" +
                    " | Malformed JSON caused an unexpected server error" + " | expected=4xx" + " | actual=" + actualStatus);
        }
        ApiAssertions.assertStatus(response,
                actualStatus,
                "NEG-004 | Malformed JSON request must not cause an unhandled server error");
        Assert.assertTrue(actualStatus >= 400 && actualStatus < 500,
                "NEG-004 | Malformed JSON body should be rejected with 4xx, got " + actualStatus);
    }

    /**
     * Verifies that authentication does not succeed when a valid JSON body
     * is submitted using an unexpected Content-Type.
     * Security expectation:
     * - The API must not process the request as a valid JSON authentication request.
     * - Authentication must not succeed with an incorrect Content-Type.
     * - The request should be rejected as a client error.
     */
    @Test(description = "NEG-005 - Verify login rejects an unexpected Content-Type on an otherwise valid body")
    public void verifyWrongContentTypeIsRejected() {

        ApiClient client = ApiClient.anonymous();
        String validJsonAsPlainText = """
                {"username":"%s","password":"%s","expiresInMins":60}"""
                .formatted(
                        userResolver.getUsername("userA"),
                        userResolver.getPassword("userA")
                );
        stepInfo("Negative Boundary | case=NEG-005" + " | actor=userA" + " | authentication=ANONYMOUS"
                + " | action=POST /auth/login" + " | Content-Type=text/plain");
        Response response = client.sendRaw("POST", ApiEndpoints.AUTH_LOGIN, validJsonAsPlainText, "text/plain");
        int actualStatus = response.statusCode();

        stepInfo("Response | case=NEG-005" + " | actor=userA" + " | status=" + actualStatus);
        if (actualStatus >= 200 && actualStatus < 300) {
            logger.warn("SECURITY FINDING | case=NEG-005" + " | type=CONTENT_TYPE_BYPASS"
                            + " | actor=userA" + " | method=POST" + " | endpoint={}" + " | actualStatus={}",
                    ApiEndpoints.AUTH_LOGIN, actualStatus);
            throw new AssertionError("SECURITY FINDING | case=NEG-005"
                    + " | Login succeeded despite an incorrect Content-Type header"
                    + " | expected=4xx" + " | actual=" + actualStatus);
        }
        Assert.assertTrue(actualStatus >= 400 && actualStatus < 500,
                "NEG-005 | Wrong Content-Type should be rejected with 4xx, got " + actualStatus);
    }

    /**
     * Verifies that injection-style credentials cannot bypass authentication.
     *  Security expectation:
     *  - Injection-style username/password values must not authenticate successfully.
     *  - The request must be rejected as invalid credentials/input.
     *   Note:
     *  This test demonstrates that the supplied injection-style payload
     *  does not result in authentication bypass. It does not claim to
     *  prove that every possible injection vector is impossible.
     */
    @Test(description = "NEG-006 - Verify injection-style credentials cannot bypass authentication")
    public void verifyInjectionStyleLoginInputCannotBypassAuthentication() {
        ApiClient client = ApiClient.anonymous();
        String payload = "{\"username\":\"' OR '1'='1\",\"password\":\"' OR '1'='1\",\"expiresInMins\":60}";

        stepInfo("Negative Boundary | case=NEG-006" + " | actor=anonymous" + " | authentication=ANONYMOUS"
                + " | action=POST /auth/login" + " | input=INJECTION_STYLE");
        Response response = client.sendRaw("POST", ApiEndpoints.AUTH_LOGIN, payload, "application/json");
        int actualStatus = response.statusCode();

        stepInfo("Response | case=NEG-006" + " | actor=anonymous" + " | status=" + actualStatus);
        if (actualStatus >= 200 && actualStatus < 300) {
            logger.warn("SECURITY FINDING | case=NEG-006" + " | type=AUTHENTICATION_BYPASS"
                    + " | actor=anonymous" + " | method=POST" + " | endpoint={}"
                    + " | actualStatus={}", ApiEndpoints.AUTH_LOGIN, actualStatus);
            throw new AssertionError("SECURITY FINDING | case=NEG-006"
                    + " | Injection-style credentials resulted in successful authentication"
                    + " | expected=4xx" + " | actual=" + actualStatus);
        }
        Assert.assertTrue(actualStatus >= 400 && actualStatus < 500,
                "NEG-006 | Injection-style credentials should fail with 4xx, got " + actualStatus);
    }
}
