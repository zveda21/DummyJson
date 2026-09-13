package com.qa.security.test;

import com.qa.security.assertions.ApiAssertions;
import com.qa.security.client.ApiClient;
import com.qa.security.config.ConfigManager;
import com.qa.security.constants.ApiEndpoints;
import com.qa.security.constants.HttpStatusCodes;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.Test;

public class ResilienceOperationalSecurityTest extends BaseSecurityTest {

    private static final int DOCUMENTED_DELAY_MS = 3000;

    /**
     * Verifies that the client tolerates DummyJSON's documented response delay
     * without timing out or producing a false failure.
     */
    @Test(description = "RES-001 - Verify the client tolerates DummyJSON's documented response delay without a false failure")
    public void verifyClientToleratesDocumentedLatency() {

        int readTimeoutMs = ConfigManager.getReadTimeoutMs();
        Assert.assertTrue(
                readTimeoutMs > DOCUMENTED_DELAY_MS,
                "Test precondition invalid: configured read timeout ("
                        + readTimeoutMs
                        + "ms) must exceed the documented delay under test ("
                        + DOCUMENTED_DELAY_MS
                        + "ms)"
        );

        stepInfo("Resilience Test | case=RES-001 | requesting documented delay=" + DOCUMENTED_DELAY_MS + "ms");
        ApiClient client = ApiClient.anonymous();
        long startTime = System.currentTimeMillis();
        Response response = client.get(
                ApiEndpoints.USERS_WITH_DELAY.formatted(DOCUMENTED_DELAY_MS)
        );
        long durationMs = System.currentTimeMillis() - startTime;

        stepInfo(
                "Resilience Test | case=RES-001 | "
                        + "observedDurationMs="
                        + durationMs
                        + " | configuredReadTimeoutMs="
                        + readTimeoutMs
        );
        ApiAssertions.assertStatus(
                response,
                HttpStatusCodes.OK,
                "RES-001 | GET "
                        + ApiEndpoints.USERS
                        + "?delay="
                        + DOCUMENTED_DELAY_MS
                        + " | a documented, bounded response delay "
                        + "must not be treated as a failure"
        );
    }

    /**
     * Verifies that repeated invalid requests are consistently rejected with
     * a safe 400 response without causing server-side errors.
     */
    @Test(description = "RES-002 - Verify repeated invalid requests do not cause server errors")
    public void verifyRepeatedInvalidRequestsRemainStable() {

        ApiClient client = getClient("userA");

        stepInfo("Resilience Test | case=RES-002 | actor=userA | action=repeated GET /users/abc");
        int requestCount = 10;
        for (int i = 1; i <= requestCount; i++) {
            Response response = client.get(
                    ApiEndpoints.USER_BY_ID.replace(
                            "{id}",
                            "abc"
                    )
            );
            int actualStatus = response.statusCode();

            stepInfo(
                    "Resilience Test | case=RES-002 | request="
                            + i
                            + "/"
                            + requestCount
                            + " | status="
                            + actualStatus
            );
            ApiAssertions.assertStatus(
                    response,
                    HttpStatusCodes.BAD_REQUEST,
                    "RES-002 | GET "
                            + ApiEndpoints.USER_BY_ID.replace("{id}", "abc")
                            + " | repeated invalid requests must be rejected safely"
            );
        }
    }

    /**
     * Verifies that large pagination parameters are handled safely without
     * causing a server-side error.
     */
    @Test(description = "RES-003 - Verify large pagination parameters are handled safely")
    public void verifyLargePaginationRequestIsHandledSafely() {

        ApiClient client = ApiClient.anonymous();

        stepInfo("Resilience Test | case=RES-003 | actor=anonymous | action=GET /users with large pagination parameters");
        Response response = client.get(
                "/users?limit=100000&skip=0"
        );
        int actualStatus = response.statusCode();

        stepInfo("Resilience Test | case=RES-003 | status=" + actualStatus);
        Assert.assertTrue(
                actualStatus < HttpStatusCodes.INTERNAL_SERVER_ERROR,
                "RES-003 | Large pagination request caused server error: "
                        + actualStatus
        );
    }

    /**
     * Verifies that excessive pagination parameters are handled safely without
     * causing a 5xx server error.
     */
    @Test(description = "RES-004 - Verify excessive pagination parameters are handled safely")
    public void verifyExcessivePaginationRequestIsHandledSafely() {

        ApiClient client = ApiClient.anonymous();

        stepInfo("Resilience Test | case=RES-004 | actor=anonymous | action=GET /users with excessive skip/limit");
        Response response = client.get(
                "/users?limit=100000&skip=100000"
        );
        int actualStatus = response.statusCode();

        stepInfo("Resilience Test | case=RES-004 | status=" + actualStatus);
        Assert.assertTrue(
                actualStatus < HttpStatusCodes.INTERNAL_SERVER_ERROR,
                "RES-004 | Excessive pagination request caused server error: "
                        + actualStatus
        );
    }
}
