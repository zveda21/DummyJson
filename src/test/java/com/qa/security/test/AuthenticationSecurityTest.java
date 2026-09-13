package com.qa.security.test;

import com.qa.security.assertions.ApiAssertions;
import com.qa.security.client.ApiClient;
import com.qa.security.constants.ApiEndpoints;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.qa.security.constants.HttpStatusCodes.UNAUTHORIZED;

public class AuthenticationSecurityTest extends BaseSecurityTest {

    @Test(description = "AUTH-001 - Verify that protected user identity information is inaccessible without valid authentication")
    public void verifyUnauthenticatedAccessIsRejected() {

        stepInfo("Authentication | actor=anonymous | authentication=ANONYMOUS");
        ApiClient client = authFactory.anonymous();

        stepInfo("Request | GET " + ApiEndpoints.AUTH_ME);
        Response response = client.get(ApiEndpoints.AUTH_ME);

        stepInfo("Response | status=" + response.statusCode());
        ApiAssertions.assertStatus(
                response,
                UNAUTHORIZED,
                "AUTH-001 | anonymous | GET " + ApiEndpoints.AUTH_ME
                        + " | Protected endpoint requires authentication"
        );
    }

    @Test(
            description = "AUTH-003 - Verify that protected user identity information is inaccessible with an invalid authentication token"
    )
    public void verifyInvalidTokenIsRejected() {

        stepInfo("Authentication | actor=invalid-token | authentication=INVALID");
        ApiClient client = new ApiClient("invalid-token");

        stepInfo("Request | GET " + ApiEndpoints.AUTH_ME);
        Response response = client.get(ApiEndpoints.AUTH_ME);

        stepInfo("Response | status=" + response.statusCode());
        ApiAssertions.assertStatus(
                response,
                UNAUTHORIZED,
                "AUTH-003 | invalid-token | GET " + ApiEndpoints.AUTH_ME
                        + " | Protected user identity information must reject invalid authentication tokens"
        );
    }

    @Test(description = "AUTH-005 - Verify that protected user identity information is inaccessible with an expired authentication token")
    public void verifyExpiredTokenCannotAccessProtectedEndpoint() {

        String roleKey = "userA";
        int expiresInMins = 1;

        stepInfo("Authentication | actor=" + roleKey + " | authentication=EXPIRED");
        ApiClient client =
                authFactory.forRoleWithExpiry(
                        roleKey,
                        expiresInMins
                );

        stepInfo("Authentication | actor=" + roleKey
                + " | tokenLifetime=" + expiresInMins + "min");
        waitForTokenExpiration();

        stepInfo("Authentication | actor=" + roleKey
                + " | tokenState=EXPIRED | request=GET /auth/me");
        Response response = client.get(ApiEndpoints.AUTH_ME);

        stepInfo("Authentication | actor=" + roleKey
                + " | responseStatus=" + response.statusCode());
        Assert.assertEquals(
                response.statusCode(),
                UNAUTHORIZED,
                "An expired access token must not access /auth/me"
        );
    }

    private void waitForTokenExpiration() {

        stepInfo("Authentication | waiting for token expiration");
        try {
            Thread.sleep(65_000);
        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            throw new RuntimeException(
                    "Interrupted while waiting for token expiration",
                    e
            );
        }
    }
}
