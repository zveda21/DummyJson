package com.qa.security.test;

import com.qa.security.assertions.ApiAssertions;
import com.qa.security.client.ApiClient;
import com.qa.security.constants.ApiEndpoints;
import com.qa.security.constants.HttpStatusCodes;
import com.qa.security.models.response.auth.LoginResponse;
import com.qa.security.models.response.auth.RefreshRequest;
import com.qa.security.services.auth.AuthService;
import com.qa.security.utils.SecurityFindingReporter;
import io.restassured.response.Response;
import org.testng.annotations.Test;

import java.util.List;

public class TokenSessionSecurityTest extends BaseSecurityTest {

    /**
     * Verifies that a valid refresh token issues a usable access token
     * that continues to resolve to the same authenticated identity.
     */
    @Test(description = "REFRESH-001 - A valid refresh token issues a usable new access token for the same identity")
    public void verifyRefreshTokenIssuesUsableAccessToken() {

        String roleKey = "userA";

        stepInfo("Authentication | actor=" + roleKey + " | authentication=AUTHENTICATED");
        LoginResponse original = loginAndCapture(roleKey);

        stepInfo("Request | POST " + ApiEndpoints.AUTH_REFRESH);
        AuthService authService = new AuthService(ApiClient.anonymous());
        Response refreshResponse = authService.refresh(
                new RefreshRequest(original.getRefreshToken(), 60)
        );

        stepInfo("Response | status=" + refreshResponse.statusCode());
        ApiAssertions.assertStatus(
                refreshResponse,
                HttpStatusCodes.OK,
                "REFRESH-001 | " + roleKey + " | POST " + ApiEndpoints.AUTH_REFRESH
                        + " | A valid refresh token must be accepted"
        );

        LoginResponse refreshed = ApiAssertions.assertMatchesContract(
                refreshResponse,
                LoginResponse.class,
                List.of("accessToken", "refreshToken"),
                "REFRESH-001 | " + roleKey + " | Refresh response must match the documented token-pair contract"
        );

        stepInfo("Request | GET " + ApiEndpoints.AUTH_ME + " using refreshed access token");
        ApiClient refreshedClient = new ApiClient(refreshed.getAccessToken());
        Response meResponse = refreshedClient.get(ApiEndpoints.AUTH_ME);

        ApiAssertions.assertStatus(
                meResponse,
                HttpStatusCodes.OK,
                "REFRESH-001 | " + roleKey + " | A refreshed access token must be usable against a protected endpoint"
        );

        int expectedUserId = original.getId();
        int actualUserId = meResponse.jsonPath().getInt("id");

        if (expectedUserId != actualUserId) {
            throw new AssertionError(
                    "REFRESH-001 | Refreshed access token resolved to a different identity | "
                            + "expectedUserId=%d | actualUserId=%d"
                            .formatted(expectedUserId, actualUserId)
            );
        }

        SecurityFindingReporter.reportPass("REFRESH-001", roleKey, "POST", ApiEndpoints.AUTH_REFRESH);
    }

    /**
     * Verifies that an invalid refresh token is rejected and cannot establish
     * a new authenticated session.
     */
    @Test(description = "REFRESH-002 - An invalid or garbage refresh token must be rejected")
    public void verifyInvalidRefreshTokenIsRejected() {

        stepInfo("Authentication | actor=anonymous | refreshToken=invalid");
        AuthService authService = new AuthService(ApiClient.anonymous());

        stepInfo("Request | POST " + ApiEndpoints.AUTH_REFRESH);
        Response response = authService.refresh(
                new RefreshRequest("not-a-real-refresh-token", 60)
        );

        stepInfo("Response | status=" + response.statusCode());
        int actualStatus = response.statusCode();

        if (actualStatus != HttpStatusCodes.UNAUTHORIZED
                && actualStatus != HttpStatusCodes.FORBIDDEN) {

            SecurityFindingReporter.report(
                    "REFRESH-002",
                    "anonymous",
                    "POST",
                    ApiEndpoints.AUTH_REFRESH,
                    HttpStatusCodes.UNAUTHORIZED,
                    actualStatus,
                    "SECURITY_HYPOTHESIS",
                    "HIGH",
                    "Verify that /auth/refresh rejects a syntactically invalid refresh token",
                    "A refresh token that was never issued by the authentication service must not "
                            + "be accepted and must not result in a new session being established."
            );

            logger.warn(
                    "SECURITY FINDING | case=REFRESH-002 | actor=anonymous | method=POST | endpoint={} | actual={}",
                    ApiEndpoints.AUTH_REFRESH,
                    actualStatus
            );

            throw new AssertionError(
                    "REFRESH-002 | Invalid refresh token was not rejected | actualStatus=" + actualStatus
            );
        }

        SecurityFindingReporter.reportPass("REFRESH-002", "anonymous", "POST", ApiEndpoints.AUTH_REFRESH);
    }

    /**
     * Verifies that a pre-refresh access token is no longer usable after
     * the session has been successfully refreshed.
     */
    @Test(description = "REFRESH-003 - A pre-refresh access token must not remain usable after token refresh")
    public void verifyOriginalAccessTokenAfterRefresh() {
        String roleKey = "userB";

        stepInfo("Authentication | actor=" + roleKey + " | authentication=AUTHENTICATED");
        LoginResponse original = loginAndCapture(roleKey);
        AuthService authService = new AuthService(ApiClient.anonymous());

        stepInfo("Request | POST " + ApiEndpoints.AUTH_REFRESH);
        Response refreshResponse = authService.refresh(new RefreshRequest(original.getRefreshToken(), 60));
        ApiAssertions.assertStatus(refreshResponse, HttpStatusCodes.OK, "REFRESH-003 | "
                + roleKey + " | Refresh must succeed as a precondition for this case");

        stepInfo("Request | GET " + ApiEndpoints.AUTH_ME + " using PRE-refresh access token");
        ApiClient originalClient = new ApiClient(original.getAccessToken());
        Response meResponse = originalClient.get(ApiEndpoints.AUTH_ME);
        int actualStatus = meResponse.statusCode();

        stepInfo("Security Validation | case=REFRESH-003 | preRefreshTokenStatus=" + actualStatus);
        if (actualStatus == HttpStatusCodes.OK) {
            SecurityFindingReporter.report("REFRESH-003", roleKey, "GET", ApiEndpoints.AUTH_ME,
                    HttpStatusCodes.UNAUTHORIZED, actualStatus,
                    "SECURITY_HYPOTHESIS", "MEDIUM",
                    "Verify whether the access token issued before a refresh remains usable after that refresh " +
                            "completes", "The pre-refresh access token remained usable after refresh. "
                            + "If the application requires refresh-based token invalidation, "
                            + "the previous access token should no longer authorize protected requests.");
            logger.warn("SECURITY FINDING | case=REFRESH-003 | actor={} | " +
                    "pre-refresh access token remained valid after refresh", roleKey);
            throw new AssertionError(
                    "SECURITY FINDING | case=REFRESH-003 | actor=" + roleKey +
                            " | Pre-refresh access token remained valid after refresh" +
                            " | expectedStatus=" + HttpStatusCodes.UNAUTHORIZED + " | actualStatus=" + actualStatus);
        }
        if (actualStatus == HttpStatusCodes.UNAUTHORIZED) {
            stepInfo("Security Validation | case=REFRESH-003 | " + "pre-refresh access token correctly rejected");
            SecurityFindingReporter.reportPass("REFRESH-003", roleKey, "GET", ApiEndpoints.AUTH_ME);
            return;
        }
        throw new AssertionError("REFRESH-003 | Unexpected response when validating pre-refresh access token"
                + " | expected=" + HttpStatusCodes.UNAUTHORIZED + " | actual=" + actualStatus);
    }

    private LoginResponse loginAndCapture(String roleKey) {

        AuthService authService = new AuthService(ApiClient.anonymous());
        com.qa.security.client.TestUserResolver resolver = new com.qa.security.client.TestUserResolver();

        Response loginResponse = authService.login(
                new com.qa.security.models.request.auth.LoginRequest(
                        resolver.getUsername(roleKey),
                        resolver.getPassword(roleKey),
                        60
                )
        );

        ApiAssertions.assertStatus(
                loginResponse,
                HttpStatusCodes.OK,
                "Precondition login for role '" + roleKey + "' must succeed"
        );

        return loginResponse.as(LoginResponse.class);
    }
}
