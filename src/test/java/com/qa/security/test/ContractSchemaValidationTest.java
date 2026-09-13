package com.qa.security.test;

import com.qa.security.assertions.ApiAssertions;
import com.qa.security.client.ApiClient;
import com.qa.security.client.TestUserResolver;
import com.qa.security.constants.ApiEndpoints;
import com.qa.security.constants.HttpStatusCodes;
import com.qa.security.models.request.auth.LoginRequest;
import com.qa.security.models.response.auth.LoginResponse;
import com.qa.security.models.response.users.UserSummary;
import com.qa.security.models.response.users.UsersListResponse;
import com.qa.security.services.auth.AuthService;
import com.qa.security.services.users.UserService;
import io.restassured.response.Response;
import org.testng.annotations.Test;

import java.util.List;

public class ContractSchemaValidationTest extends BaseSecurityTest {

    /**
     * Validates that the authenticated user's response matches the expected user contract
     * and contains all required fields.
     */
    @Test(description = "SCHEMA-001 - GET /auth/me response matches the documented authenticated-user contract")
    public void verifyAuthMeSchema() {

        stepInfo("Authentication | actor=userA | authentication=AUTHENTICATED");
        ApiClient client = getClient("userA");

        stepInfo("Request | GET " + ApiEndpoints.AUTH_ME);
        Response response = client.get(ApiEndpoints.AUTH_ME);

        ApiAssertions.assertStatus(
                response,
                HttpStatusCodes.OK,
                "SCHEMA-001 | userA | GET " + ApiEndpoints.AUTH_ME
        );

        ApiAssertions.assertMatchesContract(
                response,
                LoginResponse.class,
                List.of("id", "username", "email"),
                "SCHEMA-001 | userA | GET " + ApiEndpoints.AUTH_ME + " | Response must match the documented contract"
        );
    }

    /**
     * Validates that a single user resource matches the expected contract
     * and contains all required user fields.
     */
    @Test(description = "SCHEMA-002 - GET /users/{id} response matches the documented user resource contract")
    public void verifyUserResourceSchema() {

        stepInfo("Authentication | actor=userA | authentication=AUTHENTICATED");
        ApiClient client = getClient("userA");
        registerUserId("userA");

        int userId = matrixContext.getInt("userA.id");

        stepInfo("Request | GET /users/" + userId);
        UserService userService = new UserService(client);
        Response response = userService.getUserById(userId);

        ApiAssertions.assertStatus(
                response,
                HttpStatusCodes.OK,
                "SCHEMA-002 | userA | GET /users/" + userId
        );

        ApiAssertions.assertMatchesContract(
                response,
                UserSummary.class,
                List.of("id", "username", "email"),
                "SCHEMA-002 | userA | GET /users/" + userId + " | Response must match the documented contract"
        );
    }

    /**
     * Validates that the users directory matches the expected collection and pagination contract,
     * including the required fields of returned users.
     */
    @Test(description = "SCHEMA-003 - GET /users (directory) response matches the documented pagination + collection contract")
    public void verifyUsersListSchema() {

        stepInfo("Request | GET " + ApiEndpoints.USERS + "?limit=0");
        Response response = ApiClient.anonymous().get(ApiEndpoints.USERS + "?limit=0");

        ApiAssertions.assertStatus(
                response,
                HttpStatusCodes.OK,
                "SCHEMA-003 | anonymous | GET " + ApiEndpoints.USERS
        );

        UsersListResponse body = ApiAssertions.assertMatchesContract(
                response,
                UsersListResponse.class,
                List.of("users", "total", "skip", "limit", "users[0].id", "users[0].username", "users[0].email"),
                "SCHEMA-003 | anonymous | GET " + ApiEndpoints.USERS + " | Response must match the documented contract"
        );

        if (body.getUsers().isEmpty()) {
            throw new AssertionError(
                    "SCHEMA-003 | anonymous | GET " + ApiEndpoints.USERS
                            + " | Directory reported total=" + body.getTotal() + " but returned zero users"
            );
        }
    }

    /**
     * Validates that a successful login response matches the expected authentication contract
     * and contains the required user and token fields.
     */
    @Test(description = "SCHEMA-004 - POST /auth/login response matches the documented token-pair contract")
    public void verifyLoginResponseSchema() {

        stepInfo("Authentication | actor=userA | authentication=ANONYMOUS -> AUTHENTICATED");
        TestUserResolver resolver = new TestUserResolver();
        AuthService authService = new AuthService(ApiClient.anonymous());

        Response loginResponse = authService.login(
                new LoginRequest(
                        resolver.getUsername("userA"),
                        resolver.getPassword("userA"),
                        60
                )
        );

        ApiAssertions.assertStatus(
                loginResponse,
                HttpStatusCodes.OK,
                "SCHEMA-004 | userA | POST " + ApiEndpoints.AUTH_LOGIN
        );

        ApiAssertions.assertMatchesContract(
                loginResponse,
                LoginResponse.class,
                List.of("id", "username", "email", "accessToken", "refreshToken"),
                "SCHEMA-004 | userA | POST " + ApiEndpoints.AUTH_LOGIN + " | Response must match the documented contract"
        );
    }
}
