package com.qa.security.client;

import com.qa.security.constants.HttpStatusCodes;
import com.qa.security.models.request.auth.LoginRequest;
import com.qa.security.models.response.auth.LoginResponse;
import com.qa.security.services.auth.AuthService;
import com.qa.security.utils.LoggerManager;
import io.restassured.response.Response;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Builds an authenticated ApiClient per role.
 * <p>
 * Normal authenticated clients are cached for the lifetime of this
 * factory instance. Short-lived clients created with an explicit
 * expiration are not cached because they are intended for specific
 * authentication tests.
 */
public class AuthContextFactory {

    private static final int DEFAULT_EXPIRES_IN_MINS = 60;

    private static final Logger LOGGER =
            LoggerManager.getLogger(AuthContextFactory.class);

    private final Map<String, ApiClient> cache =
            new ConcurrentHashMap<>();

    private final TestUserResolver userResolver =
            new TestUserResolver();

    public ApiClient anonymous() {

        return ApiClient.anonymous();
    }

    public ApiClient forRole(String roleKey) {

        if ("anonymous".equals(roleKey)) {
            LOGGER.debug("AUTH CONTEXT | role={} | authentication=ANONYMOUS", roleKey);
            return anonymous();
        }

        if (cache.containsKey(roleKey)) {

            LOGGER.debug(
                    "AUTH CACHE HIT | role={} | authentication=AUTHENTICATED",
                    roleKey
            );
        }

        return cache.computeIfAbsent(
                roleKey,
                this::login
        );
    }

    /**
     * Creates a non-cached authenticated client with
     * a custom token expiration time.
     * <p>
     * Used by authentication tests such as expired-token validation.
     */
    public ApiClient forRoleWithExpiry(
            String roleKey,
            int expiresInMins
    ) {

        if ("anonymous".equals(roleKey)) {
            LOGGER.debug("AUTH CONTEXT | role={} | authentication=ANONYMOUS", roleKey);
            return anonymous();
        }

        return login(
                roleKey,
                expiresInMins
        );
    }

    /**
     * Normal authentication flow using the default
     * token lifetime.
     */
    private ApiClient login(String roleKey) {

        return login(
                roleKey,
                DEFAULT_EXPIRES_IN_MINS
        );
    }

    /**
     * Authentication flow with an explicit token lifetime.
     */
    private ApiClient login(
            String roleKey,
            int expiresInMins
    ) {

        LOGGER.info(
                "AUTH LOGIN REQUIRED | role={} | expiresInMins={} | authentication=AUTHENTICATED",
                roleKey,
                expiresInMins
        );

        String username =
                userResolver.getUsername(roleKey);

        String password =
                userResolver.getPassword(roleKey);

        AuthService authService =
                new AuthService(
                        ApiClient.anonymous()
                );

        Response response =
                authService.login(
                        new LoginRequest(
                                username,
                                password,
                                expiresInMins
                        )
                );

        if (response.statusCode() != HttpStatusCodes.OK) {

            throw new IllegalStateException(
                    "Failed to authenticate role '%s' - login returned %d"
                            .formatted(
                                    roleKey,
                                    response.statusCode()
                            )
            );
        }

        LoginResponse loginResponse =
                response.as(LoginResponse.class);

        LOGGER.info(
                "AUTH LOGIN SUCCESS | role={} | expiresInMins={} | authentication=AUTHENTICATED",
                roleKey,
                expiresInMins
        );

        return new ApiClient(
                loginResponse.getAccessToken()
        );
    }
}