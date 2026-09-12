package com.qa.security.client;


import io.restassured.RestAssured;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.apache.logging.log4j.Logger;
import com.qa.security.utils.LoggerManager;

import static com.qa.security.config.ConfigManager.getBaseUrl;

public class ApiClient {

    private static final Logger LOGGER =
            LoggerManager.getLogger(ApiClient.class);

    private final String authToken;

    /**
     * Creates an API client.
     *
     * @param authToken Bearer token. Null means unauthenticated client.
     */
    public ApiClient(String authToken) {
        this.authToken = authToken;

        LOGGER.debug(
                "ApiClient initialized | authentication={}",
                authToken != null ? "AUTHENTICATED" : "ANONYMOUS"
        );
    }

    /**
     * Creates an unauthenticated API client.
     */
    public static ApiClient anonymous() {
        return new ApiClient(null);
    }

    /**
     * Builds the common RestAssured request specification.
     */
    private RequestSpecification getRequestSpecification() {

        RequestSpecBuilder builder = new RequestSpecBuilder()
                .setBaseUri(getBaseUrl())
                .setContentType(ContentType.JSON);

        if (authToken != null) {
            builder.addHeader(
                    "Authorization",
                    "Bearer " + authToken
            );
        }

        return builder.build();
    }

    /**
     * GET request.
     */
    public Response get(String endpoint) {

        return execute(
                "GET",
                endpoint,
                null,
                () -> RestAssured
                        .given()
                        .spec(getRequestSpecification())
                        .when()
                        .get(endpoint)
        );
    }

    /**
     * GET request with path parameters.
     */
    public Response get(String endpoint, Object... pathParams) {

        String resolvedEndpoint = resolveEndpoint(endpoint, pathParams);

        return execute(
                "GET",
                resolvedEndpoint,
                null,
                () -> RestAssured
                        .given()
                        .spec(getRequestSpecification())
                        .when()
                        .get(endpoint, pathParams)
        );
    }

    private String resolveEndpoint(
            String endpoint,
            Object... pathParams
    ) {
        String resolved = endpoint;

        for (Object pathParam : pathParams) {
            resolved = resolved.replaceFirst(
                    "\\{[^}]+\\}",
                    String.valueOf(pathParam)
            );
        }

        return resolved;
    }

    /**
     * POST request.
     */
    public Response post(String endpoint, Object body) {

        return execute(
                "POST",
                endpoint,
                body,
                () -> RestAssured
                        .given()
                        .spec(getRequestSpecification())
                        .body(body)
                        .when()
                        .post(endpoint)
        );
    }

    /**
     * PUT request.
     */
    public Response put(String endpoint, Object body) {

        return execute(
                "PUT",
                endpoint,
                body,
                () -> RestAssured
                        .given()
                        .spec(getRequestSpecification())
                        .body(body)
                        .when()
                        .put(endpoint)
        );
    }

    /**
     * PATCH request.
     */
    public Response patch(String endpoint, Object body) {

        return execute(
                "PATCH",
                endpoint,
                body,
                () -> RestAssured
                        .given()
                        .spec(getRequestSpecification())
                        .body(body)
                        .when()
                        .patch(endpoint)
        );
    }

    /**
     * DELETE request.
     */
    public Response delete(String endpoint) {

        return execute(
                "DELETE",
                endpoint,
                null,
                () -> RestAssured
                        .given()
                        .spec(getRequestSpecification())
                        .when()
                        .delete(endpoint)
        );
    }

    /**
     * Executes the request and logs useful execution information.
     * <p>
     * Sensitive information such as tokens is never logged.
     */
    private Response execute(
            String method,
            String endpoint,
            Object requestBody,
            RequestExecutor requestExecutor
    ) {

        String authentication = authToken != null
                ? "AUTHENTICATED"
                : "ANONYMOUS";

        LOGGER.info(
                "API REQUEST | method={} | endpoint={} | authentication={}",
                method,
                endpoint,
                authentication
        );

        if (requestBody != null) {
            LOGGER.debug(
                    "API REQUEST BODY | method={} | endpoint={} | body={}",
                    method,
                    endpoint,
                    sanitize(requestBody)
            );
        }

        long startTime = System.currentTimeMillis();

        try {

            Response response = requestExecutor.execute();

            long duration = System.currentTimeMillis() - startTime;

            LOGGER.info(
                    "API RESPONSE | method={} | endpoint={} | status={} | duration={}ms",
                    method,
                    endpoint,
                    response.getStatusCode(),
                    duration
            );

            LOGGER.debug(
                    "API RESPONSE | method={} | endpoint={} | contentType={}",
                    method,
                    endpoint,
                    response.getContentType()
            );

            return response;

        } catch (Exception e) {

            long duration = System.currentTimeMillis() - startTime;

            LOGGER.error(
                    "API REQUEST FAILED | method={} | endpoint={} | duration={}ms | error={}",
                    method,
                    endpoint,
                    duration,
                    e.getMessage(),
                    e
            );

            throw e;
        }
    }

    /**
     * Prevents sensitive request information from being written to logs.
     * <p>
     * We intentionally do not log authentication tokens.
     * Request body logging can be improved later with a dedicated
     * sensitive-data masking utility.
     */
    private String sanitize(Object requestBody) {

        if (requestBody == null) {
            return null;
        }

        String body = requestBody.toString();

        return body
                .replaceAll(
                        "(?i)(\"?password\"?\\s*[:=]\\s*)[^,}\\s]+",
                        "$1***"
                )
                .replaceAll(
                        "(?i)(\"?token\"?\\s*[:=]\\s*)[^,}\\s]+",
                        "$1***"
                )
                .replaceAll(
                        "(?i)(\"?accessToken\"?\\s*[:=]\\s*)[^,}\\s]+",
                        "$1***"
                )
                .replaceAll(
                        "(?i)(\"?authorization\"?\\s*[:=]\\s*)[^,}\\s]+",
                        "$1***"
                );
    }

    @FunctionalInterface
    private interface RequestExecutor {
        Response execute();
    }
}