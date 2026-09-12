package com.qa.security.constants;

public final class ApiEndpoints {

    public static final String AUTH_LOGIN = "/auth/login";
    public static final String AUTH_ME = "/auth/me";
    public static final String AUTH_REFRESH = "/auth/refresh";

    public static final String USERS = "/users";
    public static final String USER_BY_ID = "/users/{id}";

    private ApiEndpoints() {
    }
}