package com.qa.security.services.auth;

import com.qa.security.client.ApiClient;
import com.qa.security.constants.ApiEndpoints;
import com.qa.security.models.request.auth.LoginRequest;
import com.qa.security.models.response.auth.RefreshRequest;
import com.qa.security.services.BaseService;
import io.restassured.response.Response;

public class AuthService extends BaseService {

    public AuthService(ApiClient apiClient) {
        super(apiClient);
    }

    public Response login(LoginRequest request) {
        return apiClient.post(ApiEndpoints.AUTH_LOGIN, request);
    }

    public Response refresh(RefreshRequest request) {
        return apiClient.post(ApiEndpoints.AUTH_REFRESH, request);
    }

}
