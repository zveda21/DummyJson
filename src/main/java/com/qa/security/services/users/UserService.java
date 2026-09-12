package com.qa.security.services.users;

import com.qa.security.client.ApiClient;
import com.qa.security.constants.ApiEndpoints;
import com.qa.security.models.response.users.UsersListResponse;
import com.qa.security.services.BaseService;
import io.restassured.response.Response;

public class UserService extends BaseService {

    public UserService(ApiClient apiClient) {
        super(apiClient);
    }

    public Response getUserById(int id) {
        return apiClient.get(ApiEndpoints.USER_BY_ID, id);
    }

    public Response updateUser(int id, Object body) {
        return apiClient.patch(ApiEndpoints.USER_BY_ID.replace("{id}", String.valueOf(id)), body);
    }

    public Response deleteUser(int id) {
        return apiClient.delete(ApiEndpoints.USER_BY_ID.replace("{id}", String.valueOf(id)));
    }

    /** Fetches the full user directory (limit=0 = no pagination cap) for role discovery. */
    public UsersListResponse getAllUsers() {
        Response response = apiClient.get(ApiEndpoints.USERS + "?limit=0");
        return response.as(UsersListResponse.class);
    }
}