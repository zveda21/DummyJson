package com.qa.security.services;

import com.qa.security.client.ApiClient;

public abstract class BaseService {

    protected final ApiClient apiClient;

    protected BaseService(ApiClient apiClient) {
        this.apiClient = apiClient;
    }
}
