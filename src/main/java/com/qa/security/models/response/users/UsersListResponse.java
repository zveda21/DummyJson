package com.qa.security.models.response.users;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class UsersListResponse {

    private List<UserSummary> users;
    private int total;
    private int skip;
    private int limit;
}