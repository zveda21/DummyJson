package com.qa.security.models.response.users;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserSummary {

    private int id;
    private String username;
    private String password;
    private String email;
    private String role; // "admin" | "moderator" | "user"

}