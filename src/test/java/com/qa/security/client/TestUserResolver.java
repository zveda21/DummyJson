package com.qa.security.client;

import com.qa.security.models.response.users.UserSummary;
import com.qa.security.models.response.users.UsersListResponse;
import com.qa.security.services.users.UserService;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TEST: resolves role keys ("userA", "userB", "admin") to real DummyJSON credentials
 * by reading the public /users directory and grouping by the "role" field it exposes.
 * Test-only because the role-key semantics (userA/userB/admin) are specific to this
 * test strategy, not a general framework capability.
 */
public class TestUserResolver {

    private final UserService userDirectory = new UserService(ApiClient.anonymous());
    private final Map<String, UserSummary> resolved = new ConcurrentHashMap<>();
    private volatile List<UserSummary> directoryCache;

    public String getUsername(String roleKey) {
        return resolveUser(roleKey).getUsername();
    }

    public String getPassword(String roleKey) {
        return resolveUser(roleKey).getPassword();
    }

    private UserSummary resolveUser(String roleKey) {
        return resolved.computeIfAbsent(roleKey, this::pickUserFor);
    }

    private UserSummary pickUserFor(String roleKey) {
        List<UserSummary> directory = directory();
        return switch (roleKey) {
            case "admin" -> nthWithRole(directory, "admin", 0);
            case "moderator" -> nthWithRole(directory, "moderator", 0);
            case "userA" -> nthWithRole(directory, "user", 0);
            case "userB" -> nthWithRole(directory, "user", 1);
            default -> throw new IllegalArgumentException("Unknown role key: " + roleKey);
        };
    }

    private List<UserSummary> directory() {
        List<UserSummary> local = directoryCache;
        if (local == null) {
            synchronized (this) {
                local = directoryCache;
                if (local == null) {
                    local = userDirectory.getAllUsers().getUsers();
                    directoryCache = local;
                }
            }
        }
        return local;
    }

    private UserSummary nthWithRole(List<UserSummary> directory, String role, int index) {
        List<UserSummary> matches = directory.stream()
                .filter(u -> role.equalsIgnoreCase(u.getRole()))
                .toList();

        if (matches.size() <= index) {
            throw new IllegalStateException(
                    "Expected at least %d user(s) with role '%s', found %d"
                            .formatted(index + 1, role, matches.size()));
        }
        return matches.get(index);
    }
}
