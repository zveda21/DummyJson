package com.qa.security.test;

import com.qa.security.client.ApiClient;
import com.qa.security.constants.ApiEndpoints;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class TestIsolationSecurityTest extends BaseSecurityTest {

    /**
     * Verifies that concurrent access to the same role consistently resolves to the same identity.
     * Helps detect authentication state leaks or concurrency-related isolation issues.
     */
    @Test(description = "ISO-001 - AuthContextFactory resolves a role to the same cached identity under concurrent access")
    public void verifyRoleResolutionIsConsistentUnderConcurrentAccess() throws Exception {

        int threadCount = 10;
        String roleKey = "userA";

        stepInfo("Isolation Validation | case=ISO-001 | role=" + roleKey + " | threads=" + threadCount);

        ExecutorService pool = Executors.newFixedThreadPool(threadCount);

        try {
            List<Callable<String>> tasks = IntStream.range(0, threadCount)
                    .<Callable<String>>mapToObj(i -> () -> {
                        ApiClient client = getClient(roleKey);
                        return client.get(ApiEndpoints.AUTH_ME).jsonPath().getString("id");
                    })
                    .toList();

            List<Future<String>> futures = pool.invokeAll(tasks);

            Set<String> distinctIdentities = futures.stream()
                    .map(this::resolveFuture)
                    .collect(Collectors.toSet());

            stepInfo("Isolation Validation | case=ISO-001 | distinctIdentitiesObserved=" + distinctIdentities.size());

            if (distinctIdentities.size() != 1) {
                throw new AssertionError(
                        "ISO-001 | Concurrent resolution of role '%s' produced inconsistent identities: %s"
                                .formatted(roleKey, distinctIdentities)
                );
            }

        } finally {
            pool.shutdown();
            pool.awaitTermination(30, TimeUnit.SECONDS);
        }
    }

    /**
     * Verifies that authentication contexts for different roles remain isolated and do not share identity state.
     * Also confirms that each role consistently resolves to its own identity across successive requests.
     */
    @Test(description = "ISO-002 - Authenticated contexts for different roles remain isolated from one another")
    public void verifyDifferentRolesDoNotShareAuthenticationState() {

        stepInfo("Isolation Validation | case=ISO-002 | roles=userA,userB");

        ApiClient userAClient = getClient("userA");
        ApiClient userBClient = getClient("userB");

        String userAIdentity = userAClient.get(ApiEndpoints.AUTH_ME).jsonPath().getString("id");
        String userBIdentity = userBClient.get(ApiEndpoints.AUTH_ME).jsonPath().getString("id");

        stepInfo(
                "Isolation Validation | case=ISO-002 | userA.id=" + userAIdentity
                        + " | userB.id=" + userBIdentity
        );

        if (userAIdentity.equals(userBIdentity)) {
            throw new AssertionError(
                    "ISO-002 | Distinct role keys 'userA' and 'userB' resolved to the same identity (%s), "
                            + "indicating a state leak between authentication contexts"
                            .formatted(userAIdentity)
            );
        }

        // Interleave a second round of calls on each client to catch a
        // subtler leak: one role's client accidentally picking up the
        // other's token on a later call (e.g. via shared mutable request
        // spec state) rather than only on the first call.
        String userAIdentityAgain = userAClient.get(ApiEndpoints.AUTH_ME).jsonPath().getString("id");
        String userBIdentityAgain = userBClient.get(ApiEndpoints.AUTH_ME).jsonPath().getString("id");

        if (!userAIdentity.equals(userAIdentityAgain) || !userBIdentity.equals(userBIdentityAgain)) {
            throw new AssertionError(
                    "ISO-002 | A role's resolved identity changed between successive calls on the same "
                            + "client instance - userA: %s -> %s, userB: %s -> %s"
                            .formatted(userAIdentity, userAIdentityAgain, userBIdentity, userBIdentityAgain)
            );
        }
    }

    private String resolveFuture(Future<String> future) {
        try {
            return future.get();
        } catch (Exception e) {
            throw new IllegalStateException("ISO-001 | A concurrent role-resolution task failed", e);
        }
    }
}
