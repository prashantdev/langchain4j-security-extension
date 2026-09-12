package dev.langchain4j.security.context;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityBridgeTest {

    @Test
    @DisplayName("Custom IdentityBridge SPI resolves identity from InvocationParameters")
    void testCustomIdentityBridgeResolution() {
        // Mock SPI implementation resolving identity from a bearer token / custom header in parameters
        IdentityBridge bearerTokenBridge = parameters -> {
            if (parameters == null) {
                return Optional.empty();
            }
            return parameters.get("authorization", String.class)
                .filter(header -> header.startsWith("Bearer "))
                .map(header -> header.substring("Bearer ".length()).trim())
                .filter(token -> !token.isBlank())
                .map(token -> SecurityIdentity.builder()
                    .subjectId("sub-" + token)
                    .tenantId("tenant-enterprise")
                    .roles(Set.of("ROLE_API_USER"))
                    .clearanceFloor(1)
                    .addAttribute("token", token)
                    .build());
        };

        InvocationParameters validParams = InvocationParameters.from(Map.of("authorization", "Bearer tok-secret-456"));
        Optional<SecurityIdentity> resolved = bearerTokenBridge.resolveIdentity(validParams);

        assertThat(resolved).isPresent();
        SecurityIdentity identity = resolved.get();
        assertThat(identity.subjectId()).isEqualTo("sub-tok-secret-456");
        assertThat(identity.tenantId()).isEqualTo("tenant-enterprise");
        assertThat(identity.roles()).containsExactly("ROLE_API_USER");
        assertThat(identity.clearanceFloor()).isEqualTo(1);
        assertThat(identity.getAttribute("token")).contains("tok-secret-456");

        // Invalid or absent authorization header
        InvocationParameters invalidParams = InvocationParameters.from(Map.of("authorization", "Basic dXNlcjpwYXNz"));
        assertThat(bearerTokenBridge.resolveIdentity(invalidParams)).isEmpty();

        InvocationParameters emptyParams = InvocationParameters.empty();
        assertThat(bearerTokenBridge.resolveIdentity(emptyParams)).isEmpty();

        assertThat(bearerTokenBridge.resolveIdentity((InvocationParameters) null)).isEmpty();
    }

    @Test
    @DisplayName("IdentityBridge default method resolveIdentity(Map) delegates to InvocationParameters")
    void testDefaultMapResolutionDelegation() {
        IdentityBridge bridge = SecurityInvocationParameters::extractIdentity;

        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("alice")
            .tenantId("tenant-wonderland")
            .addRole("ROLE_EXPLORER")
            .build();

        Map<String, Object> map = SecurityInvocationParameters.withIdentity(Map.of(), identity);

        // Invoking the default method taking a Map
        Optional<SecurityIdentity> resolved = bridge.resolveIdentity(map);

        assertThat(resolved).isPresent().contains(identity);
        assertThat(bridge.resolveIdentity((Map<String, Object>) null)).isEmpty();
    }

    @Test
    @DisplayName("AC 1.4: InvocationParameters and IdentityBridge resolution are thread-safe under concurrent load")
    void testConcurrentIdentityBridgeResolution() throws InterruptedException {
        IdentityBridge bridge = parameters -> {
            if (parameters == null) {
                return Optional.empty();
            }
            return parameters.get("userId", String.class)
                .map(uid -> SecurityIdentity.builder()
                    .subjectId(uid)
                    .tenantId("tenant-" + uid.hashCode())
                    .build());
        };

        int threadCount = 20;
        int iterationsPerThread = 50;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < iterationsPerThread; j++) {
                        String userId = "user-" + threadId + "-" + j;
                        InvocationParameters params = InvocationParameters.from(Map.of("userId", userId));
                        Optional<SecurityIdentity> idOpt = bridge.resolveIdentity(params);
                        if (idOpt.isPresent() && idOpt.get().subjectId().equals(userId)) {
                            successCount.incrementAndGet();
                        }
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        boolean completed = latch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(completed).isTrue();
        assertThat(successCount.get()).isEqualTo(threadCount * iterationsPerThread);
    }
}
