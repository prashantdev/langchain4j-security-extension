package dev.langchain4j.security.pdp.embedded;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoleGraphTest {

    @Test
    @DisplayName("Should correctly handle direct single-hop inheritance")
    void testDirectInheritance() {
        RoleGraph graph = new RoleGraph();
        graph.addInheritance("ADMIN", "OPERATOR");

        Set<String> expanded = graph.expandRoles(Set.of("ADMIN"));
        assertThat(expanded).containsExactlyInAnyOrder("ADMIN", "OPERATOR");
        assertThat(graph.hasRole(Set.of("ADMIN"), "OPERATOR")).isTrue();
        assertThat(graph.hasRole(Set.of("OPERATOR"), "ADMIN")).isFalse();
    }

    @Test
    @DisplayName("Should correctly expand multi-hop transitive inheritance (A -> B -> C -> D)")
    void testTransitiveInheritance() {
        RoleGraph graph = new RoleGraph();
        graph.addInheritance("SUPER_ADMIN", "ADMIN");
        graph.addInheritance("ADMIN", "OPERATOR");
        graph.addInheritance("OPERATOR", "VIEWER");

        Set<String> expanded = graph.expandRoles(Set.of("SUPER_ADMIN"));
        assertThat(expanded).containsExactlyInAnyOrder("SUPER_ADMIN", "ADMIN", "OPERATOR", "VIEWER");

        assertThat(graph.hasRole(Set.of("SUPER_ADMIN"), "VIEWER")).isTrue();
        assertThat(graph.hasRole(Set.of("ADMIN"), "VIEWER")).isTrue();
        assertThat(graph.hasRole(Set.of("OPERATOR"), "SUPER_ADMIN")).isFalse();
    }

    @Test
    @DisplayName("Should detect immediate cycle and throw IllegalArgumentException (A -> B -> A)")
    void testImmediateCycleDetection() {
        RoleGraph graph = new RoleGraph();
        graph.addInheritance("ADMIN", "OPERATOR");

        assertThatThrownBy(() -> graph.addInheritance("OPERATOR", "ADMIN"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Cyclic role inheritance detected");
    }

    @Test
    @DisplayName("Should detect multi-node cycle and throw IllegalArgumentException (A -> B -> C -> A)")
    void testMultiNodeCycleDetection() {
        RoleGraph graph = new RoleGraph();
        graph.addInheritance("A", "B");
        graph.addInheritance("B", "C");

        assertThatThrownBy(() -> graph.addInheritance("C", "A"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Cyclic role inheritance detected");
    }

    @Test
    @DisplayName("Should ignore self-inheritance gracefully (A -> A)")
    void testSelfInheritanceIgnored() {
        RoleGraph graph = new RoleGraph();
        graph.addInheritance("ADMIN", "ADMIN");

        Set<String> expanded = graph.expandRoles(Set.of("ADMIN"));
        assertThat(expanded).containsExactly("ADMIN");
    }

    @Test
    @DisplayName("Should handle empty or null roles safely")
    void testEmptyAndNullRoles() {
        RoleGraph graph = new RoleGraph();
        assertThat(graph.expandRoles(null)).isEmpty();
        assertThat(graph.expandRoles(Set.of())).isEmpty();
        assertThat(graph.hasRole(null, "ADMIN")).isFalse();
        assertThat(graph.hasRole(Set.of("USER"), null)).isFalse();
    }

    @Test
    @DisplayName("Should remain thread-safe under concurrent role additions and expansions")
    void testConcurrentAccess() throws Exception {
        RoleGraph graph = new RoleGraph();
        int threadCount = 8;
        int operationsPerThread = 500;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            final int threadIdx = i;
            futures.add(executor.submit(() -> {
                try {
                    latch.await();
                    for (int j = 0; j < operationsPerThread; j++) {
                        String parent = "ROLE_" + threadIdx + "_" + j;
                        String child = "ROLE_" + threadIdx + "_" + (j + 1);
                        graph.addInheritance(parent, child);
                        Set<String> exp = graph.expandRoles(Set.of(parent));
                        assertThat(exp).contains(parent, child);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }

        latch.countDown();
        for (Future<?> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        executor.shutdown();
    }
}
