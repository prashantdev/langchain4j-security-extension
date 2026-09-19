package dev.langchain4j.security.pdp.embedded;

import java.util.*;

/**
 * Directed Acyclic Graph (DAG) for transitive role expansion with cycle detection.
 */
public class RoleGraph {

    // Parent role -> Children roles inherited
    private final Map<String, Set<String>> adjacency = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    /**
     * Adds a directed inheritance edge where parentRole inherits all permissions of childRole.
     *
     * @param parentRole the parent role name
     * @param childRole the child role name inherited by parent
     */
    public synchronized void addInheritance(String parentRole, String childRole) {
        Objects.requireNonNull(parentRole, "parentRole must not be null");
        Objects.requireNonNull(childRole, "childRole must not be null");
        String parent = parentRole.trim();
        String child = childRole.trim();
        if (parent.equalsIgnoreCase(child)) {
            return;
        }

        // Verify that adding child -> parent does not introduce a cycle
        if (isReachable(child, parent)) {
            throw new IllegalArgumentException(
                String.format("Cyclic role inheritance detected: cannot make '%s' inherit '%s'", parent, child)
            );
        }

        adjacency.computeIfAbsent(parent, k -> new TreeSet<>(String.CASE_INSENSITIVE_ORDER)).add(child);
    }

    /**
     * Transitively expands a set of assigned roles based on registered role inheritance edges.
     *
     * @param assignedRoles set of directly assigned role names
     * @return unmodifiable set containing directly assigned and transitively inherited roles
     */
    public synchronized Set<String> expandRoles(Set<String> assignedRoles) {
        if (assignedRoles == null || assignedRoles.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> expanded = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        Queue<String> queue = new ArrayDeque<>();

        for (String role : assignedRoles) {
            if (role != null && !role.isBlank()) {
                String clean = role.trim();
                expanded.add(clean);
                queue.add(clean);
            }
        }

        while (!queue.isEmpty()) {
            String curr = queue.poll();
            Set<String> children = adjacency.get(curr);
            if (children != null) {
                for (String child : children) {
                    if (expanded.add(child)) {
                        queue.add(child);
                    }
                }
            }
        }
        return Collections.unmodifiableSet(expanded);
    }

    /**
     * Checks if a set of assigned roles includes a required role, either directly or via inheritance.
     *
     * @param assignedRoles set of assigned roles
     * @param requiredRole required role name to test
     * @return true if assignedRoles contains or inherits requiredRole, false otherwise
     */
    public boolean hasRole(Set<String> assignedRoles, String requiredRole) {
        if (assignedRoles == null || requiredRole == null) {
            return false;
        }
        String target = requiredRole.trim();
        for (String r : assignedRoles) {
            if (r != null && r.trim().equalsIgnoreCase(target)) {
                return true;
            }
        }
        return expandRoles(assignedRoles).contains(target);
    }

    private boolean isReachable(String from, String target) {
        Set<String> visited = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        Queue<String> queue = new ArrayDeque<>();
        queue.add(from);
        visited.add(from);

        while (!queue.isEmpty()) {
            String curr = queue.poll();
            if (curr.equalsIgnoreCase(target)) {
                return true;
            }
            Set<String> next = adjacency.get(curr);
            if (next != null) {
                for (String n : next) {
                    if (visited.add(n)) {
                        queue.add(n);
                    }
                }
            }
        }
        return false;
    }
}
