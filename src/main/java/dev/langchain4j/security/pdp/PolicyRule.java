package dev.langchain4j.security.pdp;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Declarative authorization rule descriptor.
 */
public record PolicyRule(
    String id,
    String actionPattern,
    String resourcePattern,
    Set<String> requiredRoles,
    int minClearance,
    String requiredTenant,
    PolicyDecision effect
) {
    public PolicyRule {
        Objects.requireNonNull(id, "id must not be null");
        if (actionPattern == null || actionPattern.isBlank()) {
            actionPattern = "*";
        }
        if (resourcePattern == null || resourcePattern.isBlank()) {
            resourcePattern = "*";
        }
        if (requiredRoles == null || requiredRoles.isEmpty()) {
            requiredRoles = Set.of();
        } else {
            Set<String> cleanRoles = new HashSet<>();
            for (String role : requiredRoles) {
                if (role != null && !role.isBlank()) {
                    cleanRoles.add(role.trim());
                }
            }
            requiredRoles = Collections.unmodifiableSet(cleanRoles);
        }
        effect = (effect == null) ? PolicyDecision.PERMIT : effect;
    }
}
