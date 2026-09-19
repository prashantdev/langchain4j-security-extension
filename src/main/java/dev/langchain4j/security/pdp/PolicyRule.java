package dev.langchain4j.security.pdp;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Declarative authorization rule descriptor.
 *
 * @param id unique rule identifier
 * @param actionPattern target action pattern (e.g. tool:execute or *)
 * @param resourcePattern target resource pattern (e.g. BankingOperations#* or *)
 * @param requiredRoles set of required roles
 * @param minClearance minimum required clearance level
 * @param requiredTenant required tenant identifier
 * @param effect policy decision effect (PERMIT or DENY)
 */
public record PolicyRule(
    /** Unique rule identifier. */
    String id,
    /** Target action pattern. */
    String actionPattern,
    /** Target resource pattern. */
    String resourcePattern,
    /** Set of required roles. */
    Set<String> requiredRoles,
    /** Minimum required clearance level. */
    int minClearance,
    /** Required tenant identifier. */
    String requiredTenant,
    /** Policy decision effect. */
    PolicyDecision effect
) {
    /**
     * Compact constructor validating and standardizing PolicyRule fields.
     *
     * @param id unique rule identifier
     * @param actionPattern target action pattern (e.g. tool:execute or *)
     * @param resourcePattern target resource pattern (e.g. BankingOperations#* or *)
     * @param requiredRoles set of required roles
     * @param minClearance minimum required clearance level
     * @param requiredTenant required tenant identifier
     * @param effect policy decision effect (PERMIT or DENY)
     */
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
