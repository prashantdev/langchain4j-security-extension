package dev.langchain4j.security.pdp.embedded;

import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.PolicyDecision;
import dev.langchain4j.security.pdp.PolicyDecisionEngine;
import dev.langchain4j.security.pdp.PolicyEvaluationRequest;
import dev.langchain4j.security.pdp.PolicyRule;

import java.util.*;

/**
 * Embedded in-memory Policy Decision Point executing strict deny-overrides logic.
 */
public class EmbeddedInMemoryPdp implements PolicyDecisionEngine {

    private final RoleGraph roleGraph;
    private final ClearanceLattice clearanceLattice;
    private final List<PolicyRule> rules = new ArrayList<>();

    public EmbeddedInMemoryPdp() {
        this(new RoleGraph(), new ClearanceLattice());
    }

    public EmbeddedInMemoryPdp(RoleGraph roleGraph, ClearanceLattice clearanceLattice) {
        this.roleGraph = Objects.requireNonNull(roleGraph, "roleGraph must not be null");
        this.clearanceLattice = Objects.requireNonNull(clearanceLattice, "clearanceLattice must not be null");
    }

    public synchronized void addRule(PolicyRule rule) {
        rules.add(Objects.requireNonNull(rule, "rule must not be null"));
    }

    public RoleGraph getRoleGraph() {
        return roleGraph;
    }

    public ClearanceLattice getClearanceLattice() {
        return clearanceLattice;
    }

    @Override
    public synchronized PolicyDecision evaluate(PolicyEvaluationRequest request) {
        // Fail-closed on null request or missing subject
        if (request == null || request.subject() == null) {
            return PolicyDecision.DENY;
        }

        SecurityIdentity subject = request.subject();
        Map<String, Object> ctx = request.context();

        // 1. Direct Evaluation of Context-Supplied Constraints (from annotations)
        if (ctx.containsKey("requiredTenant")) {
            Object reqTenantObj = ctx.get("requiredTenant");
            if (reqTenantObj instanceof String reqTenant && !reqTenant.isBlank()) {
                if (!reqTenant.equals(subject.tenantId())) {
                    return PolicyDecision.DENY;
                }
            }
        }

        if (ctx.containsKey("minClearance")) {
            Object minClearanceObj = ctx.get("minClearance");
            int minClearance = 0;
            if (minClearanceObj instanceof Number num) {
                minClearance = num.intValue();
            }
            if (!clearanceLattice.satisfies(subject.clearanceFloor(), minClearance)) {
                return PolicyDecision.DENY;
            }
        }

        if (ctx.containsKey("requiredRoles")) {
            Set<String> reqRoles = extractRoles(ctx.get("requiredRoles"));
            if (!reqRoles.isEmpty()) {
                boolean hasAnyRequired = reqRoles.stream()
                    .anyMatch(r -> roleGraph.hasRole(subject.roles(), r));
                if (!hasAnyRequired) {
                    return PolicyDecision.DENY;
                }
            }
        }

        // 2. Strict Deny-Overrides Evaluation over Registered Rules
        boolean hasPermit = false;
        for (PolicyRule rule : rules) {
            if (matches(rule, request)) {
                if (rule.effect() == PolicyDecision.DENY) {
                    return PolicyDecision.DENY; // Deny overrides all
                }
                if (rule.effect() == PolicyDecision.PERMIT) {
                    if (rule.requiredTenant() != null && !rule.requiredTenant().isBlank()
                        && !rule.requiredTenant().equals(subject.tenantId())) {
                        return PolicyDecision.DENY;
                    }
                    if (!clearanceLattice.satisfies(subject.clearanceFloor(), rule.minClearance())) {
                        return PolicyDecision.DENY;
                    }
                    if (!rule.requiredRoles().isEmpty()) {
                        boolean hasAnyRole = rule.requiredRoles().stream()
                            .anyMatch(r -> roleGraph.hasRole(subject.roles(), r));
                        if (!hasAnyRole) {
                            return PolicyDecision.DENY;
                        }
                    }
                    hasPermit = true;
                }
            }
        }

        // If context constraints were passed and no conflicting rules, permit
        if (rules.isEmpty() && (ctx.containsKey("requiredRoles") || ctx.containsKey("minClearance") || ctx.containsKey("requiredTenant"))) {
            return PolicyDecision.PERMIT;
        }

        return hasPermit ? PolicyDecision.PERMIT : PolicyDecision.NOT_APPLICABLE;
    }

    private boolean matches(PolicyRule rule, PolicyEvaluationRequest req) {
        if (!patternMatches(rule.actionPattern(), req.action())) {
            return false;
        }
        if (!patternMatches(rule.resourcePattern(), req.resource())) {
            return false;
        }
        return true;
    }

    private boolean patternMatches(String pattern, String value) {
        if (pattern == null || pattern.equals("*")) {
            return true;
        }
        if (value == null) {
            return false;
        }
        if (pattern.endsWith("*")) {
            String prefix = pattern.substring(0, pattern.length() - 1);
            return value.regionMatches(true, 0, prefix, 0, prefix.length());
        }
        return pattern.equalsIgnoreCase(value);
    }

    private Set<String> extractRoles(Object rolesObj) {
        if (rolesObj == null) {
            return Collections.emptySet();
        }
        Set<String> set = new HashSet<>();
        if (rolesObj instanceof Collection<?> coll) {
            for (Object o : coll) {
                if (o != null && !o.toString().isBlank()) {
                    set.add(o.toString().trim());
                }
            }
        } else if (rolesObj instanceof String[] arr) {
            for (String s : arr) {
                if (s != null && !s.isBlank()) {
                    set.add(s.trim());
                }
            }
        }
        return set;
    }
}
